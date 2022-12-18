#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import asyncio
import hashlib
from typing import Dict, List, TYPE_CHECKING, Tuple, Set
from collections import defaultdict
import logging

from aiorpcx import run_in_thread, RPCError

from . import util
from .transaction import Transaction, PartialTransaction
from .util import make_aiohttp_session, NetworkJobOnDefaultServer, random_shuffled_copy, OldTaskGroup, is_hex_str
from .bitcoin import script_to_scripthash, address_to_script
from .logging import Logger
from .interface import GracefulDisconnect, NetworkTimeout

if TYPE_CHECKING:
    from .network import Network
    from .address_synchronizer import AddressSynchronizer


class SynchronizerFailure(Exception): pass


def history_status(h):
    if not h:
        return None
    status = ''
    for tx_hash, height in h:
        status += tx_hash + ':%d:' % height
    return hashlib.sha256(status.encode('ascii')).digest().hex()


class SynchronizerBase(NetworkJobOnDefaultServer):
    """Subscribe over the network to a set of addresses, and monitor their statuses.
    Every time a status changes, run a coroutine provided by the subclass.
    """
    def __init__(self, network: 'Network'):
        self.asyncio_loop = network.asyncio_loop

        NetworkJobOnDefaultServer.__init__(self, network)

    def _reset(self):
        super()._reset()
        self._adding_spks = set()
        self.requested_scriptpubkeys = set()
        self._handling_spk_statuses = set()
        self.scripthash_to_spk = {}
        self._processed_some_notifications = False  # so that we don't miss them
        # Queues
        self.status_queue = asyncio.Queue()

    async def _run_tasks(self, *, taskgroup):
        await super()._run_tasks(taskgroup=taskgroup)
        try:
            async with taskgroup as group:
                await group.spawn(self.handle_status())
                await group.spawn(self.main())
        finally:
            # we are being cancelled now
            self.session.unsubscribe(self.status_queue)

    def add_spk(self, spk: str) -> None:
        assert is_hex_str(spk)
        self._adding_spks.add(spk)  # this lets is_up_to_date already know about spk

    async def _add_spk(self, spk: str):
        try:
            assert is_hex_str(spk)
            if spk in self.requested_scriptpubkeys: return
            self.requested_scriptpubkeys.add(spk)
            await self.taskgroup.spawn(self._subscribe_to_address, spk)
        finally:
            self._adding_spks.discard(spk)  # ok for addr not to be present

    async def _on_spk_status(self, spk, status):
        """Handle the change of the status of a scriptPubKey."""
        raise NotImplementedError()  # implemented by subclasses

    async def _subscribe_to_address(self, spk):
        h = script_to_scripthash(spk)
        self.scripthash_to_spk[h] = spk
        self._requests_sent += 1
        try:
            async with self._network_request_semaphore:
                await self.session.subscribe('blockchain.scripthash.subscribe', [h], self.status_queue)
        except RPCError as e:
            if e.message == 'history too large':  # no unique error code
                raise GracefulDisconnect(e, log_level=logging.ERROR) from e
            raise
        self._requests_answered += 1

    async def handle_status(self):
        while True:
            h, status = await self.status_queue.get()
            spk = self.scripthash_to_spk[h]
            self._handling_spk_statuses.add(spk)
            self.requested_scriptpubkeys.discard(spk)  # ok for addr not to be present
            await self.taskgroup.spawn(self._on_spk_status, spk, status)
            self._processed_some_notifications = True

    async def main(self):
        raise NotImplementedError()  # implemented by subclasses


class Synchronizer(SynchronizerBase):
    '''The synchronizer keeps the wallet up-to-date with its set of
    scriptPubKeys and their transactions.  It subscribes over the network
    to wallet addresses, gets the wallet to generate new addresses
    when necessary, requests the transaction history of any addresses
    we don't have the full history of, and requests binary transaction
    data of any transactions the wallet doesn't have.
    '''
    def __init__(self, adb: 'AddressSynchronizer'):
        self.adb = adb
        SynchronizerBase.__init__(self, adb.network)

    def _reset(self):
        super()._reset()
        self._init_done = False
        self.requested_tx = {}
        self.requested_histories = set()
        self._stale_histories = dict()  # type: Dict[str, asyncio.Task]

    def diagnostic_name(self):
        return self.adb.diagnostic_name()

    def is_up_to_date(self):
        return (self._init_done
                and not self._adding_spks
                and not self.requested_scriptpubkeys
                and not self._handling_spk_statuses
                and not self.requested_histories
                and not self.requested_tx
                and not self._stale_histories
                and self.status_queue.empty())

    async def _on_spk_status(self, spk, status):
        try:
            history = self.adb.db.get_spk_history(spk)
            if history_status(history) == status:
                return
            # No point in requesting history twice for the same announced status.
            # However if we got announced a new status, we should request history again:
            if (spk, status) in self.requested_histories:
                return
            # request address history
            self.requested_histories.add((spk, status))
            self._stale_histories.pop(spk, asyncio.Future()).cancel()
        finally:
            self._handling_spk_statuses.discard(spk)
        h = script_to_scripthash(spk)
        self._requests_sent += 1
        async with self._network_request_semaphore:
            result = await self.interface.get_history_for_scripthash(h)
        self._requests_answered += 1
        self.logger.info(f"receiving history {spk} {len(result)}")
        hist = list(map(lambda item: (item['tx_hash'], item['height']), result))
        # tx_fees
        tx_fees = [(item['tx_hash'], item.get('fee')) for item in result]
        tx_fees = dict(filter(lambda x:x[1] is not None, tx_fees))
        # Check that the status corresponds to what was announced
        if history_status(hist) != status:
            # could happen naturally if history changed between getting status and history (race)
            self.logger.info(f"error: status mismatch: {spk}. we'll wait a bit for status update.")
            # The server is supposed to send a new status notification, which will trigger a new
            # get_history. We shall wait a bit for this to happen, otherwise we disconnect.
            async def disconnect_if_still_stale():
                timeout = self.network.get_network_timeout_seconds(NetworkTimeout.Generic)
                await asyncio.sleep(timeout)
                raise SynchronizerFailure(f"timeout reached waiting for spk {spk}: history still stale")
            self._stale_histories[spk] = await self.taskgroup.spawn(disconnect_if_still_stale)
        else:
            self._stale_histories.pop(spk, asyncio.Future()).cancel()
            # Store received history
            self.adb.receive_history_callback(spk, hist, tx_fees)
            # Request transactions we don't have
            await self._request_missing_txs(hist)

        # Remove request; this allows up_to_date to be True
        self.requested_histories.discard((spk, status))

    async def _request_missing_txs(self, hist, *, allow_server_not_finding_tx=False):
        # "hist" is a list of [tx_hash, tx_height] lists
        transaction_hashes = []
        for tx_hash, tx_height in hist:
            if tx_hash in self.requested_tx:
                continue
            tx = self.adb.db.get_transaction(tx_hash)
            if tx and not isinstance(tx, PartialTransaction):
                continue  # already have complete tx
            transaction_hashes.append(tx_hash)
            self.requested_tx[tx_hash] = tx_height

        if not transaction_hashes: return
        async with OldTaskGroup() as group:
            for tx_hash in transaction_hashes:
                await group.spawn(self._get_transaction(tx_hash, allow_server_not_finding_tx=allow_server_not_finding_tx))

    async def _get_transaction(self, tx_hash, *, allow_server_not_finding_tx=False):
        self._requests_sent += 1
        try:
            async with self._network_request_semaphore:
                raw_tx = await self.interface.get_transaction(tx_hash)
        except RPCError as e:
            # most likely, "No such mempool or blockchain transaction"
            if allow_server_not_finding_tx:
                self.requested_tx.pop(tx_hash)
                return
            else:
                raise
        finally:
            self._requests_answered += 1
        tx = Transaction(raw_tx)
        if tx_hash != tx.txid():
            raise SynchronizerFailure(f"received tx does not match expected txid ({tx_hash} != {tx.txid()})")
        tx_height = self.requested_tx.pop(tx_hash)
        self.adb.receive_tx_callback(tx_hash, tx, tx_height)
        self.logger.info(f"received tx {tx_hash} height: {tx_height} bytes: {len(raw_tx)}")

    async def main(self):
        self.adb.up_to_date_changed()
        # request missing txns, if any
        for spk in random_shuffled_copy(self.adb.db.get_scriptpubkeys()):
            history = self.adb.db.get_spk_history(spk)
            # Old electrum servers returned ['*'] when all history for the address
            # was pruned. This no longer happens but may remain in old wallets.
            if history == ['*']: continue
            await self._request_missing_txs(history, allow_server_not_finding_tx=True)
        # add addresses to bootstrap
        for spk in random_shuffled_copy(self.adb.get_scriptpubkeys()):
            await self._add_spk(spk)
        # main loop
        self._init_done = True
        prev_uptodate = False
        while True:
            await asyncio.sleep(0.1)
            for spk in self._adding_spks.copy():  # copy set to ensure iterator stability
                await self._add_spk(spk)
            up_to_date = self.adb.is_up_to_date()
            # see if status changed
            if (up_to_date != prev_uptodate
                    or up_to_date and self._processed_some_notifications):
                self._processed_some_notifications = False
                self.adb.up_to_date_changed()
            prev_uptodate = up_to_date


class Notifier(SynchronizerBase):
    """Watch addresses. Every time the status of an address changes,
    an HTTP POST is sent to the corresponding URL.
    """
    def __init__(self, network):
        SynchronizerBase.__init__(self, network)
        self.watched_scriptpubkeys = defaultdict(list)  # type: Dict[str, List[str]]
        self._start_watching_queue = asyncio.Queue()  # type: asyncio.Queue[Tuple[str, str]]
        self._spk_to_addr = {}  # type: Dict[str, str]

    async def main(self):
        # resend existing subscriptions if we were restarted
        for spk in self.watched_scriptpubkeys:
            await self._add_spk(spk)
        # main loop
        while True:
            spk, url = await self._start_watching_queue.get()
            self.watched_scriptpubkeys[spk].append(url)
            await self._add_spk(spk)

    async def start_watching_addr(self, addr: str, url: str):
        spk = address_to_script(addr)
        self._spk_to_addr[spk] = addr
        await self.start_watching_spk(spk=spk, url=url)

    async def stop_watching_spk(self, spk: str):
        self.watched_scriptpubkeys.pop(spk, None)
        # TODO blockchain.scripthash.unsubscribe

    async def stop_watching_addr(self, addr: str):
        spk = address_to_script(addr)
        await self.stop_watching_spk(spk=spk)
        self._spk_to_addr.pop(spk, None)

    async def _on_spk_status(self, spk, status):
        if spk not in self.watched_scriptpubkeys:
            return
        addr = self._spk_to_addr.get(spk, None)
        self.logger.info(f'new status for spk {spk}. (addr={addr})')
        headers = {'content-type': 'application/json'}
        data = {'spk': spk, 'status': status}
        if addr:
            data['address'] = addr
        for url in self.watched_scriptpubkeys[spk]:
            if not url:
                continue
            try:
                async with make_aiohttp_session(proxy=self.network.proxy, headers=headers) as session:
                    async with session.post(url, json=data, headers=headers) as resp:
                        await resp.text()
            except Exception as e:
                self.logger.info(repr(e))
            else:
                self.logger.info(f'Got Response for spk {spk}. (addr={addr})')
