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
from typing import Dict, List, TYPE_CHECKING, Tuple, Set, Optional, Sequence
from collections import defaultdict
import logging

from aiorpcx import run_in_thread, RPCError

from . import util
from .transaction import Transaction, PartialTransaction
from .util import make_aiohttp_session, NetworkJobOnDefaultServer, random_shuffled_copy, OldTaskGroup, log_exceptions
from .bitcoin import address_to_script, script_to_scripthash, is_address, neuter_bitcoin_address
from .logging import Logger
from .interface import GracefulDisconnect, NetworkTimeout

if TYPE_CHECKING:
    from .network import Network
    from .address_synchronizer import AddressSynchronizer


class SynchronizerFailure(Exception): pass


def history_status(h: Sequence[tuple[str, int]]) -> Optional[str]:
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
        self._adding_addrs = set()
        self._adding_outpoints = set()
        self.requested_addrs = set()
        self.requested_outpoints = set()
        self._handling_addr_statuses = set()
        self._handling_outpoint_statuses = set()
        self.scripthash_to_address = {}
        self._processed_some_notifications = False  # so that we don't miss them
        # Queues
        self.address_status_queue = asyncio.Queue()
        self.outpoint_status_queue = asyncio.Queue()

    async def _run_tasks(self, *, taskgroup):
        await super()._run_tasks(taskgroup=taskgroup)
        try:
            async with taskgroup as group:
                await group.spawn(self.handle_address_status())
                await group.spawn(self.handle_outpoint_status())
                await group.spawn(self.main())
        finally:
            # we are being cancelled now
            self.session.unsubscribe(self.address_status_queue)
            self.session.unsubscribe(self.outpoint_status_queue)

    def add_address(self, addr: str) -> None:
        if not is_address(addr): raise ValueError(f"invalid bitcoin address {neuter_bitcoin_address(addr)}")
        self._adding_addrs.add(addr)  # this lets is_up_to_date already know about addr

    def add_outpoint(self, outpoint: str) -> None:
        self._adding_outpoints.add(outpoint)  # this lets is_up_to_date already know about outpoint

    async def _add_address(self, addr: str):
        try:
            if not is_address(addr): raise ValueError(f"invalid bitcoin address {neuter_bitcoin_address(addr)}")
            if addr in self.requested_addrs: return
            self.requested_addrs.add(addr)
            await self.taskgroup.spawn(self._subscribe_to_address, addr)
        finally:
            self._adding_addrs.discard(addr)  # ok for addr not to be present

    async def _add_outpoint(self, outpoint: str):
        try:
            if outpoint in self.requested_outpoints: return
            self.requested_outpoints.add(outpoint)
            await self.taskgroup.spawn(self._subscribe_to_outpoint, outpoint)
        finally:
            self._adding_outpoints.discard(outpoint)  # ok for addr not to be present

    async def _on_address_status(self, addr: str, status: Optional[str]):
        """Handle the change of the status of an address.
        Should remove addr from self._handling_addr_statuses when done.
        """
        raise NotImplementedError()  # implemented by subclasses

    async def _on_outpoint_status(self, outpoint: str, status: Optional[str]):
        raise NotImplementedError()  # implemented by subclasses

    async def _subscribe_to_address(self, addr):
        spk = address_to_script(addr)
        h = script_to_scripthash(spk)
        self.scripthash_to_address[h] = addr
        self._requests_sent += 1
        try:
            async with self._network_request_semaphore:
                await self.session.subscribe('blockchain.scriptpubkey.subscribe', [spk.hex()], self.address_status_queue)
        except RPCError as e:
            if e.message == 'history too large':  # no unique error code
                raise GracefulDisconnect(e, log_level=logging.ERROR) from e
            raise
        self._requests_answered += 1

    async def _subscribe_to_outpoint(self, outpoint):
        self._requests_sent += 1
        txhash, idx = outpoint.split(':')
        idx = int(idx)
        self.logger.info(f'subscribe to outpoint: {txhash}:{idx}')
        try:
            async with self._network_request_semaphore:
                await self.session.subscribe('blockchain.outpoint.subscribe', [txhash, idx], self.outpoint_status_queue)
        except RPCError as e:
            raise
        self._requests_answered += 1

    @log_exceptions
    async def handle_address_status(self):
        while True:
            h, status = await self.address_status_queue.get()
            addr = self.scripthash_to_address[h]
            self._handling_addr_statuses.add(addr)
            self.requested_addrs.discard(addr)  # ok for addr not to be present
            await self.taskgroup.spawn(self._on_address_status, addr, status)
            self._processed_some_notifications = True

    @log_exceptions
    async def handle_outpoint_status(self):
        while True:
            txhash, idx, status = await self.outpoint_status_queue.get()
            outpoint = txhash + ':%d'%idx
            self._handling_outpoint_statuses.add(outpoint)
            self.requested_outpoints.discard(outpoint)  # ok for addr not to be present
            await self.taskgroup.spawn(self._on_outpoint_status, outpoint, status)
            self._processed_some_notifications = True

    async def main(self):
        raise NotImplementedError()  # implemented by subclasses


class Synchronizer(SynchronizerBase):
    '''The synchronizer keeps the wallet up-to-date with its set of
    addresses and their transactions.  It subscribes over the network
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
        self.requested_tx = set()  # type: Set[str]
        self.requested_histories = set()
        self._stale_histories = dict()  # type: Dict[str, asyncio.Task]

    def diagnostic_name(self):
        return self.adb.diagnostic_name()

    def is_up_to_date(self):
        return (self._init_done
                and not self._adding_addrs
                and not self._adding_outpoints
                and not self.requested_addrs
                and not self._handling_addr_statuses
                and not self.requested_histories
                and not self.requested_tx
                and not self._stale_histories
                and self.address_status_queue.empty()
                and self.outpoint_status_queue.empty())

    async def _maybe_request_history_for_addr(self, addr: str, *, ann_status: Optional[str]) -> List[dict]:
        # First opportunistically try to guess the addr history. Might save us network requests.
        old_history = self.adb.db.get_addr_history(addr)
        def guess_height(old_height: int) -> int:
            if old_height in (0, -1,):
                return self.interface.tip  # maybe mempool tx got mined just now
            return old_height
        guessed_history = [(txid, guess_height(old_height)) for (txid, old_height) in old_history]
        if history_status(guessed_history) == ann_status:
            self.logger.debug(f"managed to guess new history for {addr}. won't call 'blockchain.scriptpubkey.get_history'.")
            return [{"height": height, "tx_hash": txid} for (txid, height) in guessed_history]
        # request addr history from server
        spk = address_to_script(addr)
        sh = script_to_scripthash(spk)
        self._requests_sent += 1
        async with self._network_request_semaphore:
            result = await self.interface.get_history_for_spk(spk.hex())
        self._requests_answered += 1
        self.logger.info(f"receiving history {addr} {len(result)}")
        return result

    async def _on_address_status(self, addr, status):
        try:
            old_history = self.adb.db.get_addr_history(addr)
            if history_status(old_history) == status:
                return
            # No point in requesting history twice for the same announced status.
            # However if we got announced a new status, we should request history again:
            if (addr, status) in self.requested_histories:
                return
            # request address history
            self.requested_histories.add((addr, status))
            self._stale_histories.pop(addr, asyncio.Future()).cancel()
        finally:
            self._handling_addr_statuses.discard(addr)
        result = await self._maybe_request_history_for_addr(addr, ann_status=status)
        hist = list(map(lambda item: (item['tx_hash'], item['height']), result))
        # tx_fees
        tx_fees = [(item['tx_hash'], item.get('fee')) for item in result]
        tx_fees = dict(filter(lambda x:x[1] is not None, tx_fees))
        # Check that the status corresponds to what was announced
        if history_status(hist) != status:
            # could happen naturally if history changed between getting status and history (race)
            self.logger.info(f"error: status mismatch: {addr}. we'll wait a bit for status update.")
            # The server is supposed to send a new status notification, which will trigger a new
            # get_history. We shall wait a bit for this to happen, otherwise we disconnect.
            async def disconnect_if_still_stale():
                timeout = self.network.get_network_timeout_seconds(NetworkTimeout.Generic)
                await asyncio.sleep(timeout)
                raise SynchronizerFailure(f"timeout reached waiting for addr {addr}: history still stale")
            self._stale_histories[addr] = await self.taskgroup.spawn(disconnect_if_still_stale)
        else:
            self._stale_histories.pop(addr, asyncio.Future()).cancel()
            # Store received history
            self.adb.receive_history_callback(addr, hist, tx_fees)
            # Request transactions we don't have
            await self._request_txs_from_history(hist)

        # Remove request; this allows up_to_date to be True
        self.requested_histories.discard((addr, status))

    async def _on_outpoint_status(self, outpoint, status):
        txs = set()
        txid, index = outpoint.split(':')
        txs.add(txid)
        height = status.get('height')
        if height is not None:
            # spv the input
            self.adb.add_unverified_or_unconfirmed_tx(txid, height)
        # fetch the output
        spender_txid = status.get('spender_txhash')
        if spender_txid is not None:
            spender_height = status['spender_height']
            self.adb.add_unverified_or_unconfirmed_tx(spender_txid, spender_height)
            txs.add(spender_txid)

        await self._request_missing_txs(txs, allow_server_not_finding_tx=False)

    async def _request_txs_from_history(self, hist, *, allow_server_not_finding_tx=False):
        # "hist" is a list of [tx_hash, tx_height] lists
        txs = set()
        for tx_hash, _tx_height in hist:
            txs.add(tx_hash)
        await self._request_missing_txs(txs, allow_server_not_finding_tx=allow_server_not_finding_tx)

    @log_exceptions
    async def _request_missing_txs(self, txs, *, allow_server_not_finding_tx=False):
        transaction_hashes = []
        for tx_hash in txs:
            if tx_hash in self.requested_tx:
                continue
            tx = self.adb.db.get_transaction(tx_hash)
            if tx and not isinstance(tx, PartialTransaction):
                continue  # already have complete tx
            transaction_hashes.append(tx_hash)
            # note: tx_height might change by the time we get the raw_tx
            self.requested_tx.add(tx_hash)

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
                self.requested_tx.remove(tx_hash)
                return
            else:
                raise
        finally:
            self._requests_answered += 1
        tx = Transaction(raw_tx)
        if tx_hash != tx.txid():
            raise SynchronizerFailure(f"received tx does not match expected txid ({tx_hash} != {tx.txid()})")
        self.requested_tx.remove(tx_hash)
        self.adb.receive_tx_callback(tx)
        self.logger.info(f"received tx {tx_hash}. bytes-len: {len(raw_tx)//2}")

    async def main(self):
        self.adb.up_to_date_changed()
        # request missing txns, if any
        for addr in random_shuffled_copy(self.adb.db.get_history()):
            history = self.adb.db.get_addr_history(addr)
            # Old electrum servers returned ['*'] when all history for the address
            # was pruned. This no longer happens but may remain in old wallets.
            if history == ['*']: continue
            await self._request_txs_from_history(history, allow_server_not_finding_tx=True)
        # add addresses to bootstrap
        for addr in random_shuffled_copy(self.adb.get_addresses()):
            await self._add_address(addr)
        # add outpoints to bootstrap (race)
        for outpoint in self.adb._subscribed_outpoints:
            await self._add_outpoint(outpoint)
        # main loop
        self._init_done = True
        prev_uptodate = False
        while True:
            await asyncio.sleep(0.1)
            for addr in self._adding_addrs.copy(): # copy set to ensure iterator stability
                await self._add_address(addr)
            for outpoint in list(self._adding_outpoints):
                await self._add_outpoint(outpoint)
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
        self.watched_addresses = defaultdict(list)  # type: Dict[str, List[str]]
        self._start_watching_queue = asyncio.Queue()  # type: asyncio.Queue[Tuple[str, str]]

    async def main(self):
        # resend existing subscriptions if we were restarted
        for addr in self.watched_addresses:
            await self._add_address(addr)
        # main loop
        while True:
            addr, url = await self._start_watching_queue.get()
            self.watched_addresses[addr].append(url)
            await self._add_address(addr)

    async def start_watching_addr(self, addr: str, url: str):
        await self._start_watching_queue.put((addr, url))

    async def stop_watching_addr(self, addr: str):
        self.watched_addresses.pop(addr, None)
        # TODO blockchain.scriptpubkey.unsubscribe

    async def _on_address_status(self, addr, status):
        if addr not in self.watched_addresses:
            return
        self.logger.info(f'new status for addr {addr}')
        headers = {'content-type': 'application/json'}
        data = {'address': addr, 'status': status}
        for url in self.watched_addresses[addr]:
            try:
                async with make_aiohttp_session(proxy=self.network.proxy, headers=headers) as session:
                    async with session.post(url, json=data, headers=headers) as resp:
                        await resp.text()
            except Exception as e:
                self.logger.info(repr(e))
            else:
                self.logger.info(f'Got Response for {addr}')
