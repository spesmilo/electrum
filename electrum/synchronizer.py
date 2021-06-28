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

from aiorpcx import TaskGroup, run_in_thread, RPCError

from . import util
from .transaction import Transaction, PartialTransaction
from .util import bh2u, make_aiohttp_session, NetworkJobOnDefaultServer, random_shuffled_copy
from .bitcoin import address_to_scripthash, is_address, b58_address_to_hash160
from .logging import Logger
from .interface import GracefulDisconnect, NetworkTimeout

if TYPE_CHECKING:
    from .network import Network
    from .address_synchronizer import AddressSynchronizer

class SynchronizerFailure(Exception): pass

from struct import Struct
from .bitcoin import sha256


def history_status(h):
    if not h:
        return None
    status = bytes(32)
    for tx_hash, height in h:
        if height > 0:
            hash = bytearray.fromhex(tx_hash)
            hash.reverse()
            tx_item = hash + Struct('<i').pack(height)
            status = sha256(status + tx_item)
    return status.hex()


class SynchronizerBase(NetworkJobOnDefaultServer):
    """Subscribe over the network to a set of addresses, and monitor their statuses.
    Every time a status changes, run a coroutine provided by the subclass.
    """
    def __init__(self, network: 'Network'):
        self.asyncio_loop = network.asyncio_loop
        self._reset_request_counters()

        NetworkJobOnDefaultServer.__init__(self, network)

    def _reset(self):
        super()._reset()
        self.requested_addrs = set()
        self.scripthash_to_address = {}
        self._processed_some_notifications = False  # so that we don't miss them
        self._reset_request_counters()
        # Queues
        self.add_queue = asyncio.Queue()
        self.status_queue = asyncio.Queue()
        self.dao_queue = asyncio.Queue()
        self.votes_queue = asyncio.Queue()
        self.consensus_queue = asyncio.Queue()

    async def _run_tasks(self, *, taskgroup):
        await super()._run_tasks(taskgroup=taskgroup)
        try:
            async with taskgroup as group:
                await group.spawn(self.send_subscriptions())
                await group.spawn(self.handle_status())
                await group.spawn(self.handle_consensus())
                await group.spawn(self.handle_dao())
                await group.spawn(self.handle_votes())
                await group.spawn(self.main())
        finally:
            # we are being cancelled now
            self.session.unsubscribe(self.status_queue)
            self.session.unsubscribe(self.dao_queue)
            self.session.unsubscribe(self.votes_queue)
            self.session.unsubscribe(self.consensus_queue)

    def _reset_request_counters(self):
        self._requests_sent = 0
        self._requests_answered = 0

    def add(self, addr):
        asyncio.run_coroutine_threadsafe(self._add_address(addr), self.asyncio_loop)

    async def _add_address(self, addr: str):
        # note: this method is async as add_queue.put_nowait is not thread-safe.
        if not is_address(addr): raise ValueError(f"invalid bitcoin address {addr}")
        if addr in self.requested_addrs: return
        self.requested_addrs.add(addr)
        self.add_queue.put_nowait(addr)

    async def _on_address_status(self, addr, status):
        """Handle the change of the status of an address."""
        raise NotImplementedError()  # implemented by subclasses

    async def send_subscriptions(self):
        async def subscribe_to_address(addr):
            h = address_to_scripthash(addr)
            self.scripthash_to_address[h] = addr
            self._requests_sent += 1
            try:
                async with self._network_request_semaphore:
                    await self.session.subscribe('blockchain.scripthash.subscribe', [h], self.status_queue)
            except RPCError as e:
                if e.message == 'history too large':  # no unique error code
                    raise GracefulDisconnect(e, log_level=logging.ERROR) from e
                raise
            self._requests_answered += 1
            self.requested_addrs.remove(addr)

        await self.session.subscribe('blockchain.dao.subscribe', [], self.dao_queue)
        await self.session.subscribe('blockchain.consensus.subscribe', [], self.consensus_queue)

        while True:
            addr = await self.add_queue.get()
            await self.taskgroup.spawn(subscribe_to_address, addr)

    async def handle_status(self):
        while True:
            h, status = await self.status_queue.get()
            addr = self.scripthash_to_address[h]
            await self.taskgroup.spawn(self._on_address_status, addr, status)
            self._processed_some_notifications = True

    async def handle_dao(self):
        while True:
            h = await self.dao_queue.get()
            if len(h) == 0:
                continue
            if h[0] == {}:
                continue
            if "r" not in h[0]:
                continue
            if h[0]["r"] == 0:
                if h[0]["t"] not in self.wallet.dao:
                    self.wallet.dao[h[0]["t"]] = {}
                self.wallet.dao[h[0]["t"]][h[0]["w"]["hash"]] = h[0]["w"]
            elif h[0]["r"] == 1:
                if h[0]["t"] in wallet.dao and h[0]["w"]["hash"] in self.wallet.dao[h[0]["t"]]:
                    del self.wallet.dao[h[0]["t"]][h[0]["w"]["hash"]]
            self.wallet.set_dao_up_to_date(False)

    async def handle_votes(self):
        while True:
            v = await self.votes_queue.get()
            if len(v) != 2:
                continue
            self.wallet.votes[v[0]] = v[1]
            self.wallet.set_votes_up_to_date(False)

    async def handle_consensus(self):
        while True:
            c = await self.consensus_queue.get()
            cp = {}
            for par in c[0]:
                cp[par['id']] = par
            self.wallet.consensus = cp
            self.wallet.set_consensus_up_to_date(False)

    def num_requests_sent_and_answered(self) -> Tuple[int, int]:
        return self._requests_sent, self._requests_answered

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
    def __init__(self, wallet: 'AddressSynchronizer'):
        self.wallet = wallet
        SynchronizerBase.__init__(self, wallet.network)

    def _reset(self):
        super()._reset()
        self.requested_tx = {}
        self.requested_histories = set()
        self._stale_histories = dict()  # type: Dict[str, asyncio.Task]

    def diagnostic_name(self):
        return self.wallet.diagnostic_name()

    def is_up_to_date(self):
        return (not self.requested_addrs
                and not self.requested_histories
                and not self.requested_tx
                and not self._stale_histories
                and len(self.wallet.get_unverified_txs().items()) == 0)

    async def _on_address_status(self, addr, status):
        history = self.wallet.db.get_addr_history(addr)
        if history_status(history) == status or status == "0000000000000000000000000000000000000000000000000000000000000000":
            return
        # No point in requesting history twice for the same announced status.
        # However if we got announced a new status, we should request history again:
        if (addr, status) in self.requested_histories:
            return
        # request address history
        self.requested_histories.add((addr, status))
        self._stale_histories.pop(addr, asyncio.Future()).cancel()
        h = address_to_scripthash(addr)
        self._requests_sent += 1
        prev_height = 0
        prev_hist = self.wallet.db.get_addr_history(addr)
        prev_hist = [entry for entry in prev_hist if entry[1] > 0]

        for tx_ in prev_hist:
            if tx_[1] > prev_height:
                prev_height = tx_[1]

        async with self._network_request_semaphore:
            result = await self.interface.get_history_for_scripthash(h, prev_height)
        self._requests_answered += 1

        hist_ = list(map(lambda item: (item['tx_hash'], item['height']), result['history']))

        seen_hashes = set()
        new_hist = []

        for obj in hist_:
             new_hist.append(obj)
             seen_hashes.add(obj[0])

        hist = list(filter(lambda x:x[0] not in seen_hashes, prev_hist)) + new_hist

        # tx_fees
        tx_fees = [(item['tx_hash'], item.get('fee')) for item in result['history']]
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
            self.wallet.receive_history_callback(addr, hist, tx_fees)
            # Request transactions we don't have
            await self._request_missing_txs(hist)

        # Remove request; this allows up_to_date to be True
        self.requested_histories.discard((addr, status))

    async def _request_missing_txs(self, hist, *, allow_server_not_finding_tx=False):
        # "hist" is a list of [tx_hash, tx_height] lists
        transaction_hashes = []
        for tx_hash, tx_height in hist:
            if tx_hash in self.requested_tx:
                continue
            tx = self.wallet.db.get_transaction(tx_hash)
            if tx and not isinstance(tx, PartialTransaction):
                continue  # already have complete tx
            transaction_hashes.append(tx_hash)
            self.requested_tx[tx_hash] = tx_height

        if not transaction_hashes: return
        async with TaskGroup() as group:
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
        self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
        self.logger.info(f"received tx {tx_hash} height: {tx_height} bytes: {len(raw_tx)}")
        # callbacks
        util.trigger_callback('new_transaction', self.wallet, tx)

    async def main(self):
        self.wallet.set_up_to_date(False)
        self.wallet.set_dao_up_to_date(False)
        self.wallet.set_consensus_up_to_date(False)
        self.wallet.set_votes_up_to_date(False)
        # request missing txns, if any
        if self.wallet.wallet_type == 'voting':
            va = self.wallet.create_new_address()
            addrtype, h160 = b58_address_to_hash160(va)
            await self.session.subscribe('blockchain.stakervote.subscribe', ["14"+h160.hex()[:-2]], self.votes_queue)
        for addr in random_shuffled_copy(self.wallet.db.get_history()):
            history = self.wallet.db.get_addr_history(addr)
            # Old electrum servers returned ['*'] when all history for the address
            # was pruned. This no longer happens but may remain in old wallets.
            if history == ['*']: continue
            await self._request_missing_txs(history, allow_server_not_finding_tx=True)
        # add addresses to bootstrap
        for addr in random_shuffled_copy(self.wallet.get_addresses()):
            await self._add_address(addr)
        # main loop
        while True:
            await asyncio.sleep(0.1)
            await run_in_thread(self.wallet.synchronize)
            up_to_date = self.is_up_to_date()
            if (up_to_date != self.wallet.is_up_to_date()
                    or up_to_date and self._processed_some_notifications):
                self._processed_some_notifications = False
                if up_to_date:
                    self._reset_request_counters()
                self.wallet.set_up_to_date(up_to_date)
                util.trigger_callback('wallet_updated', self.wallet)


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
        # TODO blockchain.scripthash.unsubscribe

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
