# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum Developers
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
import threading
import itertools
from collections import defaultdict
from typing import TYPE_CHECKING, Dict, Optional, Set, Tuple, NamedTuple, Sequence, List

from .crypto import sha256
from . import bitcoin, util
from .bitcoin import COINBASE_MATURITY
from .util import profiler, bfh, TxMinedInfo, UnrelatedTransactionException, with_lock, OldTaskGroup
from .transaction import Transaction, TxOutput, TxInput, PartialTxInput, TxOutpoint, PartialTransaction
from .synchronizer import Synchronizer
from .verifier import SPV
from .blockchain import hash_header, Blockchain
from .i18n import _
from .logging import Logger
from .util import EventListener, event_listener

if TYPE_CHECKING:
    from .network import Network
    from .wallet_db import WalletDB
    from .simple_config import SimpleConfig


TX_HEIGHT_FUTURE = -3
TX_HEIGHT_LOCAL = -2
TX_HEIGHT_UNCONF_PARENT = -1
TX_HEIGHT_UNCONFIRMED = 0

TX_TIMESTAMP_INF = 999_999_999_999
TX_HEIGHT_INF = 10 ** 9


class HistoryItem(NamedTuple):
    txid: str
    tx_mined_status: TxMinedInfo
    delta: int
    fee: Optional[int]
    balance: int


class AddressSynchronizer(Logger, EventListener):
    """ address database """

    network: Optional['Network']
    asyncio_loop: Optional['asyncio.AbstractEventLoop'] = None
    synchronizer: Optional['Synchronizer']
    verifier: Optional['SPV']

    def __init__(self, db: 'WalletDB', config: 'SimpleConfig', *, name: str = None):
        self.db = db
        self.config = config
        self.name = name
        self.network = None
        Logger.__init__(self)
        # verifier (SPV) and synchronizer are started in start_network
        self.synchronizer = None
        self.verifier = None
        # locks: if you need to take multiple ones, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self.transaction_lock = threading.RLock()
        self.future_tx = {}  # type: Dict[str, int]  # txid -> wanted (abs) height
        # Txs the server claims are mined but still pending verification:
        self.unverified_tx = defaultdict(int)  # type: Dict[str, int]  # txid -> height. Access with self.lock.
        # Txs the server claims are in the mempool:
        self.unconfirmed_tx = defaultdict(int)  # type: Dict[str, int]  # txid -> height. Access with self.lock.
        # thread local storage for caching stuff
        self.threadlocal_cache = threading.local()

        self._get_balance_cache = {}

        self.load_and_cleanup()

    def diagnostic_name(self):
        return self.name or ""

    def with_transaction_lock(func):
        def func_wrapper(self: 'AddressSynchronizer', *args, **kwargs):
            with self.transaction_lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def load_and_cleanup(self):
        self.load_local_history()
        self.check_history()
        self.load_unverified_transactions()
        self.remove_local_transactions_we_dont_have()

    def is_mine(self, address: Optional[str]) -> bool:
        """Returns whether an address is in our set.

        Differences between adb.is_mine and wallet.is_mine:
        - adb.is_mine: addrs that we are watching (e.g. via Synchronizer)
            - lnwatcher adds its own lightning-related addresses that are not part of the wallet
        - wallet.is_mine: addrs that are part of the wallet balance or the wallet might sign for
            - an offline wallet might learn from a PSBT about addrs beyond its gap limit
        Neither set is guaranteed to be a subset of the other.
        """
        if not address: return False
        return self.db.is_addr_in_history(address)

    def get_addresses(self):
        return sorted(self.db.get_history())

    def get_address_history(self, addr: str) -> Dict[str, int]:
        """Returns the history for the address, as a txid->height dict.
        In addition to what we have from the server, this includes local and future txns.

        Also see related method db.get_addr_history, which stores the response from the server,
        so that only includes txns the server sees.
        """
        h = {}
        # we need self.transaction_lock but get_tx_height will take self.lock
        # so we need to take that too here, to enforce order of locks
        with self.lock, self.transaction_lock:
            related_txns = self._history_local.get(addr, set())
            for tx_hash in related_txns:
                tx_height = self.get_tx_height(tx_hash).height
                h[tx_hash] = tx_height
        return h

    def get_address_history_len(self, addr: str) -> int:
        """Return number of transactions where address is involved."""
        return len(self._history_local.get(addr, ()))

    def get_txin_address(self, txin: TxInput) -> Optional[str]:
        if txin.address:
            return txin.address
        prevout_hash = txin.prevout.txid.hex()
        prevout_n = txin.prevout.out_idx
        for addr in self.db.get_txo_addresses(prevout_hash):
            d = self.db.get_txo_addr(prevout_hash, addr)
            if prevout_n in d:
                return addr
        tx = self.db.get_transaction(prevout_hash)
        if tx:
            return tx.outputs()[prevout_n].address
        return None

    def get_txin_value(self, txin: TxInput, *, address: str = None) -> Optional[int]:
        if txin.value_sats() is not None:
            return txin.value_sats()
        prevout_hash = txin.prevout.txid.hex()
        prevout_n = txin.prevout.out_idx
        if address is None:
            address = self.get_txin_address(txin)
        if address:
            d = self.db.get_txo_addr(prevout_hash, address)
            try:
                v, cb = d[prevout_n]
                return v
            except KeyError:
                pass
        tx = self.db.get_transaction(prevout_hash)
        if tx:
            return tx.outputs()[prevout_n].value
        return None

    def load_unverified_transactions(self):
        # review transactions that are in the history
        for addr in self.db.get_history():
            hist = self.db.get_addr_history(addr)
            for tx_hash, tx_height in hist:
                # add it in case it was previously unconfirmed
                self.add_unverified_or_unconfirmed_tx(tx_hash, tx_height)

    def start_network(self, network: Optional['Network']) -> None:
        assert self.network is None, "already started"
        self.network = network
        if self.network is not None:
            self.synchronizer = Synchronizer(self)
            self.verifier = SPV(self.network, self)
            self.asyncio_loop = network.asyncio_loop
            self.register_callbacks()

    @event_listener
    def on_event_blockchain_updated(self, *args):
        self._get_balance_cache = {}  # invalidate cache
        self.db.put('stored_height', self.get_local_height())

    async def stop(self):
        if self.network:
            try:
                async with OldTaskGroup() as group:
                    if self.synchronizer:
                        await group.spawn(self.synchronizer.stop())
                    if self.verifier:
                        await group.spawn(self.verifier.stop())
            finally:  # even if we get cancelled
                self.synchronizer = None
                self.verifier = None
                self.unregister_callbacks()

    def add_address(self, address):
        if address not in self.db.history:
            self.db.history[address] = []
        if self.synchronizer:
            self.synchronizer.add(address)
        self.up_to_date_changed()

    def get_conflicting_transactions(self, tx: Transaction, *, include_self: bool = False) -> Set[str]:
        """Returns a set of transaction hashes from the wallet history that are
        directly conflicting with tx, i.e. they have common outpoints being
        spent with tx.

        include_self specifies whether the tx itself should be reported as a
        conflict (if already in wallet history)
        """
        conflicting_txns = set()
        with self.transaction_lock:
            for txin in tx.inputs():
                if txin.is_coinbase_input():
                    continue
                prevout_hash = txin.prevout.txid.hex()
                prevout_n = txin.prevout.out_idx
                spending_tx_hash = self.db.get_spent_outpoint(prevout_hash, prevout_n)
                if spending_tx_hash is None:
                    continue
                # this outpoint has already been spent, by spending_tx
                # annoying assert that has revealed several bugs over time:
                assert self.db.get_transaction(spending_tx_hash), "spending tx not in wallet db"
                conflicting_txns |= {spending_tx_hash}
            if tx_hash := tx.txid():
                if tx_hash in conflicting_txns:
                    # this tx is already in history, so it conflicts with itself
                    if len(conflicting_txns) > 1:
                        raise Exception('Found conflicting transactions already in wallet history.')
                    if not include_self:
                        conflicting_txns -= {tx_hash}
            return conflicting_txns

    def get_transaction(self, txid: str) -> Optional[Transaction]:
        tx = self.db.get_transaction(txid)
        if tx:
            tx.deserialize()
            for txin in tx._inputs:
                tx_mined_info = self.get_tx_height(txin.prevout.txid.hex())
                txin.block_height = tx_mined_info.height  # not SPV-ed
                txin.block_txpos = tx_mined_info.txpos
        return tx

    def add_transaction(self, tx: Transaction, *, allow_unrelated=False, is_new=True) -> bool:
        """
        Returns whether the tx was successfully added to the wallet history.
        Note that a transaction may need to be added several times, if our
        list of addresses has increased. This will return True even if the
        transaction was already in self.db.
        """
        assert tx, tx
        # note: tx.is_complete() is not necessarily True; tx might be partial
        # but it *needs* to have a txid:
        tx_hash = tx.txid()
        if tx_hash is None:
            raise Exception("cannot add tx without txid to wallet history")
        # we need self.transaction_lock but get_tx_height will take self.lock
        # so we need to take that too here, to enforce order of locks
        with self.lock, self.transaction_lock:
            # NOTE: returning if tx in self.transactions might seem like a good idea
            # BUT we track is_mine inputs in a txn, and during subsequent calls
            # of add_transaction tx, we might learn of more-and-more inputs of
            # being is_mine, as we roll the gap_limit forward
            is_coinbase = tx.inputs()[0].is_coinbase_input()
            tx_height = self.get_tx_height(tx_hash).height
            if not allow_unrelated:
                # note that during sync, if the transactions are not properly sorted,
                # it could happen that we think tx is unrelated but actually one of the inputs is is_mine.
                # this is the main motivation for allow_unrelated
                is_mine = any([self.is_mine(self.get_txin_address(txin)) for txin in tx.inputs()])
                is_for_me = any([self.is_mine(txo.address) for txo in tx.outputs()])
                if not is_mine and not is_for_me:
                    raise UnrelatedTransactionException()
            # Find all conflicting transactions.
            # In case of a conflict,
            #     1. confirmed > mempool > local
            #     2. this new txn has priority over existing ones
            # When this method exits, there must NOT be any conflict, so
            # either keep this txn and remove all conflicting (along with dependencies)
            #     or drop this txn
            conflicting_txns = self.get_conflicting_transactions(tx)
            if conflicting_txns:
                existing_mempool_txn = any(
                    self.get_tx_height(tx_hash2).height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT)
                    for tx_hash2 in conflicting_txns)
                existing_confirmed_txn = any(
                    self.get_tx_height(tx_hash2).height > 0
                    for tx_hash2 in conflicting_txns)
                if existing_confirmed_txn and tx_height <= 0:
                    # this is a non-confirmed tx that conflicts with confirmed txns; drop.
                    return False
                if existing_mempool_txn and tx_height == TX_HEIGHT_LOCAL:
                    # this is a local tx that conflicts with non-local txns; drop.
                    return False
                # keep this txn and remove all conflicting
                for tx_hash2 in conflicting_txns:
                    self.remove_transaction(tx_hash2)
            # add inputs
            def add_value_from_prev_output():
                # note: this takes linear time in num is_mine outputs of prev_tx
                addr = self.get_txin_address(txi)
                if addr and self.is_mine(addr):
                    outputs = self.db.get_txo_addr(prevout_hash, addr)
                    try:
                        v, is_cb = outputs[prevout_n]
                    except KeyError:
                        pass
                    else:
                        self.db.add_txi_addr(tx_hash, addr, ser, v)
                        self._get_balance_cache.clear()  # invalidate cache
            for txi in tx.inputs():
                if txi.is_coinbase_input():
                    continue
                prevout_hash = txi.prevout.txid.hex()
                prevout_n = txi.prevout.out_idx
                ser = txi.prevout.to_str()
                self.db.set_spent_outpoint(prevout_hash, prevout_n, tx_hash)
                add_value_from_prev_output()
            # add outputs
            for n, txo in enumerate(tx.outputs()):
                v = txo.value
                ser = tx_hash + ':%d'%n
                scripthash = bitcoin.script_to_scripthash(txo.scriptpubkey)
                self.db.add_prevout_by_scripthash(scripthash, prevout=TxOutpoint.from_str(ser), value=v)
                addr = txo.address
                if addr and self.is_mine(addr):
                    self.db.add_txo_addr(tx_hash, addr, n, v, is_coinbase)
                    self._get_balance_cache.clear()  # invalidate cache
                    # give v to txi that spends me
                    next_tx = self.db.get_spent_outpoint(tx_hash, n)
                    if next_tx is not None:
                        self.db.add_txi_addr(next_tx, addr, ser, v)
                        self._add_tx_to_local_history(next_tx)
            # add to local history
            self._add_tx_to_local_history(tx_hash)
            # save
            self.db.add_transaction(tx_hash, tx)
            self.db.add_num_inputs_to_tx(tx_hash, len(tx.inputs()))
            if is_new:
                util.trigger_callback('adb_added_tx', self, tx_hash, tx)
            return True

    def remove_transaction(self, tx_hash: str) -> None:
        """Removes a transaction AND all its dependents/children
        from the wallet history.
        """
        with self.lock, self.transaction_lock:
            to_remove = {tx_hash}
            to_remove |= self.get_depending_transactions(tx_hash)
            for txid in to_remove:
                self._remove_transaction(txid)

    def _remove_transaction(self, tx_hash: str) -> None:
        """Removes a single transaction from the wallet history, and attempts
         to undo all effects of the tx (spending inputs, creating outputs, etc).
        """
        def remove_from_spent_outpoints():
            # undo spends in spent_outpoints
            if tx is not None:
                # if we have the tx, this branch is faster
                for txin in tx.inputs():
                    if txin.is_coinbase_input():
                        continue
                    prevout_hash = txin.prevout.txid.hex()
                    prevout_n = txin.prevout.out_idx
                    self.db.remove_spent_outpoint(prevout_hash, prevout_n)
            else:
                # expensive but always works
                for prevout_hash, prevout_n in self.db.list_spent_outpoints():
                    spending_txid = self.db.get_spent_outpoint(prevout_hash, prevout_n)
                    if spending_txid == tx_hash:
                        self.db.remove_spent_outpoint(prevout_hash, prevout_n)

        with self.lock, self.transaction_lock:
            self.logger.info(f"removing tx from history {tx_hash}")
            tx = self.db.remove_transaction(tx_hash)
            remove_from_spent_outpoints()
            self._remove_tx_from_local_history(tx_hash)
            for addr in itertools.chain(self.db.get_txi_addresses(tx_hash), self.db.get_txo_addresses(tx_hash)):
                self._get_balance_cache.clear()  # invalidate cache
            self.db.remove_txi(tx_hash)
            self.db.remove_txo(tx_hash)
            self.db.remove_tx_fee(tx_hash)
            self.db.remove_verified_tx(tx_hash)
            self.unverified_tx.pop(tx_hash, None)
            self.unconfirmed_tx.pop(tx_hash, None)
            if tx:
                for idx, txo in enumerate(tx.outputs()):
                    scripthash = bitcoin.script_to_scripthash(txo.scriptpubkey)
                    prevout = TxOutpoint(bfh(tx_hash), idx)
                    self.db.remove_prevout_by_scripthash(scripthash, prevout=prevout, value=txo.value)
        util.trigger_callback('adb_removed_tx', self, tx_hash, tx)

    def get_depending_transactions(self, tx_hash: str) -> Set[str]:
        """Returns all (grand-)children of tx_hash in this wallet."""
        with self.transaction_lock:
            children = set()
            for n in self.db.get_spent_outpoints(tx_hash):
                other_hash = self.db.get_spent_outpoint(tx_hash, n)
                children.add(other_hash)
                children |= self.get_depending_transactions(other_hash)
            return children

    def receive_tx_callback(self, tx: Transaction, tx_height: int) -> None:
        txid = tx.txid()
        assert txid is not None
        self.add_unverified_or_unconfirmed_tx(txid, tx_height)
        self.add_transaction(tx, allow_unrelated=True)

    def receive_history_callback(self, addr: str, hist, tx_fees: Dict[str, int]):
        with self.lock:
            old_hist = self.get_address_history(addr)
            for tx_hash, height in old_hist.items():
                if (tx_hash, height) not in hist:
                    # make tx local
                    self.unverified_tx.pop(tx_hash, None)
                    self.unconfirmed_tx.pop(tx_hash, None)
                    self.db.remove_verified_tx(tx_hash)
                    if self.verifier:
                        self.verifier.remove_spv_proof_for_tx(tx_hash)
            self.db.set_addr_history(addr, hist)

        for tx_hash, tx_height in hist:
            # add it in case it was previously unconfirmed
            self.add_unverified_or_unconfirmed_tx(tx_hash, tx_height)
            # if addr is new, we have to recompute txi and txo
            tx = self.db.get_transaction(tx_hash)
            if tx is None:
                continue
            self.add_transaction(tx, allow_unrelated=True, is_new=False)
            # if we already had this tx, see if its height changed (e.g. local->unconfirmed)
            old_height = old_hist.get(tx_hash, None)
            if old_height is not None and old_height != tx_height:
                util.trigger_callback('adb_tx_height_changed', self, tx_hash, old_height, tx_height)

        # Store fees
        for tx_hash, fee_sat in tx_fees.items():
            self.db.add_tx_fee_from_server(tx_hash, fee_sat)

    @profiler
    def load_local_history(self):
        self._history_local = {}  # type: Dict[str, Set[str]]  # address -> set(txid)
        self._address_history_changed_events = defaultdict(asyncio.Event)  # address -> Event
        for txid in itertools.chain(self.db.list_txi(), self.db.list_txo()):
            self._add_tx_to_local_history(txid)

    @profiler
    def check_history(self):
        hist_addrs_mine = list(filter(lambda k: self.is_mine(k), self.db.get_history()))
        hist_addrs_not_mine = list(filter(lambda k: not self.is_mine(k), self.db.get_history()))
        for addr in hist_addrs_not_mine:
            self.db.remove_addr_history(addr)
        for addr in hist_addrs_mine:
            hist = self.db.get_addr_history(addr)
            for tx_hash, tx_height in hist:
                if self.db.get_txi_addresses(tx_hash) or self.db.get_txo_addresses(tx_hash):
                    continue
                tx = self.db.get_transaction(tx_hash)
                if tx is not None:
                    self.add_transaction(tx, allow_unrelated=True)

    def remove_local_transactions_we_dont_have(self):
        for txid in itertools.chain(self.db.list_txi(), self.db.list_txo()):
            tx_height = self.get_tx_height(txid).height
            if tx_height == TX_HEIGHT_LOCAL and not self.db.get_transaction(txid):
                self.remove_transaction(txid)

    def clear_history(self):
        with self.lock:
            with self.transaction_lock:
                self.db.clear_history()
                self._history_local.clear()
                self._get_balance_cache.clear()  # invalidate cache

    def _get_tx_sort_key(self, tx_hash: str) -> Tuple[int, int]:
        """Returns a key to be used for sorting txs."""
        with self.lock:
            tx_mined_info = self.get_tx_height(tx_hash)
            height = self.tx_height_to_sort_height(tx_mined_info.height)
            txpos = tx_mined_info.txpos or -1
            return height, txpos

    @classmethod
    def tx_height_to_sort_height(cls, height: int = None):
        """Return a height-like value to be used for sorting txs."""
        if height is not None:
            if height > 0:
                return height
            if height == TX_HEIGHT_UNCONFIRMED:
                return TX_HEIGHT_INF
            if height == TX_HEIGHT_UNCONF_PARENT:
                return TX_HEIGHT_INF + 1
            if height == TX_HEIGHT_FUTURE:
                return TX_HEIGHT_INF + 2
            if height == TX_HEIGHT_LOCAL:
                return TX_HEIGHT_INF + 3
        return TX_HEIGHT_INF + 100

    def with_local_height_cached(func):
        # get local height only once, as it's relatively expensive.
        # take care that nested calls work as expected
        def f(self, *args, **kwargs):
            orig_val = getattr(self.threadlocal_cache, 'local_height', None)
            self.threadlocal_cache.local_height = orig_val or self.get_local_height()
            try:
                return func(self, *args, **kwargs)
            finally:
                self.threadlocal_cache.local_height = orig_val
        return f

    @with_lock
    @with_transaction_lock
    @with_local_height_cached
    def get_history(self, domain) -> Sequence[HistoryItem]:
        domain = set(domain)
        # 1. Get the history of each address in the domain, maintain the
        #    delta of a tx as the sum of its deltas on domain addresses
        tx_deltas = defaultdict(int)  # type: Dict[str, int]
        for addr in domain:
            h = self.get_address_history(addr).items()
            for tx_hash, height in h:
                tx_deltas[tx_hash] += self.get_tx_delta(tx_hash, addr)
        # 2. create sorted history
        history = []
        for tx_hash in tx_deltas:
            delta = tx_deltas[tx_hash]
            tx_mined_status = self.get_tx_height(tx_hash)
            fee = self.get_tx_fee(tx_hash)
            history.append((tx_hash, tx_mined_status, delta, fee))
        history.sort(key = lambda x: self._get_tx_sort_key(x[0]))
        # 3. add balance
        h2 = []
        balance = 0
        for tx_hash, tx_mined_status, delta, fee in history:
            balance += delta
            h2.append(HistoryItem(
                txid=tx_hash,
                tx_mined_status=tx_mined_status,
                delta=delta,
                fee=fee,
                balance=balance))
        # sanity check
        c, u, x = self.get_balance(domain)
        if balance != c + u + x:
            self.logger.error(f'sanity check failed! c={c},u={u},x={x} while history balance={balance}')
            raise Exception("wallet.get_history() failed balance sanity-check")
        return h2

    def _add_tx_to_local_history(self, txid):
        with self.transaction_lock:
            for addr in itertools.chain(self.db.get_txi_addresses(txid), self.db.get_txo_addresses(txid)):
                cur_hist = self._history_local.get(addr, set())
                cur_hist.add(txid)
                self._history_local[addr] = cur_hist
                self._mark_address_history_changed(addr)

    def _remove_tx_from_local_history(self, txid):
        with self.transaction_lock:
            for addr in itertools.chain(self.db.get_txi_addresses(txid), self.db.get_txo_addresses(txid)):
                cur_hist = self._history_local.get(addr, set())
                try:
                    cur_hist.remove(txid)
                except KeyError:
                    pass
                else:
                    self._history_local[addr] = cur_hist
                    self._mark_address_history_changed(addr)

    def _mark_address_history_changed(self, addr: str) -> None:
        def set_and_clear():
            event = self._address_history_changed_events[addr]
            # history for this address changed, wake up coroutines:
            event.set()
            # clear event immediately so that coroutines can wait() for the next change:
            event.clear()
        if self.asyncio_loop:
            self.asyncio_loop.call_soon_threadsafe(set_and_clear)

    async def wait_for_address_history_to_change(self, addr: str) -> None:
        """Wait until the server tells us about a new transaction related to addr.

        Unconfirmed and confirmed transactions are not distinguished, and so e.g. SPV
        is not taken into account.
        """
        assert self.is_mine(addr), "address needs to be is_mine to be watched"
        await self._address_history_changed_events[addr].wait()

    def add_unverified_or_unconfirmed_tx(self, tx_hash, tx_height):
        if self.db.is_in_verified_tx(tx_hash):
            if tx_height <= 0:
                # tx was previously SPV-verified but now in mempool (probably reorg)
                with self.lock:
                    self.db.remove_verified_tx(tx_hash)
                    self.unconfirmed_tx[tx_hash] = tx_height
                if self.verifier:
                    self.verifier.remove_spv_proof_for_tx(tx_hash)
        else:
            with self.lock:
                if tx_height > 0:
                    self.unverified_tx[tx_hash] = tx_height
                else:
                    self.unconfirmed_tx[tx_hash] = tx_height

    def remove_unverified_tx(self, tx_hash, tx_height):
        with self.lock:
            new_height = self.unverified_tx.get(tx_hash)
            if new_height == tx_height:
                self.unverified_tx.pop(tx_hash, None)

    def add_verified_tx(self, tx_hash: str, info: TxMinedInfo):
        # Remove from the unverified map and add to the verified map
        with self.lock:
            self.unverified_tx.pop(tx_hash, None)
            self.db.add_verified_tx(tx_hash, info)
        util.trigger_callback('adb_added_verified_tx', self, tx_hash)

    def get_unverified_txs(self) -> Dict[str, int]:
        '''Returns a map from tx hash to transaction height'''
        with self.lock:
            return dict(self.unverified_tx)  # copy

    def undo_verifications(self, blockchain: Blockchain, above_height: int) -> Set[str]:
        '''Used by the verifier when a reorg has happened'''
        txs = set()
        with self.lock:
            for tx_hash in self.db.list_verified_tx():
                info = self.db.get_verified_tx(tx_hash)
                tx_height = info.height
                if tx_height > above_height:
                    header = blockchain.read_header(tx_height)
                    if not header or hash_header(header) != info.header_hash:
                        self.db.remove_verified_tx(tx_hash)
                        # NOTE: we should add these txns to self.unverified_tx,
                        # but with what height?
                        # If on the new fork after the reorg, the txn is at the
                        # same height, we will not get a status update for the
                        # address. If the txn is not mined or at a diff height,
                        # we should get a status update. Unless we put tx into
                        # unverified_tx, it will turn into local. So we put it
                        # into unverified_tx with the old height, and if we get
                        # a status update, that will overwrite it.
                        self.unverified_tx[tx_hash] = tx_height
                        txs.add(tx_hash)

        for tx_hash in txs:
            util.trigger_callback('adb_removed_verified_tx', self, tx_hash)
        return txs

    def get_local_height(self) -> int:
        """ return last known height if we are offline """
        cached_local_height = getattr(self.threadlocal_cache, 'local_height', None)
        if cached_local_height is not None:
            return cached_local_height
        return self.network.get_local_height() if self.network else self.db.get('stored_height', 0)

    def set_future_tx(self, txid: str, *, wanted_height: int):
        """Mark a local tx as "future" (encumbered by a timelock).
        wanted_height is the min (abs) block height at which the tx can get into the mempool (be broadcast).
                      note: tx becomes consensus-valid to be mined in a block at height wanted_height+1
        In case of a CSV-locked tx with unconfirmed inputs, the wanted_height is a best-case guess.
        """
        with self.lock:
            old_height = self.future_tx.get(txid) or None
            self.future_tx[txid] = wanted_height
        if old_height != wanted_height:
            util.trigger_callback('adb_set_future_tx', self, txid)

    def get_tx_height(self, tx_hash: str) -> TxMinedInfo:
        if tx_hash is None:  # ugly backwards compat...
            return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)
        with self.lock:
            verified_tx_mined_info = self.db.get_verified_tx(tx_hash)
            if verified_tx_mined_info:
                conf = max(self.get_local_height() - verified_tx_mined_info.height + 1, 0)
                return verified_tx_mined_info._replace(conf=conf)
            elif tx_hash in self.unverified_tx:
                height = self.unverified_tx[tx_hash]
                return TxMinedInfo(height=height, conf=0)
            elif tx_hash in self.unconfirmed_tx:
                height = self.unconfirmed_tx[tx_hash]
                return TxMinedInfo(height=height, conf=0)
            elif wanted_height := self.future_tx.get(tx_hash):
                if wanted_height > self.get_local_height():
                    return TxMinedInfo(height=TX_HEIGHT_FUTURE, conf=0, wanted_height=wanted_height)
                else:
                    return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)
            else:
                # local transaction
                return TxMinedInfo(height=TX_HEIGHT_LOCAL, conf=0)

    def up_to_date_changed(self) -> None:
        # fire triggers
        util.trigger_callback('adb_set_up_to_date', self)

    def is_up_to_date(self):
        if not self.synchronizer or not self.verifier:
            return False
        return self.synchronizer.is_up_to_date() and self.verifier.is_up_to_date()

    def reset_netrequest_counters(self) -> None:
        if self.synchronizer:
            self.synchronizer.reset_request_counters()
        if self.verifier:
            self.verifier.reset_request_counters()

    def get_history_sync_state_details(self) -> Tuple[int, int]:
        nsent, nans = 0, 0
        if self.synchronizer:
            n1, n2 = self.synchronizer.num_requests_sent_and_answered()
            nsent += n1
            nans += n2
        if self.verifier:
            n1, n2 = self.verifier.num_requests_sent_and_answered()
            nsent += n1
            nans += n2
        return nsent, nans

    @with_transaction_lock
    def get_tx_delta(self, tx_hash: str, address: str) -> int:
        """effect of tx on address"""
        delta = 0
        # subtract the value of coins sent from address
        d = self.db.get_txi_addr(tx_hash, address)
        for n, v in d:
            delta -= v
        # add the value of the coins received at address
        d = self.db.get_txo_addr(tx_hash, address)
        for n, (v, cb) in d.items():
            delta += v
        return delta

    def get_tx_fee(self, txid: str) -> Optional[int]:
        """Returns tx_fee or None. Use server fee only if tx is unconfirmed and not mine.

        Note: being fast is prioritised over completeness here. We try to avoid deserializing
              the tx, as that is expensive if we are called for the whole history. We sometimes
              incorrectly early-exit and return None, e.g. for not-all-ismine-input txs,
              where we could calculate the fee if we deserialized (but to see if we have all
              the parent txs available, we would have to deserialize first).
              More expensive but more complete alternative: wallet.get_tx_info(tx).fee
        """
        # check if stored fee is available
        fee = self.db.get_tx_fee(txid, trust_server=False)
        if fee is not None:
            return fee
        # delete server-sent fee for confirmed txns
        confirmed = self.get_tx_height(txid).conf > 0
        if confirmed:
            self.db.add_tx_fee_from_server(txid, None)
        # if all inputs are ismine, try to calc fee now;
        # otherwise, return stored value
        num_all_inputs = self.db.get_num_all_inputs_of_tx(txid)
        if num_all_inputs is not None:
            # check if tx is mine
            num_ismine_inputs = self.db.get_num_ismine_inputs_of_tx(txid)
            assert num_ismine_inputs <= num_all_inputs, (num_ismine_inputs, num_all_inputs)
            # trust server if tx is unconfirmed and not mine
            if num_ismine_inputs < num_all_inputs:
                return None if confirmed else self.db.get_tx_fee(txid, trust_server=True)
        # lookup tx and deserialize it.
        # note that deserializing is expensive, hence above hacks
        tx = self.db.get_transaction(txid)
        if not tx:
            return None
        # compute fee if possible
        v_in = v_out = 0
        with self.lock, self.transaction_lock:
            for txin in tx.inputs():
                addr = self.get_txin_address(txin)
                value = self.get_txin_value(txin, address=addr)
                if value is None:
                    v_in = None
                elif v_in is not None:
                    v_in += value
            for txout in tx.outputs():
                v_out += txout.value
        if v_in is not None:
            fee = v_in - v_out
        else:
            fee = None
        # save result
        self.db.add_tx_fee_we_calculated(txid, fee)
        self.db.add_num_inputs_to_tx(txid, len(tx.inputs()))
        return fee

    def get_addr_io(self, address: str):
        with self.lock, self.transaction_lock:
            h = self.get_address_history(address).items()
            received = {}
            sent = {}
            for tx_hash, height in h:
                tx_mined_info = self.get_tx_height(tx_hash)
                txpos = tx_mined_info.txpos if tx_mined_info.txpos is not None else -1
                d = self.db.get_txo_addr(tx_hash, address)
                for n, (v, is_cb) in d.items():
                    received[tx_hash + ':%d'%n] = (height, txpos, v, is_cb)
                l = self.db.get_txi_addr(tx_hash, address)
                for txi, v in l:
                    sent[txi] = tx_hash, height, txpos
        return received, sent

    def get_addr_outputs(self, address: str) -> Dict[TxOutpoint, PartialTxInput]:
        received, sent = self.get_addr_io(address)
        out = {}
        for prevout_str, v in received.items():
            tx_height, tx_pos, value, is_cb = v
            prevout = TxOutpoint.from_str(prevout_str)
            utxo = PartialTxInput(prevout=prevout, is_coinbase_output=is_cb)
            utxo._trusted_address = address
            utxo._trusted_value_sats = value
            utxo.block_height = tx_height
            utxo.block_txpos = tx_pos
            if prevout_str in sent:
                txid, height, pos = sent[prevout_str]
                utxo.spent_txid = txid
                utxo.spent_height = height
            else:
                utxo.spent_txid = None
                utxo.spent_height = None
            out[prevout] = utxo
        return out

    def get_addr_utxo(self, address: str) -> Dict[TxOutpoint, PartialTxInput]:
        out = self.get_addr_outputs(address)
        for k, v in list(out.items()):
            if v.spent_height is not None:
                out.pop(k)
        return out

    # return the total amount ever received by an address
    def get_addr_received(self, address):
        received, sent = self.get_addr_io(address)
        return sum([value for height, pos, value, is_cb in received.values()])

    @with_lock
    @with_transaction_lock
    @with_local_height_cached
    def get_balance(self, domain, *, excluded_addresses: Set[str] = None,
                    excluded_coins: Set[str] = None) -> Tuple[int, int, int]:
        """Return the balance of a set of addresses:
        confirmed and matured, unconfirmed, unmatured
        Note: intended for display-purposes. would need extreme care for "has enough funds" checks (see #8835)
        """
        if excluded_addresses is None:
            excluded_addresses = set()
        assert isinstance(excluded_addresses, set), f"excluded_addresses should be set, not {type(excluded_addresses)}"
        domain = set(domain) - excluded_addresses
        if excluded_coins is None:
            excluded_coins = set()
        assert isinstance(excluded_coins, set), f"excluded_coins should be set, not {type(excluded_coins)}"

        cache_key = sha256(','.join(sorted(domain)) + ';'
                           + ','.join(sorted(excluded_coins)))
        cached_value = self._get_balance_cache.get(cache_key)
        if cached_value:
            return cached_value

        coins = {}
        for address in domain:
            coins.update(self.get_addr_outputs(address))

        c = u = x = 0
        mempool_height = self.get_local_height() + 1  # height of next block
        for utxo in coins.values():  # type: PartialTxInput
            if utxo.spent_height is not None:
                continue
            if utxo.prevout.to_str() in excluded_coins:
                continue
            v = utxo.value_sats()
            tx_height = utxo.block_height
            is_cb = utxo.is_coinbase_output()
            if is_cb and tx_height + COINBASE_MATURITY > mempool_height:
                x += v
            elif tx_height > 0:
                c += v
            else:
                txid = utxo.prevout.txid.hex()
                tx = self.db.get_transaction(txid)
                assert tx is not None # txid comes from get_addr_io
                # we look at the outputs that are spent by this transaction
                # if those outputs are ours and confirmed, we count this coin as confirmed
                confirmed_spent_amount = 0
                for txin in tx.inputs():
                    if txin.prevout in coins:
                        coin = coins[txin.prevout]
                        if coin.block_height > 0:
                            confirmed_spent_amount += coin.value_sats()
                # Compare amount, in case tx has confirmed and unconfirmed inputs, or is a coinjoin.
                # (fixme: tx may have multiple change outputs)
                if confirmed_spent_amount >= v:
                    c += v
                else:
                    c += confirmed_spent_amount
                    u += v - confirmed_spent_amount
        result = c, u, x
        # cache result.
        # Cache needs to be invalidated if a transaction is added to/
        # removed from history; or on new blocks (maturity...)
        self._get_balance_cache[cache_key] = result
        return result

    @with_local_height_cached
    def get_utxos(
            self,
            domain,
            *,
            excluded_addresses=None,
            mature_only: bool = False,
            confirmed_funding_only: bool = False,
            confirmed_spending_only: bool = False,
            nonlocal_only: bool = False,
            block_height: int = None,
    ) -> Sequence[PartialTxInput]:
        if block_height is not None:
            # caller wants the UTXOs we had at a given height; check other parameters
            assert confirmed_funding_only
            assert confirmed_spending_only
            assert nonlocal_only
        else:
            block_height = self.get_local_height()
        coins = []
        domain = set(domain)
        if excluded_addresses:
            domain = set(domain) - set(excluded_addresses)
        mempool_height = block_height + 1  # height of next block
        for addr in domain:
            txos = self.get_addr_outputs(addr)
            for txo in txos.values():
                if txo.spent_height is not None:
                    if not confirmed_spending_only:
                        continue
                    if confirmed_spending_only and 0 < txo.spent_height <= block_height:
                        continue
                if confirmed_funding_only and not (0 < txo.block_height <= block_height):
                    continue
                if nonlocal_only and txo.block_height in (TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE):
                    continue
                if (mature_only and txo.is_coinbase_output()
                        and txo.block_height + COINBASE_MATURITY > mempool_height):
                    continue
                coins.append(txo)
                continue
        return coins

    def is_used(self, address: str) -> bool:
        return self.get_address_history_len(address) != 0

    def is_empty(self, address: str) -> bool:
        coins = self.get_addr_utxo(address)
        return not bool(coins)

    @with_local_height_cached
    def address_is_old(self, address: str, *, req_conf: int = 3) -> bool:
        """Returns whether address has any history that is deeply confirmed.
        Used for reorg-safe(ish) gap limit roll-forward.
        """
        max_conf = -1
        h = self.db.get_addr_history(address)
        needs_spv_check = not self.config.NETWORK_SKIPMERKLECHECK
        for tx_hash, tx_height in h:
            if needs_spv_check:
                tx_age = self.get_tx_height(tx_hash).conf
            else:
                if tx_height <= 0:
                    tx_age = 0
                else:
                    tx_age = self.get_local_height() - tx_height + 1
            max_conf = max(max_conf, tx_age)
        return max_conf >= req_conf
