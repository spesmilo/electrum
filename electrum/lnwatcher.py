# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import threading
from typing import NamedTuple, Iterable, TYPE_CHECKING
import os
from collections import defaultdict
import asyncio
from enum import IntEnum, auto
from typing import NamedTuple, Dict

import jsonrpclib

from .util import PrintError, bh2u, bfh, log_exceptions, ignore_exceptions
from . import wallet
from .storage import WalletStorage
from .address_synchronizer import AddressSynchronizer, TX_HEIGHT_LOCAL, TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_UNCONFIRMED
from .transaction import Transaction

if TYPE_CHECKING:
    from .network import Network

class ListenerItem(NamedTuple):
    # this is triggered when the lnwatcher is all done with the outpoint used as index in LNWatcher.tx_progress
    all_done : asyncio.Event
    # txs we broadcast are put on this queue so that the test can wait for them to get mined
    tx_queue : asyncio.Queue

class TxMinedDepth(IntEnum):
    """ IntEnum because we call min() in get_deepest_tx_mined_depth_for_txids """
    DEEP = auto()
    SHALLOW = auto()
    MEMPOOL = auto()
    FREE = auto()


class LNWatcher(AddressSynchronizer):
    verbosity_filter = 'W'

    def __init__(self, network: 'Network'):
        path = os.path.join(network.config.path, "watcher_db")
        storage = WalletStorage(path)
        AddressSynchronizer.__init__(self, storage)
        self.config = network.config
        self.start_network(network)
        self.lock = threading.RLock()
        self.channel_info = storage.get('channel_info', {})  # access with 'lock'
        # [funding_outpoint_str][prev_txid] -> set of Transaction
        # prev_txid is the txid of a tx that is watched for confirmations
        # access with 'lock'
        self.sweepstore = defaultdict(lambda: defaultdict(set))
        for funding_outpoint, ctxs in storage.get('sweepstore', {}).items():
            for txid, set_of_txns in ctxs.items():
                for tx in set_of_txns:
                    tx2 = Transaction.from_dict(tx)
                    self.sweepstore[funding_outpoint][txid].add(tx2)

        self.network.register_callback(self.on_network_update,
                                       ['network_updated', 'blockchain_updated', 'verified', 'wallet_updated'])
        self.set_remote_watchtower()
        # this maps funding_outpoints to ListenerItems, which have an event for when the watcher is done,
        # and a queue for seeing which txs are being published
        self.tx_progress = {} # type: Dict[str, ListenerItem]

    def set_remote_watchtower(self):
        watchtower_url = self.config.get('watchtower_url')
        self.watchtower = jsonrpclib.Server(watchtower_url) if watchtower_url else None
        self.watchtower_queue = asyncio.Queue()

    def with_watchtower(func):
        def wrapper(self, *args, **kwargs):
            if self.watchtower:
                self.watchtower_queue.put_nowait((func.__name__, args, kwargs))
            return func(self, *args, **kwargs)
        return wrapper

    @ignore_exceptions
    @log_exceptions
    async def watchtower_task(self):
        self.print_error('watchtower task started')
        while True:
            name, args, kwargs = await self.watchtower_queue.get()
            if self.watchtower is None:
                continue
            func = getattr(self.watchtower, name)
            try:
                r = func(*args, **kwargs)
                self.print_error("watchtower answer", r)
            except:
                self.print_error('could not reach watchtower, will retry in 5s', name, args)
                await asyncio.sleep(5)
                await self.watchtower_queue.put((name, args, kwargs))

    def write_to_disk(self):
        # FIXME: json => every update takes linear instead of constant disk write
        with self.lock:
            storage = self.storage
            storage.put('channel_info', self.channel_info)
            # self.sweepstore
            sweepstore = {}
            for funding_outpoint, ctxs in self.sweepstore.items():
                sweepstore[funding_outpoint] = {}
                for prev_txid, set_of_txns in ctxs.items():
                    sweepstore[funding_outpoint][prev_txid] = [tx.as_dict() for tx in set_of_txns]
            storage.put('sweepstore', sweepstore)
        storage.write()

    @with_watchtower
    def watch_channel(self, address, outpoint):
        self.add_address(address)
        with self.lock:
            if address not in self.channel_info:
                self.channel_info[address] = outpoint
            self.write_to_disk()

    def unwatch_channel(self, address, funding_outpoint):
        self.print_error('unwatching', funding_outpoint)
        with self.lock:
            self.channel_info.pop(address)
            self.sweepstore.pop(funding_outpoint)
            self.write_to_disk()
        if funding_outpoint in self.tx_progress:
            self.tx_progress[funding_outpoint].all_done.set()

    @log_exceptions
    async def on_network_update(self, event, *args):
        if event in ('verified', 'wallet_updated'):
            if args[0] != self:
                return
        if not self.synchronizer:
            self.print_error("synchronizer not set yet")
            return
        if not self.synchronizer.is_up_to_date():
            return
        with self.lock:
            channel_info_items = list(self.channel_info.items())
        for address, outpoint in channel_info_items:
            await self.check_onchain_situation(address, outpoint)

    async def check_onchain_situation(self, address, funding_outpoint):
        keep_watching, spenders = self.inspect_tx_candidate(funding_outpoint, 0)
        txid = spenders.get(funding_outpoint)
        if txid is None:
            self.network.trigger_callback('channel_open', funding_outpoint)
        else:
            self.network.trigger_callback('channel_closed', funding_outpoint, txid, spenders)
            await self.do_breach_remedy(funding_outpoint, spenders)
        if not keep_watching:
            self.unwatch_channel(address, funding_outpoint)
        else:
            self.print_error('we will keep_watching', funding_outpoint)

    def inspect_tx_candidate(self, outpoint, n):
        # FIXME: instead of stopping recursion at n == 2,
        # we should detect which outputs are HTLCs
        prev_txid, index = outpoint.split(':')
        txid = self.spent_outpoints[prev_txid].get(int(index))
        result = {outpoint:txid}
        if txid is None:
            self.print_error('keep watching because outpoint is unspent')
            return True, result
        keep_watching = (self.get_tx_mined_depth(txid) != TxMinedDepth.DEEP)
        if keep_watching:
            self.print_error('keep watching because spending tx is not deep')
        tx = self.transactions[txid]
        for i, o in enumerate(tx.outputs()):
            if o.address not in self.get_addresses():
                self.add_address(o.address)
                keep_watching = True
            elif n < 2:
                k, r = self.inspect_tx_candidate(txid+':%d'%i, n+1)
                keep_watching |= k
                result.update(r)
        return keep_watching, result

    async def do_breach_remedy(self, funding_outpoint, spenders):
        for prevout, spender in spenders.items():
            if spender is not None:
                continue
            prev_txid, prev_n = prevout.split(':')
            with self.lock:
                sweep_txns = self.sweepstore[funding_outpoint][prev_txid]
            for tx in sweep_txns:
                if not await self.broadcast_or_log(funding_outpoint, tx):
                    self.print_error(tx.name, f'could not publish tx: {str(tx)}, prev_txid: {prev_txid}')

    async def broadcast_or_log(self, funding_outpoint, tx):
        height = self.get_tx_height(tx.txid()).height
        if height != TX_HEIGHT_LOCAL:
            return
        try:
            txid = await self.network.broadcast_transaction(tx)
        except Exception as e:
            self.print_error(f'broadcast: {tx.name}: failure: {repr(e)}')
        else:
            self.print_error(f'broadcast: {tx.name}: success. txid: {txid}')
            if funding_outpoint in self.tx_progress:
                await self.tx_progress[funding_outpoint].tx_queue.put(tx)
            return txid

    @with_watchtower
    def add_sweep_tx(self, funding_outpoint: str, prev_txid: str, tx_dict):
        tx = Transaction.from_dict(tx_dict)
        with self.lock:
            self.sweepstore[funding_outpoint][prev_txid].add(tx)
        self.write_to_disk()

    def get_tx_mined_depth(self, txid: str):
        if not txid:
            return TxMinedDepth.FREE
        tx_mined_depth = self.get_tx_height(txid)
        height, conf = tx_mined_depth.height, tx_mined_depth.conf
        if conf > 100:
            return TxMinedDepth.DEEP
        elif conf > 0:
            return TxMinedDepth.SHALLOW
        elif height in (TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT):
            return TxMinedDepth.MEMPOOL
        elif height == TX_HEIGHT_LOCAL:
            return TxMinedDepth.FREE
        elif height > 0 and conf == 0:
            # unverified but claimed to be mined
            return TxMinedDepth.MEMPOOL
        else:
            raise NotImplementedError()
