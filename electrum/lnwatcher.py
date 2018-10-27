# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import threading
from typing import NamedTuple, Iterable, TYPE_CHECKING
import os
from collections import defaultdict
import asyncio

import jsonrpclib

from .util import PrintError, bh2u, bfh, log_exceptions, ignore_exceptions
from .lnutil import EncumberedTransaction
from . import wallet
from .storage import WalletStorage
from .address_synchronizer import AddressSynchronizer

if TYPE_CHECKING:
    from .network import Network


TX_MINED_STATUS_DEEP, TX_MINED_STATUS_SHALLOW, TX_MINED_STATUS_MEMPOOL, TX_MINED_STATUS_FREE = range(0, 4)


class LNWatcher(PrintError):
    # TODO if verifier gets an incorrect merkle proof, that tx will never verify!!
    # similarly, what if server ignores request for merkle proof?
    # maybe we should disconnect from server in these cases
    verbosity_filter = 'W'

    def __init__(self, network: 'Network'):
        self.network = network
        self.config = network.config
        path = os.path.join(network.config.path, "watcher_db")
        storage = WalletStorage(path)
        self.addr_sync = AddressSynchronizer(storage)
        self.addr_sync.diagnostic_name = lambda: 'LnWatcherAS'
        self.addr_sync.start_network(network)
        self.lock = threading.RLock()
        self.watched_addresses = set()
        self.channel_info = storage.get('channel_info', {})  # access with 'lock'
        # [funding_outpoint_str][prev_txid] -> set of EncumberedTransaction
        # prev_txid is the txid of a tx that is watched for confirmations
        # access with 'lock'
        self.sweepstore = defaultdict(lambda: defaultdict(set))
        for funding_outpoint, ctxs in storage.get('sweepstore', {}).items():
            for txid, set_of_txns in ctxs.items():
                for e_tx in set_of_txns:
                    e_tx2 = EncumberedTransaction.from_json(e_tx)
                    self.sweepstore[funding_outpoint][txid].add(e_tx2)

        self.network.register_callback(self.on_network_update,
                                       ['network_updated', 'blockchain_updated', 'verified', 'wallet_updated'])
        # remote watchtower
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
            storage = self.addr_sync.storage
            storage.put('channel_info', self.channel_info)
            # self.sweepstore
            sweepstore = {}
            for funding_outpoint, ctxs in self.sweepstore.items():
                sweepstore[funding_outpoint] = {}
                for prev_txid, set_of_txns in ctxs.items():
                    sweepstore[funding_outpoint][prev_txid] = [e_tx.to_json() for e_tx in set_of_txns]
            storage.put('sweepstore', sweepstore)
        storage.write()

    @with_watchtower
    def watch_channel(self, address, outpoint):
        self.watch_address(address)
        with self.lock:
            if address not in self.channel_info:
                self.channel_info[address] = outpoint
            self.write_to_disk()

    @log_exceptions
    async def on_network_update(self, event, *args):
        if event in ('verified', 'wallet_updated'):
            wallet = args[0]
            if wallet != self.addr_sync:
                return
        if not self.addr_sync.synchronizer:
            self.print_error("synchronizer not set yet")
            return
        if not self.addr_sync.synchronizer.is_up_to_date():
            return
        with self.lock:
            channel_info_items = list(self.channel_info.items())
        for address, outpoint in channel_info_items:
            await self.check_onchain_situation(outpoint)

    def watch_address(self, addr):
        with self.lock:
            self.watched_addresses.add(addr)
            self.addr_sync.add_address(addr)

    async def check_onchain_situation(self, funding_outpoint):
        txid, index = funding_outpoint.split(':')
        ctx_candidate_txid = self.addr_sync.spent_outpoints[txid].get(int(index))
        is_spent = ctx_candidate_txid is not None
        self.network.trigger_callback('channel_txo', funding_outpoint, is_spent)
        if not is_spent:
            return
        ctx_candidate = self.addr_sync.transactions.get(ctx_candidate_txid)
        if ctx_candidate is None:
            return
        #self.print_error("funding outpoint {} is spent by {}"
        #                 .format(funding_outpoint, ctx_candidate_txid))
        conf = self.addr_sync.get_tx_height(ctx_candidate_txid).conf
        # only care about confirmed and verified ctxs. TODO is this necessary?
        if conf == 0:
            return
        keep_watching_this = await self.inspect_tx_candidate(funding_outpoint, ctx_candidate)
        if not keep_watching_this:
            self.stop_and_delete(funding_outpoint)

    def stop_and_delete(self, funding_outpoint):
        # TODO delete channel from watcher_db
        pass

    async def inspect_tx_candidate(self, funding_outpoint, prev_tx):
        """Returns True iff found any not-deeply-spent outputs that we could
        potentially sweep at some point."""
        # make sure we are subscribed to all outputs of tx
        not_yet_watching = False
        for o in prev_tx.outputs():
            if o.address not in self.watched_addresses:
                self.watch_address(o.address)
                not_yet_watching = True
        if not_yet_watching:
            return True
        # get all possible responses we have
        prev_txid = prev_tx.txid()
        with self.lock:
            encumbered_sweep_txns = self.sweepstore[funding_outpoint][prev_txid]
        if len(encumbered_sweep_txns) == 0:
            if self.get_tx_mined_status(prev_txid) == TX_MINED_STATUS_DEEP:
                return False
        # check if any response applies
        keep_watching_this = False
        local_height = self.network.get_local_height()
        for e_tx in list(encumbered_sweep_txns):
            conflicts = self.addr_sync.get_conflicting_transactions(e_tx.tx.txid(), e_tx.tx, include_self=True)
            conflict_mined_status = self.get_deepest_tx_mined_status_for_txids(conflicts)
            if conflict_mined_status != TX_MINED_STATUS_DEEP:
                keep_watching_this = True
            if conflict_mined_status == TX_MINED_STATUS_FREE:
                tx_height = self.addr_sync.get_tx_height(prev_txid).height
                num_conf = local_height - tx_height + 1
                broadcast = True
                if e_tx.cltv_expiry:
                    if local_height > e_tx.cltv_expiry:
                        self.print_error('CLTV ({} > {}) fulfilled'.format(local_height, e_tx.cltv_expiry))
                    else:
                        self.print_error('waiting for {}: CLTV ({} > {}), funding outpoint {} and tx {}'
                                .format(e_tx.name, local_height, e_tx.cltv_expiry, funding_outpoint[:8], prev_tx.txid()[:8]))
                        broadcast = False
                if e_tx.csv_delay:
                    if num_conf < e_tx.csv_delay:
                        self.print_error('waiting for {}: CSV ({} >= {}), funding outpoint {} and tx {}'
                                .format(e_tx.name, num_conf, e_tx.csv_delay, funding_outpoint[:8], prev_tx.txid()[:8]))
                        broadcast = False
                if broadcast:
                    if not await self.broadcast_or_log(e_tx):
                        self.print_error(f'encumbered tx: {str(e_tx)}, prev_txid: {prev_txid}')
            else:
                # not mined or in mempool
                keep_watching_this |= await self.inspect_tx_candidate(funding_outpoint, e_tx.tx)

        return keep_watching_this

    async def broadcast_or_log(self, e_tx):
        try:
            txid = await self.network.broadcast_transaction(e_tx.tx)
        except Exception as e:
            self.print_error(f'broadcast: {e_tx.name}: failure: {repr(e)}')
        else:
            self.print_error(f'broadcast: {e_tx.name}: success. txid: {txid}')

    @with_watchtower
    def add_sweep_tx(self, funding_outpoint: str, prev_txid: str, sweeptx):
        encumbered_sweeptx = EncumberedTransaction.from_json(sweeptx)
        with self.lock:
            self.sweepstore[funding_outpoint][prev_txid].add(encumbered_sweeptx)
        self.write_to_disk()

    def get_tx_mined_status(self, txid: str):
        if not txid:
            return TX_MINED_STATUS_FREE
        tx_mined_status = self.addr_sync.get_tx_height(txid)
        height, conf = tx_mined_status.height, tx_mined_status.conf
        if conf > 100:
            return TX_MINED_STATUS_DEEP
        elif conf > 0:
            return TX_MINED_STATUS_SHALLOW
        elif height in (wallet.TX_HEIGHT_UNCONFIRMED, wallet.TX_HEIGHT_UNCONF_PARENT):
            return TX_MINED_STATUS_MEMPOOL
        elif height == wallet.TX_HEIGHT_LOCAL:
            return TX_MINED_STATUS_FREE
        elif height > 0 and conf == 0:
            # unverified but claimed to be mined
            return TX_MINED_STATUS_MEMPOOL
        else:
            raise NotImplementedError()

    def get_deepest_tx_mined_status_for_txids(self, set_of_txids: Iterable[str]):
        if not set_of_txids:
            return TX_MINED_STATUS_FREE
        # note: using "min" as lower status values are deeper
        return min(map(self.get_tx_mined_status, set_of_txids))
