import threading
from typing import NamedTuple, Iterable
import os
from collections import defaultdict
import asyncio
import jsonrpclib

from .util import PrintError, bh2u, bfh, NoDynamicFeeEstimates, aiosafe
from .lnutil import EncumberedTransaction, Outpoint
from . import wallet
from .storage import WalletStorage
from .address_synchronizer import AddressSynchronizer


TX_MINED_STATUS_DEEP, TX_MINED_STATUS_SHALLOW, TX_MINED_STATUS_MEMPOOL, TX_MINED_STATUS_FREE = range(0, 4)


class LNWatcher(PrintError):
    # TODO if verifier gets an incorrect merkle proof, that tx will never verify!!
    # similarly, what if server ignores request for merkle proof?
    # maybe we should disconnect from server in these cases

    def __init__(self, network):
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
        # TODO structure will need to change when we handle HTLCs......
        # [funding_outpoint_str][ctx_txid] -> set of EncumberedTransaction
        # access with 'lock'
        self.sweepstore = defaultdict(lambda: defaultdict(set))
        for funding_outpoint, ctxs in storage.get('sweepstore', {}).items():
            for ctx_txid, set_of_txns in ctxs.items():
                for e_tx in set_of_txns:
                    e_tx2 = EncumberedTransaction.from_json(e_tx)
                    self.sweepstore[funding_outpoint][ctx_txid].add(e_tx2)

        self.network.register_callback(self.on_network_update,
                                       ['network_updated', 'blockchain_updated', 'verified', 'wallet_updated'])
        # remote watchtower
        watchtower_url = self.config.get('watchtower_url')
        self.watchtower = jsonrpclib.Server(watchtower_url) if watchtower_url else None
        self.watchtower_queue = asyncio.Queue()
        asyncio.run_coroutine_threadsafe(self.watchtower_task(), self.network.asyncio_loop)

    def with_watchtower(func):
        def wrapper(self, *args, **kwargs):
            if self.watchtower:
                self.watchtower_queue.put_nowait((func.__name__, args, kwargs))
            return func(self, *args, **kwargs)
        return wrapper

    async def watchtower_task(self):
        while True:
            name, args, kwargs = await self.watchtower_queue.get()
            self.print_error('sending to watchtower', name, args)
            func = getattr(self.watchtower, name)
            func(*args, **kwargs)

    def write_to_disk(self):
        # FIXME: json => every update takes linear instead of constant disk write
        with self.lock:
            storage = self.addr_sync.storage
            storage.put('channel_info', self.channel_info)
            # self.sweepstore
            sweepstore = {}
            for funding_outpoint, ctxs in self.sweepstore.items():
                sweepstore[funding_outpoint] = {}
                for ctx_txid, set_of_txns in ctxs.items():
                    sweepstore[funding_outpoint][ctx_txid] = [e_tx.to_json() for e_tx in set_of_txns]
            storage.put('sweepstore', sweepstore)
        storage.write()

    def watch_channel(self, address, outpoint):
        self.watch_address(address)
        with self.lock:
            if address not in self.channel_info:
                self.channel_info[address] = outpoint
            self.write_to_disk()

    @aiosafe
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
        keep_watching_this = await self.inspect_ctx_candidate(funding_outpoint, ctx_candidate)
        if not keep_watching_this:
            self.stop_and_delete(funding_outpoint)

    def stop_and_delete(self, funding_outpoint):
        # TODO delete channel from watcher_db
        pass

    async def inspect_ctx_candidate(self, funding_outpoint, ctx):
        """Returns True iff found any not-deeply-spent outputs that we could
        potentially sweep at some point."""
        # make sure we are subscribed to all outputs of ctx
        not_yet_watching = False
        for o in ctx.outputs():
            if o.address not in self.watched_addresses:
                self.watch_address(o.address)
                not_yet_watching = True
        if not_yet_watching:
            return True
        # get all possible responses we have
        ctx_txid = ctx.txid()
        with self.lock:
            encumbered_sweep_txns = self.sweepstore[funding_outpoint][ctx_txid]
        if len(encumbered_sweep_txns) == 0:
            # no useful response for this channel close..
            if self.get_tx_mined_status(ctx_txid) == TX_MINED_STATUS_DEEP:
                self.print_error("channel close detected for {}. but can't sweep anything :(".format(funding_outpoint))
                return False
        # check if any response applies
        keep_watching_this = False
        local_height = self.network.get_local_height()
        for e_tx in encumbered_sweep_txns:
            conflicts = self.addr_sync.get_conflicting_transactions(e_tx.tx.txid(), e_tx.tx, include_self=True)
            conflict_mined_status = self.get_deepest_tx_mined_status_for_txids(conflicts)
            if conflict_mined_status != TX_MINED_STATUS_DEEP:
                keep_watching_this = True
            if conflict_mined_status == TX_MINED_STATUS_FREE:
                tx_height = self.addr_sync.get_tx_height(ctx_txid).height
                num_conf = local_height - tx_height + 1
                if num_conf >= e_tx.csv_delay:
                    try:
                        await self.network.broadcast_transaction(e_tx.tx)
                    except Exception as e:
                        self.print_error('broadcast: {}, {}'.format('failure', repr(e)))
                    else:
                        self.print_error('broadcast: {}'.format('success'))
                else:
                    self.print_error('waiting for CSV ({} < {}) for funding outpoint {} and ctx {}'
                                     .format(num_conf, e_tx.csv_delay, funding_outpoint, ctx.txid()))
        return keep_watching_this

    @with_watchtower
    def add_sweep_tx(self, funding_outpoint: str, ctx_txid: str, encumbered_sweeptx: EncumberedTransaction):
        if encumbered_sweeptx is None:
            return
        with self.lock:
            self.sweepstore[funding_outpoint][ctx_txid].add(encumbered_sweeptx)
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
