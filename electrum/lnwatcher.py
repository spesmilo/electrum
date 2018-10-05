import threading
from typing import NamedTuple, Iterable
import os
from collections import defaultdict

from .util import PrintError, bh2u, bfh, NoDynamicFeeEstimates, aiosafe
from .lnutil import EncumberedTransaction, Outpoint
from . import wallet
from .storage import WalletStorage
from .address_synchronizer import AddressSynchronizer


TX_MINED_STATUS_DEEP, TX_MINED_STATUS_SHALLOW, TX_MINED_STATUS_MEMPOOL, TX_MINED_STATUS_FREE = range(0, 4)




class ChannelWatchInfo(NamedTuple("ChannelWatchInfo", [('outpoint', Outpoint),
                                                       ('local_pubkey', bytes),
                                                       ('remote_pubkey', bytes),
                                                       ('last_ctn_our_ctx', int),
                                                       ('last_ctn_their_ctx', int),
                                                       ('last_ctn_revoked_pcs', int)])):
    def to_json(self) -> dict:
        return {
            'outpoint': self.outpoint,
            'local_pubkey': bh2u(self.local_pubkey),
            'remote_pubkey': bh2u(self.remote_pubkey),
            'last_ctn_our_ctx': self.last_ctn_our_ctx,
            'last_ctn_their_ctx': self.last_ctn_their_ctx,
            'last_ctn_revoked_pcs': self.last_ctn_revoked_pcs,
        }

    @classmethod
    def from_json(cls, d: dict):
        d2 = dict(d)
        d2['outpoint'] = Outpoint(*d['outpoint'])
        d2['local_pubkey'] = bfh(d['local_pubkey'])
        d2['remote_pubkey'] = bfh(d['remote_pubkey'])
        return ChannelWatchInfo(**d2)


class LNWatcher(PrintError):
    # TODO if verifier gets an incorrect merkle proof, that tx will never verify!!
    # similarly, what if server ignores request for merkle proof?
    # maybe we should disconnect from server in these cases

    def __init__(self, network):
        self.network = network

        path = os.path.join(network.config.path, "watcher_db")
        storage = WalletStorage(path)
        self.addr_sync = AddressSynchronizer(storage)
        self.addr_sync.start_network(network)
        self.lock = threading.RLock()
        self.watched_addresses = set()

        self.channel_info = {k: ChannelWatchInfo.from_json(v)
                             for k,v in storage.get('channel_info', {}).items()}  # access with 'lock'
        self.funding_txo_spent_callback = {}  # funding_outpoint -> callback

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

    def write_to_disk(self):
        # FIXME: json => every update takes linear instead of constant disk write
        with self.lock:
            storage = self.addr_sync.storage
            # self.channel_info
            channel_info = {k: v.to_json() for k,v in self.channel_info.items()}
            storage.put('channel_info', channel_info)
            # self.sweepstore
            sweepstore = {}
            for funding_outpoint, ctxs in self.sweepstore.items():
                sweepstore[funding_outpoint] = {}
                for ctx_txid, set_of_txns in ctxs.items():
                    sweepstore[funding_outpoint][ctx_txid] = [e_tx.to_json() for e_tx in set_of_txns]
            storage.put('sweepstore', sweepstore)
        storage.write()

    def watch_channel(self, chan, callback_funding_txo_spent):
        address = chan.get_funding_address()
        self.watch_address(address)
        with self.lock:
            if address not in self.channel_info:
                self.channel_info[address] = ChannelWatchInfo(outpoint=chan.funding_outpoint,
                                                              local_pubkey=chan.local_config.payment_basepoint.pubkey,
                                                              remote_pubkey=chan.remote_config.payment_basepoint.pubkey,
                                                              last_ctn_our_ctx=0,
                                                              last_ctn_their_ctx=0,
                                                              last_ctn_revoked_pcs=-1)
            self.funding_txo_spent_callback[chan.funding_outpoint] = callback_funding_txo_spent
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
        for address, info in channel_info_items:
            await self.check_onchain_situation(info.outpoint)

    def watch_address(self, addr):
        with self.lock:
            self.watched_addresses.add(addr)
            self.addr_sync.add_address(addr)

    async def check_onchain_situation(self, funding_outpoint):
        ctx_candidate_txid = self.addr_sync.spent_outpoints[funding_outpoint.txid].get(funding_outpoint.output_index)
        # call funding_txo_spent_callback if there is one
        is_funding_txo_spent = ctx_candidate_txid is not None
        cb = self.funding_txo_spent_callback.get(funding_outpoint)
        if cb: cb(is_funding_txo_spent)
        if not is_funding_txo_spent:
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
            encumbered_sweep_txns = self.sweepstore[funding_outpoint.to_str()][ctx_txid]
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
                    result = await self.network.broadcast_transaction(e_tx.tx)
                    self.print_tx_broadcast_result(result)
                else:
                    self.print_error('waiting for CSV ({} < {}) for funding outpoint {} and ctx {}'
                                     .format(num_conf, e_tx.csv_delay, funding_outpoint, ctx.txid()))
        return keep_watching_this

    def _get_last_ctn_for_processed_ctx(self, funding_address: str, ours: bool) -> int:
        try:
            ci = self.channel_info[funding_address]
        except KeyError:
            return -1
        if ours:
            return ci.last_ctn_our_ctx
        else:
            return ci.last_ctn_their_ctx

    def _inc_last_ctn_for_processed_ctx(self, funding_address: str, ours: bool) -> None:
        try:
            ci = self.channel_info[funding_address]
        except KeyError:
            return
        if ours:
            ci = ci._replace(last_ctn_our_ctx=ci.last_ctn_our_ctx + 1)
        else:
            ci = ci._replace(last_ctn_their_ctx=ci.last_ctn_their_ctx + 1)
        self.channel_info[funding_address] = ci

    def _get_last_ctn_for_revoked_secret(self, funding_address: str) -> int:
        try:
            ci = self.channel_info[funding_address]
        except KeyError:
            return -1
        return ci.last_ctn_revoked_pcs

    def _inc_last_ctn_for_revoked_secret(self, funding_address: str) -> None:
        try:
            ci = self.channel_info[funding_address]
        except KeyError:
            return
        ci = ci._replace(last_ctn_revoked_pcs=ci.last_ctn_revoked_pcs + 1)
        self.channel_info[funding_address] = ci

    def add_offchain_ctx(self, ctn, funding_address, ours, outpoint, ctx_id, encumbered_sweeptx):
        last_ctn_watcher_saw = self._get_last_ctn_for_processed_ctx(funding_address, ours)
        if last_ctn_watcher_saw + 1 != ctn:
            raise Exception('watcher skipping ctns!! ctn {}. last seen {}. our ctx: {}'.format(ctn, last_ctn_watcher_saw, ours))
        self.add_to_sweepstore(outpoint, ctx_id, encumbered_sweeptx)
        self._inc_last_ctn_for_processed_ctx(funding_address, ours)
        self.write_to_disk()

    def add_revocation_secret(self, ctn, funding_address, outpoint, ctx_id, encumbered_sweeptx):
        last_ctn_watcher_saw = self._get_last_ctn_for_revoked_secret(funding_address)
        if last_ctn_watcher_saw + 1 != ctn:
            raise Exception('watcher skipping ctns!! ctn {}. last seen {}'.format(ctn, last_ctn_watcher_saw))
        self.add_to_sweepstore(outpoint, ctx_id, encumbered_sweeptx)
        self._inc_last_ctn_for_revoked_secret(funding_address)
        self.write_to_disk()

    def add_to_sweepstore(self, funding_outpoint: str, ctx_txid: str, encumbered_sweeptx: EncumberedTransaction):
        if encumbered_sweeptx is None:
            return
        with self.lock:
            self.sweepstore[funding_outpoint][ctx_txid].add(encumbered_sweeptx)

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


    def print_tx_broadcast_result(self, res):
        success, msg = res
        self.print_error('broadcast: {}, {}'.format('success' if success else 'failure', msg))
