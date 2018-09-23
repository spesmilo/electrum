import threading
from typing import Optional, NamedTuple, Iterable
import os
from collections import defaultdict

from .util import PrintError, bh2u, bfh, NoDynamicFeeEstimates, aiosafe
from .lnutil import (extract_ctn_from_tx_and_chan, derive_privkey,
                     get_per_commitment_secret_from_seed, derive_pubkey,
                     make_commitment_output_to_remote_address,
                     RevocationStore, Outpoint)
from . import lnutil
from .bitcoin import redeem_script_to_address, TYPE_ADDRESS
from . import transaction
from .transaction import Transaction, TxOutput
from . import ecc
from . import wallet
from .simple_config import SimpleConfig, FEERATE_FALLBACK_STATIC_FEE
from .storage import WalletStorage
from .address_synchronizer import AddressSynchronizer


TX_MINED_STATUS_DEEP, TX_MINED_STATUS_SHALLOW, TX_MINED_STATUS_MEMPOOL, TX_MINED_STATUS_FREE = range(0, 4)


class EncumberedTransaction(NamedTuple("EncumberedTransaction", [('tx', Transaction),
                                                                 ('csv_delay', Optional[int])])):
    def to_json(self) -> dict:
        return {
            'tx': str(self.tx),
            'csv_delay': self.csv_delay,
        }

    @classmethod
    def from_json(cls, d: dict):
        d2 = dict(d)
        d2['tx'] = Transaction(d['tx'])
        return EncumberedTransaction(**d2)


class ChannelWatchInfo(NamedTuple("ChannelWatchInfo", [('outpoint', Outpoint),
                                                       ('sweep_address', str),
                                                       ('local_pubkey', bytes),
                                                       ('remote_pubkey', bytes),
                                                       ('last_ctn_our_ctx', int),
                                                       ('last_ctn_their_ctx', int),
                                                       ('last_ctn_revoked_pcs', int)])):
    def to_json(self) -> dict:
        return {
            'outpoint': self.outpoint,
            'sweep_address': self.sweep_address,
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

        self.network.register_callback(self.on_network_update, ['updated'])

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

    def watch_channel(self, chan, sweep_address, callback_funding_txo_spent):
        address = chan.get_funding_address()
        self.watch_address(address)
        with self.lock:
            if address not in self.channel_info:
                self.channel_info[address] = ChannelWatchInfo(outpoint=chan.funding_outpoint,
                                                              sweep_address=sweep_address,
                                                              local_pubkey=chan.local_config.payment_basepoint.pubkey,
                                                              remote_pubkey=chan.remote_config.payment_basepoint.pubkey,
                                                              last_ctn_our_ctx=0,
                                                              last_ctn_their_ctx=0,
                                                              last_ctn_revoked_pcs=-1)
            self.funding_txo_spent_callback[chan.funding_outpoint] = callback_funding_txo_spent
            self.write_to_disk()

    @aiosafe
    async def on_network_update(self, event, *args):
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
                    await self.network.broadcast_transaction(e_tx.tx, self.print_tx_broadcast_result)
                else:
                    self.print_error('waiting for CSV ({} < {}) for funding outpoint {} and ctx {}'
                                     .format(num_conf, e_tx.csv_delay, funding_outpoint, ctx.txid()))
        return keep_watching_this

    def _get_sweep_address_for_chan(self, chan) -> str:
        funding_address = chan.get_funding_address()
        try:
            channel_info = self.channel_info[funding_address]
        except KeyError:
            # this is used during channel opening, as we only start watching
            # the channel once it gets into the "opening" state, but we need to
            # process the first ctx before that.
            return chan.sweep_address
        return channel_info.sweep_address

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

    # TODO batch sweeps
    # TODO sweep HTLC outputs
    def process_new_offchain_ctx(self, chan, ctx, ours: bool):
        funding_address = chan.get_funding_address()
        ctn = extract_ctn_from_tx_and_chan(ctx, chan)
        latest_ctn_on_channel = chan.local_state.ctn if ours else chan.remote_state.ctn
        last_ctn_watcher_saw = self._get_last_ctn_for_processed_ctx(funding_address, ours)
        if latest_ctn_on_channel + 1 != ctn:
            raise Exception('unexpected ctn {}. latest is {}. our ctx: {}'.format(ctn, latest_ctn_on_channel, ours))
        if last_ctn_watcher_saw + 1 != ctn:
            raise Exception('watcher skipping ctns!! ctn {}. last seen {}. our ctx: {}'.format(ctn, last_ctn_watcher_saw, ours))
        #self.print_error("process_new_offchain_ctx. funding {}, ours {}, ctn {}, ctx {}"
        #      .format(chan.funding_outpoint.to_str(), ours, ctn, ctx.txid()))
        sweep_address = self._get_sweep_address_for_chan(chan)
        if ours:
            our_per_commitment_secret = get_per_commitment_secret_from_seed(
                chan.local_state.per_commitment_secret_seed, RevocationStore.START_INDEX - ctn)
            our_cur_pcp = ecc.ECPrivkey(our_per_commitment_secret).get_public_key_bytes(compressed=True)
            encumbered_sweeptx = maybe_create_sweeptx_for_our_ctx_to_local(chan, ctx, our_cur_pcp, sweep_address)
        else:
            their_cur_pcp = chan.remote_state.next_per_commitment_point
            encumbered_sweeptx = maybe_create_sweeptx_for_their_ctx_to_remote(chan, ctx, their_cur_pcp, sweep_address)
        self.add_to_sweepstore(chan.funding_outpoint.to_str(), ctx.txid(), encumbered_sweeptx)
        self._inc_last_ctn_for_processed_ctx(funding_address, ours)
        self.write_to_disk()

    def process_new_revocation_secret(self, chan, per_commitment_secret: bytes):
        funding_address = chan.get_funding_address()
        ctx = chan.remote_commitment_to_be_revoked
        ctn = extract_ctn_from_tx_and_chan(ctx, chan)
        latest_ctn_on_channel = chan.remote_state.ctn
        last_ctn_watcher_saw = self._get_last_ctn_for_revoked_secret(funding_address)
        if latest_ctn_on_channel != ctn:
            raise Exception('unexpected ctn {}. latest is {}'.format(ctn, latest_ctn_on_channel))
        if last_ctn_watcher_saw + 1 != ctn:
            raise Exception('watcher skipping ctns!! ctn {}. last seen {}'.format(ctn, last_ctn_watcher_saw))
        sweep_address = self._get_sweep_address_for_chan(chan)
        encumbered_sweeptx = maybe_create_sweeptx_for_their_ctx_to_local(chan, ctx, per_commitment_secret, sweep_address)
        self.add_to_sweepstore(chan.funding_outpoint.to_str(), ctx.txid(), encumbered_sweeptx)
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


    def print_tx_broadcast_result(self, name, res):
        error, msg = res
        if error:
            self.print_error('{} broadcast failed: {}'.format(name, msg))
        else:
            self.print_error('{} broadcast succeeded'.format(name))



def maybe_create_sweeptx_for_their_ctx_to_remote(chan, ctx, their_pcp: bytes,
                                                 sweep_address) -> Optional[EncumberedTransaction]:
    assert isinstance(their_pcp, bytes)
    payment_bp_privkey = ecc.ECPrivkey(chan.local_config.payment_basepoint.privkey)
    our_payment_privkey = derive_privkey(payment_bp_privkey.secret_scalar, their_pcp)
    our_payment_privkey = ecc.ECPrivkey.from_secret_scalar(our_payment_privkey)
    our_payment_pubkey = our_payment_privkey.get_public_key_bytes(compressed=True)
    to_remote_address = make_commitment_output_to_remote_address(our_payment_pubkey)
    for output_idx, (type_, addr, val) in enumerate(ctx.outputs()):
        if type_ == TYPE_ADDRESS and addr == to_remote_address:
            break
    else:
        return None
    sweep_tx = create_sweeptx_their_ctx_to_remote(address=sweep_address,
                                                  ctx=ctx,
                                                  output_idx=output_idx,
                                                  our_payment_privkey=our_payment_privkey)
    return EncumberedTransaction(sweep_tx, csv_delay=0)


def maybe_create_sweeptx_for_their_ctx_to_local(chan, ctx, per_commitment_secret: bytes,
                                                sweep_address) -> Optional[EncumberedTransaction]:
    assert isinstance(per_commitment_secret, bytes)
    per_commitment_point = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    revocation_privkey = lnutil.derive_blinded_privkey(chan.local_config.revocation_basepoint.privkey,
                                                       per_commitment_secret)
    revocation_pubkey = ecc.ECPrivkey(revocation_privkey).get_public_key_bytes(compressed=True)
    to_self_delay = chan.local_config.to_self_delay
    delayed_pubkey = derive_pubkey(chan.remote_config.delayed_basepoint.pubkey,
                                   per_commitment_point)
    witness_script = bh2u(lnutil.make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, delayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    for output_idx, o in enumerate(ctx.outputs()):
        if o.type == TYPE_ADDRESS and o.address == to_local_address:
            break
    else:
        return None
    sweep_tx = create_sweeptx_ctx_to_local(address=sweep_address,
                                           ctx=ctx,
                                           output_idx=output_idx,
                                           witness_script=witness_script,
                                           privkey=revocation_privkey,
                                           is_revocation=True)
    return EncumberedTransaction(sweep_tx, csv_delay=0)


def maybe_create_sweeptx_for_our_ctx_to_local(chan, ctx, our_pcp: bytes,
                                              sweep_address) -> Optional[EncumberedTransaction]:
    assert isinstance(our_pcp, bytes)
    delayed_bp_privkey = ecc.ECPrivkey(chan.local_config.delayed_basepoint.privkey)
    our_localdelayed_privkey = derive_privkey(delayed_bp_privkey.secret_scalar, our_pcp)
    our_localdelayed_privkey = ecc.ECPrivkey.from_secret_scalar(our_localdelayed_privkey)
    our_localdelayed_pubkey = our_localdelayed_privkey.get_public_key_bytes(compressed=True)
    revocation_pubkey = lnutil.derive_blinded_pubkey(chan.remote_config.revocation_basepoint.pubkey,
                                                     our_pcp)
    to_self_delay = chan.remote_config.to_self_delay
    witness_script = bh2u(lnutil.make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, our_localdelayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    for output_idx, o in enumerate(ctx.outputs()):
        if o.type == TYPE_ADDRESS and o.address == to_local_address:
            break
    else:
        return None
    sweep_tx = create_sweeptx_ctx_to_local(address=sweep_address,
                                           ctx=ctx,
                                           output_idx=output_idx,
                                           witness_script=witness_script,
                                           privkey=our_localdelayed_privkey.get_secret_bytes(),
                                           is_revocation=False,
                                           to_self_delay=to_self_delay)

    return EncumberedTransaction(sweep_tx, csv_delay=to_self_delay)


def create_sweeptx_their_ctx_to_remote(address, ctx, output_idx: int, our_payment_privkey: ecc.ECPrivkey,
                                       fee_per_kb: int=None) -> Transaction:
    our_payment_pubkey = our_payment_privkey.get_public_key_hex(compressed=True)
    val = ctx.outputs()[output_idx].value
    sweep_inputs = [{
        'type': 'p2wpkh',
        'x_pubkeys': [our_payment_pubkey],
        'num_sig': 1,
        'prevout_n': output_idx,
        'prevout_hash': ctx.txid(),
        'value': val,
        'coinbase': False,
        'signatures': [None],
    }]
    tx_size_bytes = 110  # approx size of p2wpkh->p2wpkh
    if fee_per_kb is None: fee_per_kb = FEERATE_FALLBACK_STATIC_FEE
    fee = SimpleConfig.estimate_fee_for_feerate(fee_per_kb, tx_size_bytes)
    sweep_outputs = [TxOutput(TYPE_ADDRESS, address, val-fee)]
    sweep_tx = Transaction.from_io(sweep_inputs, sweep_outputs)
    sweep_tx.set_rbf(True)
    sweep_tx.sign({our_payment_pubkey: (our_payment_privkey.get_secret_bytes(), True)})
    if not sweep_tx.is_complete():
        raise Exception('channel close sweep tx is not complete')
    return sweep_tx


def create_sweeptx_ctx_to_local(address, ctx, output_idx: int, witness_script: str,
                                privkey: bytes, is_revocation: bool,
                                to_self_delay: int=None,
                                fee_per_kb: int=None) -> Transaction:
    """Create a txn that sweeps the 'to_local' output of a commitment
    transaction into our wallet.

    privkey: either revocation_privkey or localdelayed_privkey
    is_revocation: tells us which ^
    """
    val = ctx.outputs()[output_idx].value
    sweep_inputs = [{
        'scriptSig': '',
        'type': 'p2wsh',
        'signatures': [],
        'num_sig': 0,
        'prevout_n': output_idx,
        'prevout_hash': ctx.txid(),
        'value': val,
        'coinbase': False,
        'preimage_script': witness_script,
    }]
    if to_self_delay is not None:
        sweep_inputs[0]['sequence'] = to_self_delay
    tx_size_bytes = 121  # approx size of to_local -> p2wpkh
    if fee_per_kb is None: fee_per_kb = FEERATE_FALLBACK_STATIC_FEE
    fee = SimpleConfig.estimate_fee_for_feerate(fee_per_kb, tx_size_bytes)
    sweep_outputs = [TxOutput(TYPE_ADDRESS, address, val - fee)]
    sweep_tx = Transaction.from_io(sweep_inputs, sweep_outputs, version=2)
    sig = sweep_tx.sign_txin(0, privkey)
    witness = transaction.construct_witness([sig, int(is_revocation), witness_script])
    sweep_tx.inputs()[0]['witness'] = witness
    return sweep_tx
