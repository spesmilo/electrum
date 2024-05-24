# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import Optional, Dict, List, Tuple, TYPE_CHECKING, NamedTuple, Callable
from enum import Enum, auto

from .util import bfh
from .bitcoin import redeem_script_to_address, dust_threshold, construct_witness
from .invoices import PR_PAID
from . import descriptor
from . import ecc
from .lnutil import (make_commitment_output_to_remote_address, make_commitment_output_to_local_witness_script,
                     derive_privkey, derive_pubkey, derive_blinded_pubkey, derive_blinded_privkey,
                     make_htlc_tx_witness, make_htlc_tx_with_open_channel, UpdateAddHtlc,
                     LOCAL, REMOTE, make_htlc_output_witness_script,
                     get_ordered_channel_configs, privkey_to_pubkey, get_per_commitment_secret_from_seed,
                     RevocationStore, extract_ctn_from_tx_and_chan, UnableToDeriveSecret, SENT, RECEIVED,
                     map_htlcs_to_ctx_output_idxs, Direction)
from .transaction import (Transaction, TxOutput, PartialTransaction, PartialTxInput,
                          PartialTxOutput, TxOutpoint)
from .simple_config import SimpleConfig
from .logging import get_logger, Logger

if TYPE_CHECKING:
    from .lnchannel import Channel, AbstractChannel


_logger = get_logger(__name__)
# note: better to use chan.logger instead, when applicable


class SweepInfo(NamedTuple):
    name: str
    csv_delay: int
    cltv_abs: int
    gen_tx: Callable[[], Optional[Transaction]]


def create_sweeptxs_for_watchtower(chan: 'Channel', ctx: Transaction, per_commitment_secret: bytes,
                                   sweep_address: str) -> List[Transaction]:
    """Presign sweeping transactions using the just received revoked pcs.
    These will only be utilised if the remote breaches.
    Sweep 'to_local', and all the HTLCs (two cases: directly from ctx, or from HTLC tx).
    """
    # prep
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    this_conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=False)
    other_revocation_privkey = derive_blinded_privkey(other_conf.revocation_basepoint.privkey,
                                                      per_commitment_secret)
    to_self_delay = other_conf.to_self_delay
    this_delayed_pubkey = derive_pubkey(this_conf.delayed_basepoint.pubkey, pcp)
    txs = []
    # to_local
    revocation_pubkey = ecc.ECPrivkey(other_revocation_privkey).get_public_key_bytes(compressed=True)
    witness_script = make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, this_delayed_pubkey)
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    output_idxs = ctx.get_output_idxs_from_address(to_local_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        sweep_tx = create_sweeptx_ctx_to_local(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            witness_script=witness_script,
            privkey=other_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config)
        if sweep_tx:
            txs.append(sweep_tx)
    # HTLCs
    def create_sweeptx_for_htlc(*, htlc: 'UpdateAddHtlc', htlc_direction: Direction,
                                ctx_output_idx: int) -> Optional[Transaction]:
        htlc_tx_witness_script, htlc_tx = make_htlc_tx_with_open_channel(
            chan=chan,
            pcp=pcp,
            subject=REMOTE,
            ctn=ctn,
            htlc_direction=htlc_direction,
            commit=ctx,
            htlc=htlc,
            ctx_output_idx=ctx_output_idx)
        return create_sweeptx_that_spends_htlctx_that_spends_htlc_in_ctx(
            htlc_tx=htlc_tx,
            htlctx_witness_script=htlc_tx_witness_script,
            sweep_address=sweep_address,
            privkey=other_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config)

    htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(
        chan=chan,
        ctx=ctx,
        pcp=pcp,
        subject=REMOTE,
        ctn=ctn)
    for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
        secondstage_sweep_tx = create_sweeptx_for_htlc(
            htlc=htlc,
            htlc_direction=direction,
            ctx_output_idx=ctx_output_idx)
        if secondstage_sweep_tx:
            txs.append(secondstage_sweep_tx)
    return txs


def create_sweeptx_for_their_revoked_ctx(
        chan: 'Channel',
        ctx: Transaction,
        per_commitment_secret: bytes,
        sweep_address: str) -> Optional[Callable[[], Optional[Transaction]]]:
    # prep
    pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    this_conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=False)
    other_revocation_privkey = derive_blinded_privkey(other_conf.revocation_basepoint.privkey,
                                                      per_commitment_secret)
    to_self_delay = other_conf.to_self_delay
    this_delayed_pubkey = derive_pubkey(this_conf.delayed_basepoint.pubkey, pcp)
    txs = []
    # to_local
    revocation_pubkey = ecc.ECPrivkey(other_revocation_privkey).get_public_key_bytes(compressed=True)
    witness_script = make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, this_delayed_pubkey)
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    output_idxs = ctx.get_output_idxs_from_address(to_local_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        sweep_tx = lambda: create_sweeptx_ctx_to_local(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            witness_script=witness_script,
            privkey=other_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config)
        return sweep_tx
    return None


def create_sweeptx_for_their_revoked_htlc(
        chan: 'Channel',
        ctx: Transaction,
        htlc_tx: Transaction,
        sweep_address: str) -> Optional[SweepInfo]:

    x = analyze_ctx(chan, ctx)
    if not x:
        return
    ctn, their_pcp, is_revocation, per_commitment_secret = x
    if not is_revocation:
        return
    # prep
    pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    this_conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=False)
    other_revocation_privkey = derive_blinded_privkey(
        other_conf.revocation_basepoint.privkey,
        per_commitment_secret)
    to_self_delay = other_conf.to_self_delay
    this_delayed_pubkey = derive_pubkey(this_conf.delayed_basepoint.pubkey, pcp)
    # same witness script as to_local
    revocation_pubkey = ecc.ECPrivkey(other_revocation_privkey).get_public_key_bytes(compressed=True)
    witness_script = make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, this_delayed_pubkey)
    htlc_address = redeem_script_to_address('p2wsh', witness_script)
    # check that htlc_tx is a htlc
    if htlc_tx.outputs()[0].address != htlc_address:
        return
    gen_tx = lambda: create_sweeptx_that_spends_htlctx_that_spends_htlc_in_ctx(
        sweep_address=sweep_address,
        htlc_tx=htlc_tx,
        htlctx_witness_script=witness_script,
        privkey=other_revocation_privkey,
        is_revocation=True,
        config=chan.lnworker.config)
    return SweepInfo(
        name='redeem_htlc2',
        csv_delay=0,
        cltv_abs=0,
        gen_tx=gen_tx)


def create_sweeptxs_for_our_ctx(
        *, chan: 'AbstractChannel',
        ctx: Transaction,
        sweep_address: str) -> Optional[Dict[str, SweepInfo]]:
    """Handle the case where we force close unilaterally with our latest ctx.
    Construct sweep txns for 'to_local', and for all HTLCs (2 txns each).
    'to_local' can be swept even if this is a breach (by us),
    but HTLCs cannot (old HTLCs are no longer stored).
    """
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    our_conf, their_conf = get_ordered_channel_configs(chan=chan, for_us=True)
    our_per_commitment_secret = get_per_commitment_secret_from_seed(
        our_conf.per_commitment_secret_seed, RevocationStore.START_INDEX - ctn)
    our_pcp = ecc.ECPrivkey(our_per_commitment_secret).get_public_key_bytes(compressed=True)
    our_delayed_bp_privkey = ecc.ECPrivkey(our_conf.delayed_basepoint.privkey)
    our_localdelayed_privkey = derive_privkey(our_delayed_bp_privkey.secret_scalar, our_pcp)
    our_localdelayed_privkey = ecc.ECPrivkey.from_secret_scalar(our_localdelayed_privkey)
    their_revocation_pubkey = derive_blinded_pubkey(their_conf.revocation_basepoint.pubkey, our_pcp)
    to_self_delay = their_conf.to_self_delay
    our_htlc_privkey = derive_privkey(secret=int.from_bytes(our_conf.htlc_basepoint.privkey, 'big'),
                                       per_commitment_point=our_pcp).to_bytes(32, 'big')
    our_localdelayed_pubkey = our_localdelayed_privkey.get_public_key_bytes(compressed=True)
    to_local_witness_script = make_commitment_output_to_local_witness_script(
        their_revocation_pubkey, to_self_delay, our_localdelayed_pubkey)
    to_local_address = redeem_script_to_address('p2wsh', to_local_witness_script)
    to_remote_address = None
    # test if this is our_ctx
    found_to_local = bool(ctx.get_output_idxs_from_address(to_local_address))
    if not chan.is_backup():
        assert chan.is_static_remotekey_enabled()
        their_payment_pubkey = their_conf.payment_basepoint.pubkey
        to_remote_address = make_commitment_output_to_remote_address(their_payment_pubkey)
        found_to_remote = bool(ctx.get_output_idxs_from_address(to_remote_address))
    else:
        found_to_remote = False
    if not found_to_local and not found_to_remote:
        return
    chan.logger.debug(f'(lnsweep) found our ctx: {to_local_address} {to_remote_address}')
    # other outputs are htlcs
    # if they are spent, we need to generate the script
    # so, second-stage htlc sweep should not be returned here
    txs = {}  # type: Dict[str, SweepInfo]
    # to_local
    output_idxs = ctx.get_output_idxs_from_address(to_local_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        sweep_tx = lambda: create_sweeptx_ctx_to_local(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            witness_script=to_local_witness_script,
            privkey=our_localdelayed_privkey.get_secret_bytes(),
            is_revocation=False,
            to_self_delay=to_self_delay,
            config=chan.lnworker.config)
        prevout = ctx.txid() + ':%d'%output_idx
        txs[prevout] = SweepInfo(
            name='our_ctx_to_local',
            csv_delay=to_self_delay,
            cltv_abs=0,
            gen_tx=sweep_tx)
    we_breached = ctn < chan.get_oldest_unrevoked_ctn(LOCAL)
    if we_breached:
        chan.logger.info(f"(lnsweep) we breached. txid: {ctx.txid()}")
        # return only our_ctx_to_local, because we don't keep htlc_signatures for old states
        return txs

    # HTLCs
    def create_txns_for_htlc(
            *, htlc: 'UpdateAddHtlc',
            htlc_direction: Direction,
            ctx_output_idx: int,
            htlc_relative_idx: int,
            preimage: Optional[bytes]):
        htlctx_witness_script, htlc_tx = create_htlctx_that_spends_from_our_ctx(
            chan=chan,
            our_pcp=our_pcp,
            ctx=ctx,
            htlc=htlc,
            local_htlc_privkey=our_htlc_privkey,
            preimage=preimage,
            htlc_direction=htlc_direction,
            ctx_output_idx=ctx_output_idx,
            htlc_relative_idx=htlc_relative_idx)
        sweep_tx = lambda: create_sweeptx_that_spends_htlctx_that_spends_htlc_in_ctx(
            to_self_delay=to_self_delay,
            htlc_tx=htlc_tx,
            htlctx_witness_script=htlctx_witness_script,
            sweep_address=sweep_address,
            privkey=our_localdelayed_privkey.get_secret_bytes(),
            is_revocation=False,
            config=chan.lnworker.config)
        # side effect
        txs[htlc_tx.inputs()[0].prevout.to_str()] = SweepInfo(
            name='first-stage-htlc',
            csv_delay=0,
            cltv_abs=htlc_tx.locktime,
            gen_tx=lambda: htlc_tx)
        txs[htlc_tx.txid() + ':0'] = SweepInfo(
            name='second-stage-htlc',
            csv_delay=to_self_delay,
            cltv_abs=0,
            gen_tx=sweep_tx)

    # offered HTLCs, in our ctx --> "timeout"
    # received HTLCs, in our ctx --> "success"
    htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(
        chan=chan,
        ctx=ctx,
        pcp=our_pcp,
        subject=LOCAL,
        ctn=ctn)
    for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
        if direction == RECEIVED:
            if chan.lnworker.get_payment_status(htlc.payment_hash) == PR_PAID:
                preimage = chan.lnworker.get_preimage(htlc.payment_hash)
            else:
                # do not redeem this, it might publish the preimage of an incomplete MPP
                continue
        else:
            preimage = None
        create_txns_for_htlc(
            htlc=htlc,
            htlc_direction=direction,
            ctx_output_idx=ctx_output_idx,
            htlc_relative_idx=htlc_relative_idx,
            preimage=preimage)
    return txs


def analyze_ctx(chan: 'Channel', ctx: Transaction):
    # note: the remote sometimes has two valid non-revoked commitment transactions,
    # either of which could be broadcast
    our_conf, their_conf = get_ordered_channel_configs(chan=chan, for_us=True)
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    per_commitment_secret = None
    oldest_unrevoked_remote_ctn = chan.get_oldest_unrevoked_ctn(REMOTE)
    if ctn == oldest_unrevoked_remote_ctn:
        their_pcp = their_conf.current_per_commitment_point
        is_revocation = False
    elif ctn == oldest_unrevoked_remote_ctn + 1:
        their_pcp = their_conf.next_per_commitment_point
        is_revocation = False
    elif ctn < oldest_unrevoked_remote_ctn:  # breach
        try:
            per_commitment_secret = chan.revocation_store.retrieve_secret(RevocationStore.START_INDEX - ctn)
        except UnableToDeriveSecret:
            return
        their_pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
        is_revocation = True
        #chan.logger.debug(f'(lnsweep) tx for revoked: {list(txs.keys())}')
    elif chan.get_data_loss_protect_remote_pcp(ctn):
        their_pcp = chan.get_data_loss_protect_remote_pcp(ctn)
        is_revocation = False
    else:
        return
    return ctn, their_pcp, is_revocation, per_commitment_secret


def create_sweeptxs_for_their_ctx(
        *, chan: 'Channel',
        ctx: Transaction,
        sweep_address: str) -> Optional[Dict[str,SweepInfo]]:
    """Handle the case when the remote force-closes with their ctx.
    Sweep outputs that do not have a CSV delay ('to_remote' and first-stage HTLCs).
    Outputs with CSV delay ('to_local' and second-stage HTLCs) are redeemed by LNWatcher.
    """
    txs = {}  # type: Dict[str, SweepInfo]
    our_conf, their_conf = get_ordered_channel_configs(chan=chan, for_us=True)
    x = analyze_ctx(chan, ctx)
    if not x:
        return
    ctn, their_pcp, is_revocation, per_commitment_secret = x
    # to_local and to_remote addresses
    our_revocation_pubkey = derive_blinded_pubkey(our_conf.revocation_basepoint.pubkey, their_pcp)
    their_delayed_pubkey = derive_pubkey(their_conf.delayed_basepoint.pubkey, their_pcp)
    witness_script = make_commitment_output_to_local_witness_script(
        our_revocation_pubkey, our_conf.to_self_delay, their_delayed_pubkey)
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    to_remote_address = None
    # test if this is their ctx
    found_to_local = bool(ctx.get_output_idxs_from_address(to_local_address))
    if not chan.is_backup():
        assert chan.is_static_remotekey_enabled()
        our_payment_pubkey = our_conf.payment_basepoint.pubkey
        to_remote_address = make_commitment_output_to_remote_address(our_payment_pubkey)
        found_to_remote = bool(ctx.get_output_idxs_from_address(to_remote_address))
    else:
        found_to_remote = False
    if not found_to_local and not found_to_remote:
        return
    chan.logger.debug(f'(lnsweep) found their ctx: {to_local_address} {to_remote_address}')
    if is_revocation:
        our_revocation_privkey = derive_blinded_privkey(our_conf.revocation_basepoint.privkey, per_commitment_secret)
        gen_tx = create_sweeptx_for_their_revoked_ctx(chan, ctx, per_commitment_secret, chan.sweep_address)
        if gen_tx:
            tx = gen_tx()
            txs[tx.inputs()[0].prevout.to_str()] = SweepInfo(
                name='to_local_for_revoked_ctx',
                csv_delay=0,
                cltv_abs=0,
                gen_tx=gen_tx)
    # prep
    our_htlc_privkey = derive_privkey(secret=int.from_bytes(our_conf.htlc_basepoint.privkey, 'big'), per_commitment_point=their_pcp)
    our_htlc_privkey = ecc.ECPrivkey.from_secret_scalar(our_htlc_privkey)
    their_htlc_pubkey = derive_pubkey(their_conf.htlc_basepoint.pubkey, their_pcp)
    # to_local is handled by lnwatcher
    # HTLCs
    def create_sweeptx_for_htlc(
            *, htlc: 'UpdateAddHtlc',
            is_received_htlc: bool,
            ctx_output_idx: int,
            preimage: Optional[bytes]) -> None:
        htlc_output_witness_script = make_htlc_output_witness_script(
            is_received_htlc=is_received_htlc,
            remote_revocation_pubkey=our_revocation_pubkey,
            remote_htlc_pubkey=our_htlc_privkey.get_public_key_bytes(compressed=True),
            local_htlc_pubkey=their_htlc_pubkey,
            payment_hash=htlc.payment_hash,
            cltv_abs=htlc.cltv_abs)

        cltv_abs = htlc.cltv_abs if is_received_htlc and not is_revocation else 0
        prevout = ctx.txid() + ':%d'%ctx_output_idx
        sweep_tx = lambda: create_sweeptx_their_ctx_htlc(
            ctx=ctx,
            witness_script=htlc_output_witness_script,
            sweep_address=sweep_address,
            preimage=preimage,
            output_idx=ctx_output_idx,
            privkey=our_revocation_privkey if is_revocation else our_htlc_privkey.get_secret_bytes(),
            is_revocation=is_revocation,
            cltv_abs=cltv_abs,
            config=chan.lnworker.config)
        txs[prevout] = SweepInfo(
            name=f'their_ctx_htlc_{ctx_output_idx}',
            csv_delay=0,
            cltv_abs=cltv_abs,
            gen_tx=sweep_tx)
    # received HTLCs, in their ctx --> "timeout"
    # offered HTLCs, in their ctx --> "success"
    htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(
        chan=chan,
        ctx=ctx,
        pcp=their_pcp,
        subject=REMOTE,
        ctn=ctn)
    for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
        is_received_htlc = direction == RECEIVED
        if not is_received_htlc and not is_revocation:
            if chan.lnworker.get_payment_status(htlc.payment_hash) == PR_PAID:
                preimage = chan.lnworker.get_preimage(htlc.payment_hash)
            else:
                # do not redeem this, it might publish the preimage of an incomplete MPP
                continue
        else:
            preimage = None
        create_sweeptx_for_htlc(
            htlc=htlc,
            is_received_htlc=is_received_htlc,
            ctx_output_idx=ctx_output_idx,
            preimage=preimage)
    return txs


def create_htlctx_that_spends_from_our_ctx(
        chan: 'Channel',
        our_pcp: bytes,
        ctx: Transaction,
        htlc: 'UpdateAddHtlc',
        local_htlc_privkey: bytes,
        preimage: Optional[bytes],
        htlc_direction: Direction,
        htlc_relative_idx: int,
        ctx_output_idx: int) -> Tuple[bytes, Transaction]:
    assert (htlc_direction == RECEIVED) == bool(preimage), 'preimage is required iff htlc is received'
    preimage = preimage or b''
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    witness_script_out, htlc_tx = make_htlc_tx_with_open_channel(
        chan=chan,
        pcp=our_pcp,
        subject=LOCAL,
        ctn=ctn,
        htlc_direction=htlc_direction,
        commit=ctx,
        htlc=htlc,
        ctx_output_idx=ctx_output_idx,
        name=f'our_ctx_{ctx_output_idx}_htlc_tx_{htlc.payment_hash.hex()}')
    remote_htlc_sig = chan.get_remote_htlc_sig_for_htlc(htlc_relative_idx=htlc_relative_idx)
    local_htlc_sig = htlc_tx.sign_txin(0, local_htlc_privkey)
    txin = htlc_tx.inputs()[0]
    witness_script_in = txin.witness_script
    assert witness_script_in
    txin.witness = make_htlc_tx_witness(remote_htlc_sig, local_htlc_sig, preimage, witness_script_in)
    return witness_script_out, htlc_tx


def create_sweeptx_their_ctx_htlc(
        ctx: Transaction, witness_script: bytes, sweep_address: str,
        preimage: Optional[bytes], output_idx: int,
        privkey: bytes, is_revocation: bool,
        cltv_abs: int, config: SimpleConfig) -> Optional[PartialTransaction]:
    assert type(cltv_abs) is int
    preimage = preimage or b''  # preimage is required iff (not is_revocation and htlc is offered)
    val = ctx.outputs()[output_idx].value
    prevout = TxOutpoint(txid=bfh(ctx.txid()), out_idx=output_idx)
    txin = PartialTxInput(prevout=prevout)
    txin._trusted_value_sats = val
    txin.witness_script = witness_script
    txin.script_sig = b''
    sweep_inputs = [txin]
    tx_size_bytes = 200  # TODO (depends on offered/received and is_revocation)
    fee = config.estimate_fee(tx_size_bytes, allow_fallback_to_static_rates=True)
    outvalue = val - fee
    if outvalue <= dust_threshold(): return None
    sweep_outputs = [PartialTxOutput.from_address_and_value(sweep_address, outvalue)]
    tx = PartialTransaction.from_io(sweep_inputs, sweep_outputs, version=2, locktime=cltv_abs)
    sig = tx.sign_txin(0, privkey)
    if not is_revocation:
        witness = construct_witness([sig, preimage, witness_script])
    else:
        revocation_pubkey = privkey_to_pubkey(privkey)
        witness = construct_witness([sig, revocation_pubkey, witness_script])
    tx.inputs()[0].witness = witness
    assert tx.is_complete()
    return tx


def create_sweeptx_their_ctx_to_remote(
        sweep_address: str, ctx: Transaction, output_idx: int,
        our_payment_privkey: ecc.ECPrivkey,
        config: SimpleConfig) -> Optional[PartialTransaction]:
    our_payment_pubkey = our_payment_privkey.get_public_key_bytes(compressed=True)
    val = ctx.outputs()[output_idx].value
    prevout = TxOutpoint(txid=bfh(ctx.txid()), out_idx=output_idx)
    txin = PartialTxInput(prevout=prevout)
    txin._trusted_value_sats = val
    desc = descriptor.get_singlesig_descriptor_from_legacy_leaf(pubkey=our_payment_pubkey.hex(), script_type='p2wpkh')
    txin.script_descriptor = desc
    sweep_inputs = [txin]
    tx_size_bytes = 110  # approx size of p2wpkh->p2wpkh
    fee = config.estimate_fee(tx_size_bytes, allow_fallback_to_static_rates=True)
    outvalue = val - fee
    if outvalue <= dust_threshold(): return None
    sweep_outputs = [PartialTxOutput.from_address_and_value(sweep_address, outvalue)]
    sweep_tx = PartialTransaction.from_io(sweep_inputs, sweep_outputs)
    sweep_tx.set_rbf(True)
    sweep_tx.sign({our_payment_pubkey: our_payment_privkey.get_secret_bytes()})
    if not sweep_tx.is_complete():
        raise Exception('channel close sweep tx is not complete')
    return sweep_tx


def create_sweeptx_ctx_to_local(
        *, sweep_address: str, ctx: Transaction, output_idx: int, witness_script: bytes,
        privkey: bytes, is_revocation: bool, config: SimpleConfig,
        to_self_delay: int = None) -> Optional[PartialTransaction]:
    """Create a txn that sweeps the 'to_local' output of a commitment
    transaction into our wallet.

    privkey: either revocation_privkey or localdelayed_privkey
    is_revocation: tells us which ^
    """
    val = ctx.outputs()[output_idx].value
    prevout = TxOutpoint(txid=bfh(ctx.txid()), out_idx=output_idx)
    txin = PartialTxInput(prevout=prevout)
    txin._trusted_value_sats = val
    txin.script_sig = b''
    txin.witness_script = witness_script
    sweep_inputs = [txin]
    if not is_revocation:
        assert isinstance(to_self_delay, int)
        sweep_inputs[0].nsequence = to_self_delay
    tx_size_bytes = 121  # approx size of to_local -> p2wpkh
    fee = config.estimate_fee(tx_size_bytes, allow_fallback_to_static_rates=True)
    outvalue = val - fee
    if outvalue <= dust_threshold():
        return None
    sweep_outputs = [PartialTxOutput.from_address_and_value(sweep_address, outvalue)]
    sweep_tx = PartialTransaction.from_io(sweep_inputs, sweep_outputs, version=2)
    sig = sweep_tx.sign_txin(0, privkey)
    witness = construct_witness([sig, int(is_revocation), witness_script])
    sweep_tx.inputs()[0].witness = witness
    return sweep_tx


def create_sweeptx_that_spends_htlctx_that_spends_htlc_in_ctx(
        *, htlc_tx: Transaction, htlctx_witness_script: bytes, sweep_address: str,
        privkey: bytes, is_revocation: bool, to_self_delay: int = None,
        config: SimpleConfig) -> Optional[PartialTransaction]:
    """Create a txn that sweeps the output of a second stage htlc tx
    (i.e. sweeps from an HTLC-Timeout or an HTLC-Success tx).
    """
    # note: this is the same as sweeping the to_local output of the ctx,
    #       as these are the same script (address-reuse).
    return create_sweeptx_ctx_to_local(
        sweep_address=sweep_address,
        ctx=htlc_tx,
        output_idx=0,
        witness_script=htlctx_witness_script,
        privkey=privkey,
        is_revocation=is_revocation,
        to_self_delay=to_self_delay,
        config=config,
    )
