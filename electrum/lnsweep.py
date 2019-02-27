# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import Optional, Dict, List, Tuple, TYPE_CHECKING

from .util import bfh, bh2u, print_error
from .bitcoin import TYPE_ADDRESS, redeem_script_to_address, dust_threshold
from . import ecc
from .lnutil import (make_commitment_output_to_remote_address, make_commitment_output_to_local_witness_script,
                     derive_privkey, derive_pubkey, derive_blinded_pubkey, derive_blinded_privkey,
                     make_htlc_tx_witness, make_htlc_tx_with_open_channel, UpdateAddHtlc,
                     LOCAL, REMOTE, make_htlc_output_witness_script, UnknownPaymentHash,
                     get_ordered_channel_configs, privkey_to_pubkey, get_per_commitment_secret_from_seed,
                     RevocationStore, extract_ctn_from_tx_and_chan, UnableToDeriveSecret, SENT, RECEIVED)
from .transaction import Transaction, TxOutput, construct_witness
from .simple_config import SimpleConfig, FEERATE_FALLBACK_STATIC_FEE

if TYPE_CHECKING:
    from .lnchannel import Channel


def maybe_create_sweeptx_for_their_ctx_to_remote(ctx: Transaction, sweep_address: str,
                                                 our_payment_privkey: ecc.ECPrivkey) -> Optional[Transaction]:
    our_payment_pubkey = our_payment_privkey.get_public_key_bytes(compressed=True)
    to_remote_address = make_commitment_output_to_remote_address(our_payment_pubkey)
    output_idx = ctx.get_output_idx_from_address(to_remote_address)
    if output_idx is None: return None
    sweep_tx = create_sweeptx_their_ctx_to_remote(sweep_address=sweep_address,
                                                  ctx=ctx,
                                                  output_idx=output_idx,
                                                  our_payment_privkey=our_payment_privkey)
    return sweep_tx


def maybe_create_sweeptx_for_their_ctx_to_local(ctx: Transaction, revocation_privkey: bytes,
                                                to_self_delay: int, delayed_pubkey: bytes,
                                                sweep_address: str) -> Optional[Transaction]:
    revocation_pubkey = ecc.ECPrivkey(revocation_privkey).get_public_key_bytes(compressed=True)
    witness_script = bh2u(make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, delayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    output_idx = ctx.get_output_idx_from_address(to_local_address)
    if output_idx is None: return None
    sweep_tx = create_sweeptx_ctx_to_local(sweep_address=sweep_address,
                                           ctx=ctx,
                                           output_idx=output_idx,
                                           witness_script=witness_script,
                                           privkey=revocation_privkey,
                                           is_revocation=True)
    return sweep_tx


def create_sweeptxs_for_their_just_revoked_ctx(chan: 'Channel', ctx: Transaction, per_commitment_secret: bytes,
                                               sweep_address: str) -> Dict[str,Transaction]:
    """Presign sweeping transactions using the just received revoked pcs.
    These will only be utilised if the remote breaches.
    Sweep 'lo_local', and all the HTLCs (two cases: directly from ctx, or from HTLC tx).
    """
    # prep
    pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    this_conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=False)
    other_revocation_privkey = derive_blinded_privkey(other_conf.revocation_basepoint.privkey,
                                                      per_commitment_secret)
    to_self_delay = other_conf.to_self_delay
    this_delayed_pubkey = derive_pubkey(this_conf.delayed_basepoint.pubkey, pcp)
    txs = {}
    # to_local
    sweep_tx = maybe_create_sweeptx_for_their_ctx_to_local(ctx=ctx,
                                                           revocation_privkey=other_revocation_privkey,
                                                           to_self_delay=to_self_delay,
                                                           delayed_pubkey=this_delayed_pubkey,
                                                           sweep_address=sweep_address)
    if sweep_tx:
        txs[ctx.txid()] = sweep_tx
    # HTLCs
    def create_sweeptx_for_htlc(htlc: 'UpdateAddHtlc', is_received_htlc: bool) -> Tuple[Optional[Transaction],
                                                                                      Optional[Transaction],
                                                                                      Transaction]:
        htlc_tx_witness_script, htlc_tx = make_htlc_tx_with_open_channel(chan=chan,
                                                                         pcp=pcp,
                                                                         for_us=False,
                                                                         we_receive=not is_received_htlc,
                                                                         commit=ctx,
                                                                         htlc=htlc)
        htlc_tx_txin = htlc_tx.inputs()[0]
        htlc_output_witness_script = bfh(Transaction.get_preimage_script(htlc_tx_txin))
        # sweep directly from ctx
        direct_sweep_tx = maybe_create_sweeptx_for_their_ctx_htlc(
            ctx=ctx,
            sweep_address=sweep_address,
            htlc_output_witness_script=htlc_output_witness_script,
            privkey=other_revocation_privkey,
            preimage=None,
            is_revocation=True)
        # sweep from htlc tx
        secondstage_sweep_tx = create_sweeptx_that_spends_htlctx_that_spends_htlc_in_ctx(
            'sweep_from_their_ctx_htlc_',
            to_self_delay=0,
            htlc_tx=htlc_tx,
            htlctx_witness_script=htlc_tx_witness_script,
            sweep_address=sweep_address,
            privkey=other_revocation_privkey,
            is_revocation=True)
        return direct_sweep_tx, secondstage_sweep_tx, htlc_tx
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    assert ctn == chan.config[REMOTE].ctn
    # received HTLCs, in their ctx
    received_htlcs = chan.included_htlcs(REMOTE, RECEIVED, ctn)
    for htlc in received_htlcs:
        direct_sweep_tx, secondstage_sweep_tx, htlc_tx = create_sweeptx_for_htlc(htlc, is_received_htlc=True)
        if direct_sweep_tx:
            txs[ctx.txid()] = direct_sweep_tx
        if secondstage_sweep_tx:
            txs[htlc_tx.txid()] = secondstage_sweep_tx
    # offered HTLCs, in their ctx
    offered_htlcs = chan.included_htlcs(REMOTE, SENT, ctn)
    for htlc in offered_htlcs:
        direct_sweep_tx, secondstage_sweep_tx, htlc_tx = create_sweeptx_for_htlc(htlc, is_received_htlc=False)
        if direct_sweep_tx:
            txs[ctx.txid()] = direct_sweep_tx
        if secondstage_sweep_tx:
            txs[htlc_tx.txid()] = secondstage_sweep_tx
    return txs


def create_sweeptxs_for_our_latest_ctx(chan: 'Channel', ctx: Transaction,
                                       sweep_address: str) -> Dict[str,Transaction]:
    """Handle the case where we force close unilaterally with our latest ctx.
    Construct sweep txns for 'to_local', and for all HTLCs (2 txns each).
    'to_local' can be swept even if this is a breach (by us),
    but HTLCs cannot (old HTLCs are no longer stored).
    """
    this_conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=True)
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    our_per_commitment_secret = get_per_commitment_secret_from_seed(
        this_conf.per_commitment_secret_seed, RevocationStore.START_INDEX - ctn)
    our_pcp = ecc.ECPrivkey(our_per_commitment_secret).get_public_key_bytes(compressed=True)
    # prep
    this_delayed_bp_privkey = ecc.ECPrivkey(this_conf.delayed_basepoint.privkey)
    this_localdelayed_privkey = derive_privkey(this_delayed_bp_privkey.secret_scalar, our_pcp)
    this_localdelayed_privkey = ecc.ECPrivkey.from_secret_scalar(this_localdelayed_privkey)
    other_revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, our_pcp)
    to_self_delay = chan.config[REMOTE].to_self_delay
    this_htlc_privkey = derive_privkey(secret=int.from_bytes(this_conf.htlc_basepoint.privkey, 'big'),
                                       per_commitment_point=our_pcp).to_bytes(32, 'big')
    txs = {}
    # to_local
    sweep_tx = maybe_create_sweeptx_that_spends_to_local_in_our_ctx(ctx=ctx,
                                                                    sweep_address=sweep_address,
                                                                    our_localdelayed_privkey=this_localdelayed_privkey,
                                                                    remote_revocation_pubkey=other_revocation_pubkey,
                                                                    to_self_delay=to_self_delay)
    if sweep_tx:
        txs[sweep_tx.prevout(0)] = sweep_tx
    # HTLCs
    def create_txns_for_htlc(htlc: 'UpdateAddHtlc', is_received_htlc: bool) -> Tuple[Optional[Transaction], Optional[Transaction]]:
        if is_received_htlc:
            try:
                preimage = chan.lnworker.get_preimage(htlc.payment_hash)
            except UnknownPaymentHash as e:
                print_error(f'trying to sweep htlc from our latest ctx but getting {repr(e)}')
                return None, None
        else:
            preimage = None
        htlctx_witness_script, htlc_tx = create_htlctx_that_spends_from_our_ctx(
            chan=chan,
            our_pcp=our_pcp,
            ctx=ctx,
            htlc=htlc,
            local_htlc_privkey=this_htlc_privkey,
            preimage=preimage,
            is_received_htlc=is_received_htlc)
        to_wallet_tx = create_sweeptx_that_spends_htlctx_that_spends_htlc_in_ctx(
            'sweep_from_our_ctx_htlc_',
            to_self_delay=to_self_delay,
            htlc_tx=htlc_tx,
            htlctx_witness_script=htlctx_witness_script,
            sweep_address=sweep_address,
            privkey=this_localdelayed_privkey.get_secret_bytes(),
            is_revocation=False)
        return htlc_tx, to_wallet_tx
    # offered HTLCs, in our ctx --> "timeout"
    # received HTLCs, in our ctx --> "success"
    offered_htlcs = chan.included_htlcs(LOCAL, SENT, ctn)  # type: List[UpdateAddHtlc]
    received_htlcs = chan.included_htlcs(LOCAL, RECEIVED, ctn)  # type: List[UpdateAddHtlc]
    for htlc in offered_htlcs:
        htlc_tx, to_wallet_tx = create_txns_for_htlc(htlc, is_received_htlc=False)
        if htlc_tx and to_wallet_tx:
            txs[to_wallet_tx.prevout(0)] = to_wallet_tx
            txs[htlc_tx.prevout(0)] = htlc_tx
    for htlc in received_htlcs:
        htlc_tx, to_wallet_tx = create_txns_for_htlc(htlc, is_received_htlc=True)
        if htlc_tx and to_wallet_tx:
            txs[to_wallet_tx.prevout(0)] = to_wallet_tx
            txs[htlc_tx.prevout(0)] = htlc_tx
    return txs


def create_sweeptxs_for_their_latest_ctx(chan: 'Channel', ctx: Transaction,
                                         sweep_address: str) -> Dict[str,Transaction]:
    """Handle the case when the remote force-closes with their ctx.
    Regardless of it is a breach or not, construct sweep tx for 'to_remote'.
    If it is a breach, also construct sweep tx for 'to_local'.
    Sweep txns for HTLCs are only constructed if it is NOT a breach, as
    lnchannel does not store old HTLCs.
    """
    this_conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=False)
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    # note: the remote sometimes has two valid non-revoked commitment transactions,
    # either of which could be broadcast (this_conf.ctn, this_conf.ctn+1)
    per_commitment_secret = None
    if ctn == this_conf.ctn:
        their_pcp = this_conf.current_per_commitment_point
    elif ctn == this_conf.ctn + 1:
        their_pcp = this_conf.next_per_commitment_point
    elif ctn < this_conf.ctn:  # breach
        try:
            per_commitment_secret = this_conf.revocation_store.retrieve_secret(RevocationStore.START_INDEX - ctn)
        except UnableToDeriveSecret:
            return {}
        their_pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    else:
        return {}
    # prep
    other_revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, their_pcp)
    other_htlc_privkey = derive_privkey(secret=int.from_bytes(other_conf.htlc_basepoint.privkey, 'big'),
                                        per_commitment_point=their_pcp)
    other_htlc_privkey = ecc.ECPrivkey.from_secret_scalar(other_htlc_privkey)
    this_htlc_pubkey = derive_pubkey(this_conf.htlc_basepoint.pubkey, their_pcp)
    other_payment_bp_privkey = ecc.ECPrivkey(other_conf.payment_basepoint.privkey)
    other_payment_privkey = derive_privkey(other_payment_bp_privkey.secret_scalar, their_pcp)
    other_payment_privkey = ecc.ECPrivkey.from_secret_scalar(other_payment_privkey)

    txs = {}
    if per_commitment_secret:  # breach
        # to_local
        other_revocation_privkey = derive_blinded_privkey(other_conf.revocation_basepoint.privkey,
                                                          per_commitment_secret)
        this_delayed_pubkey = derive_pubkey(this_conf.delayed_basepoint.pubkey, their_pcp)
        sweep_tx = maybe_create_sweeptx_for_their_ctx_to_local(ctx=ctx,
                                                               revocation_privkey=other_revocation_privkey,
                                                               to_self_delay=other_conf.to_self_delay,
                                                               delayed_pubkey=this_delayed_pubkey,
                                                               sweep_address=sweep_address)
        if sweep_tx:
            txs[sweep_tx.prevout(0)] = sweep_tx
    # to_remote
    sweep_tx = maybe_create_sweeptx_for_their_ctx_to_remote(ctx=ctx,
                                                            sweep_address=sweep_address,
                                                            our_payment_privkey=other_payment_privkey)
    if sweep_tx:
        txs[sweep_tx.prevout(0)] = sweep_tx
    # HTLCs
    # from their ctx, we can only redeem HTLCs if the ctx was not revoked,
    # as old HTLCs are not stored. (if it was revoked, then we should have presigned txns
    # to handle the breach already; out of scope here)
    if ctn not in (this_conf.ctn, this_conf.ctn + 1):
        return txs
    def create_sweeptx_for_htlc(htlc: 'UpdateAddHtlc', is_received_htlc: bool) -> Optional[Transaction]:
        if not is_received_htlc:
            try:
                preimage = chan.lnworker.get_preimage(htlc.payment_hash)
            except UnknownPaymentHash as e:
                print_error(f'trying to sweep htlc from their latest ctx but getting {repr(e)}')
                return None
        else:
            preimage = None
        htlc_output_witness_script = make_htlc_output_witness_script(
            is_received_htlc=is_received_htlc,
            remote_revocation_pubkey=other_revocation_pubkey,
            remote_htlc_pubkey=other_htlc_privkey.get_public_key_bytes(compressed=True),
            local_htlc_pubkey=this_htlc_pubkey,
            payment_hash=htlc.payment_hash,
            cltv_expiry=htlc.cltv_expiry)
        sweep_tx = maybe_create_sweeptx_for_their_ctx_htlc(
            ctx=ctx,
            sweep_address=sweep_address,
            htlc_output_witness_script=htlc_output_witness_script,
            privkey=other_htlc_privkey.get_secret_bytes(),
            preimage=preimage,
            is_revocation=False,
            cltv_expiry=htlc.cltv_expiry if is_received_htlc else 0)
        return sweep_tx
    # received HTLCs, in their ctx --> "timeout"
    received_htlcs = chan.included_htlcs_in_their_latest_ctxs(LOCAL)[ctn]  # type: List[UpdateAddHtlc]
    for htlc in received_htlcs:
        sweep_tx = create_sweeptx_for_htlc(htlc, is_received_htlc=True)
        if sweep_tx:
            txs[sweep_tx.prevout(0)] = sweep_tx
    # offered HTLCs, in their ctx --> "success"
    offered_htlcs = chan.included_htlcs_in_their_latest_ctxs(REMOTE)[ctn]  # type: List[UpdateAddHtlc]
    for htlc in offered_htlcs:
        sweep_tx = create_sweeptx_for_htlc(htlc, is_received_htlc=False)
        if sweep_tx:
            txs[sweep_tx.prevout(0)] = sweep_tx
    return txs


def maybe_create_sweeptx_that_spends_to_local_in_our_ctx(
        ctx: Transaction, sweep_address: str, our_localdelayed_privkey: ecc.ECPrivkey,
        remote_revocation_pubkey: bytes, to_self_delay: int) -> Optional[Transaction]:
    our_localdelayed_pubkey = our_localdelayed_privkey.get_public_key_bytes(compressed=True)
    to_local_witness_script = bh2u(make_commitment_output_to_local_witness_script(
        remote_revocation_pubkey, to_self_delay, our_localdelayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', to_local_witness_script)
    output_idx = ctx.get_output_idx_from_address(to_local_address)
    if output_idx is None: return None
    sweep_tx = create_sweeptx_ctx_to_local(sweep_address=sweep_address,
                                           ctx=ctx,
                                           output_idx=output_idx,
                                           witness_script=to_local_witness_script,
                                           privkey=our_localdelayed_privkey.get_secret_bytes(),
                                           is_revocation=False,
                                           to_self_delay=to_self_delay)
    return sweep_tx


def create_htlctx_that_spends_from_our_ctx(chan: 'Channel', our_pcp: bytes,
                                           ctx: Transaction, htlc: 'UpdateAddHtlc',
                                           local_htlc_privkey: bytes, preimage: Optional[bytes],
                                           is_received_htlc: bool) -> Tuple[bytes, Transaction]:
    assert is_received_htlc == bool(preimage), 'preimage is required iff htlc is received'
    preimage = preimage or b''
    witness_script, htlc_tx = make_htlc_tx_with_open_channel(chan=chan,
                                                             pcp=our_pcp,
                                                             for_us=True,
                                                             we_receive=is_received_htlc,
                                                             commit=ctx,
                                                             htlc=htlc,
                                                             name=f'our_ctx_htlc_tx_{bh2u(htlc.payment_hash)}',
                                                             cltv_expiry=0 if is_received_htlc else htlc.cltv_expiry)
    remote_htlc_sig = chan.get_remote_htlc_sig_for_htlc(htlc, we_receive=is_received_htlc, ctx=ctx)
    local_htlc_sig = bfh(htlc_tx.sign_txin(0, local_htlc_privkey))
    txin = htlc_tx.inputs()[0]
    witness_program = bfh(Transaction.get_preimage_script(txin))
    txin['witness'] = bh2u(make_htlc_tx_witness(remote_htlc_sig, local_htlc_sig, preimage, witness_program))
    return witness_script, htlc_tx


def maybe_create_sweeptx_for_their_ctx_htlc(ctx: Transaction, sweep_address: str,
                                            htlc_output_witness_script: bytes,
                                            privkey: bytes, is_revocation: bool,
                                            preimage: Optional[bytes], cltv_expiry: int = 0) -> Optional[Transaction]:
    htlc_address = redeem_script_to_address('p2wsh', bh2u(htlc_output_witness_script))
    # FIXME handle htlc_address collision
    # also: https://github.com/lightningnetwork/lightning-rfc/issues/448
    output_idx = ctx.get_output_idx_from_address(htlc_address)
    if output_idx is None: return None
    sweep_tx = create_sweeptx_their_ctx_htlc(ctx=ctx,
                                             witness_script=htlc_output_witness_script,
                                             sweep_address=sweep_address,
                                             preimage=preimage,
                                             output_idx=output_idx,
                                             privkey=privkey,
                                             is_revocation=is_revocation,
                                             cltv_expiry=cltv_expiry)
    return sweep_tx


def create_sweeptx_their_ctx_htlc(ctx: Transaction, witness_script: bytes, sweep_address: str,
                                  preimage: Optional[bytes], output_idx: int,
                                  privkey: bytes, is_revocation: bool, cltv_expiry: int,
                                  fee_per_kb: int=None) -> Optional[Transaction]:
    assert type(cltv_expiry) is int
    preimage = preimage or b''  # preimage is required iff (not is_revocation and htlc is offered)
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
        'preimage_script': bh2u(witness_script),
    }]
    tx_size_bytes = 200  # TODO (depends on offered/received and is_revocation)
    if fee_per_kb is None: fee_per_kb = FEERATE_FALLBACK_STATIC_FEE
    fee = SimpleConfig.estimate_fee_for_feerate(fee_per_kb, tx_size_bytes)
    outvalue = val - fee
    if outvalue <= dust_threshold(): return None
    sweep_outputs = [TxOutput(TYPE_ADDRESS, sweep_address, outvalue)]
    tx = Transaction.from_io(sweep_inputs, sweep_outputs, version=2
            , name=f'their_ctx_sweep_htlc_{ctx.txid()[:8]}_{output_idx}'
            # note that cltv_expiry, and therefore also locktime will be zero when breach!
            , cltv_expiry=cltv_expiry, locktime=cltv_expiry)

    sig = bfh(tx.sign_txin(0, privkey))
    if not is_revocation:
        witness = construct_witness([sig, preimage, witness_script])
    else:
        revocation_pubkey = privkey_to_pubkey(privkey)
        witness = construct_witness([sig, revocation_pubkey, witness_script])
    tx.inputs()[0]['witness'] = witness
    assert tx.is_complete()
    return tx


def create_sweeptx_their_ctx_to_remote(sweep_address: str, ctx: Transaction, output_idx: int,
                                       our_payment_privkey: ecc.ECPrivkey,
                                       fee_per_kb: int=None) -> Optional[Transaction]:
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
    outvalue = val - fee
    if outvalue <= dust_threshold(): return None
    sweep_outputs = [TxOutput(TYPE_ADDRESS, sweep_address, outvalue)]
    sweep_tx = Transaction.from_io(sweep_inputs, sweep_outputs, name='their_ctx_to_remote')
    sweep_tx.set_rbf(True)
    sweep_tx.sign({our_payment_pubkey: (our_payment_privkey.get_secret_bytes(), True)})
    if not sweep_tx.is_complete():
        raise Exception('channel close sweep tx is not complete')
    return sweep_tx


def create_sweeptx_ctx_to_local(sweep_address: str, ctx: Transaction, output_idx: int, witness_script: str,
                                privkey: bytes, is_revocation: bool,
                                to_self_delay: int=None,
                                fee_per_kb: int=None) -> Optional[Transaction]:
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
    if not is_revocation:
        assert isinstance(to_self_delay, int)
        sweep_inputs[0]['sequence'] = to_self_delay
    tx_size_bytes = 121  # approx size of to_local -> p2wpkh
    if fee_per_kb is None:
        fee_per_kb = FEERATE_FALLBACK_STATIC_FEE
    fee = SimpleConfig.estimate_fee_for_feerate(fee_per_kb, tx_size_bytes)
    outvalue = val - fee
    if outvalue <= dust_threshold():
        return None
    sweep_outputs = [TxOutput(TYPE_ADDRESS, sweep_address, outvalue)]
    name = 'their_ctx_to_local' if is_revocation else 'our_ctx_to_local'
    csv_delay = 0 if is_revocation else to_self_delay
    sweep_tx = Transaction.from_io(sweep_inputs, sweep_outputs, version=2, name=name, csv_delay=csv_delay)
    sig = sweep_tx.sign_txin(0, privkey)
    witness = construct_witness([sig, int(is_revocation), witness_script])
    sweep_tx.inputs()[0]['witness'] = witness
    return sweep_tx


def create_sweeptx_that_spends_htlctx_that_spends_htlc_in_ctx(
        name_prefix: str,
        htlc_tx: Transaction, htlctx_witness_script: bytes, sweep_address: str,
        privkey: bytes, is_revocation: bool, to_self_delay: int,
        fee_per_kb: int=None) -> Optional[Transaction]:
    val = htlc_tx.outputs()[0].value
    sweep_inputs = [{
        'scriptSig': '',
        'type': 'p2wsh',
        'signatures': [],
        'num_sig': 0,
        'prevout_n': 0,
        'prevout_hash': htlc_tx.txid(),
        'value': val,
        'coinbase': False,
        'preimage_script': bh2u(htlctx_witness_script),
    }]
    if not is_revocation:
        assert isinstance(to_self_delay, int)
        sweep_inputs[0]['sequence'] = to_self_delay
    tx_size_bytes = 200  # TODO
    if fee_per_kb is None: fee_per_kb = FEERATE_FALLBACK_STATIC_FEE
    fee = SimpleConfig.estimate_fee_for_feerate(fee_per_kb, tx_size_bytes)
    outvalue = val - fee
    if outvalue <= dust_threshold(): return None
    sweep_outputs = [TxOutput(TYPE_ADDRESS, sweep_address, outvalue)]
    tx = Transaction.from_io(sweep_inputs, sweep_outputs, version=2, name=name_prefix + htlc_tx.txid(), csv_delay=to_self_delay)

    sig = bfh(tx.sign_txin(0, privkey))
    witness = construct_witness([sig, int(is_revocation), htlctx_witness_script])
    tx.inputs()[0]['witness'] = witness
    assert tx.is_complete()
    return tx
