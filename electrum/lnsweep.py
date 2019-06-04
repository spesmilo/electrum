# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import Optional, Dict, List, Tuple, TYPE_CHECKING, NamedTuple
from enum import Enum, auto

from .util import bfh, bh2u
from .bitcoin import TYPE_ADDRESS, redeem_script_to_address, dust_threshold
from . import ecc
from .lnutil import (make_commitment_output_to_remote_address, make_commitment_output_to_local_witness_script,
                     derive_privkey, derive_pubkey, derive_blinded_pubkey, derive_blinded_privkey,
                     make_htlc_tx_witness, make_htlc_tx_with_open_channel, UpdateAddHtlc,
                     LOCAL, REMOTE, make_htlc_output_witness_script, UnknownPaymentHash,
                     get_ordered_channel_configs, privkey_to_pubkey, get_per_commitment_secret_from_seed,
                     RevocationStore, extract_ctn_from_tx_and_chan, UnableToDeriveSecret, SENT, RECEIVED)
from .transaction import Transaction, TxOutput, construct_witness
from .simple_config import estimate_fee
from .logging import get_logger

if TYPE_CHECKING:
    from .lnchannel import Channel


_logger = get_logger(__name__)




def create_sweeptxs_for_their_revoked_ctx(chan: 'Channel', ctx: Transaction, per_commitment_secret: bytes,
                                          sweep_address: str) -> Dict[str,Transaction]:
    """Presign sweeping transactions using the just received revoked pcs.
    These will only be utilised if the remote breaches.
    Sweep 'to_local', and all the HTLCs (two cases: directly from ctx, or from HTLC tx).
    """
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
    witness_script = bh2u(make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, this_delayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    output_idx = ctx.get_output_idx_from_address(to_local_address)
    if output_idx is not None:
        sweep_tx = create_sweeptx_ctx_to_local(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            witness_script=witness_script,
            privkey=other_revocation_privkey,
            is_revocation=True)
        txs.append(sweep_tx)
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
        return create_sweeptx_that_spends_htlctx_that_spends_htlc_in_ctx(
            'sweep_from_their_ctx_htlc_',
            to_self_delay=0,
            htlc_tx=htlc_tx,
            htlctx_witness_script=htlc_tx_witness_script,
            sweep_address=sweep_address,
            privkey=other_revocation_privkey,
            is_revocation=True)
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    assert ctn == chan.config[REMOTE].ctn
    # received HTLCs, in their ctx
    received_htlcs = chan.included_htlcs(REMOTE, RECEIVED, ctn)
    for htlc in received_htlcs:
        secondstage_sweep_tx = create_sweeptx_for_htlc(htlc, is_received_htlc=True)
        if secondstage_sweep_tx:
            txs.append(secondstage_sweep_tx)
    # offered HTLCs, in their ctx
    offered_htlcs = chan.included_htlcs(REMOTE, SENT, ctn)
    for htlc in offered_htlcs:
        secondstage_sweep_tx = create_sweeptx_for_htlc(htlc, is_received_htlc=False)
        if secondstage_sweep_tx:
            txs.append(secondstage_sweep_tx)
    return txs


def create_sweeptxs_for_our_ctx(chan: 'Channel', ctx: Transaction, ctn: int,
                                sweep_address: str) -> Dict[str,Transaction]:
    """Handle the case where we force close unilaterally with our latest ctx.
    Construct sweep txns for 'to_local', and for all HTLCs (2 txns each).
    'to_local' can be swept even if this is a breach (by us),
    but HTLCs cannot (old HTLCs are no longer stored).
    """
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
    to_local_witness_script = bh2u(make_commitment_output_to_local_witness_script(
        their_revocation_pubkey, to_self_delay, our_localdelayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', to_local_witness_script)
    their_payment_pubkey = derive_pubkey(their_conf.payment_basepoint.pubkey, our_pcp)
    to_remote_address = make_commitment_output_to_remote_address(their_payment_pubkey)

    # test ctx
    if ctx.get_output_idx_from_address(to_local_address) is None\
       and ctx.get_output_idx_from_address(to_remote_address) is None:
        return

    txs = {}
    # to_local
    output_idx = ctx.get_output_idx_from_address(to_local_address)
    if output_idx is not None:
        sweep_tx = lambda: create_sweeptx_ctx_to_local(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            witness_script=to_local_witness_script,
            privkey=our_localdelayed_privkey.get_secret_bytes(),
            is_revocation=False,
            to_self_delay=to_self_delay)
        prevout = ctx.txid() + ':%d'%output_idx
        txs[prevout] = ('our_ctx_to_local', to_self_delay, 0, sweep_tx)
    # HTLCs
    def create_txns_for_htlc(htlc: 'UpdateAddHtlc', is_received_htlc: bool) -> Tuple[Optional[Transaction], Optional[Transaction]]:
        if is_received_htlc:
            try:
                preimage = chan.lnworker.get_preimage(htlc.payment_hash)
            except UnknownPaymentHash as e:
                _logger.info(f'trying to sweep htlc from our latest ctx but getting {repr(e)}')
                return None, None
        else:
            preimage = None
        htlctx_witness_script, htlc_tx = create_htlctx_that_spends_from_our_ctx(
            chan=chan,
            our_pcp=our_pcp,
            ctx=ctx,
            htlc=htlc,
            local_htlc_privkey=our_htlc_privkey,
            preimage=preimage,
            is_received_htlc=is_received_htlc)
        sweep_tx = lambda: create_sweeptx_that_spends_htlctx_that_spends_htlc_in_ctx(
            'sweep_from_our_ctx_htlc_',
            to_self_delay=to_self_delay,
            htlc_tx=htlc_tx,
            htlctx_witness_script=htlctx_witness_script,
            sweep_address=sweep_address,
            privkey=our_localdelayed_privkey.get_secret_bytes(),
            is_revocation=False)
        # side effect
        txs[htlc_tx.prevout(0)] = ('first-stage-htlc', 0, htlc_tx.cltv_expiry, lambda: htlc_tx)
        txs[htlc_tx.txid() + ':0'] = ('second-stage-htlc', to_self_delay, 0, sweep_tx)
    # offered HTLCs, in our ctx --> "timeout"
    # received HTLCs, in our ctx --> "success"
    offered_htlcs = chan.included_htlcs(LOCAL, SENT, ctn)  # type: List[UpdateAddHtlc]
    received_htlcs = chan.included_htlcs(LOCAL, RECEIVED, ctn)  # type: List[UpdateAddHtlc]
    for htlc in offered_htlcs:
        create_txns_for_htlc(htlc, is_received_htlc=False)
    for htlc in received_htlcs:
        create_txns_for_htlc(htlc, is_received_htlc=True)
    return txs


def create_sweeptxs_for_their_ctx(chan: 'Channel', ctx: Transaction, ctn: int,
                                  sweep_address: str) -> Dict[str,Transaction]:
    """Handle the case when the remote force-closes with their ctx.
    Sweep outputs that do not have a CSV delay ('to_remote' and first-stage HTLCs).
    Outputs with CSV delay ('to_local' and second-stage HTLCs) are redeemed by LNWatcher.
    """
    our_conf, their_conf = get_ordered_channel_configs(chan=chan, for_us=True)
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    # note: the remote sometimes has two valid non-revoked commitment transactions,
    # either of which could be broadcast (their_conf.ctn, their_conf.ctn+1)
    per_commitment_secret = None
    if ctn == their_conf.ctn:
        their_pcp = their_conf.current_per_commitment_point
        is_revocation = False
    elif ctn == their_conf.ctn + 1:
        their_pcp = their_conf.next_per_commitment_point
        is_revocation = False
    elif ctn < their_conf.ctn:  # breach
        try:
            per_commitment_secret = their_conf.revocation_store.retrieve_secret(RevocationStore.START_INDEX - ctn)
        except UnableToDeriveSecret:
            return
        their_pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
        is_revocation = True
        our_revocation_privkey = derive_blinded_privkey(our_conf.revocation_basepoint.privkey, per_commitment_secret)
    else:
        return
    # to_local and to_remote addresses
    our_revocation_pubkey = derive_blinded_pubkey(our_conf.revocation_basepoint.pubkey, their_pcp)
    their_delayed_pubkey = derive_pubkey(their_conf.delayed_basepoint.pubkey, their_pcp)
    witness_script = bh2u(make_commitment_output_to_local_witness_script(
        our_revocation_pubkey, our_conf.to_self_delay, their_delayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    our_payment_pubkey = derive_pubkey(our_conf.payment_basepoint.pubkey, their_pcp)
    to_remote_address = make_commitment_output_to_remote_address(our_payment_pubkey)
    # test ctx
    if ctx.get_output_idx_from_address(to_local_address) is None \
       and ctx.get_output_idx_from_address(to_remote_address) is None:
        return
    # prep
    our_htlc_privkey = derive_privkey(secret=int.from_bytes(our_conf.htlc_basepoint.privkey, 'big'), per_commitment_point=their_pcp)
    our_htlc_privkey = ecc.ECPrivkey.from_secret_scalar(our_htlc_privkey)
    their_htlc_pubkey = derive_pubkey(their_conf.htlc_basepoint.pubkey, their_pcp)
    our_payment_bp_privkey = ecc.ECPrivkey(our_conf.payment_basepoint.privkey)
    our_payment_privkey = derive_privkey(our_payment_bp_privkey.secret_scalar, their_pcp)
    our_payment_privkey = ecc.ECPrivkey.from_secret_scalar(our_payment_privkey)
    assert our_payment_pubkey == our_payment_privkey.get_public_key_bytes(compressed=True)
    txs = {}
    # to_local is handled by lnwatcher
    # to_remote
    output_idx = ctx.get_output_idx_from_address(to_remote_address)
    if output_idx is not None:
        prevout = ctx.txid() + ':%d'%output_idx
        sweep_tx = lambda: create_sweeptx_their_ctx_to_remote(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            our_payment_privkey=our_payment_privkey)
        txs[prevout] = ('their_ctx_to_remote', 0, 0, sweep_tx)
    # HTLCs
    def create_sweeptx_for_htlc(htlc: 'UpdateAddHtlc', is_received_htlc: bool) -> Optional[Transaction]:
        if not is_received_htlc and not is_revocation:
            try:
                preimage = chan.lnworker.get_preimage(htlc.payment_hash)
            except UnknownPaymentHash as e:
                _logger.info(f'trying to sweep htlc from their latest ctx but getting {repr(e)}')
                return None
        else:
            preimage = None
        htlc_output_witness_script = make_htlc_output_witness_script(
            is_received_htlc=is_received_htlc,
            remote_revocation_pubkey=our_revocation_pubkey,
            remote_htlc_pubkey=our_htlc_privkey.get_public_key_bytes(compressed=True),
            local_htlc_pubkey=their_htlc_pubkey,
            payment_hash=htlc.payment_hash,
            cltv_expiry=htlc.cltv_expiry)
        htlc_address = redeem_script_to_address('p2wsh', bh2u(htlc_output_witness_script))
        # FIXME handle htlc_address collision
        # also: https://github.com/lightningnetwork/lightning-rfc/issues/448
        output_idx = ctx.get_output_idx_from_address(htlc_address)
        if output_idx is not None:
            cltv_expiry = htlc.cltv_expiry if is_received_htlc and not is_revocation else 0
            prevout = ctx.txid() + ':%d'%output_idx
            sweep_tx = lambda: create_sweeptx_their_ctx_htlc(
                ctx=ctx,
                witness_script=htlc_output_witness_script,
                sweep_address=sweep_address,
                preimage=preimage,
                output_idx=output_idx,
                privkey=our_revocation_privkey if is_revocation else our_htlc_privkey.get_secret_bytes(),
                is_revocation=is_revocation,
                cltv_expiry=cltv_expiry)
            name = f'their_ctx_sweep_htlc_{ctx.txid()[:8]}_{output_idx}'
            txs[prevout] = (name, 0, cltv_expiry, sweep_tx)
    # received HTLCs, in their ctx --> "timeout"
    received_htlcs = chan.included_htlcs(REMOTE, RECEIVED, ctn=ctn)  # type: List[UpdateAddHtlc]
    for htlc in received_htlcs:
        create_sweeptx_for_htlc(htlc, is_received_htlc=True)
    # offered HTLCs, in their ctx --> "success"
    offered_htlcs = chan.included_htlcs(REMOTE, SENT, ctn=ctn)  # type: List[UpdateAddHtlc]
    for htlc in offered_htlcs:
        create_sweeptx_for_htlc(htlc, is_received_htlc=False)
    return txs


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


def create_sweeptx_their_ctx_htlc(ctx: Transaction, witness_script: bytes, sweep_address: str,
                                  preimage: Optional[bytes], output_idx: int,
                                  privkey: bytes, is_revocation: bool,
                                  cltv_expiry: int) -> Optional[Transaction]:
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
    fee = estimate_fee(tx_size_bytes)
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
                                       our_payment_privkey: ecc.ECPrivkey) -> Optional[Transaction]:
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
    fee = estimate_fee(tx_size_bytes)
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
                                to_self_delay: int=None) -> Optional[Transaction]:
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
    fee = estimate_fee(tx_size_bytes)
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
        privkey: bytes, is_revocation: bool, to_self_delay: int) -> Optional[Transaction]:
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
    fee = estimate_fee(tx_size_bytes)
    outvalue = val - fee
    if outvalue <= dust_threshold(): return None
    sweep_outputs = [TxOutput(TYPE_ADDRESS, sweep_address, outvalue)]
    tx = Transaction.from_io(sweep_inputs, sweep_outputs, version=2, name=name_prefix + htlc_tx.txid(), csv_delay=to_self_delay)

    sig = bfh(tx.sign_txin(0, privkey))
    witness = construct_witness([sig, int(is_revocation), htlctx_witness_script])
    tx.inputs()[0]['witness'] = witness
    assert tx.is_complete()
    return tx
