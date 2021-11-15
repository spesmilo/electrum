# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import Optional, Dict, List, Tuple, TYPE_CHECKING, NamedTuple, Callable
from enum import Enum, auto

from .util import bfh, bh2u, UneconomicFee
from .bitcoin import redeem_script_to_address, dust_threshold, construct_witness
from .invoices import PR_PAID
from . import coinchooser
from . import ecc
from .lnutil import (make_commitment_output_to_remote_address, make_commitment_output_to_local_witness_script,
                     derive_privkey, derive_pubkey, derive_blinded_pubkey, derive_blinded_privkey,
                     make_htlc_tx_witness, make_htlc_tx_with_open_channel, UpdateAddHtlc,
                     LOCAL, REMOTE, make_htlc_output_witness_script,
                     get_ordered_channel_configs, privkey_to_pubkey, get_per_commitment_secret_from_seed,
                     RevocationStore, extract_ctn_from_tx_and_chan, UnableToDeriveSecret, SENT, RECEIVED,
                     map_htlcs_to_ctx_output_idxs, Direction, make_commitment_output_to_remote_witness_script,
                     derive_payment_basepoint, ctx_has_anchors, SCRIPT_TEMPLATE_FUNDING)
from .transaction import (Transaction, TxInput, PartialTransaction, PartialTxInput,
                          PartialTxOutput, TxOutpoint, script_GetOp, match_script_against_template)
from .simple_config import SimpleConfig
from .logging import get_logger, Logger

if TYPE_CHECKING:
    from .lnchannel import Channel, AbstractChannel, ChannelBackup


_logger = get_logger(__name__)

HTLC_TRANSACTION_DEADLINE_FRACTION = 4
HTLC_TRANSACTION_SWEEP_TARGET = 10
HTLCTX_INPUT_OUTPUT_INDEX = 0


class SweepInfo(NamedTuple):
    name: str
    csv_delay: int
    cltv_expiry: int
    gen_tx: Callable[[], Optional[Transaction]]


def extract_ctx_secrets(chan: 'Channel', ctx: Transaction):
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
        #_logger.info(f'tx for revoked: {list(txs.keys())}')
    elif chan.get_data_loss_protect_remote_pcp(ctn):
        their_pcp = chan.get_data_loss_protect_remote_pcp(ctn)
        is_revocation = False
    else:
        return
    return ctn, their_pcp, is_revocation, per_commitment_secret


def extract_funding_pubkeys_from_ctx(txin: TxInput) -> Tuple[bytes, bytes]:
    """Extract the two funding pubkeys from the published commitment transaction.

    We expect to see a witness script of: OP_2 pk1 pk2 OP_2 OP_CHECKMULTISIG"""
    elements = txin.witness_elements()
    witness_script = elements[-1]
    assert match_script_against_template(witness_script, SCRIPT_TEMPLATE_FUNDING)
    parsed_script = [x for x in script_GetOp(witness_script)]
    pubkey1 = parsed_script[1][1]
    pubkey2 = parsed_script[2][1]
    return (pubkey1, pubkey2)


def txs_our_ctx(
        *, chan: 'AbstractChannel',
        ctx: Transaction,
        sweep_address: str) -> Optional[Dict[str, SweepInfo]]:
    """Handle the case where we force-close unilaterally with our latest ctx.

    We sweep:
        to_local: CSV delayed
        htlc success: CSV delay with anchors, no delay otherwise
        htlc timeout: CSV delay with anchors, CLTV locktime
        second-stage htlc transactions: CSV delay

    'to_local' can be swept even if this is a breach (by us),
    but HTLCs cannot (old HTLCs are no longer stored).

    Outputs with CSV/CLTV are redeemed by LNWatcher.
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
    to_local_witness_script = bh2u(make_commitment_output_to_local_witness_script(
        their_revocation_pubkey, to_self_delay, our_localdelayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', to_local_witness_script)
    # test if this is our_ctx
    found_to_local = bool(ctx.get_output_idxs_from_address(to_local_address))
    if not chan.is_backup():
        assert chan.is_static_remotekey_enabled()
        their_payment_pubkey = their_conf.payment_basepoint.pubkey
        to_remote_address = make_commitment_output_to_remote_address(their_payment_pubkey, has_anchors=chan.has_anchors())
        found_to_remote = bool(ctx.get_output_idxs_from_address(to_remote_address))
    else:
        found_to_remote = False
    if not found_to_local and not found_to_remote:
        return
    _logger.debug(f'found our ctx: {to_local_address} {to_remote_address}')
    # other outputs are htlcs
    # if they are spent, we need to generate the script
    # so, second-stage htlc sweep should not be returned here
    txs = {}  # type: Dict[str, SweepInfo]
    # to_local
    output_idxs = ctx.get_output_idxs_from_address(to_local_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        sweep_tx = lambda: tx_ctx_to_local(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            witness_script=bfh(to_local_witness_script),
            privkey=our_localdelayed_privkey.get_secret_bytes(),
            is_revocation=False,
            to_self_delay=to_self_delay,
            config=chan.lnworker.config)
        prevout = ctx.txid() + ':%d'%output_idx
        txs[prevout] = SweepInfo(
            name='our_ctx_to_local',
            csv_delay=to_self_delay,
            cltv_expiry=0,
            gen_tx=sweep_tx)
    we_breached = ctn < chan.get_oldest_unrevoked_ctn(LOCAL)
    if we_breached:
        _logger.info("we breached.")
        # return only our_ctx_to_local, because we don't keep htlc_signatures for old states
        return txs

    # HTLCs
    def txs_htlc(
            *, htlc: 'UpdateAddHtlc',
            htlc_direction: Direction,
            ctx_output_idx: int,
            htlc_relative_idx,
            preimage: Optional[bytes]):
        htlctx_witness_script, htlc_tx = tx_our_ctx_htlctx(
            chan=chan,
            our_pcp=our_pcp,
            ctx=ctx,
            htlc=htlc,
            local_htlc_privkey=our_htlc_privkey,
            preimage=preimage,
            htlc_direction=htlc_direction,
            ctx_output_idx=ctx_output_idx,
            htlc_relative_idx=htlc_relative_idx)
        # we sweep our ctx with HTLC transactions individually, therefore the CSV-locked output is always at
        # index TIMELOCKED_HTLCTX_OUTPUT_INDEX
        assert True
        sweep_tx = lambda: tx_sweep_htlctx_output(
            to_self_delay=to_self_delay,
            htlc_tx=htlc_tx,
            output_idx=HTLCTX_INPUT_OUTPUT_INDEX,
            htlctx_witness_script=htlctx_witness_script,
            sweep_address=sweep_address,
            privkey=our_localdelayed_privkey.get_secret_bytes(),
            is_revocation=False,
            config=chan.lnworker.config)
        # side effect
        txs[htlc_tx.inputs()[HTLCTX_INPUT_OUTPUT_INDEX].prevout.to_str()] = SweepInfo(
            name='first-stage-htlc',
            csv_delay=0,
            cltv_expiry=htlc_tx.locktime,
            gen_tx=lambda: htlc_tx)
        txs[htlc_tx.txid() + f':{HTLCTX_INPUT_OUTPUT_INDEX}'] = SweepInfo(
            name='second-stage-htlc',
            csv_delay=to_self_delay,
            cltv_expiry=0,
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
        try:
            txs_htlc(
                htlc=htlc,
                htlc_direction=direction,
                ctx_output_idx=ctx_output_idx,
                htlc_relative_idx=htlc_relative_idx,
                preimage=preimage)
        except UneconomicFee:
            continue
    return txs




def tx_ctx_to_local(
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
    sweep_tx.inputs()[0].witness = bfh(witness)
    return sweep_tx
        


def tx_our_ctx_htlctx(
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
    witness_script, maybe_zero_fee_htlc_tx = make_htlc_tx_with_open_channel(
        chan=chan,
        pcp=our_pcp,
        subject=LOCAL,
        ctn=ctn,
        htlc_direction=htlc_direction,
        commit=ctx,
        htlc=htlc,
        ctx_output_idx=ctx_output_idx,
        name=f'our_ctx_{ctx_output_idx}_htlc_tx_{bh2u(htlc.payment_hash)}')

    # we need to attach inputs that pay for the transaction fee
    if chan.has_anchors():
        wallet = chan.lnworker.wallet
        coins = wallet.get_spendable_coins(None)

        def fee_estimator(size):
            if htlc_direction == SENT:
                # we deal with an offered HTLC and therefore with a timeout transaction
                # in this case it is not time critical for us to sweep unless we
                # become a forwarding node
                fee_per_kb = wallet.config.eta_target_to_fee(HTLC_TRANSACTION_SWEEP_TARGET)
            else:
                # in the case of a received HTLC, if we have the hash preimage,
                # we should sweep before the timelock expires
                expiry_height = htlc.cltv_expiry
                current_height = wallet.network.blockchain().height()
                deadline_blocks = expiry_height - current_height
                # target block inclusion with a safety buffer
                target = int(deadline_blocks / HTLC_TRANSACTION_DEADLINE_FRACTION)
                fee_per_kb = wallet.config.eta_target_to_fee(target)
            if not fee_per_kb:  # testnet and other cases
                fee_per_kb = wallet.config.fee_per_kb()
            fee = wallet.config.estimate_fee_for_feerate(fee_per_kb=fee_per_kb, size=size)
            # we only sweep if it is makes sense economically
            if fee > htlc.amount_msat // 1000:
                raise UneconomicFee
            return fee

        coin_chooser = coinchooser.get_coin_chooser(wallet.config)
        change_address = wallet.get_single_change_address_for_new_transaction()
        funded_htlc_tx = coin_chooser.make_tx(
            coins=coins,
            inputs=maybe_zero_fee_htlc_tx.inputs(),
            outputs=maybe_zero_fee_htlc_tx.outputs(),
            change_addrs=[change_address],
            fee_estimator_vb=fee_estimator,
            dust_threshold=wallet.dust_threshold())

        # place htlc input/output at corresponding indices (due to sighash single)
        htlc_outpoint = TxOutpoint(txid=bfh(ctx.txid()), out_idx=ctx_output_idx)
        htlc_input_idx = funded_htlc_tx.get_input_idx_that_spent_prevout(htlc_outpoint)

        htlc_out_address = maybe_zero_fee_htlc_tx.outputs()[HTLCTX_INPUT_OUTPUT_INDEX].address
        htlc_output_idx = funded_htlc_tx.get_output_idxs_from_address(htlc_out_address).pop()
        inputs = funded_htlc_tx.inputs()
        outputs = funded_htlc_tx.outputs()
        if htlc_input_idx != HTLCTX_INPUT_OUTPUT_INDEX:
            htlc_txin = inputs.pop(htlc_input_idx)
            inputs.insert(HTLCTX_INPUT_OUTPUT_INDEX, htlc_txin)
        if htlc_output_idx != HTLCTX_INPUT_OUTPUT_INDEX:
            htlc_txout = outputs.pop(htlc_output_idx)
            outputs.insert(HTLCTX_INPUT_OUTPUT_INDEX, htlc_txout)
        final_htlc_tx = PartialTransaction.from_io(
            inputs,
            outputs,
            locktime=maybe_zero_fee_htlc_tx.locktime,
            version=maybe_zero_fee_htlc_tx.version,
            BIP69_sort=False
        )

        for fee_input_idx in range(1, len(funded_htlc_tx.inputs())):
            txin = final_htlc_tx.inputs()[fee_input_idx]
            pubkey = wallet.get_public_key(txin.address)
            index = wallet.get_address_index(txin.address)
            privkey, _ = wallet.keystore.get_private_key(index, chan.lnworker.wallet_password) # FIXME
            txin.num_sig = 1
            txin.script_type = 'p2wpkh'
            txin.pubkeys = [bfh(pubkey)]
            fee_input_sig = final_htlc_tx.sign_txin(fee_input_idx, privkey)
            final_htlc_tx.add_signature_to_txin(txin_idx=fee_input_idx, signing_pubkey=pubkey, sig=fee_input_sig)
    else:
        final_htlc_tx = maybe_zero_fee_htlc_tx

    # sign HTLC output
    remote_htlc_sig = chan.get_remote_htlc_sig_for_htlc(htlc_relative_idx=htlc_relative_idx)
    local_htlc_sig = bfh(final_htlc_tx.sign_txin(HTLCTX_INPUT_OUTPUT_INDEX, local_htlc_privkey))
    txin = final_htlc_tx.inputs()[HTLCTX_INPUT_OUTPUT_INDEX]
    witness_program = bfh(Transaction.get_preimage_script(txin))
    txin.witness = make_htlc_tx_witness(remote_htlc_sig, local_htlc_sig, preimage, witness_program)
    return witness_script, final_htlc_tx


def tx_sweep_htlctx_output(
        *, htlc_tx: Transaction, output_idx: int, htlctx_witness_script: bytes, sweep_address: str,
        privkey: bytes, is_revocation: bool, to_self_delay: int = None,
        config: SimpleConfig) -> Optional[PartialTransaction]:
    """Create a txn that sweeps the output of a first stage htlc tx
    (i.e. sweeps from an HTLC-Timeout or an HTLC-Success tx).
    """
    # note: this is the same as sweeping the to_local output of the ctx,
    #       as these are the same script (address-reuse).
    return tx_ctx_to_local(
        sweep_address=sweep_address,
        ctx=htlc_tx,
        output_idx=output_idx,
        witness_script=htlctx_witness_script,
        privkey=privkey,
        is_revocation=is_revocation,
        to_self_delay=to_self_delay,
        config=config,
    )


def txs_their_ctx(
        *, chan: 'Channel',
        ctx: Transaction,
        sweep_address: str) -> Optional[Dict[str,SweepInfo]]:
    """Handle the case where the remote force-closes with their ctx.

    We sweep:
        to_local: if revoked
        to_remote: CSV delay with anchors, otherwise sweeping not needed
        htlc success: CSV delay with anchors, no delay otherwise, or revoked
        htlc timeout: CSV delay with anchors, CLTV locktime, or revoked
        second-stage htlc transactions: CSV delay

    Outputs with CSV/CLTV are redeemed by LNWatcher.
    """
    txs = {}  # type: Dict[str, SweepInfo]
    our_conf, their_conf = get_ordered_channel_configs(chan=chan, for_us=True)
    x = extract_ctx_secrets(chan, ctx)
    if not x:
        return
    ctn, their_pcp, is_revocation, per_commitment_secret = x
    # to_local
    our_revocation_pubkey = derive_blinded_pubkey(our_conf.revocation_basepoint.pubkey, their_pcp)
    their_delayed_pubkey = derive_pubkey(their_conf.delayed_basepoint.pubkey, their_pcp)
    witness_script = bh2u(make_commitment_output_to_local_witness_script(
        our_revocation_pubkey, our_conf.to_self_delay, their_delayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    # test if this is their ctx
    found_to_local = bool(ctx.get_output_idxs_from_address(to_local_address))
    if not chan.is_backup():
        assert chan.is_static_remotekey_enabled()
        our_payment_pubkey = our_conf.payment_basepoint.pubkey
        to_remote_address = make_commitment_output_to_remote_address(our_payment_pubkey, has_anchors=chan.has_anchors())
        found_to_remote = bool(ctx.get_output_idxs_from_address(to_remote_address))
    else:
        found_to_remote = False
    if not found_to_local and not found_to_remote:
        return
    _logger.debug(f'found their ctx: {to_local_address} {to_remote_address}')

    # to_local is handled by lnwatcher
    if is_revocation:
        our_revocation_privkey = derive_blinded_privkey(our_conf.revocation_basepoint.privkey, per_commitment_secret)
        gen_tx = tx_their_ctx_justice(chan, ctx, per_commitment_secret, chan.sweep_address)
        if gen_tx:
            tx = gen_tx()
            txs[tx.inputs()[0].prevout.to_str()] = SweepInfo(
                name='to_local_for_revoked_ctx',
                csv_delay=0,
                cltv_expiry=0,
                gen_tx=gen_tx)


    # to_remote
    if chan.has_anchors():
        csv_delay = 1
        sweep_to_remote = True
        our_payment_privkey = ecc.ECPrivkey(our_conf.payment_basepoint.privkey)
    else:
        assert chan.is_static_remotekey_enabled()
        csv_delay = 0
        sweep_to_remote = False
        our_payment_privkey = None

    if sweep_to_remote:
        assert our_payment_pubkey == our_payment_privkey.get_public_key_bytes(compressed=True)
        output_idxs = ctx.get_output_idxs_from_address(to_remote_address)
        if output_idxs:
            output_idx = output_idxs.pop()
            prevout = ctx.txid() + ':%d' % output_idx
            sweep_tx = lambda: tx_their_ctx_to_remote(
                sweep_address=sweep_address,
                ctx=ctx,
                output_idx=output_idx,
                our_payment_privkey=our_payment_privkey,
                config=chan.lnworker.config,
                has_anchors=chan.has_anchors()
            )
            txs[prevout] = SweepInfo(
                name='their_ctx_to_remote',
                csv_delay=csv_delay,
                cltv_expiry=0,
                gen_tx=sweep_tx)

    # HTLCs
    our_htlc_privkey = derive_privkey(secret=int.from_bytes(our_conf.htlc_basepoint.privkey, 'big'), per_commitment_point=their_pcp)
    our_htlc_privkey = ecc.ECPrivkey.from_secret_scalar(our_htlc_privkey)
    their_htlc_pubkey = derive_pubkey(their_conf.htlc_basepoint.pubkey, their_pcp)
    def tx_htlc(
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
            cltv_expiry=htlc.cltv_expiry,
            has_anchors=chan.has_anchors()
        )

        cltv_expiry = htlc.cltv_expiry if is_received_htlc else 0
        csv_delay = 1 if chan.has_anchors() else 0
        prevout = ctx.txid() + ':%d'%ctx_output_idx
        sweep_tx = lambda: tx_their_ctx_htlc(
            ctx=ctx,
            witness_script=htlc_output_witness_script,
            sweep_address=sweep_address,
            preimage=preimage,
            output_idx=ctx_output_idx,
            privkey=our_revocation_privkey if is_revocation else our_htlc_privkey.get_secret_bytes(),
            is_revocation=is_revocation,
            cltv_expiry=cltv_expiry,
            config=chan.lnworker.config,
            has_anchors=chan.has_anchors()
        )
        txs[prevout] = SweepInfo(
            name=f'their_ctx_htlc_{ctx_output_idx}{"_for_revoked_ctx" if is_revocation else ""}',
            csv_delay=csv_delay,
            cltv_expiry=cltv_expiry,
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
        tx_htlc(
            htlc=htlc,
            is_received_htlc=is_received_htlc,
            ctx_output_idx=ctx_output_idx,
            preimage=preimage)
    return txs



def txs_their_ctx_watchtower(chan: 'Channel', ctx: Transaction, per_commitment_secret: bytes,
                             sweep_address: str) -> List[Transaction]:
    """Presign sweeping transactions using the just received revoked pcs.
    These will only be utilised if the remote breaches.
    Sweep 'to_local', and all the HTLCs (two cases: directly from ctx, or from HTLC tx).
    """
    # prep
    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
    pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    breacher_conf, watcher_conf = get_ordered_channel_configs(chan=chan, for_us=False)
    watcher_revocation_privkey = derive_blinded_privkey(
        watcher_conf.revocation_basepoint.privkey,
        per_commitment_secret
    )
    to_self_delay = watcher_conf.to_self_delay
    breacher_delayed_pubkey = derive_pubkey(breacher_conf.delayed_basepoint.pubkey, pcp)
    txs = []

    # create justice tx for breacher's to_local output
    revocation_pubkey = ecc.ECPrivkey(watcher_revocation_privkey).get_public_key_bytes(compressed=True)
    witness_script = bh2u(make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, breacher_delayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    output_idxs = ctx.get_output_idxs_from_address(to_local_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        sweep_tx = tx_ctx_to_local(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            witness_script=bfh(witness_script),
            privkey=watcher_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config)
        if sweep_tx:
            txs.append(sweep_tx)

    # create justice txs for breacher's HTLC outputs
    breacher_htlc_pubkey = derive_pubkey(breacher_conf.htlc_basepoint.pubkey, pcp)
    watcher_htlc_pubkey = derive_pubkey(watcher_conf.htlc_basepoint.pubkey, pcp)
    def tx_htlc(
            htlc: 'UpdateAddHtlc', is_received_htlc: bool,
            ctx_output_idx: int) -> None:
        htlc_output_witness_script = make_htlc_output_witness_script(
            is_received_htlc=is_received_htlc,
            remote_revocation_pubkey=revocation_pubkey,
            remote_htlc_pubkey=watcher_htlc_pubkey,
            local_htlc_pubkey=breacher_htlc_pubkey,
            payment_hash=htlc.payment_hash,
            cltv_expiry=htlc.cltv_expiry,
            has_anchors=chan.has_anchors()
        )

        cltv_expiry = htlc.cltv_expiry if is_received_htlc else 0
        return tx_their_ctx_htlc(
            ctx=ctx,
            witness_script=htlc_output_witness_script,
            sweep_address=sweep_address,
            preimage=None,
            output_idx=ctx_output_idx,
            privkey=watcher_revocation_privkey,
            is_revocation=True,
            cltv_expiry=cltv_expiry,
            config=chan.lnworker.config,
            has_anchors=chan.has_anchors()
        )
    htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(
        chan=chan,
        ctx=ctx,
        pcp=pcp,
        subject=REMOTE,
        ctn=ctn)
    for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
        txs.append(
            tx_htlc(
                htlc=htlc,
                is_received_htlc=direction == RECEIVED,
                ctx_output_idx=ctx_output_idx)
        )

    # for anchor channels we don't know the HTLC transaction's txid beforehand due
    # to malleability because of ANYONECANPAY
    if chan.has_anchors():
        return txs

    # create justice transactions for HTLC transaction's outputs
    def txs_their_htlctx_justice(
            *,
            htlc: 'UpdateAddHtlc',
            htlc_direction: Direction,
            ctx_output_idx: int
    ) -> Optional[Transaction]:
        htlc_tx_witness_script, htlc_tx = make_htlc_tx_with_open_channel(
            chan=chan,
            pcp=pcp,
            subject=REMOTE,
            ctn=ctn,
            htlc_direction=htlc_direction,
            commit=ctx,
            htlc=htlc,
            ctx_output_idx=ctx_output_idx)
        return tx_sweep_htlctx_output(
            htlc_tx=htlc_tx,
            output_idx=HTLCTX_INPUT_OUTPUT_INDEX,
            htlctx_witness_script=htlc_tx_witness_script,
            sweep_address=sweep_address,
            privkey=watcher_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config)
    htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(
        chan=chan,
        ctx=ctx,
        pcp=pcp,
        subject=REMOTE,
        ctn=ctn)
    for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
        secondstage_sweep_tx = txs_their_htlctx_justice(
            htlc=htlc,
            htlc_direction=direction,
            ctx_output_idx=ctx_output_idx)
        if secondstage_sweep_tx:
            txs.append(secondstage_sweep_tx)
    return txs


def tx_their_ctx_to_remote(
        sweep_address: str, ctx: Transaction, output_idx: int,
        our_payment_privkey: ecc.ECPrivkey,
        config: SimpleConfig,
        has_anchors: bool
) -> Optional[PartialTransaction]:
    our_payment_pubkey = our_payment_privkey.get_public_key_hex(compressed=True)
    val = ctx.outputs()[output_idx].value
    prevout = TxOutpoint(txid=bfh(ctx.txid()), out_idx=output_idx)
    txin = PartialTxInput(prevout=prevout)
    txin._trusted_value_sats = val
    txin.pubkeys = [bfh(our_payment_pubkey)]
    txin.num_sig = 1
    if not has_anchors:
        txin.script_type = 'p2wpkh'
        tx_size_bytes = 110  # approx size of p2wpkh->p2wpkh
    else:
        txin.script_sig = b''
        txin.witness_script = make_commitment_output_to_remote_witness_script(bfh(our_payment_pubkey))
        txin.nsequence = 1
        tx_size_bytes = 196  # approx size of p2wsh->p2wpkh
    sweep_inputs = [txin]
    fee = config.estimate_fee(tx_size_bytes, allow_fallback_to_static_rates=True)
    outvalue = val - fee
    if outvalue <= dust_threshold(): return None
    sweep_outputs = [PartialTxOutput.from_address_and_value(sweep_address, outvalue)]
    sweep_tx = PartialTransaction.from_io(sweep_inputs, sweep_outputs)

    if not has_anchors:
        sweep_tx.set_rbf(True)
        sweep_tx.sign({our_payment_pubkey: (our_payment_privkey.get_secret_bytes(), True)})
    else:
        sig = sweep_tx.sign_txin(0, our_payment_privkey.get_secret_bytes())
        witness = construct_witness([sig, sweep_tx.inputs()[0].witness_script])
        sweep_tx.inputs()[0].witness = bfh(witness)

    if not sweep_tx.is_complete():
        raise Exception('channel close sweep tx is not complete')
    return sweep_tx


def tx_their_ctx_to_remote_backup(
        *, chan: 'ChannelBackup',
        ctx: Transaction,
        sweep_address: str) -> Optional[Dict[str, SweepInfo]]:
    txs = {}  # type: Dict[str, SweepInfo]
    """If we only have a backup, and the remote force-closed with their ctx,
    and anchors are enabled, we need to sweep to_remote."""

    if ctx_has_anchors(ctx):
        # for anchors we need to sweep to_remote
        funding_pubkeys = extract_funding_pubkeys_from_ctx(ctx.inputs()[0])
        _logger.debug(f'checking their ctx for funding pubkeys: {[pk.hex() for pk in funding_pubkeys]}')
        # check which of the pubkey was ours
        for pubkey in funding_pubkeys:
            candidate_basepoint = derive_payment_basepoint(chan.lnworker.static_payment_key.privkey, funding_pubkey=pubkey)
            candidate_to_remote_address = make_commitment_output_to_remote_address(candidate_basepoint.pubkey, has_anchors=True)
            if ctx.get_output_idxs_from_address(candidate_to_remote_address):
                our_payment_pubkey = candidate_basepoint
                to_remote_address = candidate_to_remote_address
                _logger.debug(f'found funding pubkey')
                break
        else:
            return
    else:
        # we are dealing with static_remotekey which is locked to a wallet address
        return {}

    # to_remote
    csv_delay = 1
    our_payment_privkey = ecc.ECPrivkey(our_payment_pubkey.privkey)
    output_idxs = ctx.get_output_idxs_from_address(to_remote_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        prevout = ctx.txid() + ':%d' % output_idx
        sweep_tx = lambda: tx_their_ctx_to_remote(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            our_payment_privkey=our_payment_privkey,
            config=chan.lnworker.config,
            has_anchors=True
        )
        txs[prevout] = SweepInfo(
            name='their_ctx_to_remote_backup',
            csv_delay=csv_delay,
            cltv_expiry=0,
            gen_tx=sweep_tx)
    return txs


def tx_their_ctx_htlc(
        ctx: Transaction, witness_script: bytes, sweep_address: str,
        preimage: Optional[bytes], output_idx: int,
        privkey: bytes, is_revocation: bool,
        cltv_expiry: int, config: SimpleConfig,
        has_anchors: bool
) -> Optional[PartialTransaction]:
    """Deals with normal (non-CSV timelocked) HTLC output sweeps."""
    assert type(cltv_expiry) is int
    preimage = preimage or b''  # preimage is required iff (not is_revocation and htlc is offered)
    val = ctx.outputs()[output_idx].value
    prevout = TxOutpoint(txid=bfh(ctx.txid()), out_idx=output_idx)
    txin = PartialTxInput(prevout=prevout)
    txin._trusted_value_sats = val
    txin.witness_script = witness_script
    txin.script_sig = b''
    if has_anchors:
        txin.nsequence = 1
    sweep_inputs = [txin]
    tx_size_bytes = 200  # TODO (depends on offered/received and is_revocation)
    fee = config.estimate_fee(tx_size_bytes, allow_fallback_to_static_rates=True)
    outvalue = val - fee
    if outvalue <= dust_threshold(): return None
    sweep_outputs = [PartialTxOutput.from_address_and_value(sweep_address, outvalue)]
    tx = PartialTransaction.from_io(sweep_inputs, sweep_outputs, version=2, locktime=cltv_expiry)
    sig = bfh(tx.sign_txin(0, privkey))
    if not is_revocation:
        witness = construct_witness([sig, preimage, witness_script])
    else:
        revocation_pubkey = privkey_to_pubkey(privkey)
        witness = construct_witness([sig, revocation_pubkey, witness_script])
    tx.inputs()[0].witness = bfh(witness)
    assert tx.is_complete()
    return tx


def tx_their_ctx_justice(
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
    witness_script = bh2u(make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, this_delayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    output_idxs = ctx.get_output_idxs_from_address(to_local_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        sweep_tx = lambda: tx_ctx_to_local(
            sweep_address=sweep_address,
            ctx=ctx,
            output_idx=output_idx,
            witness_script=bfh(witness_script),
            privkey=other_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config)
        return sweep_tx
    return None


def txs_their_htlctx_justice(
        chan: 'Channel',
        ctx: Transaction,
        htlc_tx: Transaction,
        sweep_address: str) -> Dict[int, SweepInfo]:
    """Creates justice transactions for every output in the HTLC transaction.

    Due to anchor type channels it can happen that a remote party batches HTLC transactions,
    which is why this method can return multiple SweepInfos.
    """
    x = extract_ctx_secrets(chan, ctx)
    if not x:
        return {}
    ctn, their_pcp, is_revocation, per_commitment_secret = x
    if not is_revocation:
        return {}

    # get HTLC constraints (secrets and locktime)
    pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    this_conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=False)
    other_revocation_privkey = derive_blinded_privkey(
        other_conf.revocation_basepoint.privkey,
        per_commitment_secret)
    to_self_delay = other_conf.to_self_delay
    this_delayed_pubkey = derive_pubkey(this_conf.delayed_basepoint.pubkey, pcp)

    revocation_pubkey = ecc.ECPrivkey(other_revocation_privkey).get_public_key_bytes(compressed=True)
    # uses the same witness script as to_local
    witness_script = bh2u(make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, this_delayed_pubkey))
    htlc_address = redeem_script_to_address('p2wsh', witness_script)

    # check that htlc transaction contains at least an output that is supposed to be
    # spent via a second stage htlc transaction
    htlc_outputs_idxs = [idx for idx, output in enumerate(htlc_tx.outputs()) if output.address == htlc_address]
    if not htlc_outputs_idxs:
        return {}

    index_to_sweepinfo = {}
    for output_idx in htlc_outputs_idxs:
        # generate justice transactions
        gen_tx = lambda: tx_sweep_htlctx_output(
            sweep_address=sweep_address,
            output_idx=output_idx,
            htlc_tx=htlc_tx,
            htlctx_witness_script=bfh(witness_script),
            privkey=other_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config
        )
        index_to_sweepinfo[output_idx] = SweepInfo(
            name='redeem_htlc2',
            csv_delay=0,
            cltv_expiry=0,
            gen_tx=gen_tx
        )

    return index_to_sweepinfo
