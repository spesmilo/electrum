# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from typing import Optional, Dict, List, Tuple, TYPE_CHECKING, NamedTuple, Callable

import electrum_ecc as ecc

from .util import bfh, UneconomicFee
from .crypto import privkey_to_pubkey
from .bitcoin import redeem_script_to_address, dust_threshold, construct_witness
from . import descriptor
from . import bitcoin

from .lnutil import (make_commitment_output_to_remote_address, make_commitment_output_to_local_witness_script,
                     derive_privkey, derive_pubkey, derive_blinded_pubkey, derive_blinded_privkey,
                     make_htlc_tx_witness, make_htlc_tx_with_open_channel, UpdateAddHtlc,
                     LOCAL, REMOTE, make_htlc_output_witness_script,
                     get_ordered_channel_configs, get_per_commitment_secret_from_seed,
                     RevocationStore, extract_ctn_from_tx_and_chan, UnableToDeriveSecret, SENT, RECEIVED,
                     map_htlcs_to_ctx_output_idxs, Direction, make_commitment_output_to_remote_witness_script,
                     derive_payment_basepoint, ctx_has_anchors, SCRIPT_TEMPLATE_FUNDING, Keypair,
                     derive_multisig_funding_key_if_we_opened, derive_multisig_funding_key_if_they_opened)
from .transaction import (Transaction, TxInput, PartialTxInput,
                          PartialTxOutput, TxOutpoint, script_GetOp, match_script_against_template)
from .simple_config import SimpleConfig
from .logging import get_logger, Logger

if TYPE_CHECKING:
    from .lnchannel import Channel, AbstractChannel, ChannelBackup


_logger = get_logger(__name__)
# note: better to use chan.logger instead, when applicable

HTLC_TRANSACTION_DEADLINE_FRACTION = 4
HTLC_TRANSACTION_SWEEP_TARGET = 10
HTLCTX_INPUT_OUTPUT_INDEX = 0


class SweepInfo(NamedTuple):
    name: str
    csv_delay: int
    cltv_abs: Optional[int] # set to None only if the script has no cltv
    txin: PartialTxInput
    txout: Optional[PartialTxOutput]  # only for first-stage htlc tx

def sweep_their_ctx_watchtower(
        chan: 'Channel',
        ctx: Transaction,
        per_commitment_secret: bytes
) -> List[PartialTxInput]:
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
    txins = []
    # create justice tx for breacher's to_local output
    revocation_pubkey = ecc.ECPrivkey(watcher_revocation_privkey).get_public_key_bytes(compressed=True)
    witness_script = make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, breacher_delayed_pubkey)
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    output_idxs = ctx.get_output_idxs_from_address(to_local_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        txin = sweep_ctx_to_local(
            ctx=ctx,
            output_idx=output_idx,
            witness_script=witness_script,
            privkey=watcher_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config)
        if txin:
            txins.append(txin)

    # create justice txs for breacher's HTLC outputs
    breacher_htlc_pubkey = derive_pubkey(breacher_conf.htlc_basepoint.pubkey, pcp)
    watcher_htlc_pubkey = derive_pubkey(watcher_conf.htlc_basepoint.pubkey, pcp)
    def txin_htlc(
            htlc: 'UpdateAddHtlc', is_received_htlc: bool,
            ctx_output_idx: int) -> None:
        htlc_output_witness_script = make_htlc_output_witness_script(
            is_received_htlc=is_received_htlc,
            remote_revocation_pubkey=revocation_pubkey,
            remote_htlc_pubkey=watcher_htlc_pubkey,
            local_htlc_pubkey=breacher_htlc_pubkey,
            payment_hash=htlc.payment_hash,
            cltv_abs=htlc.cltv_abs,
            has_anchors=chan.has_anchors()
        )
        cltv_abs = htlc.cltv_abs if is_received_htlc else 0
        return sweep_their_ctx_htlc(
            ctx=ctx,
            witness_script=htlc_output_witness_script,
            preimage=None,
            output_idx=ctx_output_idx,
            privkey=watcher_revocation_privkey,
            is_revocation=True,
            cltv_abs=cltv_abs,
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
        txins.append(
            txin_htlc(
                htlc=htlc,
                is_received_htlc=direction == RECEIVED,
                ctx_output_idx=ctx_output_idx)
        )
    # for anchor channels we don't know the HTLC transaction's txid beforehand due
    # to malleability because of ANYONECANPAY
    if chan.has_anchors():
        return txins

    # create justice transactions for HTLC transaction's outputs
    def sweep_their_htlctx_justice(
            *,
            htlc: 'UpdateAddHtlc',
            htlc_direction: Direction,
            ctx_output_idx: int
    ) -> Optional[PartialTxInput]:
        htlc_tx_witness_script, htlc_tx = make_htlc_tx_with_open_channel(
            chan=chan,
            pcp=pcp,
            subject=REMOTE,
            ctn=ctn,
            htlc_direction=htlc_direction,
            commit=ctx,
            htlc=htlc,
            ctx_output_idx=ctx_output_idx)
        return sweep_htlctx_output(
            htlc_tx=htlc_tx,
            output_idx=HTLCTX_INPUT_OUTPUT_INDEX,
            htlctx_witness_script=htlc_tx_witness_script,
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
        secondstage_sweep_tx = sweep_their_htlctx_justice(
            htlc=htlc,
            htlc_direction=direction,
            ctx_output_idx=ctx_output_idx)
        if secondstage_sweep_tx:
            txins.append(secondstage_sweep_tx)
    return txins


def sweep_their_ctx_justice(
        chan: 'Channel',
        ctx: Transaction,
        per_commitment_secret: bytes,
) -> Optional[PartialTxInput]:
    # prep
    pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    this_conf, other_conf = get_ordered_channel_configs(chan=chan, for_us=False)
    other_revocation_privkey = derive_blinded_privkey(other_conf.revocation_basepoint.privkey,
                                                      per_commitment_secret)
    to_self_delay = other_conf.to_self_delay
    this_delayed_pubkey = derive_pubkey(this_conf.delayed_basepoint.pubkey, pcp)

    # to_local
    revocation_pubkey = ecc.ECPrivkey(other_revocation_privkey).get_public_key_bytes(compressed=True)
    witness_script = make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, this_delayed_pubkey)
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    output_idxs = ctx.get_output_idxs_from_address(to_local_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        sweep_txin = sweep_ctx_to_local(
            ctx=ctx,
            output_idx=output_idx,
            witness_script=witness_script,
            privkey=other_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config)
        return sweep_txin
    return None


def sweep_their_htlctx_justice(
        chan: 'Channel',
        ctx: Transaction,
        htlc_tx: Transaction,
) -> Dict[str, SweepInfo]:
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
    witness_script = make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, this_delayed_pubkey)
    htlc_address = redeem_script_to_address('p2wsh', witness_script)
    # check that htlc transaction contains at least an output that is supposed to be
    # spent via a second stage htlc transaction
    htlc_outputs_idxs = [idx for idx, output in enumerate(htlc_tx.outputs()) if output.address == htlc_address]
    if not htlc_outputs_idxs:
        return {}

    # generate justice transactions
    def justice_txin(output_idx):
        return sweep_htlctx_output(
            output_idx=output_idx,
            htlc_tx=htlc_tx,
            htlctx_witness_script=witness_script,
            privkey=other_revocation_privkey,
            is_revocation=True,
            config=chan.lnworker.config
        )
    index_to_sweepinfo = {}
    for output_idx in htlc_outputs_idxs:
        prevout = htlc_tx.txid() + f':{output_idx}'
        index_to_sweepinfo[prevout] = SweepInfo(
            name=f'second-stage-htlc:{output_idx}',
            csv_delay=0,
            cltv_abs=None,
            txin=justice_txin(output_idx),
            txout=None
        )

    return index_to_sweepinfo


def sweep_our_htlctx(
        chan: 'AbstractChannel',
        ctx: Transaction,
        htlc_tx: Transaction):
    txs = sweep_our_ctx(
        chan=chan,
        ctx=ctx,
        actual_htlc_tx=htlc_tx)
    return txs


def sweep_our_ctx(
        *, chan: 'AbstractChannel',
        ctx: Transaction,
        actual_htlc_tx: Transaction=None, # if passed, second stage
) -> Dict[str, SweepInfo]:

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
    to_local_witness_script = make_commitment_output_to_local_witness_script(
        their_revocation_pubkey, to_self_delay, our_localdelayed_pubkey)
    to_local_address = redeem_script_to_address('p2wsh', to_local_witness_script)
    to_remote_address = None
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
        return {}
    #chan.logger.debug(f'(lnsweep) found our ctx: {to_local_address} {to_remote_address}')
    # other outputs are htlcs
    # if they are spent, we need to generate the script
    # so, second-stage htlc sweep should not be returned here
    txs = {}  # type: Dict[str, SweepInfo]

    # local anchor
    if chan.has_anchors():
        if txin := sweep_ctx_anchor(ctx=ctx, multisig_key=our_conf.multisig_key):
            txs[txin.prevout.to_str()] = SweepInfo(
                name='local_anchor',
                csv_delay=0,
                cltv_abs=None,
                txin=txin,
                txout=None,
            )

    # to_local
    output_idxs = ctx.get_output_idxs_from_address(to_local_address)
    if actual_htlc_tx is None and output_idxs:
        output_idx = output_idxs.pop()
        txin = sweep_ctx_to_local(
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
            cltv_abs=None,
            txin=txin,
            txout=None,
        )
    we_breached = ctn < chan.get_oldest_unrevoked_ctn(LOCAL)
    if we_breached:
        chan.logger.info(f"(lnsweep) we breached. txid: {ctx.txid()}")
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

        if actual_htlc_tx is None:
            name = 'first-stage-htlc-anchors' if chan.has_anchors() else 'first-stage-htlc'
            prevout = ctx.txid() + f':{ctx_output_idx}'
            txs[prevout] = SweepInfo(
                name=name,
                csv_delay=0,
                cltv_abs=htlc_tx.locktime,
                txin=htlc_tx.inputs()[0],
                txout=htlc_tx.outputs()[0])
        else:
            # second-stage
            address = bitcoin.script_to_p2wsh(htlctx_witness_script)
            output_idxs = actual_htlc_tx.get_output_idxs_from_address(address)
            for output_idx in output_idxs:
                sweep_txin = sweep_htlctx_output(
                    to_self_delay=to_self_delay,
                    htlc_tx=actual_htlc_tx,
                    output_idx=output_idx,
                    htlctx_witness_script=htlctx_witness_script,
                    privkey=our_localdelayed_privkey.get_secret_bytes(),
                    is_revocation=False,
                    config=chan.lnworker.config)
                txs[actual_htlc_tx.txid() + f':{output_idx}'] = SweepInfo(
                    name=f'second-stage-htlc:{output_idx}',
                    csv_delay=to_self_delay,
                    cltv_abs=0,
                    txin=sweep_txin,
                    txout=None,
                )

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
            if not chan.lnworker.is_accepted_mpp(htlc.payment_hash):
                # do not redeem this, it might publish the preimage of an incomplete MPP
                continue
            preimage = chan.lnworker.get_preimage(htlc.payment_hash)
            if not preimage:
                # we might not have the preimage if this is a hold invoice
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
        #chan.logger.debug(f'(lnsweep) tx for revoked: {list(txs.keys())}')
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


def sweep_their_ctx_to_remote_backup(
        *, chan: 'ChannelBackup',
        ctx: Transaction,
        funding_tx: Transaction,
) -> Optional[Dict[str, SweepInfo]]:
    txs = {}  # type: Dict[str, SweepInfo]
    """If we only have a backup, and the remote force-closed with their ctx,
    and anchors are enabled, we need to sweep to_remote."""

    if ctx_has_anchors(ctx):
        # for anchors we need to sweep to_remote
        funding_pubkeys = extract_funding_pubkeys_from_ctx(ctx.inputs()[0])
        _logger.debug(f'checking their ctx for funding pubkeys: {[pk.hex() for pk in funding_pubkeys]}')
        # check which of the pubkey was ours
        for fp_idx, pubkey in enumerate(funding_pubkeys):
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

    # remote anchor
    # derive funding_privkey ("multisig_key")
    # note: for imported backups, we already have this as 'local_config.multisig_key'
    #       but for on-chain backups, we need to derive it.
    #       For symmetry, we derive it now regardless of type
    our_funding_pubkey = funding_pubkeys[fp_idx]
    their_funding_pubkey = funding_pubkeys[1 - fp_idx]
    remote_node_id = chan.node_id  # for onchain backups, this is only the prefix
    if chan.is_initiator():
        funding_kp_cand = derive_multisig_funding_key_if_we_opened(
            funding_root_secret=chan.lnworker.funding_root_keypair.privkey,
            remote_node_id_or_prefix=remote_node_id,
            nlocktime=funding_tx.locktime,
        )
    else:
        funding_kp_cand = derive_multisig_funding_key_if_they_opened(
            funding_root_secret=chan.lnworker.funding_root_keypair.privkey,
            remote_node_id_or_prefix=remote_node_id,
            remote_funding_pubkey=their_funding_pubkey,
        )
    assert funding_kp_cand.pubkey == our_funding_pubkey, f"funding pubkey mismatch1. {chan.is_initiator()=}"
    our_ms_funding_keypair = funding_kp_cand
    # sanity check funding_privkey, if we had it already (if backup is imported):
    if local_config := chan.config.get(LOCAL):
        assert our_ms_funding_keypair == local_config.multisig_key, f"funding pubkey mismatch2. {chan.is_initiator()=}"

    if our_ms_funding_keypair:
        if txin := sweep_ctx_anchor(ctx=ctx, multisig_key=our_ms_funding_keypair):
            txs[txin.prevout.to_str()] = SweepInfo(
                name='remote_anchor',
                csv_delay=0,
                cltv_abs=None,
                txin=txin,
                txout=None,
            )

    # to_remote
    csv_delay = 1
    our_payment_privkey = ecc.ECPrivkey(our_payment_pubkey.privkey)
    output_idxs = ctx.get_output_idxs_from_address(to_remote_address)
    if output_idxs:
        output_idx = output_idxs.pop()
        prevout = ctx.txid() + ':%d' % output_idx
        txin = sweep_their_ctx_to_remote(
            ctx=ctx,
            output_idx=output_idx,
            our_payment_privkey=our_payment_privkey,
            config=chan.lnworker.config,
            has_anchors=True
        )
        txs[prevout] = SweepInfo(
            name='their_ctx_to_remote_backup',
            csv_delay=csv_delay,
            cltv_abs=None,
            txin=txin,
            txout=None,
        )
    return txs




def sweep_their_ctx(
        *, chan: 'Channel',
        ctx: Transaction) -> Optional[Dict[str, SweepInfo]]:
    """Handle the case when the remote force-closes with their ctx.
    Sweep outputs that do not have a CSV delay ('to_remote' and first-stage HTLCs).
    Outputs with CSV delay ('to_local' and second-stage HTLCs) are redeemed by LNWatcher.

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
    witness_script = make_commitment_output_to_local_witness_script(
        our_revocation_pubkey, our_conf.to_self_delay, their_delayed_pubkey)
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    to_remote_address = None
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
    chan.logger.debug(f'(lnsweep) found their ctx: {to_local_address} {to_remote_address}')

    # remote anchor
    if chan.has_anchors():
        if txin := sweep_ctx_anchor(ctx=ctx, multisig_key=our_conf.multisig_key):
            txs[txin.prevout.to_str()] = SweepInfo(
                name='remote_anchor',
                csv_delay=0,
                cltv_abs=None,
                txin=txin,
                txout=None,
            )

    # to_local is handled by lnwatcher
    if is_revocation:
        our_revocation_privkey = derive_blinded_privkey(our_conf.revocation_basepoint.privkey, per_commitment_secret)
        txin = sweep_their_ctx_justice(chan, ctx, per_commitment_secret)
        if txin:
            txs[txin.prevout.to_str()] = SweepInfo(
                name='to_local_for_revoked_ctx',
                csv_delay=0,
                cltv_abs=None,
                txin=txin,
                txout=None,
            )

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
            txin = sweep_their_ctx_to_remote(
                ctx=ctx,
                output_idx=output_idx,
                our_payment_privkey=our_payment_privkey,
                config=chan.lnworker.config,
                has_anchors=chan.has_anchors()
            )
            txs[prevout] = SweepInfo(
                name='their_ctx_to_remote',
                csv_delay=csv_delay,
                cltv_abs=None,
                txin=txin,
                txout=None,
            )

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
            cltv_abs=htlc.cltv_abs,
            has_anchors=chan.has_anchors())

        cltv_abs = htlc.cltv_abs if is_received_htlc and not is_revocation else 0
        csv_delay = 1 if chan.has_anchors() else 0
        prevout = ctx.txid() + ':%d'%ctx_output_idx
        txin = sweep_their_ctx_htlc(
            ctx=ctx,
            witness_script=htlc_output_witness_script,
            preimage=preimage,
            output_idx=ctx_output_idx,
            privkey=our_revocation_privkey if is_revocation else our_htlc_privkey.get_secret_bytes(),
            is_revocation=is_revocation,
            cltv_abs=cltv_abs,
            config=chan.lnworker.config,
            has_anchors=chan.has_anchors(),
        )
        txs[prevout] = SweepInfo(
            name=f'their_ctx_htlc_{ctx_output_idx}{"_for_revoked_ctx" if is_revocation else ""}',
            csv_delay=csv_delay,
            cltv_abs=cltv_abs,
            txin=txin,
            txout=None,
        )
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
            if not chan.lnworker.is_accepted_mpp(htlc.payment_hash):
                # do not redeem this, it might publish the preimage of an incomplete MPP
                continue
            preimage = chan.lnworker.get_preimage(htlc.payment_hash)
            if not preimage:
                # we might not have the preimage if this is a hold invoice
                continue
        else:
            preimage = None
        tx_htlc(
            htlc=htlc,
            is_received_htlc=is_received_htlc,
            ctx_output_idx=ctx_output_idx,
            preimage=preimage)
    return txs


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
    witness_script_out, maybe_zero_fee_htlc_tx = make_htlc_tx_with_open_channel(
        chan=chan,
        pcp=our_pcp,
        subject=LOCAL,
        ctn=ctn,
        htlc_direction=htlc_direction,
        commit=ctx,
        htlc=htlc,
        ctx_output_idx=ctx_output_idx,
        name=f'our_ctx_{ctx_output_idx}_htlc_tx_{htlc.payment_hash.hex()}')

    # sign HTLC output
    remote_htlc_sig = chan.get_remote_htlc_sig_for_htlc(htlc_relative_idx=htlc_relative_idx)
    txin = maybe_zero_fee_htlc_tx.inputs()[HTLCTX_INPUT_OUTPUT_INDEX]
    witness_script_in = txin.witness_script
    assert witness_script_in
    txin.privkey = local_htlc_privkey
    txin.make_witness = lambda local_htlc_sig: make_htlc_tx_witness(remote_htlc_sig, local_htlc_sig, preimage, witness_script_in)
    return witness_script_out, maybe_zero_fee_htlc_tx


def sweep_their_ctx_htlc(
        ctx: Transaction,
        witness_script: bytes,
        preimage: Optional[bytes], output_idx: int,
        privkey: bytes, is_revocation: bool,
        cltv_abs: int,
        config: SimpleConfig,
        has_anchors: bool,
) -> Optional[PartialTxInput]:
    """Deals with normal (non-CSV timelocked) HTLC output sweeps."""
    assert type(cltv_abs) is int
    assert witness_script is not None
    preimage = preimage or b''  # preimage is required iff (not is_revocation and htlc is offered)
    val = ctx.outputs()[output_idx].value
    prevout = TxOutpoint(txid=bfh(ctx.txid()), out_idx=output_idx)
    txin = PartialTxInput(prevout=prevout)
    txin._trusted_value_sats = val
    txin.witness_script = witness_script
    txin.script_sig = b''
    txin.nsequence = 1 if has_anchors else 0xffffffff - 2
    tx_size_bytes = 200  # TODO (depends on offered/received and is_revocation)
    fee = config.estimate_fee(tx_size_bytes, allow_fallback_to_static_rates=True)
    outvalue = val - fee
    if outvalue <= dust_threshold():
        return None
    txin.privkey = privkey
    if not is_revocation:
        txin.make_witness = lambda sig: construct_witness([sig, preimage, witness_script])
    else:
        revocation_pubkey = privkey_to_pubkey(privkey)
        txin.make_witness = lambda sig: construct_witness([sig, revocation_pubkey, witness_script])
    return txin



def sweep_their_ctx_to_remote(
        ctx: Transaction, output_idx: int,
        our_payment_privkey: ecc.ECPrivkey,
        config: SimpleConfig,
        has_anchors: bool,
) -> Optional[PartialTxInput]:
    assert has_anchors is True
    our_payment_pubkey = our_payment_privkey.get_public_key_bytes(compressed=True)
    val = ctx.outputs()[output_idx].value
    prevout = TxOutpoint(txid=bfh(ctx.txid()), out_idx=output_idx)
    txin = PartialTxInput(prevout=prevout)
    txin._trusted_value_sats = val
    desc = descriptor.get_singlesig_descriptor_from_legacy_leaf(pubkey=our_payment_pubkey.hex(), script_type='p2wpkh')
    witness_script = make_commitment_output_to_remote_witness_script(our_payment_pubkey)
    txin.script_descriptor = desc
    txin.num_sig = 1
    txin.script_sig = b''
    txin.witness_script = witness_script
    txin.nsequence = 1
    tx_size_bytes = 196  # approx size of p2wsh->p2wpkh
    fee = config.estimate_fee(tx_size_bytes, allow_fallback_to_static_rates=True)
    outvalue = val - fee
    if outvalue <= dust_threshold():
        return None
    txin.privkey = our_payment_privkey.get_secret_bytes()
    txin.make_witness = lambda sig: construct_witness([sig, witness_script])
    return txin


def sweep_ctx_anchor(*, ctx: Transaction, multisig_key: Keypair) -> Optional[PartialTxInput]:
    from .lnutil import make_commitment_output_to_anchor_address, make_commitment_output_to_anchor_witness_script
    local_funding_pubkey = multisig_key.pubkey
    local_anchor_address = make_commitment_output_to_anchor_address(local_funding_pubkey)
    witness_script = make_commitment_output_to_anchor_witness_script(local_funding_pubkey)
    output_idxs = ctx.get_output_idxs_from_address(local_anchor_address)
    if not output_idxs:
        return
    output_idx = output_idxs.pop()
    val = ctx.outputs()[output_idx].value
    prevout = TxOutpoint(txid=bfh(ctx.txid()), out_idx=output_idx)
    txin = PartialTxInput(prevout=prevout)
    txin._trusted_value_sats = val
    txin.script_sig = b''
    txin.witness_script = witness_script
    txin.nsequence = 0xffffffff - 2
    txin.privkey = multisig_key.privkey
    txin.make_witness = lambda sig: construct_witness([sig, witness_script])
    return txin


def sweep_ctx_to_local(
        *, ctx: Transaction, output_idx: int, witness_script: bytes,
        privkey: bytes, is_revocation: bool, config: SimpleConfig,
        to_self_delay: int = None) -> Optional[PartialTxInput]:
    """Create a txin that sweeps the 'to_local' output of a commitment
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
    txin.nsequence = 0xffffffff - 2
    if not is_revocation:
        assert isinstance(to_self_delay, int)
        txin.nsequence = to_self_delay
    tx_size_bytes = 121  # approx size of to_local -> p2wpkh
    fee = config.estimate_fee(tx_size_bytes, allow_fallback_to_static_rates=True)
    outvalue = val - fee
    if outvalue <= dust_threshold():
        return None
    txin.privkey = privkey
    assert txin.witness_script
    txin.make_witness = lambda sig: construct_witness([sig, int(is_revocation), witness_script])
    return txin


def sweep_htlctx_output(
        *, htlc_tx: Transaction,
        output_idx: int,
        htlctx_witness_script: bytes,
        privkey: bytes,
        is_revocation: bool,
        to_self_delay: int = None,
        config: SimpleConfig) -> Optional[PartialTxInput]:
    """Create a txn that sweeps the output of a first stage htlc tx
    (i.e. sweeps from an HTLC-Timeout or an HTLC-Success tx).
    """
    # note: this is the same as sweeping the to_local output of the ctx,
    #       as these are the same script (address-reuse).
    return sweep_ctx_to_local(
        ctx=htlc_tx,
        output_idx=output_idx,
        witness_script=htlctx_witness_script,
        privkey=privkey,
        is_revocation=is_revocation,
        to_self_delay=to_self_delay,
        config=config,
    )
