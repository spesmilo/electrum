# Copyright (C) 2018 The Electrum developers
# Copyright (C) 2015-2018 The Lightning Network Developers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# API (method signatures and docstrings) partially copied from lnd
# 42de4400bff5105352d0552155f73589166d162b

import os
from collections import namedtuple, defaultdict
import binascii
import json
from enum import Enum, auto
from typing import Optional, Dict, List, Tuple, NamedTuple, Set, Callable, Iterable, Sequence, TYPE_CHECKING
import time

from . import ecc
from .util import bfh, bh2u
from .bitcoin import TYPE_SCRIPT, TYPE_ADDRESS
from .bitcoin import redeem_script_to_address
from .crypto import sha256, sha256d
from .transaction import Transaction
from .logging import Logger

from .lnonion import decode_onion_error
from .lnutil import (Outpoint, LocalConfig, RemoteConfig, Keypair, OnlyPubkeyKeypair, ChannelConstraints,
                    get_per_commitment_secret_from_seed, secret_to_pubkey, derive_privkey, make_closing_tx,
                    sign_and_get_sig_string, RevocationStore, derive_blinded_pubkey, Direction, derive_pubkey,
                    make_htlc_tx_with_open_channel, make_commitment, make_received_htlc, make_offered_htlc,
                    HTLC_TIMEOUT_WEIGHT, HTLC_SUCCESS_WEIGHT, extract_ctn_from_tx_and_chan, UpdateAddHtlc,
                    funding_output_script, SENT, RECEIVED, LOCAL, REMOTE, HTLCOwner, make_commitment_outputs,
                    ScriptHtlc, PaymentFailure, calc_onchain_fees, RemoteMisbehaving, make_htlc_output_witness_script,
                    ShortChannelID, map_htlcs_to_ctx_output_idxs)
from .lnutil import FeeUpdate
from .lnsweep import create_sweeptxs_for_our_ctx, create_sweeptxs_for_their_ctx
from .lnsweep import create_sweeptx_for_their_revoked_htlc, SweepInfo
from .lnhtlc import HTLCManager

if TYPE_CHECKING:
    from .lnworker import LNWallet


class ChannelJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return binascii.hexlify(o).decode("ascii")
        if isinstance(o, RevocationStore):
            return o.serialize()
        if isinstance(o, set):
            return list(o)
        return super().default(o)

RevokeAndAck = namedtuple("RevokeAndAck", ["per_commitment_secret", "next_per_commitment_point"])


class RemoteCtnTooFarInFuture(Exception): pass


def decodeAll(d, local):
    for k, v in d.items():
        if k == 'revocation_store':
            yield (k, RevocationStore.from_json_obj(v))
        elif k.endswith("_basepoint") or k.endswith("_key"):
            if local:
                yield (k, Keypair(**dict(decodeAll(v, local))))
            else:
                yield (k, OnlyPubkeyKeypair(**dict(decodeAll(v, local))))
        elif k in ["node_id", "channel_id", "short_channel_id", "pubkey", "privkey", "current_per_commitment_point", "next_per_commitment_point", "per_commitment_secret_seed", "current_commitment_signature", "current_htlc_signatures"] and v is not None:
            yield (k, binascii.unhexlify(v))
        else:
            yield (k, v)

def htlcsum(htlcs):
    return sum([x.amount_msat for x in htlcs])

# following two functions are used because json
# doesn't store int keys and byte string values
def str_bytes_dict_from_save(x) -> Dict[int, bytes]:
    return {int(k): bfh(v) for k,v in x.items()}

def str_bytes_dict_to_save(x) -> Dict[str, str]:
    return {str(k): bh2u(v) for k, v in x.items()}


class Channel(Logger):
    # note: try to avoid naming ctns/ctxs/etc as "current" and "pending".
    #       they are ambiguous. Use "oldest_unrevoked" or "latest" or "next".
    #       TODO enforce this ^

    def diagnostic_name(self):
        if self.name:
            return str(self.name)
        try:
            return f"lnchannel_{bh2u(self.channel_id[-4:])}"
        except:
            return super().diagnostic_name()

    def __init__(self, state, *, sweep_address=None, name=None, lnworker=None, initial_feerate=None):
        self.name = name
        Logger.__init__(self)
        self.lnworker = lnworker  # type: Optional[LNWallet]
        self.sweep_address = sweep_address
        assert 'local_state' not in state
        self.config = {}
        self.config[LOCAL] = state["local_config"]
        if type(self.config[LOCAL]) is not LocalConfig:
            conf = dict(decodeAll(self.config[LOCAL], True))
            self.config[LOCAL] = LocalConfig(**conf)
        assert type(self.config[LOCAL].htlc_basepoint.privkey) is bytes

        self.config[REMOTE] = state["remote_config"]
        if type(self.config[REMOTE]) is not RemoteConfig:
            conf = dict(decodeAll(self.config[REMOTE], False))
            self.config[REMOTE] = RemoteConfig(**conf)
        assert type(self.config[REMOTE].htlc_basepoint.pubkey) is bytes

        self.channel_id = bfh(state["channel_id"]) if type(state["channel_id"]) not in (bytes, type(None)) else state["channel_id"]
        self.constraints = ChannelConstraints(**state["constraints"]) if type(state["constraints"]) is not ChannelConstraints else state["constraints"]
        self.funding_outpoint = Outpoint(**dict(decodeAll(state["funding_outpoint"], False))) if type(state["funding_outpoint"]) is not Outpoint else state["funding_outpoint"]
        self.node_id = bfh(state["node_id"]) if type(state["node_id"]) not in (bytes, type(None)) else state["node_id"]  # type: bytes
        self.short_channel_id = ShortChannelID.normalize(state["short_channel_id"])
        self.short_channel_id_predicted = self.short_channel_id
        self.onion_keys = str_bytes_dict_from_save(state.get('onion_keys', {}))
        self.force_closed = state.get('force_closed')
        self.data_loss_protect_remote_pcp = str_bytes_dict_from_save(state.get('data_loss_protect_remote_pcp', {}))
        self.remote_update = bfh(state.get('remote_update')) if state.get('remote_update') else None

        log = state.get('log')
        self.hm = HTLCManager(log=log,
                              initial_feerate=initial_feerate)


        self._is_funding_txo_spent = None  # "don't know"
        self._state = None
        self.set_state('DISCONNECTED')
        self.sweep_info = {}  # type: Dict[str, Dict[str, SweepInfo]]
        self._outgoing_channel_update = None  # type: Optional[bytes]

    def get_feerate(self, subject, ctn):
        return self.hm.get_feerate(subject, ctn)

    def get_oldest_unrevoked_feerate(self, subject):
        return self.hm.get_feerate_in_oldest_unrevoked_ctx(subject)

    def get_latest_feerate(self, subject):
        return self.hm.get_feerate_in_latest_ctx(subject)

    def get_next_feerate(self, subject):
        return self.hm.get_feerate_in_next_ctx(subject)

    def get_payments(self):
        out = {}
        for subject in LOCAL, REMOTE:
            log = self.hm.log[subject]
            for htlc_id, htlc in log.get('adds', {}).items():
                if htlc_id in log.get('fails',{}):
                    status = 'failed'
                elif htlc_id in log.get('settles',{}):
                    status = 'settled'
                else:
                    status = 'inflight'
                direction = SENT if subject is LOCAL else RECEIVED
                rhash = bh2u(htlc.payment_hash)
                out[rhash] = (self.channel_id, htlc, direction, status)
        return out

    def open_with_first_pcp(self, remote_pcp, remote_sig):
        self.config[REMOTE] = self.config[REMOTE]._replace(current_per_commitment_point=remote_pcp,
                                                           next_per_commitment_point=None)
        self.config[LOCAL] = self.config[LOCAL]._replace(current_commitment_signature=remote_sig)
        self.hm.channel_open_finished()
        self.set_state('OPENING')

    def set_force_closed(self):
        self.force_closed = True

    def set_state(self, state: str):
        self._state = state

    def get_state(self):
        return self._state

    def is_closed(self):
        return self.force_closed or self.get_state() in ['CLOSED', 'CLOSING']

    def _check_can_pay(self, amount_msat: int) -> None:
        # TODO check if this method uses correct ctns (should use "latest" + 1)
        if self.is_closed():
            raise PaymentFailure('Channel closed')
        if self.get_state() != 'OPEN':
            raise PaymentFailure('Channel not open')
        if self.available_to_spend(LOCAL) < amount_msat:
            raise PaymentFailure(f'Not enough local balance. Have: {self.available_to_spend(LOCAL)}, Need: {amount_msat}')
        if len(self.hm.htlcs(LOCAL)) + 1 > self.config[REMOTE].max_accepted_htlcs:
            raise PaymentFailure('Too many HTLCs already in channel')
        current_htlc_sum = (htlcsum(self.hm.htlcs_by_direction(LOCAL, SENT).values())
                            + htlcsum(self.hm.htlcs_by_direction(LOCAL, RECEIVED).values()))
        if current_htlc_sum + amount_msat > self.config[REMOTE].max_htlc_value_in_flight_msat:
            raise PaymentFailure(f'HTLC value sum (sum of pending htlcs: {current_htlc_sum/1000} sat plus new htlc: {amount_msat/1000} sat) would exceed max allowed: {self.config[REMOTE].max_htlc_value_in_flight_msat/1000} sat')
        if amount_msat < self.config[REMOTE].htlc_minimum_msat:
            raise PaymentFailure(f'HTLC value too small: {amount_msat} msat')

    def can_pay(self, amount_msat):
        try:
            self._check_can_pay(amount_msat)
        except PaymentFailure:
            return False
        return True

    def set_funding_txo_spentness(self, is_spent: bool):
        assert isinstance(is_spent, bool)
        self._is_funding_txo_spent = is_spent

    def should_try_to_reestablish_peer(self) -> bool:
        return self._is_funding_txo_spent is False and self._state == 'DISCONNECTED'

    def get_funding_address(self):
        script = funding_output_script(self.config[LOCAL], self.config[REMOTE])
        return redeem_script_to_address('p2wsh', script)

    def add_htlc(self, htlc: UpdateAddHtlc) -> UpdateAddHtlc:
        """
        AddHTLC adds an HTLC to the state machine's local update log. This method
        should be called when preparing to send an outgoing HTLC.

        This docstring is from LND.
        """
        if isinstance(htlc, dict):  # legacy conversion  # FIXME remove
            htlc = UpdateAddHtlc(**htlc)
        assert isinstance(htlc, UpdateAddHtlc)
        self._check_can_pay(htlc.amount_msat)
        if htlc.htlc_id is None:
            htlc = htlc._replace(htlc_id=self.hm.get_next_htlc_id(LOCAL))
        self.hm.send_htlc(htlc)
        self.logger.info("add_htlc")
        return htlc

    def receive_htlc(self, htlc: UpdateAddHtlc) -> UpdateAddHtlc:
        """
        ReceiveHTLC adds an HTLC to the state machine's remote update log. This
        method should be called in response to receiving a new HTLC from the remote
        party.

        This docstring is from LND.
        """
        if isinstance(htlc, dict):  # legacy conversion  # FIXME remove
            htlc = UpdateAddHtlc(**htlc)
        assert isinstance(htlc, UpdateAddHtlc)
        if htlc.htlc_id is None:  # used in unit tests
            htlc = htlc._replace(htlc_id=self.hm.get_next_htlc_id(REMOTE))
        if 0 <= self.available_to_spend(REMOTE) < htlc.amount_msat:
            raise RemoteMisbehaving('Remote dipped below channel reserve.' +\
                    f' Available at remote: {self.available_to_spend(REMOTE)},' +\
                    f' HTLC amount: {htlc.amount_msat}')
        self.hm.recv_htlc(htlc)
        self.logger.info("receive_htlc")
        return htlc

    def sign_next_commitment(self):
        """
        SignNextCommitment signs a new commitment which includes any previous
        unsettled HTLCs, any new HTLCs, and any modifications to prior HTLCs
        committed in previous commitment updates.
        The first return parameter is the signature for the commitment transaction
        itself, while the second parameter is are all HTLC signatures concatenated.
        any). The HTLC signatures are sorted according to the BIP 69 order of the
        HTLC's on the commitment transaction.

        This docstring was adapted from LND.
        """
        next_remote_ctn = self.get_next_ctn(REMOTE)
        self.logger.info(f"sign_next_commitment {next_remote_ctn}")

        pending_remote_commitment = self.get_next_commitment(REMOTE)
        sig_64 = sign_and_get_sig_string(pending_remote_commitment, self.config[LOCAL], self.config[REMOTE])

        their_remote_htlc_privkey_number = derive_privkey(
            int.from_bytes(self.config[LOCAL].htlc_basepoint.privkey, 'big'),
            self.config[REMOTE].next_per_commitment_point)
        their_remote_htlc_privkey = their_remote_htlc_privkey_number.to_bytes(32, 'big')

        htlcsigs = []
        htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(chan=self,
                                                                  ctx=pending_remote_commitment,
                                                                  pcp=self.config[REMOTE].next_per_commitment_point,
                                                                  subject=REMOTE,
                                                                  ctn=next_remote_ctn)
        for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
            _script, htlc_tx = make_htlc_tx_with_open_channel(chan=self,
                                                              pcp=self.config[REMOTE].next_per_commitment_point,
                                                              subject=REMOTE,
                                                              htlc_direction=direction,
                                                              commit=pending_remote_commitment,
                                                              ctx_output_idx=ctx_output_idx,
                                                              htlc=htlc)
            sig = bfh(htlc_tx.sign_txin(0, their_remote_htlc_privkey))
            htlc_sig = ecc.sig_string_from_der_sig(sig[:-1])
            htlcsigs.append((ctx_output_idx, htlc_sig))
        htlcsigs.sort()
        htlcsigs = [x[1] for x in htlcsigs]

        self.hm.send_ctx()

        return sig_64, htlcsigs

    def receive_new_commitment(self, sig, htlc_sigs):
        """
        ReceiveNewCommitment process a signature for a new commitment state sent by
        the remote party. This method should be called in response to the
        remote party initiating a new change, or when the remote party sends a
        signature fully accepting a new state we've initiated. If we are able to
        successfully validate the signature, then the generated commitment is added
        to our local commitment chain. Once we send a revocation for our prior
        state, then this newly added commitment becomes our current accepted channel
        state.

        This docstring is from LND.
        """
        # TODO in many failure cases below, we should "fail" the channel (force-close)
        next_local_ctn = self.get_next_ctn(LOCAL)
        self.logger.info(f"receive_new_commitment. ctn={next_local_ctn}, len(htlc_sigs)={len(htlc_sigs)}")

        assert len(htlc_sigs) == 0 or type(htlc_sigs[0]) is bytes

        pending_local_commitment = self.get_next_commitment(LOCAL)
        preimage_hex = pending_local_commitment.serialize_preimage(0)
        pre_hash = sha256d(bfh(preimage_hex))
        if not ecc.verify_signature(self.config[REMOTE].multisig_key.pubkey, sig, pre_hash):
            raise Exception(f'failed verifying signature of our updated commitment transaction: {bh2u(sig)} preimage is {preimage_hex}')

        htlc_sigs_string = b''.join(htlc_sigs)

        _secret, pcp = self.get_secret_and_point(subject=LOCAL, ctn=next_local_ctn)

        htlc_to_ctx_output_idx_map = map_htlcs_to_ctx_output_idxs(chan=self,
                                                                  ctx=pending_local_commitment,
                                                                  pcp=pcp,
                                                                  subject=LOCAL,
                                                                  ctn=next_local_ctn)
        if len(htlc_to_ctx_output_idx_map) != len(htlc_sigs):
            raise Exception(f'htlc sigs failure. recv {len(htlc_sigs)} sigs, expected {len(htlc_to_ctx_output_idx_map)}')
        for (direction, htlc), (ctx_output_idx, htlc_relative_idx) in htlc_to_ctx_output_idx_map.items():
            htlc_sig = htlc_sigs[htlc_relative_idx]
            self.verify_htlc(htlc=htlc,
                             htlc_sig=htlc_sig,
                             htlc_direction=direction,
                             pcp=pcp,
                             ctx=pending_local_commitment,
                             ctx_output_idx=ctx_output_idx)

        self.hm.recv_ctx()
        self.config[LOCAL]=self.config[LOCAL]._replace(
            current_commitment_signature=sig,
            current_htlc_signatures=htlc_sigs_string)

    def verify_htlc(self, *, htlc: UpdateAddHtlc, htlc_sig: bytes, htlc_direction: Direction,
                    pcp: bytes, ctx: Transaction, ctx_output_idx: int) -> None:
        _script, htlc_tx = make_htlc_tx_with_open_channel(chan=self,
                                                          pcp=pcp,
                                                          subject=LOCAL,
                                                          htlc_direction=htlc_direction,
                                                          commit=ctx,
                                                          ctx_output_idx=ctx_output_idx,
                                                          htlc=htlc)
        pre_hash = sha256d(bfh(htlc_tx.serialize_preimage(0)))
        remote_htlc_pubkey = derive_pubkey(self.config[REMOTE].htlc_basepoint.pubkey, pcp)
        if not ecc.verify_signature(remote_htlc_pubkey, htlc_sig, pre_hash):
            raise Exception(f'failed verifying HTLC signatures: {htlc} {htlc_direction}')

    def get_remote_htlc_sig_for_htlc(self, *, htlc_relative_idx: int) -> bytes:
        data = self.config[LOCAL].current_htlc_signatures
        htlc_sigs = [data[i:i + 64] for i in range(0, len(data), 64)]
        htlc_sig = htlc_sigs[htlc_relative_idx]
        remote_htlc_sig = ecc.der_sig_from_sig_string(htlc_sig) + b'\x01'
        return remote_htlc_sig

    def revoke_current_commitment(self):
        self.logger.info("revoke_current_commitment")
        new_ctn = self.get_latest_ctn(LOCAL)
        new_ctx = self.get_latest_commitment(LOCAL)
        if not self.signature_fits(new_ctx):
            # this should never fail; as receive_new_commitment already did this test
            raise Exception("refusing to revoke as remote sig does not fit")
        self.hm.send_rev()
        received = self.hm.received_in_ctn(new_ctn)
        sent = self.hm.sent_in_ctn(new_ctn)
        if self.lnworker:
            for htlc in received:
                self.lnworker.payment_completed(self, RECEIVED, htlc)
            for htlc in sent:
                self.lnworker.payment_completed(self, SENT, htlc)
        received_this_batch = htlcsum(received)
        sent_this_batch = htlcsum(sent)
        last_secret, last_point = self.get_secret_and_point(LOCAL, new_ctn - 1)
        next_secret, next_point = self.get_secret_and_point(LOCAL, new_ctn + 1)
        return RevokeAndAck(last_secret, next_point), (received_this_batch, sent_this_batch)

    def receive_revocation(self, revocation: RevokeAndAck):
        self.logger.info("receive_revocation")

        cur_point = self.config[REMOTE].current_per_commitment_point
        derived_point = ecc.ECPrivkey(revocation.per_commitment_secret).get_public_key_bytes(compressed=True)
        if cur_point != derived_point:
            raise Exception('revoked secret not for current point')

        self.config[REMOTE].revocation_store.add_next_entry(revocation.per_commitment_secret)
        ##### start applying fee/htlc changes
        self.hm.recv_rev()
        self.config[REMOTE]=self.config[REMOTE]._replace(
            current_per_commitment_point=self.config[REMOTE].next_per_commitment_point,
            next_per_commitment_point=revocation.next_per_commitment_point,
        )

    def balance(self, whose, *, ctx_owner=HTLCOwner.LOCAL, ctn=None):
        """
        This balance in mSAT is not including reserve and fees.
        So a node cannot actually use its whole balance.
        But this number is simple, since it is derived simply
        from the initial balance, and the value of settled HTLCs.
        Note that it does not decrease once an HTLC is added,
        failed or fulfilled, since the balance change is only
        committed to later when the respective commitment
        transaction has been revoked.
        """
        assert type(whose) is HTLCOwner
        initial = self.config[whose].initial_msat

        for direction, htlc in self.hm.all_settled_htlcs_ever(ctx_owner, ctn):
            # note: could "simplify" to (whose * ctx_owner == direction * SENT)
            if whose == ctx_owner:
                if direction == SENT:
                    initial -= htlc.amount_msat
                else:
                    initial += htlc.amount_msat
            else:
                if direction == SENT:
                    initial += htlc.amount_msat
                else:
                    initial -= htlc.amount_msat

        return initial

    def balance_minus_outgoing_htlcs(self, whose: HTLCOwner, *, ctx_owner: HTLCOwner = HTLCOwner.LOCAL):
        """
        This balance in mSAT, which includes the value of
        pending outgoing HTLCs, is used in the UI.
        """
        assert type(whose) is HTLCOwner
        ctn = self.get_next_ctn(ctx_owner)
        return self.balance(whose, ctx_owner=ctx_owner, ctn=ctn)\
                - htlcsum(self.hm.htlcs_by_direction(ctx_owner, SENT, ctn).values())

    def available_to_spend(self, subject):
        """
        This balance in mSAT, while technically correct, can
        not be used in the UI cause it fluctuates (commit fee)
        """
        # FIXME whose balance? whose ctx?
        # FIXME confusing/mixing ctns (should probably use latest_ctn + 1; not oldest_unrevoked + 1)
        assert type(subject) is HTLCOwner
        return self.balance_minus_outgoing_htlcs(subject, ctx_owner=subject)\
                - self.config[-subject].reserve_sat * 1000\
                - calc_onchain_fees(
                      # TODO should we include a potential new htlc, when we are called from receive_htlc?
                      len(self.included_htlcs(subject, SENT) + self.included_htlcs(subject, RECEIVED)),
                      self.get_latest_feerate(subject),
                      self.constraints.is_initiator,
                  )[subject]

    def included_htlcs(self, subject, direction, ctn=None):
        """
        return filter of non-dust htlcs for subjects commitment transaction, initiated by given party
        """
        assert type(subject) is HTLCOwner
        assert type(direction) is Direction
        if ctn is None:
            ctn = self.get_oldest_unrevoked_ctn(subject)
        feerate = self.get_feerate(subject, ctn)
        conf = self.config[subject]
        if (subject, direction) in [(REMOTE, RECEIVED), (LOCAL, SENT)]:
            weight = HTLC_SUCCESS_WEIGHT
        else:
            weight = HTLC_TIMEOUT_WEIGHT
        htlcs = self.hm.htlcs_by_direction(subject, direction, ctn=ctn).values()
        htlc_value_after_fees = lambda htlc: htlc.amount_msat // 1000 - (weight * feerate // 1000)
        return list(filter(lambda htlc: htlc_value_after_fees(htlc) >= conf.dust_limit_sat, htlcs))

    def get_secret_and_point(self, subject: HTLCOwner, ctn: int) -> Tuple[Optional[bytes], bytes]:
        assert type(subject) is HTLCOwner
        assert ctn >= 0, ctn
        offset = ctn - self.get_oldest_unrevoked_ctn(subject)
        if subject == REMOTE:
            if offset > 1:
                raise RemoteCtnTooFarInFuture(f"offset: {offset}")
            conf = self.config[REMOTE]
            if offset == 1:
                secret = None
                point = conf.next_per_commitment_point
            elif offset == 0:
                secret = None
                point = conf.current_per_commitment_point
            else:
                secret = conf.revocation_store.retrieve_secret(RevocationStore.START_INDEX - ctn)
                point = secret_to_pubkey(int.from_bytes(secret, 'big'))
        else:
            secret = get_per_commitment_secret_from_seed(self.config[LOCAL].per_commitment_secret_seed, RevocationStore.START_INDEX - ctn)
            point = secret_to_pubkey(int.from_bytes(secret, 'big'))
        return secret, point

    def get_secret_and_commitment(self, subject, ctn):
        secret, point = self.get_secret_and_point(subject, ctn)
        ctx = self.make_commitment(subject, point, ctn)
        return secret, ctx

    def get_commitment(self, subject, ctn):
        secret, ctx = self.get_secret_and_commitment(subject, ctn)
        return ctx

    def get_next_commitment(self, subject: HTLCOwner) -> Transaction:
        ctn = self.get_next_ctn(subject)
        return self.get_commitment(subject, ctn)

    def get_latest_commitment(self, subject: HTLCOwner) -> Transaction:
        ctn = self.get_latest_ctn(subject)
        return self.get_commitment(subject, ctn)

    def get_oldest_unrevoked_commitment(self, subject: HTLCOwner) -> Transaction:
        ctn = self.get_oldest_unrevoked_ctn(subject)
        return self.get_commitment(subject, ctn)

    def create_sweeptxs(self, ctn: int) -> List[Transaction]:
        from .lnsweep import create_sweeptxs_for_watchtower
        secret, ctx = self.get_secret_and_commitment(REMOTE, ctn)
        return create_sweeptxs_for_watchtower(self, ctx, secret, self.sweep_address)

    def get_oldest_unrevoked_ctn(self, subject: HTLCOwner) -> int:
        return self.hm.ctn_oldest_unrevoked(subject)

    def get_latest_ctn(self, subject: HTLCOwner) -> int:
        return self.hm.ctn_latest(subject)

    def get_next_ctn(self, subject: HTLCOwner) -> int:
        return self.hm.ctn_latest(subject) + 1

    def total_msat(self, direction):
        """Return the cumulative total msat amount received/sent so far."""
        assert type(direction) is Direction
        return htlcsum(self.hm.all_settled_htlcs_ever_by_direction(LOCAL, direction))

    def settle_htlc(self, preimage, htlc_id):
        """
        SettleHTLC attempts to settle an existing outstanding received HTLC.
        """
        self.logger.info("settle_htlc")
        log = self.hm.log[REMOTE]
        htlc = log['adds'][htlc_id]
        assert htlc.payment_hash == sha256(preimage)
        assert htlc_id not in log['settles']
        self.hm.send_settle(htlc_id)

    def get_payment_hash(self, htlc_id):
        log = self.hm.log[LOCAL]
        htlc = log['adds'][htlc_id]
        return htlc.payment_hash

    def decode_onion_error(self, reason, route, htlc_id):
        failure_msg, sender_idx = decode_onion_error(
            reason,
            [x.node_id for x in route],
            self.onion_keys[htlc_id])
        return failure_msg, sender_idx

    def receive_htlc_settle(self, preimage, htlc_id):
        self.logger.info("receive_htlc_settle")
        log = self.hm.log[LOCAL]
        htlc = log['adds'][htlc_id]
        assert htlc.payment_hash == sha256(preimage)
        assert htlc_id not in log['settles']
        self.hm.recv_settle(htlc_id)

    def fail_htlc(self, htlc_id):
        self.logger.info("fail_htlc")
        self.hm.send_fail(htlc_id)

    def receive_fail_htlc(self, htlc_id):
        self.logger.info("receive_fail_htlc")
        self.hm.recv_fail(htlc_id)

    def pending_local_fee(self):
        return self.constraints.capacity - sum(x[2] for x in self.get_next_commitment(LOCAL).outputs())

    def update_fee(self, feerate: int, from_us: bool):
        # feerate uses sat/kw
        if self.constraints.is_initiator != from_us:
            raise Exception(f"Cannot update_fee: wrong initiator. us: {from_us}")
        if from_us:
            self.hm.send_update_fee(feerate)
        else:
            self.hm.recv_update_fee(feerate)

    def to_save(self):
        to_save = {
                "local_config": self.config[LOCAL],
                "remote_config": self.config[REMOTE],
                "channel_id": self.channel_id,
                "short_channel_id": self.short_channel_id,
                "constraints": self.constraints,
                "funding_outpoint": self.funding_outpoint,
                "node_id": self.node_id,
                "log": self.hm.to_save(),
                "onion_keys": str_bytes_dict_to_save(self.onion_keys),
                "force_closed": self.force_closed,
                "data_loss_protect_remote_pcp": str_bytes_dict_to_save(self.data_loss_protect_remote_pcp),
                "remote_update": self.remote_update.hex() if self.remote_update else None
        }
        return to_save

    def serialize(self):
        namedtuples_to_dict = lambda v: {i: j._asdict() if isinstance(j, tuple) else j for i, j in v._asdict().items()}
        serialized_channel = {}
        to_save_ref = self.to_save()
        for k, v in to_save_ref.items():
            if isinstance(v, tuple):
                serialized_channel[k] = namedtuples_to_dict(v)
            else:
                serialized_channel[k] = v
        dumped = ChannelJsonEncoder().encode(serialized_channel)
        roundtripped = json.loads(dumped)
        reconstructed = Channel(roundtripped)
        to_save_new = reconstructed.to_save()
        if to_save_new != to_save_ref:
            from pprint import PrettyPrinter
            pp = PrettyPrinter(indent=168)
            try:
                from deepdiff import DeepDiff
            except ImportError:
                raise Exception("Channels did not roundtrip serialization without changes:\n" + pp.pformat(to_save_ref) + "\n" + pp.pformat(to_save_new))
            else:
                raise Exception("Channels did not roundtrip serialization without changes:\n" + pp.pformat(DeepDiff(to_save_ref, to_save_new)))
        return roundtripped

    def __str__(self):
        return str(self.serialize())

    def make_commitment(self, subject, this_point, ctn) -> Transaction:
        assert type(subject) is HTLCOwner
        feerate = self.get_feerate(subject, ctn)
        other = REMOTE if LOCAL == subject else LOCAL
        local_msat = self.balance(subject, ctx_owner=subject, ctn=ctn)
        remote_msat = self.balance(other, ctx_owner=subject, ctn=ctn)
        received_htlcs = self.hm.htlcs_by_direction(subject, SENT if subject == LOCAL else RECEIVED, ctn).values()
        sent_htlcs = self.hm.htlcs_by_direction(subject, RECEIVED if subject == LOCAL else SENT, ctn).values()
        if subject != LOCAL:
            remote_msat -= htlcsum(received_htlcs)
            local_msat -= htlcsum(sent_htlcs)
        else:
            remote_msat -= htlcsum(sent_htlcs)
            local_msat -= htlcsum(received_htlcs)
        assert remote_msat >= 0
        assert local_msat >= 0
        # same htlcs as before, but now without dust.
        received_htlcs = self.included_htlcs(subject, SENT if subject == LOCAL else RECEIVED, ctn)
        sent_htlcs = self.included_htlcs(subject, RECEIVED if subject == LOCAL else SENT, ctn)

        this_config = self.config[subject]
        other_config = self.config[-subject]
        other_htlc_pubkey = derive_pubkey(other_config.htlc_basepoint.pubkey, this_point)
        this_htlc_pubkey = derive_pubkey(this_config.htlc_basepoint.pubkey, this_point)
        other_revocation_pubkey = derive_blinded_pubkey(other_config.revocation_basepoint.pubkey, this_point)
        htlcs = []  # type: List[ScriptHtlc]
        for is_received_htlc, htlc_list in zip((subject != LOCAL, subject == LOCAL), (received_htlcs, sent_htlcs)):
            for htlc in htlc_list:
                htlcs.append(ScriptHtlc(make_htlc_output_witness_script(
                    is_received_htlc=is_received_htlc,
                    remote_revocation_pubkey=other_revocation_pubkey,
                    remote_htlc_pubkey=other_htlc_pubkey,
                    local_htlc_pubkey=this_htlc_pubkey,
                    payment_hash=htlc.payment_hash,
                    cltv_expiry=htlc.cltv_expiry), htlc))
        onchain_fees = calc_onchain_fees(
            len(htlcs),
            feerate,
            self.constraints.is_initiator == (subject == LOCAL),
        )
        payment_pubkey = derive_pubkey(other_config.payment_basepoint.pubkey, this_point)
        return make_commitment(
            ctn,
            this_config.multisig_key.pubkey,
            other_config.multisig_key.pubkey,
            payment_pubkey,
            self.config[LOCAL if     self.constraints.is_initiator else REMOTE].payment_basepoint.pubkey,
            self.config[LOCAL if not self.constraints.is_initiator else REMOTE].payment_basepoint.pubkey,
            other_revocation_pubkey,
            derive_pubkey(this_config.delayed_basepoint.pubkey, this_point),
            other_config.to_self_delay,
            *self.funding_outpoint,
            self.constraints.capacity,
            local_msat,
            remote_msat,
            this_config.dust_limit_sat,
            onchain_fees,
            htlcs=htlcs)

    def get_local_index(self):
        return int(self.config[LOCAL].multisig_key.pubkey > self.config[REMOTE].multisig_key.pubkey)

    def make_closing_tx(self, local_script: bytes, remote_script: bytes,
                        fee_sat: int) -> Tuple[bytes, Transaction]:
        """ cooperative close """
        _, outputs = make_commitment_outputs({
                    LOCAL:  fee_sat * 1000 if     self.constraints.is_initiator else 0,
                    REMOTE: fee_sat * 1000 if not self.constraints.is_initiator else 0,
                },
                self.balance(LOCAL),
                self.balance(REMOTE),
                (TYPE_SCRIPT, bh2u(local_script)),
                (TYPE_SCRIPT, bh2u(remote_script)),
                [], self.config[LOCAL].dust_limit_sat)

        closing_tx = make_closing_tx(self.config[LOCAL].multisig_key.pubkey,
                                     self.config[REMOTE].multisig_key.pubkey,
                                     funding_txid=self.funding_outpoint.txid,
                                     funding_pos=self.funding_outpoint.output_index,
                                     funding_sat=self.constraints.capacity,
                                     outputs=outputs)

        der_sig = bfh(closing_tx.sign_txin(0, self.config[LOCAL].multisig_key.privkey))
        sig = ecc.sig_string_from_der_sig(der_sig[:-1])
        return sig, closing_tx

    def signature_fits(self, tx):
        remote_sig = self.config[LOCAL].current_commitment_signature
        preimage_hex = tx.serialize_preimage(0)
        pre_hash = sha256d(bfh(preimage_hex))
        assert remote_sig
        res = ecc.verify_signature(self.config[REMOTE].multisig_key.pubkey, remote_sig, pre_hash)
        return res

    def force_close_tx(self):
        tx = self.get_latest_commitment(LOCAL)
        assert self.signature_fits(tx)
        tx = Transaction(str(tx))
        tx.deserialize(True)
        tx.sign({bh2u(self.config[LOCAL].multisig_key.pubkey): (self.config[LOCAL].multisig_key.privkey, True)})
        remote_sig = self.config[LOCAL].current_commitment_signature
        remote_sig = ecc.der_sig_from_sig_string(remote_sig) + b"\x01"
        sigs = tx._inputs[0]["signatures"]
        none_idx = sigs.index(None)
        tx.add_signature_to_txin(0, none_idx, bh2u(remote_sig))
        assert tx.is_complete()
        return tx

    def sweep_ctx(self, ctx: Transaction) -> Dict[str, SweepInfo]:
        txid = ctx.txid()
        if self.sweep_info.get(txid) is None:
            our_sweep_info = create_sweeptxs_for_our_ctx(chan=self, ctx=ctx, sweep_address=self.sweep_address)
            their_sweep_info = create_sweeptxs_for_their_ctx(chan=self, ctx=ctx, sweep_address=self.sweep_address)
            if our_sweep_info is not None:
                self.sweep_info[txid] = our_sweep_info
                self.logger.info(f'we force closed.')
            elif their_sweep_info is not None:
                self.sweep_info[txid] = their_sweep_info
                self.logger.info(f'they force closed.')
            else:
                self.sweep_info[txid] = {}
                self.logger.info(f'not sure who closed {ctx}.')
        return self.sweep_info[txid]

    def sweep_htlc(self, ctx:Transaction, htlc_tx: Transaction):
        # look at the output address, check if it matches
        return create_sweeptx_for_their_revoked_htlc(self, ctx, htlc_tx, self.sweep_address)
