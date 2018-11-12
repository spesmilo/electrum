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

from collections import namedtuple, defaultdict
import binascii
import json
from enum import Enum, auto
from typing import Optional, Dict, List, Tuple, NamedTuple, Set, Callable, Iterable
from copy import deepcopy

from .util import bfh, PrintError, bh2u
from .bitcoin import TYPE_SCRIPT, TYPE_ADDRESS
from .bitcoin import redeem_script_to_address
from .crypto import sha256, sha256d
from . import ecc
from .lnutil import Outpoint, LocalConfig, RemoteConfig, Keypair, OnlyPubkeyKeypair, ChannelConstraints, RevocationStore, EncumberedTransaction
from .lnutil import get_per_commitment_secret_from_seed
from .lnutil import make_commitment_output_to_remote_address, make_commitment_output_to_local_witness_script
from .lnutil import secret_to_pubkey, derive_privkey, derive_pubkey, derive_blinded_pubkey, derive_blinded_privkey
from .lnutil import sign_and_get_sig_string, privkey_to_pubkey, make_htlc_tx_witness
from .lnutil import make_htlc_tx_with_open_channel, make_commitment, make_received_htlc, make_offered_htlc
from .lnutil import HTLC_TIMEOUT_WEIGHT, HTLC_SUCCESS_WEIGHT
from .lnutil import funding_output_script, LOCAL, REMOTE, HTLCOwner, make_closing_tx, make_commitment_outputs
from .lnutil import ScriptHtlc, SENT, RECEIVED, PaymentFailure, calc_onchain_fees, RemoteMisbehaving
from .transaction import Transaction, TxOutput, construct_witness
from .simple_config import SimpleConfig, FEERATE_FALLBACK_STATIC_FEE

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

class FeeUpdateProgress(Enum):
    FUNDEE_SIGNED = auto()
    FUNDEE_ACKED =  auto()
    FUNDER_SIGNED = auto()

FUNDEE_SIGNED = FeeUpdateProgress.FUNDEE_SIGNED
FUNDEE_ACKED = FeeUpdateProgress.FUNDEE_ACKED
FUNDER_SIGNED = FeeUpdateProgress.FUNDER_SIGNED

class FeeUpdate(defaultdict):
    def __init__(self, chan, rate):
        super().__init__(lambda: False)
        self.rate = rate
        self.chan = chan

    def pending_feerate(self, subject):
        if self[FUNDEE_ACKED]:
            return self.rate
        if subject == REMOTE and self.chan.constraints.is_initiator:
            return self.rate
        if subject == LOCAL and not self.chan.constraints.is_initiator:
            return self.rate
        # implicit return None

class UpdateAddHtlc(namedtuple('UpdateAddHtlc', ['amount_msat', 'payment_hash', 'cltv_expiry', 'htlc_id'])):
    """
    This whole class body is so that if you pass a hex-string as payment_hash,
    it is decoded to bytes. Bytes can't be saved to disk, so we save hex-strings.
    """
    __slots__ = ()
    def __new__(cls, *args, **kwargs):
        if len(args) > 0:
            args = list(args)
            if type(args[1]) is str:
                args[1] = bfh(args[1])
            return super().__new__(cls, *args)
        if type(kwargs['payment_hash']) is str:
            kwargs['payment_hash'] = bfh(kwargs['payment_hash'])
        return super().__new__(cls, **kwargs)

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
def str_bytes_dict_from_save(x):
    return {int(k): bfh(v) for k,v in x.items()}

def str_bytes_dict_to_save(x):
    return {str(k): bh2u(v) for k, v in x.items()}

class HtlcChanges(NamedTuple):
    # ints are htlc ids
    adds: Dict[int, UpdateAddHtlc]
    settles: Set[int]
    fails: Set[int]
    locked_in: Set[int]

    @staticmethod
    def new():
        """
        Since we can't use default arguments for these types (they would be shared among instances)
        """
        return HtlcChanges({}, set(), set(), set())

class Channel(PrintError):
    def diagnostic_name(self):
        if self.name:
            return str(self.name)
        try:
            return f"lnchan_{bh2u(self.channel_id[-4:])}"
        except:
            return super().diagnostic_name()

    def __init__(self, state, name = None, payment_completed : Optional[Callable[[HTLCOwner, UpdateAddHtlc, bytes], None]] = None):
        self.preimages = {}
        if not payment_completed:
            payment_completed = lambda x, y, z: None
        self.payment_completed = payment_completed
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
        self.node_id = bfh(state["node_id"]) if type(state["node_id"]) not in (bytes, type(None)) else state["node_id"]
        self.short_channel_id = bfh(state["short_channel_id"]) if type(state["short_channel_id"]) not in (bytes, type(None)) else state["short_channel_id"]
        self.short_channel_id_predicted = self.short_channel_id
        self.onion_keys = str_bytes_dict_from_save(state.get('onion_keys', {}))

        # FIXME this is a tx serialised in the custom electrum partial tx format.
        # we should not persist txns in this format. we should persist htlcs, and be able to derive
        # any past commitment transaction and use that instead; until then...
        self.remote_commitment_to_be_revoked = Transaction(state["remote_commitment_to_be_revoked"])

        self.log = {LOCAL: HtlcChanges.new(), REMOTE: HtlcChanges.new()}
        for strname, subject in [('remote_log', REMOTE), ('local_log', LOCAL)]:
            if strname not in state: continue
            for y in state[strname]:
                htlc = UpdateAddHtlc(**y)
                self.log[subject].adds[htlc.htlc_id] = htlc

        self.name = name

        self.pending_fee = None

        self.local_commitment = self.pending_local_commitment
        self.remote_commitment = self.pending_remote_commitment

        self._is_funding_txo_spent = None  # "don't know"
        self._state = None
        if state.get('force_closed', False):
            self.set_state('FORCE_CLOSING')
        else:
            self.set_state('DISCONNECTED')

        self.lnwatcher = None

        self.settled = {LOCAL: state.get('settled_local', []), REMOTE: state.get('settled_remote', [])}

        for sub in (LOCAL, REMOTE):
            self.log[sub].locked_in.update(self.log[sub].adds.keys())

    def set_state(self, state: str):
        if self._state == 'FORCE_CLOSING':
            assert state == 'FORCE_CLOSING', 'new state was not FORCE_CLOSING: ' + state
        self._state = state

    def get_state(self):
        return self._state

    def _check_can_pay(self, amount_msat: int) -> None:
        if self.get_state() != 'OPEN':
            raise PaymentFailure('Channel not open')
        if self.available_to_spend(LOCAL) < amount_msat:
            raise PaymentFailure(f'Not enough local balance. Have: {self.available_to_spend(LOCAL)}, Need: {amount_msat}')
        if len(self.htlcs(LOCAL, only_pending=True)) + 1 > self.config[REMOTE].max_accepted_htlcs:
            raise PaymentFailure('Too many HTLCs already in channel')
        current_htlc_sum = htlcsum(self.htlcs(LOCAL, only_pending=True))
        if current_htlc_sum + amount_msat > self.config[REMOTE].max_htlc_value_in_flight_msat:
            raise PaymentFailure(f'HTLC value sum (sum of pending htlcs: {current_htlc_sum/1000} sat plus new htlc: {amount_msat/1000} sat) would exceed max allowed: {self.config[REMOTE].max_htlc_value_in_flight_msat/1000} sat')
        if amount_msat <= 0:  # FIXME htlc_minimum_msat
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

    def add_htlc(self, htlc):
        """
        AddHTLC adds an HTLC to the state machine's local update log. This method
        should be called when preparing to send an outgoing HTLC.

        This docstring is from LND.
        """
        assert type(htlc) is dict
        self._check_can_pay(htlc['amount_msat'])
        htlc = UpdateAddHtlc(**htlc, htlc_id=self.config[LOCAL].next_htlc_id)
        self.log[LOCAL].adds[htlc.htlc_id] = htlc
        self.print_error("add_htlc")
        self.config[LOCAL]=self.config[LOCAL]._replace(next_htlc_id=htlc.htlc_id + 1)
        return htlc.htlc_id

    def receive_htlc(self, htlc):
        """
        ReceiveHTLC adds an HTLC to the state machine's remote update log. This
        method should be called in response to receiving a new HTLC from the remote
        party.

        This docstring is from LND.
        """
        assert type(htlc) is dict
        htlc = UpdateAddHtlc(**htlc, htlc_id = self.config[REMOTE].next_htlc_id)
        if self.available_to_spend(REMOTE) < htlc.amount_msat:
            raise RemoteMisbehaving('Remote dipped below channel reserve.' +\
                    f' Available at remote: {self.available_to_spend(REMOTE)},' +\
                    f' HTLC amount: {htlc.amount_msat}')
        adds = self.log[REMOTE].adds
        adds[htlc.htlc_id] = htlc
        self.print_error("receive_htlc")
        self.config[REMOTE]=self.config[REMOTE]._replace(next_htlc_id=htlc.htlc_id + 1)
        return htlc.htlc_id

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
        self.print_error("sign_next_commitment")

        old_logs = dict(self.lock_in_htlc_changes(LOCAL))

        pending_remote_commitment = self.pending_remote_commitment
        sig_64 = sign_and_get_sig_string(pending_remote_commitment, self.config[LOCAL], self.config[REMOTE])

        their_remote_htlc_privkey_number = derive_privkey(
            int.from_bytes(self.config[LOCAL].htlc_basepoint.privkey, 'big'),
            self.config[REMOTE].next_per_commitment_point)
        their_remote_htlc_privkey = their_remote_htlc_privkey_number.to_bytes(32, 'big')

        for_us = False

        htlcsigs = []
        for we_receive, htlcs in zip([True, False], [self.included_htlcs(REMOTE, REMOTE), self.included_htlcs(REMOTE, LOCAL)]):
            for htlc in htlcs:
                args = [self.config[REMOTE].next_per_commitment_point, for_us, we_receive, pending_remote_commitment, htlc]
                _script, htlc_tx = make_htlc_tx_with_open_channel(self, *args)
                sig = bfh(htlc_tx.sign_txin(0, their_remote_htlc_privkey))
                htlc_sig = ecc.sig_string_from_der_sig(sig[:-1])
                htlcsigs.append((pending_remote_commitment.htlc_output_indices[htlc.payment_hash], htlc_sig))

        self.process_new_offchain_ctx(pending_remote_commitment, ours=False)

        htlcsigs.sort()
        htlcsigs = [x[1] for x in htlcsigs]

        # we can't know if this message arrives.
        # since we shouldn't actually throw away
        # failed htlcs yet (or mark htlc locked in),
        # roll back the changes that were made
        self.log = old_logs

        return sig_64, htlcsigs

    def lock_in_htlc_changes(self, subject):
        for sub in (LOCAL, REMOTE):
            log = self.log[sub]
            yield (sub, deepcopy(log))
            for htlc_id in log.fails:
                log.adds.pop(htlc_id)
            log.fails.clear()

        self.log[subject].locked_in.update(self.log[subject].adds.keys())

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
        self.print_error("receive_new_commitment")

        for _ in self.lock_in_htlc_changes(REMOTE): pass

        assert len(htlc_sigs) == 0 or type(htlc_sigs[0]) is bytes

        pending_local_commitment = self.pending_local_commitment
        preimage_hex = pending_local_commitment.serialize_preimage(0)
        pre_hash = sha256d(bfh(preimage_hex))
        if not ecc.verify_signature(self.config[REMOTE].multisig_key.pubkey, sig, pre_hash):
            raise Exception('failed verifying signature of our updated commitment transaction: ' + bh2u(sig) + ' preimage is ' + preimage_hex)

        htlc_sigs_string = b''.join(htlc_sigs)

        htlc_sigs = htlc_sigs[:] # copy cause we will delete now
        for htlcs, we_receive in [(self.included_htlcs(LOCAL, REMOTE), True), (self.included_htlcs(LOCAL, LOCAL), False)]:
            for htlc in htlcs:
                idx = self.verify_htlc(htlc, htlc_sigs, we_receive)
                del htlc_sigs[idx]
        if len(htlc_sigs) != 0: # all sigs should have been popped above
            raise Exception('failed verifying HTLC signatures: invalid amount of correct signatures')

        self.config[LOCAL]=self.config[LOCAL]._replace(
            current_commitment_signature=sig,
            current_htlc_signatures=htlc_sigs_string)

        if self.pending_fee:
            if not self.constraints.is_initiator:
                self.pending_fee[FUNDEE_SIGNED] = True
            if self.constraints.is_initiator and self.pending_fee[FUNDEE_ACKED]:
                self.pending_fee[FUNDER_SIGNED] = True

        self.process_new_offchain_ctx(pending_local_commitment, ours=True)

    def verify_htlc(self, htlc, htlc_sigs, we_receive):
        _, this_point, _ = self.points
        _script, htlc_tx = make_htlc_tx_with_open_channel(self, this_point, True, we_receive, self.pending_local_commitment, htlc)
        pre_hash = sha256d(bfh(htlc_tx.serialize_preimage(0)))
        remote_htlc_pubkey = derive_pubkey(self.config[REMOTE].htlc_basepoint.pubkey, this_point)
        for idx, sig in enumerate(htlc_sigs):
            if ecc.verify_signature(remote_htlc_pubkey, sig, pre_hash):
                return idx
        else:
            raise Exception(f'failed verifying HTLC signatures: {htlc}')

    def revoke_current_commitment(self):
        self.print_error("revoke_current_commitment")

        last_secret, this_point, next_point = self.points

        new_feerate = self.constraints.feerate

        if self.pending_fee:
            if not self.constraints.is_initiator and self.pending_fee[FUNDEE_SIGNED]:
                new_feerate = self.pending_fee.rate
                self.pending_fee = None
                print("FEERATE CHANGE COMPLETE (non-initiator)")
            if self.constraints.is_initiator and self.pending_fee[FUNDER_SIGNED]:
                new_feerate = self.pending_fee.rate
                self.pending_fee = None
                print("FEERATE CHANGE COMPLETE (initiator)")

        self.config[LOCAL]=self.config[LOCAL]._replace(
            ctn=self.config[LOCAL].ctn + 1,
        )
        self.constraints=self.constraints._replace(
            feerate=new_feerate
        )

        self.local_commitment = self.pending_local_commitment

        return RevokeAndAck(last_secret, next_point), "current htlcs"

    @property
    def points(self):
        last_small_num = self.config[LOCAL].ctn
        this_small_num = last_small_num + 1
        next_small_num = last_small_num + 2
        last_secret = get_per_commitment_secret_from_seed(self.config[LOCAL].per_commitment_secret_seed, RevocationStore.START_INDEX - last_small_num)
        this_secret = get_per_commitment_secret_from_seed(self.config[LOCAL].per_commitment_secret_seed, RevocationStore.START_INDEX - this_small_num)
        this_point = secret_to_pubkey(int.from_bytes(this_secret, 'big'))
        next_secret = get_per_commitment_secret_from_seed(self.config[LOCAL].per_commitment_secret_seed, RevocationStore.START_INDEX - next_small_num)
        next_point = secret_to_pubkey(int.from_bytes(next_secret, 'big'))
        return last_secret, this_point, next_point

    # TODO batch sweeps
    # TODO sweep HTLC outputs
    def process_new_offchain_ctx(self, ctx, ours: bool):
        if not self.lnwatcher:
            return
        outpoint = self.funding_outpoint.to_str()
        if ours:
            ctn = self.config[LOCAL].ctn + 1
            our_per_commitment_secret = get_per_commitment_secret_from_seed(
                self.config[LOCAL].per_commitment_secret_seed, RevocationStore.START_INDEX - ctn)
            our_cur_pcp = ecc.ECPrivkey(our_per_commitment_secret).get_public_key_bytes(compressed=True)
            encumbered_sweeptxs = create_sweeptxs_for_our_ctx(self, ctx, our_cur_pcp, self.sweep_address)
        else:
            their_cur_pcp = self.config[REMOTE].next_per_commitment_point
            encumbered_sweeptxs = [(None, maybe_create_sweeptx_for_their_ctx_to_remote(self, ctx, their_cur_pcp, self.sweep_address))]
        for prev_txid, encumbered_tx in encumbered_sweeptxs:
            if prev_txid is None:
                prev_txid = ctx.txid()
            if encumbered_tx is not None:
                self.lnwatcher.add_sweep_tx(outpoint, prev_txid, encumbered_tx.to_json())

    def process_new_revocation_secret(self, per_commitment_secret: bytes):
        if not self.lnwatcher:
            return
        outpoint = self.funding_outpoint.to_str()
        ctx = self.remote_commitment_to_be_revoked
        encumbered_sweeptx = maybe_create_sweeptx_for_their_ctx_to_local(self, ctx, per_commitment_secret, self.sweep_address)
        if encumbered_sweeptx:
            self.lnwatcher.add_sweep_tx(outpoint, ctx.txid(), encumbered_sweeptx.to_json())

    def receive_revocation(self, revocation) -> Tuple[int, int]:
        self.print_error("receive_revocation")

        old_logs = dict(self.lock_in_htlc_changes(LOCAL))

        cur_point = self.config[REMOTE].current_per_commitment_point
        derived_point = ecc.ECPrivkey(revocation.per_commitment_secret).get_public_key_bytes(compressed=True)
        if cur_point != derived_point:
            self.log = old_logs
            raise Exception('revoked secret not for current point')

        if self.pending_fee:
            if not self.constraints.is_initiator:
                self.pending_fee[FUNDEE_SIGNED] = True
            if self.constraints.is_initiator and pending_fee[FUNDEE_ACKED]:
                self.pending_fee[FUNDER_SIGNED] = True

        # FIXME not sure this is correct... but it seems to work
        # if there are update_add_htlc msgs between commitment_signed and rev_ack,
        # this might break
        prev_remote_commitment = self.pending_remote_commitment

        self.config[REMOTE].revocation_store.add_next_entry(revocation.per_commitment_secret)
        self.process_new_revocation_secret(revocation.per_commitment_secret)

        def mark_settled(subject):
            """
            find pending settlements for subject (LOCAL or REMOTE) and mark them settled, return value of settled htlcs
            """
            old_amount = htlcsum(self.htlcs(subject, False))

            for htlc_id in self.log[subject].settles:
                adds = self.log[subject].adds
                htlc = adds.pop(htlc_id)
                self.settled[subject].append(htlc.amount_msat)
                if subject == LOCAL:
                    preimage = self.preimages.pop(htlc_id)
                else:
                    preimage = None
                self.payment_completed(subject, htlc, preimage)
            self.log[subject].settles.clear()

            return old_amount - htlcsum(self.htlcs(subject, False))

        sent_this_batch = mark_settled(LOCAL)
        received_this_batch = mark_settled(REMOTE)

        next_point = self.config[REMOTE].next_per_commitment_point

        print("RECEIVED", received_this_batch)
        print("SENT", sent_this_batch)
        self.config[REMOTE]=self.config[REMOTE]._replace(
            ctn=self.config[REMOTE].ctn + 1,
            current_per_commitment_point=next_point,
            next_per_commitment_point=revocation.next_per_commitment_point,
            amount_msat=self.config[REMOTE].amount_msat + (sent_this_batch - received_this_batch)
        )
        self.config[LOCAL]=self.config[LOCAL]._replace(
            amount_msat = self.config[LOCAL].amount_msat + (received_this_batch - sent_this_batch)
        )

        if self.pending_fee:
            if self.constraints.is_initiator:
                self.pending_fee[FUNDEE_ACKED] = True

        self.local_commitment = self.pending_local_commitment
        self.remote_commitment = self.pending_remote_commitment
        self.remote_commitment_to_be_revoked = prev_remote_commitment
        return received_this_batch, sent_this_batch

    def balance(self, subject):
        """
        This balance in mSAT is not including reserve and fees.
        So a node cannot actually use it's whole balance.
        But this number is simple, since it is derived simply
        from the initial balance, and the value of settled HTLCs.
        Note that it does not decrease once an HTLC is added,
        failed or fulfilled, since the balance change is only
        commited to later when the respective commitment
        transaction as been revoked.
        """
        initial = self.config[subject].initial_msat

        initial -= sum(self.settled[subject])
        initial += sum(self.settled[-subject])

        assert initial == self.config[subject].amount_msat
        return initial

    def balance_minus_outgoing_htlcs(self, subject):
        """
        This balance in mSAT, which includes the value of
        pending outgoing HTLCs, is used in the UI.
        """
        return self.balance(subject)\
                - htlcsum(self.log[subject].adds.values())

    def available_to_spend(self, subject):
        """
        This balance in mSAT, while technically correct, can
        not be used in the UI cause it fluctuates (commit fee)
        """
        return self.balance_minus_outgoing_htlcs(subject)\
                - htlcsum(self.log[subject].adds.values())\
                - self.config[-subject].reserve_sat * 1000\
                - calc_onchain_fees(
                      # TODO should we include a potential new htlc, when we are called from receive_htlc?
                      len(list(self.included_htlcs(subject, LOCAL)) + list(self.included_htlcs(subject, REMOTE))),
                      self.pending_feerate(subject),
                      True, # for_us
                      self.constraints.is_initiator,
                  )[subject]

    def amounts(self):
        remote_settled= htlcsum(self.htlcs(REMOTE, False))
        local_settled= htlcsum(self.htlcs(LOCAL, False))
        unsettled_local = htlcsum(self.htlcs(LOCAL, True))
        unsettled_remote = htlcsum(self.htlcs(REMOTE, True))
        remote_msat = self.config[REMOTE].amount_msat -\
          unsettled_remote + local_settled - remote_settled
        local_msat = self.config[LOCAL].amount_msat -\
          unsettled_local + remote_settled - local_settled
        return remote_msat, local_msat

    def included_htlcs(self, subject, htlc_initiator, only_pending=True):
        """
        return filter of non-dust htlcs for subjects commitment transaction, initiated by given party
        """
        feerate = self.pending_feerate(subject)
        conf = self.config[subject]
        weight = HTLC_SUCCESS_WEIGHT if subject != htlc_initiator else HTLC_TIMEOUT_WEIGHT
        htlcs = self.htlcs(htlc_initiator, only_pending=only_pending)
        fee_for_htlc = lambda htlc: htlc.amount_msat // 1000 - (weight * feerate // 1000)
        return filter(lambda htlc: fee_for_htlc(htlc) >= conf.dust_limit_sat, htlcs)

    @property
    def pending_remote_commitment(self):
        this_point = self.config[REMOTE].next_per_commitment_point
        return self.make_commitment(REMOTE, this_point)

    def pending_feerate(self, subject):
        candidate = self.constraints.feerate
        if self.pending_fee:
            x = self.pending_fee.pending_feerate(subject)
            if x is not None:
                candidate = x
        return candidate

    @property
    def pending_local_commitment(self):
        _, this_point, _ = self.points
        return self.make_commitment(LOCAL, this_point)

    def total_msat(self, sub):
        return sum(self.settled[sub])

    def htlcs(self, subject, only_pending):
        """
        only_pending: require the htlc's settlement to be pending (needs additional signatures/acks)
        """
        update_log = self.log[subject]
        res = []
        for htlc in update_log.adds.values():
            locked_in = htlc.htlc_id in update_log.locked_in
            settled = htlc.htlc_id in update_log.settles
            failed =  htlc.htlc_id in update_log.fails
            if not locked_in:
                continue
            if only_pending == (settled or failed):
                continue
            res.append(htlc)
        return res

    def settle_htlc(self, preimage, htlc_id):
        """
        SettleHTLC attempts to settle an existing outstanding received HTLC.
        """
        self.print_error("settle_htlc")
        log = self.log[REMOTE]
        htlc = log.adds[htlc_id]
        assert htlc.payment_hash == sha256(preimage)
        assert htlc_id not in log.settles
        log.settles.add(htlc_id)
        # not saving preimage because it's already saved in LNWorker.invoices

    def receive_htlc_settle(self, preimage, htlc_id):
        self.print_error("receive_htlc_settle")
        log = self.log[LOCAL]
        htlc = log.adds[htlc_id]
        assert htlc.payment_hash == sha256(preimage)
        assert htlc_id not in log.settles
        self.preimages[htlc_id] = preimage
        log.settles.add(htlc_id)
        # we don't save the preimage because we don't need to forward it anyway

    def fail_htlc(self, htlc_id):
        self.print_error("fail_htlc")
        log = self.log[REMOTE]
        assert htlc_id not in log.fails
        log.fails.add(htlc_id)

    def receive_fail_htlc(self, htlc_id):
        self.print_error("receive_fail_htlc")
        log = self.log[LOCAL]
        assert htlc_id not in log.fails
        log.fails.add(htlc_id)

    @property
    def current_height(self):
        return {LOCAL: self.config[LOCAL].ctn, REMOTE: self.config[REMOTE].ctn}

    @property
    def pending_local_fee(self):
        return self.constraints.capacity - sum(x[2] for x in self.pending_local_commitment.outputs())

    def update_fee(self, feerate, initiator):
        if self.constraints.is_initiator != initiator:
            raise Exception("Cannot update_fee: wrong initiator", initiator)
        if self.pending_fee:
            raise Exception("a fee update is already in progress")
        self.pending_fee = FeeUpdate(self, rate=feerate)

    def remove_uncommitted_htlcs_from_log(self, subject):
        """
        returns
        - the htlcs with uncommited (not locked in) htlcs removed
        - a list of htlc_ids that were removed
        """
        removed = []
        htlcs = []
        log = self.log[subject]
        for i in log.adds.values():
            locked_in = i.htlc_id in log.locked_in
            if locked_in:
                htlcs.append(i._asdict())
            else:
                removed.append(i.htlc_id)
        return htlcs, removed

    def to_save(self):
        # need to forget about uncommited htlcs
        # since we must assume they don't know about it,
        # if it was not acked
        remote_filtered, remote_removed = self.remove_uncommitted_htlcs_from_log(REMOTE)
        local_filtered, local_removed = self.remove_uncommitted_htlcs_from_log(LOCAL)
        to_save = {
                "local_config": self.config[LOCAL],
                "remote_config": self.config[REMOTE],
                "channel_id": self.channel_id,
                "short_channel_id": self.short_channel_id,
                "constraints": self.constraints,
                "funding_outpoint": self.funding_outpoint,
                "node_id": self.node_id,
                "remote_commitment_to_be_revoked": str(self.remote_commitment_to_be_revoked),
                "remote_log": remote_filtered,
                "local_log": local_filtered,
                "onion_keys": str_bytes_dict_to_save(self.onion_keys),
                "settled_local": self.settled[LOCAL],
                "settled_remote": self.settled[REMOTE],
                "force_closed": self.get_state() == 'FORCE_CLOSING',
        }

        # htlcs number must be monotonically increasing,
        # so we have to decrease the counter
        if len(remote_removed) != 0:
            assert min(remote_removed) < to_save['remote_config'].next_htlc_id
            to_save['remote_config'] = to_save['remote_config']._replace(next_htlc_id = min(remote_removed))

        if len(local_removed) != 0:
            assert min(local_removed) < to_save['local_config'].next_htlc_id
            to_save['local_config'] = to_save['local_config']._replace(next_htlc_id = min(local_removed))

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

    def make_commitment(self, subject, this_point) -> Transaction:
        remote_msat, local_msat = self.amounts()
        assert local_msat >= 0, local_msat
        assert remote_msat >= 0, remote_msat
        this_config = self.config[subject]
        other_config = self.config[-subject]
        other_htlc_pubkey = derive_pubkey(other_config.htlc_basepoint.pubkey, this_point)
        this_htlc_pubkey = derive_pubkey(this_config.htlc_basepoint.pubkey, this_point)
        other_revocation_pubkey = derive_blinded_pubkey(other_config.revocation_basepoint.pubkey, this_point)
        htlcs = []
        for htlc in self.included_htlcs(subject, -subject):
            htlcs.append( ScriptHtlc( make_received_htlc(
                other_revocation_pubkey,
                other_htlc_pubkey,
                this_htlc_pubkey,
                htlc.payment_hash,
                htlc.cltv_expiry), htlc))
        for htlc in self.included_htlcs(subject, subject):
            htlcs.append(
                ScriptHtlc( make_offered_htlc(
                    other_revocation_pubkey,
                    other_htlc_pubkey,
                    this_htlc_pubkey,
                    htlc.payment_hash), htlc))
        if subject != LOCAL:
            remote_msat, local_msat = local_msat, remote_msat
        payment_pubkey = derive_pubkey(other_config.payment_basepoint.pubkey, this_point)
        return make_commitment(
            self.config[subject].ctn + 1,
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
            calc_onchain_fees(
                len(htlcs),
                self.pending_feerate(subject),
                subject == LOCAL,
                self.constraints.is_initiator,
            ),
            htlcs=htlcs)

    def make_closing_tx(self, local_script: bytes, remote_script: bytes,
                        fee_sat: Optional[int]=None) -> Tuple[bytes, int, str]:
        """ cooperative close """
        if fee_sat is None:
            fee_sat = self.pending_local_fee

        _, outputs = make_commitment_outputs({
                    LOCAL:  fee_sat * 1000 if     self.constraints.is_initiator else 0,
                    REMOTE: fee_sat * 1000 if not self.constraints.is_initiator else 0,
                },
                self.config[LOCAL].amount_msat,
                self.config[REMOTE].amount_msat,
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
        return sig, fee_sat, closing_tx.txid()

    def force_close_tx(self):
        # local_commitment always gives back the next expected local_commitment,
        # but in this case, we want the current one. So substract one ctn number
        old_local_state = self.config[LOCAL]
        self.config[LOCAL]=self.config[LOCAL]._replace(ctn=self.config[LOCAL].ctn - 1)
        tx = self.pending_local_commitment
        self.config[LOCAL] = old_local_state
        tx.sign({bh2u(self.config[LOCAL].multisig_key.pubkey): (self.config[LOCAL].multisig_key.privkey, True)})
        remote_sig = self.config[LOCAL].current_commitment_signature
        remote_sig = ecc.der_sig_from_sig_string(remote_sig) + b"\x01"
        none_idx = tx._inputs[0]["signatures"].index(None)
        tx.add_signature_to_txin(0, none_idx, bh2u(remote_sig))
        assert tx.is_complete()
        return tx

    def included_htlcs_in_latest_ctxs(self):
        """ A map from commitment number to list of HTLCs in
            their latest two commitment transactions.
            The oldest might have been revoked.  """
        old_htlcs = list(self.included_htlcs(REMOTE, REMOTE, only_pending=False)) \
                  + list(self.included_htlcs(REMOTE, LOCAL,  only_pending=False))

        old_logs = dict(self.lock_in_htlc_changes(LOCAL))
        new_htlcs = list(self.included_htlcs(REMOTE, REMOTE)) \
                  + list(self.included_htlcs(REMOTE, LOCAL))
        self.log = old_logs

        return {self.config[REMOTE].ctn:   old_htlcs,
                self.config[REMOTE].ctn+1: new_htlcs, }

def maybe_create_sweeptx_for_their_ctx_to_remote(chan, ctx, their_pcp: bytes,
                                                 sweep_address) -> Optional[EncumberedTransaction]:
    assert isinstance(their_pcp, bytes)
    payment_bp_privkey = ecc.ECPrivkey(chan.config[LOCAL].payment_basepoint.privkey)
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
    return EncumberedTransaction('their_ctx_to_remote', sweep_tx, csv_delay=0, cltv_expiry=0)


def maybe_create_sweeptx_for_their_ctx_to_local(chan, ctx, per_commitment_secret: bytes,
                                                sweep_address) -> Optional[EncumberedTransaction]:
    assert isinstance(per_commitment_secret, bytes)
    per_commitment_point = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
    revocation_privkey = derive_blinded_privkey(chan.config[LOCAL].revocation_basepoint.privkey,
                                                per_commitment_secret)
    revocation_pubkey = ecc.ECPrivkey(revocation_privkey).get_public_key_bytes(compressed=True)
    to_self_delay = chan.config[LOCAL].to_self_delay
    delayed_pubkey = derive_pubkey(chan.config[REMOTE].delayed_basepoint.pubkey,
                                   per_commitment_point)
    witness_script = bh2u(make_commitment_output_to_local_witness_script(
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
    return EncumberedTransaction('their_ctx_to_local', sweep_tx, csv_delay=0, cltv_expiry=0)


def create_sweeptxs_for_our_ctx(chan, ctx, our_pcp: bytes, sweep_address) \
                                                        -> List[Tuple[Optional[str],EncumberedTransaction]]:
    assert isinstance(our_pcp, bytes)
    delayed_bp_privkey = ecc.ECPrivkey(chan.config[LOCAL].delayed_basepoint.privkey)
    our_localdelayed_privkey = derive_privkey(delayed_bp_privkey.secret_scalar, our_pcp)
    our_localdelayed_privkey = ecc.ECPrivkey.from_secret_scalar(our_localdelayed_privkey)
    our_localdelayed_pubkey = our_localdelayed_privkey.get_public_key_bytes(compressed=True)
    revocation_pubkey = derive_blinded_pubkey(chan.config[REMOTE].revocation_basepoint.pubkey,
                                              our_pcp)
    to_self_delay = chan.config[REMOTE].to_self_delay
    witness_script = bh2u(make_commitment_output_to_local_witness_script(
        revocation_pubkey, to_self_delay, our_localdelayed_pubkey))
    to_local_address = redeem_script_to_address('p2wsh', witness_script)
    txs = []
    for output_idx, o in enumerate(ctx.outputs()):
        if o.type == TYPE_ADDRESS and o.address == to_local_address:
            sweep_tx = create_sweeptx_ctx_to_local(address=sweep_address,
                                                   ctx=ctx,
                                                   output_idx=output_idx,
                                                   witness_script=witness_script,
                                                   privkey=our_localdelayed_privkey.get_secret_bytes(),
                                                   is_revocation=False,
                                                   to_self_delay=to_self_delay)

            txs.append((None, EncumberedTransaction('our_ctx_to_local', sweep_tx, csv_delay=to_self_delay, cltv_expiry=0)))
            break

    # TODO htlc successes
    htlcs = list(chan.included_htlcs(LOCAL, LOCAL)) # timeouts
    for htlc in htlcs:
        witness_script, htlc_tx = make_htlc_tx_with_open_channel(
            chan,
            our_pcp,
            True, # for_us
            False, # we_receive
            ctx, htlc)

        data = chan.config[LOCAL].current_htlc_signatures
        htlc_sigs = [data[i:i+64] for i in range(0, len(data), 64)]
        idx = chan.verify_htlc(htlc, htlc_sigs, False)
        remote_htlc_sig = ecc.der_sig_from_sig_string(htlc_sigs[idx]) + b'\x01'

        remote_revocation_pubkey = derive_blinded_pubkey(chan.config[REMOTE].revocation_basepoint.pubkey, our_pcp)
        remote_htlc_pubkey = derive_pubkey(chan.config[REMOTE].htlc_basepoint.pubkey, our_pcp)
        local_htlc_key = derive_privkey(
            int.from_bytes(chan.config[LOCAL].htlc_basepoint.privkey, 'big'),
            our_pcp).to_bytes(32, 'big')
        program = make_offered_htlc(remote_revocation_pubkey, remote_htlc_pubkey, privkey_to_pubkey(local_htlc_key), htlc.payment_hash)
        local_htlc_sig = bfh(htlc_tx.sign_txin(0, local_htlc_key))

        htlc_tx.inputs()[0]['witness'] = bh2u(make_htlc_tx_witness(remote_htlc_sig, local_htlc_sig, b'', program))

        tx_size_bytes = 999  # TODO
        fee_per_kb = FEERATE_FALLBACK_STATIC_FEE
        fee = SimpleConfig.estimate_fee_for_feerate(fee_per_kb, tx_size_bytes)
        second_stage_outputs = [TxOutput(TYPE_ADDRESS, chan.sweep_address, htlc.amount_msat // 1000 - fee)]
        assert to_self_delay is not None
        second_stage_inputs = [{
            'scriptSig': '',
            'type': 'p2wsh',
            'signatures': [],
            'num_sig': 0,
            'prevout_n': 0,
            'prevout_hash': htlc_tx.txid(),
            'value': htlc_tx.outputs()[0].value,
            'coinbase': False,
            'preimage_script': bh2u(witness_script),
            'sequence': to_self_delay,
        }]
        tx = Transaction.from_io(second_stage_inputs, second_stage_outputs, version=2)

        local_delaykey = derive_privkey(
            int.from_bytes(chan.config[LOCAL].delayed_basepoint.privkey, 'big'),
            our_pcp).to_bytes(32, 'big')
        assert local_delaykey == our_localdelayed_privkey.get_secret_bytes()

        witness = construct_witness([bfh(tx.sign_txin(0, local_delaykey)), 0, witness_script])
        tx.inputs()[0]['witness'] = witness
        assert tx.is_complete()

        txs.append((htlc_tx.txid(), EncumberedTransaction(f'second_stage_to_wallet_{bh2u(htlc.payment_hash)}', tx, csv_delay=to_self_delay, cltv_expiry=0)))
        txs.append((ctx.txid(), EncumberedTransaction(f'our_ctx_htlc_tx_{bh2u(htlc.payment_hash)}', htlc_tx, csv_delay=0, cltv_expiry=htlc.cltv_expiry)))

    return txs

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
    witness = construct_witness([sig, int(is_revocation), witness_script])
    sweep_tx.inputs()[0]['witness'] = witness
    return sweep_tx
