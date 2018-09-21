# ported from lnd 42de4400bff5105352d0552155f73589166d162b
from collections import namedtuple
import binascii
import json
from enum import Enum, auto
from typing import Optional

from .util import bfh, PrintError, bh2u
from .bitcoin import Hash, TYPE_SCRIPT
from .bitcoin import redeem_script_to_address
from .crypto import sha256
from . import ecc
from .lnutil import Outpoint, ChannelConfig, LocalState, RemoteState, Keypair, OnlyPubkeyKeypair, ChannelConstraints, RevocationStore
from .lnutil import get_per_commitment_secret_from_seed
from .lnutil import secret_to_pubkey, derive_privkey, derive_pubkey, derive_blinded_pubkey
from .lnutil import sign_and_get_sig_string
from .lnutil import make_htlc_tx_with_open_channel, make_commitment, make_received_htlc, make_offered_htlc
from .lnutil import HTLC_TIMEOUT_WEIGHT, HTLC_SUCCESS_WEIGHT
from .lnutil import funding_output_script, LOCAL, REMOTE, HTLCOwner, make_closing_tx, make_outputs
from .transaction import Transaction


SettleHtlc = namedtuple("SettleHtlc", ["htlc_id"])
RevokeAndAck = namedtuple("RevokeAndAck", ["per_commitment_secret", "next_per_commitment_point"])

class FeeUpdateProgress(Enum):
    FUNDEE_SIGNED = auto()
    FUNDEE_ACKED =  auto()
    FUNDER_SIGNED = auto()
    COMMITTED = auto()

FUNDEE_SIGNED = FeeUpdateProgress.FUNDEE_SIGNED
FUNDEE_ACKED = FeeUpdateProgress.FUNDEE_ACKED
FUNDER_SIGNED = FeeUpdateProgress.FUNDER_SIGNED
COMMITTED = FeeUpdateProgress.COMMITTED

from collections import namedtuple

class FeeUpdate:
    def __init__(self, chan, **kwargs):
        if 'rate' in kwargs:
            self.rate = kwargs['rate']
        else:
            assert False
        if 'proposed' not in kwargs:
            self.proposed = chan.remote_state.ctn if not chan.constraints.is_initiator else chan.local_state.ctn
        else:
            self.proposed = kwargs['proposed']
        if 'progress' not in kwargs:
            self.progress = {FUNDEE_SIGNED: None, FUNDEE_ACKED: None, FUNDER_SIGNED: None, COMMITTED: None}
        else:
            self.progress = {FeeUpdateProgress[x.partition('.')[2]]: y for x,y in kwargs['progress'].items()}
        self.chan = chan

    @property
    def height(self):
        return self.chan.current_height[LOCAL if self.chan.constraints.is_initiator else REMOTE]

    def set(self, field):
        self.progress[field] = self.height

    def is_proposed(self):
        return self.progress[COMMITTED] is None and self.proposed is not None and self.proposed <= self.height

    def had(self, field):
        return self.progress[field] is not None and self.height >= self.progress[field]

    def pending_feerate(self, subject):
        if not self.is_proposed():
            return
        if self.had(FUNDEE_ACKED):
            return self.rate
        if subject == REMOTE and self.chan.constraints.is_initiator:
            return self.rate
        if subject == LOCAL and not self.chan.constraints.is_initiator:
            return self.rate

    def to_save(self):
        return {'rate': self.rate, 'proposed': self.proposed, 'progress': self.progress}

class UpdateAddHtlc(namedtuple('UpdateAddHtlc', ['amount_msat', 'payment_hash', 'cltv_expiry', 'settled', 'locked_in', 'htlc_id'])):
    __slots__ = ()
    def __new__(cls, *args, **kwargs):
        if len(args) > 0:
            args = list(args)
            if type(args[1]) is str:
                args[1] = bfh(args[1])
            args[3] = {HTLCOwner(int(x)): y for x,y in args[3].items()}
            args[4] = {HTLCOwner(int(x)): y for x,y in args[4].items()}
            return super().__new__(cls, *args)
        if type(kwargs['payment_hash']) is str:
            kwargs['payment_hash'] = bfh(kwargs['payment_hash'])
        if 'locked_in' not in kwargs:
            kwargs['locked_in'] = {LOCAL: None, REMOTE: None}
        else:
            kwargs['locked_in'] = {HTLCOwner(int(x)): y for x,y in kwargs['locked_in']}
        if 'settled' not in kwargs:
            kwargs['settled'] = {LOCAL: None, REMOTE: None}
        else:
            kwargs['settled'] = {HTLCOwner(int(x)): y for x,y in kwargs['settled']}
        return super().__new__(cls, **kwargs)

is_key = lambda k: k.endswith("_basepoint") or k.endswith("_key")

def maybeDecode(k, v):
    assert type(v) is not list
    if k in ["node_id", "channel_id", "short_channel_id", "pubkey", "privkey", "current_per_commitment_point", "next_per_commitment_point", "per_commitment_secret_seed", "current_commitment_signature", "current_htlc_signatures"] and v is not None:
        return binascii.unhexlify(v)
    return v

def decodeAll(v):
    return {i: maybeDecode(i, j) for i, j in v.items()} if isinstance(v, dict) else v

def typeWrap(k, v, local):
    if is_key(k):
        if local:
            return Keypair(**v)
        else:
            return OnlyPubkeyKeypair(**v)
    return v

class HTLCStateMachine(PrintError):
    def lookup_htlc(self, log, htlc_id):
        assert type(htlc_id) is int
        for htlc in log:
            if type(htlc) is not UpdateAddHtlc: continue
            if htlc.htlc_id == htlc_id:
                return htlc
        assert False, self.diagnostic_name() + ": htlc_id {} not found in {}".format(htlc_id, log)

    def diagnostic_name(self):
        return str(self.name)

    def __init__(self, state, name = None):
        self.local_config = state["local_config"]
        if type(self.local_config) is not ChannelConfig:
            new_local_config = {k: typeWrap(k, decodeAll(v), True) for k, v in self.local_config.items()}
            self.local_config = ChannelConfig(**new_local_config)

        self.remote_config = state["remote_config"]
        if type(self.remote_config) is not ChannelConfig:
            new_remote_config = {k: typeWrap(k, decodeAll(v), False) for k, v in self.remote_config.items()}
            self.remote_config = ChannelConfig(**new_remote_config)

        self.local_state = state["local_state"]
        if type(self.local_state) is not LocalState:
            self.local_state = LocalState(**decodeAll(self.local_state))

        self.remote_state = state["remote_state"]
        if type(self.remote_state) is not RemoteState:
            self.remote_state = RemoteState(**decodeAll(self.remote_state))

        if type(self.remote_state.revocation_store) is not RevocationStore:
            self.remote_state = self.remote_state._replace(revocation_store = RevocationStore.from_json_obj(self.remote_state.revocation_store))

        self.channel_id = maybeDecode("channel_id", state["channel_id"]) if type(state["channel_id"]) is not bytes else state["channel_id"]
        self.constraints = ChannelConstraints(**decodeAll(state["constraints"])) if type(state["constraints"]) is not ChannelConstraints else state["constraints"]
        self.funding_outpoint = Outpoint(**decodeAll(state["funding_outpoint"])) if type(state["funding_outpoint"]) is not Outpoint else state["funding_outpoint"]
        self.node_id = maybeDecode("node_id", state["node_id"]) if type(state["node_id"]) is not bytes else state["node_id"]
        self.short_channel_id = maybeDecode("short_channel_id", state["short_channel_id"]) if type(state["short_channel_id"]) is not bytes else state["short_channel_id"]

        # FIXME this is a tx serialised in the custom electrum partial tx format.
        # we should not persist txns in this format. we should persist htlcs, and be able to derive
        # any past commitment transaction and use that instead; until then...
        self.remote_commitment_to_be_revoked = Transaction(state["remote_commitment_to_be_revoked"])

        self.log = {LOCAL: [], REMOTE: []}
        for strname, subject in [('remote_log', REMOTE), ('local_log', LOCAL)]:
            if strname not in state: continue
            for typ,y in state[strname]:
                if typ == "UpdateAddHtlc":
                    self.log[subject].append(UpdateAddHtlc(*decodeAll(y)))
                elif typ == "SettleHtlc":
                    self.log[subject].append(SettleHtlc(*decodeAll(y)))
                else:
                    assert False

        self.name = name

        self.fee_mgr = []
        if 'fee_updates' in state:
            for y in state['fee_updates']:
                self.fee_mgr.append(FeeUpdate(self, **y))

        self.local_commitment = self.pending_local_commitment
        self.remote_commitment = self.pending_remote_commitment

        self._is_funding_txo_spent = None  # "don't know"
        self.set_state('DISCONNECTED')

        self.lnwatcher = None

    def set_state(self, state: str):
        self._state = state

    def get_state(self):
        return self._state

    def set_funding_txo_spentness(self, is_spent: bool):
        assert isinstance(is_spent, bool)
        self._is_funding_txo_spent = is_spent

    def should_try_to_reestablish_peer(self) -> bool:
        return self._is_funding_txo_spent is False and self._state == 'DISCONNECTED'

    def get_funding_address(self):
        script = funding_output_script(self.local_config, self.remote_config)
        return redeem_script_to_address('p2wsh', script)

    def add_htlc(self, htlc):
        """
        AddHTLC adds an HTLC to the state machine's local update log. This method
        should be called when preparing to send an outgoing HTLC.
        """
        assert type(htlc) is dict
        htlc = UpdateAddHtlc(**htlc, htlc_id=self.local_state.next_htlc_id)
        self.log[LOCAL].append(htlc)
        self.print_error("add_htlc")
        self.local_state=self.local_state._replace(next_htlc_id=htlc.htlc_id + 1)
        return htlc.htlc_id

    def receive_htlc(self, htlc):
        """
        ReceiveHTLC adds an HTLC to the state machine's remote update log. This
        method should be called in response to receiving a new HTLC from the remote
        party.
        """
        assert type(htlc) is dict
        htlc = UpdateAddHtlc(**htlc, htlc_id = self.remote_state.next_htlc_id)
        self.log[REMOTE].append(htlc)
        self.print_error("receive_htlc")
        self.remote_state=self.remote_state._replace(next_htlc_id=htlc.htlc_id + 1)
        return htlc.htlc_id

    def sign_next_commitment(self):
        """
        SignNextCommitment signs a new commitment which includes any previous
        unsettled HTLCs, any new HTLCs, and any modifications to prior HTLCs
        committed in previous commitment updates. Signing a new commitment
        decrements the available revocation window by 1. After a successful method
        call, the remote party's commitment chain is extended by a new commitment
        which includes all updates to the HTLC log prior to this method invocation.
        The first return parameter is the signature for the commitment transaction
        itself, while the second parameter is a slice of all HTLC signatures (if
        any). The HTLC signatures are sorted according to the BIP 69 order of the
        HTLC's on the commitment transaction.
        """
        for htlc in self.log[LOCAL]:
            if not type(htlc) is UpdateAddHtlc: continue
            if htlc.locked_in[LOCAL] is None: htlc.locked_in[LOCAL] = self.local_state.ctn
        self.print_error("sign_next_commitment")

        pending_remote_commitment = self.pending_remote_commitment
        sig_64 = sign_and_get_sig_string(pending_remote_commitment, self.local_config, self.remote_config)

        their_remote_htlc_privkey_number = derive_privkey(
            int.from_bytes(self.local_config.htlc_basepoint.privkey, 'big'),
            self.remote_state.next_per_commitment_point)
        their_remote_htlc_privkey = their_remote_htlc_privkey_number.to_bytes(32, 'big')

        for_us = False

        feerate = self.pending_feerate(REMOTE)

        htlcsigs = []
        for we_receive, htlcs in zip([True, False], [self.htlcs_in_remote, self.htlcs_in_local]):
            assert len(htlcs) <= 1
            for htlc in htlcs:
                weight = HTLC_SUCCESS_WEIGHT if we_receive else HTLC_TIMEOUT_WEIGHT
                fee = feerate // 1000 * weight
                if htlc.amount_msat // 1000 < self.remote_config.dust_limit_sat + fee:
                    print("value too small, skipping. htlc amt: {}, weight: {}, remote feerate {}, remote dust limit {}".format( htlc.amount_msat, weight, feerate, self.remote_config.dust_limit_sat))
                    continue
                original_htlc_output_index = 0
                args = [self.remote_state.next_per_commitment_point, for_us, we_receive, htlc.amount_msat, htlc.cltv_expiry, htlc.payment_hash, pending_remote_commitment, original_htlc_output_index]
                htlc_tx = make_htlc_tx_with_open_channel(self, *args)
                sig = bfh(htlc_tx.sign_txin(0, their_remote_htlc_privkey))
                htlc_sig = ecc.sig_string_from_der_sig(sig[:-1])
                htlcsigs.append(htlc_sig)

        for pending_fee in self.fee_mgr:
            if pending_fee.is_proposed():
                if not self.constraints.is_initiator:
                    pending_fee.set(FUNDEE_SIGNED)
                if self.constraints.is_initiator and pending_fee.had(FUNDEE_ACKED):
                    pending_fee.set(FUNDER_SIGNED)

        if self.lnwatcher:
            self.lnwatcher.process_new_offchain_ctx(self, pending_remote_commitment, ours=False)

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
        """

        self.print_error("receive_new_commitment")
        for htlc in self.log[REMOTE]:
            if not type(htlc) is UpdateAddHtlc: continue
            if htlc.locked_in[REMOTE] is None: htlc.locked_in[REMOTE] = self.remote_state.ctn
        assert len(htlc_sigs) == 0 or type(htlc_sigs[0]) is bytes

        pending_local_commitment = self.pending_local_commitment
        preimage_hex = pending_local_commitment.serialize_preimage(0)
        pre_hash = Hash(bfh(preimage_hex))
        if not ecc.verify_signature(self.remote_config.multisig_key.pubkey, sig, pre_hash):
            raise Exception('failed verifying signature of our updated commitment transaction: ' + bh2u(sig) + ' preimage is ' + preimage_hex)

        _, this_point, _ = self.points

        if len(pending_local_commitment.outputs()) >= 3:
            print("CHECKING HTLC SIGS")
            assert len(pending_local_commitment.outputs()) == 3
            if len(self.htlcs_in_remote) > 0:
                assert len(self.htlcs_in_remote) == 1
                we_receive = True
                htlc = self.htlcs_in_remote[0]
            elif len(self.htlcs_in_local) > 0:
                assert len(self.htlcs_in_local) == 1
                we_receive = False
                htlc = self.htlcs_in_local[0]
            else:
                assert False

            htlc_tx = make_htlc_tx_with_open_channel(self, this_point, True, we_receive, htlc.amount_msat, htlc.cltv_expiry, htlc.payment_hash, pending_local_commitment, 0)
            pre_hash = Hash(bfh(htlc_tx.serialize_preimage(0)))
            remote_htlc_pubkey = derive_pubkey(self.remote_config.htlc_basepoint.pubkey, this_point)
            if not ecc.verify_signature(remote_htlc_pubkey, htlc_sigs[0], pre_hash):
                raise Exception("failed verifying signature an HTLC tx spending from one of our commit tx'es HTLC outputs")

        # TODO check htlc in htlcs_in_local

        for pending_fee in self.fee_mgr:
            if pending_fee.is_proposed():
                if not self.constraints.is_initiator:
                    pending_fee.set(FUNDEE_SIGNED)
                if self.constraints.is_initiator and pending_fee.had(FUNDEE_ACKED):
                    pending_fee.set(FUNDER_SIGNED)

        if self.lnwatcher:
            self.lnwatcher.process_new_offchain_ctx(self, pending_local_commitment, ours=True)


    def revoke_current_commitment(self):
        """
        RevokeCurrentCommitment revokes the next lowest unrevoked commitment
        transaction in the local commitment chain. As a result the edge of our
        revocation window is extended by one, and the tail of our local commitment
        chain is advanced by a single commitment. This now lowest unrevoked
        commitment becomes our currently accepted state within the channel. This
        method also returns the set of HTLC's currently active within the commitment
        transaction. This return value allows callers to act once an HTLC has been
        locked into our commitment transaction.
        """
        self.print_error("revoke_current_commitment")

        last_secret, this_point, next_point = self.points

        new_local_feerate = self.local_state.feerate
        new_remote_feerate = self.remote_state.feerate

        for pending_fee in self.fee_mgr:
            if not self.constraints.is_initiator and pending_fee.had(FUNDEE_SIGNED):
                new_local_feerate = new_remote_feerate = pending_fee.rate
                pending_fee.set(COMMITTED)
                print("FEERATE CHANGE COMPLETE (non-initiator)")
            if self.constraints.is_initiator and pending_fee.had(FUNDER_SIGNED):
                new_local_feerate = new_remote_feerate = pending_fee.rate
                pending_fee.set(COMMITTED)
                print("FEERATE CHANGE COMPLETE (initiator)")

        self.local_state=self.local_state._replace(
            ctn=self.local_state.ctn + 1,
            feerate=new_local_feerate
        )
        self.remote_state=self.remote_state._replace(
            feerate=new_remote_feerate
        )

        self.local_commitment = self.pending_local_commitment

        return RevokeAndAck(last_secret, next_point), "current htlcs"

    @property
    def points(self):
        last_small_num = self.local_state.ctn
        this_small_num = last_small_num + 1
        next_small_num = last_small_num + 2
        last_secret = get_per_commitment_secret_from_seed(self.local_state.per_commitment_secret_seed, RevocationStore.START_INDEX - last_small_num)
        this_secret = get_per_commitment_secret_from_seed(self.local_state.per_commitment_secret_seed, RevocationStore.START_INDEX - this_small_num)
        this_point = secret_to_pubkey(int.from_bytes(this_secret, 'big'))
        next_secret = get_per_commitment_secret_from_seed(self.local_state.per_commitment_secret_seed, RevocationStore.START_INDEX - next_small_num)
        next_point = secret_to_pubkey(int.from_bytes(next_secret, 'big'))
        return last_secret, this_point, next_point

    def receive_revocation(self, revocation):
        """
        ReceiveRevocation processes a revocation sent by the remote party for the
        lowest unrevoked commitment within their commitment chain. We receive a
        revocation either during the initial session negotiation wherein revocation
        windows are extended, or in response to a state update that we initiate. If
        successful, then the remote commitment chain is advanced by a single
        commitment, and a log compaction is attempted.

        Returns the forwarding package corresponding to the remote commitment height
        that was revoked.
        """
        self.print_error("receive_revocation")

        cur_point = self.remote_state.current_per_commitment_point
        derived_point = ecc.ECPrivkey(revocation.per_commitment_secret).get_public_key_bytes(compressed=True)
        if cur_point != derived_point:
            raise Exception('revoked secret not for current point')

        # FIXME not sure this is correct... but it seems to work
        # if there are update_add_htlc msgs between commitment_signed and rev_ack,
        # this might break
        prev_remote_commitment = self.pending_remote_commitment

        self.remote_state.revocation_store.add_next_entry(revocation.per_commitment_secret)
        if self.lnwatcher:
            self.lnwatcher.process_new_revocation_secret(self, revocation.per_commitment_secret)

        def mark_settled(subject):
            """
            find settled htlcs for subject (LOCAL or REMOTE) and mark them settled, return value of settled htlcs
            """
            old_amount = self.htlcsum(self.gen_htlc_indices(subject, False))

            for x in self.log[-subject]:
                if type(x) is not SettleHtlc: continue
                htlc = self.lookup_htlc(self.log[subject], x.htlc_id)
                htlc.settled[subject] = self.current_height[subject]

            return old_amount - self.htlcsum(self.gen_htlc_indices(subject, False))

        sent_this_batch = mark_settled(LOCAL)
        received_this_batch = mark_settled(REMOTE)

        next_point = self.remote_state.next_per_commitment_point

        print("RECEIVED", received_this_batch)
        print("SENT", sent_this_batch)
        self.remote_state=self.remote_state._replace(
            ctn=self.remote_state.ctn + 1,
            current_per_commitment_point=next_point,
            next_per_commitment_point=revocation.next_per_commitment_point,
            amount_msat=self.remote_state.amount_msat + (sent_this_batch - received_this_batch)
        )
        self.local_state=self.local_state._replace(
            amount_msat = self.local_state.amount_msat + (received_this_batch - sent_this_batch)
        )

        for pending_fee in self.fee_mgr:
            if pending_fee.is_proposed():
                if self.constraints.is_initiator:
                    pending_fee.set(FUNDEE_ACKED)

        self.local_commitment = self.pending_local_commitment
        self.remote_commitment = self.pending_remote_commitment
        self.remote_commitment_to_be_revoked = prev_remote_commitment
        return received_this_batch, sent_this_batch

    def balance(self, subject):
        initial = self.local_config.initial_msat if subject == LOCAL else self.remote_config.initial_msat

        for x in self.log[-subject]:
            if type(x) is not SettleHtlc: continue
            htlc = self.lookup_htlc(self.log[subject], x.htlc_id)
            htlc_height = htlc.settled[subject]
            if htlc_height is not None and htlc_height <= self.current_height[subject]:
                initial -= htlc.amount_msat

        for x in self.log[subject]:
            if type(x) is not SettleHtlc: continue
            htlc = self.lookup_htlc(self.log[-subject], x.htlc_id)
            htlc_height = htlc.settled[-subject]
            if htlc_height is not None and htlc_height <= self.current_height[-subject]:
                initial += htlc.amount_msat

        assert initial == (self.local_state.amount_msat if subject == LOCAL else self.remote_state.amount_msat)
        return initial

    @staticmethod
    def htlcsum(htlcs):
        amount_unsettled = 0
        for x in htlcs:
            amount_unsettled += x.amount_msat
        return amount_unsettled

    def amounts(self):
        remote_settled= self.htlcsum(self.gen_htlc_indices(REMOTE, False))
        local_settled= self.htlcsum(self.gen_htlc_indices(LOCAL, False))
        unsettled_local = self.htlcsum(self.gen_htlc_indices(LOCAL, True))
        unsettled_remote = self.htlcsum(self.gen_htlc_indices(REMOTE, True))
        remote_msat = self.remote_state.amount_msat -\
          unsettled_remote + local_settled - remote_settled
        local_msat = self.local_state.amount_msat -\
          unsettled_local + remote_settled - local_settled
        return remote_msat, local_msat

    @property
    def pending_remote_commitment(self):
        remote_msat, local_msat = self.amounts()
        assert local_msat >= 0
        assert remote_msat >= 0

        this_point = self.remote_state.next_per_commitment_point

        remote_htlc_pubkey = derive_pubkey(self.remote_config.htlc_basepoint.pubkey, this_point)
        local_htlc_pubkey = derive_pubkey(self.local_config.htlc_basepoint.pubkey, this_point)
        local_revocation_pubkey = derive_blinded_pubkey(self.local_config.revocation_basepoint.pubkey, this_point)

        feerate = self.pending_feerate(REMOTE)

        htlcs_in_local = []
        for htlc in self.htlcs_in_local:
            if htlc.amount_msat // 1000 - HTLC_SUCCESS_WEIGHT * (feerate // 1000) < self.remote_config.dust_limit_sat:
                continue
            htlcs_in_local.append(
                ( make_received_htlc(local_revocation_pubkey, local_htlc_pubkey, remote_htlc_pubkey, htlc.payment_hash, htlc.cltv_expiry), htlc.amount_msat))

        htlcs_in_remote = []
        for htlc in self.htlcs_in_remote:
            if htlc.amount_msat // 1000 - HTLC_TIMEOUT_WEIGHT * (feerate // 1000) < self.remote_config.dust_limit_sat:
                continue
            htlcs_in_remote.append(
                ( make_offered_htlc(local_revocation_pubkey, local_htlc_pubkey, remote_htlc_pubkey, htlc.payment_hash), htlc.amount_msat))

        commit = self.make_commitment(self.remote_state.ctn + 1,
            False, this_point,
            remote_msat, local_msat, htlcs_in_local + htlcs_in_remote)
        return commit

    def pending_feerate(self, subject):
        candidate = None
        for pending_fee in self.fee_mgr:
            x = pending_fee.pending_feerate(subject)
            if x is not None:
                candidate = x

        feerate = candidate if candidate is not None else self._committed_feerate[subject]
        return feerate

    @property
    def _committed_feerate(self):
        return {LOCAL: self.local_state.feerate, REMOTE: self.remote_state.feerate}

    @property
    def pending_local_commitment(self):
        remote_msat, local_msat = self.amounts()
        assert local_msat >= 0
        assert remote_msat >= 0

        _, this_point, _ = self.points

        remote_htlc_pubkey = derive_pubkey(self.remote_config.htlc_basepoint.pubkey, this_point)
        local_htlc_pubkey = derive_pubkey(self.local_config.htlc_basepoint.pubkey, this_point)
        remote_revocation_pubkey = derive_blinded_pubkey(self.remote_config.revocation_basepoint.pubkey, this_point)

        feerate = self.pending_feerate(LOCAL)

        htlcs_in_local = []
        for htlc in self.htlcs_in_local:
            if htlc.amount_msat // 1000 - HTLC_TIMEOUT_WEIGHT * (feerate // 1000) < self.local_config.dust_limit_sat:
                continue
            htlcs_in_local.append(
                ( make_offered_htlc(remote_revocation_pubkey, remote_htlc_pubkey, local_htlc_pubkey, htlc.payment_hash), htlc.amount_msat))

        htlcs_in_remote = []
        for htlc in self.htlcs_in_remote:
            if htlc.amount_msat // 1000 - HTLC_SUCCESS_WEIGHT * (feerate // 1000) < self.local_config.dust_limit_sat:
                continue
            htlcs_in_remote.append(
                ( make_received_htlc(remote_revocation_pubkey, remote_htlc_pubkey, local_htlc_pubkey, htlc.payment_hash, htlc.cltv_expiry), htlc.amount_msat))

        commit = self.make_commitment(self.local_state.ctn + 1,
            True, this_point,
            local_msat, remote_msat, htlcs_in_local + htlcs_in_remote)
        return commit

    @property
    def total_msat(self):
        return {LOCAL: self.htlcsum(self.gen_htlc_indices(LOCAL, False, True)), REMOTE: self.htlcsum(self.gen_htlc_indices(REMOTE, False, True))}

    def gen_htlc_indices(self, subject, only_pending, include_settled=False):
        """
        only_pending: require the htlc's settlement to be pending (needs additional signatures/acks)
        include_settled: include settled (totally done with) htlcs
        """
        update_log = self.log[subject]
        other_log = self.log[-subject]
        res = []
        for htlc in update_log:
            if type(htlc) is not UpdateAddHtlc:
                continue
            height = self.current_height[-subject]
            locked_in = htlc.locked_in[subject]

            if locked_in is None or only_pending == (SettleHtlc(htlc.htlc_id) in other_log):
                continue

            settled_cutoff = self.local_state.ctn if subject == LOCAL else self.remote_state.ctn

            if not include_settled and htlc.settled[subject] is not None and settled_cutoff >= htlc.settled[subject]:
                continue

            res.append(htlc)
        return res

    @property
    def htlcs_in_local(self):
        """in the local log. 'offered by us'"""
        return self.gen_htlc_indices(LOCAL, True)

    @property
    def htlcs_in_remote(self):
        """in the remote log. 'offered by them'"""
        return self.gen_htlc_indices(REMOTE, True)

    def settle_htlc(self, preimage, htlc_id):
        """
        SettleHTLC attempts to settle an existing outstanding received HTLC.
        """
        self.print_error("settle_htlc")
        htlc = self.lookup_htlc(self.log[REMOTE], htlc_id)
        assert htlc.payment_hash == sha256(preimage)
        self.log[LOCAL].append(SettleHtlc(htlc_id))

    def receive_htlc_settle(self, preimage, htlc_index):
        self.print_error("receive_htlc_settle")
        htlc = self.lookup_htlc(self.log[LOCAL], htlc_index)
        assert htlc.payment_hash == sha256(preimage)
        assert len([x for x in self.log[LOCAL] if x.htlc_id == htlc_index and type(x) is UpdateAddHtlc]) == 1, (self.log[LOCAL], htlc_index)
        self.log[REMOTE].append(SettleHtlc(htlc_index))

    def fail_htlc(self, htlc):
        # TODO
        self.log[LOCAL] = []
        self.log[REMOTE] = []
        self.print_error("fail_htlc (EMPTIED LOGS)")

    @property
    def current_height(self):
        return {LOCAL: self.local_state.ctn, REMOTE: self.remote_state.ctn}

    @property
    def pending_local_fee(self):
        return self.constraints.capacity - sum(x[2] for x in self.pending_local_commitment.outputs())

    def update_fee(self, feerate):
        if not self.constraints.is_initiator:
            raise Exception("only initiator can update_fee, this counterparty is not initiator")
        pending_fee = FeeUpdate(self, rate=feerate)
        self.fee_mgr.append(pending_fee)

    def receive_update_fee(self, feerate):
        if self.constraints.is_initiator:
            raise Exception("only the non-initiator can receive_update_fee, this counterparty is initiator")
        pending_fee = FeeUpdate(self, rate=feerate)
        self.fee_mgr.append(pending_fee)

    def to_save(self):
        return {
                "local_config": self.local_config,
                "remote_config": self.remote_config,
                "local_state": self.local_state,
                "remote_state": self.remote_state,
                "channel_id": self.channel_id,
                "short_channel_id": self.short_channel_id,
                "constraints": self.constraints,
                "funding_outpoint": self.funding_outpoint,
                "node_id": self.node_id,
                "remote_commitment_to_be_revoked": str(self.remote_commitment_to_be_revoked),
                "remote_log": [(type(x).__name__, x) for x in self.log[REMOTE]],
                "local_log": [(type(x).__name__, x) for x in self.log[LOCAL]],
                "fee_updates": [x.to_save() for x in self.fee_mgr],
        }

    def serialize(self):
        namedtuples_to_dict = lambda v: {i: j._asdict() if isinstance(j, tuple) else j for i, j in v._asdict().items()}
        serialized_channel = {k: namedtuples_to_dict(v) if isinstance(v, tuple) else v for k, v in self.to_save().items()}
        class MyJsonEncoder(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, bytes):
                    return binascii.hexlify(o).decode("ascii")
                if isinstance(o, RevocationStore):
                    return o.serialize()
                if isinstance(o, SettleHtlc):
                    return json.dumps(('SettleHtlc', namedtuples_to_dict(o)))
                if isinstance(o, UpdateAddHtlc):
                    return json.dumps(('UpdateAddHtlc', namedtuples_to_dict(o)))
                return super(MyJsonEncoder, self)
        for fee_upd in serialized_channel['fee_updates']:
            fee_upd['progress'] = {str(k): v for k,v in fee_upd['progress'].items()}
        dumped = MyJsonEncoder().encode(serialized_channel)
        roundtripped = json.loads(dumped)
        reconstructed = HTLCStateMachine(roundtripped)
        if reconstructed.to_save() != self.to_save():
            raise Exception("Channels did not roundtrip serialization without changes:\n" + repr(reconstructed.to_save()) + "\n" + repr(self.to_save()))
        return roundtripped

    def __str__(self):
        return self.serialize()

    def make_commitment(chan, ctn, for_us, pcp, local_msat, remote_msat, htlcs=[]):
        conf = chan.local_config if for_us else chan.remote_config
        other_conf = chan.local_config if not for_us else chan.remote_config
        payment_pubkey = derive_pubkey(other_conf.payment_basepoint.pubkey, pcp)
        remote_revocation_pubkey = derive_blinded_pubkey(other_conf.revocation_basepoint.pubkey, pcp)
        return make_commitment(
            ctn,
            conf.multisig_key.pubkey,
            other_conf.multisig_key.pubkey,
            payment_pubkey,
            chan.local_config.payment_basepoint.pubkey,
            chan.remote_config.payment_basepoint.pubkey,
            remote_revocation_pubkey,
            derive_pubkey(conf.delayed_basepoint.pubkey, pcp),
            other_conf.to_self_delay,
            *chan.funding_outpoint,
            chan.constraints.capacity,
            local_msat,
            remote_msat,
            conf.dust_limit_sat,
            chan.pending_feerate(LOCAL if for_us else REMOTE),
            for_us,
            chan.constraints.is_initiator,
            htlcs=htlcs)

    def make_closing_tx(self, local_script: bytes, remote_script: bytes, fee_sat: Optional[int] = None) -> (bytes, int):
        if fee_sat is None:
            fee_sat = self.pending_local_fee

        _, outputs = make_outputs(fee_sat * 1000, True,
                self.local_state.amount_msat,
                self.remote_state.amount_msat,
                (TYPE_SCRIPT, bh2u(local_script)),
                (TYPE_SCRIPT, bh2u(remote_script)),
                [], self.local_config.dust_limit_sat)

        closing_tx = make_closing_tx(self.local_config.multisig_key.pubkey,
                self.remote_config.multisig_key.pubkey,
                self.local_config.payment_basepoint.pubkey,
                self.remote_config.payment_basepoint.pubkey,
                # TODO hardcoded we_are_initiator:
                True, *self.funding_outpoint, self.constraints.capacity,
                outputs)

        der_sig = bfh(closing_tx.sign_txin(0, self.local_config.multisig_key.privkey))
        sig = ecc.sig_string_from_der_sig(der_sig[:-1])
        return sig, fee_sat
