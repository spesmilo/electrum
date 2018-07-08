# ported from lnd 42de4400bff5105352d0552155f73589166d162b
from collections import namedtuple
import binascii
import json
from .util import bfh, PrintError
from .bitcoin import Hash
from .crypto import sha256
from . import ecc
from .lnutil import Outpoint, ChannelConfig, LocalState, RemoteState, Keypair, OnlyPubkeyKeypair, ChannelConstraints, RevocationStore
from .lnutil import get_per_commitment_secret_from_seed
from .lnutil import secret_to_pubkey, derive_privkey, derive_pubkey, derive_blinded_pubkey
from .lnutil import sign_and_get_sig_string
from .lnutil import make_htlc_tx_with_open_channel, make_commitment, make_received_htlc, make_offered_htlc
from .lnutil import HTLC_TIMEOUT_WEIGHT, HTLC_SUCCESS_WEIGHT
from contextlib import contextmanager

SettleHtlc = namedtuple("SettleHtlc", ["htlc_id"])
RevokeAndAck = namedtuple("RevokeAndAck", ["per_commitment_secret", "next_per_commitment_point"])

@contextmanager
def PendingFeerateApplied(machine):
    old_local_state = machine.local_state
    old_remote_state = machine.remote_state

    new_local_feerate = machine.local_state.feerate
    new_remote_feerate = machine.remote_state.feerate

    if machine.constraints.is_initiator:
        if machine.pending_fee_update is not None:
            new_remote_feerate = machine.pending_fee_update
        if machine.pending_ack_fee_update is not None:
            new_local_feerate = machine.pending_ack_fee_update
    else:
        if machine.pending_fee_update is not None:
            new_local_feerate = machine.pending_fee_update
        if machine.pending_ack_fee_update is not None:
            new_remote_feerate = machine.pending_ack_fee_update

    machine.local_state = machine.local_state._replace(feerate=new_local_feerate)
    machine.remote_state = machine.remote_state._replace(feerate=new_remote_feerate)
    yield
    machine.local_state = old_local_state._replace(feerate=old_local_state.feerate)
    machine.remote_state = old_remote_state._replace(feerate=old_remote_state.feerate)

class UpdateAddHtlc:
    def __init__(self, amount_msat, payment_hash, cltv_expiry, total_fee):
        self.amount_msat = amount_msat
        self.payment_hash = payment_hash
        self.cltv_expiry = cltv_expiry
        self.total_fee = total_fee

        # the height the htlc was locked in at, or None
        self.r_locked_in = None
        self.l_locked_in = None

        self.htlc_id = None

    def as_tuple(self):
        return (self.htlc_id, self.amount_msat, self.payment_hash, self.cltv_expiry, self.r_locked_in, self.l_locked_in, self.total_fee)

    def __hash__(self):
        return hash(self.as_tuple())

    def __eq__(self, o):
        return type(o) is UpdateAddHtlc and self.as_tuple() == o.as_tuple()

    def __repr__(self):
        return "UpdateAddHtlc" + str(self.as_tuple())

is_key = lambda k: k.endswith("_basepoint") or k.endswith("_key")

def maybeDecode(k, v):
    assert type(v) is not list
    if k in ["node_id", "channel_id", "short_channel_id", "pubkey", "privkey", "current_per_commitment_point", "next_per_commitment_point", "per_commitment_secret_seed", "current_commitment_signature"] and v is not None:
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

        self.local_update_log = []
        self.remote_update_log = []

        self.name = name

        self.total_msat_sent = 0
        self.total_msat_received = 0
        self.pending_fee_update = None
        self.pending_ack_fee_update = None

        self.local_commitment = self.pending_local_commitment
        self.remote_commitment = self.pending_remote_commitment

    def add_htlc(self, htlc):
        """
        AddHTLC adds an HTLC to the state machine's local update log. This method
        should be called when preparing to send an outgoing HTLC.
        """
        assert type(htlc) is UpdateAddHtlc
        self.local_update_log.append(htlc)
        self.print_error("add_htlc")
        htlc_id = self.local_state.next_htlc_id
        self.local_state=self.local_state._replace(next_htlc_id=htlc_id + 1)
        htlc.htlc_id = htlc_id
        return htlc_id

    def receive_htlc(self, htlc):
        """
        ReceiveHTLC adds an HTLC to the state machine's remote update log. This
        method should be called in response to receiving a new HTLC from the remote
        party.
        """
        self.print_error("receive_htlc")
        assert type(htlc) is UpdateAddHtlc
        self.remote_update_log.append(htlc)
        htlc_id = self.remote_state.next_htlc_id
        self.remote_state=self.remote_state._replace(next_htlc_id=htlc_id + 1)
        htlc.htlc_id = htlc_id
        return htlc_id

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
        for htlc in self.local_update_log:
            if not type(htlc) is UpdateAddHtlc: continue
            if htlc.l_locked_in is None: htlc.l_locked_in = self.local_state.ctn
        self.print_error("sign_next_commitment")

        if self.constraints.is_initiator and self.pending_fee_update:
            self.pending_ack_fee_update = self.pending_fee_update
            self.pending_fee_update = None

        with PendingFeerateApplied(self):
            sig_64 = sign_and_get_sig_string(self.pending_remote_commitment, self.local_config, self.remote_config)

            their_remote_htlc_privkey_number = derive_privkey(
                int.from_bytes(self.local_config.htlc_basepoint.privkey, 'big'),
                self.remote_state.next_per_commitment_point)
            their_remote_htlc_privkey = their_remote_htlc_privkey_number.to_bytes(32, 'big')

            for_us = False

            htlcsigs = []
            for we_receive, htlcs in zip([True, False], [self.htlcs_in_remote, self.htlcs_in_local]):
                assert len(htlcs) <= 1
                for htlc in htlcs:
                    weight = HTLC_SUCCESS_WEIGHT if we_receive else HTLC_TIMEOUT_WEIGHT
                    fee = self.remote_state.feerate // 1000 * weight
                    if htlc.amount_msat // 1000 < self.remote_config.dust_limit_sat + fee:
                        print("value too small, skipping. htlc amt: {}, weight: {}, remote feerate {}, remote dust limit {}".format( htlc.amount_msat, weight, self.remote_state.feerate, self.remote_config.dust_limit_sat))
                        continue
                    original_htlc_output_index = 0
                    args = [self.remote_state.next_per_commitment_point, for_us, we_receive, htlc.amount_msat + htlc.total_fee, htlc.cltv_expiry, htlc.payment_hash, self.pending_remote_commitment, original_htlc_output_index]
                    htlc_tx = make_htlc_tx_with_open_channel(self, *args)
                    sig = bfh(htlc_tx.sign_txin(0, their_remote_htlc_privkey))
                    htlc_sig = ecc.sig_string_from_der_sig(sig[:-1])
                    htlcsigs.append(htlc_sig)

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
        for htlc in self.remote_update_log:
            if not type(htlc) is UpdateAddHtlc: continue
            if htlc.r_locked_in is None: htlc.r_locked_in = self.remote_state.ctn
        assert len(htlc_sigs) == 0 or type(htlc_sigs[0]) is bytes

        if not self.constraints.is_initiator:
            self.pending_ack_fee_update = self.pending_fee_update
            self.pending_fee_update = None

        with PendingFeerateApplied(self):
            preimage_hex = self.pending_local_commitment.serialize_preimage(0)
            pre_hash = Hash(bfh(preimage_hex))
            if not ecc.verify_signature(self.remote_config.multisig_key.pubkey, sig, pre_hash):
                raise Exception('failed verifying signature of our updated commitment transaction: ' + str(sig))

            _, this_point, _ = self.points

            if len(self.htlcs_in_remote) > 0 and len(self.pending_local_commitment.outputs()) == 3:
                print("CHECKING HTLC SIGS")
                we_receive = True
                payment_hash = self.htlcs_in_remote[0].payment_hash
                amount_msat = self.htlcs_in_remote[0].amount_msat
                cltv_expiry = self.htlcs_in_remote[0].cltv_expiry
                htlc_tx = make_htlc_tx_with_open_channel(self, this_point, True, we_receive, amount_msat, cltv_expiry, payment_hash, self.pending_local_commitment, 0)
                pre_hash = Hash(bfh(htlc_tx.serialize_preimage(0)))
                remote_htlc_pubkey = derive_pubkey(self.remote_config.htlc_basepoint.pubkey, this_point)
                if not ecc.verify_signature(remote_htlc_pubkey, htlc_sigs[0], pre_hash):
                    raise Exception("failed verifying signature an HTLC tx spending from one of our commit tx'es HTLC outputs")

            # TODO check htlc in htlcs_in_local

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

        new_feerate = self.local_state.feerate

        if not self.constraints.is_initiator and self.pending_fee_update is not None:
            new_feerate = self.pending_fee_update
            self.pending_fee_update = None
            self.pending_ack_fee_update = None
        elif self.pending_ack_fee_update is not None:
            new_feerate = self.pending_ack_fee_update
            self.pending_fee_update = None
            self.pending_ack_fee_update = None

        self.remote_state=self.remote_state._replace(
            feerate=new_feerate
        )

        self.local_state=self.local_state._replace(
            ctn=self.local_state.ctn + 1,
            feerate=new_feerate
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

        settle_fails2 = []
        for x in self.remote_update_log:
            if type(x) is not SettleHtlc:
                continue
            settle_fails2.append(x)

        sent_this_batch, sent_fees = 0, 0

        for x in settle_fails2:
            htlc = self.lookup_htlc(self.local_update_log, x.htlc_id)
            sent_this_batch += htlc.amount_msat
            sent_fees += htlc.total_fee

        self.total_msat_sent += sent_this_batch

        # log compaction (remove entries relating to htlc's that have been settled)

        to_remove = []
        for x in filter(lambda x: type(x) is SettleHtlc, self.remote_update_log):
            to_remove += [y for y in self.local_update_log if y.htlc_id == x.htlc_id]

        # assert that we should have compacted the log earlier
        assert len(to_remove) <= 1, to_remove
        if len(to_remove) == 1:
            self.remote_update_log = [x for x in self.remote_update_log if x.htlc_id != to_remove[0].htlc_id]
            self.local_update_log = [x for x in self.local_update_log if x.htlc_id != to_remove[0].htlc_id]

        to_remove = []
        for x in filter(lambda x: type(x) is SettleHtlc, self.local_update_log):
            to_remove += [y for y in self.remote_update_log if y.htlc_id == x.htlc_id]
        if len(to_remove) == 1:
            self.remote_update_log = [x for x in self.remote_update_log if x.htlc_id != to_remove[0].htlc_id]
            self.local_update_log = [x for x in self.local_update_log if x.htlc_id != to_remove[0].htlc_id]
        received_this_batch = sum(x.amount_msat for x in to_remove)

        self.total_msat_received += received_this_batch

        received_fees = sum(x.total_fee for x in to_remove)

        self.remote_state.revocation_store.add_next_entry(revocation.per_commitment_secret)

        next_point = self.remote_state.next_per_commitment_point

        print("RECEIVED", received_this_batch)
        print("SENT", sent_this_batch)
        self.remote_state=self.remote_state._replace(
            ctn=self.remote_state.ctn + 1,
            current_per_commitment_point=next_point,
            next_per_commitment_point=revocation.next_per_commitment_point,
            amount_msat=self.remote_state.amount_msat + (sent_this_batch - received_this_batch) + sent_fees - received_fees,
            feerate=self.pending_fee_update if self.pending_fee_update is not None else self.remote_state.feerate
        )
        self.local_state=self.local_state._replace(
            amount_msat = self.local_state.amount_msat + (received_this_batch - sent_this_batch) - sent_fees + received_fees
        )
        self.local_commitment = self.pending_local_commitment
        self.remote_commitment = self.pending_remote_commitment

    @staticmethod
    def htlcsum(htlcs):
        amount_unsettled = 0
        fee = 0
        for x in htlcs:
            amount_unsettled += x.amount_msat
            fee += x.total_fee
        return amount_unsettled, fee

    def amounts(self):
        remote_settled_value, remote_settled_fee = self.htlcsum(self.gen_htlc_indices("remote", False))
        local_settled_value, local_settled_fee = self.htlcsum(self.gen_htlc_indices("local", False))
        htlc_value_local, total_fee_local = self.htlcsum(self.htlcs_in_local)
        htlc_value_remote, total_fee_remote = self.htlcsum(self.htlcs_in_remote)
        total_fee_local += local_settled_fee
        total_fee_remote += remote_settled_fee
        local_msat = self.local_state.amount_msat -\
          htlc_value_local + remote_settled_value - local_settled_value
        remote_msat = self.remote_state.amount_msat -\
          htlc_value_remote + local_settled_value - remote_settled_value
        return remote_msat, total_fee_remote, local_msat, total_fee_local

    @property
    def pending_remote_commitment(self):
        remote_msat, total_fee_remote, local_msat, total_fee_local = self.amounts()
        assert local_msat >= 0
        assert remote_msat >= 0

        this_point = self.remote_state.next_per_commitment_point

        remote_htlc_pubkey = derive_pubkey(self.remote_config.htlc_basepoint.pubkey, this_point)
        local_htlc_pubkey = derive_pubkey(self.local_config.htlc_basepoint.pubkey, this_point)
        local_revocation_pubkey = derive_blinded_pubkey(self.local_config.revocation_basepoint.pubkey, this_point)

        with PendingFeerateApplied(self):
            htlcs_in_local = []
            for htlc in self.htlcs_in_local:
                if htlc.amount_msat // 1000 - HTLC_SUCCESS_WEIGHT * (self.remote_state.feerate // 1000) < self.remote_config.dust_limit_sat:
                    continue
                htlcs_in_local.append(
                    ( make_received_htlc(local_revocation_pubkey, local_htlc_pubkey, remote_htlc_pubkey, htlc.payment_hash, htlc.cltv_expiry), htlc.amount_msat + htlc.total_fee))

            htlcs_in_remote = []
            for htlc in self.htlcs_in_remote:
                if htlc.amount_msat // 1000 - HTLC_TIMEOUT_WEIGHT * (self.remote_state.feerate // 1000) < self.remote_config.dust_limit_sat:
                    continue
                htlcs_in_remote.append(
                    ( make_offered_htlc(local_revocation_pubkey, local_htlc_pubkey, remote_htlc_pubkey, htlc.payment_hash), htlc.amount_msat + htlc.total_fee))

            commit = self.make_commitment(self.remote_state.ctn + 1,
                False, this_point,
                remote_msat - total_fee_remote, local_msat - total_fee_local, htlcs_in_local + htlcs_in_remote)
            return commit

    @property
    def pending_local_commitment(self):
        remote_msat, total_fee_remote, local_msat, total_fee_local = self.amounts()
        assert local_msat >= 0
        assert remote_msat >= 0

        _, this_point, _ = self.points

        remote_htlc_pubkey = derive_pubkey(self.remote_config.htlc_basepoint.pubkey, this_point)
        local_htlc_pubkey = derive_pubkey(self.local_config.htlc_basepoint.pubkey, this_point)
        remote_revocation_pubkey = derive_blinded_pubkey(self.remote_config.revocation_basepoint.pubkey, this_point)

        with PendingFeerateApplied(self):
            htlcs_in_local = []
            for htlc in self.htlcs_in_local:
                if htlc.amount_msat // 1000 - HTLC_TIMEOUT_WEIGHT * (self.local_state.feerate // 1000) < self.local_config.dust_limit_sat:
                    continue
                htlcs_in_local.append(
                    ( make_offered_htlc(remote_revocation_pubkey, remote_htlc_pubkey, local_htlc_pubkey, htlc.payment_hash), htlc.amount_msat + htlc.total_fee))

            htlcs_in_remote = []
            for htlc in self.htlcs_in_remote:
                if htlc.amount_msat // 1000 - HTLC_SUCCESS_WEIGHT * (self.local_state.feerate // 1000) < self.local_config.dust_limit_sat:
                    continue
                htlcs_in_remote.append(
                    ( make_received_htlc(remote_revocation_pubkey, remote_htlc_pubkey, local_htlc_pubkey, htlc.payment_hash, htlc.cltv_expiry), htlc.amount_msat + htlc.total_fee))

            commit = self.make_commitment(self.local_state.ctn + 1,
                True, this_point,
                local_msat - total_fee_local, remote_msat - total_fee_remote, htlcs_in_local + htlcs_in_remote)
            return commit

    def gen_htlc_indices(self, subject, just_unsettled=True):
        assert subject in ["local", "remote"]
        update_log = (self.remote_update_log if subject == "remote" else self.local_update_log)
        other_log = (self.remote_update_log if subject != "remote" else self.local_update_log)
        res = []
        for htlc in update_log:
            if type(htlc) is not UpdateAddHtlc:
                continue
            height = (self.local_state.ctn if subject == "remote" else self.remote_state.ctn)
            locked_in = (htlc.r_locked_in if subject == "remote" else htlc.l_locked_in)

            if locked_in is None or just_unsettled == (SettleHtlc(htlc.htlc_id) in other_log):
                continue
            res.append(htlc)
        return res

    @property
    def htlcs_in_local(self):
        return self.gen_htlc_indices("local")

    @property
    def htlcs_in_remote(self):
        return self.gen_htlc_indices("remote")

    def settle_htlc(self, preimage, htlc_id):
        """
        SettleHTLC attempts to settle an existing outstanding received HTLC.
        """
        self.print_error("settle_htlc")
        htlc = self.lookup_htlc(self.remote_update_log, htlc_id)
        assert htlc.payment_hash == sha256(preimage)
        self.local_update_log.append(SettleHtlc(htlc_id))

    def receive_htlc_settle(self, preimage, htlc_index):
        self.print_error("receive_htlc_settle")
        htlc = self.lookup_htlc(self.local_update_log, htlc_index)
        assert htlc.payment_hash == sha256(preimage)
        assert len([x.htlc_id == htlc_index for x in self.local_update_log]) == 1
        self.remote_update_log.append(SettleHtlc(htlc_index))

    def fail_htlc(self, htlc):
        # TODO
        self.local_update_log = []
        self.remote_update_log = []
        self.print_error("fail_htlc (EMPTIED LOGS)")

    @property
    def l_current_height(self):
        return self.local_state.ctn

    @property
    def r_current_height(self):
        return self.remote_state.ctn

    @property
    def local_commit_fee(self):
        return self.constraints.capacity - sum(x[2] for x in self.local_commitment.outputs())

    def update_fee(self, fee):
        if not self.constraints.is_initiator:
            raise Exception("only initiator can update_fee, this counterparty is not initiator")
        self.pending_fee_update = fee

    def receive_update_fee(self, fee):
        if self.constraints.is_initiator:
            raise Exception("only the non-initiator can receive_update_fee, this counterparty is initiator")
        self.pending_fee_update = fee

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
                "channel_id": self.channel_id
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
                return super(MyJsonEncoder, self)
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
            chan.local_config.dust_limit_sat,
            chan.local_state.feerate if for_us else chan.remote_state.feerate,
            for_us,
            chan.constraints.is_initiator,
            htlcs=htlcs)
