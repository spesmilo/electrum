# ported from lnd 42de4400bff5105352d0552155f73589166d162b
from ecdsa.util import sigencode_string_canonize, sigdecode_der
from .util import bfh, PrintError
from .bitcoin import Hash
from collections import namedtuple
from ecdsa.curves import SECP256k1
from .crypto import sha256
from . import ecc

SettleHtlc = namedtuple("SettleHtlc", ["htlc_id"])
RevokeAndAck = namedtuple("RevokeAndAck", ["per_commitment_secret", "next_per_commitment_point"])

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
        self.state = state
        self.local_update_log = []
        self.remote_update_log = []

        self.name = name

        self.total_msat_sent = 0
        self.total_msat_received = 0

    def add_htlc(self, htlc):
        """
        AddHTLC adds an HTLC to the state machine's local update log. This method
        should be called when preparing to send an outgoing HTLC.
        """
        assert type(htlc) is UpdateAddHtlc
        self.local_update_log.append(htlc)
        self.print_error("add_htlc")
        htlc_id = self.state.local_state.next_htlc_id
        self.state = self.state._replace(local_state=self.state.local_state._replace(next_htlc_id=htlc_id + 1))
        htlc.htlc_id = htlc_id
        return htlc_id

    def receive_htlc(self, htlc):
        """
        ReceiveHTLC adds an HTLC to the state machine's remote update log. This
        method should be called in response to receiving a new HTLC from the remote
        party.
        """
        assert type(htlc) is UpdateAddHtlc
        self.remote_update_log.append(htlc)
        self.print_error("receive_htlc")
        htlc_id = self.state.remote_state.next_htlc_id
        self.state = self.state._replace(remote_state=self.state.remote_state._replace(next_htlc_id=htlc_id + 1))
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
        from .lnbase import sign_and_get_sig_string, derive_privkey, make_htlc_tx_with_open_channel
        for htlc in self.local_update_log:
            if not type(htlc) is UpdateAddHtlc: continue
            if htlc.l_locked_in is None: htlc.l_locked_in = self.state.local_state.ctn
        self.print_error("sign_next_commitment")

        sig_64 = sign_and_get_sig_string(self.remote_commitment, self.state.local_config, self.state.remote_config)

        their_remote_htlc_privkey_number = derive_privkey(
            int.from_bytes(self.state.local_config.htlc_basepoint.privkey, 'big'),
            self.state.remote_state.next_per_commitment_point)
        their_remote_htlc_privkey = their_remote_htlc_privkey_number.to_bytes(32, 'big')

        for_us = False

        htlcsigs = []
        for we_receive, htlcs in zip([True, False], [self.htlcs_in_remote, self.htlcs_in_local]):
            assert len(htlcs) <= 1
            for htlc in htlcs:
                original_htlc_output_index = 0
                args = [self.state.remote_state.next_per_commitment_point, for_us, we_receive, htlc.amount_msat + htlc.total_fee, htlc.cltv_expiry, htlc.payment_hash, self.remote_commitment, original_htlc_output_index]
                htlc_tx = make_htlc_tx_with_open_channel(self.state, *args)
                sig = bfh(htlc_tx.sign_txin(0, their_remote_htlc_privkey))
                r, s = sigdecode_der(sig[:-1], SECP256k1.generator.order())
                htlc_sig = sigencode_string_canonize(r, s, SECP256k1.generator.order())
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
        from .lnbase import make_htlc_tx_with_open_channel , derive_pubkey

        self.print_error("receive_new_commitment")
        for htlc in self.remote_update_log:
            if not type(htlc) is UpdateAddHtlc: continue
            if htlc.r_locked_in is None: htlc.r_locked_in = self.state.remote_state.ctn
        assert len(htlc_sigs) == 0 or type(htlc_sigs[0]) is bytes

        preimage_hex = self.local_commitment.serialize_preimage(0)
        pre_hash = Hash(bfh(preimage_hex))
        if not ecc.verify_signature(self.state.remote_config.multisig_key.pubkey, sig, pre_hash):
            raise Exception('failed verifying signature of our updated commitment transaction: ' + str(sig))

        _, this_point, _ = self.points

        if len(self.htlcs_in_remote) > 0:
            print("CHECKING HTLC SIGS")
            assert len(self.local_commitment.outputs()) == 3 # TODO
            we_receive = True
            payment_hash = self.htlcs_in_remote[0].payment_hash
            amount_msat = self.htlcs_in_remote[0].amount_msat
            cltv_expiry = self.htlcs_in_remote[0].cltv_expiry
            htlc_tx = make_htlc_tx_with_open_channel(self.state, this_point, True, we_receive, amount_msat, cltv_expiry, payment_hash, self.local_commitment, 0)
            pre_hash = Hash(bfh(htlc_tx.serialize_preimage(0)))
            remote_htlc_pubkey = derive_pubkey(self.state.remote_config.htlc_basepoint.pubkey, this_point)
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

        self.state = self.state._replace(
            local_state=self.state.local_state._replace(
                ctn=self.state.local_state.ctn + 1
            )
        )

        return RevokeAndAck(last_secret, next_point), "current htlcs"

    @property
    def points(self):
        from .lnbase import get_per_commitment_secret_from_seed, secret_to_pubkey
        chan = self.state
        last_small_num = chan.local_state.ctn
        next_small_num = last_small_num + 2
        this_small_num = last_small_num + 1
        last_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-last_small_num-1)
        this_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-this_small_num-1)
        this_point = secret_to_pubkey(int.from_bytes(this_secret, 'big'))
        next_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-next_small_num-1)
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

        sent_this_batch = 0
        received_this_batch = 0

        for x in settle_fails2:
            htlc = self.lookup_htlc(self.local_update_log, x.htlc_id)
            sent_this_batch += htlc.amount_msat

        self.total_msat_sent += sent_this_batch

        # increase received_msat counter for htlc's that have been settled
        adds2 = self.gen_htlc_indices("remote")
        for htlc in adds2:
            htlc_id = htlc.htlc_id
            if SettleHtlc(htlc_id) in self.local_update_log:
                htlc = self.lookup_htlc(self.remote_update_log, htlc_id)
                received_this_batch += htlc.amount_msat
        self.total_msat_received += received_this_batch

        # log compaction (remove entries relating to htlc's that have been settled)

        to_remove = []
        for x in filter(lambda x: type(x) is SettleHtlc, self.remote_update_log):
            to_remove += [y for y in self.local_update_log if y.htlc_id == x.htlc_id]

        if to_remove != []:
            print("REMOVING")

        # assert that we should have compacted the log earlier
        assert len(to_remove) <= 1, to_remove
        if len(to_remove) == 1:
            self.remote_update_log = [x for x in self.remote_update_log if x.htlc_id != to_remove[0].htlc_id]
            self.local_update_log = [x for x in self.local_update_log if x.htlc_id != to_remove[0].htlc_id]

        to_remove = []
        for x in filter(lambda x: type(x) is SettleHtlc, self.local_update_log):
            to_remove += [y for y in self.remote_update_log if y.htlc_id == x.htlc_id]

        assert len(to_remove) <= 1, to_remove
        if len(to_remove) == 1:
            self.local_update_log = [x for x in self.local_update_log if x.htlc_id != to_remove[0].htlc_id]
            self.remote_update_log = [x for x in self.remote_update_log if x.htlc_id != to_remove[0].htlc_id]

        self.state.remote_state.revocation_store.add_next_entry(revocation.per_commitment_secret)

        next_point = self.state.remote_state.next_per_commitment_point

        self.state = self.state._replace(
            remote_state=self.state.remote_state._replace(
                ctn=self.state.remote_state.ctn + 1,
                current_per_commitment_point=next_point,
                next_per_commitment_point=revocation.next_per_commitment_point,
                amount_msat=self.state.remote_state.amount_msat + (sent_this_batch - received_this_batch)
            ),
            local_state=self.state.local_state._replace(
                amount_msat = self.state.local_state.amount_msat + (received_this_batch - sent_this_batch)
            )
        )

    @staticmethod
    def htlcsum(htlcs):
        return sum(x.amount_msat for x in htlcs), sum(x.total_fee for x in htlcs)

    @property
    def remote_commitment(self):
        from .lnbase import make_commitment_using_open_channel, make_received_htlc, make_offered_htlc, derive_pubkey, derive_blinded_pubkey
        htlc_value_local, total_fee_local = self.htlcsum(self.htlcs_in_local)
        htlc_value_remote, total_fee_remote = self.htlcsum(self.htlcs_in_remote)
        local_msat = self.state.local_state.amount_msat -\
          htlc_value_local
        remote_msat = self.state.remote_state.amount_msat -\
          htlc_value_remote
        assert local_msat >= 0
        assert remote_msat >= 0

        this_point = self.state.remote_state.next_per_commitment_point

        remote_htlc_pubkey = derive_pubkey(self.state.remote_config.htlc_basepoint.pubkey, this_point)
        local_htlc_pubkey = derive_pubkey(self.state.local_config.htlc_basepoint.pubkey, this_point)
        local_revocation_pubkey = derive_blinded_pubkey(self.state.local_config.revocation_basepoint.pubkey, this_point)

        htlcs_in_local = []
        for htlc in self.htlcs_in_local:
            htlcs_in_local.append(
                ( make_received_htlc(local_revocation_pubkey, local_htlc_pubkey, remote_htlc_pubkey, htlc.payment_hash, htlc.cltv_expiry), htlc.amount_msat + total_fee_local))

        htlcs_in_remote = []
        for htlc in self.htlcs_in_remote:
            htlcs_in_remote.append(
                ( make_offered_htlc(local_revocation_pubkey, local_htlc_pubkey, remote_htlc_pubkey, htlc.payment_hash), htlc.amount_msat + total_fee_remote))

        commit = make_commitment_using_open_channel(self.state, self.state.remote_state.ctn + 1,
            False, this_point,
            remote_msat - total_fee_remote, local_msat - total_fee_local, htlcs_in_local + htlcs_in_remote)
        return commit

    @property
    def local_commitment(self):
        from .lnbase import make_commitment_using_open_channel, make_received_htlc, make_offered_htlc, derive_pubkey, derive_blinded_pubkey, get_per_commitment_secret_from_seed, secret_to_pubkey
        htlc_value_local, total_fee_local = self.htlcsum(self.htlcs_in_local)
        htlc_value_remote, total_fee_remote = self.htlcsum(self.htlcs_in_remote)
        local_msat = self.state.local_state.amount_msat -\
          htlc_value_local
        remote_msat = self.state.remote_state.amount_msat -\
          htlc_value_remote
        assert local_msat >= 0
        assert remote_msat >= 0

        _, this_point, _ = self.points

        remote_htlc_pubkey = derive_pubkey(self.state.remote_config.htlc_basepoint.pubkey, this_point)
        local_htlc_pubkey = derive_pubkey(self.state.local_config.htlc_basepoint.pubkey, this_point)
        remote_revocation_pubkey = derive_blinded_pubkey(self.state.remote_config.revocation_basepoint.pubkey, this_point)

        htlcs_in_local = []
        for htlc in self.htlcs_in_local:
            htlcs_in_local.append(
                ( make_offered_htlc(remote_revocation_pubkey, remote_htlc_pubkey, local_htlc_pubkey, htlc.payment_hash), htlc.amount_msat + total_fee_local))

        htlcs_in_remote = []
        for htlc in self.htlcs_in_remote:
            htlcs_in_remote.append(
                ( make_received_htlc(remote_revocation_pubkey, remote_htlc_pubkey, local_htlc_pubkey, htlc.payment_hash, htlc.cltv_expiry), htlc.amount_msat + total_fee_remote))

        commit = make_commitment_using_open_channel(self.state, self.state.local_state.ctn + 1,
            True, this_point,
            local_msat - total_fee_local, remote_msat - total_fee_remote, htlcs_in_local + htlcs_in_remote)
        return commit

    def gen_htlc_indices(self, subject):
        assert subject in ["local", "remote"]
        update_log = (self.remote_update_log if subject == "remote" else self.local_update_log)
        res = []
        for htlc in update_log:
            if type(htlc) is not UpdateAddHtlc:
                continue
            height = (self.state.local_state.ctn if subject == "remote" else self.state.remote_state.ctn)
            locked_in = (htlc.r_locked_in if subject == "remote" else htlc.l_locked_in)

            if locked_in is None:
                print("skipping", locked_in, height)
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
        htlc = self.lookup_htlc(self.remote_update_log, htlc_id)
        assert htlc.payment_hash == sha256(preimage)
        self.local_update_log.append(SettleHtlc(htlc_id))

    def receive_htlc_settle(self, preimage, htlc_index):
        htlc = self.lookup_htlc(self.local_update_log, htlc_index)
        assert htlc.payment_hash == sha256(preimage)
        assert len([x.htlc_id == htlc_index for x in self.local_update_log]) == 1
        self.remote_update_log.append(SettleHtlc(htlc_index))

    def fail_htlc(self, htlc):
        # TODO
        self.local_update_log = []
        self.remote_update_log = []
