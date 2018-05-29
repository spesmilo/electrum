# ported from lnd 42de4400bff5105352d0552155f73589166d162b
from .lnbase import *

SettleHtlc = namedtuple("SettleHtlc", ["htlc_id"])
RevokeAndAck = namedtuple("RevokeAndAck", ["height", "per_commitment_secret", "next_per_commitment_point"])

class UpdateAddHtlc:
    def __init__(self, amount_msat, payment_hash, cltv_expiry, final_cltv_expiry_with_deltas):
        self.amount_msat = amount_msat
        self.payment_hash = payment_hash
        self.cltv_expiry = cltv_expiry

        # the height the htlc was locked in at, or None
        self.locked_in = None

        # this field is not in update_add_htlc but we need to to make the right htlcs
        self.final_cltv_expiry_with_deltas = final_cltv_expiry_with_deltas

        self.htlc_id = None

    def as_tuple(self):
        return (self.htlc_id, self.amount_msat, self.payment_hash, self.cltv_expiry, self.locked_in, self.final_cltv_expiry_with_deltas)

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

    def __init__(self, state: OpenChannel, name = None):
        self.state = state
        self.local_update_log = []
        self.remote_update_log = []

        self.name = name

        self.current_height = 0
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
        htlc_id = len(self.local_update_log)-1
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
        htlc_id = len(self.remote_update_log)-1
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
        for htlc in self.remote_update_log:
            if not type(htlc) is UpdateAddHtlc: continue
            if htlc.locked_in is None: htlc.locked_in = self.current_height
        self.print_error("sign_next_commitment")

        sig_64 = sign_and_get_sig_string(self.remote_commitment, self.state.local_config, self.state.remote_config)

        their_remote_htlc_privkey_number = derive_privkey(
            int.from_bytes(self.state.local_config.htlc_basepoint.privkey, 'big'),
            self.state.remote_state.next_per_commitment_point)
        their_remote_htlc_privkey = their_remote_htlc_privkey_number.to_bytes(32, 'big')

        for_us = False

        htlcs = self.htlcs_in_remote # TODO also htlcs_in_local
        assert len(htlcs) <= 1
        htlcsigs = []
        for htlc in htlcs:
            original_htlc_output_index = 0
            we_receive = True # when we do htlcs_in_local, we need to flip this flag
            htlc_tx = make_htlc_tx_with_open_channel(self.state, self.state.remote_state.next_per_commitment_point, for_us, we_receive, htlc.amount_msat, htlc.final_cltv_expiry_with_deltas, htlc.payment_hash, self.remote_commitment, original_htlc_output_index)
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
        self.print_error("receive_new_commitment")
        # TODO

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
        self.current_height += 1
        self.print_error("revoke_current_commitment")

        chan = self.state
        last_small_num = chan.local_state.ctn
        next_small_num = last_small_num + 2
        this_small_num = last_small_num + 1
        last_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-last_small_num-1)
        this_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-this_small_num-1)
        this_point = secret_to_pubkey(int.from_bytes(this_secret, 'big'))
        next_secret = get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, 2**48-next_small_num-1)
        next_point = secret_to_pubkey(int.from_bytes(next_secret, 'big'))
        self.state = chan._replace(
            local_state=chan.local_state._replace(
                ctn=chan.local_state.ctn + 1
            )
        )

        return RevokeAndAck(self.current_height, last_secret, next_point), "current htlcs"

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

        if revocation.height is not None:
            adds2 = list(x for x in self.htlcs_in_remote if x.locked_in == revocation.height)

            class FwdPkg:
                adds = adds2
                settle_fails = settle_fails2

        for x in settle_fails2:
            self.total_msat_sent += self.lookup_htlc(self.local_update_log, x.htlc_id).amount_msat

        # increase received_msat counter for htlc's that have been settled
        adds2 = self.gen_htlc_indices(self.remote_update_log)
        for x in adds2:
            if SettleHtlc(x) in self.local_update_log:
                self.total_msat_received += self.lookup_htlc(self.remote_update_log, x).amount_msat

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

        assert len(to_remove) <= 1, to_remove
        if len(to_remove) == 1:
            self.local_update_log = [x for x in self.local_update_log if x.htlc_id != to_remove[0].htlc_id]
            self.remote_update_log = [x for x in self.remote_update_log if x.htlc_id != to_remove[0].htlc_id]

        self.state.remote_state.revocation_store.add_next_entry(revocation.per_commitment_secret)

        next_point = self.state.remote_state.next_per_commitment_point

        self.state = self.state._replace(
            remote_state=self.state.remote_state._replace(
                ctn=self.state.remote_state.ctn + 1,
                last_per_commitment_point=next_point,
                next_per_commitment_point=revocation.next_per_commitment_point,
            )
        )

        if revocation.height is not None:
            return FwdPkg
        else:
            return None

    @staticmethod
    def htlcsum(htlcs):
        return sum(x.amount_msat for x in htlcs)

    @property
    def remote_commitment(self):
        local_msat = self.state.local_state.amount_msat -\
          self.htlcsum(self.htlcs_in_local)
        remote_msat = self.state.remote_state.amount_msat -\
          self.htlcsum(self.htlcs_in_remote)
        assert local_msat > 0
        assert remote_msat > 0

        this_point = self.state.remote_state.next_per_commitment_point

        remote_htlc_pubkey = derive_pubkey(self.state.remote_config.htlc_basepoint.pubkey, this_point)
        local_htlc_pubkey = derive_pubkey(self.state.local_config.htlc_basepoint.pubkey, this_point)
        local_revocation_pubkey = derive_blinded_pubkey(self.state.local_config.revocation_basepoint.pubkey, this_point)
        remote_revocation_pubkey = derive_blinded_pubkey(self.state.remote_config.revocation_basepoint.pubkey, this_point)

        htlcs_in_local = []
        for htlc in self.htlcs_in_local:
            htlcs_in_local.append(
                ( make_received_htlc(local_revocation_pubkey, local_htlc_pubkey, remote_htlc_pubkey, htlc.payment_hash, htlc.cltv_expiry), htlc.amount_msat))

        htlcs_in_remote = []
        for htlc in self.htlcs_in_remote:
            htlcs_in_remote.append(
                ( make_offered_htlc(remote_revocation_pubkey, remote_htlc_pubkey, local_htlc_pubkey, htlc.payment_hash), htlc.amount_msat))

        commit = make_commitment_using_open_channel(self.state, self.state.remote_state.ctn + 1,
            True, this_point,
            remote_msat, local_msat, htlcs_in_local + htlcs_in_remote)
        assert len(commit.outputs()) == 2 + len(htlcs_in_local) + len(htlcs_in_remote)
        return commit

    @property
    def local_commitment(self):
        local_msat = self.state.local_state.amount_msat -\
          self.htlcsum(self.htlcs_in_local)
        remote_msat = self.state.remote_state.amount_msat -\
          self.htlcsum(self.htlcs_in_remote)
        assert local_msat > 0
        assert remote_msat > 0

        this_small_num = self.state.local_state.ctn + 1
        this_secret = get_per_commitment_secret_from_seed(self.state.local_state.per_commitment_secret_seed, 2**48-this_small_num-1)
        this_point = secret_to_pubkey(int.from_bytes(this_secret, 'big'))

        remote_htlc_pubkey = derive_pubkey(self.state.remote_config.htlc_basepoint.pubkey, this_point)
        local_htlc_pubkey = derive_pubkey(self.state.local_config.htlc_basepoint.pubkey, this_point)
        local_revocation_pubkey = derive_blinded_pubkey(self.state.local_config.revocation_basepoint.pubkey, this_point)
        remote_revocation_pubkey = derive_blinded_pubkey(self.state.remote_config.revocation_basepoint.pubkey, this_point)

        htlcs_in_local = []
        for htlc in self.htlcs_in_local:
            htlcs_in_local.append(
                ( make_offered_htlc(local_revocation_pubkey, local_htlc_pubkey, remote_htlc_pubkey, htlc.payment_hash), htlc.amount_msat))

        htlcs_in_remote = []
        for htlc in self.htlcs_in_remote:
            htlcs_in_remote.append(
                ( make_received_htlc(remote_revocation_pubkey, remote_htlc_pubkey, local_htlc_pubkey, htlc.payment_hash, htlc.cltv_expiry), htlc.amount_msat))

        commit = make_commitment_using_open_channel(self.state, self.state.local_state.ctn + 1,
            True, this_point,
            local_msat, remote_msat, htlcs_in_local + htlcs_in_remote)
        assert len(commit.outputs()) == 2 + len(htlcs_in_local) + len(htlcs_in_remote)
        return commit

    def gen_htlc_indices(self, update_log):
        for num, htlc in enumerate(update_log):
            if type(htlc) is not UpdateAddHtlc:
                continue
            if htlc.locked_in is None or htlc.locked_in < self.current_height:
                continue
            yield num

    @property
    def htlcs_in_local(self):
        return [self.local_update_log[x] for x in self.gen_htlc_indices(self.local_update_log)]

    @property
    def htlcs_in_remote(self):
        return [self.remote_update_log[x] for x in self.gen_htlc_indices(self.remote_update_log)]

    def settle_htlc(self, preimage, htlc_id, source_ref, dest_ref, close_key):
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
