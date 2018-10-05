# ported from lnd 42de4400bff5105352d0552155f73589166d162b

import unittest
import electrum.bitcoin as bitcoin
import electrum.lnbase as lnbase
import electrum.lnhtlc as lnhtlc
import electrum.lnutil as lnutil
import electrum.util as util
import os
import binascii

from electrum.lnutil import SENT, LOCAL, REMOTE, RECEIVED

def create_channel_state(funding_txid, funding_index, funding_sat, local_feerate, is_initiator, local_amount, remote_amount, privkeys, other_pubkeys, seed, cur, nex, other_node_id, l_dust, r_dust, l_csv, r_csv):
    assert local_amount > 0
    assert remote_amount > 0
    channel_id, _ = lnbase.channel_id_from_funding_tx(funding_txid, funding_index)
    their_revocation_store = lnbase.RevocationStore()
    local_config=lnbase.ChannelConfig(
        payment_basepoint=privkeys[0],
        multisig_key=privkeys[1],
        htlc_basepoint=privkeys[2],
        delayed_basepoint=privkeys[3],
        revocation_basepoint=privkeys[4],
        to_self_delay=l_csv,
        dust_limit_sat=l_dust,
        max_htlc_value_in_flight_msat=500000 * 1000,
        max_accepted_htlcs=5,
        initial_msat=local_amount,
    )
    remote_config=lnbase.ChannelConfig(
        payment_basepoint=other_pubkeys[0],
        multisig_key=other_pubkeys[1],
        htlc_basepoint=other_pubkeys[2],
        delayed_basepoint=other_pubkeys[3],
        revocation_basepoint=other_pubkeys[4],
        to_self_delay=r_csv,
        dust_limit_sat=r_dust,
        max_htlc_value_in_flight_msat=500000 * 1000,
        max_accepted_htlcs=5,
        initial_msat=remote_amount,
    )

    return {
            "channel_id":channel_id,
            "short_channel_id":channel_id[:8],
            "funding_outpoint":lnbase.Outpoint(funding_txid, funding_index),
            "local_config":local_config,
            "remote_config":remote_config,
            "remote_state":lnbase.RemoteState(
                ctn = 0,
                next_per_commitment_point=nex,
                current_per_commitment_point=cur,
                amount_msat=remote_amount,
                revocation_store=their_revocation_store,
                next_htlc_id = 0,
                feerate=local_feerate
            ),
            "local_state":lnbase.LocalState(
                ctn = 0,
                per_commitment_secret_seed=seed,
                amount_msat=local_amount,
                next_htlc_id = 0,
                funding_locked_received=True,
                was_announced=False,
                current_commitment_signature=None,
                current_htlc_signatures=None,
                feerate=local_feerate
            ),
            "constraints":lnbase.ChannelConstraints(capacity=funding_sat, is_initiator=is_initiator, funding_txn_minimum_depth=3),
            "node_id":other_node_id,
            "remote_commitment_to_be_revoked": None,
            'onion_keys': {},
    }

def bip32(sequence):
    xprv, xpub = bitcoin.bip32_root(b"9dk", 'standard')
    xprv, xpub = bitcoin.bip32_private_derivation(xprv, "m/", sequence)
    xtype, depth, fingerprint, child_number, c, k = bitcoin.deserialize_xprv(xprv)
    assert len(k) == 32
    assert type(k) is bytes
    return k

def create_test_channels(feerate=6000, local=None, remote=None):
    funding_txid = binascii.hexlify(os.urandom(32)).decode("ascii")
    funding_index = 0
    funding_sat = ((local + remote) // 1000) if local is not None and remote is not None else (bitcoin.COIN * 10)
    local_amount = local if local is not None else (funding_sat * 1000 // 2)
    remote_amount = remote if remote is not None else (funding_sat * 1000 // 2)
    alice_raw = [ bip32("m/" + str(i)) for i in range(5) ]
    bob_raw = [ bip32("m/" + str(i)) for i in range(5,11) ]
    alice_privkeys = [lnutil.Keypair(lnbase.privkey_to_pubkey(x), x) for x in alice_raw]
    bob_privkeys = [lnutil.Keypair(lnbase.privkey_to_pubkey(x), x) for x in bob_raw]
    alice_pubkeys = [lnutil.OnlyPubkeyKeypair(x.pubkey) for x in alice_privkeys]
    bob_pubkeys = [lnutil.OnlyPubkeyKeypair(x.pubkey) for x in bob_privkeys]

    alice_seed = os.urandom(32)
    bob_seed = os.urandom(32)

    alice_cur = lnutil.secret_to_pubkey(int.from_bytes(lnutil.get_per_commitment_secret_from_seed(alice_seed, lnutil.RevocationStore.START_INDEX), "big"))
    alice_next = lnutil.secret_to_pubkey(int.from_bytes(lnutil.get_per_commitment_secret_from_seed(alice_seed, lnutil.RevocationStore.START_INDEX - 1), "big"))
    bob_cur = lnutil.secret_to_pubkey(int.from_bytes(lnutil.get_per_commitment_secret_from_seed(bob_seed, lnutil.RevocationStore.START_INDEX), "big"))
    bob_next = lnutil.secret_to_pubkey(int.from_bytes(lnutil.get_per_commitment_secret_from_seed(bob_seed, lnutil.RevocationStore.START_INDEX - 1), "big"))

    return \
        lnhtlc.HTLCStateMachine(
            create_channel_state(funding_txid, funding_index, funding_sat, feerate, True, local_amount, remote_amount, alice_privkeys, bob_pubkeys, alice_seed, bob_cur, bob_next, b"\x02"*33, l_dust=200, r_dust=1300, l_csv=5, r_csv=4), "alice"), \
        lnhtlc.HTLCStateMachine(
            create_channel_state(funding_txid, funding_index, funding_sat, feerate, False, remote_amount, local_amount, bob_privkeys, alice_pubkeys, bob_seed, alice_cur, alice_next, b"\x01"*33, l_dust=1300, r_dust=200, l_csv=4, r_csv=5), "bob")

one_bitcoin_in_msat = bitcoin.COIN * 1000

class TestFee(unittest.TestCase):
    """
    test
    https://github.com/lightningnetwork/lightning-rfc/blob/e0c436bd7a3ed6a028e1cb472908224658a14eca/03-transactions.md#requirements-2
    """
    def test_SimpleAddSettleWorkflow(self):
        alice_channel, bob_channel = create_test_channels(253, 10000000000, 5000000000)
        self.assertIn(9999817, [x[2] for x in alice_channel.local_commitment.outputs()])

class TestLNBaseHTLCStateMachine(unittest.TestCase):
    def assertOutputExistsByValue(self, tx, amt_sat):
        for typ, scr, val in tx.outputs():
            if val == amt_sat:
                break
        else:
            self.assertFalse()

    def setUp(self):
        # Create a test channel which will be used for the duration of this
        # unittest. The channel will be funded evenly with Alice having 5 BTC,
        # and Bob having 5 BTC.
        self.alice_channel, self.bob_channel = create_test_channels()

        self.paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(self.paymentPreimage)
        self.htlc = {
            'payment_hash' : paymentHash,
            'amount_msat' :  one_bitcoin_in_msat,
            'cltv_expiry' :  5,
        }

        # First Alice adds the outgoing HTLC to her local channel's state
        # update log. Then Alice sends this wire message over to Bob who adds
        # this htlc to his remote state update log.
        self.aliceHtlcIndex = self.alice_channel.add_htlc(self.htlc)

        self.bobHtlcIndex = self.bob_channel.receive_htlc(self.htlc)
        self.htlc = self.bob_channel.log[lnutil.REMOTE][0]

    def test_SimpleAddSettleWorkflow(self):
        alice_channel, bob_channel = self.alice_channel, self.bob_channel
        htlc = self.htlc

        # Next alice commits this change by sending a signature message. Since
        # we expect the messages to be ordered, Bob will receive the HTLC we
        # just sent before he receives this signature, so the signature will
        # cover the HTLC.
        aliceSig, aliceHtlcSigs = alice_channel.sign_next_commitment()

        self.assertEqual(len(aliceHtlcSigs), 1, "alice should generate one htlc signature")

        # Bob receives this signature message, and checks that this covers the
        # state he has in his remote log. This includes the HTLC just sent
        # from Alice.
        bob_channel.receive_new_commitment(aliceSig, aliceHtlcSigs)

        # Bob revokes his prior commitment given to him by Alice, since he now
        # has a valid signature for a newer commitment.
        bobRevocation, _ = bob_channel.revoke_current_commitment()

        # Bob finally send a signature for Alice's commitment transaction.
        # This signature will cover the HTLC, since Bob will first send the
        # revocation just created. The revocation also acks every received
        # HTLC up to the point where Alice sent here signature.
        bobSig, bobHtlcSigs = bob_channel.sign_next_commitment()

        # Alice then processes this revocation, sending her own revocation for
        # her prior commitment transaction. Alice shouldn't have any HTLCs to
        # forward since she's sending an outgoing HTLC.
        alice_channel.receive_revocation(bobRevocation)

        # Alice then processes bob's signature, and since she just received
        # the revocation, she expect this signature to cover everything up to
        # the point where she sent her signature, including the HTLC.
        alice_channel.receive_new_commitment(bobSig, bobHtlcSigs)

        # Alice then generates a revocation for bob.
        aliceRevocation, _ = alice_channel.revoke_current_commitment()

        # Finally Bob processes Alice's revocation, at this point the new HTLC
        # is fully locked in within both commitment transactions. Bob should
        # also be able to forward an HTLC now that the HTLC has been locked
        # into both commitment transactions.
        bob_channel.receive_revocation(aliceRevocation)

        # At this point, both sides should have the proper number of satoshis
        # sent, and commitment height updated within their local channel
        # state.
        aliceSent = 0
        bobSent = 0

        self.assertEqual(alice_channel.total_msat[SENT], aliceSent, "alice has incorrect milli-satoshis sent")
        self.assertEqual(alice_channel.total_msat[RECEIVED], bobSent, "alice has incorrect milli-satoshis received")
        self.assertEqual(bob_channel.total_msat[SENT], bobSent, "bob has incorrect milli-satoshis sent")
        self.assertEqual(bob_channel.total_msat[RECEIVED], aliceSent, "bob has incorrect milli-satoshis received")
        self.assertEqual(bob_channel.local_state.ctn, 1, "bob has incorrect commitment height")
        self.assertEqual(alice_channel.local_state.ctn, 1, "alice has incorrect commitment height")

        # Both commitment transactions should have three outputs, and one of
        # them should be exactly the amount of the HTLC.
        self.assertEqual(len(alice_channel.local_commitment.outputs()), 3, "alice should have three commitment outputs, instead have %s"% len(alice_channel.local_commitment.outputs()))
        self.assertEqual(len(bob_channel.local_commitment.outputs()), 3, "bob should have three commitment outputs, instead have %s"% len(bob_channel.local_commitment.outputs()))
        self.assertOutputExistsByValue(alice_channel.local_commitment, htlc.amount_msat // 1000)
        self.assertOutputExistsByValue(bob_channel.local_commitment, htlc.amount_msat // 1000)

        # Now we'll repeat a similar exchange, this time with Bob settling the
        # HTLC once he learns of the preimage.
        preimage = self.paymentPreimage
        bob_channel.settle_htlc(preimage, self.bobHtlcIndex)

        alice_channel.receive_htlc_settle(preimage, self.aliceHtlcIndex)

        bobSig2, bobHtlcSigs2 = bob_channel.sign_next_commitment()
        alice_channel.receive_new_commitment(bobSig2, bobHtlcSigs2)

        aliceRevocation2, _ = alice_channel.revoke_current_commitment()
        aliceSig2, aliceHtlcSigs2 = alice_channel.sign_next_commitment()
        self.assertEqual(aliceHtlcSigs2, [], "alice should generate no htlc signatures")

        received, sent = bob_channel.receive_revocation(aliceRevocation2)
        self.assertEqual(received, one_bitcoin_in_msat)

        bob_channel.receive_new_commitment(aliceSig2, aliceHtlcSigs2)

        bobRevocation2, _ = bob_channel.revoke_current_commitment()
        alice_channel.receive_revocation(bobRevocation2)

        # At this point, Bob should have 6 BTC settled, with Alice still having
        # 4 BTC. Alice's channel should show 1 BTC sent and Bob's channel
        # should show 1 BTC received. They should also be at commitment height
        # two, with the revocation window extended by 1 (5).
        mSatTransferred = one_bitcoin_in_msat
        self.assertEqual(alice_channel.total_msat[SENT], mSatTransferred, "alice satoshis sent incorrect")
        self.assertEqual(alice_channel.total_msat[RECEIVED], 0, "alice satoshis received incorrect")
        self.assertEqual(bob_channel.total_msat[RECEIVED], mSatTransferred, "bob satoshis received incorrect")
        self.assertEqual(bob_channel.total_msat[SENT], 0, "bob satoshis sent incorrect")
        self.assertEqual(bob_channel.current_height[LOCAL], 2, "bob has incorrect commitment height")
        self.assertEqual(alice_channel.current_height[LOCAL], 2, "alice has incorrect commitment height")

        # The logs of both sides should now be cleared since the entry adding
        # the HTLC should have been removed once both sides receive the
        # revocation.
        #self.assertEqual(alice_channel.local_update_log, [], "alice's local not updated, should be empty, has %s entries instead"% len(alice_channel.local_update_log))
        #self.assertEqual(alice_channel.remote_update_log, [], "alice's remote not updated, should be empty, has %s entries instead"% len(alice_channel.remote_update_log))
        alice_channel.update_fee(100000)
        alice_channel.serialize()

    def alice_to_bob_fee_update(self):
        fee = 111
        self.alice_channel.update_fee(fee)
        self.bob_channel.receive_update_fee(fee)
        return fee

    def test_UpdateFeeSenderCommits(self):
        old_feerate = self.alice_channel.pending_feerate(LOCAL)
        fee = self.alice_to_bob_fee_update()

        alice_channel, bob_channel = self.alice_channel, self.bob_channel

        self.assertEqual(self.alice_channel.pending_feerate(LOCAL), old_feerate)
        alice_sig, alice_htlc_sigs = alice_channel.sign_next_commitment()
        self.assertEqual(self.alice_channel.pending_feerate(LOCAL), old_feerate)

        bob_channel.receive_new_commitment(alice_sig, alice_htlc_sigs)

        self.assertNotEqual(fee, bob_channel.local_state.feerate)
        rev, _ = bob_channel.revoke_current_commitment()
        self.assertEqual(fee, bob_channel.local_state.feerate)

        bob_sig, bob_htlc_sigs = bob_channel.sign_next_commitment()
        alice_channel.receive_revocation(rev)
        alice_channel.receive_new_commitment(bob_sig, bob_htlc_sigs)

        self.assertNotEqual(fee, alice_channel.local_state.feerate)
        rev, _ = alice_channel.revoke_current_commitment()
        self.assertEqual(fee, alice_channel.local_state.feerate)

        bob_channel.receive_revocation(rev)
        self.assertEqual(fee, bob_channel.remote_state.feerate)


    def test_UpdateFeeReceiverCommits(self):
        fee = self.alice_to_bob_fee_update()

        alice_channel, bob_channel = self.alice_channel, self.bob_channel

        bob_sig, bob_htlc_sigs = bob_channel.sign_next_commitment()
        alice_channel.receive_new_commitment(bob_sig, bob_htlc_sigs)

        alice_revocation, _ = alice_channel.revoke_current_commitment()
        bob_channel.receive_revocation(alice_revocation)
        alice_sig, alice_htlc_sigs = alice_channel.sign_next_commitment()
        bob_channel.receive_new_commitment(alice_sig, alice_htlc_sigs)

        self.assertNotEqual(fee, bob_channel.local_state.feerate)
        bob_revocation, _ = bob_channel.revoke_current_commitment()
        self.assertEqual(fee, bob_channel.local_state.feerate)

        bob_sig, bob_htlc_sigs = bob_channel.sign_next_commitment()
        alice_channel.receive_revocation(bob_revocation)
        alice_channel.receive_new_commitment(bob_sig, bob_htlc_sigs)

        self.assertNotEqual(fee, alice_channel.local_state.feerate)
        alice_revocation, _ = alice_channel.revoke_current_commitment()
        self.assertEqual(fee, alice_channel.local_state.feerate)

        bob_channel.receive_revocation(alice_revocation)
        self.assertEqual(fee, bob_channel.remote_state.feerate)



class TestLNHTLCDust(unittest.TestCase):
    def test_HTLCDustLimit(self):
        alice_channel, bob_channel = create_test_channels()

        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        fee_per_kw = alice_channel.local_state.feerate
        self.assertEqual(fee_per_kw, 6000)
        htlcAmt = 500 + lnutil.HTLC_TIMEOUT_WEIGHT * (fee_per_kw // 1000)
        self.assertEqual(htlcAmt, 4478)
        htlc = {
            'payment_hash' : paymentHash,
            'amount_msat' :  1000 * htlcAmt,
            'cltv_expiry' :  5, # also in create_test_channels
        }

        aliceHtlcIndex = alice_channel.add_htlc(htlc)
        bobHtlcIndex = bob_channel.receive_htlc(htlc)
        force_state_transition(alice_channel, bob_channel)
        self.assertEqual(len(alice_channel.local_commitment.outputs()), 3)
        self.assertEqual(len(bob_channel.local_commitment.outputs()), 2)
        default_fee = calc_static_fee(0)
        self.assertEqual(bob_channel.pending_local_fee, default_fee + htlcAmt)
        bob_channel.settle_htlc(paymentPreimage, bobHtlcIndex)
        alice_channel.receive_htlc_settle(paymentPreimage, aliceHtlcIndex)
        force_state_transition(bob_channel, alice_channel)
        self.assertEqual(len(alice_channel.local_commitment.outputs()), 2)
        self.assertEqual(alice_channel.total_msat[SENT] // 1000, htlcAmt)

def force_state_transition(chanA, chanB):
    chanB.receive_new_commitment(*chanA.sign_next_commitment())
    rev, _ = chanB.revoke_current_commitment()
    bob_sig, bob_htlc_sigs = chanB.sign_next_commitment()
    chanA.receive_revocation(rev)
    chanA.receive_new_commitment(bob_sig, bob_htlc_sigs)
    chanB.receive_revocation(chanA.revoke_current_commitment()[0])

# calcStaticFee calculates appropriate fees for commitment transactions.  This
# function provides a simple way to allow test balance assertions to take fee
# calculations into account.
def calc_static_fee(numHTLCs):
    commitWeight = 724
    htlcWeight   = 172
    feePerKw     = 24//4 * 1000
    return feePerKw * (commitWeight + htlcWeight*numHTLCs) // 1000
