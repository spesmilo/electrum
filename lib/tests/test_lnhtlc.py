# ported from lnd 42de4400bff5105352d0552155f73589166d162b

import unittest
import lib.bitcoin as bitcoin
import lib.lnbase as lnbase
import lib.lnhtlc as lnhtlc
import lib.util as util
import os
import binascii

def create_channel_state(funding_txid, funding_index, funding_sat, local_feerate, is_initiator, local_amount, remote_amount, privkeys, other_pubkeys, seed, cur, nex, other_node_id):
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
        to_self_delay=143,
        dust_limit_sat=10,
        max_htlc_value_in_flight_msat=500000 * 1000,
        max_accepted_htlcs=5
    )
    remote_config=lnbase.ChannelConfig(
        payment_basepoint=other_pubkeys[0],
        multisig_key=other_pubkeys[1],
        htlc_basepoint=other_pubkeys[2],
        delayed_basepoint=other_pubkeys[3],
        revocation_basepoint=other_pubkeys[4],
        to_self_delay=143,
        dust_limit_sat=10,
        max_htlc_value_in_flight_msat=500000 * 1000,
        max_accepted_htlcs=5
    )

    return lnbase.OpenChannel(
            channel_id=channel_id,
            short_channel_id=channel_id[:8],
            funding_outpoint=lnbase.Outpoint(funding_txid, funding_index),
            local_config=local_config,
            remote_config=remote_config,
            remote_state=lnbase.RemoteState(
                ctn = 0,
                next_per_commitment_point=nex,
                last_per_commitment_point=cur,
                amount_msat=remote_amount,
                revocation_store=their_revocation_store,
                next_htlc_id = 0
            ),
            local_state=lnbase.LocalState(
                ctn = 0,
                per_commitment_secret_seed=seed,
                amount_msat=local_amount,
                next_htlc_id = 0,
                funding_locked_received=True
            ),
            constraints=lnbase.ChannelConstraints(capacity=funding_sat, feerate=local_feerate, is_initiator=is_initiator, funding_txn_minimum_depth=3),
            node_id=other_node_id
    )

def bip32(sequence):
    xprv, xpub = bitcoin.bip32_root(b"9dk", 'standard')
    xprv, xpub = bitcoin.bip32_private_derivation(xprv, "m/", sequence)
    xtype, depth, fingerprint, child_number, c, k = bitcoin.deserialize_xprv(xprv)
    assert len(k) == 32
    assert type(k) is bytes
    return k

def create_test_channels():
    funding_txid = binascii.hexlify(os.urandom(32)).decode("ascii")
    funding_index = 0
    funding_sat = bitcoin.COIN * 5
    local_amount = (funding_sat * 1000) // 2
    remote_amount = (funding_sat * 1000) // 2
    alice_raw = [ bip32("m/" + str(i)) for i in range(5) ]
    bob_raw = [ bip32("m/" + str(i)) for i in range(5,11) ]
    alice_privkeys = [lnbase.Keypair(lnbase.privkey_to_pubkey(x), x) for x in alice_raw]
    bob_privkeys = [lnbase.Keypair(lnbase.privkey_to_pubkey(x), x) for x in bob_raw]
    alice_pubkeys = [lnbase.OnlyPubkeyKeypair(x.pubkey) for x in alice_privkeys]
    bob_pubkeys = [lnbase.OnlyPubkeyKeypair(x.pubkey) for x in bob_privkeys]

    alice_seed = os.urandom(32)
    bob_seed = os.urandom(32)

    alice_cur = lnbase.secret_to_pubkey(int.from_bytes(lnbase.get_per_commitment_secret_from_seed(alice_seed, 2**48 - 1), "big"))
    alice_next = lnbase.secret_to_pubkey(int.from_bytes(lnbase.get_per_commitment_secret_from_seed(alice_seed, 2**48 - 2), "big"))
    bob_cur = lnbase.secret_to_pubkey(int.from_bytes(lnbase.get_per_commitment_secret_from_seed(bob_seed, 2**48 - 1), "big"))
    bob_next = lnbase.secret_to_pubkey(int.from_bytes(lnbase.get_per_commitment_secret_from_seed(bob_seed, 2**48 - 2), "big"))

    return lnhtlc.HTLCStateMachine(
        create_channel_state(funding_txid, funding_index, funding_sat, 20000, True, local_amount, remote_amount, alice_privkeys, bob_pubkeys, alice_seed, bob_cur, bob_next, b"\x02"*33), "alice"), lnhtlc.HTLCStateMachine(
        create_channel_state(funding_txid, funding_index, funding_sat, 20000, False, remote_amount, local_amount, bob_privkeys, alice_pubkeys, bob_seed, alice_cur, alice_next, b"\x01"*33), "bob")

one_bitcoin_in_msat = bitcoin.COIN * 1000

class TestLNBaseHTLCStateMachine(unittest.TestCase):
    def assertOutputExistsByValue(self, tx, amt_sat):
        for typ, scr, val in tx.outputs():
            if val == amt_sat:
                break
        else:
            self.assertFalse()

    def test_SimpleAddSettleWorkflow(self):

        # Create a test channel which will be used for the duration of this
        # unittest. The channel will be funded evenly with Alice having 5 BTC,
        # and Bob having 5 BTC.
        alice_channel, bob_channel = create_test_channels()

        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        htlcAmt = one_bitcoin_in_msat
        htlc = lnhtlc.UpdateAddHtlc(
            payment_hash = paymentHash,
            amount_msat =  htlcAmt,
            cltv_expiry =  5,
            total_fee = 0
        )

        # First Alice adds the outgoing HTLC to her local channel's state
        # update log. Then Alice sends this wire message over to Bob who adds
        # this htlc to his remote state update log.
        aliceHtlcIndex = alice_channel.add_htlc(htlc)

        bobHtlcIndex = bob_channel.receive_htlc(htlc)

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

        self.assertEqual(alice_channel.total_msat_sent, aliceSent, "alice has incorrect milli-satoshis sent: %s vs %s"% (alice_channel.total_msat_sent, aliceSent))
        self.assertEqual(alice_channel.total_msat_received, bobSent, "alice has incorrect milli-satoshis received %s vs %s"% (alice_channel.total_msat_received, bobSent))
        self.assertEqual(bob_channel.total_msat_sent, bobSent, "bob has incorrect milli-satoshis sent %s vs %s"% (bob_channel.total_msat_sent, bobSent))
        self.assertEqual(bob_channel.total_msat_received, aliceSent, "bob has incorrect milli-satoshis received %s vs %s"% (bob_channel.total_msat_received, aliceSent))
        self.assertEqual(bob_channel.state.local_state.ctn, 1, "bob has incorrect commitment height, %s vs %s"% (bob_channel.state.local_state.ctn, 1))
        self.assertEqual(alice_channel.state.local_state.ctn, 1, "alice has incorrect commitment height, %s vs %s"% (alice_channel.state.local_state.ctn, 1))

        # Both commitment transactions should have three outputs, and one of
        # them should be exactly the amount of the HTLC.
        self.assertEqual(len(alice_channel.local_commitment.outputs()), 3, "alice should have three commitment outputs, instead have %s"% len(alice_channel.local_commitment.outputs()))
        self.assertEqual(len(bob_channel.local_commitment.outputs()), 3, "bob should have three commitment outputs, instead have %s"% len(bob_channel.local_commitment.outputs()))
        self.assertOutputExistsByValue(alice_channel.local_commitment, htlcAmt // 1000)
        self.assertOutputExistsByValue(bob_channel.local_commitment, htlcAmt // 1000)

        # Now we'll repeat a similar exchange, this time with Bob settling the
        # HTLC once he learns of the preimage.
        preimage = paymentPreimage
        bob_channel.settle_htlc(preimage, bobHtlcIndex, None, None, None)

        alice_channel.receive_htlc_settle(preimage, aliceHtlcIndex)

        bobSig2, bobHtlcSigs2 = bob_channel.sign_next_commitment()
        alice_channel.receive_new_commitment(bobSig2, bobHtlcSigs2)

        aliceRevocation2, _ = alice_channel.revoke_current_commitment()
        aliceSig2, aliceHtlcSigs2 = alice_channel.sign_next_commitment()

        bob_channel.receive_revocation(aliceRevocation2)

        bob_channel.receive_new_commitment(aliceSig2, aliceHtlcSigs2)

        bobRevocation2, _ = bob_channel.revoke_current_commitment()
        alice_channel.receive_revocation(bobRevocation2)

        # At this point, Bob should have 6 BTC settled, with Alice still having
        # 4 BTC. Alice's channel should show 1 BTC sent and Bob's channel
        # should show 1 BTC received. They should also be at commitment height
        # two, with the revocation window extended by 1 (5).
        mSatTransferred = one_bitcoin_in_msat
        self.assertEqual(alice_channel.total_msat_sent, mSatTransferred, "alice satoshis sent incorrect %s vs %s expected"% (alice_channel.total_msat_sent, mSatTransferred))
        self.assertEqual(alice_channel.total_msat_received, 0, "alice satoshis received incorrect %s vs %s expected"% (alice_channel.total_msat_received, 0))
        self.assertEqual(bob_channel.total_msat_received, mSatTransferred, "bob satoshis received incorrect %s vs %s expected"% (bob_channel.total_msat_received, mSatTransferred))
        self.assertEqual(bob_channel.total_msat_sent, 0, "bob satoshis sent incorrect %s vs %s expected"% (bob_channel.total_msat_sent, 0))
        self.assertEqual(bob_channel.l_current_height, 2, "bob has incorrect commitment height, %s vs %s"% (bob_channel.l_current_height, 2))
        self.assertEqual(alice_channel.l_current_height, 2, "alice has incorrect commitment height, %s vs %s"% (alice_channel.l_current_height, 2))

        # The logs of both sides should now be cleared since the entry adding
        # the HTLC should have been removed once both sides receive the
        # revocation.
        self.assertEqual(alice_channel.local_update_log, [], "alice's local not updated, should be empty, has %s entries instead"% len(alice_channel.local_update_log))
        self.assertEqual(alice_channel.remote_update_log, [], "alice's remote not updated, should be empty, has %s entries instead"% len(alice_channel.remote_update_log))
