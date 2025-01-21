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
#
# Many of these unit tests are heavily based on unit tests in lnd
# (around commit 42de4400bff5105352d0552155f73589166d162b).

import unittest
import os
import binascii
from pprint import pformat
import logging

from electrum import bitcoin
from electrum import lnpeer
from electrum import lnchannel
from electrum import lnutil
from electrum import bip32 as bip32_utils
from electrum.crypto import privkey_to_pubkey
from electrum.lnutil import SENT, LOCAL, REMOTE, RECEIVED, UpdateAddHtlc
from electrum.lnutil import effective_htlc_tx_weight
from electrum.logging import console_stderr_handler
from electrum.lnchannel import ChannelState
from electrum.json_db import StoredDict
from electrum.coinchooser import PRNG

from . import ElectrumTestCase

one_bitcoin_in_msat = bitcoin.COIN * 1000


def create_channel_state(funding_txid, funding_index, funding_sat, is_initiator,
                         local_amount, remote_amount, privkeys, other_pubkeys,
                         seed, cur, nex, other_node_id, l_dust, r_dust, l_csv,
                         r_csv, anchor_outputs):
    #assert local_amount > 0
    #assert remote_amount > 0

    channel_id, _ = lnpeer.channel_id_from_funding_tx(funding_txid, funding_index)
    channel_type = lnutil.ChannelType.OPTION_STATIC_REMOTEKEY
    if anchor_outputs:
        channel_type |= lnutil.ChannelType.OPTION_ANCHORS_ZERO_FEE_HTLC_TX
    state = {
            "channel_id":channel_id.hex(),
            "short_channel_id":channel_id[:8],
            "funding_outpoint":lnpeer.Outpoint(funding_txid, funding_index),
            "remote_config":lnpeer.RemoteConfig(
                payment_basepoint=other_pubkeys[0],
                multisig_key=other_pubkeys[1],
                htlc_basepoint=other_pubkeys[2],
                delayed_basepoint=other_pubkeys[3],
                revocation_basepoint=other_pubkeys[4],
                to_self_delay=r_csv,
                dust_limit_sat=r_dust,
                max_htlc_value_in_flight_msat=one_bitcoin_in_msat * 5,
                max_accepted_htlcs=5,
                initial_msat=remote_amount,
                reserve_sat=0,
                htlc_minimum_msat=1,
                next_per_commitment_point=nex,
                current_per_commitment_point=cur,
                upfront_shutdown_script=b'',
                announcement_node_sig=b'',
                announcement_bitcoin_sig=b'',
            ),
            "local_config":lnpeer.LocalConfig(
                channel_seed = None,
                payment_basepoint=privkeys[0],
                multisig_key=privkeys[1],
                htlc_basepoint=privkeys[2],
                delayed_basepoint=privkeys[3],
                revocation_basepoint=privkeys[4],
                to_self_delay=l_csv,
                dust_limit_sat=l_dust,
                max_htlc_value_in_flight_msat=one_bitcoin_in_msat * 5,
                max_accepted_htlcs=5,
                initial_msat=local_amount,
                reserve_sat=0,
                per_commitment_secret_seed=seed,
                funding_locked_received=True,
                current_commitment_signature=None,
                current_htlc_signatures=None,
                htlc_minimum_msat=1,
                upfront_shutdown_script=b'',
                announcement_node_sig=b'',
                announcement_bitcoin_sig=b'',
            ),
            "constraints":lnpeer.ChannelConstraints(
                flags=0,
                capacity=funding_sat,
                is_initiator=is_initiator,
                funding_txn_minimum_depth=3,
            ),
            "node_id":other_node_id.hex(),
            'onion_keys': {},
            'data_loss_protect_remote_pcp': {},
            'state': 'PREOPENING',
            'log': {},
            'unfulfilled_htlcs': {},
            'revocation_store': {},
            'channel_type': channel_type,
    }
    return StoredDict(state, None, [])

def bip32(sequence):
    node = bip32_utils.BIP32Node.from_rootseed(b"9dk", xtype='standard').subkey_at_private_derivation(sequence)
    k = node.eckey.get_secret_bytes()
    assert len(k) == 32
    assert type(k) is bytes
    return k

def create_test_channels(*, feerate=6000, local_msat=None, remote_msat=None,
                         alice_name="alice", bob_name="bob",
                         alice_pubkey=b"\x01"*33, bob_pubkey=b"\x02"*33, random_seed=None,
                         anchor_outputs=False):
    if random_seed is None:  # needed for deterministic randomness
        random_seed = os.urandom(32)
    random_gen = PRNG(random_seed)
    funding_txid = binascii.hexlify(random_gen.get_bytes(32)).decode("ascii")
    funding_index = 0
    funding_sat = ((local_msat + remote_msat) // 1000) if local_msat is not None and remote_msat is not None else (bitcoin.COIN * 10)
    local_amount = local_msat if local_msat is not None else (funding_sat * 1000 // 2)
    remote_amount = remote_msat if remote_msat is not None else (funding_sat * 1000 // 2)
    alice_raw = [bip32("m/" + str(i)) for i in range(5)]
    bob_raw = [bip32("m/" + str(i)) for i in range(5,11)]
    alice_privkeys = [lnutil.Keypair(privkey_to_pubkey(x), x) for x in alice_raw]
    bob_privkeys = [lnutil.Keypair(privkey_to_pubkey(x), x) for x in bob_raw]
    alice_pubkeys = [lnutil.OnlyPubkeyKeypair(x.pubkey) for x in alice_privkeys]
    bob_pubkeys = [lnutil.OnlyPubkeyKeypair(x.pubkey) for x in bob_privkeys]

    alice_seed = random_gen.get_bytes(32)
    bob_seed = random_gen.get_bytes(32)

    alice_first = lnutil.secret_to_pubkey(
        int.from_bytes(lnutil.get_per_commitment_secret_from_seed(
            alice_seed, lnutil.RevocationStore.START_INDEX), "big"))
    bob_first = lnutil.secret_to_pubkey(
        int.from_bytes(lnutil.get_per_commitment_secret_from_seed(
            bob_seed, lnutil.RevocationStore.START_INDEX), "big"))

    alice, bob = (
        lnchannel.Channel(
            create_channel_state(
                funding_txid, funding_index, funding_sat, True, local_amount,
                remote_amount, alice_privkeys, bob_pubkeys, alice_seed, None,
                bob_first, other_node_id=bob_pubkey, l_dust=200, r_dust=1300,
                l_csv=5, r_csv=4, anchor_outputs=anchor_outputs
            ),
            name=f"{alice_name}->{bob_name}",
            initial_feerate=feerate),
        lnchannel.Channel(
            create_channel_state(
                funding_txid, funding_index, funding_sat, False, remote_amount,
                local_amount, bob_privkeys, alice_pubkeys, bob_seed, None,
                alice_first, other_node_id=alice_pubkey, l_dust=1300, r_dust=200,
                l_csv=4, r_csv=5, anchor_outputs=anchor_outputs
            ),
            name=f"{bob_name}->{alice_name}",
            initial_feerate=feerate)
    )

    alice.hm.log[LOCAL]['ctn'] = 0
    bob.hm.log[LOCAL]['ctn'] = 0

    alice._state = ChannelState.OPEN
    bob._state = ChannelState.OPEN

    a_out = alice.get_latest_commitment(LOCAL).outputs()
    b_out = bob.get_next_commitment(REMOTE).outputs()
    assert a_out == b_out, "\n" + pformat((a_out, b_out))

    sig_from_bob, a_htlc_sigs = bob.sign_next_commitment()
    sig_from_alice, b_htlc_sigs = alice.sign_next_commitment()

    assert len(a_htlc_sigs) == 0
    assert len(b_htlc_sigs) == 0

    alice.open_with_first_pcp(bob_first, sig_from_bob)
    bob.open_with_first_pcp(alice_first, sig_from_alice)

    alice_second = lnutil.secret_to_pubkey(int.from_bytes(lnutil.get_per_commitment_secret_from_seed(alice_seed, lnutil.RevocationStore.START_INDEX - 1), "big"))
    bob_second = lnutil.secret_to_pubkey(int.from_bytes(lnutil.get_per_commitment_secret_from_seed(bob_seed, lnutil.RevocationStore.START_INDEX - 1), "big"))

    # from funding_locked:
    alice.config[REMOTE].next_per_commitment_point = bob_second
    bob.config[REMOTE].next_per_commitment_point = alice_second

    alice._fallback_sweep_address = bitcoin.pubkey_to_address('p2wpkh', alice.config[LOCAL].payment_basepoint.pubkey.hex())
    bob._fallback_sweep_address = bitcoin.pubkey_to_address('p2wpkh', bob.config[LOCAL].payment_basepoint.pubkey.hex())

    return alice, bob

class TestFee(ElectrumTestCase):
    """
    test
    https://github.com/lightningnetwork/lightning-rfc/blob/e0c436bd7a3ed6a028e1cb472908224658a14eca/03-transactions.md#requirements-2
    """
    def test_fee(self):
        alice_channel, bob_channel = create_test_channels(
            feerate=253,
            local_msat=10000000000,
            remote_msat=5000000000,
            anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        expected_value = 9999056 if self.TEST_ANCHOR_CHANNELS else 9999817
        self.assertIn(expected_value, [x.value for x in alice_channel.get_latest_commitment(LOCAL).outputs()])

class TestChannel(ElectrumTestCase):
    maxDiff = 999

    def assertOutputExistsByValue(self, tx, amt_sat):
        for o in tx.outputs():
            if o.value == amt_sat:
                break
        else:
            self.assertFalse()

    def assertNumberNonAnchorOutputs(self, number, tx):
        self.assertEqual(number, len(tx.outputs()) - (2 if self.TEST_ANCHOR_CHANNELS else 0))

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()
        # Create a test channel which will be used for the duration of this
        # unittest. The channel will be funded evenly with Alice having 5 BTC,
        # and Bob having 5 BTC.
        self.alice_channel, self.bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)

        self.paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(self.paymentPreimage)
        self.htlc_dict = {
            'payment_hash': paymentHash,
            'amount_msat':  one_bitcoin_in_msat,
            'cltv_abs': 5,
            'timestamp': 0,
        }

        # First Alice adds the outgoing HTLC to her local channel's state
        # update log. Then Alice sends this wire message over to Bob who adds
        # this htlc to his remote state update log.
        self.aliceHtlcIndex = self.alice_channel.add_htlc(self.htlc_dict).htlc_id
        self.assertNotEqual(list(self.alice_channel.hm.htlcs_by_direction(REMOTE, RECEIVED, 1).values()), [])

        before = self.bob_channel.balance_minus_outgoing_htlcs(REMOTE)
        beforeLocal = self.bob_channel.balance_minus_outgoing_htlcs(LOCAL)

        self.bobHtlcIndex = self.bob_channel.receive_htlc(self.htlc_dict).htlc_id

        self.htlc = self.bob_channel.hm.log[REMOTE]['adds'][0]

    def test_concurrent_reversed_payment(self):
        self.htlc_dict['payment_hash'] = bitcoin.sha256(32 * b'\x02')
        self.htlc_dict['amount_msat'] += 1000
        self.bob_channel.add_htlc(self.htlc_dict)
        self.alice_channel.receive_htlc(self.htlc_dict)

        self.assertNumberNonAnchorOutputs(2, self.alice_channel.get_latest_commitment(LOCAL))
        self.assertNumberNonAnchorOutputs(3, self.alice_channel.get_next_commitment(LOCAL))
        self.assertNumberNonAnchorOutputs(2, self.alice_channel.get_latest_commitment(REMOTE))
        self.assertNumberNonAnchorOutputs(3, self.alice_channel.get_next_commitment(REMOTE))

        self.alice_channel.receive_new_commitment(*self.bob_channel.sign_next_commitment())

        self.assertNumberNonAnchorOutputs(3, self.alice_channel.get_latest_commitment(LOCAL))
        self.assertNumberNonAnchorOutputs(3, self.alice_channel.get_next_commitment(LOCAL))
        self.assertNumberNonAnchorOutputs(2, self.alice_channel.get_latest_commitment(REMOTE))
        self.assertNumberNonAnchorOutputs(3, self.alice_channel.get_next_commitment(REMOTE))

        self.alice_channel.revoke_current_commitment()

        self.assertNumberNonAnchorOutputs(3, self.alice_channel.get_latest_commitment(LOCAL))
        self.assertNumberNonAnchorOutputs(3, self.alice_channel.get_next_commitment(LOCAL))
        self.assertNumberNonAnchorOutputs(2, self.alice_channel.get_latest_commitment(REMOTE))
        self.assertNumberNonAnchorOutputs(4, self.alice_channel.get_next_commitment(REMOTE))

    def test_SimpleAddSettleWorkflow(self):
        alice_channel, bob_channel = self.alice_channel, self.bob_channel
        htlc = self.htlc

        # Starting point: alice has sent an update_add_htlc message to bob
        # but the htlc is not yet committed to
        alice_out = alice_channel.get_latest_commitment(LOCAL).outputs()
        if not alice_channel.has_anchors():
            # ctx outputs are ordered by increasing amounts
            low_amt_idx = 0
            assert len(alice_out[low_amt_idx].address) == 62  # p2wsh
            high_amt_idx = 1
            assert len(alice_out[high_amt_idx].address) == 42  # p2wpkh
        else:
            # using anchor outputs, all outputs are p2wsh
            low_amt_idx = 2
            assert len(alice_out[low_amt_idx].address) == 62
            high_amt_idx = 3
            assert len(alice_out[high_amt_idx].address) == 62
        self.assertLess(alice_out[low_amt_idx].value, 5 * 10**8, alice_out)
        self.assertEqual(alice_out[high_amt_idx].value, 5 * 10**8, alice_out)

        alice_out = alice_channel.get_latest_commitment(REMOTE).outputs()
        if not alice_channel.has_anchors():
            low_amt_idx = 0
            assert len(alice_out[low_amt_idx].address) == 42
            high_amt_idx = 1
            assert len(alice_out[high_amt_idx].address) == 62
        else:
            low_amt_idx = 2
            assert len(alice_out[low_amt_idx].address) == 62
            high_amt_idx = 3
            assert len(alice_out[high_amt_idx].address) == 62
        self.assertLess(alice_out[low_amt_idx].value, 5 * 10**8)
        self.assertEqual(alice_out[high_amt_idx].value, 5 * 10**8)

        self.assertTrue(alice_channel.signature_fits(alice_channel.get_latest_commitment(LOCAL)))

        self.assertNotEqual(alice_channel.included_htlcs(REMOTE, RECEIVED, 1), [])

        self.assertEqual(alice_channel.included_htlcs(REMOTE, RECEIVED, 0), [])
        self.assertEqual(alice_channel.included_htlcs(REMOTE, RECEIVED, 1), [htlc])

        self.assertEqual(bob_channel.included_htlcs(REMOTE, SENT, 0), [])
        self.assertEqual(bob_channel.included_htlcs(REMOTE, SENT, 1), [])

        self.assertEqual(alice_channel.included_htlcs(REMOTE, SENT, 0), [])
        self.assertEqual(alice_channel.included_htlcs(REMOTE, SENT, 1), [])

        self.assertEqual(bob_channel.included_htlcs(REMOTE, RECEIVED, 0), [])
        self.assertEqual(bob_channel.included_htlcs(REMOTE, RECEIVED, 1), [])

        from electrum.lnutil import extract_ctn_from_tx_and_chan
        tx0 = str(alice_channel.force_close_tx())
        self.assertEqual(alice_channel.get_oldest_unrevoked_ctn(LOCAL), 0)
        self.assertEqual(extract_ctn_from_tx_and_chan(alice_channel.force_close_tx(), alice_channel), 0)
        self.assertTrue(alice_channel.signature_fits(alice_channel.get_latest_commitment(LOCAL)))

        # Next alice commits this change by sending a signature message. Since
        # we expect the messages to be ordered, Bob will receive the HTLC we
        # just sent before he receives this signature, so the signature will
        # cover the HTLC.
        aliceSig, aliceHtlcSigs = alice_channel.sign_next_commitment()
        self.assertEqual(len(aliceHtlcSigs), 1, "alice should generate one htlc signature")

        self.assertTrue(alice_channel.signature_fits(alice_channel.get_latest_commitment(LOCAL)))

        self.assertEqual(next(iter(alice_channel.hm.get_htlcs_in_next_ctx(REMOTE)))[0], RECEIVED)
        self.assertEqual(alice_channel.hm.get_htlcs_in_next_ctx(REMOTE), bob_channel.hm.get_htlcs_in_next_ctx(LOCAL))
        self.assertEqual(alice_channel.get_latest_commitment(REMOTE).outputs(), bob_channel.get_next_commitment(LOCAL).outputs())

        # Bob receives this signature message, and checks that this covers the
        # state he has in his remote log. This includes the HTLC just sent
        # from Alice.
        self.assertTrue(bob_channel.signature_fits(bob_channel.get_latest_commitment(LOCAL)))
        bob_channel.receive_new_commitment(aliceSig, aliceHtlcSigs)
        self.assertTrue(bob_channel.signature_fits(bob_channel.get_latest_commitment(LOCAL)))

        self.assertEqual(bob_channel.get_oldest_unrevoked_ctn(REMOTE), 0)
        self.assertEqual(bob_channel.included_htlcs(LOCAL, RECEIVED, 1), [htlc])

        self.assertEqual(alice_channel.included_htlcs(REMOTE, RECEIVED, 0), [])
        self.assertEqual(alice_channel.included_htlcs(REMOTE, RECEIVED, 1), [htlc])

        self.assertEqual(alice_channel.included_htlcs(REMOTE, SENT, 0), [])
        self.assertEqual(alice_channel.included_htlcs(REMOTE, SENT, 1), [])

        self.assertEqual(bob_channel.included_htlcs(REMOTE, RECEIVED, 0), [])
        self.assertEqual(bob_channel.included_htlcs(REMOTE, RECEIVED, 1), [])

        # Bob revokes his prior commitment given to him by Alice, since he now
        # has a valid signature for a newer commitment.
        bobRevocation = bob_channel.revoke_current_commitment()
        self.assertTrue(bob_channel.signature_fits(bob_channel.get_latest_commitment(LOCAL)))

        # Bob finally sends a signature for Alice's commitment transaction.
        # This signature will cover the HTLC, since Bob will first send the
        # revocation just created. The revocation also acks every received
        # HTLC up to the point where Alice sent her signature.
        bobSig, bobHtlcSigs = bob_channel.sign_next_commitment()
        self.assertTrue(bob_channel.signature_fits(bob_channel.get_latest_commitment(LOCAL)))

        self.assertEqual(len(bobHtlcSigs), 1)

        self.assertTrue(alice_channel.signature_fits(alice_channel.get_latest_commitment(LOCAL)))

        # so far: Alice added htlc, Alice signed.
        self.assertNumberNonAnchorOutputs(2, alice_channel.get_latest_commitment(LOCAL))
        self.assertNumberNonAnchorOutputs(2, alice_channel.get_next_commitment(LOCAL))
        self.assertNumberNonAnchorOutputs(2, alice_channel.get_oldest_unrevoked_commitment(REMOTE))
        self.assertNumberNonAnchorOutputs(3, alice_channel.get_latest_commitment(REMOTE))

        # Alice then processes this revocation, sending her own revocation for
        # her prior commitment transaction. Alice shouldn't have any HTLCs to
        # forward since she's sending an outgoing HTLC.
        alice_channel.receive_revocation(bobRevocation)

        self.assertTrue(alice_channel.signature_fits(alice_channel.get_latest_commitment(LOCAL)))

        self.assertNumberNonAnchorOutputs(2, alice_channel.get_latest_commitment(LOCAL))
        self.assertNumberNonAnchorOutputs(3, alice_channel.get_latest_commitment(REMOTE))
        self.assertNumberNonAnchorOutputs(2, alice_channel.force_close_tx())

        self.assertEqual(len(alice_channel.hm.log[LOCAL]['adds']), 1)
        self.assertEqual(alice_channel.get_next_commitment(LOCAL).outputs(),
                         bob_channel.get_latest_commitment(REMOTE).outputs())

        # Alice then processes bob's signature, and since she just received
        # the revocation, she expects this signature to cover everything up to
        # the point where she sent her signature, including the HTLC.
        alice_channel.receive_new_commitment(bobSig, bobHtlcSigs)

        self.assertNumberNonAnchorOutputs(3, alice_channel.get_latest_commitment(REMOTE))
        self.assertNumberNonAnchorOutputs(3, alice_channel.force_close_tx())

        self.assertEqual(len(alice_channel.hm.log[LOCAL]['adds']), 1)

        tx1 = str(alice_channel.force_close_tx())
        self.assertNotEqual(tx0, tx1)

        # Alice then generates a revocation for bob.
        aliceRevocation = alice_channel.revoke_current_commitment()

        tx2 = str(alice_channel.force_close_tx())
        # since alice already has the signature for the next one, it doesn't change her force close tx (it was already the newer one)
        self.assertEqual(tx1, tx2)

        # Finally Bob processes Alice's revocation, at this point the new HTLC
        # is fully locked in within both commitment transactions. Bob should
        # also be able to forward an HTLC now that the HTLC has been locked
        # into both commitment transactions.
        self.assertTrue(bob_channel.signature_fits(bob_channel.get_latest_commitment(LOCAL)))
        bob_channel.receive_revocation(aliceRevocation)

        # At this point, both sides should have the proper number of satoshis
        # sent, and commitment height updated within their local channel
        # state.
        aliceSent = 0
        bobSent = 0

        self.assertEqual(alice_channel.total_msat(SENT), aliceSent, "alice has incorrect milli-satoshis sent")
        self.assertEqual(alice_channel.total_msat(RECEIVED), bobSent, "alice has incorrect milli-satoshis received")
        self.assertEqual(bob_channel.total_msat(SENT), bobSent, "bob has incorrect milli-satoshis sent")
        self.assertEqual(bob_channel.total_msat(RECEIVED), aliceSent, "bob has incorrect milli-satoshis received")
        self.assertEqual(bob_channel.get_oldest_unrevoked_ctn(LOCAL), 1, "bob has incorrect commitment height")
        self.assertEqual(alice_channel.get_oldest_unrevoked_ctn(LOCAL), 1, "alice has incorrect commitment height")

        # Both commitment transactions should have three outputs, and one of
        # them should be exactly the amount of the HTLC.
        alice_ctx = alice_channel.get_next_commitment(LOCAL)
        bob_ctx = bob_channel.get_next_commitment(LOCAL)
        self.assertNumberNonAnchorOutputs(3, alice_ctx)
        self.assertNumberNonAnchorOutputs(3, bob_ctx)
        self.assertOutputExistsByValue(alice_ctx, htlc.amount_msat // 1000)
        self.assertOutputExistsByValue(bob_ctx, htlc.amount_msat // 1000)

        # Now we'll repeat a similar exchange, this time with Bob settling the
        # HTLC once he learns of the preimage.
        preimage = self.paymentPreimage
        bob_channel.settle_htlc(preimage, self.bobHtlcIndex)

        alice_channel.receive_htlc_settle(preimage, self.aliceHtlcIndex)

        tx3 = str(alice_channel.force_close_tx())
        # just settling a htlc does not change her force close tx
        self.assertEqual(tx2, tx3)

        bobSig2, bobHtlcSigs2 = bob_channel.sign_next_commitment()
        self.assertEqual(len(bobHtlcSigs2), 0)

        self.assertEqual(list(alice_channel.hm.htlcs_by_direction(REMOTE, RECEIVED).values()), [htlc])
        self.assertEqual(alice_channel.included_htlcs(REMOTE, RECEIVED, alice_channel.get_oldest_unrevoked_ctn(REMOTE)), [htlc])

        self.assertEqual(alice_channel.included_htlcs(REMOTE, RECEIVED, 1), [htlc])
        self.assertEqual(alice_channel.included_htlcs(REMOTE, RECEIVED, 2), [htlc])

        self.assertEqual(bob_channel.included_htlcs(REMOTE, SENT, 1), [htlc])
        self.assertEqual(bob_channel.included_htlcs(REMOTE, SENT, 2), [])

        self.assertEqual(alice_channel.included_htlcs(REMOTE, SENT, 1), [])
        self.assertEqual(alice_channel.included_htlcs(REMOTE, SENT, 2), [])

        self.assertEqual(bob_channel.included_htlcs(REMOTE, RECEIVED, 1), [])
        self.assertEqual(bob_channel.included_htlcs(REMOTE, RECEIVED, 2), [])

        alice_ctx_bob_version = bob_channel.get_latest_commitment(REMOTE).outputs()
        alice_ctx_alice_version = alice_channel.get_next_commitment(LOCAL).outputs()
        self.assertEqual(alice_ctx_alice_version, alice_ctx_bob_version)

        alice_channel.receive_new_commitment(bobSig2, bobHtlcSigs2)

        tx4 = str(alice_channel.force_close_tx())
        self.assertNotEqual(tx3, tx4)

        self.assertEqual(alice_channel.balance(LOCAL), 500000000000)
        self.assertEqual(1, alice_channel.get_oldest_unrevoked_ctn(LOCAL))
        self.assertEqual(len(alice_channel.included_htlcs(LOCAL, RECEIVED, ctn=2)), 0)
        aliceRevocation2 = alice_channel.revoke_current_commitment()
        aliceSig2, aliceHtlcSigs2 = alice_channel.sign_next_commitment()
        self.assertEqual(aliceHtlcSigs2, [], "alice should generate no htlc signatures")
        self.assertNumberNonAnchorOutputs(3, bob_channel.get_latest_commitment(LOCAL))
        bob_channel.receive_revocation(aliceRevocation2)

        bob_channel.receive_new_commitment(aliceSig2, aliceHtlcSigs2)

        bobRevocation2 = bob_channel.revoke_current_commitment()
        received = lnchannel.htlcsum(bob_channel.hm.received_in_ctn(bob_channel.get_latest_ctn(LOCAL)))
        self.assertEqual(one_bitcoin_in_msat, received)
        alice_channel.receive_revocation(bobRevocation2)

        # At this point, Bob should have 6 BTC settled, with Alice still having
        # 4 BTC. Alice's channel should show 1 BTC sent and Bob's channel
        # should show 1 BTC received. They should also be at commitment height
        # two, with the revocation window extended by 1 (5).
        mSatTransferred = one_bitcoin_in_msat
        self.assertEqual(alice_channel.total_msat(SENT), mSatTransferred, "alice satoshis sent incorrect")
        self.assertEqual(alice_channel.total_msat(RECEIVED), 0, "alice satoshis received incorrect")
        self.assertEqual(bob_channel.total_msat(RECEIVED), mSatTransferred, "bob satoshis received incorrect")
        self.assertEqual(bob_channel.total_msat(SENT), 0, "bob satoshis sent incorrect")
        self.assertEqual(bob_channel.get_latest_ctn(LOCAL), 2, "bob has incorrect commitment height")
        self.assertEqual(alice_channel.get_latest_ctn(LOCAL), 2, "alice has incorrect commitment height")

        alice_channel.update_fee(100000, True)
        alice_outputs = alice_channel.get_next_commitment(REMOTE).outputs()
        old_outputs = bob_channel.get_next_commitment(LOCAL).outputs()
        bob_channel.update_fee(100000, False)
        new_outputs = bob_channel.get_next_commitment(LOCAL).outputs()
        self.assertNotEqual(old_outputs, new_outputs)
        self.assertEqual(alice_outputs, new_outputs)

        tx5 = str(alice_channel.force_close_tx())
        # sending a fee update does not change her force close tx
        self.assertEqual(tx4, tx5)

        force_state_transition(alice_channel, bob_channel)

        tx6 = str(alice_channel.force_close_tx())
        self.assertNotEqual(tx5, tx6)

        self.htlc_dict['amount_msat'] *= 5
        bob_index = bob_channel.add_htlc(self.htlc_dict).htlc_id
        alice_index = alice_channel.receive_htlc(self.htlc_dict).htlc_id

        force_state_transition(bob_channel, alice_channel)

        alice_channel.settle_htlc(self.paymentPreimage, alice_index)
        bob_channel.receive_htlc_settle(self.paymentPreimage, bob_index)

        force_state_transition(alice_channel, bob_channel)
        self.assertEqual(alice_channel.total_msat(SENT), one_bitcoin_in_msat, "alice satoshis sent incorrect")
        self.assertEqual(alice_channel.total_msat(RECEIVED), 5 * one_bitcoin_in_msat, "alice satoshis received incorrect")
        self.assertEqual(bob_channel.total_msat(RECEIVED), one_bitcoin_in_msat, "bob satoshis received incorrect")
        self.assertEqual(bob_channel.total_msat(SENT), 5 * one_bitcoin_in_msat, "bob satoshis sent incorrect")

    def alice_to_bob_fee_update(self, fee=1111):
        aoldctx = self.alice_channel.get_next_commitment(REMOTE).outputs()
        self.alice_channel.update_fee(fee, True)
        anewctx = self.alice_channel.get_next_commitment(REMOTE).outputs()
        self.assertNotEqual(aoldctx, anewctx)
        boldctx = self.bob_channel.get_next_commitment(LOCAL).outputs()
        self.bob_channel.update_fee(fee, False)
        bnewctx = self.bob_channel.get_next_commitment(LOCAL).outputs()
        self.assertNotEqual(boldctx, bnewctx)
        self.assertEqual(anewctx, bnewctx)
        return fee

    def test_UpdateFeeSenderCommits(self):
        alice_channel, bob_channel = self.alice_channel, self.bob_channel

        old_feerate = alice_channel.get_next_feerate(LOCAL)

        fee = self.alice_to_bob_fee_update()
        self.assertEqual(alice_channel.get_next_feerate(LOCAL), old_feerate)

        alice_sig, alice_htlc_sigs = alice_channel.sign_next_commitment()
        #self.assertEqual(alice_channel.get_next_feerate(LOCAL), old_feerate)

        bob_channel.receive_new_commitment(alice_sig, alice_htlc_sigs)

        self.assertNotEqual(fee, bob_channel.get_oldest_unrevoked_feerate(LOCAL))
        self.assertEqual(fee, bob_channel.get_latest_feerate(LOCAL))
        rev = bob_channel.revoke_current_commitment()
        self.assertEqual(fee, bob_channel.get_oldest_unrevoked_feerate(LOCAL))

        alice_channel.receive_revocation(rev)


        bob_sig, bob_htlc_sigs = bob_channel.sign_next_commitment()
        alice_channel.receive_new_commitment(bob_sig, bob_htlc_sigs)

        self.assertNotEqual(fee, alice_channel.get_oldest_unrevoked_feerate(LOCAL))
        self.assertEqual(fee, alice_channel.get_latest_feerate(LOCAL))
        rev = alice_channel.revoke_current_commitment()
        self.assertEqual(fee, alice_channel.get_oldest_unrevoked_feerate(LOCAL))

        bob_channel.receive_revocation(rev)
        self.assertEqual(fee, bob_channel.get_oldest_unrevoked_feerate(LOCAL))
        self.assertEqual(fee, bob_channel.get_latest_feerate(LOCAL))


    def test_UpdateFeeReceiverCommits(self):
        fee = self.alice_to_bob_fee_update()

        alice_channel, bob_channel = self.alice_channel, self.bob_channel

        bob_sig, bob_htlc_sigs = bob_channel.sign_next_commitment()
        alice_channel.receive_new_commitment(bob_sig, bob_htlc_sigs)

        alice_revocation = alice_channel.revoke_current_commitment()
        bob_channel.receive_revocation(alice_revocation)
        alice_sig, alice_htlc_sigs = alice_channel.sign_next_commitment()
        bob_channel.receive_new_commitment(alice_sig, alice_htlc_sigs)

        self.assertNotEqual(fee, bob_channel.get_oldest_unrevoked_feerate(LOCAL))
        self.assertEqual(fee, bob_channel.get_latest_feerate(LOCAL))
        bob_revocation = bob_channel.revoke_current_commitment()
        self.assertEqual(fee, bob_channel.get_oldest_unrevoked_feerate(LOCAL))

        bob_sig, bob_htlc_sigs = bob_channel.sign_next_commitment()
        alice_channel.receive_revocation(bob_revocation)
        alice_channel.receive_new_commitment(bob_sig, bob_htlc_sigs)

        self.assertNotEqual(fee, alice_channel.get_oldest_unrevoked_feerate(LOCAL))
        self.assertEqual(fee, alice_channel.get_latest_feerate(LOCAL))
        alice_revocation = alice_channel.revoke_current_commitment()
        self.assertEqual(fee, alice_channel.get_oldest_unrevoked_feerate(LOCAL))

        bob_channel.receive_revocation(alice_revocation)
        self.assertEqual(fee, bob_channel.get_oldest_unrevoked_feerate(LOCAL))
        self.assertEqual(fee, bob_channel.get_latest_feerate(LOCAL))

    @unittest.skip("broken probably because we haven't implemented detecting when we come out of a situation where we violate reserve")
    def test_AddHTLCNegativeBalance(self):
        # the test in lnd doesn't set the fee to zero.
        # probably lnd subtracts commitment fee after deciding weather
        # an htlc can be added. so we set the fee to zero so that
        # the test can work.
        self.alice_to_bob_fee_update(0)
        force_state_transition(self.alice_channel, self.bob_channel)

        self.htlc_dict['payment_hash'] = bitcoin.sha256(32 * b'\x02')
        self.alice_channel.add_htlc(self.htlc_dict)
        self.htlc_dict['payment_hash'] = bitcoin.sha256(32 * b'\x03')
        self.alice_channel.add_htlc(self.htlc_dict)
        # now there are three htlcs (one was in setUp)

        # Alice now has an available balance of 2 BTC. We'll add a new HTLC of
        # value 2 BTC, which should make Alice's balance negative (since she
        # has to pay a commitment fee).
        new = dict(self.htlc_dict)
        new['amount_msat'] *= 2.5
        new['payment_hash'] = bitcoin.sha256(32 * b'\x04')
        with self.assertRaises(lnutil.PaymentFailure) as cm:
            self.alice_channel.add_htlc(new)
        self.assertIn('Not enough local balance', cm.exception.args[0])


class TestChannelAnchors(TestChannel):
    TEST_ANCHOR_CHANNELS = True


class TestAvailableToSpend(ElectrumTestCase):
    def test_DesyncHTLCs(self):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        self.assertEqual(499986152000 if not alice_channel.has_anchors() else 499980692000, alice_channel.available_to_spend(LOCAL))
        self.assertEqual(500000000000, bob_channel.available_to_spend(LOCAL))

        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        htlc = UpdateAddHtlc(
            payment_hash=paymentHash,
            amount_msat=one_bitcoin_in_msat * 41 // 10,
            cltv_abs=5,
            timestamp=0,
        )

        alice_idx = alice_channel.add_htlc(htlc).htlc_id
        bob_idx = bob_channel.receive_htlc(htlc).htlc_id
        self.assertEqual(89984088000 if not alice_channel.has_anchors() else 89978628000, alice_channel.available_to_spend(LOCAL))
        self.assertEqual(500000000000, bob_channel.available_to_spend(LOCAL))

        force_state_transition(alice_channel, bob_channel)
        bob_channel.fail_htlc(bob_idx)
        alice_channel.receive_fail_htlc(alice_idx, error_bytes=None)
        self.assertEqual(89984088000 if not alice_channel.has_anchors() else 89978628000, alice_channel.available_to_spend(LOCAL))
        self.assertEqual(500000000000, bob_channel.available_to_spend(LOCAL))
        # Alice now has gotten all her original balance (5 BTC) back, however,
        # adding a new HTLC at this point SHOULD fail, since if she adds the
        # HTLC and signs the next state, Bob cannot assume she received the
        # FailHTLC, and must assume she doesn't have the necessary balance
        # available.
        # We try adding an HTLC of value 1 BTC, which should fail because the
        # balance is unavailable.
        htlc = UpdateAddHtlc(
            payment_hash=paymentHash,
            amount_msat=one_bitcoin_in_msat,
            cltv_abs=5,
            timestamp=0,
        )
        with self.assertRaises(lnutil.PaymentFailure):
            alice_channel.add_htlc(htlc)
        # Now do a state transition, which will ACK the FailHTLC, making Alice
        # able to add the new HTLC.
        force_state_transition(alice_channel, bob_channel)
        self.assertEqual(499986152000 if not alice_channel.has_anchors() else 499980692000, alice_channel.available_to_spend(LOCAL))
        self.assertEqual(500000000000, bob_channel.available_to_spend(LOCAL))
        alice_channel.add_htlc(htlc)


class TestAvailableToSpendAnchors(TestAvailableToSpend):
    TEST_ANCHOR_CHANNELS = True


class TestChanReserve(ElectrumTestCase):
    def setUp(self):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=False)
        alice_min_reserve = int(.5 * one_bitcoin_in_msat // 1000)
        # We set Bob's channel reserve to a value that is larger than
        # his current balance in the channel. This will ensure that
        # after a channel is first opened, Bob can still receive HTLCs
        # even though his balance is less than his channel reserve.
        bob_min_reserve = 6 * one_bitcoin_in_msat // 1000
        # bob min reserve was decided by alice, but applies to bob

        alice_channel.config[LOCAL].reserve_sat = bob_min_reserve
        alice_channel.config[REMOTE].reserve_sat = alice_min_reserve

        bob_channel.config[LOCAL].reserve_sat = alice_min_reserve
        bob_channel.config[REMOTE].reserve_sat = bob_min_reserve

        self.alice_channel = alice_channel
        self.bob_channel = bob_channel

    @unittest.skip("broken probably because we haven't implemented detecting when we come out of a situation where we violate reserve")
    def test_part1(self):
        # Add an HTLC that will increase Bob's balance. This should succeed,
        # since Alice stays above her channel reserve, and Bob increases his
        # balance (while still being below his channel reserve).
        #
        # Resulting balances:
        #	Alice:	4.5
        #	Bob:	5.0
        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        htlc_dict = {
            'payment_hash': paymentHash,
            'amount_msat': int(.5 * one_bitcoin_in_msat),
            'cltv_abs': 5,
            'timestamp': 0,
        }
        self.alice_channel.add_htlc(htlc_dict)
        self.bob_channel.receive_htlc(htlc_dict)
        # Force a state transition, making sure this HTLC is considered valid
        # even though the channel reserves are not met.
        force_state_transition(self.alice_channel, self.bob_channel)

        aliceSelfBalance = self.alice_channel.balance(LOCAL)\
                - lnchannel.htlcsum(self.alice_channel.hm.htlcs_by_direction(LOCAL, SENT).values())
        bobBalance = self.bob_channel.balance(REMOTE)\
                - lnchannel.htlcsum(self.alice_channel.hm.htlcs_by_direction(REMOTE, SENT).values())
        self.assertEqual(aliceSelfBalance, one_bitcoin_in_msat*4.5)
        self.assertEqual(bobBalance, one_bitcoin_in_msat*5)
        # Now let Bob try to add an HTLC. This should fail, since it will
        # decrease his balance, which is already below the channel reserve.
        #
        # Resulting balances:
        #	Alice:	4.5
        #	Bob:	5.0
        with self.assertRaises(lnutil.PaymentFailure):
            htlc_dict['payment_hash'] = bitcoin.sha256(32 * b'\x02')
            self.bob_channel.add_htlc(htlc_dict)
        with self.assertRaises(lnutil.RemoteMisbehaving):
            self.alice_channel.receive_htlc(htlc_dict)

    def part2(self):
        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        # Now we'll add HTLC of 3.5 BTC to Alice's commitment, this should put
        # Alice's balance at 1.5 BTC.
        #
        # Resulting balances:
        #	Alice:	1.5
        #	Bob:	9.5
        htlc_dict = {
            'payment_hash': paymentHash,
            'amount_msat': int(3.5 * one_bitcoin_in_msat),
            'cltv_abs': 5,
        }
        self.alice_channel.add_htlc(htlc_dict)
        self.bob_channel.receive_htlc(htlc_dict)
        # Add a second HTLC of 1 BTC. This should fail because it will take
        # Alice's balance all the way down to her channel reserve, but since
        # she is the initiator the additional transaction fee makes her
        # balance dip below.
        htlc_dict['amount_msat'] = one_bitcoin_in_msat
        with self.assertRaises(lnutil.PaymentFailure):
            self.alice_channel.add_htlc(htlc_dict)
        with self.assertRaises(lnutil.RemoteMisbehaving):
            self.bob_channel.receive_htlc(htlc_dict)

    def part3(self):
        # Add a HTLC of 2 BTC to Alice, and the settle it.
        # Resulting balances:
        #	Alice:	3.0
        #	Bob:	7.0
        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        htlc_dict = {
            'payment_hash': paymentHash,
            'amount_msat': int(2 * one_bitcoin_in_msat),
            'cltv_abs': 5,
            'timestamp': 0,
        }
        alice_idx = self.alice_channel.add_htlc(htlc_dict).htlc_id
        bob_idx = self.bob_channel.receive_htlc(htlc_dict).htlc_id
        force_state_transition(self.alice_channel, self.bob_channel)
        self.check_bals(one_bitcoin_in_msat * 3
                        - self.alice_channel.get_next_fee(LOCAL),
                        one_bitcoin_in_msat * 5)
        self.bob_channel.settle_htlc(paymentPreimage, bob_idx)
        self.alice_channel.receive_htlc_settle(paymentPreimage, alice_idx)
        force_state_transition(self.alice_channel, self.bob_channel)
        self.check_bals(one_bitcoin_in_msat * 3
                        - self.alice_channel.get_next_fee(LOCAL),
                        one_bitcoin_in_msat * 7)
        # And now let Bob add an HTLC of 1 BTC. This will take Bob's balance
        # all the way down to his channel reserve, but since he is not paying
        # the fee this is okay.
        htlc_dict['amount_msat'] = one_bitcoin_in_msat
        self.bob_channel.add_htlc(htlc_dict)
        self.alice_channel.receive_htlc(htlc_dict)
        force_state_transition(self.alice_channel, self.bob_channel)
        self.check_bals(one_bitcoin_in_msat * 3 \
                        - self.alice_channel.get_next_fee(LOCAL),
                        one_bitcoin_in_msat * 6)

    def check_bals(self, amt1, amt2):
        self.assertEqual(self.alice_channel.available_to_spend(LOCAL), amt1)
        self.assertEqual(self.bob_channel.available_to_spend(REMOTE), amt1)
        self.assertEqual(self.alice_channel.available_to_spend(REMOTE), amt2)
        self.assertEqual(self.bob_channel.available_to_spend(LOCAL), amt2)


class TestChanReserveAnchors(TestChanReserve):
    TEST_ANCHOR_CHANNELS = True


class TestDust(ElectrumTestCase):
    def test_DustLimit(self):
        """Test that addition of an HTLC below the dust limit changes the balances."""
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        dust_limit_alice = alice_channel.config[LOCAL].dust_limit_sat
        dust_limit_bob = bob_channel.config[LOCAL].dust_limit_sat
        self.assertLess(dust_limit_alice, dust_limit_bob)

        bob_ctx = bob_channel.get_latest_commitment(LOCAL)
        bobs_original_outputs = [x.value for x in bob_ctx.outputs()]
        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        fee_per_kw = alice_channel.get_next_feerate(LOCAL)
        success_weight = effective_htlc_tx_weight(success=True, has_anchors=self.TEST_ANCHOR_CHANNELS)
        # we put a single sat less into the htlc than bob can afford
        # to pay for his htlc success transaction
        below_dust_for_bob = dust_limit_bob - 1
        htlc_amt = below_dust_for_bob + success_weight * (fee_per_kw // 1000)
        htlc = {
            'payment_hash': paymentHash,
            'amount_msat': 1000 * htlc_amt,
            'cltv_abs': 5,  # consistent with channel policy
            'timestamp': 0,
        }

        # add the htlc
        alice_htlc_id = alice_channel.add_htlc(htlc).htlc_id
        bob_htlc_id = bob_channel.receive_htlc(htlc).htlc_id
        force_state_transition(alice_channel, bob_channel)
        alice_ctx = alice_channel.get_latest_commitment(LOCAL)
        bob_ctx = bob_channel.get_latest_commitment(LOCAL)
        bobs_second_outputs = [x.value for x in bob_ctx.outputs()]
        self.assertNotEqual(bobs_original_outputs, bobs_second_outputs)
        # the htlc appears as an output in alice's ctx, as she has a lower
        # dust limit (also because her timeout tx costs less)
        self.assertEqual(3, len(alice_ctx.outputs()) - (2 if self.TEST_ANCHOR_CHANNELS else 0))
        # htlc in bob's case goes to miner fees
        self.assertEqual(2, len(bob_ctx.outputs()) - (2 if self.TEST_ANCHOR_CHANNELS else 0))
        self.assertEqual(htlc_amt, sum(bobs_original_outputs) - sum(bobs_second_outputs))
        empty_ctx_fee = lnutil.calc_fees_for_commitment_tx(
            num_htlcs=0, feerate=fee_per_kw, is_local_initiator=True,
            round_to_sat=True, has_anchors=self.TEST_ANCHOR_CHANNELS)[LOCAL] // 1000
        self.assertEqual(empty_ctx_fee + htlc_amt, bob_channel.get_next_fee(LOCAL))

        bob_channel.settle_htlc(paymentPreimage, bob_htlc_id)
        alice_channel.receive_htlc_settle(paymentPreimage, alice_htlc_id)
        force_state_transition(bob_channel, alice_channel)
        bob_ctx = bob_channel.get_latest_commitment(LOCAL)
        bobs_third_outputs = [x.value for x in bob_ctx.outputs()]
        # htlc is added back into the balance
        self.assertEqual(sum(bobs_original_outputs), sum(bobs_third_outputs))
        # balance shifts in bob's direction after settlement
        self.assertEqual(htlc_amt, bobs_third_outputs[1 + (2 if self.TEST_ANCHOR_CHANNELS else 0)] - bobs_original_outputs[1 + (2 if self.TEST_ANCHOR_CHANNELS else 0)])
        self.assertEqual(2, len(alice_channel.get_next_commitment(LOCAL).outputs()) - (2 if self.TEST_ANCHOR_CHANNELS else 0))
        self.assertEqual(2, len(bob_channel.get_next_commitment(LOCAL).outputs()) - (2 if self.TEST_ANCHOR_CHANNELS else 0))
        self.assertEqual(htlc_amt, alice_channel.total_msat(SENT) // 1000)


class TestDustAnchors(TestDust):
    TEST_ANCHOR_CHANNELS = True


def force_state_transition(chanA, chanB):
    chanB.receive_new_commitment(*chanA.sign_next_commitment())
    rev = chanB.revoke_current_commitment()
    bob_sig, bob_htlc_sigs = chanB.sign_next_commitment()
    chanA.receive_revocation(rev)
    chanA.receive_new_commitment(bob_sig, bob_htlc_sigs)
    chanB.receive_revocation(chanA.revoke_current_commitment())
