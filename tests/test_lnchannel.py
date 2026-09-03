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
from unittest import mock
import os
import logging
import dataclasses
import time

import electrum_ecc as ecc

from electrum import bitcoin
from electrum import lnchannel
from electrum import lnutil
from electrum.crypto import sha256
from electrum.lnutil import (
    SENT, LOCAL, REMOTE, RECEIVED, UpdateAddHtlc, ChannelType,
    effective_htlc_tx_weight, ZEROCONF_TIMEOUT,
    CHANNEL_OPENING_TIMEOUT_SEC,
)
from electrum.logging import console_stderr_handler
from electrum.lnchannel import ChannelState, Channel
from electrum.lnsweep import SweepInfo
from electrum.transaction import PartialTransaction, PartialTxOutput, Transaction, TxInput, tx_from_any

from . import ElectrumTestCase
from .lnhelpers import create_test_channels


one_bitcoin_in_msat = bitcoin.COIN * 1000


class TestFee(ElectrumTestCase):
    """
    test
    https://github.com/lightningnetwork/lightning-rfc/blob/e0c436bd7a3ed6a028e1cb472908224658a14eca/03-transactions.md#requirements-2
    """

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice_lnwallet = self.create_mock_lnwallet(name="alice")
        self.bob_lnwallet = self.create_mock_lnwallet(name="bob")

    async def test_fee(self):
        alice_channel, bob_channel = create_test_channels(
            feerate=253,
            local_msat=10_000_000_000,
            remote_msat=5_000_000_000,
            alice_lnwallet=self.alice_lnwallet,
            bob_lnwallet=self.bob_lnwallet,
        )
        expected_value = 9_999_056 if self.TEST_ANCHOR_CHANNELS else 9_999_817
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

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice_lnwallet = self.create_mock_lnwallet(name="alice")
        self.bob_lnwallet = self.create_mock_lnwallet(name="bob")

        # Create a test channel which will be used for the duration of this
        # unittest. The channel will be funded evenly with Alice having 5 BTC,
        # and Bob having 5 BTC.
        self.alice_channel, self.bob_channel = create_test_channels(
            alice_lnwallet=self.alice_lnwallet, bob_lnwallet=self.bob_lnwallet)

        self.paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(self.paymentPreimage)
        self.htlc = UpdateAddHtlc(
            payment_hash=paymentHash,
            amount_msat=one_bitcoin_in_msat,
            cltv_abs=5,
            timestamp=0,
        )

        # First Alice adds the outgoing HTLC to her local channel's state
        # update log. Then Alice sends this wire message over to Bob who adds
        # this htlc to his remote state update log.
        self.aliceHtlcIndex = self.alice_channel.add_htlc(self.htlc).htlc_id
        self.assertNotEqual(list(self.alice_channel.hm.htlcs_by_direction(REMOTE, RECEIVED, 1).values()), [])

        before = self.bob_channel.balance_minus_outgoing_htlcs(REMOTE)
        beforeLocal = self.bob_channel.balance_minus_outgoing_htlcs(LOCAL)

        self.bobHtlcIndex = self.bob_channel.receive_htlc(self.htlc).htlc_id

        self.htlc = self.bob_channel.hm.log[REMOTE]['adds'][0]

    def test_concurrent_reversed_payment(self):
        self.htlc = dataclasses.replace(
            self.htlc,
            payment_hash=bitcoin.sha256(32 * b'\x02'),
            amount_msat=self.htlc.amount_msat + 1000,
        )
        self.bob_channel.add_htlc(self.htlc)
        self.alice_channel.receive_htlc(self.htlc)

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

    async def test_SimpleAddSettleWorkflow(self):
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

        self.assertEqual(alice_channel.balance(LOCAL, ctx_owner=LOCAL), 500000000000)
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

        self.htlc = dataclasses.replace(
            self.htlc,
            amount_msat=self.htlc.amount_msat * 5,
        )
        bob_index = bob_channel.add_htlc(self.htlc).htlc_id
        alice_index = alice_channel.receive_htlc(self.htlc).htlc_id

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

        self.htlc = dataclasses.replace(
            self.htlc,
            payment_hash=bitcoin.sha256(32 * b'\x02'),
        )
        self.alice_channel.add_htlc(self.htlc)
        self.htlc = dataclasses.replace(
            self.htlc,
            payment_hash=bitcoin.sha256(32 * b'\x03'),
        )
        self.alice_channel.add_htlc(self.htlc)
        # now there are three htlcs (one was in setUp)

        # Alice now has an available balance of 2 BTC. We'll add a new HTLC of
        # value 2 BTC, which should make Alice's balance negative (since she
        # has to pay a commitment fee).
        new = dataclasses.replace(
            self.htlc,
            amount_msat=int(self.htlc.amount_msat * 2.5),
            payment_hash=bitcoin.sha256(32 * b'\x04'),
        )
        with self.assertRaises(lnutil.PaymentFailure) as cm:
            self.alice_channel.add_htlc(new)
        self.assertIn('Not enough local balance', cm.exception.args[0])

    def test_unfunded_channel_can_be_removed(self):
        """
        Test that an incoming channel which stays unfunded longer than
        lnutil.CHANNEL_OPENING_TIMEOUT_BLOCKS and lnutil.CHANNEL_OPENING_TIMEOUT_SEC
        can be removed
        """
        # set the init_height and init_timestamp
        self.current_height = 800_000
        self.bob_channel.storage['init_height'] = self.current_height
        self.alice_channel.storage['init_height'] = self.current_height
        self.bob_channel.storage['init_timestamp'] = int(time.time())
        self.alice_channel.storage['init_timestamp'] = int(time.time())

        mock_lnworker = mock.Mock()
        mock_blockchain = mock.Mock()
        mock_lnworker.wallet = mock.Mock()
        mock_lnworker.wallet.is_up_to_date = lambda: True
        mock_blockchain.is_tip_stale = lambda: False
        mock_lnworker.network.blockchain = lambda: mock_blockchain
        mock_lnworker.network.get_local_height = lambda: self.current_height
        self.bob_channel.lnworker = mock_lnworker
        self.alice_channel.lnworker = mock_lnworker

        # test that the non-initiator can remove the channel after timeout
        self.assertFalse(self.bob_channel.is_initiator())
        self.bob_channel._state = ChannelState.OPENING
        self.assertFalse(self.bob_channel.can_be_deleted())
        self.current_height += lnutil.CHANNEL_OPENING_TIMEOUT_BLOCKS + 1
        self.assertFalse(self.bob_channel.can_be_deleted())  # needs both block and time based timeout
        self.bob_channel.storage['init_timestamp'] -= lnutil.CHANNEL_OPENING_TIMEOUT_SEC + 1
        self.alice_channel.storage['init_timestamp'] -= lnutil.CHANNEL_OPENING_TIMEOUT_SEC + 1
        self.assertTrue(self.bob_channel.can_be_deleted())  # now both timeouts are reached
        self.current_height = 800_000  # reset to check if we can delete with just the time based timeout
        self.assertFalse(self.bob_channel.can_be_deleted())

        # test that the initiator can't remove the channel, even after timeout
        self.current_height += lnutil.CHANNEL_OPENING_TIMEOUT_BLOCKS + 1
        self.assertTrue(self.alice_channel.is_initiator())
        self.alice_channel._state = ChannelState.OPENING
        self.assertFalse(self.alice_channel.can_be_deleted())

    async def test_update_unfunded_zeroconf_channel(self):
        """Cover the zeroconf branch of update_unfunded_state"""
        chan = self.bob_channel
        chan.set_state(ChannelState.OPEN, force=True)
        bob = self.bob_lnwallet
        self.assertFalse(chan.is_initiator())
        trusted_node = f"{chan.node_id.hex()}@127.0.0.1:9735"
        chan.storage['channel_type'] |= ChannelType.OPTION_ZEROCONF
        self.assertTrue(chan.is_zeroconf())
        # add channel to lnwallet/db
        bob._channels[chan.channel_id] = chan
        bob.db.get('channels')[chan.channel_id.hex()] = "something"
        self.assertIsNotNone(bob.get_channel_by_id(chan.channel_id))
        chan.storage['init_height'] = 0  # checked by has_funding_timed_out
        chan.storage['init_timestamp'] = int(time.time())
        self.assertEqual(chan.get_state(), ChannelState.OPEN)
        self.assertEqual(chan.balance(LOCAL), 500000000000)
        bob.config.ZEROCONF_TRUSTED_NODE = trusted_node

        chan.update_unfunded_state()

        # assert nothing happened
        self.assertIsNotNone(bob.get_channel_by_id(chan.channel_id))
        self.assertIsNotNone(bob.db.get('channels').get(chan.channel_id.hex()))
        self.assertEqual(chan.get_state(), ChannelState.OPEN)
        self.assertEqual(bob.config.ZEROCONF_TRUSTED_NODE, trusted_node)

        # now time out zeroconf funding and try again, however her wallet is not up to date
        chan.storage['init_timestamp'] -= ZEROCONF_TIMEOUT + 1
        bob.wallet.is_up_to_date = lambda: False

        chan.update_unfunded_state()

        # assert nothing happened again
        self.assertIsNotNone(bob.get_channel_by_id(chan.channel_id))
        self.assertIsNotNone(bob.db.get('channels').get(chan.channel_id.hex()))
        self.assertEqual(chan.get_state(), ChannelState.OPEN)
        self.assertEqual(bob.config.ZEROCONF_TRUSTED_NODE, trusted_node)
        self.assertFalse(chan.is_frozen_for_receiving())

        # now her wallet is synced, and the channel is still unfunded
        bob.wallet.is_up_to_date = lambda: True

        chan.update_unfunded_state()

        # check zeroconf provider gets unset
        self.assertEqual(bob.config.ZEROCONF_TRUSTED_NODE, "")
        self.assertFalse(chan.has_funding_timed_out())
        self.assertTrue(chan.is_frozen_for_receiving())

        # time out funding (~2 weeks)
        chan.storage['init_timestamp'] -= CHANNEL_OPENING_TIMEOUT_SEC + 1
        self.assertTrue(chan.has_funding_timed_out())

        chan.update_unfunded_state()

        # check that channel got removed, now that funding has timed out
        self.assertIsNone(self.alice_lnwallet.get_channel_by_id(chan.channel_id))
        self.assertIsNone(self.alice_lnwallet.db.get('channels').get(chan.channel_id.hex()))

    async def test_should_be_closed_due_to_expiring_htlcs_offered_htlcs(self):
        alice_lnwallet = self.create_mock_lnwallet(name="alice")
        bob_lnwallet = self.create_mock_lnwallet(name="bob")
        alice_channel, bob_channel = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)

        # no htlcs
        self.assertFalse(alice_channel.should_be_closed_due_to_expiring_htlcs(local_height=100))

        # one offered htlc, not expired
        htlc = UpdateAddHtlc(payment_hash=sha256(os.urandom(32)), amount_msat=one_bitcoin_in_msat, cltv_abs=1000)
        alice_channel.add_htlc(htlc)
        alice_channel.sign_next_commitment()
        self.assertFalse(alice_channel.should_be_closed_due_to_expiring_htlcs(local_height=100))

        # expired offered htlc, within startup grace period
        expired_local_height = 1000 + lnutil.NBLOCK_DEADLINE_DELTA_AFTER_EXPIRY_FOR_OFFERED_HTLCS + 5
        self.assertFalse(alice_channel.should_be_closed_due_to_expiring_htlcs(expired_local_height))

        # expired offered htlc, past startup grace period
        alice_lnwallet.instantiation_timestamp -= (lnutil.TIME_FOR_OFFERED_HTLCS_TO_GET_FAILED_OFFCHAIN_ON_RESTART + 10)
        self.assertTrue(alice_channel.should_be_closed_due_to_expiring_htlcs(expired_local_height))

    async def test_should_be_closed_due_to_expiring_htlcs_received_htlcs(self):
        alice_lnwallet = self.create_mock_lnwallet(name="alice")
        bob_lnwallet = self.create_mock_lnwallet(name="bob")
        alice_channel, bob_channel = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)

        preimage = os.urandom(32)
        htlc = UpdateAddHtlc(payment_hash=sha256(preimage), amount_msat=one_bitcoin_in_msat, cltv_abs=100)
        expired_height = 100 + lnutil.NBLOCK_DEADLINE_DELTA_BEFORE_EXPIRY_FOR_RECEIVED_HTLCS + 5
        alice_channel.add_htlc(htlc)
        bob_htlc_id =  bob_channel.receive_htlc(htlc).htlc_id
        force_state_transition(alice_channel, bob_channel)

        # preimage wasn't released
        self.assertFalse(bob_channel.should_be_closed_due_to_expiring_htlcs(local_height=expired_height))

        # now the preimage is released
        bob_channel.settle_htlc(preimage, bob_htlc_id)

        # still in 30s grace period waiting for peers revack
        self.assertFalse(bob_channel.should_be_closed_due_to_expiring_htlcs(local_height=expired_height))

        # now the settled htlc is past the grace period
        bob_channel.htlc_settle_time[bob_htlc_id] = int(time.time()) - 60
        self.assertTrue(bob_channel.should_be_closed_due_to_expiring_htlcs(local_height=expired_height))

        # if bob force-closes, the sweep info for the received htlc must expose the correct cltv heights for both sides.
        bob_lnwallet.save_preimage(htlc.payment_hash, preimage, mark_as_public=True)
        is_local_ctx, sweep_info_dict = bob_channel.get_ctx_sweep_info(bob_channel.force_close_tx())
        self.assertTrue(is_local_ctx)
        sweep_infos = [si for si in sweep_info_dict.values() if si.name == 'received-htlc']
        self.assertEqual(1, len(sweep_infos))
        self.assertEqual(0, sweep_infos[0].our_cltv_abs)
        self.assertEqual(htlc.cltv_abs, sweep_infos[0].their_cltv_abs)

        # while the htlc-success tx is not broadcast yet, the user must be warned to stay online
        lnwatcher = bob_lnwallet.lnwatcher
        with mock.patch.object(lnwatcher.adb, 'get_local_height', return_value=htlc.cltv_abs - 1):
            lnwatcher.maybe_add_pending_forceclose(
                chan=bob_channel,
                spender_txid=None,
                is_local_ctx=is_local_ctx,
                sweep_info=sweep_infos[0],
            )
        self.assertEqual({bob_channel: htlc.cltv_abs}, lnwatcher.get_pending_force_closes())
        # but not forever: once alice had plenty of time to time out the htlc, we stop warning
        lnwatcher._pending_force_closes.clear()
        with mock.patch.object(
            lnwatcher.adb,
            'get_local_height',
            return_value=htlc.cltv_abs + lnutil.REDEEM_AFTER_DOUBLE_SPENT_DELAY + 1,
        ):
            lnwatcher.maybe_add_pending_forceclose(
                chan=bob_channel,
                spender_txid=None,
                is_local_ctx=is_local_ctx,
                sweep_info=sweep_infos[0],
            )
        self.assertEqual({}, lnwatcher.get_pending_force_closes())


class TestChannelNoAnchors(TestChannel):
    assert TestChannel.TEST_ANCHOR_CHANNELS is True
    TEST_ANCHOR_CHANNELS = False


class TestAvailableToSpend(ElectrumTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice_lnwallet = self.create_mock_lnwallet(name="alice")
        self.bob_lnwallet = self.create_mock_lnwallet(name="bob")

    async def test_DesyncHTLCs(self):
        alice_channel, bob_channel = create_test_channels(
            alice_lnwallet=self.alice_lnwallet, bob_lnwallet=self.bob_lnwallet)
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

    async def test_single_payment(self):
        alice_channel, bob_channel = create_test_channels(
            local_msat=4000000000,
            remote_msat=4000000000,
            local_max_inflight=1000000000,
            remote_max_inflight=2000000000,
            alice_lnwallet=self.alice_lnwallet,
            bob_lnwallet=self.bob_lnwallet,
        )

        # alice can send 20 but bob can only receive 10, because of stricter receiving rules
        self.assertEqual(2000000000, alice_channel.available_to_spend(LOCAL))
        self.assertEqual(1000000000, bob_channel.available_to_spend(REMOTE))

        # bob can send 10, alice can receive 10
        self.assertEqual(1000000000, bob_channel.available_to_spend(LOCAL))
        self.assertEqual(1000000000, alice_channel.available_to_spend(REMOTE))

        paymentPreimage1 = b"\x01" * 32
        htlc = UpdateAddHtlc(
            payment_hash=bitcoin.sha256(paymentPreimage1),
            amount_msat=1000000000,
            cltv_abs=5,
            timestamp=0,
        )
        # put 10mBTC inflight a->b
        alice_idx1 = alice_channel.add_htlc(htlc).htlc_id
        bob_idx1 = bob_channel.receive_htlc(htlc).htlc_id
        force_state_transition(alice_channel, bob_channel)

        self.assertEqual(1000000000, alice_channel.available_to_spend(LOCAL))
        self.assertEqual(0, bob_channel.available_to_spend(REMOTE))

        self.assertEqual(1000000000, bob_channel.available_to_spend(LOCAL))
        self.assertEqual(1000000000, alice_channel.available_to_spend(REMOTE))

        paymentPreimage2 = b"\x02" * 32
        htlc2 = UpdateAddHtlc(
            payment_hash=bitcoin.sha256(paymentPreimage2),
            amount_msat=1500000000,
            cltv_abs=5,
            timestamp=0,
        )
        # try to add another 15mBTC HTLC while 15mBTC already inflight
        with self.assertRaises(lnutil.PaymentFailure):
            alice_idx2 = alice_channel.add_htlc(htlc2).htlc_id

        # settle htlc 1 to clear inflight
        bob_channel.settle_htlc(paymentPreimage1, bob_idx1)
        alice_channel.receive_htlc_settle(paymentPreimage1, alice_idx1)
        force_state_transition(alice_channel, bob_channel)

        self.assertEqual(2000000000, alice_channel.available_to_spend(LOCAL))
        self.assertEqual(1000000000, alice_channel.available_to_spend(REMOTE))

        self.assertEqual(1000000000, bob_channel.available_to_spend(LOCAL))
        self.assertEqual(1000000000, alice_channel.available_to_spend(REMOTE))


class TestAvailableToSpendNoAnchors(TestAvailableToSpend):
    assert TestAvailableToSpend.TEST_ANCHOR_CHANNELS is True
    TEST_ANCHOR_CHANNELS = False


class TestChanReserve(ElectrumTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        alice_lnwallet = self.create_mock_lnwallet(name="alice")
        bob_lnwallet = self.create_mock_lnwallet(name="bob")
        alice_channel, bob_channel = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)
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
        htlc = UpdateAddHtlc(
            payment_hash=paymentHash,
            amount_msat=int(.5 * one_bitcoin_in_msat),
            cltv_abs=5,
            timestamp=0,
        )
        self.alice_channel.add_htlc(htlc)
        self.bob_channel.receive_htlc(htlc)
        # Force a state transition, making sure this HTLC is considered valid
        # even though the channel reserves are not met.
        force_state_transition(self.alice_channel, self.bob_channel)

        self.check_bals(int(4.5 * one_bitcoin_in_msat), one_bitcoin_in_msat * 5)
        # Now let Bob try to add an HTLC. This should fail, since it will
        # decrease his balance, which is already below the channel reserve.
        #
        # Resulting balances:
        #	Alice:	4.5
        #	Bob:	5.0
        htlc = dataclasses.replace(htlc, payment_hash=bitcoin.sha256(32 * b'\x02'))
        with self.assertRaises(lnutil.PaymentFailure):
            self.bob_channel.add_htlc(htlc)
        with self.assertRaises(lnutil.RemoteMisbehaving):
            self.alice_channel.receive_htlc(htlc)

    def test_part2(self):
        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        # Now we'll add HTLC of 3.5 BTC to Alice's commitment, this should put
        # Alice's balance at 1.5 BTC.
        #
        # Resulting balances:
        #	Alice:	1.5
        #	Bob:	5.0
        htlc = UpdateAddHtlc(
            payment_hash=paymentHash,
            amount_msat=int(3.5 * one_bitcoin_in_msat),
            cltv_abs=5,
            timestamp=0,
        )
        self.alice_channel.add_htlc(htlc)
        self.bob_channel.receive_htlc(htlc)
        # Add a second HTLC of 1 BTC. This should fail because it will take
        # Alice's balance all the way down to her channel reserve, but since
        # she is the initiator the additional transaction fee makes her
        # balance dip below.
        htlc = dataclasses.replace(
            htlc,
            payment_hash=bitcoin.sha256(32 * b'\x02'),
            amount_msat=one_bitcoin_in_msat,
        )
        with self.assertRaises(lnutil.PaymentFailure):
            self.alice_channel.add_htlc(htlc)
        with self.assertRaises(lnutil.RemoteMisbehaving):
            self.bob_channel.receive_htlc(htlc)

    async def test_part3(self):
        # Add a HTLC of 2 BTC to Alice, and then settle it.
        # Resulting balances:
        #	Alice:	3.0
        #	Bob:	7.0
        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        htlc = UpdateAddHtlc(
            payment_hash=paymentHash,
            amount_msat=int(2 * one_bitcoin_in_msat),
            cltv_abs=5,
            timestamp=0,
        )
        alice_idx = self.alice_channel.add_htlc(htlc).htlc_id
        bob_idx = self.bob_channel.receive_htlc(htlc).htlc_id
        force_state_transition(self.alice_channel, self.bob_channel)
        self.check_bals(one_bitcoin_in_msat * 3, one_bitcoin_in_msat * 5)
        # The HTLC is still in-flight, so Bob's balance is unchanged and still
        # below his channel reserve: he cannot send anything.
        self.assertEqual(0, self.bob_channel.available_to_spend(LOCAL))
        self.bob_channel.settle_htlc(paymentPreimage, bob_idx)
        self.alice_channel.receive_htlc_settle(paymentPreimage, alice_idx)
        force_state_transition(self.alice_channel, self.bob_channel)
        self.check_bals(one_bitcoin_in_msat * 3, one_bitcoin_in_msat * 7)
        # And now let Bob add an HTLC of 1 BTC. This will take Bob's balance
        # all the way down to his channel reserve, but since he is not paying
        # the fee this is okay.
        self.assertEqual(one_bitcoin_in_msat, self.bob_channel.available_to_spend(LOCAL))
        htlc = dataclasses.replace(
            htlc,
            payment_hash=bitcoin.sha256(32 * b'\x02'),
            amount_msat=one_bitcoin_in_msat,
        )
        self.bob_channel.add_htlc(htlc)
        self.alice_channel.receive_htlc(htlc)
        force_state_transition(self.alice_channel, self.bob_channel)
        self.check_bals(one_bitcoin_in_msat * 3, one_bitcoin_in_msat * 6)
        self.assertEqual(0, self.bob_channel.available_to_spend(LOCAL))

    def check_bals(self, amt1: int, amt2: int) -> None:
        """Assert Alice's (amt1) and Bob's (amt2) balance in msat, as seen by
        both channels. HTLCs that are still in-flight count towards neither.
        """
        self.assertEqual(amt1, self.alice_channel.balance_minus_outgoing_htlcs(LOCAL))
        self.assertEqual(amt1, self.bob_channel.balance_minus_outgoing_htlcs(REMOTE))
        self.assertEqual(amt2, self.alice_channel.balance_minus_outgoing_htlcs(REMOTE))
        self.assertEqual(amt2, self.bob_channel.balance_minus_outgoing_htlcs(LOCAL))


class TestChanReserveNoAnchors(TestChanReserve):
    assert TestChanReserve.TEST_ANCHOR_CHANNELS is True
    TEST_ANCHOR_CHANNELS = False


class TestDust(ElectrumTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice_lnwallet = self.create_mock_lnwallet(name="alice")
        self.bob_lnwallet = self.create_mock_lnwallet(name="bob")

    async def test_DustLimit(self):
        """Test that addition of an HTLC below the dust limit changes the balances."""
        alice_channel, bob_channel = create_test_channels(alice_lnwallet=self.alice_lnwallet, bob_lnwallet=self.bob_lnwallet)
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
        htlc = UpdateAddHtlc(
            payment_hash=paymentHash,
            amount_msat=1000 * htlc_amt,
            cltv_abs=5,  # consistent with channel policy
            timestamp=0,
        )

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

    async def test_DustLimit_at_trim_threshold(self):
        """An HTLC worth *exactly* the trim threshold must NOT be trimmed.

        BOLT-3 only trims when "the HTLC amount minus the HTLC-timeout/success fee
        would be less than dust_limit_satoshis". For anchor channels that fee is
        zero, so the threshold collapses onto the dust limit itself.
        """
        alice_channel, bob_channel = create_test_channels(
            alice_lnwallet=self.alice_lnwallet, bob_lnwallet=self.bob_lnwallet)
        dust_limit_bob = bob_channel.config[LOCAL].dust_limit_sat
        feerate = bob_channel.get_next_feerate(LOCAL)
        threshold_sat = lnutil.received_htlc_trim_threshold_sat(
            dust_limit_sat=dust_limit_bob, feerate=feerate,
            has_anchors=self.TEST_ANCHOR_CHANNELS)
        htlc = UpdateAddHtlc(
            payment_hash=bitcoin.sha256(b"\x01" * 32),
            amount_msat=1000 * threshold_sat,
            cltv_abs=5,  # consistent with channel policy
            timestamp=0,
        )
        alice_channel.add_htlc(htlc)
        bob_channel.receive_htlc(htlc)

        ctn = bob_channel.get_next_ctn(LOCAL)
        ctx = bob_channel.get_next_commitment(LOCAL)
        _secret, pcp = bob_channel.get_secret_and_point(subject=LOCAL, ctn=ctn)
        # the htlc counts as non-dust for fee purposes...
        self.assertEqual(1, len(bob_channel.included_htlcs(LOCAL, RECEIVED, ctn=ctn)))
        # ...so it must really have an output in the ctx
        self.assertEqual(3, len(ctx.outputs()) - (2 if self.TEST_ANCHOR_CHANNELS else 0))
        self.assertIn(threshold_sat, [x.value for x in ctx.outputs()])
        self.assertEqual(1, len(lnutil.map_htlcs_to_ctx_output_idxs(
            chan=bob_channel, ctx=ctx, pcp=pcp, subject=LOCAL, ctn=ctn)))
        # ...and the peer must be sent exactly one htlc signature for it
        _sig, htlc_sigs = alice_channel.sign_next_commitment()
        self.assertEqual(1, len(htlc_sigs))


class TestDustNoAnchors(TestDust):
    assert TestDust.TEST_ANCHOR_CHANNELS is True
    TEST_ANCHOR_CHANNELS = False


class TestHtlcSpendWitnesses(ElectrumTestCase):
    """Tests Channel htlc onchain preimage extraction (extract_preimage_from_htlc_txin()).

    Scenario for all tests:
    two pending htlcs, one per direction (alice->bob, bob->alice), and alice's ctx gets broadcast.
    The ctx has two htlc outputs, and each spender produces one success and one
    timeout spend of them: bob (remote wrt the ctx) spends them directly, while alice
    (owner of the ctx) spends them through 2nd-stage htlc txs.
    https://github.com/lightning/bolts/blob/444805d12ab98c30006173bb190cd9d6fce9e405/03-transactions.md#offered-htlc-outputs
    """

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice_lnwallet, self.bob_lnwallet = self.create_mock_lnwallet(name="alice"), self.create_mock_lnwallet(name="bob")
        self.alice_channel, self.bob_channel = create_test_channels(alice_lnwallet=self.alice_lnwallet, bob_lnwallet=self.bob_lnwallet)
        local_height = self.alice_lnwallet.network.get_local_height()

        # alice offers an htlc to bob
        self.preimage_ab = os.urandom(32)
        htlc_ab = self.alice_channel.add_htlc(UpdateAddHtlc(
            payment_hash=sha256(self.preimage_ab), amount_msat=one_bitcoin_in_msat, cltv_abs=local_height + 100))
        self.bob_channel.receive_htlc(htlc_ab)

        # bob offers an htlc to alice
        self.preimage_ba = os.urandom(32)
        htlc_ba = self.bob_channel.add_htlc(UpdateAddHtlc(
            payment_hash=sha256(self.preimage_ba), amount_msat=2 * one_bitcoin_in_msat, cltv_abs=local_height + 200))
        self.alice_channel.receive_htlc(htlc_ba)

        # commit both htlcs, so that alice's ctx contains their two htlc outputs
        force_state_transition(self.alice_channel, self.bob_channel)
        self.alice_ctx = tx_from_any(self.alice_channel.force_close_tx().serialize())

    def _get_htlc_spend_txins(self, spender_chan: Channel, ctx: Transaction) -> list[TxInput]:
        """Signs spender_chan's spends of the htlc outputs of ctx and returns their txins,
        serialized as they would be seen on-chain.
        """
        txins = []
        _is_local_ctx, sweep_info_dict = spender_chan.get_ctx_sweep_info(ctx)
        for sweep_info in sweep_info_dict.values():
            if not isinstance(sweep_info, SweepInfo) or 'htlc' not in sweep_info.name:
                continue
            txin = sweep_info.txin
            # sweep_info.txout is only set for 2nd-stage htlc txs; direct spends claim to a wallet address
            txout = sweep_info.txout or PartialTxOutput.from_address_and_value(
                spender_chan.lnworker.wallet.get_receiving_address(), txin.value_sats() - 1000)
            tx = PartialTransaction.from_io([txin], [txout], locktime=sweep_info.our_cltv_abs, version=2)
            spender_chan.lnworker.wallet.sign_transaction(tx, password=None, ignore_warnings=True)
            txins.append(tx_from_any(tx.serialize()).inputs()[0])
        return txins

    async def test_extract_preimage_direct_htlc_claim(self):
        """Bob claims the alice->bob htlc on-chain with his preimage.
        Alice extracts the preimage from his claim."""
        self.bob_lnwallet.save_preimage(sha256(self.preimage_ab), self.preimage_ab, mark_as_public=True)
        self.assertIsNone(self.alice_lnwallet.get_preimage(sha256(self.preimage_ab)))
        # bob's direct spends of alice's ctx:
        #   preimage claim of htlc_ab: <remotehtlcsig> <payment_preimage> <witness_script>
        #   timeout spend of htlc_ba:  <remotehtlcsig> <> <witness_script>
        txins = self._get_htlc_spend_txins(spender_chan=self.bob_channel, ctx=self.alice_ctx)
        self.assertEqual(2, len(txins))
        for txin in txins:
            self.assertEqual(3, len(txin.witness_elements()))
            self.alice_channel.extract_preimage_from_htlc_txin(txin, is_deeply_mined=True)
        # alice extracted the preimage from the claim
        self.assertEqual(self.preimage_ab, self.alice_lnwallet.get_preimage(sha256(self.preimage_ab)))

    async def test_extract_preimage_second_stage_htlc_claim(self):
        """Alice claims the bob->alice htlc from her own ctx with a 2nd-stage HTLC-success tx.
        Bob extracts the preimage from it."""
        self.alice_lnwallet.save_preimage(sha256(self.preimage_ba), self.preimage_ba, mark_as_public=True)
        self.assertIsNone(self.bob_lnwallet.get_preimage(sha256(self.preimage_ba)))
        # alice's presigned 2nd-stage spends of her own ctx:
        #   HTLC-success for htlc_ba: 0 <remotehtlcsig> <localhtlcsig> <payment_preimage> <witness_script>
        #   HTLC-timeout for htlc_ab: 0 <remotehtlcsig> <localhtlcsig> <> <witness_script>
        txins = self._get_htlc_spend_txins(spender_chan=self.alice_channel, ctx=self.alice_ctx)
        self.assertEqual(2, len(txins))
        for txin in txins:
            self.assertEqual(5, len(txin.witness_elements()))
            self.bob_channel.extract_preimage_from_htlc_txin(txin, is_deeply_mined=True)
        # bob extracted the preimage from the HTLC-success tx
        self.assertEqual(self.preimage_ba, self.bob_lnwallet.get_preimage(sha256(self.preimage_ba)))

    async def test_no_preimage_in_bobs_justice_spends_of_alices_revoked_ctx(self):
        """Alice broadcasts her ctx after it got revoked, and bob spends its htlc outputs
        with justice txs."""
        # advance the channel state, revoking self.alice_ctx
        htlc = self.alice_channel.add_htlc(UpdateAddHtlc(
            payment_hash=sha256(os.urandom(32)),
            amount_msat=one_bitcoin_in_msat,
            cltv_abs=self.alice_lnwallet.network.get_local_height() + 300))
        self.bob_channel.receive_htlc(htlc)
        force_state_transition(self.alice_channel, self.bob_channel)

        # bob's justice spends of the htlc outputs of alice's revoked ctx:
        #   <revocation_sig> <revocationpubkey> <witness_script>
        txins = self._get_htlc_spend_txins(spender_chan=self.bob_channel, ctx=self.alice_ctx)
        self.assertEqual(2, len(txins))
        for txin in txins:
            self.assertEqual(3, len(txin.witness_elements()))
            self.assertTrue(ecc.ECPubkey.is_pubkey_bytes(txin.witness_elements()[1]))   # revocationpubkey
            self.bob_channel.extract_preimage_from_htlc_txin(txin, is_deeply_mined=True)

        # the revocationpubkey must not have been mistaken for a preimage (or cause any crash)
        self.assertEqual({}, self.bob_lnwallet._preimages)


class TestHtlcSpendWitnessesSRK(TestHtlcSpendWitnesses):
    assert TestHtlcSpendWitnesses.TEST_ANCHOR_CHANNELS is True
    TEST_ANCHOR_CHANNELS = False


def force_state_transition(chanA: Channel, chanB: Channel) -> None:
    chanB.receive_new_commitment(*chanA.sign_next_commitment())
    rev = chanB.revoke_current_commitment()
    bob_sig, bob_htlc_sigs = chanB.sign_next_commitment()
    chanA.receive_revocation(rev)
    chanA.receive_new_commitment(bob_sig, bob_htlc_sigs)
    chanB.receive_revocation(chanA.revoke_current_commitment())
