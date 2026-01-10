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
from functools import lru_cache
from unittest import mock
import os
import binascii
from pprint import pformat
import logging
import dataclasses
import time
from typing import TYPE_CHECKING

from electrum import bitcoin
from electrum import lnpeer
from electrum import lnchannel
from electrum import lnutil
from electrum.crypto import privkey_to_pubkey
from electrum.lnutil import (
    SENT, LOCAL, REMOTE, RECEIVED, UpdateAddHtlc, LnFeatures, secret_to_pubkey, ChannelType,
    effective_htlc_tx_weight, LocalConfig, RemoteConfig, OnlyPubkeyKeypair,
)
from electrum.logging import console_stderr_handler
from electrum.lnchannel import ChannelState, Channel
from electrum.coinchooser import PRNG

from . import ElectrumTestCase

if TYPE_CHECKING:
    from .test_lnpeer import MockLNWallet


one_bitcoin_in_msat = bitcoin.COIN * 1000


def _convert_to_rconfig_from_lconfig(lconfig: LocalConfig) -> RemoteConfig:
    """converts Alice's local config to Bob's remote config (neutering private keys, etc)"""
    ctn = 0
    pcp_secret = lnutil.get_per_commitment_secret_from_seed(
        lconfig.per_commitment_secret_seed,
        lnutil.RevocationStore.START_INDEX - ctn)
    pcp_point = secret_to_pubkey(int.from_bytes(pcp_secret, 'big'))
    rconfig = RemoteConfig(
        payment_basepoint=OnlyPubkeyKeypair(pubkey=lconfig.payment_basepoint.pubkey),
        multisig_key=OnlyPubkeyKeypair(pubkey=lconfig.multisig_key.pubkey),
        htlc_basepoint=OnlyPubkeyKeypair(pubkey=lconfig.htlc_basepoint.pubkey),
        delayed_basepoint=OnlyPubkeyKeypair(pubkey=lconfig.delayed_basepoint.pubkey),
        revocation_basepoint=OnlyPubkeyKeypair(pubkey=lconfig.revocation_basepoint.pubkey),
        to_self_delay=lconfig.to_self_delay,
        dust_limit_sat=lconfig.dust_limit_sat,
        max_htlc_value_in_flight_msat=lconfig.max_htlc_value_in_flight_msat,
        max_accepted_htlcs=lconfig.max_accepted_htlcs,
        initial_msat=lconfig.initial_msat,
        reserve_sat=lconfig.reserve_sat,
        htlc_minimum_msat=lconfig.htlc_minimum_msat,
        upfront_shutdown_script=lconfig.upfront_shutdown_script,
        announcement_node_sig=lconfig.announcement_node_sig,
        announcement_bitcoin_sig=lconfig.announcement_bitcoin_sig,
        next_per_commitment_point=pcp_point,
        current_per_commitment_point=None,
    )
    return rconfig


def create_channel_state(
    *,
    funding_txid: str,
    funding_index: int,
    funding_sat: int,
    is_initiator: bool,
    other_node_id: bytes,
    channel_type: ChannelType,
    local_config: LocalConfig,
    remote_config: RemoteConfig,
):
    channel_id, _ = lnpeer.channel_id_from_funding_tx(funding_txid, funding_index)
    state = {
            "channel_id":channel_id.hex(),
            "short_channel_id":channel_id[:8],
            "funding_outpoint":lnpeer.Outpoint(funding_txid, funding_index),
            "remote_config": remote_config,
            "local_config": local_config,
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
    return state


def create_test_channels(
    *,
    alice_lnwallet: 'MockLNWallet',
    bob_lnwallet: 'MockLNWallet',
    feerate=6000,
    local_msat=None,
    remote_msat=None,
    random_seed=None,
    anchor_outputs: bool = False,
    local_max_inflight=None,
    remote_max_inflight=None,
    max_accepted_htlcs=5,
) -> tuple[Channel, Channel]:
    if random_seed is None:  # needed for deterministic randomness
        random_seed = os.urandom(32)
    random_gen = PRNG(random_seed)
    alice_name = alice_lnwallet.name
    bob_name = bob_lnwallet.name
    alice_pubkey = alice_lnwallet.node_keypair.pubkey
    bob_pubkey = bob_lnwallet.node_keypair.pubkey
    funding_txid = random_gen.get_bytes(32).hex()
    funding_index = 0
    funding_sat = ((local_msat + remote_msat) // 1000) if local_msat is not None and remote_msat is not None else (bitcoin.COIN * 10)
    local_msat = local_msat if local_msat is not None else (funding_sat * 1000 // 2)
    remote_msat = remote_msat if remote_msat is not None else (funding_sat * 1000 // 2)
    local_max_inflight = funding_sat * 1000 if local_max_inflight is None else local_max_inflight
    remote_max_inflight = funding_sat * 1000 if remote_max_inflight is None else remote_max_inflight

    for config in [alice_lnwallet.config, bob_lnwallet.config]:
        config.LIGHTNING_MAX_FUNDING_SAT = max(config.LIGHTNING_MAX_FUNDING_SAT, funding_sat)

    peer_features = alice_lnwallet.features | LnFeatures.OPTION_SUPPORT_LARGE_CHANNEL_OPT
    channel_type = ChannelType.OPTION_STATIC_REMOTEKEY
    if anchor_outputs:
        channel_type |= ChannelType.OPTION_ANCHORS_ZERO_FEE_HTLC_TX
    # create alice's local config
    alice_lconfig = alice_lnwallet.make_local_config_for_new_channel(
        funding_sat=funding_sat,
        push_msat=remote_msat,
        initiator=LOCAL,
        channel_type=channel_type,
        multisig_funding_keypair=None,
        peer_features=peer_features,
        channel_seed=random_gen.get_bytes(32),
    )
    alice_lconfig.funding_locked_received = True
    alice_lconfig.dust_limit_sat = 200
    alice_lconfig.to_self_delay = 5
    alice_lconfig.reserve_sat = 0
    alice_lconfig.max_accepted_htlcs = max_accepted_htlcs
    alice_lconfig.max_htlc_value_in_flight_msat = local_max_inflight
    # create bob's local config
    bob_lconfig = bob_lnwallet.make_local_config_for_new_channel(
        funding_sat=funding_sat,
        push_msat=remote_msat,
        initiator=REMOTE,
        channel_type=channel_type,
        multisig_funding_keypair=None,
        peer_features=peer_features,
        channel_seed=random_gen.get_bytes(32),
    )
    bob_lconfig.funding_locked_received = True
    bob_lconfig.dust_limit_sat = 1300
    bob_lconfig.to_self_delay = 4
    bob_lconfig.reserve_sat = 0
    bob_lconfig.max_accepted_htlcs = max_accepted_htlcs
    bob_lconfig.max_htlc_value_in_flight_msat = remote_max_inflight

    alice, bob = (
        lnchannel.Channel(
            create_channel_state(
                funding_txid=funding_txid,
                funding_index=funding_index,
                funding_sat=funding_sat,
                is_initiator=True,
                other_node_id=bob_pubkey,
                channel_type=channel_type,
                local_config=alice_lconfig,
                remote_config=_convert_to_rconfig_from_lconfig(bob_lconfig),
            ),
            name=f"{alice_name}->{bob_name}",
            initial_feerate=feerate,
            lnworker=alice_lnwallet,
        ),
        lnchannel.Channel(
            create_channel_state(
                funding_txid=funding_txid,
                funding_index=funding_index,
                funding_sat=funding_sat,
                is_initiator=False,
                other_node_id=alice_pubkey,
                channel_type=channel_type,
                local_config=bob_lconfig,
                remote_config=_convert_to_rconfig_from_lconfig(alice_lconfig),
            ),
            name=f"{bob_name}->{alice_name}",
            initial_feerate=feerate,
            lnworker=bob_lnwallet,
        )
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

    alice.open_with_first_pcp(alice.config[REMOTE].next_per_commitment_point, sig_from_bob)
    bob.open_with_first_pcp(bob.config[REMOTE].next_per_commitment_point, sig_from_alice)

    alice_second = lnutil.secret_to_pubkey(int.from_bytes(
        lnutil.get_per_commitment_secret_from_seed(alice.config[LOCAL].per_commitment_secret_seed, lnutil.RevocationStore.START_INDEX - 1), "big"))
    bob_second = lnutil.secret_to_pubkey(int.from_bytes(
        lnutil.get_per_commitment_secret_from_seed(bob.config[LOCAL].per_commitment_secret_seed, lnutil.RevocationStore.START_INDEX - 1), "big"))

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

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice_lnwallet = self.create_mock_lnwallet(name="alice", has_anchors=self.TEST_ANCHOR_CHANNELS)
        self.bob_lnwallet = self.create_mock_lnwallet(name="bob", has_anchors=self.TEST_ANCHOR_CHANNELS)

    async def test_fee(self):
        alice_channel, bob_channel = create_test_channels(
            feerate=253,
            local_msat=10_000_000_000,
            remote_msat=5_000_000_000,
            anchor_outputs=self.TEST_ANCHOR_CHANNELS,
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
        self.alice_lnwallet = self.create_mock_lnwallet(name="alice", has_anchors=self.TEST_ANCHOR_CHANNELS)
        self.bob_lnwallet = self.create_mock_lnwallet(name="bob", has_anchors=self.TEST_ANCHOR_CHANNELS)

        # Create a test channel which will be used for the duration of this
        # unittest. The channel will be funded evenly with Alice having 5 BTC,
        # and Bob having 5 BTC.
        self.alice_channel, self.bob_channel = create_test_channels(
            anchor_outputs=self.TEST_ANCHOR_CHANNELS, alice_lnwallet=self.alice_lnwallet, bob_lnwallet=self.bob_lnwallet)

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

class TestChannelAnchors(TestChannel):
    TEST_ANCHOR_CHANNELS = True


class TestAvailableToSpend(ElectrumTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice_lnwallet = self.create_mock_lnwallet(name="alice", has_anchors=self.TEST_ANCHOR_CHANNELS)
        self.bob_lnwallet = self.create_mock_lnwallet(name="bob", has_anchors=self.TEST_ANCHOR_CHANNELS)

    async def test_DesyncHTLCs(self):
        alice_channel, bob_channel = create_test_channels(
            anchor_outputs=self.TEST_ANCHOR_CHANNELS, alice_lnwallet=self.alice_lnwallet, bob_lnwallet=self.bob_lnwallet)
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
            anchor_outputs=self.TEST_ANCHOR_CHANNELS,
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


class TestAvailableToSpendAnchors(TestAvailableToSpend):
    TEST_ANCHOR_CHANNELS = True


class TestChanReserve(ElectrumTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        alice_lnwallet = self.create_mock_lnwallet(name="alice", has_anchors=self.TEST_ANCHOR_CHANNELS)
        bob_lnwallet = self.create_mock_lnwallet(name="bob", has_anchors=self.TEST_ANCHOR_CHANNELS)
        alice_channel, bob_channel = create_test_channels(anchor_outputs=False, alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)
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
            htlc = dataclasses.replace(htlc, payment_hash=bitcoin.sha256(32 * b'\x02'))
            self.bob_channel.add_htlc(htlc)
        with self.assertRaises(lnutil.RemoteMisbehaving):
            self.alice_channel.receive_htlc(htlc)

    def part2(self):
        paymentPreimage = b"\x01" * 32
        paymentHash = bitcoin.sha256(paymentPreimage)
        # Now we'll add HTLC of 3.5 BTC to Alice's commitment, this should put
        # Alice's balance at 1.5 BTC.
        #
        # Resulting balances:
        #	Alice:	1.5
        #	Bob:	9.5
        htlc = UpdateAddHtlc(
            payment_hash=paymentHash,
            amount_msat=int(3.5 * one_bitcoin_in_msat),
            cltv_abs=5,
        )
        self.alice_channel.add_htlc(htlc)
        self.bob_channel.receive_htlc(htlc)
        # Add a second HTLC of 1 BTC. This should fail because it will take
        # Alice's balance all the way down to her channel reserve, but since
        # she is the initiator the additional transaction fee makes her
        # balance dip below.
        htlc = dataclasses.replace(htlc, amount_msat=one_bitcoin_in_msat)
        with self.assertRaises(lnutil.PaymentFailure):
            self.alice_channel.add_htlc(htlc)
        with self.assertRaises(lnutil.RemoteMisbehaving):
            self.bob_channel.receive_htlc(htlc)

    def part3(self):
        # Add a HTLC of 2 BTC to Alice, and the settle it.
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
        htlc = dataclasses.replace(htlc, amount_msat=one_bitcoin_in_msat)
        self.bob_channel.add_htlc(htlc)
        self.alice_channel.receive_htlc(htlc)
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
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice_lnwallet = self.create_mock_lnwallet(name="alice", has_anchors=self.TEST_ANCHOR_CHANNELS)
        self.bob_lnwallet = self.create_mock_lnwallet(name="bob", has_anchors=self.TEST_ANCHOR_CHANNELS)

    async def test_DustLimit(self):
        """Test that addition of an HTLC below the dust limit changes the balances."""
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS, alice_lnwallet=self.alice_lnwallet, bob_lnwallet=self.bob_lnwallet)
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


class TestDustAnchors(TestDust):
    TEST_ANCHOR_CHANNELS = True


def force_state_transition(chanA, chanB):
    chanB.receive_new_commitment(*chanA.sign_next_commitment())
    rev = chanB.revoke_current_commitment()
    bob_sig, bob_htlc_sigs = chanB.sign_next_commitment()
    chanA.receive_revocation(rev)
    chanA.receive_new_commitment(bob_sig, bob_htlc_sigs)
    chanB.receive_revocation(chanA.revoke_current_commitment())
