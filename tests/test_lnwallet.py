import asyncio
import dataclasses
import logging
import os
from unittest import mock
from decimal import Decimal
from typing import Optional
import time
from unittest.mock import patch

from electrum_ecc import ECPrivkey

from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum import bitcoin
import electrum.trampoline
from electrum.onion_message import NoOnionMessagePeers
from electrum import constants
from electrum.bolt12 import BOLT12Offer, BOLT12InvoiceRequest, BOLT12Invoice
from electrum.crypto import sha256, hmac_oneshot
from electrum.lnonion import BlindedPath, BlindedPathHop, BlindedPathInfo, BlindedPayInfo
from electrum.lnutil import RECEIVED, MIN_FINAL_CLTV_DELTA_ACCEPTED, serialize_htlc_key, LnFeatures, HTLCOwner
from electrum.logging import console_stderr_handler
from electrum.lntransport import LNPeerAddr
from electrum.invoices import LN_EXPIRY_NEVER, PR_UNPAID
from electrum.lnpeer import Peer
from electrum.lnchannel import Channel, ChannelState
from electrum.lnonion import OnionPacket, OnionRoutingFailure
from electrum.crypto import sha256
from electrum.simple_config import SimpleConfig

from . import ElectrumTestCase, lnhelpers
from .lnhelpers import create_test_channels


class TestLNWallet(ElectrumTestCase):
    TESTNET = True
    TEST_ANCHOR_CHANNELS = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    async def asyncSetUp(self):
        self.lnwallet_anchors = self.create_mock_lnwallet(name='mock_lnwallet_anchors')
        await super().asyncSetUp()

    def test_create_payment_info(self):
        wallet = self.lnwallet_anchors
        tests = (
            (100_000, 200, 100),
            (None, 200, 100),
            (None, None, LN_EXPIRY_NEVER),
            (100_000, None, 0),
        )
        for amount_msat, min_final_cltv_delta, exp_delay in tests:
            payment_hash = wallet.create_payment_info(
                amount_msat=amount_msat,
                min_final_cltv_delta=min_final_cltv_delta,
                exp_delay=exp_delay,
            )
            self.assertIsNotNone(wallet.get_preimage(payment_hash))
            pi = wallet.get_payment_info(payment_hash, direction=RECEIVED)
            self.assertEqual(pi.amount_msat, amount_msat)
            self.assertEqual(pi.min_final_cltv_delta, min_final_cltv_delta or MIN_FINAL_CLTV_DELTA_ACCEPTED)
            self.assertEqual(pi.expiry_delay, exp_delay or LN_EXPIRY_NEVER)
            self.assertEqual(pi.db_key, f"{payment_hash.hex()}:{int(pi.direction)}")
            self.assertEqual(pi.status, PR_UNPAID)
        self.assertIsNone(wallet.get_payment_info(os.urandom(32), direction=RECEIVED))

    def test_create_payment_info__amount_must_not_be_zero(self):
        wallet = self.lnwallet_anchors
        amount_msat, min_final_cltv_delta, exp_delay = (0, 200, 100)
        with self.assertRaises(ValueError):
            wallet.create_payment_info(
                amount_msat=amount_msat,
                min_final_cltv_delta=min_final_cltv_delta,
                exp_delay=exp_delay,
            )

    async def test_trampoline_invoice_features_and_routing_hints(self):
        """
        When the invoice_features signal trampoline support, routing hints must only
        contain trampoline nodes. When it does not, all channel can be added as r_tags.
        We only signal trampoline support in the invoice if all open channels do support trampoline.
        """
        wallet = self.lnwallet_anchors
        self.assertFalse(wallet.uses_trampoline())

        trampoline_peer = self.create_mock_lnwallet(name='trampoline_peer')
        trampoline_pubkey = trampoline_peer.node_keypair.pubkey

        regular_peer = self.create_mock_lnwallet(name='regular_peer')
        regular_pubkey = regular_peer.node_keypair.pubkey

        chan_t, _ = create_test_channels(alice_lnwallet=wallet, bob_lnwallet=trampoline_peer)
        chan_r, _ = create_test_channels(alice_lnwallet=wallet, bob_lnwallet=regular_peer)
        wallet._add_channel(chan_t)
        wallet._add_channel(chan_r)

        # only trampoline_peer is a known trampoline forwarder
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            'trampoline_peer': LNPeerAddr(
                host="127.0.0.1",
                port=9735,
                pubkey=trampoline_pubkey,
            ),
        }
        self.addCleanup(lambda: electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS.clear())

        amount_msat = 100_000

        # mixed peers: trampoline feature must be stripped, all peers in hints
        payment_hash = wallet.create_payment_info(amount_msat=amount_msat)
        pi = wallet.get_payment_info(payment_hash, direction=RECEIVED)
        self.assertFalse(
            pi.invoice_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM),
            "trampoline bit should be stripped when not all peers are trampoline",
        )

        lnaddr, _ = wallet.get_bolt11_invoice(payment_info=pi, message='test', fallback_address=None)
        hint_node_ids = {route[0][0] for route in lnaddr.get_routing_info('r')}
        self.assertEqual(hint_node_ids, {trampoline_pubkey, regular_pubkey})

        # trampoline feature should not be set if we use trampoline but one peer is not a trampoline
        old_check, wallet.uses_trampoline = wallet.uses_trampoline, lambda: True
        self.assertTrue(wallet.uses_trampoline())

        payment_hash = wallet.create_payment_info(amount_msat=amount_msat)
        pi = wallet.get_payment_info(payment_hash, direction=RECEIVED)
        self.assertFalse(
            pi.invoice_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM),
            "trampoline feature should not be set if we use trampoline but one peer is not a trampoline",
        )

        wallet.clear_invoices_cache()
        lnaddr, _ = wallet.get_bolt11_invoice(payment_info=pi, message='test', fallback_address=None)
        hint_node_ids = {route[0][0] for route in lnaddr.get_routing_info('r')}
        self.assertEqual(hint_node_ids, {trampoline_pubkey, regular_pubkey})

        wallet.uses_trampoline = old_check
        self.assertFalse(wallet.uses_trampoline())

        # all peers trampoline: we signal trampoline support, even with trampoline disabled
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS['regular_peer'] = LNPeerAddr(
            host="127.0.0.1",
            port=9735,
            pubkey=regular_pubkey,
        )

        payment_hash2 = wallet.create_payment_info(amount_msat=amount_msat)
        pi2 = wallet.get_payment_info(payment_hash2, direction=RECEIVED)
        self.assertTrue(
            pi2.invoice_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM),
            "trampoline bit should be present when all peers are trampoline",
        )

        wallet.clear_invoices_cache()
        lnaddr2, _ = wallet.get_bolt11_invoice(payment_info=pi2, message='test', fallback_address=None)
        hint_node_ids2 = {route[0][0] for route in lnaddr2.get_routing_info('r')}
        self.assertEqual(hint_node_ids2, {trampoline_pubkey, regular_pubkey})

        # assert only trampoline peers are included in r_tags if the invoice_features signal trampoline
        del electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS['regular_peer']
        wallet.clear_invoices_cache()
        lnaddr3, _ = wallet.get_bolt11_invoice(payment_info=pi2, message='test', fallback_address=None)
        hint_node_ids3 = {route[0][0] for route in lnaddr3.get_routing_info('r')}
        self.assertEqual(hint_node_ids3, {trampoline_pubkey})

    async def test_open_channel_just_in_time_success(self):
        wallet = self.lnwallet_anchors
        wallet.config.ZEROCONF_MIN_OPENING_FEE = 0
        wallet.config.OPEN_ZEROCONF_CHANNELS = True

        next_peer = mock.Mock(spec=Peer)
        next_chan = mock.Mock(spec=Channel)
        next_chan.get_scid_or_local_alias.return_value = bytes(8)

        funding_tx = mock.Mock()
        funding_tx.txid.return_value = os.urandom(32).hex()
        funding_tx.get_fee = lambda: 250

        wallet.open_channel_with_peer = mock.AsyncMock(return_value=(next_chan, funding_tx))
        wallet.network.try_broadcasting = mock.AsyncMock(return_value=True)

        preimage = os.urandom(32)
        payment_hash = sha256(preimage)

        htlc = mock.Mock()
        htlc.htlc_id = 0
        next_peer.send_htlc.return_value = htlc

        task = asyncio.create_task(wallet.open_channel_just_in_time(
            next_peer=next_peer,
            next_amount_msat_htlc=1000000,
            next_cltv_abs=500,
            payment_hash=payment_hash,
            next_onion=mock.Mock(spec=OnionPacket)
        ))

        await asyncio.sleep(0.1)
        wallet.save_preimage(payment_hash, preimage)
        htlc_key = await task
        htlc_key_correct = serialize_htlc_key(next_chan.get_scid_or_local_alias(), htlc.htlc_id)
        self.assertEqual(htlc_key, htlc_key_correct)

        wallet.open_channel_with_peer.assert_called_once()
        next_peer.send_htlc.assert_called_once()
        wallet.network.try_broadcasting.assert_called()

    async def test_open_channel_just_in_time_failure_channel_open(self):
        """The channel opening failed on the LSP side because the client rejected the incoming channel"""
        wallet = self.lnwallet_anchors
        wallet.config.ZEROCONF_MIN_OPENING_FEE = 0
        wallet.config.OPEN_ZEROCONF_CHANNELS = True
        next_peer = mock.Mock(spec=Peer)
        wallet.open_channel_with_peer = mock.AsyncMock(side_effect=Exception("peer rejected incoming channel"))
        preimage = os.urandom(32)
        wallet.save_preimage(sha256(preimage), preimage)
        wallet._cleanup_failed_jit_channel = mock.AsyncMock()

        with self.assertRaises(OnionRoutingFailure):
            await wallet.open_channel_just_in_time(
                next_peer=next_peer,
                next_amount_msat_htlc=1000000,
                next_cltv_abs=500,
                payment_hash=sha256(preimage),
                next_onion=mock.Mock(spec=OnionPacket)
            )

        self.assertIsNone(wallet.get_preimage(sha256(preimage)))
        wallet._cleanup_failed_jit_channel.assert_not_called()

    async def test_open_channel_just_in_time_failure_send_htlc(self):
        """The LSP fails to forward the htlc to the client"""
        wallet = self.lnwallet_anchors
        wallet.config.ZEROCONF_MIN_OPENING_FEE = 0
        wallet.config.OPEN_ZEROCONF_CHANNELS = True

        next_peer = mock.Mock(spec=Peer)
        chan = mock.Mock(spec=Channel)
        funding_tx = mock.Mock()

        wallet.open_channel_with_peer = mock.AsyncMock(return_value=(chan, funding_tx))
        next_peer.send_htlc.side_effect = Exception("couldn't send htlc, peer disconnected")
        preimage = os.urandom(32)
        wallet.save_preimage(sha256(preimage), preimage)
        wallet._cleanup_failed_jit_channel = mock.AsyncMock()

        with self.assertRaises(OnionRoutingFailure):
            await wallet.open_channel_just_in_time(
                next_peer=next_peer,
                next_amount_msat_htlc=1000000,
                next_cltv_abs=500,
                payment_hash=sha256(preimage),
                next_onion=mock.Mock(spec=OnionPacket)
            )

        self.assertIsNone(wallet.get_preimage(sha256(preimage)))
        wallet._cleanup_failed_jit_channel.assert_called_once_with(chan)

    async def test_open_channel_just_in_time_failure_preimage_timeout(self):
        """The client never releases the preimage"""
        wallet = self.lnwallet_anchors
        wallet.config.ZEROCONF_MIN_OPENING_FEE = 0
        wallet.config.OPEN_ZEROCONF_CHANNELS = True

        next_peer = mock.Mock(spec=Peer)
        chan = mock.Mock(spec=Channel)
        funding_tx = mock.Mock()

        wallet.open_channel_with_peer = mock.AsyncMock(return_value=(chan, funding_tx))

        htlc = mock.Mock()
        next_peer.send_htlc.return_value = htlc

        wallet._cleanup_failed_jit_channel = mock.AsyncMock()

        with mock.patch('electrum.lnworker.LN_P2P_NETWORK_TIMEOUT', 0.01):
            with self.assertRaises(OnionRoutingFailure):
                await wallet.open_channel_just_in_time(
                    next_peer=next_peer,
                    next_amount_msat_htlc=1000000,
                    next_cltv_abs=500,
                    payment_hash=os.urandom(32),
                    next_onion=mock.Mock(spec=OnionPacket)
                )

        wallet._cleanup_failed_jit_channel.assert_called_once_with(chan)

    async def test_open_channel_just_in_time_failure_broadcast(self):
        wallet = self.lnwallet_anchors
        wallet.config.ZEROCONF_MIN_OPENING_FEE = 0
        wallet.config.OPEN_ZEROCONF_CHANNELS = True

        next_peer = mock.Mock(spec=Peer)
        chan = mock.Mock(spec=Channel)

        funding_tx = mock.Mock()

        wallet.open_channel_with_peer = mock.AsyncMock(return_value=(chan, funding_tx))

        preimage = os.urandom(32)
        wallet.save_preimage(sha256(preimage), preimage)

        wallet.network.try_broadcasting = mock.AsyncMock(return_value=False)
        wallet.wallet.adb.get_tx_height = mock.Mock(return_value=mock.Mock(height=lambda: TX_HEIGHT_LOCAL))

        wallet._cleanup_failed_jit_channel = mock.AsyncMock()

        with mock.patch('electrum.lnworker.ZEROCONF_TIMEOUT', 0.01), \
             mock.patch('electrum.lnworker.asyncio.sleep', new_callable=mock.AsyncMock):
             with self.assertRaises(OnionRoutingFailure):
                await wallet.open_channel_just_in_time(
                    next_peer=next_peer,
                    next_amount_msat_htlc=1000000,
                    next_cltv_abs=500,
                    payment_hash=sha256(preimage),
                    next_onion=mock.Mock(spec=OnionPacket)
                )

        self.assertIsNone(wallet.get_preimage(sha256(preimage)))
        wallet._cleanup_failed_jit_channel.assert_called_once_with(chan)

    async def test_open_channel_just_in_time_config_disabled(self):
        """open_channel_just_in_time rejects to open a channel if the config is disabled"""
        wallet = self.lnwallet_anchors
        wallet.config.ZEROCONF_MIN_OPENING_FEE = 0
        wallet.config.OPEN_ZEROCONF_CHANNELS = False

        with self.assertRaises(AssertionError):
            await wallet.open_channel_just_in_time(
                next_peer=mock.Mock(spec=Peer),
                next_amount_msat_htlc=1000000,
                next_cltv_abs=500,
                payment_hash=os.urandom(32),
                next_onion=mock.Mock(spec=OnionPacket)
            )

    async def test_cleanup_failed_jit_channel(self):
        wallet = self.lnwallet_anchors

        chan = mock.Mock(spec=Channel)
        chan_id = os.urandom(32).hex()
        chan.channel_id = chan_id
        funding_txid = os.urandom(32).hex()
        chan.funding_outpoint = mock.Mock()
        chan.funding_outpoint.txid = funding_txid
        chan.get_funding_height.return_value = None

        # close_channel fails with exception
        wallet.close_channel = mock.AsyncMock(side_effect=Exception("peer disconnected"))
        wallet.remove_channel = mock.Mock()
        wallet.lnwatcher = mock.Mock()
        wallet.lnwatcher.stop = mock.AsyncMock()
        wallet.lnwatcher.adb = mock.Mock()
        wallet.lnwatcher.adb.remove_transaction = mock.Mock()

        await wallet._cleanup_failed_jit_channel(chan)

        wallet.close_channel.assert_called_once_with(chan_id)
        chan.set_state.assert_called_once_with(ChannelState.REDEEMED, force=True)
        wallet.lnwatcher.adb.remove_transaction.assert_called_once_with(funding_txid)
        wallet.remove_channel.assert_called_once_with(chan_id)

    async def test_receive_requires_jit_channel(self):
        wallet = self.lnwallet_anchors

        with self.subTest(msg="cannot get jit channel"):
            wallet.can_get_zeroconf_channel = mock.Mock(return_value=False)
            wallet.num_sats_can_receive = mock.Mock(return_value=Decimal(0))
            self.assertFalse(wallet.receive_requires_jit_channel(1_000_000))

        with self.subTest(msg="could get zeroconf channel but doesn't need one"):
            wallet.can_get_zeroconf_channel = mock.Mock(return_value=True)
            wallet.num_sats_can_receive = mock.Mock(return_value=Decimal(2000))
            self.assertFalse(wallet.receive_requires_jit_channel(1_000_000))

        with self.subTest(msg="could get zeroconf channel and needs one"):
            wallet.can_get_zeroconf_channel = mock.Mock(return_value=True)
            wallet.num_sats_can_receive = mock.Mock(return_value=Decimal(500))
            self.assertTrue(wallet.receive_requires_jit_channel(1_000_000))

        with self.subTest(msg="could get one but can receive exactly the requested amount"):
            wallet.can_get_zeroconf_channel = mock.Mock(return_value=True)
            wallet.num_sats_can_receive = mock.Mock(return_value=Decimal(1000))
            self.assertFalse(wallet.receive_requires_jit_channel(1_000_000))

        with self.subTest(msg="0 amount invoice, could get channel but can receive something"):
            wallet.can_get_zeroconf_channel = mock.Mock(return_value=True)
            wallet.num_sats_can_receive = mock.Mock(return_value=Decimal(1))
            self.assertFalse(wallet.receive_requires_jit_channel(None))

        with self.subTest(msg="0 amount invoice (None amount), cannot receive anything and can get channel"):
            wallet.can_get_zeroconf_channel = mock.Mock(return_value=True)
            wallet.num_sats_can_receive = mock.Mock(return_value=Decimal(0))
            self.assertTrue(wallet.receive_requires_jit_channel(None))

        with self.subTest(msg="0 amount invoice (0 msat), cannot receive anything, could get channel"):
            wallet.can_get_zeroconf_channel = mock.Mock(return_value=True)
            wallet.num_sats_can_receive = mock.Mock(return_value=Decimal(0))
            self.assertTrue(wallet.receive_requires_jit_channel(0))

    async def test_can_get_zeroconf_channel(self):
        wallet = self.lnwallet_anchors
        valid_peer = "02" * 33 + "@localhost:9735"

        with self.subTest(msg="disabled in config"):
            wallet.config.OPEN_ZEROCONF_CHANNELS = False
            wallet.config.ZEROCONF_TRUSTED_NODE = valid_peer
            self.assertFalse(wallet.can_get_zeroconf_channel())

        with self.subTest(msg="enabled, but no trusted node configured"):
            wallet.config.OPEN_ZEROCONF_CHANNELS = True
            wallet.config.ZEROCONF_TRUSTED_NODE = ''
            self.assertFalse(wallet.can_get_zeroconf_channel())

        with self.subTest(msg="enabled, invalid trusted node string"):
            wallet.config.OPEN_ZEROCONF_CHANNELS = True
            wallet.config.ZEROCONF_TRUSTED_NODE = "invalid_node_string"
            self.assertFalse(wallet.can_get_zeroconf_channel())

        with self.subTest(msg="enabled, valid trusted node, but not connected"):
            wallet.config.OPEN_ZEROCONF_CHANNELS = True
            wallet.config.ZEROCONF_TRUSTED_NODE = valid_peer
            self.assertFalse(wallet.can_get_zeroconf_channel())

        with self.subTest(msg="enabled, valid trusted node, and connected"):
            wallet.lnpeermgr.get_peer_by_pubkey = mock.Mock(return_value=mock.Mock(spec=Peer))
            wallet.config.OPEN_ZEROCONF_CHANNELS = True
            wallet.config.ZEROCONF_TRUSTED_NODE = valid_peer
            self.assertTrue(wallet.can_get_zeroconf_channel())

    async def test_rebalance_channels(self):
        graph_def = {
            'alice': {
                'channels': {
                    'bob': [
                        {
                            'local_balance_msat': 10_000_000_000,
                            'remote_balance_msat': 50_000_000,
                        },
                        {
                            'local_balance_msat': 50_000_000,
                            'remote_balance_msat': 10_000_000_000,
                        },
                    ],
                },
            },
            'bob': {
                'config': {
                    SimpleConfig.EXPERIMENTAL_LN_FORWARD_PAYMENTS: True,
                },
            },
        }
        graph = lnhelpers.prepare_chans_and_peers_in_graph(self, graph_def)
        alice, bob = graph.workers.values()
        peer_ab, peer_ba = graph.peers.values()
        await alice.lnpeermgr.taskgroup.spawn(peer_ab.main_loop())
        await bob.lnpeermgr.taskgroup.spawn(peer_ba.main_loop())
        self.assertFalse(alice.uses_trampoline())
        chan0 = graph.channels[('alice', 'bob')][0]
        chan1 = graph.channels[('alice', 'bob')][1]

        # test num_sats_can_rebalance
        self.assertGreater(alice.num_sats_can_rebalance(chan0, chan1), 9_000_000)
        chan0.set_frozen_for_sending(True)
        self.assertEqual(alice.num_sats_can_rebalance(chan0, chan1), 0)
        chan0.set_frozen_for_sending(False)
        chan1.set_frozen_for_receiving(True)
        self.assertEqual(alice.num_sats_can_rebalance(chan0, chan1), 0)
        chan1.set_frozen_for_receiving(False)

        # simple rebalance: alice chan1 -> bob -> alice chan2
        rebalance_amount = 60_000_000
        self.assertEqual(chan0.balance(HTLCOwner.LOCAL), 10_000_000_000)
        success, log = await alice.rebalance_channels(chan0, chan1, amount_msat=rebalance_amount)
        self.assertTrue(success, msg=log)
        self.assertLessEqual(chan0.balance(HTLCOwner.LOCAL), 10_000_000_000 - rebalance_amount)
        self.assertEqual(chan1.balance(HTLCOwner.LOCAL), 50_000_000 + rebalance_amount)

        # test another rebalance, with partially frozen channels
        chan0.set_frozen_for_receiving(True)  # shouldn't matter, this channel will send
        chan1.set_frozen_for_sending(True)  # shouldn't matter, this channel will receive
        success, log = await alice.rebalance_channels(chan0, chan1, amount_msat=150_000_000)
        self.assertTrue(success, msg=log)

    async def test_request_bolt12_invoice(self):
        wallet = self.lnwallet_anchors

        offer_issuer_id = ECPrivkey.generate_random_key().get_public_key_bytes()
        offer = BOLT12Offer(
            offer_chains=[constants.net.rev_genesis_bytes()],
            offer_description="test",
            offer_issuer_id=offer_issuer_id,
        )

        introduction_point = ECPrivkey.generate_random_key().get_public_key_bytes()
        reply_paths = [BlindedPathInfo(
            path=BlindedPath(
                first_node_id=introduction_point,
                first_path_key=ECPrivkey.generate_random_key().get_public_key_bytes(),
                num_hops=(1).to_bytes(1, 'big'),
                path=[BlindedPathHop(
                    blinded_node_id=ECPrivkey.generate_random_key().get_public_key_bytes(),
                    enclen=5,
                    encrypted_recipient_data=b'12345',
                )],
            ),
            payinfo=None,
        )]

        submit_send_calls = []
        def fake_submit_send(*, payload, node_id_or_blinded_paths, key=None):
            submit_send_calls.append((payload, node_id_or_blinded_paths))
            return asyncio.Future()

        with patch('electrum.lnworker.get_blinded_reply_paths', return_value=reply_paths), \
             patch.object(wallet.onion_message_manager, 'submit_send', side_effect=fake_submit_send):
            task = asyncio.create_task(
                wallet.request_bolt12_invoice(bolt12_offer=offer, amount_msat=21_000)
            )

            start = time.time()
            while not wallet._pending_bolt12_invoice_requests:
                await asyncio.sleep(0.05)
                if time.time() - start > 2:
                    task.cancel()
                    self.fail(f"invreq future wasn't registered")

            self.assertEqual(len(submit_send_calls), 1)
            payload, destination = submit_send_calls[0]
            self.assertEqual(destination, offer_issuer_id)
            self.assertIn('invoice_request', payload)
            self.assertIn('reply_path', payload)

            self.assertEqual(len(wallet._pending_bolt12_invoice_requests), 1)
            path_id, fut = next(iter(wallet._pending_bolt12_invoice_requests.items()))
            fut.set_result("invoice")

            self.assertIs(await task, "invoice")

        self.assertNotIn(path_id, wallet._pending_bolt12_invoice_requests)

    def test_create_bolt12_invoice_request_with_offer(self):
        wallet = self.lnwallet_anchors

        amount_msat = 10_000
        offer_issuer_id = ECPrivkey.generate_random_key().get_public_key_bytes()
        offer = BOLT12Offer(
            offer_chains=[constants.net.rev_genesis_bytes()],
            offer_amount=amount_msat,
            offer_description="test offer",
            offer_issuer_id=offer_issuer_id,
        )

        # raises if amount is much higher than offer_amount
        with self.assertRaises(ValueError):
            _ = wallet.create_bolt12_invoice_request(offer=offer, amount_msat=40000)

        unsigned_invreq, signing_key = wallet.create_bolt12_invoice_request(
            offer=offer,
            amount_msat=amount_msat,
            payer_note="pls send invoice",
        )

        self.assertIsInstance(unsigned_invreq, BOLT12InvoiceRequest)
        self.assertIsInstance(signing_key, ECPrivkey)

        # offer fields propagated into the invreq
        self.assertEqual(unsigned_invreq.offer_issuer_id, offer_issuer_id)
        self.assertEqual(unsigned_invreq.offer_amount, 10_000)
        self.assertEqual(unsigned_invreq.offer_description, "test offer")
        self.assertEqual(unsigned_invreq.offer_chains, [constants.net.rev_genesis_bytes()])

        # invreq fields set from our parameters
        self.assertEqual(unsigned_invreq.invreq_amount, amount_msat)
        self.assertEqual(unsigned_invreq.invreq_payer_note, "pls send invoice")
        self.assertEqual(unsigned_invreq.invreq_payer_id, signing_key.get_public_key_bytes())
        self.assertEqual(unsigned_invreq.invreq_chain, constants.net.rev_genesis_bytes())
        # invreq_metadata is the 16-byte entropy concatenated with sha256(signed_invreq_tlv)
        self.assertEqual(len(unsigned_invreq.invreq_metadata), 16 + 32)

        # standalone-only fields are absent
        self.assertIsNone(unsigned_invreq.invreq_paths)

        # derived signing key is not the node key
        self.assertNotEqual(signing_key.get_secret_bytes(), wallet.node_keypair.privkey)

        # test the stateless authenticity scheme
        entropy, invreq_sig_digest = unsigned_invreq.invreq_metadata[:16], unsigned_invreq.invreq_metadata[-32:]
        derived_privkey = hmac_oneshot(
            key=wallet.bolt12_secret_key,
            msg=b'invreq_key' + entropy,
            digest='sha-256',
        )
        self.assertEqual(derived_privkey, signing_key.get_secret_bytes())

        signable_invreq = dataclasses.replace(unsigned_invreq, invreq_metadata=entropy)
        resigned = signable_invreq.encode(signing_key=signing_key.get_secret_bytes(), as_bech32=False)
        self.assertEqual(sha256(resigned), invreq_sig_digest)

    def test_create_bolt12_invoice_request_without_offer(self):
        wallet = self.lnwallet_anchors

        fake_pubkey = ECPrivkey.generate_random_key().get_public_key_bytes()
        reply_paths = [BlindedPathInfo(
            path=BlindedPath(
                first_node_id=fake_pubkey,
                first_path_key=fake_pubkey,
                num_hops=(1).to_bytes(1, 'big'),
                path=[BlindedPathHop(
                    blinded_node_id=fake_pubkey,
                    enclen=5,
                    encrypted_recipient_data=b'12345',
                )],
            ),
            payinfo=None,
        )]

        amount_msat = 42_000
        with patch('electrum.lnworker.get_blinded_reply_paths', return_value=reply_paths):
            unsigned_invreq, signing_key = wallet.create_bolt12_invoice_request(
                offer=None,
                amount_msat=amount_msat,
                payer_note="standalone invreq",
                allow_unblinded=False,
            )

        self.assertIsInstance(unsigned_invreq, BOLT12InvoiceRequest)
        self.assertIsInstance(signing_key, ECPrivkey)

        # not a response to an offer: offer identity fields must be empty
        self.assertIsNone(unsigned_invreq.offer_issuer_id)
        self.assertIsNone(unsigned_invreq.offer_paths)
        self.assertIsNone(unsigned_invreq.offer_amount)
        self.assertIsNone(unsigned_invreq.offer_chains)
        # payer_note is stored in offer_description for standalone invreqs
        self.assertEqual(unsigned_invreq.offer_description, "standalone invreq")

        # invreq fields set from our parameters
        self.assertEqual(unsigned_invreq.invreq_amount, amount_msat)
        self.assertEqual(unsigned_invreq.invreq_payer_id, signing_key.get_public_key_bytes())
        self.assertEqual(unsigned_invreq.invreq_chain, constants.net.rev_genesis_bytes())
        self.assertEqual(len(unsigned_invreq.invreq_metadata), 16 + 32)

        # blinded reply paths are attached so the payee can respond
        self.assertEqual(len(unsigned_invreq.invreq_paths), 1)
        self.assertEqual(unsigned_invreq.invreq_paths[0], reply_paths[0].path)

        # with reply paths available, the derived signing key is used (not node key)
        self.assertNotEqual(signing_key.get_secret_bytes(), wallet.node_keypair.privkey)

        # authenticity scheme (same as offer-based invreqs)
        entropy, stored_digest = unsigned_invreq.invreq_metadata[:16], unsigned_invreq.invreq_metadata[-32:]
        derived_privkey = hmac_oneshot(
            key=wallet.bolt12_secret_key,
            msg=b'invreq_key' + entropy,
            digest='sha-256',
        )
        self.assertEqual(derived_privkey, signing_key.get_secret_bytes())

        signable_invreq = dataclasses.replace(unsigned_invreq, invreq_metadata=entropy)
        resigned = signable_invreq.encode(signing_key=signing_key.get_secret_bytes(), as_bech32=False)
        self.assertEqual(sha256(resigned), stored_digest)

    def test_create_offer(self):
        wallet = self.lnwallet_anchors

        amount_msat = 10_000
        memo = "test"
        expiry = 4000
        issuer = "pizza italy"
        with self.assertRaises(NoOnionMessagePeers):
            wallet.create_offer(
                amount_msat=amount_msat,
                description=memo,
                relative_expiry=expiry,
                issuer_name=issuer,
                allow_unblinded=False,
            )

        offer = wallet.create_offer(
            amount_msat=amount_msat,
            description=memo,
            relative_expiry=expiry,
            issuer_name=issuer,
            allow_unblinded=True,
        )

        self.assertEqual(offer.offer_amount, amount_msat)
        self.assertEqual(offer.offer_description, memo)
        self.assertEqual(offer.offer_issuer, issuer)
        self.assertEqual(offer.offer_issuer_id, wallet.node_keypair.pubkey)
        self.assertIsNone(offer.offer_paths)
        absolute_expiry = int(time.time()) + expiry
        self.assertLess(offer.offer_absolute_expiry - absolute_expiry,  2)

        # test that offer metadata is a mac of encoded offer
        mac, remaining_metadata = offer.offer_metadata[-32:], offer.offer_metadata[:-32]
        offer = dataclasses.replace(offer, offer_metadata=remaining_metadata)
        encoded_offer = offer.encode(as_bech32=False)
        our_mac = hmac_oneshot(key=wallet.bolt12_secret_key, msg=b'offer' + encoded_offer, digest='sha-256')
        self.assertEqual(our_mac, mac)

        # assert two offers signed with node keypair are not equal
        # this allows for example to blacklist/revoke certain offers
        offer1 = wallet.create_offer(allow_unblinded=True).encode()
        offer2 = wallet.create_offer(allow_unblinded=True).encode()
        self.assertNotEqual(offer1, offer2)
