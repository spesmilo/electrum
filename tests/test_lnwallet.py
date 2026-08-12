import logging
import os
import asyncio
import time
from unittest import mock
from decimal import Decimal
from typing import Callable, Optional, Sequence

import attr
import electrum_ecc as ecc

from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum import bitcoin, keystore
from electrum.bitcoin import COIN
import electrum.trampoline
from electrum.channel_db import UpdateStatus
from electrum.lnutil import (RECEIVED, MIN_FINAL_CLTV_DELTA_ACCEPTED, serialize_htlc_key, LnFeatures, HTLCOwner,
                            LOCAL, REMOTE, ImportedChannelBackupStorage, make_commitment_output_to_anchor_address)
from electrum.logging import console_stderr_handler
from electrum.lnmsg import decode_msg
from electrum.lnrouter import RouteEdge
from electrum.lntransport import LNPeerAddr
from electrum.invoices import LN_EXPIRY_NEVER, PR_UNPAID
from electrum.lnpeer import Peer
from electrum.lnchannel import Channel, ChannelBackup, ChannelState
from electrum.lnonion import OnionPacket, OnionRoutingFailure, OnionFailureCode
from electrum.mpp_split import SplitConfig, SplitConfigRating
from electrum.crypto import sha256
from electrum.simple_config import SimpleConfig
from electrum.transaction import Transaction, TxOutpoint
from electrum.wallet import Abstract_Wallet

from . import ElectrumTestCase, lnhelpers
from .lnhelpers import create_test_channels, find_free_port
from .toyserver.testcase import SEED, ToyInstance, ToyServerTestCase


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

    async def test_payment_multipart_single_channel_split(self):
        """A split configuration can put multiple parts on a single channel. The parts
        must then be sent over that channel, instead of the pathfinder freely choosing
        a first hop, which would ignore the balance allocation of the config."""
        graph = lnhelpers.prepare_chans_and_peers_in_graph(self, lnhelpers._GRAPH_DEFINITIONS['square_graph'])
        alice_w, dave_w = graph.workers['alice'], graph.workers['dave']
        dave_w.features |= LnFeatures.BASIC_MPP_OPT
        self.assertFalse(alice_w.uses_trampoline())
        amount_to_pay = 200_000_000
        lnaddr, _pay_req = lnhelpers.prepare_invoice(dave_w, include_routing_hints=True, amount_msat=amount_to_pay)
        # force a split config with two parts on the high-fee alice-bob channel,
        # although the pathfinder considers the route via carol cheaper
        bob_chan = graph.channels[('alice', 'bob')][0]
        split_config = SplitConfig({(bob_chan.channel_id, bob_chan.node_id): [amount_to_pay // 2, amount_to_pay // 2]})
        alice_w.suggest_payment_splits = lambda **kwargs: [SplitConfigRating(config=split_config, rating=0)]
        routes = await alice_w.create_routes_from_invoice(amount_to_pay, decoded_invoice=lnaddr)
        self.assertEqual(2, len(routes))
        for shi, _, _ in routes:
            # all constructed routes use the outgoing channel of the split config
            self.assertEqual(bob_chan.short_channel_id, shi.route[0].short_channel_id)

    async def test_unchanged_channel_update_from_failed_htlc(self):
        # a TEMPORARY_CHANNEL_FAILURE carrying a channel update identical to what we
        # already have (UpdateStatus.UNCHANGED) is a liquidity issue: the recorded
        # liquidity hint is sufficient and the channel must not get blacklisted, so
        # that smaller (mpp) retry amounts can still use it. for other failure codes
        # an unchanged update still results in blacklisting.
        graph = lnhelpers.prepare_chans_and_peers_in_graph(self, lnhelpers._GRAPH_DEFINITIONS['square_graph'])
        alice_w = graph.workers['alice']
        path_finder = alice_w.network.path_finder
        amount_msat = 100_000_000
        now = int(time.time())

        def add_chan_to_alice_channel_db(chan: Channel) -> bytes:
            # inject with a backdated policy, so that presenting the current signed
            # update in an onion error below yields UpdateStatus.UNCHANGED
            chan_ann = decode_msg(chan.construct_channel_announcement_without_sigs()[0])[1]
            alice_w.channel_db.add_channel_announcements(chan_ann, trusted=True)
            chan_upd_raw = chan.get_outgoing_gossip_channel_update()
            chan_upd = decode_msg(chan_upd_raw)[1]
            chan_upd['timestamp'] -= 3600
            self.assertEqual(UpdateStatus.GOOD, alice_w.channel_db.add_channel_update(chan_upd, verify=False))
            return chan_upd_raw

        def two_hop_route(middle: str) -> Sequence[RouteEdge]:
            return [
                RouteEdge(
                    start_node=graph.workers[a].node_keypair.pubkey,
                    end_node=graph.workers[b].node_keypair.pubkey,
                    short_channel_id=graph.channels[(a, b)][0].short_channel_id,
                    fee_base_msat=0, fee_proportional_millionths=0, cltv_delta=10, node_features=0,
                ) for a, b in [('alice', middle), (middle, 'dave')]
            ]

        # bob fails an htlc with a liquidity error: no blacklisting, only a liquidity hint
        chan_bd = graph.channels[('bob', 'dave')][0]
        chan_upd_raw = add_chan_to_alice_channel_db(chan_bd)
        failure_data = len(chan_upd_raw).to_bytes(2, 'big') + chan_upd_raw
        alice_w.handle_error_code_from_failed_htlc(
            route=two_hop_route('bob'), sender_idx=0, amount_msat=amount_msat,
            failure_msg=OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_CHANNEL_FAILURE, data=failure_data))
        self.assertFalse(path_finder._is_edge_blacklisted(chan_bd.short_channel_id, now=now))
        hint_bd = path_finder.liquidity_hints.get_hint(chan_bd.short_channel_id)
        pubkey_b = graph.workers['bob'].node_keypair.pubkey
        pubkey_d = graph.workers['dave'].node_keypair.pubkey
        self.assertEqual(amount_msat, hint_bd.cannot_send(pubkey_b < pubkey_d))

        # carol fails an htlc with a non-liquidity error: the channel gets blacklisted
        chan_cd = graph.channels[('carol', 'dave')][0]
        chan_upd_raw = add_chan_to_alice_channel_db(chan_cd)
        failure_data = amount_msat.to_bytes(8, 'big') + len(chan_upd_raw).to_bytes(2, 'big') + chan_upd_raw
        alice_w.handle_error_code_from_failed_htlc(
            route=two_hop_route('carol'), sender_idx=0, amount_msat=amount_msat,
            failure_msg=OnionRoutingFailure(code=OnionFailureCode.FEE_INSUFFICIENT, data=failure_data))
        self.assertTrue(path_finder._is_edge_blacklisted(chan_cd.short_channel_id, now=now))

    async def test_missing_channel_update_from_failed_htlc(self):
        # the channel_update in UPDATE-type failure messages is optional, nodes
        # omitting it set the channel_update len field to zero:
        # https://github.com/lightning/bolts/blob/93b7ee031b50acd59967a105f1326176a37628f9/04-onion-routing.md?plain=1#L1384-L1389
        # a TEMPORARY_CHANNEL_FAILURE without channel update is a liquidity issue:
        # we record a liquidity hint and must not blacklist the channel
        graph = lnhelpers.prepare_chans_and_peers_in_graph(self, lnhelpers._GRAPH_DEFINITIONS['square_graph'])
        alice_w = graph.workers['alice']
        path_finder = alice_w.network.path_finder
        amount_msat = 100_000_000
        route = [
            RouteEdge(
                start_node=graph.workers[a].node_keypair.pubkey,
                end_node=graph.workers[b].node_keypair.pubkey,
                short_channel_id=graph.channels[(a, b)][0].short_channel_id,
                fee_base_msat=0, fee_proportional_millionths=0, cltv_delta=10, node_features=0,
            ) for a, b in [('alice', 'bob'), ('bob', 'dave')]
        ]
        failure_data = (0).to_bytes(2, 'big')  # channel_update len field set to zero
        alice_w.handle_error_code_from_failed_htlc(
            route=route, sender_idx=0, amount_msat=amount_msat,
            failure_msg=OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_CHANNEL_FAILURE, data=failure_data))
        chan_bd = graph.channels[('bob', 'dave')][0]
        self.assertFalse(path_finder._is_edge_blacklisted(chan_bd.short_channel_id, now=int(time.time())))
        hint_bd = path_finder.liquidity_hints.get_hint(chan_bd.short_channel_id)
        pubkey_b = graph.workers['bob'].node_keypair.pubkey
        pubkey_d = graph.workers['dave'].node_keypair.pubkey
        self.assertEqual(amount_msat, hint_bd.cannot_send(pubkey_b < pubkey_d))


class TestChannelBackup(ToyServerTestCase):
    """Alice and Bob are two LNWallets sharing a ToyServer and talking to each other over a real BOLT-08 transport."""
    FUNDING_SAT = 5_000_000

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice_instance = await self.create_instance("alice")
        self.bob_instance = await self.create_instance("bob")
        self.bob_instance.config.LIGHTNING_LISTEN = f"127.0.0.1:{find_free_port()}"
        self.bob = self.create_wallet("bob", instance=self.bob_instance)
        await self.wait_until(lambda: self.bob.lnworker.lnpeermgr.listen_server is not None)

    def create_wallet(self, name: str, **kwargs) -> Abstract_Wallet:
        # increase gap limit for lightning
        return super().create_wallet(name, gap_limit=10, gap_limit_for_change=10, **kwargs)

    def create_deterministic_wallet(self, instance: ToyInstance) -> Abstract_Wallet:
        return self.create_wallet(instance.name, instance=instance)

    def create_non_deterministic_xprv_wallet(self, instance: ToyInstance) -> Abstract_Wallet:
        xprv = keystore.from_seed(SEED, passphrase=instance.name).get_master_private_key(None)
        wallet = self.create_wallet(instance.name, text=xprv, instance=instance)
        wallet.init_lightning(password=None)
        self.assertFalse(wallet.lnworker.has_deterministic_node_id())
        return wallet

    def create_config(self, name: Optional[str] = None) -> SimpleConfig:
        config = super().create_config(name)
        config.LIGHTNING_USE_RECOVERABLE_CHANNELS = False  # onchain backup tests opt in explicitly
        return config

    async def open_channel(self, from_wallet, to_wallet) -> Channel:
        to_nodeid = to_wallet.lnworker.node_keypair.pubkey
        peer = await from_wallet.lnworker.lnpeermgr.add_peer(f"{to_nodeid.hex()}@{to_wallet.config.LIGHTNING_LISTEN}")
        chan, funding_tx = await from_wallet.lnworker.open_channel_with_peer(peer, self.FUNDING_SAT, password=None)
        await self.mine_blocks(chan.funding_txn_minimum_depth() + 1)
        await self.wait_until(lambda: chan.is_open())
        chan_bob = to_wallet.lnworker.get_channel_by_id(chan.channel_id)
        await self.wait_until(lambda: chan_bob.is_open())
        return chan

    async def fund_and_open_channel(self, alice: Abstract_Wallet, *, anchors: bool) -> Channel:
        """Fund alice from the faucet, and open a channel from her to bob."""
        if not anchors:  # both peers have to agree on the channel type
            self.alice_instance.config.TEST_LN_OPEN_SRK_CHANNELS = True
            self.bob_instance.config.TEST_LN_OPEN_SRK_CHANNELS = True
        await self.pay_to_address(alice.get_receiving_address(), 1 * COIN)
        await self.mine_blocks(1)
        chan = await self.open_channel(alice, self.bob)
        self.assertEqual(anchors, chan.has_anchors())
        return chan

    async def claim_to_remote_from_their_ctx(self, alice: Abstract_Wallet, chan: Channel) -> Transaction:
        """Wait for bob to force-close with his own ctx, and for alice to get hold of what is hers in it.
        chan is alice's channel from before she lost her wallet db, we only read from it here."""
        ctx = await self.wait_for_spender_of(TxOutpoint.from_str(chan.funding_outpoint.to_str()))
        chan_bob = self.bob.lnworker.get_channel_by_id(chan.channel_id)
        if chan.has_anchors():
            # anchor spend needs to be checked before ctx confirms, otherwise TxBatcher will drop it.
            anchor_address = make_commitment_output_to_anchor_address(chan.config[LOCAL].multisig_key.pubkey)
            anchor_idx = ctx.get_output_idxs_from_address(anchor_address).pop()
            await self.wait_for_spender_of(TxOutpoint.from_str(f"{ctx.txid()}:{anchor_idx}"))
        await self.mine_blocks(1)  # mine to_remote csv delay
        await self.wait_until(lambda: chan_bob.get_state() == ChannelState.CLOSED)
        self.assertEqual(ctx.txid(), chan_bob.get_closing_height()[0])
        to_remote_idx = max(range(len(ctx.outputs())), key=lambda i: ctx.outputs()[i].value)
        if not chan.has_anchors():  # to_remote is one of alice's wallet addresses, nothing to sweep
            self.assertTrue(alice.is_mine(ctx.outputs()[to_remote_idx].address))
            return ctx
        await self.wait_for_spender_of(TxOutpoint.from_str(f"{ctx.txid()}:{to_remote_idx}"))
        return ctx

    async def assert_balance_recovered(
        self,
        alice: Abstract_Wallet,
        cb: ChannelBackup, *,
        balance_before: int,
        chan_balance_sat: int,
    ) -> None:
        """Alice got (most of) her channel balance back on-chain, and the backup is settled."""
        await self.mine_blocks(1)
        confirmed_balance, unconfirmed_balance, _ = alice.get_balance()
        self.assertEqual(0, unconfirmed_balance)
        self.assertGreater(confirmed_balance, balance_before + chan_balance_sat * 0.9)
        self.assertTrue(cb.is_closed())

    async def _test_request_fclose_from_chan_backup(
        self, *,
        create_alice_cb: Callable[[ToyInstance], Abstract_Wallet],
        anchors: bool,
    ) -> None:
        """Alice exports a channel backup, then loses her wallet db. She restores her wallet, imports
        the backup, and asks bob to force-close, so that she can claim her to_remote output."""
        alice = create_alice_cb(self.alice_instance)
        chan = await self.fund_and_open_channel(alice, anchors=anchors)
        chan_id = chan.channel_id
        alice_balance_sat = chan.balance(LOCAL) // 1000
        self.assertGreater(alice_balance_sat, self.FUNDING_SAT * 0.9)
        backup = alice.lnworker.export_channel_backup(chan_id)
        self.assertIsInstance(backup, str)
        self.assertTrue(backup.startswith('channel_backup:'))

        # alice loses her wallet db, and restores the wallet from her seed
        await self.stop_wallet(alice)
        alice = create_alice_cb(self.alice_instance)
        await self.sync()
        self.assertEqual({}, dict(alice.lnworker.channels))
        self.assertEqual({}, dict(alice.lnworker.channel_backups))
        onchain_balance_before = sum(alice.get_balance())

        # alice imports the channel backup, and asks bob to force-close
        alice.lnworker.import_channel_backup(backup)
        cb = alice.lnworker.channel_backups[chan_id]
        self.assertEqual(alice.lnworker.has_deterministic_node_id(), alice.lnworker.node_keypair.privkey == cb.cb.privkey)
        await self.wait_until(lambda: cb.get_state() == ChannelState.FUNDED)
        await alice.lnworker.request_force_close(chan_id)

        # bob force-closes with his own ctx, and alice claims her balance out of it
        await self.claim_to_remote_from_their_ctx(alice, chan)
        await self.assert_balance_recovered(alice, cb, balance_before=onchain_balance_before, chan_balance_sat=alice_balance_sat)

    async def test_request_fclose_from_anchor_chan_backup_deterministic_lightning(self):
        await self._test_request_fclose_from_chan_backup(create_alice_cb=self.create_deterministic_wallet, anchors=True)

    async def test_request_fclose_from_anchor_chan_backup_non_deterministic_lightning(self):
        await self._test_request_fclose_from_chan_backup(create_alice_cb=self.create_non_deterministic_xprv_wallet, anchors=True)

    async def test_request_fclose_from_srk_chan_backup_deterministic_lightning(self):
        await self._test_request_fclose_from_chan_backup(create_alice_cb=self.create_deterministic_wallet, anchors=False)

    async def test_request_fclose_from_srk_chan_backup_non_deterministic_lightning(self):
        await self._test_request_fclose_from_chan_backup(create_alice_cb=self.create_non_deterministic_xprv_wallet, anchors=False)

    async def test_request_fclose_from_pre_v2_anchor_chan_backup_deterministic_wallet(self):
        """Test recovery with an older channel backup on a deterministic lnwallet with anchor channel"""
        alice = self.create_deterministic_wallet(self.alice_instance)
        chan = await self.fund_and_open_channel(alice, anchors=True)
        chan_id = chan.channel_id
        alice_balance_sat = chan.balance(LOCAL) // 1000
        backup = alice.lnworker.export_channel_backup(chan_id)

        # alice loses her wallet db, and restores the wallet from her seed
        await self.stop_wallet(alice)
        alice = self.create_deterministic_wallet(self.alice_instance)
        await self.sync()
        onchain_balance_before = sum(alice.get_balance())

        # downgrade the backup to v1: no channel_type, payment pubkey instead of privkey, no multisig privkey
        cb_storage = ImportedChannelBackupStorage.from_encrypted_str(backup, password=alice.get_fingerprint())
        cb_storage = attr.evolve(
            cb_storage,
            channel_type=None,
            local_payment_basepoint=ecc.ECPrivkey(cb_storage.local_payment_basepoint).get_public_key_bytes(),
            multisig_funding_privkey=None,
        )
        # insert channel backup into wallet
        alice.lnworker.db.get_dict("imported_channel_backups")[chan_id.hex()] = cb_storage
        cb = ChannelBackup(cb_storage, lnworker=alice.lnworker)
        alice.lnworker._channel_backups[chan_id] = cb
        alice.lnworker.lnwatcher.add_channel(cb)

        await self.wait_until(lambda: cb.get_state() == ChannelState.FUNDED)
        await alice.lnworker.request_force_close(chan_id)

        # bob force-closes with his own ctx, and alice sweeps to_remote and her anchor
        await self.claim_to_remote_from_their_ctx(alice, chan)
        await self.assert_balance_recovered(alice, cb, balance_before=onchain_balance_before, chan_balance_sat=alice_balance_sat)

    async def _test_local_fclose_then_sweep_to_local_from_chan_backup(
        self, *,
        create_alice_cb: Callable[[ToyInstance], Abstract_Wallet],
        anchors: bool,
    ) -> None:
        """Alice force-closes with her own ctx, then loses her wallet db. She restores her wallet,
        imports the channel backup, and sweeps her to_local output once the CSV delay expired."""
        csv_delay = 5  # demanded of alice by bob, hence set on bob's config
        self.bob_instance.config.LIGHTNING_TO_SELF_DELAY_CSV = csv_delay
        alice = create_alice_cb(self.alice_instance)
        chan = await self.fund_and_open_channel(alice, anchors=anchors)
        self.assertEqual(csv_delay, chan.config[REMOTE].to_self_delay)
        chan_id = chan.channel_id
        funding_outpoint = TxOutpoint.from_str(chan.funding_outpoint.to_str())
        alice_balance_sat = chan.balance(LOCAL) // 1000
        backup = alice.lnworker.export_channel_backup(chan_id)

        # alice force-closes with her own ctx, and loses her wallet db before she can sweep it
        ctx_txid = await alice.lnworker.force_close_channel(chan_id)
        await self.stop_wallet(alice)
        await self.mine_blocks(1)
        ctx = await self.wait_for_spender_of(funding_outpoint)
        self.assertEqual(ctx_txid, ctx.txid())

        # alice restores her wallet and imports the channel backup
        alice = create_alice_cb(self.alice_instance)
        await self.sync()
        self.assertEqual({}, dict(alice.lnworker.channels))
        onchain_balance_before = sum(alice.get_balance())
        alice.lnworker.import_channel_backup(backup)
        cb = alice.lnworker.channel_backups[chan_id]

        # once the CSV delay expired, alice claims her balance out of her old ctx
        await self.mine_blocks(csv_delay)
        to_local_idx = max(range(len(ctx.outputs())), key=lambda i: ctx.outputs()[i].value)
        await self.wait_for_spender_of(TxOutpoint.from_str(f"{ctx.txid()}:{to_local_idx}"))
        await self.assert_balance_recovered(alice, cb, balance_before=onchain_balance_before, chan_balance_sat=alice_balance_sat)

    async def test_local_fclose_from_anchor_chan_backup_deterministic_lightning(self):
        await self._test_local_fclose_then_sweep_to_local_from_chan_backup(
            create_alice_cb=self.create_deterministic_wallet,
            anchors=True,
        )

    async def test_local_fclose_from_anchor_chan_backup_non_deterministic_lightning(self):
        await self._test_local_fclose_then_sweep_to_local_from_chan_backup(
            create_alice_cb=self.create_non_deterministic_xprv_wallet,
            anchors=True,
        )

    async def test_local_fclose_from_srk_chan_backup_deterministic_lightning(self):
        await self._test_local_fclose_then_sweep_to_local_from_chan_backup(
            create_alice_cb=self.create_deterministic_wallet,
            anchors=False,
        )

    async def test_local_fclose_from_srk_chan_backup_non_deterministic_lightning(self):
        await self._test_local_fclose_then_sweep_to_local_from_chan_backup(
            create_alice_cb=self.create_non_deterministic_xprv_wallet,
            anchors=False,
        )

    async def _test_request_fclose_from_onchain_chan_backup(self, *, anchors: bool) -> None:
        """Alice has a deterministic LNWallet, so her funding txs contain an OP_RETURN onchain backup.
        She loses her wallet db, restores from her seed, discovers the backup in the funding tx,
        and recovers her balance by asking bob to force-close."""
        self.alice_instance.config.LIGHTNING_USE_RECOVERABLE_CHANNELS = True
        alice = self.create_deterministic_wallet(self.alice_instance)
        self.assertTrue(alice.lnworker.has_recoverable_channels())
        chan = await self.fund_and_open_channel(alice, anchors=anchors)
        chan_id = chan.channel_id
        alice_balance_sat = chan.balance(LOCAL) // 1000

        # alice loses her wallet db, restores from seed, and finds the backup in the funding tx
        await self.stop_wallet(alice)
        alice = self.create_deterministic_wallet(self.alice_instance)
        await self.sync()
        self.assertEqual({}, dict(alice.lnworker.channels))
        onchain_balance_before = sum(alice.get_balance())
        await self.wait_until(lambda: chan_id in alice.lnworker.channel_backups)
        cb = alice.lnworker.channel_backups[chan_id]
        self.assertFalse(cb.is_imported)
        await self.wait_until(lambda: cb.get_state() == ChannelState.FUNDED)

        # the onchain backup only contains a node id prefix: bob must be findable as a hardcoded node
        bob_host, bob_port = self.bob_instance.config.LIGHTNING_LISTEN.rsplit(':', 1)
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            'bob': LNPeerAddr(host=bob_host, port=int(bob_port), pubkey=self.bob.lnworker.node_keypair.pubkey),
        }
        self.addCleanup(lambda: electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS.clear())
        await alice.lnworker.request_force_close(chan_id)

        # bob force-closes with his own ctx, and alice claims her balance out of it
        await self.claim_to_remote_from_their_ctx(alice, chan)
        await self.assert_balance_recovered(alice, cb, balance_before=onchain_balance_before, chan_balance_sat=alice_balance_sat)

    async def test_request_fclose_from_anchor_onchain_chan_backup(self):
        await self._test_request_fclose_from_onchain_chan_backup(anchors=True)

    async def test_request_fclose_from_srk_onchain_chan_backup(self):
        await self._test_request_fclose_from_onchain_chan_backup(anchors=False)
