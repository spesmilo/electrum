import asyncio
import dataclasses
import itertools
import shutil
import copy
import tempfile
import os
from contextlib import contextmanager
from collections import defaultdict
import logging
import concurrent
from concurrent import futures
from functools import lru_cache
from unittest import mock
from typing import Iterable, NamedTuple, Tuple, List, Dict, Sequence, Mapping, Optional
from types import MappingProxyType
import time
import statistics

from aiorpcx import timeout_after, TaskTimeout
from electrum_ecc import ECPrivkey, ECPubkey
import electrum_ecc as ecc

import electrum
import electrum.trampoline
from electrum import bitcoin
from electrum import util
from electrum import constants
from electrum import bip32
from electrum.network import Network, ProxySettings
from electrum import simple_config, lnutil
from electrum.bolt11 import encode_bolt11_invoice, BOLT11Addr
from electrum.bitcoin import sha256
from electrum.transaction import Transaction
from electrum.util import NetworkRetryManager, bfh, OldTaskGroup, EventListener, InvoiceError
from electrum.lnpeer import Peer
from electrum.lnpeer import CoopCloseFailure
from electrum.lntransport import LNPeerAddr
from electrum.crypto import privkey_to_pubkey, sha256d
from electrum.lnutil import Keypair, PaymentFailure, LnFeatures, HTLCOwner, PaymentFeeBudget, RECEIVED
from electrum.lnchannel import ChannelState, PeerState, Channel, CF_ANNOUNCE_CHANNEL
from electrum.lnrouter import LNPathFinder, PathEdge, LNPathInconsistent
from electrum.channel_db import ChannelDB, InvalidGossipMsg
from electrum.lnworker import LNWallet, NoPathFound, SentHtlcInfo, PaySession, LNPeerManager
from electrum.lnmsg import encode_msg, decode_msg
from electrum import lnmsg
from electrum.logging import console_stderr_handler, Logger
from electrum.lnonion import OnionFailureCode, OnionRoutingFailure, OnionHopsDataSingle, OnionPacket, OnionParsingError
from electrum.lnutil import LOCAL, REMOTE, UpdateAddHtlc, RecvMPPResolution, RevocationStore
from electrum.invoices import PR_PAID, PR_UNPAID, PR_INFLIGHT, Invoice, PR_FAILED
from electrum.interface import GracefulDisconnect
from electrum.fee_policy import FeeTimeEstimates, FEE_ETA_TARGETS
from electrum.mpp_split import split_amount_normal
from electrum.wallet import Abstract_Wallet, Standard_Wallet

from .test_bitcoin import needs_test_with_all_chacha20_implementations
from . import ElectrumTestCase, restore_wallet_from_text__for_unittest, lnhelpers
from .lnhelpers import Graph, MockLNWallet, create_test_channels, low_fee_channel, depleted_channel


class PaymentDone(Exception): pass
class PaymentTimeout(Exception): pass
class SuccessfulTest(Exception): pass


def inject_chan_into_gossipdb(
    *,
    channel_db: ChannelDB,
    chanAB: Channel,
    chanBA: Channel,
) -> None:
    assert chanAB.channel_id == chanBA.channel_id
    print(f"injecting channel {chanAB.name} into channel_db")
    chan_ann_raw = chanAB.construct_channel_announcement_without_sigs()[0]
    chan_ann_dict = decode_msg(chan_ann_raw)[1]
    channel_db.add_channel_announcements(chan_ann_dict, trusted=True)

    chan_upd1_raw = chanAB.get_outgoing_gossip_channel_update()
    chan_upd1_dict = decode_msg(chan_upd1_raw)[1]
    channel_db.add_channel_update(chan_upd1_dict, verify=False)

    chan_upd2_raw = chanBA.get_outgoing_gossip_channel_update()
    chan_upd2_dict = decode_msg(chan_upd2_raw)[1]
    channel_db.add_channel_update(chan_upd2_dict, verify=False)


@dataclasses.dataclass(kw_only=True)
class SenderHtlcResolvedTracker:
    resolved_event: asyncio.Event  # "single HTLC got fulfilled/failed"
    num_success: int = 0
    num_failed: int = 0

    async def _on_sender_htlc_fulfilled(self, *args):
        self.num_success += 1
        self.resolved_event.set()
        self.resolved_event.clear()

    async def _on_sender_htlc_failed(self, *args):
        self.num_failed += 1
        self.resolved_event.set()
        self.resolved_event.clear()

    @classmethod
    def register(cls) -> 'SenderHtlcResolvedTracker':
        evt = asyncio.Event()
        tracker = SenderHtlcResolvedTracker(resolved_event=evt)
        # note: these callbacks only fire for the original sender of an HTLC
        util.register_callback(tracker._on_sender_htlc_fulfilled, ["htlc_fulfilled"])
        util.register_callback(tracker._on_sender_htlc_failed, ["htlc_failed"])
        # ElectrumTestCase.tearDown() will clean up after us using callback_mgr.clear_all_callbacks()
        return tracker

def send_trampoline_htlc_to_forward(
    *,
    p1: Peer,
    w1: MockLNWallet,
    w2: MockLNWallet,
    chan: Channel,
    payment_hash: bytes,
    outer_payment_secret: bytes,
    htlc_amount_msat: int,
    amt_to_forward: int,
    inner_cltv_delta: int = 144,
    outgoing_node_id: bytes = None,
) -> UpdateAddHtlc:
    """Sends an htlc from w1 to w2 whose outer onion is a final hop to w2, claiming
    total_msat == htlc_amount_msat, and whose inner trampoline onion asks w2 to *forward*
    amt_to_forward to outgoing_node_id, to be delivered at (cltv_abs - inner_cltv_delta).
    A negative inner_cltv_delta asks w2 to lock up funds for longer than it is given.
    note: nothing constrains the outer onion's total_msat here. w2 is not the final
    recipient, so he has no invoice to validate such an htlc against.
    """
    cltv_abs = w1.network.get_local_height() + 500
    next_node_id = outgoing_node_id or privkey_to_pubkey(os.urandom(32))
    trampoline_hops_data = [
        OnionHopsDataSingle(payload={
            "amt_to_forward": {"amt_to_forward": amt_to_forward},
            "outgoing_cltv_value": {"outgoing_cltv_value": cltv_abs - inner_cltv_delta},
            "outgoing_node_id": {"outgoing_node_id": next_node_id},
        }),
        OnionHopsDataSingle(payload={
            "amt_to_forward": {"amt_to_forward": amt_to_forward},
            "outgoing_cltv_value": {"outgoing_cltv_value": cltv_abs - inner_cltv_delta},
            "payment_data": {"payment_secret": os.urandom(32), "total_msat": amt_to_forward},
        }),
    ]
    trampoline_onion = electrum.lnonion.new_onion_packet(
        [w2.node_keypair.pubkey, next_node_id],
        os.urandom(32),
        trampoline_hops_data,
        associated_data=payment_hash,
        trampoline=True,
    )
    hops_data = [OnionHopsDataSingle(payload={
        "amt_to_forward": {"amt_to_forward": htlc_amount_msat},
        "outgoing_cltv_value": {"outgoing_cltv_value": cltv_abs},
        "payment_data": {"payment_secret": outer_payment_secret, "total_msat": htlc_amount_msat},
        "trampoline_onion_packet": {"trampoline_onion_packet": trampoline_onion.to_bytes()},
    })]
    onion = electrum.lnonion.new_onion_packet(
        [w2.node_keypair.pubkey], os.urandom(32), hops_data, associated_data=payment_hash)
    return p1.send_htlc(
        chan=chan,
        payment_hash=payment_hash,
        amount_msat=htlc_amount_msat,
        cltv_abs=cltv_abs,
        onion=onion,
    )


class TestPeer(ElectrumTestCase):
    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()
        self.GRAPH_DEFINITIONS = copy.deepcopy(lnhelpers._GRAPH_DEFINITIONS)

    async def asyncTearDown(self):
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {}
        await super().asyncTearDown()

    prepare_invoice = staticmethod(lnhelpers.prepare_invoice)

    async def _activate_trampoline(self, w: MockLNWallet):
        if w.network.channel_db:
            w.network.channel_db.stop()
            await w.network.channel_db.stopped_event.wait()
            w.network.channel_db = None

    def prepare_recipient(self, w2, payment_hash, test_hold_invoice, test_failure):
        if not test_hold_invoice and not test_failure:
            return
        preimage_hex, is_public = w2._preimages.pop(payment_hash.hex())
        preimage = bytes.fromhex(preimage_hex)
        if test_hold_invoice:
            async def cb(payment_hash):
                if not test_failure:
                    w2.save_preimage(payment_hash, preimage, mark_as_public=is_public)
                else:
                    raise OnionRoutingFailure(code=OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, data=b'')
            w2.register_hold_invoice(payment_hash, cb)

    def prepare_lnwallets(self, graph_definition) -> Mapping[str, MockLNWallet]:
        return lnhelpers.prepare_lnwallets(self, graph_definition)

    def prepare_chans_and_peers_in_graph(self, *args, **kwargs):
        return lnhelpers.prepare_chans_and_peers_in_graph(self, *args, **kwargs)


class TestPeerUtils(TestPeer):

    def test_decode_short_ids(self):
        """
        Test Peer.decode_short_ids() against some data from
        https://github.com/lightning/bolts/commit/313c0f290eb87e96dc8195cad0c891418a826c2c
        """
        # Test uncompressed encoding with three scids
        encoded_uncompressed = bytes.fromhex("00" + "0000000000003043" + "00000000000778d6" + "000000000046e1c1")
        result = Peer.decode_short_ids(encoded_uncompressed)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0], bytes.fromhex("0000000000003043"))  # 0x0x12355
        self.assertEqual(result[1], bytes.fromhex("00000000000778d6"))  # 0x7x30934
        self.assertEqual(result[2], bytes.fromhex("000000000046e1c1"))  # 0x70x57793

        # Test empty list
        encoded_empty = bytes.fromhex("00")
        result = Peer.decode_short_ids(encoded_empty)
        self.assertEqual(result, [])

        # Test single scid
        encoded_single = bytes.fromhex("00" + "000000000000008e")  # 0x0x142
        result = Peer.decode_short_ids(encoded_single)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], bytes.fromhex("000000000000008e"))

        # test invalid size raises exception
        encoded_invalid = bytes.fromhex("00" + "00" * 9)
        with self.assertRaises(Exception) as ctx:
            Peer.decode_short_ids(encoded_invalid)
        self.assertIn("invalid size", str(ctx.exception))

        # Test unsupported encoding raises exception (considering it even passes the length check)
        encoded_unsupported = bytes.fromhex("01" + "00" * 8)  # 01 was zlib before removed
        with self.assertRaises(Exception) as ctx:
            Peer.decode_short_ids(encoded_unsupported)
        self.assertIn("unexpected first byte", str(ctx.exception))

    async def test_maybe_save_remote_update(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        alice_bob_peer, bob_alice_peer = graph.peers[('alice', 'bob')], graph.peers[('bob', 'alice')]
        alice_bob_chan, bob_alice_chan = graph.channels[('alice', 'bob')][0], graph.channels[('bob', 'alice')][0]

        # prepare channel update from alice
        alice_to_bob_chan_update = alice_bob_chan.get_outgoing_gossip_channel_update()
        raw = alice_to_bob_chan_update
        payload = decode_msg(alice_to_bob_chan_update)[1]
        payload['raw'] = raw

        # bob should accept the update and save it
        self.assertIsNone(bob_alice_chan.storage.get('remote_update'))
        bob_alice_peer.maybe_save_remote_update(payload)
        self.assertEqual(bob_alice_chan.storage.get('remote_update'), raw.hex())

        # alice shouldn't save her own channel update as remote update
        self.assertIsNone(alice_bob_chan.storage.get('remote_update'))
        alice_bob_peer.maybe_save_remote_update(payload)
        self.assertIsNone(alice_bob_chan.storage.get('remote_update'))

        ChannelDB.verify_channel_update(payload, start_node=bob_alice_peer.pubkey)
        # trying to verify the sig against the wrong pubkey should fail obviously
        with self.assertRaises(InvalidGossipMsg):
            ChannelDB.verify_channel_update(payload, start_node=alice_bob_peer.pubkey)

    async def test_zeroconf_feature_bit(self):
        workers = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan'])

        with self.subTest(msg="zeroconf is disabled in Alice LNWallet, so peers shouldn't signal it either"):
            graph = self.prepare_chans_and_peers_in_graph(
                self.GRAPH_DEFINITIONS['single_chan'],
                workers=workers,
            )
            alice, _ = graph.peers.values()
            self.assertFalse(alice.features.supports(LnFeatures.OPTION_ZEROCONF_OPT))

        # enable zeroconf in alice LNWallet
        workers['alice'].features |= LnFeatures.OPTION_ZEROCONF_OPT

        with self.subTest(msg="no trusted zeroconf node, zeroconf should be signaled in new peers"):
            graph = self.prepare_chans_and_peers_in_graph(
                self.GRAPH_DEFINITIONS['single_chan'],
                workers=workers,
            )
            alice, _ = graph.peers.values()   # alice is LSP
            self.assertTrue(alice.features.supports(LnFeatures.OPTION_ZEROCONF_OPT))

        with self.subTest(msg="trusted node is configured, but it is not bob"):
            workers['alice'].config.ZEROCONF_TRUSTED_NODE = f"{os.urandom(33).hex()}@1.1.1.1:9735"
            graph = self.prepare_chans_and_peers_in_graph(
                self.GRAPH_DEFINITIONS['single_chan'],
                workers=workers,
            )
            alice, _ = graph.peers.values()  # alice is client
            self.assertFalse(alice.features.supports(LnFeatures.OPTION_ZEROCONF_OPT))

        with self.subTest(msg="trusted node is configured, but it is invalid"):
            workers['alice'].config.ZEROCONF_TRUSTED_NODE = f"{os.urandom(8).hex()}@1.1.1.1:9735"
            graph = self.prepare_chans_and_peers_in_graph(
                self.GRAPH_DEFINITIONS['single_chan'],
                workers=workers,
            )
            alice, _ = graph.peers.values()  # alice is client
            self.assertFalse(alice.features.supports(LnFeatures.OPTION_ZEROCONF_OPT))

        with self.subTest(msg="Alice uses Bob as her trusted LSP"):
            workers['alice'].config.ZEROCONF_TRUSTED_NODE = workers['bob'].node_keypair.pubkey.hex()
            graph = self.prepare_chans_and_peers_in_graph(
                self.GRAPH_DEFINITIONS['single_chan'],
                workers=workers,
            )
            alice, _ = graph.peers.values()
            self.assertTrue(alice.features.supports(LnFeatures.OPTION_ZEROCONF_OPT))


class TestPeerDirect(TestPeer):

    def prepare_peers(
            self, alice_channel: Channel, bob_channel: Channel,
    ):
        graph = self.prepare_chans_and_peers_in_graph(
            self.GRAPH_DEFINITIONS['single_chan'],
            channels={('alice', 'bob'): [alice_channel], ('bob', 'alice'): [bob_channel]},
        )
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        return p1, p2, w1, w2

    async def test_reestablish_happycase(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]

        for chan in (alice_channel, bob_channel):
            chan.peer_state = PeerState.DISCONNECTED
        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            self.assertEqual(alice_channel.peer_state, PeerState.GOOD)
            self.assertEqual(bob_channel.peer_state, PeerState.GOOD)
            self.assertEqual((alice_channel._state, bob_channel._state), (ChannelState.OPEN, ChannelState.OPEN))
            gath.cancel()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(asyncio.CancelledError):
            await gath

    async def test_reestablish_with_old_state(self):
        async def f(alice_slow: bool, bob_slow: bool):
            random_seed = os.urandom(32)
            alice_lnwallet, bob_lnwallet = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan']).values()
            alice_channel, bob_channel = create_test_channels(random_seed=random_seed, alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)
            alice_channel_0, bob_channel_0 = create_test_channels(random_seed=random_seed, alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)  # these are identical
            p1, p2, w1, w2 = self.prepare_peers(alice_channel, bob_channel)
            lnaddr, pay_req = self.prepare_invoice(w2)
            async def pay():
                result, log = await w1.pay_invoice(pay_req)
                self.assertEqual(result, True)
                gath.cancel()
            gath = asyncio.gather(pay(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
            with self.assertRaises(asyncio.CancelledError):
                await gath
            p1, p2, w1, w2 = self.prepare_peers(alice_channel_0, bob_channel)
            for chan in (alice_channel_0, bob_channel):
                chan.peer_state = PeerState.DISCONNECTED

            async def alice_sends_reest():
                if alice_slow: await asyncio.sleep(0.05)
                await p1.reestablish_channel(alice_channel_0)
            async def bob_sends_reest():
                if bob_slow: await asyncio.sleep(0.05)
                await p2.reestablish_channel(bob_channel)

            with self.assertRaises(GracefulDisconnect):
                async with OldTaskGroup() as group:
                    await group.spawn(p1._message_loop())
                    await group.spawn(p1.htlc_switch())
                    await group.spawn(p2._message_loop())
                    await group.spawn(p2.htlc_switch())
                    await group.spawn(alice_sends_reest)
                    await group.spawn(bob_sends_reest)
            self.assertEqual(alice_channel_0.peer_state, PeerState.BAD)
            self.assertEqual(alice_channel_0._state, ChannelState.WE_ARE_TOXIC)
            self.assertEqual(bob_channel._state, ChannelState.FORCE_CLOSING)

        with self.subTest(msg="both fast"):
            # FIXME: we want to test the case where both Alice and Bob sends channel-reestablish before
            #        receiving what the other sent. This is not a reliable way to do that...
            await f(alice_slow=False, bob_slow=False)
        with self.subTest(msg="alice is slow"):
            await f(alice_slow=True, bob_slow=False)
        with self.subTest(msg="bob is slow"):
            await f(alice_slow=False, bob_slow=True)

    async def test_reestablish_fake_data(self):
        async def f(
            alice_slow: bool,
            bob_slow: bool,
            *,
            ctn_delta: int = 0,
            revnum_delta: int = 0,
            last_rev_secret: bytes | None = None,
        ) -> tuple[Channel, Channel]:
            alice_lnwallet, bob_lnwallet = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan']).values()
            alice_channel, bob_channel = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)
            p1, p2, w1, w2 = self.prepare_peers(alice_channel, bob_channel)
            # first make some payments, to bump the channel ctns a bit
            async def pay():
                for pnum in range(2):
                    lnaddr, pay_req = self.prepare_invoice(w2)
                    result, log = await w1.pay_invoice(pay_req)
                    self.assertEqual(result, True)
                gath.cancel()
            gath = asyncio.gather(pay(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
            with self.assertRaises(asyncio.CancelledError):
                await gath
            for chan in (alice_channel, bob_channel):
                chan.peer_state = PeerState.DISCONNECTED

            # now reestablish the channel
            async def alice_sends_reest():
                nonlocal last_rev_secret
                if alice_slow: await asyncio.sleep(0.05)
                chan = alice_channel
                next_local_ctn = chan.get_next_ctn(LOCAL) + ctn_delta
                assert next_local_ctn >= 0, next_local_ctn
                oldest_unrevoked_remote_ctn = chan.get_oldest_unrevoked_ctn(REMOTE) + revnum_delta
                assert oldest_unrevoked_remote_ctn >= 0, oldest_unrevoked_remote_ctn
                if last_rev_secret is None:
                    revnum_for_secret = oldest_unrevoked_remote_ctn % (2**48)
                    if revnum_delta <= 0:
                        last_rev_secret = chan.revocation_store.retrieve_secret(RevocationStore.START_INDEX - revnum_for_secret + 1)
                    else:  # Alice is using *magic* here, i.e. cheating: she uses Bob's channel to learn future unrevealed secrets
                        last_rev_secret, _point = bob_channel.get_secret_and_point(LOCAL, revnum_for_secret - 1)
                p1.send_message(
                    "channel_reestablish",
                    channel_id=chan.channel_id,
                    next_commitment_number=next_local_ctn,
                    next_revocation_number=oldest_unrevoked_remote_ctn,
                    your_last_per_commitment_secret=last_rev_secret,
                    my_current_per_commitment_point=ecc.GENERATOR.get_public_key_bytes(compressed=True),
                )
            async def bob_sends_reest():
                if bob_slow: await asyncio.sleep(0.05)
                await p2.reestablish_channel(bob_channel)

            async def exit_after_bob_receives_reest():
                await p2.channel_reestablish_msg[bob_channel.channel_id]

            with self.assertRaises((GracefulDisconnect, lnutil.RemoteMisbehaving)):
                async with OldTaskGroup() as group:
                    await group.spawn(p1._message_loop())
                    await group.spawn(p1.htlc_switch())
                    await group.spawn(p2._message_loop())
                    await group.spawn(p2.htlc_switch())
                    await p1.initialized
                    await p2.initialized
                    await group.spawn(alice_sends_reest)
                    await group.spawn(bob_sends_reest)
                    await group.spawn(exit_after_bob_receives_reest)
            return alice_channel, bob_channel

        cs = ChannelState
        for (alice_slow, bob_slow) in (
            (False, False),  # both fast: FIXME: we want to test the case where both Alice and Bob sends channel-reestablish before
                             #                   receiving what the other sent. This is not a reliable way to do that...
            (True, False),
            (False, True),
        ):
            kwargs = {"alice_slow": alice_slow, "bob_slow": bob_slow}
            # note: Alice's channel state will stay OPEN in every case:
            #       she is intentionally sending weird data that does not reflect her true state.
            with self.subTest(msg="next_local_ctn from past", **kwargs):
                a_chan, b_chan = await f(ctn_delta=-2, **kwargs)
                self.assertEqual((a_chan._state, b_chan._state), (cs.OPEN, cs.FORCE_CLOSING))
            with self.subTest(msg="next_local_ctn from future", **kwargs):
                a_chan, b_chan = await f(ctn_delta=1000, **kwargs)
                self.assertEqual((a_chan._state, b_chan._state), (cs.OPEN, cs.FORCE_CLOSING))
            with self.subTest(msg="oldest_unrevoked_remote_ctn from past", **kwargs):
                a_chan, b_chan = await f(revnum_delta=-2, **kwargs)
                self.assertEqual((a_chan._state, b_chan._state), (cs.OPEN, cs.FORCE_CLOSING))
            with self.subTest(msg="oldest_unrevoked_remote_ctn from future", **kwargs):
                a_chan, b_chan = await f(revnum_delta=1000, **kwargs)
                self.assertEqual((a_chan._state, b_chan._state), (cs.OPEN, cs.WE_ARE_TOXIC))
            with self.subTest(msg="invalid last_rev_secret", **kwargs):
                a_chan, b_chan = await f(last_rev_secret=sha256("fake_data"), **kwargs)
                self.assertEqual((a_chan._state, b_chan._state), (cs.OPEN, cs.FORCE_CLOSING))
            with self.subTest(msg="overflow of next_local_ctn", **kwargs):
                with self.assertLogs('electrum', level='INFO') as logs:
                    a_chan, b_chan = await f(ctn_delta=2**48, **kwargs)
                self.assertEqual((a_chan._state, b_chan._state), (cs.OPEN, cs.FORCE_CLOSING))
                self.assertTrue(any(("bob->alice" in msg and "channel_reestablish" in msg and "ctn overflow" in msg)
                                    for msg in logs.output))
            with self.subTest(msg="overflow of oldest_unrevoked_remote_ctn", **kwargs):
                with self.assertLogs('electrum', level='INFO') as logs:
                    a_chan, b_chan = await f(revnum_delta=2**48, **kwargs)
                self.assertEqual((a_chan._state, b_chan._state), (cs.OPEN, cs.FORCE_CLOSING))
                self.assertTrue(any(("bob->alice" in msg and "channel_reestablish" in msg and "ctn overflow" in msg)
                                    for msg in logs.output))

    @staticmethod
    def _send_fake_htlc(peer: Peer, chan: Channel) -> UpdateAddHtlc:
        htlc = UpdateAddHtlc(amount_msat=10000, payment_hash=os.urandom(32), cltv_abs=999, timestamp=1)
        htlc = chan.add_htlc(htlc)
        peer.send_message(
            "update_add_htlc",
            channel_id=chan.channel_id,
            id=htlc.htlc_id,
            cltv_expiry=htlc.cltv_abs,
            amount_msat=htlc.amount_msat,
            payment_hash=htlc.payment_hash,
            onion_routing_packet=1366 * b"0",
        )
        return htlc

    async def _test_reestablish_replay_messages(self, rev_then_sig: bool):
        alice_lnwallet, bob_lnwallet = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan']).values()
        chan_AB, chan_BA = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)
        # note: we don't start peer.htlc_switch() so that the fake htlcs are left alone.
        async def f():
            p1, p2, w1, w2 = self.prepare_peers(chan_AB, chan_BA)
            p1.MIN_TIME_BETWEEN_SENDING_COMMITSIGS = 0
            p2.MIN_TIME_BETWEEN_SENDING_COMMITSIGS = 0
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p2._message_loop())
                await p1.initialized
                await p2.initialized
                self._send_fake_htlc(p2, chan_BA)
                self._send_fake_htlc(p1, chan_AB)
                p2.transport.queue.put_nowait(asyncio.Event())  # break Bob's incoming pipe
                if rev_then_sig:
                    self.assertTrue(p2.maybe_send_commitment(chan_BA))
                    await p1.received_commitsig_event.wait()
                else:
                    self.assertTrue(p1.maybe_send_commitment(chan_AB))
                    self.assertTrue(p2.maybe_send_commitment(chan_BA))
                    await p1.received_commitsig_event.wait()
                await group.cancel_remaining()
            # simulating disconnection. recreate transports.
            self.logger.info("simulating disconnection. recreating transports.")
            p1, p2, w1, w2 = self.prepare_peers(chan_AB, chan_BA)
            p1.MIN_TIME_BETWEEN_SENDING_COMMITSIGS = 0
            p2.MIN_TIME_BETWEEN_SENDING_COMMITSIGS = 0
            for chan in (chan_AB, chan_BA):
                chan.peer_state = PeerState.DISCONNECTED
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p2._message_loop())
                with self.assertLogs('electrum', level='INFO') as logs:
                    async with OldTaskGroup() as group2:
                        await group2.spawn(p1.reestablish_channel(chan_AB))
                        await group2.spawn(p2.reestablish_channel(chan_BA))
                s = "replaying a revoke_and_ack " + ("first" if rev_then_sig else "last")
                self.assertTrue(any(("alice->bob" in msg and s in msg) for msg in logs.output))
                self.assertTrue(any(("alice->bob" in msg and
                                     "replayed 2 unacked messages. ['update_add_htlc', 'commitment_signed']" in msg) for msg in logs.output))
                self.assertEqual(chan_AB.peer_state, PeerState.GOOD)
                self.assertEqual(chan_BA.peer_state, PeerState.GOOD)
                await group.cancel_remaining()
            raise SuccessfulTest()
        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_reestablish_replay_messages_rev_then_sig(self):
        """
        See https://github.com/lightning/bolts/pull/810#issue-728299277

        Rev then Sig
        A            B
         <---add-----
         ----add---->
         <---sig-----
         ----rev----x
         ----sig----x

        A needs to retransmit:
        ----rev-->      (note that 'add' can be first too)
        ----add-->
        ----sig-->
        """
        await self._test_reestablish_replay_messages(True)

    async def test_reestablish_replay_messages_sig_then_rev(self):
        """
        See https://github.com/lightning/bolts/pull/810#issue-728299277

        Sig then Rev
        A            B
         <---add-----
         ----add---->
         ----sig----x
         <---sig-----
         ----rev----x

        A needs to retransmit:
        ----add-->
        ----sig-->
        ----rev-->
        """
        await self._test_reestablish_replay_messages(False)

    async def _test_simple_payment(
            self,
            test_trampoline: bool,
            test_hold_invoice=False,
            test_failure=False,
            test_bundle=False,
            test_bundle_timeout=False
    ):
        """Alice pays Bob a single HTLC via direct channel."""
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        results = {}
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            result, log = await w1.pay_invoice(pay_req)
            if result is True:
                self.assertEqual(PR_PAID, w2.get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
                results[lnaddr] = PaymentDone()
            else:
                results[lnaddr] = PaymentFailure()
        lnaddr, pay_req = self.prepare_invoice(w2)
        to_pay = [(lnaddr, pay_req)]
        self.prepare_recipient(w2, lnaddr.paymenthash, test_hold_invoice, test_failure)

        if test_bundle:
            lnaddr2, pay_req2 = self.prepare_invoice(w2)
            w2.bundle_payments([lnaddr.paymenthash, lnaddr2.paymenthash])
            if not test_bundle_timeout:
                to_pay.append((lnaddr2, pay_req2))

        if test_trampoline:
            await self._activate_trampoline(w1)
            # declare bob as trampoline node
            electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=w2.node_keypair.pubkey),
            }

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                invoice_features = lnaddr.get_features()
                self.assertFalse(invoice_features.supports(LnFeatures.BASIC_MPP_OPT))
                for lnaddr_to_pay, pay_req_to_pay in to_pay:
                    await group.spawn(pay(lnaddr_to_pay, pay_req_to_pay))
                elapsed = 0
                while len(results) < len(to_pay) and elapsed < 4:
                    await asyncio.sleep(0.05)  # wait for all payments to finish/fail (or timeout)
                    elapsed += 0.05
                self.assertEqual(len(results), len(to_pay), msg="timeout")
                # all payment results should be similar
                self.assertEqual(len(set(type(res) for res in results.values())), 1, msg=results)
                raise list(results.values())[0]

        await f()

    async def test_simple_payment_success(self):
        for test_trampoline in [False, True]:
            with self.assertRaises(PaymentDone):
                await self._test_simple_payment(test_trampoline=test_trampoline)

    async def test_simple_payment_failure(self):
        for test_trampoline in [False, True]:
            with self.assertRaises(PaymentFailure):
                await self._test_simple_payment(test_trampoline=test_trampoline, test_failure=True)

    async def test_payment_bundle(self):
        for test_trampoline in [False, True]:
            with self.assertRaises(PaymentDone):
                await self._test_simple_payment(test_trampoline=test_trampoline, test_bundle=True)

    async def test_payment_bundle_timeout(self):
        for test_trampoline in [False, True]:
            with self.assertRaises(PaymentFailure):
                await self._test_simple_payment(test_trampoline=test_trampoline, test_bundle=True, test_bundle_timeout=True)

    async def test_payment_bundle_with_hold_invoice(self):
        for test_trampoline in [False, True]:
            with self.assertRaises(PaymentDone):
                await self._test_simple_payment(test_trampoline=test_trampoline, test_bundle=True, test_hold_invoice=True)

    async def test_simple_payment_success_with_hold_invoice(self):
        for test_trampoline in [False, True]:
            with self.assertRaises(PaymentDone):
                await self._test_simple_payment(test_trampoline=test_trampoline, test_hold_invoice=True)

    async def test_simple_payment_failure_with_hold_invoice(self):
        for test_trampoline in [False, True]:
            with self.assertRaises(PaymentFailure):
                await self._test_simple_payment(test_trampoline=test_trampoline, test_hold_invoice=True, test_failure=True)

    async def test_check_invoice_before_payment(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        async def try_paying_some_invoices():
            # feature bits: unknown even fbit
            invoice_features = w2.features.for_bolt11_invoice() | (1 << 990)  # add undefined even fbit
            lnaddr, pay_req = self.prepare_invoice(w2, invoice_features=invoice_features)
            with self.assertRaises(lnutil.UnknownEvenFeatureBits):
                result, log = await w1.pay_invoice(pay_req)
            # feature bits: not all transitive dependencies are set
            invoice_features = LnFeatures((1 << 14) + (1 << 17))
            lnaddr, pay_req = self.prepare_invoice(w2, invoice_features=invoice_features)
            with self.assertRaises(lnutil.IncompatibleOrInsaneFeatures):
                result, log = await w1.pay_invoice(pay_req)
            # too large CLTV
            lnaddr, pay_req = self.prepare_invoice(w2, min_final_cltv_delta=10**6)
            with self.assertRaises(InvoiceError):
                result, log = await w1.pay_invoice(pay_req)
            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(try_paying_some_invoices())

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_reject_invalid_min_final_cltv_delta(self):
        """
        Tests that htlcs with a final cltv delta < the minimum requested in the invoice get
        rejected immediately upon receiving them.
        """
        async def run_test(test_trampoline):
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
            p1, p2 = graph.peers.values()
            w1, w2 = graph.workers.values()

            async def try_pay_with_too_low_final_cltv_delta(lnaddr, w1=w1, w2=w2):
                self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
                assert lnaddr.get_min_final_cltv_delta() == 400  # what the receiver expects
                lnaddr.tags = [tag for tag in lnaddr.tags if tag[0] != 'c'] + [['c', 144]]
                b11 = encode_bolt11_invoice(lnaddr, w2.node_keypair.privkey)
                pay_req = Invoice.from_bech32(b11)
                assert pay_req._lnaddr.get_min_final_cltv_delta() == 144  # what w1 will use to pay
                result, log = await w1.pay_invoice(pay_req)
                if not result:
                    raise PaymentFailure()
                raise PaymentDone()

            # create invoice with high min final cltv delta
            lnaddr, _pay_req = self.prepare_invoice(w2, min_final_cltv_delta=400)

            if test_trampoline:
                await self._activate_trampoline(w1)
                # declare bob as trampoline node
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=w2.node_keypair.pubkey),
                }

            async def f():
                async with OldTaskGroup() as group:
                    await group.spawn(p1._message_loop())
                    await group.spawn(p1.htlc_switch())
                    await group.spawn(p2._message_loop())
                    await group.spawn(p2.htlc_switch())
                    await asyncio.sleep(0.01)
                    await group.spawn(try_pay_with_too_low_final_cltv_delta(lnaddr))

            with self.assertRaises(PaymentFailure):
                await f()

        for _test_trampoline in [False, True]:
            await run_test(_test_trampoline)

    async def test_reject_payment_for_expired_invoice(self):
        """Tests that new htlcs paying an invoice that has already been expired will get rejected."""
        async def run_test(test_trampoline):
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
            p1, p2 = graph.peers.values()
            w1, w2 = graph.workers.values()

            # create lightning invoice in the past, so it is expired
            with mock.patch('time.time', return_value=int(time.time()) - 10000):
                lnaddr, _pay_req = self.prepare_invoice(w2, expiry=3600)
                b11 = encode_bolt11_invoice(lnaddr, w2.node_keypair.privkey)
                pay_req = Invoice.from_bech32(b11)

            async def try_pay_expired_invoice(pay_req: Invoice, w1=w1):
                assert pay_req.has_expired()
                assert lnaddr.is_expired()
                with mock.patch.object(w1, "_check_bolt11_invoice", return_value=lnaddr):
                    result, log = await w1.pay_invoice(pay_req)
                if not result:
                    raise PaymentFailure()
                raise PaymentDone()

            if test_trampoline:
                await self._activate_trampoline(w1)
                # declare bob as trampoline node
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=w2.node_keypair.pubkey),
                }

            async def f():
                async with OldTaskGroup() as group:
                    await group.spawn(p1._message_loop())
                    await group.spawn(p1.htlc_switch())
                    await group.spawn(p2._message_loop())
                    await group.spawn(p2.htlc_switch())
                    await asyncio.sleep(0.01)
                    await group.spawn(try_pay_expired_invoice(pay_req))

            with self.assertRaises(PaymentFailure):
                await f()

        for _test_trampoline in [False, True]:
            await run_test(_test_trampoline)

    async def test_reject_mpp_for_non_mpp_invoice(self):
        """Test that we reject a payment if it is mpp and we didn't signal support for mpp in the invoice"""
        async def run_test(test_trampoline):
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
            p1, p2 = graph.peers.values()
            w1, w2 = graph.workers.values()
            w1.config.TEST_FORCE_MPP = True  # force alice to send mpp

            if test_trampoline:
                await self._activate_trampoline(w1)
                await self._activate_trampoline(w2)
                # declare bob as trampoline node
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=w2.node_keypair.pubkey),
                }

            lnaddr, pay_req = self.prepare_invoice(w2)
            self.assertFalse(lnaddr.get_features().supports(LnFeatures.BASIC_MPP_OPT))
            self.assertFalse(lnaddr.get_features().supports(LnFeatures.BASIC_MPP_REQ))

            async def try_pay_invoice_with_mpp(pay_req: Invoice, w1=w1):
                result, log = await w1.pay_invoice(pay_req)
                if not result:
                    raise PaymentFailure()
                raise PaymentDone()

            async def f():
                async with OldTaskGroup() as group:
                    await group.spawn(p1._message_loop())
                    await group.spawn(p1.htlc_switch())
                    await group.spawn(p2._message_loop())
                    await group.spawn(p2.htlc_switch())
                    await asyncio.sleep(0.01)
                    await group.spawn(try_pay_invoice_with_mpp(pay_req))

            with self.assertRaises(PaymentFailure):
                await f()

        for _test_trampoline in [False, True]:
            await run_test(_test_trampoline)

    async def test_reject_multiple_payments_of_same_invoice(self):
        """Tests that new htlcs paying an invoice that has already been paid will get rejected."""
        async def run_test(test_trampoline):
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
            p1, p2 = graph.peers.values()
            w1, w2 = graph.workers.values()

            lnaddr, _pay_req = self.prepare_invoice(w2)

            async def try_pay_invoice_twice(pay_req: Invoice, w1=w1):
                result, log = await w1.pay_invoice(pay_req)
                assert result is True
                # now pay the same invoice again, the payment should be rejected by w2
                w1.set_payment_status(pay_req._lnaddr.paymenthash, PR_UNPAID, direction=lnutil.SENT)
                result, log = await w1.pay_invoice(pay_req)
                if not result:
                    # w1.pay_invoice returned a payment failure as the payment got rejected by w2
                    raise SuccessfulTest()
                raise PaymentDone()

            if test_trampoline:
                await self._activate_trampoline(w1)
                # declare bob as trampoline node
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=w2.node_keypair.pubkey),
                }

            async def f():
                async with OldTaskGroup() as group:
                    await group.spawn(p1._message_loop())
                    await group.spawn(p1.htlc_switch())
                    await group.spawn(p2._message_loop())
                    await group.spawn(p2.htlc_switch())
                    await asyncio.sleep(0.01)
                    await group.spawn(try_pay_invoice_twice(_pay_req))

            with self.assertRaises(SuccessfulTest):
                await f()

        for _test_trampoline in [False, True]:
            await run_test(_test_trampoline)

    async def test_invoice_stays_inflight_while_htlcs_unresolved_then_paid(self):
        """Tests that we don't mark an invoice as failed while htlcs we sent for it are still
        unresolved. The receiver can still fulfill those htlcs, so telling the user the payment
        failed would trick them into paying twice, e.g. using a fresh invoice, which the
        "did not clear" check in pay_invoice cannot detect as a retry.
        After we give up on a paysession, the remote fulfills the htlc, and we mark the invoice PAID.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        w2.enable_htlc_settle = False  # bob holds the htlc: he neither settles nor fails it
        lnaddr, pay_req = self.prepare_invoice(w2)
        payment_hash = lnaddr.paymenthash

        # simulate pay_to_node giving up (e.g. out of attempts) while an htlc is still unresolved
        orig_pay_to_node = w1.pay_to_node

        async def pay_to_node_that_gives_up(**kwargs):
            task = asyncio.ensure_future(orig_pay_to_node(**kwargs))
            await p2.received_commitsig_event.wait()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise PaymentFailure('giving up while htlcs are unresolved')

        w1.pay_to_node = pay_to_node_that_gives_up

        async def pay():
            result, log = await w1.pay_invoice(pay_req)
            self.assertFalse(result)
            self.assertTrue(w1.has_unresolved_sent_htlcs(payment_hash))
            # the money is still at risk, so the invoice must not look failed/unpaid
            self.assertEqual(PR_INFLIGHT, w1.get_invoice_status(pay_req))
            with self.assertRaises(PaymentFailure):
                await w1.pay_invoice(pay_req)
            # now let bob fulfill the htlc. nobody is waiting for the payment anymore,
            # but the invoice must still end up as paid.
            w2.enable_htlc_settle = True
            async with util.async_timeout(5):
                while w1.get_invoice_status(pay_req) != PR_PAID:
                    await asyncio.sleep(0.01)
            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(pay())

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_invoice_stays_inflight_while_htlcs_unresolved_then_failed(self):
        """Tests that we don't mark an invoice as failed while htlcs we sent for it are still
        unresolved. After we give up on paysession, we keep receiving htlc failures.
        Only after the very last htlc failure is received shall we mark the invoice as FAILED.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        w1.config.TEST_FORCE_MPP = True  # force alice to send mpp
        w2.features |= LnFeatures.BASIC_MPP_OPT
        w2.enable_htlc_settle = False  # bob holds the htlc: he neither settles nor fails it
        lnaddr, pay_req = self.prepare_invoice(w2)
        self.assertTrue(lnaddr.get_features().supports(LnFeatures.BASIC_MPP_OPT))
        payment_hash = lnaddr.paymenthash
        bob_channel = graph.channels[('bob', 'alice')][0]

        def bobs_pending_htlcs():
            return bob_channel.hm.get_htlcs_in_latest_ctx(HTLCOwner.LOCAL)

        async def pay():
            # Alice starts a payment attempt
            task = asyncio.create_task(w1.pay_invoice(pay_req))
            while len(bobs_pending_htlcs()) < 2:
                await p1.received_commitsig_event.wait()
            # but she quickly gives up. with htlcs left pending
            task.cancel()
            self.assertTrue(w1.has_unresolved_sent_htlcs(payment_hash))
            # the money is still at risk, so the invoice must not look failed/unpaid
            self.assertEqual(PR_INFLIGHT, w1.get_invoice_status(pay_req))  # money is still at risk, hence PR_INFLIGHT
            # Bob fails one HTLC, but keeps the rest pending (using "fail_malformed" as it's easier to simulate here)
            pending_htlcs_orig = bobs_pending_htlcs()
            assert len(pending_htlcs_orig) >= 2
            p2.fail_malformed_htlc(chan=bob_channel, htlc_id=0, reason=OnionParsingError(data=bytes(32)))
            await p2.received_commitsig_event.wait()
            pending_htlcs = bobs_pending_htlcs()
            assert len(pending_htlcs) == len(pending_htlcs_orig) - 1
            self.assertEqual(PR_INFLIGHT, w1.get_invoice_status(pay_req))
            # Bob fails all HTLCs, now Alice can safely mark the invoice as FAILED
            for htlc_dir, htlc in pending_htlcs:
                p2.fail_malformed_htlc(chan=bob_channel, htlc_id=htlc.htlc_id, reason=OnionParsingError(data=bytes(32)))
            await p2.received_commitsig_event.wait()
            self.assertEqual(PR_FAILED, w1.get_invoice_status(pay_req))
            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(pay())

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_payment_race(self):
        """Alice and Bob pay each other simultaneously.
        They both send 'update_add_htlc' and receive each other's update
        before sending 'commitment_signed'. Neither party should fulfill
        the respective HTLCs until those are irrevocably committed to.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        async def pay():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            # prep
            _maybe_send_commitment1 = p1.maybe_send_commitment
            _maybe_send_commitment2 = p2.maybe_send_commitment
            lnaddr2, pay_req2 = self.prepare_invoice(w2)
            lnaddr1, pay_req1 = self.prepare_invoice(w1)
            # alice sends htlc BUT NOT COMMITMENT_SIGNED
            p1.maybe_send_commitment = lambda x: None
            route1 = (await w1.create_routes_from_invoice(lnaddr2.get_amount_msat(), decoded_invoice=lnaddr2))[0][0].route
            paysession1 = w1._paysessions[lnaddr2.paymenthash + lnaddr2.payment_secret]
            shi1 = SentHtlcInfo(
                route=route1,
                payment_secret_orig=lnaddr2.payment_secret,
                payment_secret_bucket=lnaddr2.payment_secret,
                amount_msat=lnaddr2.get_amount_msat(),
                bucket_msat=lnaddr2.get_amount_msat(),
                amount_receiver_msat=lnaddr2.get_amount_msat(),
                trampoline_fee_level=None,
                trampoline_route=None,
            )
            await w1.pay_to_route(
                sent_htlc_info=shi1,
                paysession=paysession1,
                min_final_cltv_delta=lnaddr2.get_min_final_cltv_delta(),
            )
            p1.maybe_send_commitment = _maybe_send_commitment1
            # bob sends htlc BUT NOT COMMITMENT_SIGNED
            p2.maybe_send_commitment = lambda x: None
            route2 = (await w2.create_routes_from_invoice(lnaddr1.get_amount_msat(), decoded_invoice=lnaddr1))[0][0].route
            paysession2 = w2._paysessions[lnaddr1.paymenthash + lnaddr1.payment_secret]
            shi2 = SentHtlcInfo(
                route=route2,
                payment_secret_orig=lnaddr1.payment_secret,
                payment_secret_bucket=lnaddr1.payment_secret,
                amount_msat=lnaddr1.get_amount_msat(),
                bucket_msat=lnaddr1.get_amount_msat(),
                amount_receiver_msat=lnaddr1.get_amount_msat(),
                trampoline_fee_level=None,
                trampoline_route=None,
            )
            await w2.pay_to_route(
                sent_htlc_info=shi2,
                paysession=paysession2,
                min_final_cltv_delta=lnaddr1.get_min_final_cltv_delta(),
            )
            p2.maybe_send_commitment = _maybe_send_commitment2
            # sleep a bit so that they both receive msgs sent so far
            await asyncio.sleep(0.2)
            # now they both send COMMITMENT_SIGNED
            p1.maybe_send_commitment(alice_channel)
            p2.maybe_send_commitment(bob_channel)

            htlc_log1 = await paysession1.sent_htlcs_q.get()
            self.assertTrue(htlc_log1.success)
            htlc_log2 = await paysession2.sent_htlcs_q.get()
            self.assertTrue(htlc_log2.success)
            raise PaymentDone()

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(pay())
        with self.assertRaises(PaymentDone):
            await f()

    #@unittest.skip("too expensive")
    async def test_payments_stresstest(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        alice_init_balance_msat = alice_channel.balance(HTLCOwner.LOCAL)
        bob_init_balance_msat = bob_channel.balance(HTLCOwner.LOCAL)
        num_payments = 50
        payment_value_msat = 10_000_000  # make it large enough so that there are actually HTLCs on the ctx
        max_htlcs_in_flight = asyncio.Semaphore(5)
        async def single_payment(pay_req):
            async with max_htlcs_in_flight:
                await w1.pay_invoice(pay_req)
        async def many_payments():
            async with OldTaskGroup() as group:
                for i in range(num_payments):
                    lnaddr, pay_req = self.prepare_invoice(w2, amount_msat=payment_value_msat)
                    await group.spawn(single_payment(pay_req))
            gath.cancel()
        gath = asyncio.gather(many_payments(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(asyncio.CancelledError):
            await gath
        self.assertEqual(alice_init_balance_msat - num_payments * payment_value_msat, alice_channel.balance(HTLCOwner.LOCAL))
        self.assertEqual(alice_init_balance_msat - num_payments * payment_value_msat, bob_channel.balance(HTLCOwner.REMOTE))
        self.assertEqual(bob_init_balance_msat + num_payments * payment_value_msat, bob_channel.balance(HTLCOwner.LOCAL))
        self.assertEqual(bob_init_balance_msat + num_payments * payment_value_msat, alice_channel.balance(HTLCOwner.REMOTE))

    async def test_payment_recv_mpp_confusion1(self):
        """Regression test for https://github.com/spesmilo/electrum/security/advisories/GHSA-8r85-vp7r-hjxf"""
        # This test checks that the following attack does not work:
        #   - Bob creates invoice1: 1 BTC, H1, S1
        #   - Bob creates invoice2: 1 BTC, H2, S2;  both given to attacker to pay
        #   - Alice sends htlc1: 0.1 BTC, H1, S1  (total_msat=1 BTC)
        #   - Alice sends htlc2: 0.9 BTC, H2, S1  (total_msat=1 BTC)
        #   - Bob(victim) reveals preimage for H1 and fulfills htlc1 (fails other)
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        async def pay():
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr1.paymenthash, direction=RECEIVED))
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr2.paymenthash, direction=RECEIVED))

            route = (await w1.create_routes_from_invoice(amount_msat=1000, decoded_invoice=lnaddr1))[0][0].route
            p1.pay(
                route=route,
                chan=alice_channel,
                amount_msat=1000,
                total_msat=lnaddr1.get_amount_msat(),
                payment_hash=lnaddr1.paymenthash,
                min_final_cltv_delta=lnaddr1.get_min_final_cltv_delta(),
                payment_secret=lnaddr1.payment_secret,
            )
            p1.pay(
                route=route,
                chan=alice_channel,
                amount_msat=lnaddr1.get_amount_msat() - 1000,
                total_msat=lnaddr1.get_amount_msat(),
                payment_hash=lnaddr2.paymenthash,
                min_final_cltv_delta=lnaddr1.get_min_final_cltv_delta(),
                payment_secret=lnaddr1.payment_secret,
            )

            async with util.async_timeout(5):
                while htlc_tracker.num_success + htlc_tracker.num_failed < 2:
                    await htlc_tracker.resolved_event.wait()
            self.assertEqual(0, htlc_tracker.num_success)
            self.assertEqual(2, htlc_tracker.num_failed)
            raise SuccessfulTest()

        w2.features |= LnFeatures.BASIC_MPP_OPT
        lnaddr1, _pay_req = self.prepare_invoice(w2, amount_msat=100_000_000)
        lnaddr2, _pay_req = self.prepare_invoice(w2, amount_msat=100_000_000)
        self.assertTrue(lnaddr1.get_features().supports(LnFeatures.BASIC_MPP_OPT))
        self.assertTrue(lnaddr2.get_features().supports(LnFeatures.BASIC_MPP_OPT))

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(pay())

        htlc_tracker = SenderHtlcResolvedTracker.register()

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_payment_recv_mpp_confusion2(self):
        """Regression test for https://github.com/spesmilo/electrum/security/advisories/GHSA-8r85-vp7r-hjxf"""
        # This test checks that the following attack does not work:
        #   - Bob creates invoice: 1 BTC
        #   - Alice sends htlc1: 0.1 BTC  (total_msat=0.2 BTC)
        #   - Alice sends htlc2: 0.1 BTC  (total_msat=1 BTC)
        #   - Bob(victim) reveals preimage and fulfills htlc2 (fails other)
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        async def pay():
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr1.paymenthash, direction=RECEIVED))

            route = (await w1.create_routes_from_invoice(amount_msat=1000, decoded_invoice=lnaddr1))[0][0].route
            p1.pay(
                route=route,
                chan=alice_channel,
                amount_msat=1000,
                total_msat=2000,
                payment_hash=lnaddr1.paymenthash,
                min_final_cltv_delta=lnaddr1.get_min_final_cltv_delta(),
                payment_secret=lnaddr1.payment_secret,
            )
            p1.pay(
                route=route,
                chan=alice_channel,
                amount_msat=1000,
                total_msat=lnaddr1.get_amount_msat(),
                payment_hash=lnaddr1.paymenthash,
                min_final_cltv_delta=lnaddr1.get_min_final_cltv_delta(),
                payment_secret=lnaddr1.payment_secret,
            )

            async with util.async_timeout(5):
                while htlc_tracker.num_success + htlc_tracker.num_failed < 2:
                    await htlc_tracker.resolved_event.wait()
            self.assertEqual(0, htlc_tracker.num_success)
            self.assertEqual(2, htlc_tracker.num_failed)
            raise SuccessfulTest()

        w2.features |= LnFeatures.BASIC_MPP_OPT
        lnaddr1, _pay_req = self.prepare_invoice(w2, amount_msat=100_000_000)
        self.assertTrue(lnaddr1.get_features().supports(LnFeatures.BASIC_MPP_OPT))

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(pay())

        htlc_tracker = SenderHtlcResolvedTracker.register()

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_dont_settle_partial_mpp_trigger_with_invalid_cltv_htlc(self):
        """Alice gets two htlcs as part of a mpp, one has a cltv too close to expiry and will get failed.
        Test that the other htlc won't get settled if the mpp isn't complete anymore after failing the other htlc.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        async def pay():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            w2.features |= LnFeatures.BASIC_MPP_OPT
            lnaddr1, _pay_req = self.prepare_invoice(w2, amount_msat=10_000, min_final_cltv_delta=144)
            self.assertTrue(lnaddr1.get_features().supports(LnFeatures.BASIC_MPP_OPT))
            route = (await w1.create_routes_from_invoice(amount_msat=10_000, decoded_invoice=lnaddr1))[0][0].route

            # now p1 sends two htlcs, one is valid (1 msat), one is invalid (9_999 msat)
            p1.pay(
                route=route,
                chan=alice_channel,
                amount_msat=1,
                total_msat=lnaddr1.get_amount_msat(),
                payment_hash=lnaddr1.paymenthash,
                # this htlc is valid and will get accepted, but it shouldn't get settled
                min_final_cltv_delta=400,
                payment_secret=lnaddr1.payment_secret,
            )
            await asyncio.sleep(0.1)
            assert w1.get_preimage(lnaddr1.paymenthash) is None
            p1.pay(
                route=route,
                chan=alice_channel,
                amount_msat=9_999,
                total_msat=lnaddr1.get_amount_msat(),
                payment_hash=lnaddr1.paymenthash,
                # this htlc will get failed directly as the cltv is too close to expiry (< 144)
                min_final_cltv_delta=1,
                payment_secret=lnaddr1.payment_secret,
            )

            async with util.async_timeout(5):
                while htlc_tracker.num_success + htlc_tracker.num_failed < 2:
                    await htlc_tracker.resolved_event.wait()
            # both htlcs of the mpp set should get failed and w2 shouldn't release the preimage
            self.assertEqual(0, htlc_tracker.num_success, f"{htlc_tracker.num_success=} | {htlc_tracker.num_failed=}")
            self.assertEqual(2, htlc_tracker.num_failed,  f"{htlc_tracker.num_success=} | {htlc_tracker.num_failed=}")
            assert w1.get_preimage(lnaddr1.paymenthash) is None, "w1 shouldn't get the preimage"
            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(pay())

        htlc_tracker = SenderHtlcResolvedTracker.register()

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_trampoline_forward_request_must_not_exceed_the_budget_it_is_given(self):
        # this test is about forwarding. It is in TestPeerDirect because it only requires 2 peers.
        """An htlc whose inner trampoline onion asks us to relay is not validated against any
        invoice of ours: what we are paid is what the outer onion says, and what we are asked to
        deliver is what the inner onion says. The difference between the two is the fee/cltv budget
        we are given, so the outer onion has to cover the inner one. Otherwise a single dust htlc
        claiming a tiny total_msat completes a relay set, and the negative budget that follows
        reaches the asserts in pay_to_node.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        w2.config.EXPERIMENTAL_LN_FORWARD_PAYMENTS = True
        w2.config.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS = True

        payment_keys_used = []
        orig_update_or_create_mpp = w2.update_or_create_mpp_with_received_htlc
        def update_or_create_mpp(*, payment_key, **kwargs):
            payment_keys_used.append(payment_key)
            return orig_update_or_create_mpp(payment_key=payment_key, **kwargs)
        w2.update_or_create_mpp_with_received_htlc = update_or_create_mpp

        async def attack():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)

            with self.subTest(msg="relay request claiming a total_msat below amt_to_forward"):
                # the htlc claims to forward of 100_000_000 msat while paying 1000 msat
                send_trampoline_htlc_to_forward(
                    p1=p1, w1=w1, w2=w2, chan=alice_channel,
                    payment_hash=os.urandom(32),
                    outer_payment_secret=os.urandom(32),
                    htlc_amount_msat=1000,
                    amt_to_forward=100_000_000,
                )
                await wait_for_htlcs_failed(num_htlcs=1)
                self.assertEqual([], payment_keys_used, "dust htlc entered a relay htlc set")

            with self.subTest(msg="relay request demanding an outgoing cltv beyond the incoming one"):
                # Bob is asked to relay to a node he has a channel with, so that
                # _maybe_forward_trampoline takes its direct-channel path, which skips the budget
                # checks. The resulting negative cltv budget would reach an assert in pay_to_node,
                # i.e. it would get reported as a bug of ours.
                send_trampoline_htlc_to_forward(
                    p1=p1, w1=w1, w2=w2, chan=alice_channel,
                    payment_hash=os.urandom(32),
                    outer_payment_secret=os.urandom(32),
                    htlc_amount_msat=1000,
                    amt_to_forward=1000,
                    inner_cltv_delta=-144,
                    outgoing_node_id=w1.node_keypair.pubkey,
                )
                await wait_for_htlcs_failed(num_htlcs=2)
                self.assertEqual([], payment_keys_used, "htlc entered a relay htlc set")
                self.assertEqual([], crash_reports, "attacker-chosen cltv reached an assert")

            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(attack())

        crash_reports = []
        def send_exception_to_crash_reporter(e):
            crash_reports.append(str(e))

        htlc_tracker = SenderHtlcResolvedTracker.register()

        async def wait_for_htlcs_failed(*, num_htlcs: int):
            async with util.async_timeout(5):
                while htlc_tracker.num_failed < num_htlcs:
                    await htlc_tracker.resolved_event.wait()
            # give Bob some extra time to (wrongly) act on the htlc
            await asyncio.sleep(0.3)

        with mock.patch.object(util, "send_exception_to_crash_reporter",
                               side_effect=send_exception_to_crash_reporter):
            with self.assertRaises(SuccessfulTest):
                await f()


    async def test_trampoline_forward_budget_must_cover_our_cltv_delta(self):
        # this test is about forwarding. It is in TestPeerDirect because it only requires 2 peers.
        """The cltv budget of a trampoline forward must also cover the cltv_delta of our own
        outgoing channel. Otherwise the outgoing htlc may expire together with the incoming one,
        and we would have no time to claim the incoming htlc after learning the preimage.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        w2.config.EXPERIMENTAL_LN_FORWARD_PAYMENTS = True
        w2.config.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS = True

        forwarded_htlcs = []
        orig_pay = p2.pay
        def pay(**kwargs):
            htlc = orig_pay(**kwargs)
            forwarded_htlcs.append(htlc)
            return htlc
        p2.pay = pay

        async def run():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            # Bob is asked to relay to Alice, so that he uses his direct channel with her.
            # The fee budget (1000 msat) covers his fee, so only the cltv budget varies.
            with self.subTest(msg="cltv budget below our cltv_delta"):
                send_trampoline_htlc_to_forward(
                    p1=p1, w1=w1, w2=w2, chan=alice_channel,
                    payment_hash=os.urandom(32),
                    outer_payment_secret=os.urandom(32),
                    htlc_amount_msat=2000,
                    amt_to_forward=1000,
                    inner_cltv_delta=143,
                    outgoing_node_id=w1.node_keypair.pubkey,
                )
                await self.wait_until(lambda: htlc_tracker.num_failed == 1)
                self.assertEqual([], forwarded_htlcs)

            with self.subTest(msg="cltv budget covers our cltv_delta"):
                incoming_htlc = send_trampoline_htlc_to_forward(
                    p1=p1, w1=w1, w2=w2, chan=alice_channel,
                    payment_hash=os.urandom(32),
                    outer_payment_secret=os.urandom(32),
                    htlc_amount_msat=2000,
                    amt_to_forward=1000,
                    inner_cltv_delta=144,
                    outgoing_node_id=w1.node_keypair.pubkey,
                )
                await self.wait_until(lambda: forwarded_htlcs)
                # 144 minus one block, because _maybe_forward_trampoline skews the height towards the past
                self.assertEqual(143, incoming_htlc.cltv_abs - forwarded_htlcs[0].cltv_abs)

            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(run())

        htlc_tracker = SenderHtlcResolvedTracker.register()
        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_refuse_to_forward_htlc_that_corresponds_to_payreq_we_created(self):
        """Alice holds an invoice created by Bob, hence she knows RHASH and Bob's payment_secret.
        She sends Bob a dust htlc whose outer onion is addressed to Bob (using the invoice's
        payment_secret, and claiming a tiny total_msat), but whose inner trampoline onion asks Bob
        to *forward* the payment.
        Bob must fail such htlcs, and he must not release the preimage.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        w2.config.EXPERIMENTAL_LN_FORWARD_PAYMENTS = True
        w2.config.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS = True

        # The forwarding callback is spawned as a task *after* the htlc set has been moved to
        # SETTLING, and a SETTLING set is settled as soon as we have a preimage for its RHASH.
        # Delay the callback, modelling another peer's htlc_switch iteration (the htlc sets are
        # shared between peers) getting to the SETTLING set before the callback records its failure.
        orig_maybe_forward_htlc_set = w2.maybe_forward_htlc_set
        async def maybe_forward_htlc_set(*args, **kwargs):
            await asyncio.sleep(0.15)
            return await orig_maybe_forward_htlc_set(*args, **kwargs)
        w2.maybe_forward_htlc_set = maybe_forward_htlc_set

        payment_keys_used = []
        orig_update_or_create_mpp = w2.update_or_create_mpp_with_received_htlc
        def update_or_create_mpp(*, payment_key, **kwargs):
            payment_keys_used.append(payment_key)
            return orig_update_or_create_mpp(payment_key=payment_key, **kwargs)
        w2.update_or_create_mpp_with_received_htlc = update_or_create_mpp

        htlc_tracker = SenderHtlcResolvedTracker.register()
        async def wait_for_htlc_resolved():
            async with util.async_timeout(5):
                while htlc_tracker.num_success + htlc_tracker.num_failed < 1:
                    await htlc_tracker.resolved_event.wait()

        async def attack():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            lnaddr, _pay_req = self.prepare_invoice(w2, amount_msat=100_000_000)
            payment_hash = lnaddr.paymenthash
            self.assertIsNotNone(w2.get_preimage(payment_hash))
            invoice_payment_key = (payment_hash + lnaddr.payment_secret).hex()
            # note: the amounts of the two onions are consistent with each other, so that the htlc
            #       is only stopped by the checks this test is about.
            send_trampoline_htlc_to_forward(
                p1=p1, w1=w1, w2=w2, chan=alice_channel,
                payment_hash=payment_hash,
                outer_payment_secret=lnaddr.payment_secret,
                htlc_amount_msat=1000,
                amt_to_forward=1000,
            )
            await wait_for_htlc_resolved()
            self.assertEqual(0, htlc_tracker.num_success, "Bob settled a relay request htlc")
            self.assertIsNone(w1.get_preimage(payment_hash), "Bob released the preimage")
            self.assertEqual(PR_UNPAID, w2.get_payment_status(payment_hash, direction=RECEIVED))
            self.assertNotIn(invoice_payment_key, payment_keys_used, "htlc was bucketed together with our invoice")
            self.assertEqual([], payment_keys_used)
            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(attack())

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_mpp_cleanup_after_expiry(self):
        """
        1. Alice sends two HTLCs to Bob, not reaching total_msat, and eventually they MPP_TIMEOUT
        2. Bob fails both HTLCs
        3. Alice then retries and sends HTLCs again to Bob, for the same RHASH,
           this time reaching total_msat, and the payment succeeds

        Test that the sets are properly cleaned up after MPP_TIMEOUT
        and the sender gets a second chance to pay the same invoice.
        """
        async def run_test(test_trampoline: bool):
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
            alice_peer, bob_peer = graph.peers.values()
            alice_wallet, bob_wallet = graph.workers.values()
            alice_channel = graph.channels[('alice', 'bob')][0]
            bob_channel = graph.channels[('bob', 'alice')][0]
            bob_wallet.features |= LnFeatures.BASIC_MPP_OPT
            lnaddr1, pay_req1 = self.prepare_invoice(bob_wallet, amount_msat=10_000)

            if test_trampoline:
                await self._activate_trampoline(alice_wallet)
                # declare bob as trampoline node
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=bob_wallet.node_keypair.pubkey),
                }

            async def _test():
                route = (await alice_wallet.create_routes_from_invoice(amount_msat=10_000, decoded_invoice=lnaddr1))[0][0].route
                assert len(bob_wallet.received_mpp_htlcs) == 0
                # now alice sends two small htlcs, so the set stays incomplete
                alice_peer.pay(  # htlc 1
                    route=route,
                    chan=alice_channel,
                    amount_msat=lnaddr1.get_amount_msat() // 4,
                    total_msat=lnaddr1.get_amount_msat(),
                    payment_hash=lnaddr1.paymenthash,
                    min_final_cltv_delta=400,
                    payment_secret=lnaddr1.payment_secret,
                )
                alice_peer.pay(  # htlc 2
                    route=route,
                    chan=alice_channel,
                    amount_msat=lnaddr1.get_amount_msat() // 4,
                    total_msat=lnaddr1.get_amount_msat(),
                    payment_hash=lnaddr1.paymenthash,
                    min_final_cltv_delta=400,
                    payment_secret=lnaddr1.payment_secret,
                )
                await asyncio.sleep(bob_wallet.MPP_EXPIRY // 2)  # give bob time to receive the htlc
                bob_payment_key = bob_wallet._get_payment_key(lnaddr1.paymenthash).hex()
                assert bob_wallet.received_mpp_htlcs[bob_payment_key].resolution == RecvMPPResolution.WAITING
                assert len(bob_wallet.received_mpp_htlcs[bob_payment_key].htlcs) == 2
                # now wait until bob expires the mpp (set)
                async with util.async_timeout(bob_wallet.MPP_EXPIRY * 3):  # this can take some time, esp. on CI
                    while htlc_tracker.num_success + htlc_tracker.num_failed < 2:
                        await htlc_tracker.resolved_event.wait()
                # check that bob failed the htlc
                assert htlc_tracker.num_success == 0 and htlc_tracker.num_failed == 2
                # check that bob deleted the mpp set as it should be expired and resolved now
                assert bob_payment_key not in bob_wallet.received_mpp_htlcs
                alice_wallet._paysessions.clear()
                assert alice_wallet.get_preimage(lnaddr1.paymenthash) is None  # bob didn't preimage
                # now try to pay again, this time the full amount
                result, log = await alice_wallet.pay_invoice(pay_req1)
                assert result is True
                assert alice_wallet.get_preimage(lnaddr1.paymenthash) is not None  # bob revealed preimage
                assert len(bob_wallet.received_mpp_htlcs) == 0  # bob should also clean up a successful set
                raise SuccessfulTest()

            async def f():
                async with OldTaskGroup() as group:
                    await group.spawn(alice_peer._message_loop())
                    await group.spawn(alice_peer.htlc_switch())
                    await group.spawn(bob_peer._message_loop())
                    await group.spawn(bob_peer.htlc_switch())
                    await asyncio.sleep(0.01)
                    await group.spawn(_test())

            htlc_tracker = SenderHtlcResolvedTracker.register()

            with self.assertRaises(SuccessfulTest):
                await f()

        for use_trampoline in [True, False]:
            self.logger.debug(f"test_mpp_cleanup_after_expiry: {use_trampoline=}")
            await run_test(use_trampoline)

    async def test_modern_shutdown_with_overlap(self):
        for alice_closes in [True, False]:
            with self.subTest(alice_closes=alice_closes):
                chan_ab, chan_ba, coop_fail = await self._test_shutdown(
                    alice_fee=1,
                    bob_fee=200,
                    alice_fee_range={'min_fee_satoshis': 1, 'max_fee_satoshis': 10},
                    bob_fee_range={'min_fee_satoshis': 10, 'max_fee_satoshis': 300},
                    alice_closes=alice_closes,
                )
                await asyncio.sleep(0.1)  # FIXME test is a bit fragile...
                self.assertIsNone(coop_fail)
                self.assertEqual((chan_ab._state, chan_ba._state), (ChannelState.CLOSING, ChannelState.CLOSING))
                # the only fee that is in both ranges
                for chan in (chan_ab, chan_ba):
                    closing_tx = chan.lnworker.network.tx_queue.get_nowait()  # type: Transaction
                    self.assertEqual(10, chan.constraints.capacity - closing_tx.output_value())

    @mock.patch('electrum.lnpeer.LN_P2P_NETWORK_TIMEOUT', 0.05)
    async def test_modern_shutdown_no_overlap(self):
        for alice_closes in [True, False]:
            with self.subTest(alice_closes=alice_closes):
                with self.assertLogs('electrum', level='ERROR') as logs:
                    chan_ab, chan_ba, coop_fail = await self._test_shutdown(
                        alice_fee=1,
                        bob_fee=200,
                        alice_fee_range={'min_fee_satoshis': 1, 'max_fee_satoshis': 10},
                        bob_fee_range={'min_fee_satoshis': 50, 'max_fee_satoshis': 300},
                        alice_closes=alice_closes,
                        wait_until_both_sides_failed=True,
                    )
                self.assertIsInstance(coop_fail, CoopCloseFailure)
                if alice_closes:
                    assert "closing_signed not received" in str(coop_fail)
                else:
                    assert "There is no overlap between their and our fee range" in str(coop_fail)
                # the negotiation failed, but neither side force-closed: that is left to the user
                self.assertEqual((chan_ab._state, chan_ba._state), (ChannelState.SHUTDOWN, ChannelState.SHUTDOWN))
                for chan in (chan_ab, chan_ba):
                    self.assertEqual(0, chan.lnworker.network.tx_queue.qsize())
        self.assertTrue(any(("bob->alice" in msg and "There is no overlap between their and our fee range." in msg) for msg in logs.output))
        self.assertTrue(any(("alice->bob" in msg and "closing_signed not received." in msg) for msg in logs.output))
        # note: "Task exception was never retrieved" for the other CoopCloseFailure
        #       is because we don't start peer.main_loop and hence peer.taskgroup is never joined.

    async def test_failed_closing_negotiation_sends_warning_and_disconnects(self):
        """If the closing negotiation fails, we tell the remote, and close the connection:
        the negotiation restarts on reconnection. We do not force-close.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = 1
        w1.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 1, 'max_fee_satoshis': 10}
        w2.network.config.TEST_SHUTDOWN_FEE = 200
        w2.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 50, 'max_fee_satoshis': 300}
        warnings_received_by_alice = []
        p1.on_warning = lambda payload: warnings_received_by_alice.append(payload['data'])

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            # bob asks for the close. alice is the funder: her fee range does not overlap with his.
            await p2.close_channel(bob_channel.channel_id)
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertLogs('electrum', level='ERROR'):
            with self.assertRaisesRegex(
                    CoopCloseFailure,
                    r"There is no overlap between their and our fee range\. .* We have not closed the channel\. "
                    r"The negotiation will restart when we reconnect to the remote node\."):
                await util.wait_for2(gath, 20)
            async with util.async_timeout(5):
                while not warnings_received_by_alice:
                    await asyncio.sleep(0.01)
        self.assertTrue(p2.got_disconnected.is_set())
        self.assertEqual(PeerState.DISCONNECTED, bob_channel.peer_state)
        self.assertEqual(1, len(warnings_received_by_alice))
        self.assertIn(b"closing negotiation failed: There is no overlap", warnings_received_by_alice[0])
        self.assertEqual(ChannelState.SHUTDOWN, bob_channel._state)
        self.assertEqual(0, w2.network.tx_queue.qsize())
        # both sides count this attempt as failed: each of them has sent or received a closing_signed
        self.assertEqual(1, bob_channel.closing_negotiation_attempts[0])
        self.assertEqual(1, alice_channel.closing_negotiation_attempts[0])

    async def test_closing_tx_that_would_not_relay_fails_the_negotiation(self):
        # e.g. the output of the remote is below the dust limit of its scriptpubkey type
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        bob_channel = graph.channels[('bob', 'alice')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000
        p2.close_and_cleanup = mock.Mock()

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            await p2.close_channel(bob_channel.channel_id)
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with mock.patch('electrum.lnpeer.transaction.check_scriptpubkey_template_and_dust',
                        side_effect=Exception("amount (300) is below dust limit for scriptpubkey type (330)")):
            with self.assertLogs('electrum', level='ERROR'):
                with self.assertRaisesRegex(CoopCloseFailure, r"The closing tx would not relay: amount \(300\) is below"):
                    await util.wait_for2(gath, 20)
        p2.close_and_cleanup.assert_called_once()
        self.assertEqual(ChannelState.SHUTDOWN, bob_channel._state)
        self.assertEqual(0, w2.network.tx_queue.qsize())

    async def test_closing_negotiation_fails_when_connection_is_lost(self):
        """close_channel() does not run in the taskgroup of the peer, so nothing cancels it when the
        connection is lost. It must notice by itself, and not touch a connection that might have replaced the old one.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000

        async def bob_never_sends_closing_signed(chan, payload, *, is_local):
            await p2.wait_for_message('closing_signed', chan.channel_id)
            p1.got_disconnected.set()  # the connection is lost now
            await asyncio.Event().wait()
        p2._shutdown = bob_never_sends_closing_signed
        messages_sent_by_alice = []
        orig_send_message = p1.send_message
        def send_message(message_name, **kwargs):
            messages_sent_by_alice.append(message_name)
            return orig_send_message(message_name, **kwargs)
        p1.send_message = send_message
        p1.close_and_cleanup = mock.Mock()

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            # (if alice did not notice, she would wait 20 seconds for closing_signed)
            await util.wait_for2(p1.close_channel(alice_channel.channel_id), 5)
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertLogs('electrum', level='ERROR'):
            with self.assertRaisesRegex(
                    CoopCloseFailure, r"Lost connection to the remote node during the closing negotiation\. "
                                      r"We have not closed the channel\."):
                await util.wait_for2(gath, 20)
        p1.close_and_cleanup.assert_not_called()
        self.assertNotIn('warning', messages_sent_by_alice)
        self.assertEqual(ChannelState.SHUTDOWN, alice_channel._state)
        self.assertEqual(0, w1.network.tx_queue.qsize())
        # alice had sent her closing_signed: this attempt counts as failed
        self.assertEqual(1, alice_channel.closing_negotiation_attempts[0])

    async def test_close_channel_fails_when_connection_is_lost_before_remote_sends_shutdown(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        p2.on_shutdown = lambda chan, payload: None  # bob does not answer

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            close_task = asyncio.ensure_future(p1.close_channel(alice_channel.channel_id))
            async with util.async_timeout(5):
                while alice_channel.get_state() != ChannelState.SHUTDOWN:
                    await asyncio.sleep(0.01)
            # a second call, while the first one is waiting for the shutdown of bob
            with self.assertRaisesRegex(Exception, "already in progress"):
                await util.wait_for2(p1.close_channel(alice_channel.channel_id), 1)
            self.assertFalse(close_task.done())
            p1.got_disconnected.set()  # the connection is lost
            with self.assertRaises(CoopCloseFailure) as ctx:
                await util.wait_for2(close_task, 5)
            self.assertEqual(
                "Lost connection to the remote node during the closing negotiation. We have not closed the channel. "
                "The negotiation will restart when we reconnect to the remote node.", str(ctx.exception))
            self.assertEqual({}, p1.shutdown_received)
            # no closing_signed was sent or received: nothing has failed, there is no delay before the next attempt
            self.assertEqual((0, 0.), alice_channel.closing_negotiation_attempts)
            self.assertEqual(0, p1._closing_negotiation_backoff(alice_channel))
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertLogs('electrum', level='ERROR'):
            with self.assertRaises(SuccessfulTest):
                await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.SHUTDOWN, alice_channel._state)

    @mock.patch('electrum.lnpeer.LN_P2P_NETWORK_TIMEOUT', 0.3)
    async def test_closing_negotiation_fails_if_remote_does_not_send_closing_signed(self):
        # the connection is fine, but the remote stays silent: that attempt does count as failed
        async def silent_remote(peer, chan, payload):
            await asyncio.Event().wait()
        for remote_is_funder in [False, True]:
            with self.subTest(remote_is_funder=remote_is_funder):
                t0 = time.time()
                with self.assertLogs('electrum', level='ERROR'):
                    res = await self._test_shutdown_with_remote(
                        remote_negotiation=silent_remote, remote_is_funder=remote_is_funder, remote_closes=False)
                self._assert_negotiation_failed_with_remote(res, "closing_signed not received.")
                # (as funder, we send the first closing_signed)
                self.assertEqual([] if remote_is_funder else [1000], res.our_fees)
                # the delay before the next attempt starts when this one ends (we waited 0.3 sec for closing_signed)
                self.assertGreaterEqual(res.chan_our.closing_negotiation_attempts[1] - t0, 0.3)

    async def test_interrupted_closing_negotiation(self):
        """The caller of close_channel gives up (cancels the call) in the middle of the negotiation."""
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = 1000
        w1.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 500, 'max_fee_satoshis': 2000}

        async def bob_stops_after_one_closing_signed(chan, payload, *, is_local):
            await self._scripted_shutdown(p2, chan, payload, offers=[5000])  # (raises StopIteration at the 2nd offer)
        p2._shutdown = bob_stops_after_one_closing_signed

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            close_task = asyncio.ensure_future(p1.close_channel(alice_channel.channel_id))
            async with util.async_timeout(5):
                while alice_channel.closing_negotiation_attempts[0] == 0:
                    await asyncio.sleep(0.01)
            # bob has taken part in the negotiation, so this attempt counts
            time_counted = alice_channel.closing_negotiation_attempts[1]
            await asyncio.sleep(0.3)
            close_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await close_task
            # the delay before the next attempt starts when the attempt ends
            self.assertEqual(1, alice_channel.closing_negotiation_attempts[0])
            self.assertGreaterEqual(alice_channel.closing_negotiation_attempts[1] - time_counted, 0.25)
            # bob is in the middle of the negotiation: we disconnect, to start over on the next connection
            self.assertTrue(p1.got_disconnected.is_set())
            self.assertEqual(PeerState.DISCONNECTED, alice_channel.peer_state)
            # on this connection, close_channel has nothing left to do: it reports what happened
            with self.assertRaises(CoopCloseFailure) as ctx:
                await util.wait_for2(p1.close_channel(alice_channel.channel_id), 1)
            self.assertEqual(
                "The closing negotiation was interrupted. We have not closed the channel. "
                "The negotiation will restart when we reconnect to the remote node.", str(ctx.exception))
            self.assertEqual({}, p1.shutdown_received)
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.SHUTDOWN, alice_channel._state)

    async def test_close_channel_fails_when_connection_is_lost_while_htlcs_are_pending(self):
        # in the second case, the htlcs get settled (e.g. over a new connection) right when we lose the connection
        for htlcs_get_settled in [False, True]:
            with self.subTest(htlcs_get_settled=htlcs_get_settled):
                graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
                p1, p2 = graph.peers.values()
                alice_channel = graph.channels[('alice', 'bob')][0]
                chan_id = alice_channel.channel_id
                alice_channel.has_unsettled_htlcs = lambda: True
                sent_by_alice = []

                def send_message(message_name, *, _orig=p1.send_message, _sent=sent_by_alice, **kwargs):
                    _sent.append(message_name)
                    return _orig(message_name, **kwargs)
                p1.send_message = send_message

                async def bob_waits(chan, payload, *, is_local):
                    await asyncio.Event().wait()
                p2._shutdown = bob_waits

                async def close(p1=p1, p2=p2, alice_channel=alice_channel, chan_id=chan_id, sent_by_alice=sent_by_alice,
                                htlcs_get_settled=htlcs_get_settled):
                    await util.wait_for2(p1.initialized, 1)
                    await util.wait_for2(p2.initialized, 1)
                    close_task = asyncio.ensure_future(p1.close_channel(chan_id))
                    async with util.async_timeout(5):
                        while chan_id not in p1._closing_negotiations:  # i.e. both have sent shutdown
                            await asyncio.sleep(0.01)
                    await asyncio.sleep(0.05)
                    self.assertFalse(close_task.done())  # waiting for the htlcs
                    p1.got_disconnected.set()  # the connection is lost
                    if htlcs_get_settled:
                        alice_channel.has_unsettled_htlcs = lambda: False
                    with self.assertRaises(CoopCloseFailure) as ctx:
                        await util.wait_for2(close_task, 3)
                    self.assertEqual(
                        "Lost connection to the remote node during the closing negotiation. "
                        "We have not closed the channel. "
                        "The negotiation will restart when we reconnect to the remote node.", str(ctx.exception))
                    # the task of the old connection did not go on with the negotiation
                    self.assertNotIn('closing_signed', sent_by_alice)
                    self.assertTrue(alice_channel._can_send_ctx_updates)
                    # nothing was negotiated: there is no delay before the next attempt
                    self.assertEqual((0, 0.), alice_channel.closing_negotiation_attempts)
                    raise SuccessfulTest()
                gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
                with self.assertRaises(SuccessfulTest):
                    await util.wait_for2(gath, 20)
                self.assertEqual(ChannelState.SHUTDOWN, alice_channel._state)

    async def test_close_channel_cancelled_while_htlcs_are_pending_keeps_the_connection(self):
        """lnworker._cleanup_failed_jit_channel does this: its close_channel call usually times out while
        the htlcs are pending. No closing_signed was exchanged, so there is no reason to disconnect."""
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        chan_id = alice_channel.channel_id
        alice_channel.has_unsettled_htlcs = lambda: True

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            with self.assertRaises(asyncio.TimeoutError):
                await util.wait_for2(p1.close_channel(chan_id), 0.5)
            await asyncio.sleep(0.05)
            self.assertFalse(p1.got_disconnected.is_set())
            self.assertEqual(PeerState.GOOD, alice_channel.peer_state)
            self.assertEqual((0, 0.), alice_channel.closing_negotiation_attempts)
            with self.assertRaises(CoopCloseFailure) as ctx:
                await util.wait_for2(p1.close_channel(chan_id), 1)
            self.assertEqual(
                "The closing negotiation was interrupted. We have not closed the channel. "
                "The negotiation will restart when we reconnect to the remote node.", str(ctx.exception))
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.SHUTDOWN, alice_channel._state)

    async def test_close_channel_when_remote_sends_error_while_htlcs_are_pending(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        chan_id = alice_channel.channel_id
        alice_channel.has_unsettled_htlcs = lambda: True
        bob_should_send_error = asyncio.Event()

        async def bob_sends_error(chan, payload, *, is_local):
            await bob_should_send_error.wait()
            p2.send_message('error', channel_id=chan.channel_id, data=b'boom', len=4)
            await asyncio.Event().wait()
        p2._shutdown = bob_sends_error

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            close_task = asyncio.ensure_future(p1.close_channel(chan_id))
            async with util.async_timeout(5):
                while chan_id not in p1._closing_negotiations:
                    await asyncio.sleep(0.01)
            await asyncio.sleep(0.05)
            self.assertFalse(close_task.done())
            bob_should_send_error.set()
            with self.assertRaises(CoopCloseFailure) as ctx:
                await util.wait_for2(close_task, 5)
            self.assertEqual(
                "Lost connection to the remote node during the closing negotiation. "
                "The channel is in state FORCE_CLOSING now.", str(ctx.exception))
            raise SuccessfulTest()
        # note: the real main_loop of alice, which ends the connection when the remote sends an error
        gath = asyncio.gather(close(), p1.main_loop(), p2._message_loop(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.FORCE_CLOSING, alice_channel._state)

    async def test_close_channel_when_remote_answers_shutdown_with_error(self):
        """lnd answers our shutdown with an error e.g. if it cannot estimate the fee. We force-close then,
        as before (see on_error), so close_channel must not tell the user that the negotiation will restart."""
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]

        def bob_on_shutdown(chan, payload):
            p2.send_message('error', channel_id=chan.channel_id, data=b'unable to estimate fee', len=22)
        p2.on_shutdown = bob_on_shutdown

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            with self.assertRaises(CoopCloseFailure) as ctx:
                await util.wait_for2(p1.close_channel(alice_channel.channel_id), 5)
            self.assertEqual(
                "Lost connection to the remote node during the closing negotiation. "
                "The channel is in state FORCE_CLOSING now.", str(ctx.exception))
            raise SuccessfulTest()
        # note: alice runs the real main_loop here, which ends the connection when the remote sends an error
        gath = asyncio.gather(close(), p1.main_loop(), p2._message_loop(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.FORCE_CLOSING, alice_channel._state)

    async def test_joined_close_channel_when_remote_sends_error(self):
        """The remote has started the close, the user asks for it as well, and then the remote sends an error."""
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        chan_id = alice_channel.channel_id
        alice_channel.has_unsettled_htlcs = lambda: True  # the negotiation of alice has to wait
        bob_should_send_error = asyncio.Event()

        async def bob_sends_error(chan, payload, *, is_local):
            await bob_should_send_error.wait()
            p2.send_message('error', channel_id=chan.channel_id, data=b'boom', len=4)
            await asyncio.Event().wait()
        p2._shutdown = bob_sends_error

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            bob_task = asyncio.ensure_future(p2.close_channel(chan_id))
            async with util.async_timeout(5):
                while chan_id not in p1._closing_negotiations:
                    await asyncio.sleep(0.01)
            joined = asyncio.ensure_future(p1.close_channel(chan_id))
            await asyncio.sleep(0.05)
            self.assertFalse(joined.done())
            bob_should_send_error.set()
            with self.assertRaises(CoopCloseFailure) as ctx:
                await util.wait_for2(joined, 5)
            self.assertEqual(
                "The closing negotiation was interrupted. The channel is in state FORCE_CLOSING now.",
                str(ctx.exception))
            bob_task.cancel()
            raise SuccessfulTest()
        # note: the real main_loop of alice: its taskgroup cancels her negotiation when the error arrives
        gath = asyncio.gather(close(), p1.main_loop(), p2._message_loop(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.FORCE_CLOSING, alice_channel._state)

    async def test_joined_close_channel_reports_why_the_negotiation_failed(self):
        graph, num_sent = self._prepare_reconnect_in_shutdown_state()
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        chan_id = alice_channel.channel_id
        w1.network.config.TEST_SHUTDOWN_FEE = 1
        w1.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 1, 'max_fee_satoshis': 10}
        w2.network.config.TEST_SHUTDOWN_FEE = 200
        w2.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 50, 'max_fee_satoshis': 300}
        bob_channel.closing_negotiation_attempts = (1, time.time())  # bob holds back his shutdown

        async def reconnect():
            await asyncio.gather(p1.reestablish_channel(alice_channel), p2.reestablish_channel(bob_channel))
            async with util.async_timeout(5):
                while chan_id not in p2._closing_negotiations:  # started by the shutdown of alice
                    await asyncio.sleep(0.01)
            with self.assertRaises(CoopCloseFailure) as ctx:
                await util.wait_for2(p2.close_channel(chan_id), 5)
            self.assertEqual(
                "There is no overlap between their and our fee range. "
                "ours={'min_fee_satoshis': 50, 'max_fee_satoshis': 300}, "
                "theirs={'min_fee_satoshis': 1, 'max_fee_satoshis': 10}. We have not closed the channel. "
                "The negotiation will restart when we reconnect to the remote node.", str(ctx.exception))
            raise SuccessfulTest()
        gath = asyncio.gather(reconnect(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertLogs('electrum', level='ERROR'):
            with self.assertRaises(SuccessfulTest):
                await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.SHUTDOWN, bob_channel._state)

    async def test_joined_close_channel_can_be_cancelled_and_called_again(self):
        graph, num_sent = self._prepare_reconnect_in_shutdown_state()
        p1, p2 = graph.peers.values()
        w1 = graph.workers['alice']
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        chan_id = alice_channel.channel_id
        bob_may_negotiate = asyncio.Event()
        num_negotiations_of_alice = 0
        orig_shutdown_of_alice = p1._shutdown
        orig_shutdown_of_bob = p2._shutdown

        async def alice_shutdown(chan, payload, *, is_local):
            nonlocal num_negotiations_of_alice
            num_negotiations_of_alice += 1
            return await orig_shutdown_of_alice(chan, payload, is_local=is_local)
        p1._shutdown = alice_shutdown

        async def bob_shutdown(chan, payload, *, is_local):
            await bob_may_negotiate.wait()
            return await orig_shutdown_of_bob(chan, payload, is_local=is_local)
        p2._shutdown = bob_shutdown

        async def reconnect():
            await asyncio.gather(p1.reestablish_channel(alice_channel), p2.reestablish_channel(bob_channel))
            async with util.async_timeout(5):
                while chan_id not in p1._closing_negotiations:  # started by the shutdown of bob
                    await asyncio.sleep(0.01)
            joined = asyncio.ensure_future(p1.close_channel(chan_id))
            await asyncio.sleep(0.05)
            self.assertFalse(joined.done())
            joined.cancel()  # that caller gives up
            with self.assertRaises(asyncio.CancelledError):
                await joined
            # the negotiation goes on. two more callers join it, and both get its outcome
            calls = asyncio.gather(p1.close_channel(chan_id), p1.close_channel(chan_id))
            await asyncio.sleep(0.05)
            bob_may_negotiate.set()
            txid1, txid2 = await util.wait_for2(calls, 5)
            txid = w1.network.tx_queue.get_nowait().txid()
            self.assertEqual((txid, txid), (txid1, txid2))
            self.assertFalse(p1.got_disconnected.is_set())
            raise SuccessfulTest()
        gath = asyncio.gather(reconnect(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(1, num_negotiations_of_alice)
        self.assertEqual(ChannelState.CLOSING, alice_channel._state)

    async def test_close_channel_does_not_end_the_wait_of_another_channel(self):
        graph_def = copy.deepcopy(self.GRAPH_DEFINITIONS['single_chan'])
        graph_def['alice']['channels']['bob'].append(copy.deepcopy(graph_def['alice']['channels']['bob'][0]))
        graph = self.prepare_chans_and_peers_in_graph(graph_def)
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000
        alice_chan1, alice_chan2 = graph.channels[('alice', 'bob')]
        bob_chan1, bob_chan2 = graph.channels[('bob', 'alice')]
        for chan in (alice_chan1, alice_chan2, bob_chan1, bob_chan2):
            chan.set_state(ChannelState.SHUTDOWN)
            chan.peer_state = PeerState.DISCONNECTED
        for chan in (alice_chan1, alice_chan2):
            chan.closing_negotiation_attempts = (1, time.time())  # alice holds back her shutdown, for both channels

        async def reconnect():
            await asyncio.gather(
                p1.reestablish_channel(alice_chan1), p2.reestablish_channel(bob_chan1),
                p1.reestablish_channel(alice_chan2), p2.reestablish_channel(bob_chan2))
            async with util.async_timeout(5):
                while not {alice_chan1.channel_id, alice_chan2.channel_id} <= p1._shutdown_seen:
                    await asyncio.sleep(0.01)
            self.assertEqual(set(), p1._shutdown_sent)
            await util.wait_for2(p1.close_channel(alice_chan1.channel_id), 5)
            await asyncio.sleep(0.3)
            self.assertEqual(ChannelState.CLOSING, alice_chan1._state)
            # the other channel is still held back
            self.assertEqual({alice_chan1.channel_id}, p1._shutdown_sent)
            self.assertEqual(ChannelState.SHUTDOWN, alice_chan2._state)
            raise SuccessfulTest()
        gath = asyncio.gather(reconnect(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)

    async def test_wait_unless_disconnected(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1 = graph.peers[('alice', 'bob')]
        loop = asyncio.get_running_loop()
        # what we wait for happens
        fut = loop.create_future()
        loop.call_later(0.05, fut.set_result, 'payload')
        self.assertEqual('payload', await util.wait_for2(p1._wait_unless_disconnected(fut), 1))

        # ... or fails
        async def fails():
            raise ValueError("boom")
        with self.assertRaisesRegex(ValueError, "boom"):
            await util.wait_for2(p1._wait_unless_disconnected(fails()), 1)
        # the connection is lost first: we stop waiting
        task = asyncio.ensure_future(asyncio.Event().wait())
        loop.call_later(0.05, p1.got_disconnected.set)
        with self.assertRaises(CoopCloseFailure) as ctx:
            await util.wait_for2(p1._wait_unless_disconnected(task), 1)
        self.assertEqual("Lost connection to the remote node during the closing negotiation.", str(ctx.exception))
        with self.assertRaises(asyncio.CancelledError):
            await util.wait_for2(task, 1)
        # a message that arrived before the connection was lost is still processed
        fut = loop.create_future()
        fut.set_result('payload')
        self.assertEqual('payload', await util.wait_for2(p1._wait_unless_disconnected(fut), 1))

    async def test_remote_initiated_closing_negotiation_is_cancelled_with_the_connection(self):
        # the remote has started the close: our side of the negotiation runs in a task of the peer's taskgroup,
        # which is cancelled when the connection is lost (unlike a call of close_channel)
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = 1000
        w1.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 500, 'max_fee_satoshis': 2000}

        async def bob_stops_after_one_closing_signed(chan, payload, *, is_local):
            await self._scripted_shutdown(p2, chan, payload, offers=[5000])
        p2._shutdown = bob_stops_after_one_closing_signed
        on_shutdown_tasks = []
        orig_on_shutdown = p1.on_shutdown

        async def on_shutdown(chan, payload):
            on_shutdown_tasks.append(await orig_on_shutdown(chan, payload))
        p1.on_shutdown = on_shutdown

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            asyncio.ensure_future(p2.close_channel(alice_channel.channel_id))  # bob starts the close
            async with util.async_timeout(5):
                while alice_channel.closing_negotiation_attempts[0] == 0:
                    await asyncio.sleep(0.01)
            await asyncio.sleep(0.05)
            self.assertEqual(1, len(on_shutdown_tasks))
            self.assertFalse(on_shutdown_tasks[0].done())
            on_shutdown_tasks[0].cancel()  # as the taskgroup does, when the connection is lost
            with self.assertRaises(asyncio.CancelledError):
                await on_shutdown_tasks[0]
            self.assertEqual(1, alice_channel.closing_negotiation_attempts[0])
            with self.assertRaises(CoopCloseFailure) as ctx:
                await util.wait_for2(p1.close_channel(alice_channel.channel_id), 1)
            self.assertEqual(
                "The closing negotiation was interrupted. We have not closed the channel. "
                "The negotiation will restart when we reconnect to the remote node.", str(ctx.exception))
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.SHUTDOWN, alice_channel._state)

    async def test_closing_negotiation_does_not_count_as_failed_before_any_closing_signed(self):
        # we are not the funder: we wait for the first closing_signed of the remote. the connection is lost
        # before it arrives: no closing_signed was sent or received, so there is no delay before the next attempt
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        bob_channel = graph.channels[('bob', 'alice')][0]
        self.assertFalse(bob_channel.constraints.is_initiator)
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000

        async def alice_stays_silent(chan, payload, *, is_local):
            await asyncio.Event().wait()
        p1._shutdown = alice_stays_silent
        p2.close_and_cleanup = mock.Mock()

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            close_task = asyncio.ensure_future(p2.close_channel(bob_channel.channel_id))
            async with util.async_timeout(5):  # bob has received the shutdown of alice: he negotiates
                while bob_channel.channel_id not in p2._closing_negotiations:
                    await asyncio.sleep(0.01)
            await asyncio.sleep(0.05)
            self.assertFalse(close_task.done())
            p2.got_disconnected.set()  # the connection is lost
            with self.assertRaisesRegex(CoopCloseFailure, "Lost connection to the remote node"):
                await util.wait_for2(close_task, 5)
            self.assertEqual((0, 0.), bob_channel.closing_negotiation_attempts)
            self.assertEqual(0, p2._closing_negotiation_backoff(bob_channel))
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertLogs('electrum', level='ERROR'):
            with self.assertRaises(SuccessfulTest):
                await util.wait_for2(gath, 20)
        p2.close_and_cleanup.assert_not_called()
        self.assertEqual(ChannelState.SHUTDOWN, bob_channel._state)

    @mock.patch('electrum.lnpeer.LN_P2P_NETWORK_TIMEOUT', 0.05)
    async def test_second_failed_closing_negotiation_doubles_the_delay(self):
        # the negotiation fails on two connections in a row: the second failure counts on top of the first one
        alice_lnwallet, bob_lnwallet = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan']).values()
        alice_channel, bob_channel = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)
        for num_attempt, delay in [(1, 15), (2, 30)]:
            p1, p2, w1, w2 = self.prepare_peers(alice_channel, bob_channel)
            w1.network.config.TEST_SHUTDOWN_FEE = 1
            w1.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 1, 'max_fee_satoshis': 10}
            w2.network.config.TEST_SHUTDOWN_FEE = 200
            w2.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 50, 'max_fee_satoshis': 300}
            for chan in (alice_channel, bob_channel):  # (the first connection has left them DISCONNECTED)
                chan.peer_state = PeerState.GOOD
            p1._closing_negotiation_wakeup[alice_channel.channel_id].set()  # (alice does not hold back her shutdown)

            async def close(p1=p1, p2=p2):
                await util.wait_for2(p1.initialized, 1)
                await util.wait_for2(p2.initialized, 1)
                await p2.close_channel(bob_channel.channel_id)
            gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
            with self.assertLogs('electrum', level='ERROR'):
                with self.assertRaisesRegex(CoopCloseFailure, "There is no overlap"):
                    await util.wait_for2(gath, 20)
                async with util.async_timeout(5):
                    while not (p1.got_disconnected.is_set() and p2.got_disconnected.is_set()):
                        await asyncio.sleep(0.01)
            self.assertEqual((num_attempt, num_attempt),
                             (alice_channel.closing_negotiation_attempts[0], bob_channel.closing_negotiation_attempts[0]))
            for peer, chan in ((p1, alice_channel), (p2, bob_channel)):
                self.assertTrue(delay - 5 < peer._closing_negotiation_backoff(chan) <= delay,
                                peer._closing_negotiation_backoff(chan))

    async def test_wait_before_restarting_closing_negotiation_waits_for_what_is_left(self):
        # the second attempt has failed 20 seconds ago: 10 of the 30 seconds are left
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1 = graph.peers[('alice', 'bob')]
        chan = graph.channels[('alice', 'bob')][0]
        chan.closing_negotiation_attempts = (2, time.time() - 20)
        p1.asyncio_loop.call_later(0.05, p1._closing_negotiation_wakeup[chan.channel_id].set)
        with mock.patch('electrum.lnpeer.ignore_after', wraps=electrum.lnpeer.ignore_after) as ignore_after_:
            await util.wait_for2(p1._wait_before_restarting_closing_negotiation(chan), 5)
        ignore_after_.assert_called_once()
        self.assertTrue(9 < ignore_after_.call_args.args[0] <= 10, ignore_after_.call_args)

    @mock.patch('electrum.lnpeer.COOP_CLOSE_RETRY_DELAY_INIT', 0.3)
    async def test_remote_sends_closing_signed_before_our_shutdown_after_reconnection(self):
        # Not every implementation waits for our shutdown after a reconnection: as funder, such a remote sends
        # its closing_signed right after its shutdown. Our last attempt has failed, so we hold back our shutdown,
        # and answer that closing_signed after the wait.
        graph, num_sent = self._prepare_reconnect_in_shutdown_state()
        p1, p2 = graph.peers.values()
        w2 = graph.workers['bob']
        alice_channel = graph.channels[('alice', 'bob')][0]  # the remote. it is the funder
        bob_channel = graph.channels[('bob', 'alice')][0]  # we
        bob_channel.closing_negotiation_attempts = (1, time.time())
        p1.on_shutdown = lambda chan, payload: None  # the remote remembers our shutdown from the last connection
        order = []
        for name, peer in (('remote', p1), ('we', p2)):
            def send_message(message_name, *, _name=name, _orig=peer.send_message, **kwargs):
                if message_name in ('shutdown', 'closing_signed'):
                    order.append((_name, message_name))
                return _orig(message_name, **kwargs)
            peer.send_message = send_message

        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            payload = {'scriptpubkey': bitcoin.address_to_script(bob_channel.get_sweep_address())}
            agreed_fee = await util.wait_for2(self._scripted_shutdown(p1, alice_channel, payload, offers=[1000]), 5)
            self.assertEqual(1000, agreed_fee)
            async with util.async_timeout(5):
                while bob_channel.get_state() != ChannelState.CLOSING:
                    await asyncio.sleep(0.01)
            raise SuccessfulTest()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(
            [('remote', 'shutdown'), ('remote', 'closing_signed'), ('we', 'shutdown'), ('we', 'closing_signed')], order)
        closing_tx = w2.network.tx_queue.get_nowait()
        self.assertEqual(1000, bob_channel.constraints.capacity - closing_tx.output_value())

    async def test_cancelled_closing_negotiation(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1 = graph.peers[('alice', 'bob')]
        alice_channel = graph.channels[('alice', 'bob')][0]
        alice_channel.set_state(ChannelState.SHUTDOWN)
        p1.close_and_cleanup = mock.Mock()
        for closing_signed_was_exchanged, connection_is_gone, should_disconnect in [
                (True, False, True),  # the remote is in the middle of the negotiation: start over on a new connection
                (True, True, False),  # as for the failures below: a stale task must not touch a newer connection
                (False, False, False),  # e.g. still waiting for htlcs to settle: nothing to start over
        ]:
            with self.subTest(closing_signed_was_exchanged=closing_signed_was_exchanged, connection_is_gone=connection_is_gone):
                async def negotiate(chan, payload, *, is_local, _counts=closing_signed_was_exchanged):
                    if _counts:
                        chan.closing_negotiation_attempts = (chan.closing_negotiation_attempts[0] + 1, time.time())
                    await asyncio.Event().wait()
                p1._negotiate_closing_tx = negotiate
                p1.got_disconnected.clear()
                p1.close_and_cleanup.reset_mock()
                task = asyncio.ensure_future(p1._closing_negotiation(alice_channel, {}, is_local=True))
                await asyncio.sleep(0.05)
                if connection_is_gone:
                    p1.got_disconnected.set()
                task.cancel()
                await asyncio.wait([task], timeout=1)
                self.assertTrue(task.cancelled())
                self.assertEqual(1 if should_disconnect else 0, p1.close_and_cleanup.call_count)
                # on this connection, later calls of close_channel report what happened
                with self.assertRaisesRegex(CoopCloseFailure, "The closing negotiation was interrupted"):
                    await util.wait_for2(p1.close_channel(alice_channel.channel_id), 1)

    async def test_unexpected_error_on_a_connection_that_is_gone(self):
        # as in _shutdown's handling of CoopCloseFailure: a stale task must not touch a newer connection
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1 = graph.peers[('alice', 'bob')]
        alice_channel = graph.channels[('alice', 'bob')][0]
        p1._negotiate_closing_tx = mock.AsyncMock(side_effect=ValueError("boom"))
        p1.close_and_cleanup = mock.Mock()
        # an earlier attempt has failed. this one ends before any closing_signed: the delay is not extended
        alice_channel.closing_negotiation_attempts = (1, 1000.)
        with self.assertLogs('electrum', level='ERROR'):
            with self.assertRaisesRegex(ValueError, "boom"):
                await p1._shutdown(alice_channel, {}, is_local=True)
            p1.close_and_cleanup.assert_called_once()
            p1.close_and_cleanup.reset_mock()
            p1.got_disconnected.set()
            with self.assertRaisesRegex(ValueError, "boom"):
                await p1._shutdown(alice_channel, {}, is_local=True)
        p1.close_and_cleanup.assert_not_called()
        self.assertEqual((1, 1000.), alice_channel.closing_negotiation_attempts)

    async def test_closing_negotiation_backoff(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1 = graph.peers[('alice', 'bob')]
        chan = graph.channels[('alice', 'bob')][0]
        self.assertEqual((0, 0.), chan.closing_negotiation_attempts)
        self.assertEqual(0, p1._closing_negotiation_backoff(chan))
        # (number of failed attempts so far, seconds since the last one ended) -> seconds left to wait
        for num_attempts, age, expected_backoff in [
                (1, 0, 15), (1, 10, 5), (1, 15, 0), (1, 1000, 0),
                (2, 0, 30), (2, 20, 10),
                (3, 0, 60), (4, 0, 120), (5, 0, 240),
                (6, 0, 300), (6, 290, 10), (6, 310, 0),
                (99, 0, 300), (10 ** 6, 0, 300),
                # the clock was set back by an hour in the meantime: we wait for the delay, not for an hour
                (1, -3600, 15), (6, -3600, 300),
        ]:
            with self.subTest(num_attempts=num_attempts, age=age):
                chan.closing_negotiation_attempts = (num_attempts, time.time() - age)
                self.assertAlmostEqual(expected_backoff, p1._closing_negotiation_backoff(chan), delta=1)

    @mock.patch('electrum.lnpeer.COOP_CLOSE_RETRY_DELAY_INIT', 0.4)
    async def test_wait_before_restarting_closing_negotiation(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1 = graph.peers[('alice', 'bob')]
        chan = graph.channels[('alice', 'bob')][0]
        t0 = time.monotonic()
        chan.closing_negotiation_attempts = (1, time.time())
        await util.wait_for2(p1._wait_before_restarting_closing_negotiation(chan), 5)
        self.assertTrue(0.35 <= time.monotonic() - t0 < 1.0)
        # the wait ends early if the user asks for the close (see close_channel)
        chan.closing_negotiation_attempts = (6, time.time())  # 12.8 sec
        p1.asyncio_loop.call_later(0.1, p1._closing_negotiation_wakeup[chan.channel_id].set)
        await util.wait_for2(p1._wait_before_restarting_closing_negotiation(chan), 5)

    def _prepare_reconnect_in_shutdown_state(self):
        """Both sides have sent shutdown, and then the connection was lost.
        Returns the graph, and a dict that counts the 'shutdown' and 'closing_signed' messages each peer sends.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        num_sent = defaultdict(int)  # (peer, message_name) -> count
        for peer in graph.peers.values():
            def send_message(message_name, *, _peer=peer, _orig=peer.send_message, **kwargs):
                num_sent[(_peer, message_name)] += 1
                return _orig(message_name, **kwargs)
            peer.send_message = send_message
        for w in graph.workers.values():
            w.network.config.TEST_SHUTDOWN_FEE = 1000
        for chan in (graph.channels[('alice', 'bob')][0], graph.channels[('bob', 'alice')][0]):
            chan.set_state(ChannelState.SHUTDOWN)
            chan.peer_state = PeerState.DISCONNECTED
        return graph, num_sent

    def _record_time_of_first_shutdown(self, peer: Peer, chan: Channel) -> dict:
        """Returns a dict that gets filled when the peer sends 'shutdown': the time, whether the shutdown
        of the remote had arrived by then, and the state of the connection."""
        record = {}
        orig_send_message = peer.send_message

        def send_message(message_name, **kwargs):
            if message_name == 'shutdown' and not record:
                record.update(
                    time=time.monotonic(),
                    remote_shutdown_seen=chan.channel_id in peer._shutdown_seen,
                    peer_state=chan.peer_state)
            return orig_send_message(message_name, **kwargs)
        peer.send_message = send_message
        return record

    async def test_delayed_retransmission_of_shutdown_when_it_was_sent_meanwhile(self):
        # reestablish_channel holds back shutdown. meanwhile the user asked for the close: shutdown was sent,
        # and the fee negotiation is running. the delayed task must leave the channel alone then
        graph, num_sent = self._prepare_reconnect_in_shutdown_state()
        p1 = graph.peers[('alice', 'bob')]
        alice_channel = graph.channels[('alice', 'bob')][0]
        alice_channel.peer_state = PeerState.GOOD
        p1.initialized.set_result(True)
        await p1.send_shutdown(alice_channel)
        self.assertEqual(1, num_sent[(p1, 'shutdown')])
        alice_channel.set_can_send_ctx_updates(False)  # as _negotiate_closing_tx does
        await p1._retransmit_shutdown(alice_channel)
        self.assertEqual(1, num_sent[(p1, 'shutdown')])
        self.assertFalse(alice_channel._can_send_ctx_updates)

    @mock.patch('electrum.lnpeer.COOP_CLOSE_RETRY_DELAY_INIT', 0.5)
    async def test_closing_negotiation_does_not_restart_right_away_after_reconnection(self):
        """If the previous attempt to negotiate has failed, we hold back our 'shutdown' after a reconnection.
        The connection stays up meanwhile. (it is also used by the other channels we have with this peer)
        """
        graph, num_sent = self._prepare_reconnect_in_shutdown_state()
        p1, p2 = graph.peers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        alice_shutdown = self._record_time_of_first_shutdown(p1, alice_channel)
        p1.close_and_cleanup = mock.Mock()

        async def reestablish():
            t0 = time.monotonic()
            # an attempt of alice has failed, just now. bob knows of none. (e.g. bob was restarted)
            alice_channel.closing_negotiation_attempts = (1, time.time())
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            async with util.async_timeout(5):
                while not (alice_channel.get_state() == bob_channel.get_state() == ChannelState.CLOSING):
                    await asyncio.sleep(0.01)
            # bob retransmitted his shutdown right away. alice had received it, but she answered only after the delay
            self.assertTrue(alice_shutdown['remote_shutdown_seen'])
            self.assertGreaterEqual(alice_shutdown['time'] - t0, 0.45)
            # the connection stayed up
            self.assertEqual(PeerState.GOOD, alice_shutdown['peer_state'])
            p1.close_and_cleanup.assert_not_called()
            raise SuccessfulTest()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(1, num_sent[(p1, 'shutdown')])
        self.assertEqual(1, num_sent[(p2, 'shutdown')])

    async def test_user_can_restart_closing_negotiation_right_away_after_reconnection(self):
        """While we hold back our 'shutdown' after a reconnection (15 seconds here), the user asks for the close."""
        for bob_has_failed_attempt in [False, True]:
            with self.subTest(bob_has_failed_attempt=bob_has_failed_attempt):
                graph, num_sent = self._prepare_reconnect_in_shutdown_state()
                p1, p2 = graph.peers.values()
                w1 = graph.workers['alice']
                alice_channel = graph.channels[('alice', 'bob')][0]
                bob_channel = graph.channels[('bob', 'alice')][0]
                alice_channel.closing_negotiation_attempts = (1, time.time())
                if bob_has_failed_attempt:
                    bob_channel.closing_negotiation_attempts = (1, time.time())

                async def reestablish(*, p1=p1, p2=p2, w1=w1, alice_channel=alice_channel, bob_channel=bob_channel,
                                      num_sent=num_sent, bob_has_failed_attempt=bob_has_failed_attempt):
                    await asyncio.gather(
                        p1.reestablish_channel(alice_channel),
                        p2.reestablish_channel(bob_channel))
                    if bob_has_failed_attempt:
                        # nobody has retransmitted shutdown yet
                        for _ in range(10):
                            await asyncio.sleep(0.01)
                        self.assertEqual(0, num_sent[(p1, 'shutdown')] + num_sent[(p2, 'shutdown')])
                    else:
                        # bob has retransmitted his shutdown. alice has received it, but she does not answer yet
                        async with util.async_timeout(5):
                            while alice_channel.channel_id not in p1._shutdown_seen:
                                await asyncio.sleep(0.01)
                        self.assertEqual((0, 1), (num_sent[(p1, 'shutdown')], num_sent[(p2, 'shutdown')]))
                    # the user of alice asks for the close: her shutdown goes out at once
                    self.assertFalse(p1._closing_negotiation_wakeup[alice_channel.channel_id].is_set())
                    close_task = asyncio.ensure_future(p1.close_channel(alice_channel.channel_id))
                    await asyncio.sleep(0)
                    self.assertTrue(p1._closing_negotiation_wakeup[alice_channel.channel_id].is_set())
                    async with util.async_timeout(5):
                        while not num_sent[(p1, 'shutdown')]:
                            await asyncio.sleep(0.01)
                    if bob_has_failed_attempt:
                        # bob did not ask for anything: he answers when his own delay is over. (we do not wait for that)
                        async with util.async_timeout(5):
                            while bob_channel.channel_id not in p2._shutdown_seen:
                                await asyncio.sleep(0.01)
                        self.assertEqual(0, num_sent[(p2, 'shutdown')])
                        p2._closing_negotiation_wakeup[bob_channel.channel_id].set()
                    # the call returns the txid of the closing tx, whoever started the negotiation on this connection
                    closing_txid = await util.wait_for2(close_task, 5)
                    self.assertEqual(ChannelState.CLOSING, alice_channel._state)
                    self.assertEqual(w1.network.tx_queue.get_nowait().txid(), closing_txid)
                    for _ in range(10):
                        await asyncio.sleep(0.01)
                    # alice's delayed retransmission of shutdown has found that there is nothing left to do
                    self.assertEqual(ChannelState.CLOSING, alice_channel._state)
                    self.assertFalse(alice_channel._can_send_ctx_updates)
                    raise SuccessfulTest()
                gath = asyncio.gather(
                    reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
                with self.assertRaises(SuccessfulTest):
                    await util.wait_for2(gath, 20)
                # nobody sent shutdown twice. (alice's delayed retransmission found that it was sent already)
                self.assertEqual((1, 1), (num_sent[(p1, 'shutdown')], num_sent[(p2, 'shutdown')]))

    async def test_no_shutdown_after_delay_if_channel_was_force_closed_meanwhile(self):
        graph, num_sent = self._prepare_reconnect_in_shutdown_state()
        p1, p2 = graph.peers.values()
        w1 = graph.workers['alice']
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        alice_channel.closing_negotiation_attempts = (1, time.time())
        p1.close_and_cleanup = mock.Mock()

        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            async with util.async_timeout(5):
                while alice_channel.channel_id not in p1._shutdown_seen:
                    await asyncio.sleep(0.01)
            # the user does not want to wait
            await w1.force_close_channel(alice_channel.channel_id)
            self.assertEqual(ChannelState.FORCE_CLOSING, alice_channel._state)
            # a call of close_channel ends the delay. there is nothing left to negotiate
            with self.assertRaisesRegex(Exception, "The channel was closed in the meantime"):
                await util.wait_for2(p1.close_channel(alice_channel.channel_id), 5)
            for _ in range(10):
                await asyncio.sleep(0.01)
            raise SuccessfulTest()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertLogs('electrum', level='ERROR'):
            with self.assertRaises(SuccessfulTest):
                await util.wait_for2(gath, 20)
        self.assertEqual(0, num_sent[(p1, 'shutdown')])
        self.assertEqual(0, num_sent[(p1, 'closing_signed')])
        self.assertEqual(ChannelState.FORCE_CLOSING, alice_channel._state)
        p1.close_and_cleanup.assert_not_called()  # (the other channels with bob keep their connection)

    async def test_force_close_while_close_channel_waits_for_shutdown_of_remote(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1 = graph.workers['alice']
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        num_closing_signed_sent_by_alice = 0
        orig_send_message = p1.send_message

        def send_message(message_name, **kwargs):
            nonlocal num_closing_signed_sent_by_alice
            num_closing_signed_sent_by_alice += message_name == 'closing_signed'
            return orig_send_message(message_name, **kwargs)
        p1.send_message = send_message
        # bob takes his time to answer the shutdown of alice
        bob_channel.closing_negotiation_attempts = (1, time.time())

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            close_task = asyncio.ensure_future(p1.close_channel(alice_channel.channel_id))
            async with util.async_timeout(5):
                while bob_channel.channel_id not in p2._shutdown_seen:
                    await asyncio.sleep(0.01)
            await w1.force_close_channel(alice_channel.channel_id)
            p2._closing_negotiation_wakeup[bob_channel.channel_id].set()  # now bob answers
            with self.assertRaisesRegex(Exception, "The channel was closed in the meantime"):
                await util.wait_for2(close_task, 5)
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertLogs('electrum', level='ERROR'):
            with self.assertRaises(SuccessfulTest):
                await util.wait_for2(gath, 20)
        self.assertEqual(0, num_closing_signed_sent_by_alice)
        self.assertEqual(ChannelState.FORCE_CLOSING, alice_channel._state)

    async def test_closing_negotiation_restarts_after_reconnection(self):
        """End to end: the negotiation fails, both sides disconnect. On the next connection each side
        retransmits shutdown (once it has waited long enough), and the negotiation starts again.
        """
        alice_lnwallet, bob_lnwallet = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan']).values()
        alice_channel, bob_channel = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)
        # -- first connection: the fee ranges do not overlap
        p1, p2, w1, w2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.TEST_SHUTDOWN_FEE = 1
        w1.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 1, 'max_fee_satoshis': 10}
        w2.network.config.TEST_SHUTDOWN_FEE = 200
        w2.network.config.TEST_SHUTDOWN_FEE_RANGE = {'min_fee_satoshis': 50, 'max_fee_satoshis': 300}

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            await p2.close_channel(bob_channel.channel_id)
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with mock.patch('electrum.lnpeer.LN_P2P_NETWORK_TIMEOUT', 0.05):
            with self.assertLogs('electrum', level='ERROR'):
                with self.assertRaisesRegex(CoopCloseFailure, "There is no overlap"):
                    await util.wait_for2(gath, 20)
                # bob has failed. alice fails a bit later: she does not get an answer to her closing_signed
                async with util.async_timeout(5):
                    while not (p1.got_disconnected.is_set() and p2.got_disconnected.is_set()):
                        await asyncio.sleep(0.01)
        self.assertEqual((ChannelState.SHUTDOWN, ChannelState.SHUTDOWN), (alice_channel._state, bob_channel._state))
        self.assertEqual((PeerState.DISCONNECTED, PeerState.DISCONNECTED), (alice_channel.peer_state, bob_channel.peer_state))
        self.assertEqual((1, 1), (alice_channel.closing_negotiation_attempts[0], bob_channel.closing_negotiation_attempts[0]))

        # -- second connection. by now the fee estimates of both sides agree
        p1, p2, w1, w2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000
        for chan in (alice_channel, bob_channel):  # prepare_peers has reset the state of the channels
            chan.set_state(ChannelState.SHUTDOWN)
            chan.peer_state = PeerState.DISCONNECTED
        num_sent = defaultdict(int)
        for peer in (p1, p2):
            def send_message(message_name, *, _peer=peer, _orig=peer.send_message, **kwargs):
                num_sent[(_peer, message_name)] += 1
                return _orig(message_name, **kwargs)
            peer.send_message = send_message
        # both sides have to wait before they take part in the next attempt: 15 seconds, minus what has passed
        self.assertTrue(10 < p1._closing_negotiation_backoff(alice_channel) <= 15)
        self.assertTrue(10 < p2._closing_negotiation_backoff(bob_channel) <= 15)
        alice_shutdown = self._record_time_of_first_shutdown(p1, alice_channel)

        async def reestablish():
            t0 = time.monotonic()
            # (the test does not want to wait that long: we reconnect 14.5 seconds after the failure)
            for chan in (alice_channel, bob_channel):
                chan.closing_negotiation_attempts = (1, time.time() - 14.5)
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            async with util.async_timeout(5):
                while not (alice_channel.get_state() == bob_channel.get_state() == ChannelState.CLOSING):
                    await asyncio.sleep(0.01)
            self.assertGreaterEqual(alice_shutdown['time'] - t0, 0.45)
            raise SuccessfulTest()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        # shutdown was sent again on the new connection, once
        self.assertEqual((1, 1), (num_sent[(p1, 'shutdown')], num_sent[(p2, 'shutdown')]))
        self.assertEqual(w1.network.tx_queue.get_nowait().txid(), w2.network.tx_queue.get_nowait().txid())

    @mock.patch('electrum.lnpeer.COOP_CLOSE_MAX_ROUNDS', 3)
    async def test_legacy_shutdown_agreement_in_last_round(self):
        # the remote repeats our fee in the last round that is allowed: that is an agreement, not a failure
        async def remote(peer, chan, payload):
            return await self._scripted_shutdown(peer, chan, payload, offers=[5000, 4000, 2000])
        res = await self._test_shutdown_with_remote(
            remote_negotiation=remote, remote_is_funder=False, remote_closes=False)
        self._assert_coop_closed_with_remote(res, expected_fee=2000)
        self.assertEqual([1000, 2000, 2000], res.our_fees)

    @mock.patch('electrum.lnpeer.COOP_CLOSE_RETRY_DELAY_INIT', 0)  # otherwise the delay would hide a second negotiation
    async def test_redundant_shutdown_from_remote_is_ignored_if_we_started_the_close(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000
        orig_send_shutdown = p2.send_shutdown

        async def send_shutdown_twice(chan):
            await orig_send_shutdown(chan)
            p2._shutdown_sent.discard(chan.channel_id)
            await orig_send_shutdown(chan)
        p2.send_shutdown = send_shutdown_twice
        num_shutdown_received_by_alice = 0
        orig_on_shutdown = p1.on_shutdown

        on_shutdown_tasks = []

        async def on_shutdown(chan, payload):
            nonlocal num_shutdown_received_by_alice
            num_shutdown_received_by_alice += 1
            on_shutdown_tasks.append(await orig_on_shutdown(chan, payload))  # (the handler runs in a task of its own)
        p1.on_shutdown = on_shutdown
        num_negotiations_of_alice = 0
        orig_shutdown = p1._shutdown

        async def shutdown(*args, **kwargs):
            nonlocal num_negotiations_of_alice
            num_negotiations_of_alice += 1
            return await orig_shutdown(*args, **kwargs)
        p1._shutdown = shutdown

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            await util.wait_for2(p1.close_channel(alice_channel.channel_id), 5)
            async with util.async_timeout(5):
                while bob_channel.get_state() != ChannelState.CLOSING or num_shutdown_received_by_alice < 2:
                    await asyncio.sleep(0.01)
                await asyncio.gather(*on_shutdown_tasks)  # neither of the two has raised
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(2, num_shutdown_received_by_alice)
        self.assertEqual(1, num_negotiations_of_alice)
        self.assertEqual(ChannelState.CLOSING, alice_channel._state)

    async def test_close_channel_can_be_called_again_after_it_was_cancelled(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000
        orig_on_shutdown = p2.on_shutdown
        held_back = []
        p2.on_shutdown = lambda chan, payload: held_back.append((chan, payload))  # bob does not answer yet

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            close_task = asyncio.ensure_future(p1.close_channel(alice_channel.channel_id))
            async with util.async_timeout(5):
                while not held_back:
                    await asyncio.sleep(0.01)
            close_task.cancel()  # e.g. the caller gave up waiting
            with self.assertRaises(asyncio.CancelledError):
                await close_task
            # the second call does not send shutdown again, and it gets the answer of bob
            close_task = asyncio.ensure_future(p1.close_channel(alice_channel.channel_id))
            await asyncio.sleep(0.05)
            await orig_on_shutdown(*held_back[0])
            await util.wait_for2(close_task, 5)
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.CLOSING, alice_channel._state)

    async def test_two_channels_with_one_peer_can_both_be_closed(self):
        # what we remember about 'shutdown' is per channel, not per connection
        graph_def = copy.deepcopy(self.GRAPH_DEFINITIONS['single_chan'])
        graph_def['alice']['channels']['bob'].append(copy.deepcopy(graph_def['alice']['channels']['bob'][0]))
        graph = self.prepare_chans_and_peers_in_graph(graph_def)
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        chan1, chan2 = graph.channels[('alice', 'bob')]
        self.assertNotEqual(chan1.channel_id, chan2.channel_id)
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            await util.wait_for2(p1.close_channel(chan1.channel_id), 5)
            # the other channel is closed on the same connection, this time by bob
            await util.wait_for2(p2.close_channel(chan2.channel_id), 5)
            async with util.async_timeout(5):  # (alice is done a moment after bob)
                while chan2.get_state() != ChannelState.CLOSING:
                    await asyncio.sleep(0.01)
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual((ChannelState.CLOSING, ChannelState.CLOSING), (chan1._state, chan2._state))
        self.assertEqual(2, w1.network.tx_queue.qsize())

    @mock.patch('electrum.lnpeer.COOP_CLOSE_RETRY_DELAY_INIT', 0)  # otherwise the delay would hide a second negotiation
    async def test_redundant_shutdown_from_remote_is_ignored(self):
        """Electrum <= 4.8.3 sends 'shutdown' twice after a reconnection in SHUTDOWN state.
        We must not start the fee negotiation a second time when the second one arrives.
        """
        graph, num_sent = self._prepare_reconnect_in_shutdown_state()
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        # bob behaves like the old code: he sends shutdown every time send_shutdown is called
        orig_send_shutdown = p2.send_shutdown

        async def send_shutdown_like_old_electrum(chan):
            p2._shutdown_sent.discard(chan.channel_id)
            await orig_send_shutdown(chan)
        p2.send_shutdown = send_shutdown_like_old_electrum
        num_negotiations_of_alice = 0
        orig_shutdown = p1._shutdown

        async def shutdown(*args, **kwargs):
            nonlocal num_negotiations_of_alice
            num_negotiations_of_alice += 1
            return await orig_shutdown(*args, **kwargs)
        p1._shutdown = shutdown

        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            async with util.async_timeout(5):
                while not (alice_channel.get_state() == bob_channel.get_state() == ChannelState.CLOSING):
                    await asyncio.sleep(0.01)
            raise SuccessfulTest()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual(2, num_sent[(p2, 'shutdown')])
        self.assertEqual(1, num_sent[(p1, 'shutdown')])
        self.assertEqual(1, num_negotiations_of_alice)
        # both broadcast the same closing tx
        self.assertEqual(w1.network.tx_queue.get_nowait().txid(), w2.network.tx_queue.get_nowait().txid())

    async def test_close_channel_can_be_called_again_if_shutdown_could_not_be_sent(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000
        orig_send_message = p1.send_message

        def send_message_fails(message_name, **kwargs):
            if message_name == 'shutdown':
                raise Exception("tried to send message before we are initialized")
            return orig_send_message(message_name, **kwargs)

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            p1.send_message = send_message_fails
            with self.assertRaisesRegex(Exception, "before we are initialized"):
                await p1.close_channel(alice_channel.channel_id)
            p1.send_message = orig_send_message
            await util.wait_for2(p1.close_channel(alice_channel.channel_id), 5)
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertLogs('electrum', level='ERROR'):
            with self.assertRaises(SuccessfulTest):
                await util.wait_for2(gath, 20)
        self.assertEqual(ChannelState.CLOSING, alice_channel._state)

    async def _test_shutdown(
        self,
        *,
        alice_fee: int,
        bob_fee: int,
        alice_fee_range: dict,
        bob_fee_range: dict,
        alice_closes: bool,  # who sends "shutdown" first
        wait_until_both_sides_failed: bool = False,
    ) -> tuple[Channel, Channel, Optional[CoopCloseFailure]]:
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = alice_fee
        w2.network.config.TEST_SHUTDOWN_FEE = bob_fee
        w1.network.config.TEST_SHUTDOWN_FEE_RANGE = alice_fee_range
        w2.network.config.TEST_SHUTDOWN_FEE_RANGE = bob_fee_range
        w2.enable_htlc_settle = False
        lnaddr, pay_req = self.prepare_invoice(w2)
        async def pay():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            # alice sends htlc
            route = (await w1.create_routes_from_invoice(lnaddr.get_amount_msat(), decoded_invoice=lnaddr))[0][0].route
            p1.pay(route=route,
                   chan=alice_channel,
                   amount_msat=lnaddr.get_amount_msat(),
                   total_msat=lnaddr.get_amount_msat(),
                   payment_hash=lnaddr.paymenthash,
                   min_final_cltv_delta=lnaddr.get_min_final_cltv_delta(),
                   payment_secret=lnaddr.payment_secret)
            await p2.received_commitsig_event.wait()
            # start mutual close
            p_shutdown_sender = p1 if alice_closes else p2
            await p_shutdown_sender.close_channel(alice_channel.channel_id)
            raise SuccessfulTest()
        async def set_settle():
            await asyncio.sleep(0.1)
            w2.enable_htlc_settle = True
        gath = asyncio.gather(pay(), set_settle(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())

        coop_close_failure = None
        try:
            await util.wait_for2(gath, 20)
        except SuccessfulTest:
            pass
        except CoopCloseFailure as e:
            coop_close_failure = e
        if wait_until_both_sides_failed:
            # the side that did not call close_channel fails in a task that nobody awaits. it disconnects then.
            async with util.async_timeout(5):
                while not (p1.got_disconnected.is_set() and p2.got_disconnected.is_set()):
                    await asyncio.sleep(0.01)

        return alice_channel, bob_channel, coop_close_failure

    @staticmethod
    async def _lnd_legacy_shutdown(peer: Peer, chan: Channel, payload, *, ideal_fee: int, max_fee: int) -> int:
        """Stand-in for Peer._shutdown that negotiates like lnd does when option_simple_close is not negotiated
        (port of lnwallet/chancloser/chancloser.go, lnd v0.21). In particular, lnd never sends a fee_range.
        Returns the fee that was agreed on.
        """
        def fee_in_acceptable_range(local_fee: int, remote_fee: int) -> bool:
            if local_fee < remote_fee:
                return remote_fee <= local_fee + (local_fee * 3) // 10
            return remote_fee >= local_fee - (local_fee * 3) // 10

        def calc_compromise_fee(last_sent_fee: int, remote_fee: int) -> int:
            if ideal_fee == remote_fee or last_sent_fee == 0:
                return ideal_fee
            if remote_fee == last_sent_fee:
                return last_sent_fee
            if fee_in_acceptable_range(last_sent_fee, remote_fee):
                return remote_fee
            if remote_fee < last_sent_fee:
                return last_sent_fee - last_sent_fee // 10
            return last_sent_fee + last_sent_fee // 10

        is_initiator = chan.constraints.is_initiator
        our_scriptpubkey = bitcoin.address_to_script(chan.get_sweep_address())
        their_scriptpubkey = payload['scriptpubkey']
        prior_fee_offers = {}  # fee -> our sig
        last_fee_proposal = 0

        def propose_close_signed(fee: int) -> None:
            nonlocal last_fee_proposal
            sig, _tx = chan.make_closing_tx(our_scriptpubkey, their_scriptpubkey, fee_sat=fee)
            prior_fee_offers[fee] = sig
            last_fee_proposal = fee

        def send_close_signed(fee: int) -> None:
            peer.send_message(
                'closing_signed',
                channel_id=chan.channel_id,
                fee_satoshis=fee,
                signature=prior_fee_offers[fee],
                closing_signed_tlvs={},  # no fee_range
            )

        if is_initiator:
            propose_close_signed(ideal_fee)
            send_close_signed(ideal_fee)
        while True:
            cs_payload = await peer.wait_for_message('closing_signed', chan.channel_id)
            remote_fee = cs_payload['fee_satoshis']
            if remote_fee not in prior_fee_offers:
                proposal = calc_compromise_fee(last_fee_proposal, remote_fee)
                if is_initiator and proposal > max_fee:
                    # lnd resets its state machine and disconnects. (it does not force-close)
                    raise GracefulDisconnect(f"lnd: proposal exceeds max fee: {proposal} > {max_fee}")
                propose_close_signed(proposal)
                if proposal != remote_fee:
                    send_close_signed(proposal)
                    continue
            # the remote must have signed the same tx as we did:
            _sig, closing_tx = chan.make_closing_tx(our_scriptpubkey, their_scriptpubkey, fee_sat=remote_fee)
            msg_hash = sha256d(closing_tx.serialize_preimage(0))
            assert ECPubkey(chan.config[REMOTE].multisig_key.pubkey).ecdsa_verify(cs_payload['signature'], msg_hash)
            send_close_signed(remote_fee)
            return remote_fee

    @staticmethod
    async def _scripted_shutdown(peer: Peer, chan: Channel, payload, *, offers: Iterable) -> int:
        """Stand-in for Peer._shutdown: a remote that sends the given closing_signed messages one after the other,
        whatever we answer. It is done when we repeat one of its fees, or it repeats our last one.
        Returns the fee that was agreed on.
        An offer is either a fee (the message then has no fee_range, as with lnd),
        or a dict with the keys 'fee', and optionally 'fee_range' (a tuple) and 'bad_sig'.
        """
        our_scriptpubkey = bitcoin.address_to_script(chan.get_sweep_address())
        their_scriptpubkey = payload['scriptpubkey']
        offers = iter(offers)
        fees_offered = set()

        def send_next_offer() -> int:
            offer = next(offers)
            if not isinstance(offer, dict):
                offer = {'fee': offer}
            fee = offer['fee']
            sig, _tx = chan.make_closing_tx(our_scriptpubkey, their_scriptpubkey, fee_sat=fee)
            if offer.get('bad_sig'):
                sig = bytes(64)
            tlvs = {}
            if offer.get('fee_range'):
                min_fee, max_fee = offer['fee_range']
                tlvs = {'fee_range': {'min_fee_satoshis': min_fee, 'max_fee_satoshis': max_fee}}
            fees_offered.add(fee)
            peer.send_message(
                'closing_signed', channel_id=chan.channel_id, fee_satoshis=fee, signature=sig, closing_signed_tlvs=tlvs)
            return fee

        if chan.constraints.is_initiator:
            send_next_offer()
        while True:
            cs_payload = await peer.wait_for_message('closing_signed', chan.channel_id)
            their_fee = cs_payload['fee_satoshis']
            if their_fee in fees_offered or their_fee == send_next_offer():
                return their_fee

    class CloseWithRemoteResult(NamedTuple):
        chan_our: Channel
        w_our: MockLNWallet
        p_our: Peer
        remote_agreed_fee: Optional[int]  # the fee the remote agreed to, if any
        exc: Optional[Exception]  # what close_channel raised, or else what our side of the negotiation raised
        our_fees: Sequence[int]  # fee_satoshis of all the closing_signed messages we sent
        warnings_received_by_remote: Sequence[bytes]
        events: Sequence[str]  # 'warning' (we sent one) and 'disconnect' (we closed the connection), in order

    async def _test_shutdown_with_remote(
        self,
        *,
        remote_negotiation,  # coroutine function (peer, chan, payload) -> agreed fee. replaces Peer._shutdown of the remote
        remote_is_funder: bool,
        remote_closes: bool,  # who sends "shutdown" first
        graph: Graph = None,
        our_fee_range: Optional[Tuple[int, int]] = (500, 2000),
    ) -> 'TestPeerDirect.CloseWithRemoteResult':
        """Cooperative close between Electrum ("we") and a remote whose side of the fee negotiation is scripted.
        Our fee is 1000 sat, and our fee range is [500, 2000] sat. With our_fee_range=None, they are not set
        by the test, but come from the fee estimates.
        """
        if graph is None:
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        assert alice_channel.constraints.is_initiator and not bob_channel.constraints.is_initiator
        if remote_is_funder:
            p_remote, (p_our, chan_our, w_our) = p1, (p2, bob_channel, w2)
        else:
            p_remote, (p_our, chan_our, w_our) = p2, (p1, alice_channel, w1)
        if our_fee_range:
            w_our.network.config.TEST_SHUTDOWN_FEE = 1000
            w_our.network.config.TEST_SHUTDOWN_FEE_RANGE = {
                'min_fee_satoshis': our_fee_range[0], 'max_fee_satoshis': our_fee_range[1]}
        else:
            orig_get_shutdown_fee_range = p_our.get_shutdown_fee_range

            def get_shutdown_fee_range(*args, **kwargs):
                nonlocal our_fee_range
                fee, fee_range = orig_get_shutdown_fee_range(*args, **kwargs)
                our_fee_range = (fee_range['min_fee_satoshis'], fee_range['max_fee_satoshis'])
                return fee, fee_range
            p_our.get_shutdown_fee_range = get_shutdown_fee_range
        remote_agreed_fee = None
        our_fees = []
        our_failures = []
        warnings_received_by_remote = []
        events = []
        orig_send_message = p_our.send_message
        orig_close_and_cleanup = p_our.close_and_cleanup
        orig_shutdown = p_our._shutdown

        def send_message(message_name, **kwargs):
            if message_name == 'closing_signed':
                our_fees.append(kwargs['fee_satoshis'])
                # the fee we sign is inside the fee_range we send along with it
                fee_range = kwargs['closing_signed_tlvs']['fee_range']
                self.assertTrue(fee_range['min_fee_satoshis'] <= kwargs['fee_satoshis'] <= fee_range['max_fee_satoshis'],
                                (kwargs['fee_satoshis'], fee_range))
            elif message_name == 'warning':
                events.append('warning')
            return orig_send_message(message_name, **kwargs)
        p_our.send_message = send_message

        def close_and_cleanup():
            events.append('disconnect')
            return orig_close_and_cleanup()
        p_our.close_and_cleanup = close_and_cleanup

        async def our_shutdown(chan, payload, *, is_local):
            try:
                return await orig_shutdown(chan, payload, is_local=is_local)
            except Exception as e:
                our_failures.append(e)
                raise
        p_our._shutdown = our_shutdown
        def on_warning(payload):
            self.assertEqual(alice_channel.channel_id, payload['channel_id'])
            warnings_received_by_remote.append(payload['data'])
        p_remote.on_warning = on_warning

        async def remote_shutdown(chan, payload, *, is_local):
            nonlocal remote_agreed_fee
            remote_agreed_fee = await remote_negotiation(p_remote, chan, payload)
            return "txid of the remote"
        p_remote._shutdown = remote_shutdown

        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            p_shutdown_sender = p_remote if remote_closes else p_our
            close_task = asyncio.ensure_future(p_shutdown_sender.close_channel(alice_channel.channel_id))
            try:
                # wait until both sides are done, or one of them has failed.
                # (the side that did not call close_channel runs in a task that nobody awaits)
                while True:
                    if close_task.done() and close_task.exception():
                        raise close_task.exception()
                    if our_failures:
                        raise our_failures[0]
                    if chan_our.get_state() == ChannelState.CLOSING and remote_agreed_fee is not None:
                        break
                    await asyncio.sleep(0.01)
            finally:
                close_task.cancel()
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())

        exc = None
        try:
            await util.wait_for2(gath, 20)  # a negotiation that does not terminate must fail the test
        except SuccessfulTest:
            pass
        except (CoopCloseFailure, GracefulDisconnect) as e:
            exc = e
        # we never signed for a fee outside our fee range. (if the remote is the one paying, there is no upper limit)
        fees_outside_our_range = [
            fee for fee in our_fees if fee < our_fee_range[0] or (fee > our_fee_range[1] and not remote_is_funder)]
        self.assertEqual([], fees_outside_our_range)
        return self.CloseWithRemoteResult(
            chan_our, w_our, p_our, remote_agreed_fee, exc, our_fees, warnings_received_by_remote, events)

    async def _test_shutdown_with_lnd(
        self,
        *,
        lnd_ideal_fee: int,
        lnd_max_fee: int = None,
        lnd_is_funder: bool,
        lnd_closes: bool,  # who sends "shutdown" first
    ) -> 'TestPeerDirect.CloseWithRemoteResult':
        """Cooperative close between Electrum and an (emulated) lnd."""
        if lnd_max_fee is None:
            lnd_max_fee = 3 * lnd_ideal_fee

        async def lnd_negotiation(peer, chan, payload):
            return await self._lnd_legacy_shutdown(peer, chan, payload, ideal_fee=lnd_ideal_fee, max_fee=lnd_max_fee)
        return await self._test_shutdown_with_remote(
            remote_negotiation=lnd_negotiation, remote_is_funder=lnd_is_funder, remote_closes=lnd_closes)

    def _assert_coop_closed_with_remote(self, res: 'TestPeerDirect.CloseWithRemoteResult', *, expected_fee: int):
        self.assertIsNone(res.exc)
        self.assertEqual(ChannelState.CLOSING, res.chan_our._state)
        self.assertEqual(expected_fee, res.remote_agreed_fee)
        # we broadcast the closing tx, and it pays the fee both sides agreed on
        self.assertEqual(1, res.w_our.network.tx_queue.qsize())
        closing_tx = res.w_our.network.tx_queue.get_nowait()  # type: Transaction
        self.assertTrue(closing_tx.is_complete())
        self.assertEqual(expected_fee, res.chan_our.constraints.capacity - closing_tx.output_value())

    def _assert_not_closed_with_remote(self, res: 'TestPeerDirect.CloseWithRemoteResult'):
        # we neither closed nor force-closed
        self.assertIsNone(res.remote_agreed_fee)
        self.assertEqual(ChannelState.SHUTDOWN, res.chan_our._state)
        self.assertEqual(0, res.w_our.network.tx_queue.qsize())

    def _assert_negotiation_failed_with_remote(self, res: 'TestPeerDirect.CloseWithRemoteResult', reason: str):
        """Our side gave up: it told the remote why, closed the connection, and did not force-close."""
        self.assertIsInstance(res.exc, CoopCloseFailure)
        self.assertIn(reason, str(res.exc))
        self.assertIn("We have not closed the channel.", str(res.exc))
        self._assert_not_closed_with_remote(res)
        self.assertEqual(['warning', 'disconnect'], res.events)
        self.assertEqual(1, len(res.warnings_received_by_remote))
        self.assertIn(b"closing negotiation failed: " + reason.encode('ascii'), res.warnings_received_by_remote[0])
        self.assertTrue(res.p_our.got_disconnected.is_set())
        self.assertEqual(PeerState.DISCONNECTED, res.chan_our.peer_state)
        self.assertEqual(1, res.chan_our.closing_negotiation_attempts[0])

    async def test_legacy_shutdown_lnd_agrees_with_our_fee(self):
        # lnd repeats our own fee (without a fee_range): the negotiation is complete after two messages.
        for lnd_is_funder in [False, True]:
            for lnd_closes in [False, True]:
                with self.subTest(lnd_is_funder=lnd_is_funder, lnd_closes=lnd_closes):
                    res = await self._test_shutdown_with_lnd(
                        lnd_ideal_fee=1000, lnd_is_funder=lnd_is_funder, lnd_closes=lnd_closes)
                    self._assert_coop_closed_with_remote(res, expected_fee=1000)
                    self.assertEqual([1000], res.our_fees)

    async def test_legacy_shutdown_lnd_fee_inside_our_range(self):
        # the fee lnd proposes is different from ours, but inside our fee range: we accept it.
        for lnd_is_funder in [False, True]:
            for lnd_closes in [False, True]:
                for lnd_ideal_fee in [500, 700, 1010, 2000]:
                    with self.subTest(lnd_is_funder=lnd_is_funder, lnd_closes=lnd_closes, lnd_ideal_fee=lnd_ideal_fee):
                        res = await self._test_shutdown_with_lnd(
                            lnd_ideal_fee=lnd_ideal_fee, lnd_is_funder=lnd_is_funder, lnd_closes=lnd_closes)
                        self._assert_coop_closed_with_remote(res, expected_fee=lnd_ideal_fee)
                        # as funder, we send our fee first, and then repeat theirs. otherwise we only repeat theirs.
                        self.assertEqual([lnd_ideal_fee] if lnd_is_funder else [1000, lnd_ideal_fee], res.our_fees)

    async def test_legacy_shutdown_lnd_fee_below_our_range(self):
        # lnd wants a lower fee than our minimum: it has to move towards us.
        for lnd_is_funder in [False, True]:
            with self.subTest(lnd_is_funder=lnd_is_funder):
                res = await self._test_shutdown_with_lnd(
                    lnd_ideal_fee=300, lnd_is_funder=lnd_is_funder, lnd_closes=lnd_is_funder)
                self._assert_coop_closed_with_remote(res, expected_fee=500)
                # we met lnd halfway first (1000 -> 650), and then insisted on our minimum,
                # while lnd raised its fee: 300 -> 330 -> 363 -> 399 (at which point 500 is within 30%)
                first_fees = [650, 500] if lnd_is_funder else [1000, 650, 500]
                self.assertEqual(first_fees, res.our_fees[:len(first_fees)])
                self.assertEqual({500}, set(res.our_fees[len(first_fees):]))
        # just below our minimum: we propose 749, lnd raises its fee by 10%, and that is inside our range
        res = await self._test_shutdown_with_lnd(lnd_ideal_fee=499, lnd_is_funder=False, lnd_closes=False)
        self._assert_coop_closed_with_remote(res, expected_fee=548)
        self.assertEqual([1000, 749, 548], res.our_fees)

    async def test_legacy_shutdown_lnd_fee_above_our_range(self):
        # we are the funder, and lnd wants a higher fee than our maximum: we do not pay more than our maximum.
        res = await self._test_shutdown_with_lnd(lnd_ideal_fee=5000, lnd_is_funder=False, lnd_closes=False)
        self._assert_coop_closed_with_remote(res, expected_fee=2000)
        # just above our maximum
        res = await self._test_shutdown_with_lnd(lnd_ideal_fee=2001, lnd_is_funder=False, lnd_closes=False)
        self._assert_coop_closed_with_remote(res, expected_fee=1500)
        # far above our maximum: lnd needs many rounds, but it gets there
        res = await self._test_shutdown_with_lnd(lnd_ideal_fee=1_000_000, lnd_is_funder=False, lnd_closes=True)
        self._assert_coop_closed_with_remote(res, expected_fee=2000)
        # lnd is the funder: it is the one paying, so we have no reason to refuse a high fee.
        res = await self._test_shutdown_with_lnd(lnd_ideal_fee=5000, lnd_is_funder=True, lnd_closes=False)
        self._assert_coop_closed_with_remote(res, expected_fee=5000)

    async def test_legacy_shutdown_lnd_cannot_reach_our_range(self):
        # lnd is the funder, and the most it is willing to pay is below our minimum: lnd gives up and disconnects.
        res = await self._test_shutdown_with_lnd(
            lnd_ideal_fee=100, lnd_max_fee=300, lnd_is_funder=True, lnd_closes=True)
        self.assertIsInstance(res.exc, GracefulDisconnect)
        self._assert_not_closed_with_remote(res)
        # it was lnd that gave up, not us. still, this attempt counts for the delay before the next one
        self.assertEqual([], res.events)
        self.assertEqual(1, res.chan_our.closing_negotiation_attempts[0])
        self.assertTrue(10 < res.p_our._closing_negotiation_backoff(res.chan_our) <= 15)

    async def test_legacy_shutdown_lnd_does_not_move(self):
        # lnd changes its fee by 10% in each round, which is 0 sat if the fee is below 10 sat:
        # it keeps sending the same fee, which is outside our range, so no progress is possible.
        for lnd_closes in [False, True]:
            with self.subTest(lnd_closes=lnd_closes):
                with self.assertLogs('electrum', level='ERROR'):
                    res = await self._test_shutdown_with_lnd(lnd_ideal_fee=5, lnd_is_funder=False, lnd_closes=lnd_closes)
                self._assert_negotiation_failed_with_remote(
                    res, "Their fee (5 sat) is not strictly between our last fee (502 sat) and their previous fee (5 sat).")

    async def test_legacy_shutdown_remote_does_not_move(self):
        # "strictly between" (BOLT-02): the remote has to come closer to our fee with every message.
        for remote_is_funder, remote_closes, stubborn_fee, second_fee, our_fees in [
                # we are the funder. the remote stays above our maximum,
                (False, False, 5000, 5000, [1000, 2000]),
                (False, True, 5000, 5000, [1000, 2000]),
                (False, False, 5000, 5001, [1000, 2000]),  # or moves away from us,
                (False, False, 5000, 2000, [1000, 2000]),  # or jumps to our last fee (which ends the negotiation),
                (False, False, 5000, 1999, [1000, 2000, 1999]),  # or beyond it (inside our range: we accept that).
                # the remote stays below our minimum
                (False, False, 100, 100, [1000, 550]),
                (False, False, 100, 99, [1000, 550]),
                # we are not the funder. the remote stays below our minimum
                (True, False, 100, 100, [550]),
                (True, True, 100, 100, [550]),
                (True, True, 100, 99, [550]),
        ]:
            with self.subTest(remote_is_funder=remote_is_funder, remote_closes=remote_closes,
                              stubborn_fee=stubborn_fee, second_fee=second_fee):
                async def stubborn_remote(peer, chan, payload, *, stubborn_fee=stubborn_fee, second_fee=second_fee):
                    fees = itertools.chain([stubborn_fee], itertools.repeat(second_fee))
                    return await self._scripted_shutdown(peer, chan, payload, offers=fees)
                with self.assertLogs('electrum', level='DEBUG'):
                    res = await self._test_shutdown_with_remote(
                        remote_negotiation=stubborn_remote, remote_is_funder=remote_is_funder, remote_closes=remote_closes)
                if second_fee in (1999, 2000):
                    self._assert_coop_closed_with_remote(res, expected_fee=second_fee)
                else:
                    self._assert_negotiation_failed_with_remote(
                        res, f"Their fee ({second_fee} sat) is not strictly between our last fee ({our_fees[-1]} sat) "
                             f"and their previous fee ({stubborn_fee} sat).")
                # we answered their first fee, and gave up when the second one arrived
                self.assertEqual(our_fees, res.our_fees)

    async def test_legacy_shutdown_fee_inside_our_range_is_accepted_at_any_time(self):
        # BOLT-02 first asks if the fee matches the fee_range we sent, and only then if it is "strictly between".
        # Here their second fee is not strictly between our last fee (2000) and their previous one (5000),
        # but it is inside our range, and cheaper for us than our own proposal.
        async def remote(peer, chan, payload):
            fees = itertools.chain([5000], itertools.repeat(1500))
            return await self._scripted_shutdown(peer, chan, payload, offers=fees)
        res = await self._test_shutdown_with_remote(
            remote_negotiation=remote, remote_is_funder=False, remote_closes=False)
        self._assert_coop_closed_with_remote(res, expected_fee=1500)
        self.assertEqual([1000, 2000, 1500], res.our_fees)

    @mock.patch('electrum.lnpeer.COOP_CLOSE_MAX_ROUNDS', 20)
    async def test_legacy_shutdown_number_of_rounds_is_limited(self):
        # the remote comes closer by 1 sat with every message: that is "strictly between", but it would take forever.
        # (in its 26th message it would send a fee that we accept)
        for remote_is_funder, start_fee, step, final_fee in [(False, 1_000_000, -1, 2000), (True, 1, 1, 500)]:
            with self.subTest(remote_is_funder=remote_is_funder):
                async def slow_remote(peer, chan, payload, *, start_fee=start_fee, step=step, final_fee=final_fee):
                    offers = itertools.chain(range(start_fee, start_fee + 25 * step, step), itertools.repeat(final_fee))
                    return await self._scripted_shutdown(peer, chan, payload, offers=offers)
                with self.assertLogs('electrum', level='ERROR'):
                    res = await self._test_shutdown_with_remote(
                        remote_negotiation=slow_remote, remote_is_funder=remote_is_funder, remote_closes=False)
                self._assert_negotiation_failed_with_remote(res, "No agreement on the fee after 20 rounds.")
                # we answered 19 of their 20 messages (and sent the first message, if we are the funder)
                self.assertEqual(19 if remote_is_funder else 20, len(res.our_fees))

    async def test_shutdown_remote_sends_fee_range_only_in_second_message(self):
        # their first closing_signed has no fee_range, the second one has. each message is handled on its own.
        async def remote(peer, chan, payload):
            offers = [5000, {'fee': 1800, 'fee_range': (1500, 3000)}]
            return await self._scripted_shutdown(peer, chan, payload, offers=offers)
        res = await self._test_shutdown_with_remote(
            remote_negotiation=remote, remote_is_funder=False, remote_closes=False)
        self._assert_coop_closed_with_remote(res, expected_fee=1800)
        self.assertEqual([1000, 2000, 1800], res.our_fees)

    async def test_shutdown_remote_sends_fee_range_only_in_first_message(self):
        # their first closing_signed has a fee_range, which does not overlap with ours.
        async def remote(peer, chan, payload):
            offers = [{'fee': 3000, 'fee_range': (2500, 4000)}, 1800]
            return await self._scripted_shutdown(peer, chan, payload, offers=offers)
        with self.assertLogs('electrum', level='ERROR'):
            res = await self._test_shutdown_with_remote(
                remote_negotiation=remote, remote_is_funder=False, remote_closes=False)
        self._assert_negotiation_failed_with_remote(res, "There is no overlap between their and our fee range.")
        self.assertEqual([1000], res.our_fees)

    async def test_legacy_shutdown_with_our_real_fee_range(self):
        # as the tests above, but our fee and fee range are not set by the test: they come from the fee estimates
        for lnd_is_funder in [False, True]:
            with self.subTest(lnd_is_funder=lnd_is_funder):
                graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
                p_our = graph.peers[('bob', 'alice')] if lnd_is_funder else graph.peers[('alice', 'bob')]
                chan_our = graph.channels[('bob', 'alice')][0] if lnd_is_funder else graph.channels[('alice', 'bob')][0]
                _sig, dummy_tx = chan_our.make_closing_tx(bytes(22), bytes(22), fee_sat=0)
                our_fee, our_fee_range = p_our.get_shutdown_fee_range(chan_our, dummy_tx, True)
                min_fee, max_fee = our_fee_range['min_fee_satoshis'], our_fee_range['max_fee_satoshis']
                self.assertTrue(100 <= min_fee < our_fee < max_fee, (min_fee, our_fee, max_fee))
                # lnd wants 4 times our fee. if we are the funder, we pay our maximum at most.
                async def lnd_negotiation(peer, chan, payload, *, our_fee=our_fee):
                    return await self._lnd_legacy_shutdown(
                        peer, chan, payload, ideal_fee=4 * our_fee, max_fee=12 * our_fee)
                res = await self._test_shutdown_with_remote(
                    remote_negotiation=lnd_negotiation, remote_is_funder=lnd_is_funder, remote_closes=True,
                    graph=graph, our_fee_range=None)
                self._assert_coop_closed_with_remote(res, expected_fee=4 * our_fee if lnd_is_funder else max_fee)

    async def test_modern_shutdown_failures_do_not_force_close(self):
        """The remote sends a fee_range, but then breaks the rules of BOLT-02. In these cases the spec says
        we MUST fail the channel, or send a warning and close the connection. We do the latter.
        """
        for remote_is_funder, remote_closes, offers, reason in [
                # we are the funder: their fee is not in the overlap of the fee ranges
                (False, False, [{'fee': 3000, 'fee_range': (1500, 4000)}], "Their fee (3000 sat) is not in the overlap region."),
                (False, True, [{'fee': 3000, 'fee_range': (1500, 4000)}], "Their fee (3000 sat) is not in the overlap region."),
                # we are not the funder: we chose a fee from the overlap [500, 3000], but they do not repeat it
                (True, False, [{'fee': 1500, 'fee_range': (300, 3000)}, {'fee': 400, 'fee_range': (300, 3000)}],
                 "Expected the same fee as ours (1750 sat), but they sent 400 sat."),
                (True, True, [{'fee': 1500, 'fee_range': (300, 3000)}, {'fee': 400, 'fee_range': (300, 3000)}],
                 "Expected the same fee as ours (1750 sat), but they sent 400 sat."),
                # their signature is not valid, with or without a fee_range
                (False, False, [{'fee': 1500, 'fee_range': (500, 2000), 'bad_sig': True}], "failed to verify their signature"),
                (True, True, [{'fee': 1500, 'bad_sig': True}], "failed to verify their signature"),
        ]:
            with self.subTest(remote_is_funder=remote_is_funder, remote_closes=remote_closes, reason=reason):
                async def remote(peer, chan, payload, *, offers=offers):
                    return await self._scripted_shutdown(peer, chan, payload, offers=offers)
                with self.assertLogs('electrum', level='DEBUG'):
                    res = await self._test_shutdown_with_remote(
                        remote_negotiation=remote, remote_is_funder=remote_is_funder, remote_closes=remote_closes)
                self._assert_negotiation_failed_with_remote(res, reason)

    async def test_failed_closing_negotiation_if_warning_cannot_be_sent(self):
        # the transport is broken already: we still close the connection, and report the original problem
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1 = graph.peers[('alice', 'bob')]
        p1.send_warning = mock.Mock(side_effect=ConnectionResetError("transport is gone"))

        async def stubborn_remote(peer, chan, payload):
            return await self._scripted_shutdown(peer, chan, payload, offers=itertools.repeat(5000))
        with self.assertLogs('electrum', level='ERROR'):
            res = await self._test_shutdown_with_remote(
                remote_negotiation=stubborn_remote, remote_is_funder=False, remote_closes=False, graph=graph)
        self.assertIsInstance(res.exc, CoopCloseFailure)
        self.assertIn("not strictly between", str(res.exc))
        p1.send_warning.assert_called_once()
        self.assertEqual(['disconnect'], res.events)
        self._assert_not_closed_with_remote(res)

    async def test_unexpected_error_during_closing_negotiation(self):
        """If the negotiation ends with an exception that is not about the fee (here: the remote sends a message
        that makes no sense), we disconnect as well, so that both sides start over. We send no warning then.
        """
        async def remote(peer, chan, payload):
            peer.send_message('funding_signed', channel_id=chan.channel_id, signature=bytes(64))
            await asyncio.Event().wait()
        with self.assertLogs('electrum', level='ERROR'):
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
            p1 = graph.peers[('alice', 'bob')]
            alice_channel = graph.channels[('alice', 'bob')][0]
            with self.assertRaisesRegex(Exception, "Received unexpected 'funding_signed'"):
                await self._test_shutdown_with_remote(
                    remote_negotiation=remote, remote_is_funder=False, remote_closes=False, graph=graph)
        self.assertTrue(p1.got_disconnected.is_set())
        self.assertEqual(ChannelState.SHUTDOWN, alice_channel._state)
        self.assertEqual(0, graph.workers['alice'].network.tx_queue.qsize())

    async def test_concurrent_send_shutdown_sends_only_one_message(self):
        # after a reconnection, send_shutdown is called both by reestablish_channel and by on_shutdown.
        # both calls might have to wait until the remote has acked our pending changes.
        graph, num_sent = self._prepare_reconnect_in_shutdown_state()
        p1 = graph.peers[('alice', 'bob')]
        alice_channel = graph.channels[('alice', 'bob')][0]
        alice_channel.peer_state = PeerState.GOOD
        p1.initialized.set_result(True)
        pending = iter([True, True, True, True])
        with mock.patch.object(alice_channel, 'has_pending_changes', side_effect=lambda *args: next(pending, False)):
            await asyncio.gather(p1.send_shutdown(alice_channel), p1.send_shutdown(alice_channel))
        self.assertEqual(1, num_sent[(p1, 'shutdown')])

    async def test_shutdown_is_retransmitted_only_once_after_reestablish(self):
        """If we reconnect while the channel is in SHUTDOWN state, both sides retransmit 'shutdown',
        and the closing negotiation restarts. We MUST NOT send 'shutdown' a second time
        when the 'shutdown' of the remote arrives: e.g. lnd disconnects if we do.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000
        num_shutdown_sent = defaultdict(int)
        for peer in (p1, p2):
            def send_message(message_name, *, _peer=peer, _orig=peer.send_message, **kwargs):
                if message_name == 'shutdown':
                    num_shutdown_sent[_peer] += 1
                return _orig(message_name, **kwargs)
            peer.send_message = send_message
        # shutdown was exchanged, and then the connection was lost:
        for chan in (alice_channel, bob_channel):
            chan.set_state(ChannelState.SHUTDOWN)
            chan.peer_state = PeerState.DISCONNECTED

        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            async with util.async_timeout(5):
                while not (alice_channel.get_state() == bob_channel.get_state() == ChannelState.CLOSING):
                    await asyncio.sleep(0.01)
            raise SuccessfulTest()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await util.wait_for2(gath, 20)
        self.assertEqual({p1: 1, p2: 1}, dict(num_shutdown_sent))
        # the user asks for a cooperative close, on the same connection: nothing is sent,
        # the call reports the outcome of the negotiation that has already taken place
        closing_txid = w1.network.tx_queue.get_nowait().txid()
        self.assertEqual(closing_txid, await util.wait_for2(p1.close_channel(alice_channel.channel_id), 1))
        self.assertEqual({p1: 1, p2: 1}, dict(num_shutdown_sent))

    async def test_shutdown_with_pending_update_fee(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        w1.network.config.TEST_SHUTDOWN_FEE = w2.network.config.TEST_SHUTDOWN_FEE = 1000
        alice_channel = graph.channels[('alice', 'bob')][0]
        async def close():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            # update_fee without commitment_signed
            feerate = alice_channel.get_latest_feerate(LOCAL) + 1
            alice_channel.update_fee(feerate, True)
            p1.send_message("update_fee", channel_id=alice_channel.channel_id, feerate_per_kw=feerate)
            await util.wait_for2(p1.close_channel(alice_channel.channel_id), 5)
            raise SuccessfulTest()
        gath = asyncio.gather(close(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(SuccessfulTest):
            await gath

    async def test_warning(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]

        async def action():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            p1.send_warning(alice_channel.channel_id, 'be warned!', close_connection=True)
        gath = asyncio.gather(action(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(GracefulDisconnect):
            await gath

    async def test_error(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]

        async def action():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            p1.send_error(alice_channel.channel_id, 'some error happened!', force_close_channel=True)
            assert alice_channel.is_closed()
            gath.cancel()
        gath = asyncio.gather(action(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(GracefulDisconnect):
            await gath

    async def test_close_upfront_shutdown_script(self):
        alice_lnwallet, bob_lnwallet = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan']).values()
        alice_channel, bob_channel = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)

        # create upfront shutdown script for bob, alice doesn't use upfront
        # shutdown script
        bob_uss_pub = privkey_to_pubkey(os.urandom(32))
        bob_uss_addr = bitcoin.pubkey_to_address('p2wpkh', bob_uss_pub.hex())
        bob_uss = bitcoin.address_to_script(bob_uss_addr)

        # bob commits to close to bob_uss
        alice_channel.config[HTLCOwner.REMOTE].upfront_shutdown_script = bob_uss
        # but bob closes to some receiving address, which we achieve by not
        # setting the upfront shutdown script in the channel config
        bob_channel.config[HTLCOwner.LOCAL].upfront_shutdown_script = b''

        p1, p2, w1, w2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.FEE_POLICY = 'feerate:5000'
        w2.network.config.FEE_POLICY = 'feerate:1000'

        async def test():
            async def close():
                await util.wait_for2(p1.initialized, 1)
                await util.wait_for2(p2.initialized, 1)
                # bob closes channel with different shutdown script
                await p1.close_channel(alice_channel.channel_id)
                self.fail("p1.close_channel should have raised above!")

            async def main_loop(peer):
                    async with peer.taskgroup as group:
                        await group.spawn(peer._message_loop())
                        await group.spawn(peer.htlc_switch())

            coros = [close(), main_loop(p1), main_loop(p2)]
            gath = asyncio.gather(*coros)
            await gath

        with self.assertRaises(GracefulDisconnect):
            await test()
        # check that neither party broadcast a closing tx (as it was not even signed)
        self.assertEqual(0, w1.network.tx_queue.qsize())
        self.assertEqual(0, w2.network.tx_queue.qsize())

        # -- new scenario:
        # bob sends the same upfront_shutdown_script has he announced
        alice_channel.config[HTLCOwner.REMOTE].upfront_shutdown_script = bob_uss
        bob_channel.config[HTLCOwner.LOCAL].upfront_shutdown_script = bob_uss

        p1, p2, w1, w2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.FEE_POLICY = 'feerate:5000'
        w2.network.config.FEE_POLICY = 'feerate:1000'

        async def test():
            async def close():
                await util.wait_for2(p1.initialized, 1)
                await util.wait_for2(p2.initialized, 1)
                await p1.close_channel(alice_channel.channel_id)
                gath.cancel()

            async def main_loop(peer):
                async with peer.taskgroup as group:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())

            coros = [close(), main_loop(p1), main_loop(p2)]
            gath = asyncio.gather(*coros)
            await gath

        with self.assertRaises(asyncio.CancelledError):
            await test()

        # check if p1 has broadcast the closing tx, and if it pays to Bob's uss
        self.assertEqual(1, w1.network.tx_queue.qsize())
        closing_tx = w1.network.tx_queue.get_nowait()  # type: Transaction
        self.assertEqual(2, len(closing_tx.outputs()))
        self.assertEqual(1, len(closing_tx.get_output_idxs_from_address(bob_uss_addr)))

    async def test_channel_usage_after_closing(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel = graph.channels[('alice', 'bob')][0]
        bob_channel = graph.channels[('bob', 'alice')][0]
        lnaddr, pay_req = self.prepare_invoice(w2)

        lnaddr = w1._check_bolt11_invoice(pay_req.lightning_invoice)
        shi = (await w1.create_routes_from_invoice(lnaddr.get_amount_msat(), decoded_invoice=lnaddr))[0][0]
        route, amount_msat = shi.route, shi.amount_msat
        assert amount_msat == lnaddr.get_amount_msat()

        await w1.force_close_channel(alice_channel.channel_id)
        # check if a tx (commitment transaction) was broadcasted:
        assert w1.network.tx_queue.qsize() == 1

        with self.assertRaises(NoPathFound) as e:
            await w1.create_routes_from_invoice(lnaddr.get_amount_msat(), decoded_invoice=lnaddr)

        peer = w1.lnpeermgr._peers[route[0].node_id]
        # AssertionError is ok since we shouldn't use old routes, and the
        # route finding should fail when channel is closed
        async def f():
            shi = SentHtlcInfo(
                route=route,
                payment_secret_orig=lnaddr.payment_secret,
                payment_secret_bucket=lnaddr.payment_secret,
                amount_msat=amount_msat,
                bucket_msat=amount_msat,
                amount_receiver_msat=amount_msat,
                trampoline_fee_level=None,
                trampoline_route=None,
            )
            paysession = w1._paysessions[lnaddr.paymenthash + lnaddr.payment_secret]
            pay = w1.pay_to_route(
                sent_htlc_info=shi,
                paysession=paysession,
                min_final_cltv_delta=lnaddr.get_min_final_cltv_delta(),
            )
            await asyncio.gather(pay, p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(PaymentFailure):
            await f()

    async def test_sending_weird_messages_that_should_be_ignored(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()

        async def send_weird_messages():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            # peer1 sends known message with trailing garbage
            # BOLT-01 says peer2 should ignore trailing garbage
            raw_msg1 = encode_msg('ping', num_pong_bytes=4, byteslen=4) + bytes(range(55))
            p1.transport.send_bytes(raw_msg1)
            await asyncio.sleep(0.05)
            # peer1 sends unknown 'odd-type' message
            # BOLT-01 says peer2 should ignore whole message
            raw_msg2 = (43333).to_bytes(length=2, byteorder="big") + bytes(range(55))
            p1.transport.send_bytes(raw_msg2)
            await asyncio.sleep(0.05)
            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                for peer in [p1, p2]:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in [p1, p2]:
                    await peer.initialized
                await group.spawn(send_weird_messages())

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_sending_weird_messages__unknown_even_type(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()

        async def send_weird_messages():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            # peer1 sends unknown 'even-type' message
            # BOLT-01 says peer2 should close the connection
            raw_msg2 = (43334).to_bytes(length=2, byteorder="big") + bytes(range(55))
            p1.transport.send_bytes(raw_msg2)
            await asyncio.sleep(0.05)

        failing_task = None
        async def f():
            nonlocal failing_task
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                failing_task = await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                for peer in [p1, p2]:
                    await peer.initialized
                await group.spawn(send_weird_messages())

        with self.assertRaises(GracefulDisconnect):
            await f()
        self.assertTrue(isinstance(failing_task.exception().__cause__, lnmsg.UnknownMandatoryMsgType))

    async def test_sending_weird_messages__known_msg_with_insufficient_length(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()

        async def send_weird_messages():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            # peer1 sends known message with insufficient length for the contents
            # BOLT-01 says peer2 should fail the connection
            raw_msg1 = encode_msg('ping', num_pong_bytes=4, byteslen=4)[:-1]
            p1.transport.send_bytes(raw_msg1)
            await asyncio.sleep(0.05)

        failing_task = None
        async def f():
            nonlocal failing_task
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                failing_task = await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                for peer in [p1, p2]:
                    await peer.initialized
                await group.spawn(send_weird_messages())

        with self.assertRaises(GracefulDisconnect):
            await f()
        self.assertTrue(isinstance(failing_task.exception().__cause__, lnmsg.UnexpectedEndOfStream))

    async def test_hold_invoice_set_doesnt_get_expired(self):
        """
        Alice pays a hold invoice from Bob, Bob doesn't release preimage. Verify that Bob doesn't
        expire the htlc set MIN_FINAL_CLTV_DELTA_ACCEPTED blocks before htlc.cltv_abs (as we would do with normal htlc sets).
        The htlc set should only get failed if the user of the hold invoice callback explicitly removes the
        callback (e.g. after refunding and failing a swap), otherwise it should get timed out onchain (force-close).

        This only tests hold invoice logic for hold invoices registered with `LNWallet.register_hold_invoice()`,
        as used e.g. by submarine swaps. It doesn't cover the hold invoices created by the hold invoice CLI
        which behave differently and use the persisted `LNWallet.dont_expire_htlcs` dict.
        """
        async def run_test(test_trampoline):
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
            alice_p, bob_p = graph.peers.values()
            alice_w, bob_w = graph.workers.values()

            lnaddr, pay_req = self.prepare_invoice(bob_w, min_final_cltv_delta=150)
            del bob_w._preimages[pay_req.rhash]  # del preimage so bob doesn't settle
            payment_key = bob_w._get_payment_key(lnaddr.paymenthash).hex()

            cb_got_called = asyncio.Event()
            async def cb(_payment_hash):
                self.logger.debug(f"hold invoice callback called. {bob_w.network.get_local_height()=}")
                cb_got_called.set()

            bob_w.register_hold_invoice(lnaddr.paymenthash, cb)

            async def check_mpp_state():
                await util.wait_for2(cb_got_called.wait(), timeout=2)
                mpp_set = bob_w.received_mpp_htlcs[payment_key]
                self.assertEqual(mpp_set.resolution, RecvMPPResolution.SETTLING, msg=mpp_set.resolution)
                self.assertEqual(len(mpp_set.htlcs), 1, f"should get only one htlc: {mpp_set.htlcs=}")
                left_to_expiry = next(iter(mpp_set.htlcs)).htlc.cltv_abs - bob_w.network.get_local_height()
                # now mine up to one block after the expiry
                bob_w.network._blockchain._height += left_to_expiry + 1
                await asyncio.sleep(0.2)
                # bob still has the mpp set and it is not failed
                # it should only get removed once the channel is redeemed
                self.assertIn(bob_w.received_mpp_htlcs[payment_key].resolution, (RecvMPPResolution.COMPLETE, RecvMPPResolution.SETTLING))
                # now also check that the mpp set will get set failed if the hold invoice
                # is being explicitly unregistered, and we don't have a preimage to settle it
                bob_w.unregister_hold_invoice(lnaddr.paymenthash)
                self.assertEqual(bob_w.received_mpp_htlcs[payment_key].resolution, RecvMPPResolution.FAILED)
                raise SuccessfulTest()

            if test_trampoline:
                await self._activate_trampoline(alice_w)
                # declare bob as trampoline node
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=bob_w.node_keypair.pubkey),
                }

            async def f():
                async with OldTaskGroup() as group:
                    await group.spawn(alice_p._message_loop())
                    await group.spawn(alice_p.htlc_switch())
                    await group.spawn(bob_p._message_loop())
                    await group.spawn(bob_p.htlc_switch())
                    await asyncio.sleep(0.01)
                    await group.spawn(alice_w.pay_invoice(pay_req))
                    await group.spawn(check_mpp_state())

            with self.assertRaises(SuccessfulTest):
                await f()

        for _test_trampoline in [False, True]:
            await run_test(_test_trampoline)

    async def test_htlc_switch_iteration_benchmark(self):
        """Test how long a call to _run_htlc_switch_iteration takes with 10 trampoline
        mpp sets of 1 htlc each. Raise if it takes longer than 20ms (median).
        To create flamegraph with py-spy raise NUM_ITERATIONS to 1000 (for more samples) then run:
        $ py-spy record -o flamegraph.svg --subprocesses -- python -m pytest tests/test_lnpeer.py::TestPeerDirect::test_htlc_switch_iteration_benchmark
        """
        NUM_ITERATIONS = 25
        alice_lnwallet, bob_lnwallet = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan']).values()
        alice_channel, bob_channel = create_test_channels(
            alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet, max_accepted_htlcs=20,
        )
        alice_p, bob_p, alice_w, bob_w = self.prepare_peers(alice_channel, bob_channel)

        await self._activate_trampoline(alice_w)
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=bob_w.node_keypair.pubkey),
        }

        # create 10 invoices (10 pending htlc sets with 1 htlc each)
        invoices = []  # type: list[tuple[BOLT11Addr, Invoice]]
        for i in range(10):
            lnaddr, pay_req = self.prepare_invoice(bob_w)
            # prevent bob from settling so that htlc switch will have to iterate through all pending htlcs
            bob_w.dont_settle_htlcs[pay_req.rhash] = None
            invoices.append((lnaddr, pay_req))
        self.assertEqual(len(invoices), 10, msg=len(invoices))

        iterations = []
        do_benchmark = False
        _run_bob_htlc_switch_iteration = bob_p._run_htlc_switch_iteration
        def timed_htlc_switch_iteration():
            start = time.perf_counter()
            _run_bob_htlc_switch_iteration()
            duration = time.perf_counter() - start
            if do_benchmark:
                iterations.append(duration)
        bob_p._run_htlc_switch_iteration = timed_htlc_switch_iteration

        async def benchmark_htlc_switch_iterations():
            waited = 0
            while not len(bob_w.received_mpp_htlcs) == 10 :
                waited += 0.1
                await asyncio.sleep(0.1)
                if waited > 2:
                    raise TimeoutError()
            nonlocal do_benchmark
            do_benchmark = True
            while len(iterations) < NUM_ITERATIONS:
                await asyncio.sleep(0.05)
            # average = sum(iterations) / len(iterations)
            median_duration = statistics.median(iterations)
            res = f"median duration per htlc switch iteration: {median_duration:.6f}s over {len(iterations)=}"
            self.logger.info(res)
            self.assertLess(median_duration, 0.02, msg=res)
            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                await group.spawn(alice_p._message_loop())
                await group.spawn(alice_p.htlc_switch())
                await group.spawn(bob_p._message_loop())
                await group.spawn(bob_p.htlc_switch())
                await asyncio.sleep(0.01)
                for _lnaddr, req in invoices:
                    await group.spawn(alice_w.pay_invoice(req))
                await benchmark_htlc_switch_iterations()

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_dont_expire_htlcs(self):
        """
        Test that htlcs registered in LNWallet.dont_expire_htlcs don't get expired before the
        specified expiry delta if their preimage isn't available.
        Also test that htlcs registered in LNWallet.dont_expire_htlcs get settled right away if their
        preimage is available.
        """
        async def run_test(test_trampoline, test_expiry):
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
            p1, p2 = graph.peers.values()
            w1, w2 = graph.workers.values()
            if test_trampoline:
                await self._activate_trampoline(w1)
                # declare bob as trampoline node
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=w2.node_keypair.pubkey),
                }

            preimage = os.urandom(32)
            lnaddr, pay_req = self.prepare_invoice(w2, payment_preimage=preimage, min_final_cltv_delta=144)

            # delete preimage, this would fail the htlcs if payment_hash wasn't in dont_expire_htlcs
            del w2._preimages[pay_req.rhash]
            # add payment_hash to dont_expire_htlcs so the htlcs are not getting failed
            w2.dont_expire_htlcs[pay_req.rhash] = None if not test_expiry else 20

            async def pay(lnaddr, pay_req):
                self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
                result, log = await util.wait_for2(w1.pay_invoice(pay_req), timeout=3)
                if result is True:
                    self.assertEqual(PR_PAID, w2.get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
                    return PaymentDone()
                else:
                    self.assertIsNone(w2.get_preimage(lnaddr.paymenthash))
                    return PaymentFailure()

            async def wait_for_htlcs():
                payment_key = w2._get_payment_key(lnaddr.paymenthash)
                while payment_key.hex() not in w2.received_mpp_htlcs:
                    await asyncio.sleep(0.05)
                if not test_expiry:
                    # the htlcs should never get expired if the dont_expire_htlcs value is None
                    w2.network.blockchain()._height += 1000
                await asyncio.sleep(0.25)  # give w2 some time to do mistakes
                self.assertEqual(w2.received_mpp_htlcs[payment_key.hex()].resolution, RecvMPPResolution.COMPLETE)
                if test_expiry:
                    # we set an expiry delta of 20 blocks before expiry, htlc expiry should be +144 current height
                    # so adding some blocks should get the htlcs failed
                    w2.network.blockchain()._height += 50
                    await asyncio.sleep(0.1)
                    # the htlcs should not get failed yet as 144-50 > 20
                    self.assertEqual(w2.received_mpp_htlcs[payment_key.hex()].resolution, RecvMPPResolution.COMPLETE)
                    w2.network.blockchain()._height += 75
                    return  # the htlcs should get failed and pay should return PaymentFailure

                # saving the preimage should let the htlcs get fulfilled
                w2.save_preimage(lnaddr.paymenthash, preimage)

            async def f():
                async with OldTaskGroup() as group:
                    await group.spawn(p1._message_loop())
                    await group.spawn(p1.htlc_switch())
                    await group.spawn(p2._message_loop())
                    await group.spawn(p2.htlc_switch())
                    await asyncio.sleep(0.01)
                    invoice_features = lnaddr.get_features()
                    self.assertFalse(invoice_features.supports(LnFeatures.BASIC_MPP_OPT))
                    pay_task = await group.spawn(pay(lnaddr, pay_req))
                    await util.wait_for2(wait_for_htlcs(), timeout=3)
                    raise await pay_task

            await f()

        for test_trampoline in [False, True]:
            for test_expiry in [False, True]:
                with self.assertRaises(PaymentFailure if test_expiry else PaymentDone):
                    await run_test(test_trampoline, test_expiry )


class TestPeerForwarding(TestPeer):

    async def test_payment_in_graph_with_direct_channel(self):
        """Test payment over a direct channel where sender has multiple available channels."""
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['line_graph'])
        peers = graph.peers.values()
        # use same MPP_SPLIT_PART_FRACTION as in regular LNWallet
        graph.workers['bob'].MPP_SPLIT_PART_FRACTION = LNWallet.MPP_SPLIT_PART_FRACTION

        # mock split_amount_normal so it's possible to test both cases, the amount getting sorted
        # out because one part is below the min size and the other case of both parts being just
        # above the min size, so no part is getting sorted out
        def mocked_split_amount_normal(total_amount: int, num_parts: int) -> List[int]:
            if num_parts == 2 and total_amount == 21_000_000:  # test amount 21k sat
                # this will not get sorted out by suggest_splits
                return [10_500_000, 10_500_000]
            elif num_parts == 2 and total_amount == 21_000_001:  # 2nd test case
                # this will get sorted out by suggest_splits
                return [11_000_002, 9_999_999]
            else:
                return split_amount_normal(total_amount, num_parts)

        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['alice'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            with mock.patch('electrum.mpp_split.split_amount_normal',
                                side_effect=mocked_split_amount_normal):
                result, log = await graph.workers['bob'].pay_invoice(pay_req)
            self.assertTrue(result)
            self.assertEqual(PR_PAID, graph.workers['alice'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))

        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                for test in [21_000_000, 21_000_001]:
                    lnaddr, pay_req = self.prepare_invoice(
                        graph.workers['alice'],
                        amount_msat=test,
                        include_routing_hints=True,
                        invoice_features=LnFeatures.BASIC_MPP_OPT
                                         | LnFeatures.PAYMENT_SECRET_REQ
                                         | LnFeatures.VAR_ONION_REQ
                    )
                    await pay(lnaddr, pay_req)
                raise PaymentDone()
        with self.assertRaises(PaymentDone):
            await f()

    async def test_payment_multihop(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        peers = graph.peers.values()
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            result, log = await graph.workers['alice'].pay_invoice(pay_req)
            self.assertTrue(result)
            self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            raise PaymentDone()
        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                lnaddr, pay_req = self.prepare_invoice(graph.workers['dave'], include_routing_hints=True)
                await group.spawn(pay(lnaddr, pay_req))
        with self.assertRaises(PaymentDone):
            await f()

    async def test_payment_multihop_with_preselected_path(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        peers = graph.peers.values()
        async def pay(pay_req):
            with self.subTest(msg="bad path: edges do not chain together"):
                path = [PathEdge(start_node=graph.workers['alice'].node_keypair.pubkey,
                                 end_node=graph.workers['carol'].node_keypair.pubkey,
                                 short_channel_id=graph.channels[('alice', 'bob')][0].short_channel_id),
                        PathEdge(start_node=graph.workers['bob'].node_keypair.pubkey,
                                 end_node=graph.workers['dave'].node_keypair.pubkey,
                                 short_channel_id=graph.channels['bob', 'dave'][0].short_channel_id)]
                with self.assertRaises(LNPathInconsistent):
                    await graph.workers['alice'].pay_invoice(pay_req, full_path=path)
            with self.subTest(msg="bad path: last node id differs from invoice pubkey"):
                path = [PathEdge(start_node=graph.workers['alice'].node_keypair.pubkey,
                                 end_node=graph.workers['bob'].node_keypair.pubkey,
                                 short_channel_id=graph.channels[('alice', 'bob')][0].short_channel_id)]
                with self.assertRaises(LNPathInconsistent):
                    await graph.workers['alice'].pay_invoice(pay_req, full_path=path)
            with self.subTest(msg="good path"):
                path = [PathEdge(start_node=graph.workers['alice'].node_keypair.pubkey,
                                 end_node=graph.workers['bob'].node_keypair.pubkey,
                                 short_channel_id=graph.channels[('alice', 'bob')][0].short_channel_id),
                        PathEdge(start_node=graph.workers['bob'].node_keypair.pubkey,
                                 end_node=graph.workers['dave'].node_keypair.pubkey,
                                 short_channel_id=graph.channels['bob', 'dave'][0].short_channel_id)]
                result, log = await graph.workers['alice'].pay_invoice(pay_req, full_path=path)
                self.assertTrue(result)
                self.assertEqual(
                    [edge.short_channel_id for edge in path],
                    [edge.short_channel_id for edge in log[0].route])
            raise PaymentDone()
        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                lnaddr, pay_req = self.prepare_invoice(graph.workers['dave'], include_routing_hints=True)
                await group.spawn(pay(pay_req))
        with self.assertRaises(PaymentDone):
            await f()

    async def test_payment_multihop_temp_node_failure(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        graph.workers['bob'].network.config.TEST_FAIL_HTLCS_WITH_TEMP_NODE_FAILURE = True
        graph.workers['carol'].network.config.TEST_FAIL_HTLCS_WITH_TEMP_NODE_FAILURE = True
        peers = graph.peers.values()
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            result, log = await graph.workers['alice'].pay_invoice(pay_req)
            self.assertFalse(result)
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, log[0].failure_msg.code)
            raise PaymentDone()
        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                lnaddr, pay_req = self.prepare_invoice(graph.workers['dave'], include_routing_hints=True)
                await group.spawn(pay(lnaddr, pay_req))
        with self.assertRaises(PaymentDone):
            await f()

    async def test_payment_multihop_route_around_failure(self):
        # Alice will pay Dave. Alice first tries A->C->D route, due to lower fees, but Carol
        # will fail the htlc and get blacklisted. Alice will then try A->B->D and succeed.
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        graph.workers['carol'].network.config.TEST_FAIL_HTLCS_WITH_TEMP_NODE_FAILURE = True
        peers = graph.peers.values()
        async def pay(lnaddr, pay_req):
            self.assertEqual(500000000000, graph.channels[('alice', 'bob')][0].balance(LOCAL))
            self.assertEqual(500000000000, graph.channels[('dave', 'bob')][0].balance(LOCAL))
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            result, log = await graph.workers['alice'].pay_invoice(pay_req, attempts=2)
            self.assertEqual(2, len(log))
            self.assertTrue(result)
            self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            self.assertEqual([graph.channels[('alice', 'carol')][0].short_channel_id, graph.channels[('carol', 'dave')][0].short_channel_id],
                             [edge.short_channel_id for edge in log[0].route])
            self.assertEqual([graph.channels[('alice', 'bob')][0].short_channel_id, graph.channels[('bob', 'dave')][0].short_channel_id],
                             [edge.short_channel_id for edge in log[1].route])
            self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, log[0].failure_msg.code)
            self.assertEqual(499899450000, graph.channels[('alice', 'bob')][0].balance(LOCAL))
            await asyncio.sleep(0.2)  # wait for COMMITMENT_SIGNED / REVACK msgs to update balance
            self.assertEqual(500100000000, graph.channels[('dave', 'bob')][0].balance(LOCAL))
            raise PaymentDone()
        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                lnaddr, pay_req = self.prepare_invoice(graph.workers['dave'], include_routing_hints=True)
                invoice_features = lnaddr.get_features()
                self.assertFalse(invoice_features.supports(LnFeatures.BASIC_MPP_OPT))
                await group.spawn(pay(lnaddr, pay_req))
        with self.assertRaises(PaymentDone):
            await f()

    async def test_payment_with_temp_channel_failure_and_liquidity_hints(self):
        # prepare channels such that a temporary channel failure happens at c->d
        graph_definition = self.GRAPH_DEFINITIONS['square_graph']
        graph_definition['alice']['channels']['carol'][0]['local_balance_msat'] = 200_000_000
        graph_definition['alice']['channels']['carol'][0]['remote_balance_msat'] = 200_000_000
        graph_definition['carol']['channels']['dave'][0]['local_balance_msat'] = 50_000_000
        graph_definition['carol']['channels']['dave'][0]['remote_balance_msat'] = 200_000_000
        graph_definition['alice']['channels']['bob'][0]['local_balance_msat'] = 200_000_000
        graph_definition['alice']['channels']['bob'][0]['remote_balance_msat'] = 200_000_000
        graph_definition['bob']['channels']['dave'][0]['local_balance_msat'] = 200_000_000
        graph_definition['bob']['channels']['dave'][0]['remote_balance_msat'] = 200_000_000
        graph = self.prepare_chans_and_peers_in_graph(graph_definition)

        # the payment happens in two attempts:
        # 1. along a->c->d due to low fees with temp channel failure:
        #   with chanupd: ORPHANED, private channel update
        #   c->d gets a liquidity hint and gets blocked
        # 2. along a->b->d with success
        amount_to_pay = 100_000_000
        peers = graph.peers.values()
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            result, log = await graph.workers['alice'].pay_invoice(pay_req, attempts=3)
            self.assertTrue(result)
            self.assertEqual(2, len(log))
            self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            self.assertEqual(OnionFailureCode.TEMPORARY_CHANNEL_FAILURE, log[0].failure_msg.code)

            liquidity_hints = graph.workers['alice'].network.path_finder.liquidity_hints
            pubkey_a = graph.workers['alice'].node_keypair.pubkey
            pubkey_b = graph.workers['bob'].node_keypair.pubkey
            pubkey_c = graph.workers['carol'].node_keypair.pubkey
            pubkey_d = graph.workers['dave'].node_keypair.pubkey
            # check liquidity hints for failing route:
            hint_ac = liquidity_hints.get_hint(graph.channels[('alice', 'carol')][0].short_channel_id)
            hint_cd = liquidity_hints.get_hint(graph.channels[('carol', 'dave')][0].short_channel_id)
            self.assertEqual(amount_to_pay, hint_ac.can_send(pubkey_a < pubkey_c))
            self.assertEqual(None, hint_ac.cannot_send(pubkey_a < pubkey_c))
            self.assertEqual(None, hint_cd.can_send(pubkey_c < pubkey_d))
            self.assertEqual(amount_to_pay, hint_cd.cannot_send(pubkey_c < pubkey_d))
            # check liquidity hints for successful route:
            hint_ab = liquidity_hints.get_hint(graph.channels[('alice', 'bob')][0].short_channel_id)
            hint_bd = liquidity_hints.get_hint(graph.channels[('bob', 'dave')][0].short_channel_id)
            self.assertEqual(amount_to_pay, hint_ab.can_send(pubkey_a < pubkey_b))
            self.assertEqual(None, hint_ab.cannot_send(pubkey_a < pubkey_b))
            self.assertEqual(amount_to_pay, hint_bd.can_send(pubkey_b < pubkey_d))
            self.assertEqual(None, hint_bd.cannot_send(pubkey_b < pubkey_d))

            raise PaymentDone()
        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                lnaddr, pay_req = self.prepare_invoice(graph.workers['dave'], amount_msat=amount_to_pay, include_routing_hints=True)
                await group.spawn(pay(lnaddr, pay_req))
        with self.assertRaises(PaymentDone):
            await f()

    async def _assert_no_inflight_htlcs_in_liquidity_hints(self, w: MockLNWallet):
        # pay_invoice returns when the first htlc resolution is processed; the remaining
        # parts resolve later. only when all parts have resolved is the paysession removed.
        async def wait_for_paysessions_to_be_cleaned_up():
            while w._paysessions:
                await asyncio.sleep(0.01)
        await util.wait_for2(wait_for_paysessions_to_be_cleaned_up(), timeout=10)
        for hint in w.network.path_finder.liquidity_hints._liquidity_hints.values():
            self.assertEqual(0, hint.num_inflight_htlcs(True))
            self.assertEqual(0, hint.num_inflight_htlcs(False))

    def _assert_all_parts_reported_can_send(self, w: MockLNWallet):
        # every part of the mpp resolved successfully, so every edge an htlc was
        # sent over should have received a can_send report for its direction of use
        for hint in w.network.path_finder.liquidity_hints._liquidity_hints.values():
            self.assertTrue(hint.can_send(True) is not None or hint.can_send(False) is not None)

    async def _run_mpp(self, graph, kwargs):
        """Tests a multipart payment scenario for failing and successful cases."""
        self.assertEqual(500_000_000_000, graph.channels[('alice', 'bob')][0].balance(LOCAL))
        self.assertEqual(500_000_000_000, graph.channels[('alice', 'carol')][0].balance(LOCAL))
        amount_to_pay = 600_000_000_000
        peers = graph.peers.values()
        async def pay(
                attempts=1,
                alice_uses_trampoline=False,
                bob_forwarding=True,
                mpp_invoice=True,
                disable_trampoline_receiving=False,
                test_hold_invoice=False,
                test_failure=False,
        ):
            alice_w = graph.workers['alice']
            bob_w = graph.workers['bob']
            carol_w = graph.workers['carol']
            dave_w = graph.workers['dave']
            if mpp_invoice:
                dave_w.features |= LnFeatures.BASIC_MPP_OPT
            if disable_trampoline_receiving:
                dave_w.features &= ~LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM
            if not bob_forwarding:
                bob_w.enable_htlc_forwarding = False
            if alice_uses_trampoline:
                await self._activate_trampoline(alice_w)
            else:
                assert alice_w.network.channel_db is not None
            lnaddr, pay_req = self.prepare_invoice(dave_w, include_routing_hints=True, amount_msat=amount_to_pay)
            self.prepare_recipient(dave_w, lnaddr.paymenthash, test_hold_invoice, test_failure)
            self.assertEqual(PR_UNPAID, dave_w.get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            result, log = await alice_w.pay_invoice(pay_req, attempts=attempts)
            if not bob_forwarding:
                # reset to previous state, sleep 2s so that the second htlc can time out
                graph.workers['bob'].enable_htlc_forwarding = True
                await asyncio.sleep(2)
            if result:
                self.assertEqual(PR_PAID, dave_w.get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
                # check mpp is cleaned up
                async with OldTaskGroup() as g:
                    for peer in peers:
                        await g.spawn(peer.wait_one_htlc_switch_iteration())
                # wait another iteration
                async with OldTaskGroup() as g:
                    for peer in peers:
                        await g.spawn(peer.wait_one_htlc_switch_iteration())
                for peer in peers:
                    self.assertEqual(len(peer.lnworker.received_mpp_htlcs), 0)
                await self._assert_no_inflight_htlcs_in_liquidity_hints(alice_w)
                self._assert_all_parts_reported_can_send(alice_w)
                raise PaymentDone()
            elif len(log) == 1 and log[0].failure_msg.code == OnionFailureCode.MPP_TIMEOUT:
                await self._assert_no_inflight_htlcs_in_liquidity_hints(alice_w)
                raise PaymentTimeout()
            else:
                raise NoPathFound()

        async with OldTaskGroup() as group:
            for peer in peers:
                await group.spawn(peer._message_loop())
                await group.spawn(peer.htlc_switch())
            for peer in peers:
                await peer.initialized
            await group.spawn(pay(**kwargs))

    async def test_payment_multipart(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        with self.assertRaises(PaymentDone):
            await self._run_mpp(graph, {})

    async def test_payment_multipart_with_hold_invoice(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        with self.assertRaises(PaymentDone):
            await self._run_mpp(graph, {'test_hold_invoice': True})

    async def test_payment_multipart_with_timeout(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        with self.assertRaises(PaymentTimeout):
            await self._run_mpp(graph, {'bob_forwarding': False})

    async def test_payment_multipart_wrong_invoice(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        with self.assertRaises(NoPathFound):
            await self._run_mpp(graph, {'mpp_invoice': False})

    async def test_payment_multipart_fee_budget(self):
        """The fee budget must be shared between the parts of an MPP payment: each part
        is checked with its part amount against its share of the budget, so that the
        aggregate fee over all parts cannot exceed the budget."""
        graph_def = self.GRAPH_DEFINITIONS['square_graph']
        # use base-fee-dominated routing fees, so each part pays the full base fee
        # and the aggregate fee doubles when the payment is split into two parts
        base_fee_msat = 1_000_000
        for node in ('bob', 'carol'):
            graph_def[node]['channels']['dave'][0].update({'local_base_fee_msat': base_fee_msat, 'local_fee_rate_millionths': 0})
        graph = self.prepare_chans_and_peers_in_graph(graph_def)
        amount_to_pay = 600_000_000_000  # exceeds single channel capacity
        alice_w, dave_w = graph.workers['alice'], graph.workers['dave']
        dave_w.features |= LnFeatures.BASIC_MPP_OPT
        self.assertFalse(alice_w.uses_trampoline())
        peers = graph.peers.values()
        async def pay(fee_budget_msat: int) -> bool:
            lnaddr, pay_req = self.prepare_invoice(dave_w, include_routing_hints=True, amount_msat=amount_to_pay)
            budget = PaymentFeeBudget.from_invoice_amount(invoice_amount_msat=amount_to_pay, config=alice_w.config, max_fee_msat=fee_budget_msat)
            result, log = await alice_w.pay_invoice(pay_req, attempts=1, budget=budget)
            return result
        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                # a budget covering one part's base fee but not both must fail the payment
                self.assertFalse(await pay(fee_budget_msat=base_fee_msat * 3 // 2))
                # a budget covering the base fee of both parts must succeed
                self.assertTrue(await pay(fee_budget_msat=base_fee_msat * 2))
                raise PaymentDone()
        with self.assertRaises(PaymentDone):
            await f()

    async def test_payment_multipart_trampoline_e2e(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
            graph.workers['carol'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['carol'].node_keypair.pubkey),
        }
        graph.workers['alice'].config.INITIAL_TRAMPOLINE_FEE_LEVEL = 6  # set high so the first attempt would succeed
        with self.assertRaises(PaymentDone):
            await self._run_mpp(graph,{'alice_uses_trampoline': True, 'attempts': 1})

    async def test_payment_multipart_trampoline_legacy(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
            graph.workers['carol'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['carol'].node_keypair.pubkey),
        }
        # trampoline-to-legacy: this is restricted, as there are no forwarders capable of doing this
        with self.assertRaises(NoPathFound):
            await self._run_mpp(graph, {'alice_uses_trampoline': True, 'attempts': 30, 'disable_trampoline_receiving': True})

    async def test_fail_pending_htlcs_on_shutdown(self):
        """Alice tries to pay Dave via MPP. Dave receives some HTLCs but not all.
        Dave shuts down (stops wallet).
        We test if Dave fails the pending HTLCs during shutdown.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        self.assertEqual(500_000_000_000, graph.channels[('alice', 'bob')][0].balance(LOCAL))
        self.assertEqual(500_000_000_000, graph.channels[('alice', 'carol')][0].balance(LOCAL))
        amount_to_pay = 600_000_000_000
        peers = graph.peers.values()
        graph.workers['dave'].MPP_EXPIRY = 120
        graph.workers['dave'].TIMEOUT_SHUTDOWN_FAIL_PENDING_HTLCS = 3
        async def pay():
            graph.workers['dave'].features |= LnFeatures.BASIC_MPP_OPT
            graph.workers['bob'].enable_htlc_forwarding = False  # Bob will hold forwarded HTLCs
            assert graph.workers['alice'].network.channel_db is not None
            lnaddr, pay_req = self.prepare_invoice(graph.workers['dave'], include_routing_hints=True, amount_msat=amount_to_pay)
            result, log = await graph.workers['alice'].pay_invoice(pay_req, attempts=1)
        async def stop():
            hm = graph.channels[('dave', 'carol')][0].hm
            while len(hm.htlcs(LOCAL)) == 0 or len(hm.htlcs(REMOTE)) == 0:
                await asyncio.sleep(0.1)
            self.assertTrue(len(hm.htlcs(LOCAL)) > 0)
            self.assertTrue(len(hm.htlcs(REMOTE)) > 0)
            await graph.workers['dave'].stop()
            # Dave is supposed to have failed the pending incomplete MPP HTLCs
            self.assertEqual(0, len(hm.htlcs(LOCAL)))
            self.assertEqual(0, len(hm.htlcs(REMOTE)))
            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                await group.spawn(pay())
                await group.spawn(stop())

        with self.assertRaises(SuccessfulTest):
            await f()

    async def _run_trampoline_payment(
            self, graph: 'Graph', *,
            include_routing_hints=True,
            test_hold_invoice=False,
            test_failure=False,
            attempts=2,
            sender_name="alice",
            destination_name="dave",
            trampoline_forwarders=("bob", "carol"),
            trampoline_users=(), # sender is also a trampoline user
    ):

        sender_w = graph.workers[sender_name]
        dest_w = graph.workers[destination_name]

        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, dest_w.get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            result, log = await sender_w.pay_invoice(pay_req, attempts=attempts)
            async with OldTaskGroup() as g:
                for peer in peers:
                    await g.spawn(peer.wait_one_htlc_switch_iteration())
            async with OldTaskGroup() as g:
                for peer in peers:
                    await g.spawn(peer.wait_one_htlc_switch_iteration())
            for peer in peers:
                self.assertEqual(len(peer.lnworker.active_forwardings), 0)
            if result:
                self.assertEqual(PR_PAID, dest_w.get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
                raise PaymentDone()
            else:
                raise NoPathFound()

        async def f():
            await self._activate_trampoline(sender_w)
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                lnaddr, pay_req = self.prepare_invoice(dest_w, include_routing_hints=include_routing_hints)
                self.prepare_recipient(dest_w, lnaddr.paymenthash, test_hold_invoice, test_failure)
                await group.spawn(pay(lnaddr, pay_req))

        peers = graph.peers.values()

        # declare routing nodes as trampoline nodes
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {}
        for name in trampoline_forwarders:
            user_w = graph.workers[name]
            user_w.config.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS = True
            peer_addr = LNPeerAddr(host="127.0.0.1", port=9735, pubkey=user_w.node_keypair.pubkey)
            electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS[user_w.name] = peer_addr

        for user in trampoline_users:
            user_w = graph.workers[user]
            await self._activate_trampoline(user_w)
            assert user_w.uses_trampoline()

        await f()

    def create_square_graph(self, *, direct=False, test_mpp_consolidation=False, is_legacy=False):
        graph_definition = self.GRAPH_DEFINITIONS['square_graph']
        if not direct:
            # deplete channel from alice to carol and from bob to dave
            graph_definition['alice']['channels']['carol'] = [depleted_channel]
            graph_definition['bob']['channels']['dave'] = [depleted_channel]
            # insert a channel from bob to carol
            graph_definition['bob']['channels']['carol'] = [low_fee_channel]
            # now the only route possible is alice -> bob -> carol -> dave
        if test_mpp_consolidation:
            # deplete alice to carol so that all htlcs go through bob
            graph_definition['alice']['channels']['carol'] = [depleted_channel]
        graph = self.prepare_chans_and_peers_in_graph(graph_definition)
        if test_mpp_consolidation:
            graph.workers['dave'].features |= LnFeatures.BASIC_MPP_OPT
            graph.workers['alice'].network.config.TEST_FORCE_MPP = True # trampoline must wait until all incoming htlcs are received before sending outgoing htlcs
            graph.workers['bob'].network.config.TEST_FORCE_MPP = True   # trampoline must wait until all outgoing htlcs have failed before failing incoming htlcs
        if is_legacy:
            # turn off trampoline features in invoice
            graph.workers['dave'].features = graph.workers['dave'].features ^ LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM
        return graph

    async def test_trampoline_mpp_consolidation(self):
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=False, test_mpp_consolidation=True, is_legacy=True)
            await self._run_trampoline_payment(graph)

    async def test_trampoline_mpp_consolidation_forwarding_amount(self):
        """sanity check that bob is forwarding less than he is receiving"""
        # alice->bob->carol->dave
        graph = self.create_square_graph(direct=False, test_mpp_consolidation=True, is_legacy=True)
        # bump alices trampoline fee level so the first payment succeeds and the htlc sums can be compared usefully below.
        alice = graph.workers['alice']
        alice.config.INITIAL_TRAMPOLINE_FEE_LEVEL = 6
        with self.assertRaises(PaymentDone):
            await self._run_trampoline_payment(graph, attempts=1)

        # assert bob hasn't forwarded more than he received
        bob_alice_channel = graph.channels[('bob', 'alice')][0]
        htlcs_bob_received_from_alice = bob_alice_channel.hm.all_htlcs_ever()
        bob_carol_channel = graph.channels[('bob', 'carol')][0]
        htlcs_bob_sent_to_carol = bob_carol_channel.hm.all_htlcs_ever()
        sum_bob_received = sum(htlc.amount_msat for (direction, htlc) in htlcs_bob_received_from_alice)
        sum_bob_sent = sum(htlc.amount_msat for (direction, htlc) in htlcs_bob_sent_to_carol)
        assert sum_bob_sent < sum_bob_received, f"{sum_bob_sent=} > {sum_bob_received=}"

    async def test_trampoline_mpp_consolidation_with_hold_invoice(self):
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=False, test_mpp_consolidation=True, is_legacy=True)
            await self._run_trampoline_payment(graph, test_hold_invoice=True)

    async def test_trampoline_mpp_consolidation_with_hold_invoice_failure(self):
        with self.assertRaises(NoPathFound):
            graph = self.create_square_graph(direct=False, test_mpp_consolidation=True, is_legacy=True)
            await self._run_trampoline_payment(graph, test_hold_invoice=True, test_failure=True)

    async def test_payment_trampoline_legacy(self):
        # alice -> T1_bob -> carol -> dave
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=False, is_legacy=True)
            await self._run_trampoline_payment(graph, include_routing_hints=True)
        with self.assertRaises(NoPathFound):
            graph = self.create_square_graph(direct=False, is_legacy=True)
            await self._run_trampoline_payment(graph, include_routing_hints=False)

    async def test_payment_trampoline_e2e_alice_t1_dave(self):
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=True, is_legacy=False)
            graph.workers['alice'].config.INITIAL_TRAMPOLINE_FEE_LEVEL = 6  # set high so the first attempt would succeed
            await self._run_trampoline_payment(graph)

    async def test_payment_trampoline_e2e_alice_t1_t2_dave(self):
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=False, is_legacy=False)
            await self._run_trampoline_payment(graph)

    async def test_payment_trampoline_e2e_alice_t1_carol_t2_edward(self):
        # alice -> T1_bob -> carol -> T2_dave -> edward
        graph_definition = self.GRAPH_DEFINITIONS['line_graph']
        graph = self.prepare_chans_and_peers_in_graph(graph_definition)
        inject_chan_into_gossipdb(
            channel_db=graph.workers['bob'].channel_db,
            chanAB=graph.channels[('carol', 'dave')][0],
            chanBA=graph.channels[('dave', 'carol')][0],
        )
        # end-to-end trampoline: we attempt
        # * a payment with one trial: fails, because initial fees are too low
        # * a payment with several trials: should succeed
        with self.assertRaises(NoPathFound):
            await self._run_trampoline_payment(
                graph, sender_name='alice',
                destination_name='edward',
                trampoline_forwarders=('bob', 'dave'),
                attempts=1,
            )
        with self.assertRaises(PaymentDone):
            await self._run_trampoline_payment(
                graph, sender_name='alice',
                destination_name='edward',
                trampoline_forwarders=('bob', 'dave'),
                attempts=2,
            )

    async def _test_lazy_trampoline(self, is_legacy):
        # alice -> T1_bob -> T2_carol -> T3_dave -> edward
        # Bob is the lazy trampoline (no gossip)
        graph_definition = self.GRAPH_DEFINITIONS['line_graph']
        workers = self.prepare_lnwallets(graph_definition)
        # carol does not advertise trampoline, so bob does not hint her in subtest 1.
        # subtests 2 and 3 rely on the hardcoded list, where she is added as forwarder.
        workers['carol'].features &= ~LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM
        graph = self.prepare_chans_and_peers_in_graph(graph_definition, workers=workers)
        graph.workers['alice'].config.INITIAL_TRAMPOLINE_FEE_LEVEL = 6  # so that one attempt is enough
        if is_legacy:
            graph.workers['edward'].features = graph.workers['edward'].features ^ LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM

        # bob must not send back to alice: make channel private
        bob_alice_channel = graph.channels[('bob', 'alice')][0]
        self.assertTrue(bob_alice_channel.is_public())
        bob_alice_channel.constraints.flags = bob_alice_channel.constraints.flags ^ CF_ANNOUNCE_CHANNEL
        self.assertFalse(bob_alice_channel.is_public())

        with self.subTest(msg="carol is not a trampoline: two attempts fail"):
            with self.assertRaises(NoPathFound):
                await self._run_trampoline_payment(
                    graph, sender_name='alice',
                    destination_name='edward',
                    trampoline_forwarders=('bob', 'dave'),
                    trampoline_users=('alice', 'bob'),
                    attempts=2,
                )
        with self.subTest(msg="carol is a trampoline: one attempt fails"):
            with self.assertRaises(NoPathFound):
                await self._run_trampoline_payment(
                    graph, sender_name='alice',
                    destination_name='edward',
                    trampoline_forwarders=('bob', 'carol', 'dave'),
                    trampoline_users=('alice', 'bob'),
                    attempts=1,
                )
        with self.subTest(msg="carol is a trampoline: two attempts succeed"):
            with self.assertRaises(PaymentDone):
                await self._run_trampoline_payment(
                    graph, sender_name='alice',
                    destination_name='edward',
                    trampoline_forwarders=('bob', 'carol', 'dave'),
                    trampoline_users=('alice', 'bob'),
                    attempts=2,
                )
        with self.subTest(msg="carol is not a trampoline: bob forwards to her directly"):
            with self.assertRaises(PaymentDone):
                await self._run_trampoline_payment(
                    graph, sender_name='alice',
                    destination_name='carol',
                    trampoline_forwarders=('bob', 'dave'),
                    trampoline_users=('alice', 'bob'),
                    attempts=1,
                )

    async def test_lazy_trampoline_e2e(self):
        await self._test_lazy_trampoline(is_legacy=False)

    async def test_lazy_trampoline_legacy(self):
        await self._test_lazy_trampoline(is_legacy=True)

    async def test_trampoline_forward_mpp_over_private_direct_channels(self):
        # alice -> T1_bob -> carol
        # bob has two private channels with carol, none of them can carry the payment alone
        graph_definition = self.GRAPH_DEFINITIONS['line_graph']
        small_channel = low_fee_channel.copy()
        small_channel['local_balance_msat'] = int(100_000_000 * 0.75)
        graph_definition['bob']['channels']['carol'] = [small_channel, small_channel.copy()]
        del graph_definition['carol']['channels']['dave']  # else carol's invoice would only hint dave
        graph = self.prepare_chans_and_peers_in_graph(graph_definition)
        for chan in graph.channels[('bob', 'carol')]:
            chan.constraints.flags &= ~CF_ANNOUNCE_CHANNEL
        graph.workers['carol'].features |= LnFeatures.BASIC_MPP_OPT
        graph.workers['alice'].config.INITIAL_TRAMPOLINE_FEE_LEVEL = 6  # so that one attempt is enough
        with self.assertRaises(PaymentDone):
            await self._run_trampoline_payment(
                graph, destination_name='carol', trampoline_forwarders=('bob',), attempts=1)


    async def test_multi_trampoline_payment(self):
        """
        Alice splits her payment to Dave between two trampoline forwarding nodes Carol and Bob.
        This should test Multi-Trampoline MPP:
        https://github.com/lightning/bolts/blob/bc7a1a0bc97b2293e7f43dd8a06529e5fdcf7cd2/proposals/trampoline.md#multi-trampoline-mpp
        """
        graph_definition = self.GRAPH_DEFINITIONS['square_graph']
        # payment amount is 100_000_000 msat, size the channels so that alice must use both to succeed
        graph_definition['alice']['channels']['bob'][0]['local_balance_msat'] = int(100_000_000 * 0.75)
        graph_definition['alice']['channels']['carol'][0]['local_balance_msat'] = int(100_000_000 * 0.75)
        graph_definition['bob']['channels']['dave'] = [low_fee_channel]
        g = self.prepare_chans_and_peers_in_graph(graph_definition)
        w = g.workers['alice'], g.workers['carol'], g.workers['bob'], g.workers['dave']
        alice_w, carol_w, bob_w, dave_w = w

        alice_w.config.TEST_FORCE_MPP = True
        bob_w.config.TEST_FORCE_MPP = True
        carol_w.config.TEST_FORCE_MPP = True
        dave_w.features |= LnFeatures.BASIC_MPP_OPT

        with self.assertRaises(PaymentDone):
            await self._run_trampoline_payment(
                g,
                sender_name='alice',
                destination_name='dave',
                trampoline_forwarders=('bob', 'carol'),
                attempts=30,  # the default used in LNWallet.pay_invoice()
            )

    async def test_forwarder_fails_for_inconsistent_trampoline_onions(self):
        """
        verify that the receiver of a trampoline forwarding fails the mpp set
        if the trampoline onions are not similar
        In this test alice tries to forward through bob, however in one trampoline onion she sends
        amt_to_forward is off by one msat. Bob should compare the trampoline onions and fail the set.
        """

        # store a modified trampoline onion to be injected into lnworker.new_onion_packet later when sending the htlcs
        modified_trampoline_onion = None  # type: OnionPacket | None
        def modified_new_onion_packet_trampoline(payment_path_pubkeys, session_key, hops_data: List[OnionHopsDataSingle], **kwargs):
            nonlocal modified_trampoline_onion
            assert modified_trampoline_onion is None, "this mock should get called only once"
            modified_hops_data = copy.copy(hops_data)
            # first payload (i[0]) is for bob who is supposed to forward the trampoline payment, in this
            # test he should fail the incoming htlcs as their trampolines are not similar
            new_payload = dict(modified_hops_data[0].payload)
            amt_to_forward = dict(new_payload['amt_to_forward'])
            amt_to_forward['amt_to_forward'] -= 1
            new_payload['amt_to_forward'] = amt_to_forward
            modified_hops_data[0] = dataclasses.replace(modified_hops_data[0], payload=new_payload)
            self.logger.debug(f"{modified_hops_data=}\nsent_{hops_data=}")
            modified_trampoline_onion = electrum.lnonion.new_onion_packet(
                payment_path_pubkeys,
                session_key,
                modified_hops_data,
                **kwargs
            )
            # return the unmodified onion
            return electrum.lnonion.new_onion_packet(
                payment_path_pubkeys,
                session_key,
                hops_data,
                **kwargs
            )

        # this gets called in lnworker per sent htlc, for one sent htlc we inject the modified trampoline
        # onion created before in the mock above
        def modified_new_onion_packet_lnworker(payment_path_pubkeys, session_key, hops_data: List[OnionHopsDataSingle], **kwargs):
            nonlocal modified_trampoline_onion
            hops_data = copy.copy(hops_data)
            if modified_trampoline_onion:
                assert isinstance(modified_trampoline_onion, OnionPacket)
                assert len(hops_data) == 1
                new_payload = dict(hops_data[0].payload)
                new_payload['trampoline_onion_packet'] = {
                    "trampoline_onion_packet": modified_trampoline_onion.to_bytes()
                }
                hops_data[0] = dataclasses.replace(hops_data[0], payload=MappingProxyType(new_payload))
                modified_trampoline_onion = None
            return electrum.lnonion.new_onion_packet(
                payment_path_pubkeys,
                session_key,
                hops_data,
                **kwargs
            )

        graph = self.create_square_graph(direct=False, test_mpp_consolidation=True, is_legacy=True)
        alice = graph.workers['alice']
        alice.config.INITIAL_TRAMPOLINE_FEE_LEVEL = 6  # set high so the first attempt would succeed
        with self.assertRaises(PaymentFailure):
            with mock.patch('electrum.trampoline.new_onion_packet', side_effect=modified_new_onion_packet_trampoline), \
                    mock.patch('electrum.lnworker.new_onion_packet', side_effect=modified_new_onion_packet_lnworker):
                        await self._run_trampoline_payment(graph, attempts=1)
        bob_alice_channel = graph.channels[('bob', 'alice')][0]
        bob_hm = bob_alice_channel.hm
        assert len(bob_hm.all_htlcs_ever()) == 2
        assert all(bob_hm.was_htlc_failed(htlc_id=htlc.htlc_id, htlc_proposer=HTLCOwner.REMOTE) for (_, htlc) in bob_hm.all_htlcs_ever())

    async def test_trampoline_forwarder_waits_for_outer_onion_total_msat(self):
        """
        A trampoline forwarder must only forward once the htlcs it received sum up to the total_msat
        of the outer onion.
        Alice claims in the outer onion that twice the htlc amount will arrive, but only sends one htlc.
        Bob must not forward the incomplete set and has to fail it with MPP_TIMEOUT.
        """
        def modified_new_onion_packet_lnworker(payment_path_pubkeys, session_key, hops_data: List[OnionHopsDataSingle], **kwargs):
            hops_data = copy.copy(hops_data)
            payload = dict(hops_data[-1].payload)
            if 'trampoline_onion_packet' in payload:  # payload is alice's outer onion for bob
                payment_data = dict(payload['payment_data'])
                payment_data['total_msat'] *= 2  # bob should expect double the amount she actually receives
                payload['payment_data'] = payment_data
                hops_data[-1] = dataclasses.replace(hops_data[-1], payload=payload)
            return electrum.lnonion.new_onion_packet(payment_path_pubkeys, session_key, hops_data, **kwargs)

        graph = self.create_square_graph(direct=False, is_legacy=True)
        alice = graph.workers['alice']
        alice.config.INITIAL_TRAMPOLINE_FEE_LEVEL = 6  # set high so the payment would succeed if bob forwarded
        with self.assertLogs('electrum', level='INFO') as logs, self.assertRaises(NoPathFound):
            with mock.patch('electrum.lnworker.new_onion_packet', side_effect=modified_new_onion_packet_lnworker):
                await self._run_trampoline_payment(graph, attempts=1)
        self.assertTrue(any('MPP TIMEOUT' in record.getMessage() for record in logs.records))
        bob_carol_channel = graph.channels[('bob', 'carol')][0]
        self.assertEqual(0, len(bob_carol_channel.hm.all_htlcs_ever()))

    async def test_payment_with_malformed_onion(self):
        """
        Alice -> Bob -> Carol. Carol fails htlc with update_fail_malformed_htlc because she is unable
        to parse the onion Alice sent to her.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['line_graph'])
        peers = graph.peers.values()

        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['carol'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            result, log = await graph.workers['alice'].pay_invoice(pay_req)
            self.assertEqual(OnionFailureCode.INVALID_ONION_VERSION, log[0].failure_msg.code)
            self.assertFalse(result, msg=log)
            raise PaymentFailure()

        # this will make carol send update_fail_malformed_htlc
        graph.workers['carol'].config.TEST_FAIL_HTLCS_AS_MALFORMED = True

        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                lnaddr, pay_req = self.prepare_invoice(graph.workers['carol'], include_routing_hints=True)
                await group.spawn(pay(lnaddr, pay_req))

        with self.assertLogs('electrum', level='INFO') as logs:
            with self.assertRaises(PaymentFailure):
                await f()
            self.assertTrue(
                any('carol->bob' in msg and 'fail_malformed_htlc' in msg for msg in logs.output)
            )
            self.assertTrue(
                any('bob->carol' in msg and 'on_update_fail_malformed_htlc' in msg for msg in logs.output)
            )

    async def test_dont_settle_htlcs_receiver_and_forwarder(self):
        """
        Test that the receiver and forwarder doesn't settle htlcs once they get the preimage if the payment
        hash is in LNWallet.dont_settle_htlcs. E.g. the forwarder could be a just-in-time channel provider.
        Alice -> Bob -> Carol. Carol and Bob shouldn't release the preimage.
        """
        async def run_test(test_trampoline):
            graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['line_graph'])
            peers = graph.peers.values()

            if test_trampoline:
                # trampoline forwarder
                graph.workers['bob'].config.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS = True
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
                }
                # trampoline users
                await self._activate_trampoline(graph.workers['carol'])
                await self._activate_trampoline(graph.workers['alice'])

            lnaddr, pay_req = self.prepare_invoice(graph.workers['carol'], include_routing_hints=True)
            # test both receiver (carol) and forwarder (bob)
            graph.workers['bob'].dont_settle_htlcs[lnaddr.paymenthash.hex()] = None
            graph.workers['carol'].dont_settle_htlcs[lnaddr.paymenthash.hex()] = None

            payment_successful = asyncio.Event()
            async def pay():
                self.assertEqual(PR_UNPAID, graph.workers['carol'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
                result, log = await graph.workers['alice'].pay_invoice(pay_req)
                self.assertEqual(PR_PAID, graph.workers['carol'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
                self.assertTrue(result)
                payment_successful.set()

            async def check_doesnt_settle():
                while not graph.workers['carol'].received_mpp_htlcs:
                    await asyncio.sleep(0.1)  # wait until carol received the htlcs

                await asyncio.sleep(0.2)  # give carol time to accidentally release the preimage
                self.assertEqual(PR_UNPAID, graph.workers['carol'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
                self.assertIsNone(graph.workers['bob'].get_preimage(lnaddr.paymenthash), "bob got preimage from carol")
                # now allow carol to release the preimage to bob
                del graph.workers['carol'].dont_settle_htlcs[lnaddr.paymenthash.hex()]

                # wait for carol to release the preimage to bob
                while not graph.workers['bob'].get_preimage(lnaddr.paymenthash):
                    await asyncio.sleep(0.1)

                # give bob some time to settle the htlcs to alice (this would complete the payment)
                await asyncio.sleep(0.2)
                self.assertIsNone(graph.workers['alice'].get_preimage(lnaddr.paymenthash), "alice got preimage from bob")
                self.assertFalse(payment_successful.is_set(), "bob released preimage")

                # now allow bob to settle the htlcs
                del graph.workers['bob'].dont_settle_htlcs[lnaddr.paymenthash.hex()]
                await payment_successful.wait()
                raise PaymentDone()

            async def f():
                async with OldTaskGroup() as group:
                    for peer in peers:
                        await group.spawn(peer._message_loop())
                        await group.spawn(peer.htlc_switch())
                    for peer in peers:
                        await peer.initialized

                    await group.spawn(pay())
                    await group.spawn(check_doesnt_settle())
                    # stop the taskgroup if anything takes too long
                    await group.spawn(asyncio.wait_for(asyncio.sleep(4), timeout=3))

            await f()

        for trampoline in (False, True):
            with self.assertRaises(PaymentDone):
                await run_test(trampoline)


class TestPeerDirectNoAnchors(TestPeerDirect):
    assert TestPeerDirect.TEST_ANCHOR_CHANNELS is True
    TEST_ANCHOR_CHANNELS = False

class TestPeerForwardinNoAnchors(TestPeerForwarding):
    assert TestPeerForwarding.TEST_ANCHOR_CHANNELS is True
    TEST_ANCHOR_CHANNELS = False


def run(coro):
    return asyncio.run_coroutine_threadsafe(coro, loop=util.get_asyncio_loop()).result()
