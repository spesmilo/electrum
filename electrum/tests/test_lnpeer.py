import asyncio
import shutil
import tempfile
from decimal import Decimal
import os
from contextlib import contextmanager
from collections import defaultdict
import logging
import concurrent
from concurrent import futures
import unittest
from typing import Iterable, NamedTuple, Tuple, List, Dict

from aiorpcx import timeout_after, TaskTimeout

import electrum
import electrum.trampoline
from electrum import bitcoin
from electrum import util
from electrum import constants
from electrum.network import Network
from electrum.ecc import ECPrivkey
from electrum import simple_config, lnutil
from electrum.lnaddr import lnencode, LnAddr, lndecode
from electrum.bitcoin import COIN, sha256
from electrum.util import bh2u, NetworkRetryManager, bfh, OldTaskGroup, EventListener
from electrum.lnpeer import Peer
from electrum.lnutil import LNPeerAddr, Keypair, privkey_to_pubkey
from electrum.lnutil import PaymentFailure, LnFeatures, HTLCOwner
from electrum.lnchannel import ChannelState, PeerState, Channel
from electrum.lnrouter import LNPathFinder, PathEdge, LNPathInconsistent
from electrum.channel_db import ChannelDB
from electrum.lnworker import LNWallet, NoPathFound
from electrum.lnmsg import encode_msg, decode_msg
from electrum import lnmsg
from electrum.logging import console_stderr_handler, Logger
from electrum.lnworker import PaymentInfo, RECEIVED
from electrum.lnonion import OnionFailureCode
from electrum.lnutil import derive_payment_secret_from_payment_preimage, UpdateAddHtlc
from electrum.lnutil import LOCAL, REMOTE
from electrum.invoices import PR_PAID, PR_UNPAID
from electrum.interface import GracefulDisconnect
from electrum.simple_config import SimpleConfig

from .test_lnchannel import create_test_channels
from .test_bitcoin import needs_test_with_all_chacha20_implementations

from . import TestCaseForTestnet


def keypair():
    priv = ECPrivkey.generate_random_key().get_secret_bytes()
    k1 = Keypair(
            pubkey=privkey_to_pubkey(priv),
            privkey=priv)
    return k1

@contextmanager
def noop_lock():
    yield

class MockNetwork:
    def __init__(self, tx_queue, *, config: SimpleConfig):
        self.callbacks = defaultdict(list)
        self.lnwatcher = None
        self.interface = None
        self.config = config
        self.asyncio_loop = util.get_asyncio_loop()
        self.channel_db = ChannelDB(self)
        self.channel_db.data_loaded.set()
        self.path_finder = LNPathFinder(self.channel_db)
        self.tx_queue = tx_queue
        self._blockchain = MockBlockchain()

    @property
    def callback_lock(self):
        return noop_lock()

    def get_local_height(self):
        return 0

    def blockchain(self):
        return self._blockchain

    async def broadcast_transaction(self, tx):
        if self.tx_queue:
            await self.tx_queue.put(tx)

    async def try_broadcasting(self, tx, name):
        await self.broadcast_transaction(tx)


class MockBlockchain:

    def height(self):
        return 0

    def is_tip_stale(self):
        return False


class MockADB:
    def add_transaction(self, tx):
        pass

class MockWallet:
    receive_requests = {}
    adb = MockADB()

    def get_request(self, key):
        pass

    def get_key_for_receive_request(self, x):
        pass

    def set_label(self, x, y):
        pass

    def save_db(self):
        pass

    def is_lightning_backup(self):
        return False

    def is_mine(self, addr):
        return True


class MockLNWallet(Logger, EventListener, NetworkRetryManager[LNPeerAddr]):
    MPP_EXPIRY = 2  # HTLC timestamps are cast to int, so this cannot be 1
    PAYMENT_TIMEOUT = 120
    TIMEOUT_SHUTDOWN_FAIL_PENDING_HTLCS = 0
    INITIAL_TRAMPOLINE_FEE_LEVEL = 0

    def __init__(self, *, local_keypair: Keypair, chans: Iterable['Channel'], tx_queue, name, has_anchors):
        self.name = name
        Logger.__init__(self)
        NetworkRetryManager.__init__(self, max_retry_delay_normal=1, init_retry_delay_normal=1)
        self.node_keypair = local_keypair
        self._user_dir = tempfile.mkdtemp(prefix="electrum-lnpeer-test-")
        self.config = SimpleConfig({}, read_user_dir_function=lambda: self._user_dir)
        self.network = MockNetwork(tx_queue, config=self.config)
        self.taskgroup = OldTaskGroup()
        self.lnwatcher = None
        self.listen_server = None
        self._channels = {chan.channel_id: chan for chan in chans}
        self.payment_info = {}
        self.logs = defaultdict(list)
        self.wallet = MockWallet()
        self.features = LnFeatures(0)
        self.features |= LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT
        self.features |= LnFeatures.OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT
        self.features |= LnFeatures.VAR_ONION_OPT
        self.features |= LnFeatures.PAYMENT_SECRET_OPT
        self.features |= LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT
        self.features |= LnFeatures.OPTION_CHANNEL_TYPE_OPT
        self.features |= LnFeatures.OPTION_STATIC_REMOTEKEY_OPT
        self.config = {'enable_anchor_channels': has_anchors}
        self.pending_payments = defaultdict(asyncio.Future)
        for chan in chans:
            chan.lnworker = self
        self._peers = {}  # bytes -> Peer
        # used in tests
        self.enable_htlc_settle = True
        self.enable_htlc_forwarding = True
        self.received_mpp_htlcs = dict()
        self.sent_htlcs = defaultdict(asyncio.Queue)
        self.sent_htlcs_info = dict()
        self.sent_buckets = defaultdict(set)
        self.trampoline_forwarding_failures = {}
        self.inflight_payments = set()
        self.preimages = {}
        self.stopping_soon = False
        self.downstream_htlc_to_upstream_peer_map = {}

        self.logger.info(f"created LNWallet[{name}] with nodeID={local_keypair.pubkey.hex()}")

    def pay_scheduled_invoices(self):
        pass

    def get_invoice_status(self, key):
        pass

    @property
    def lock(self):
        return noop_lock()

    @property
    def channel_db(self):
        return self.network.channel_db if self.network else None

    def uses_trampoline(self):
        return not bool(self.channel_db)

    @property
    def channels(self):
        return self._channels

    @property
    def peers(self):
        return self._peers

    def get_channel_by_short_id(self, short_channel_id):
        with self.lock:
            for chan in self._channels.values():
                if chan.short_channel_id == short_channel_id:
                    return chan

    def channel_state_changed(self, chan):
        pass

    def save_channel(self, chan):
        print("Ignoring channel save")

    def diagnostic_name(self):
        return self.name

    async def stop(self):
        await LNWallet.stop(self)
        if self.channel_db:
            self.channel_db.stop()
            await self.channel_db.stopped_event.wait()

    async def create_routes_from_invoice(self, amount_msat: int, decoded_invoice: LnAddr, *, full_path=None):
        return [r async for r in self.create_routes_for_payment(
            amount_msat=amount_msat,
            final_total_msat=amount_msat,
            invoice_pubkey=decoded_invoice.pubkey.serialize(),
            min_cltv_expiry=decoded_invoice.get_min_final_cltv_expiry(),
            r_tags=decoded_invoice.get_routing_info('r'),
            invoice_features=decoded_invoice.get_features(),
            trampoline_fee_level=0,
            use_two_trampolines=False,
            payment_hash=decoded_invoice.paymenthash,
            payment_secret=decoded_invoice.payment_secret,
            full_path=full_path)]

    get_payments = LNWallet.get_payments
    get_payment_info = LNWallet.get_payment_info
    save_payment_info = LNWallet.save_payment_info
    set_invoice_status = LNWallet.set_invoice_status
    set_request_status = LNWallet.set_request_status
    set_payment_status = LNWallet.set_payment_status
    get_payment_status = LNWallet.get_payment_status
    check_received_mpp_htlc = LNWallet.check_received_mpp_htlc
    htlc_fulfilled = LNWallet.htlc_fulfilled
    htlc_failed = LNWallet.htlc_failed
    save_preimage = LNWallet.save_preimage
    get_preimage = LNWallet.get_preimage
    create_route_for_payment = LNWallet.create_route_for_payment
    create_routes_for_payment = LNWallet.create_routes_for_payment
    _check_invoice = staticmethod(LNWallet._check_invoice)
    pay_to_route = LNWallet.pay_to_route
    pay_to_node = LNWallet.pay_to_node
    pay_invoice = LNWallet.pay_invoice
    force_close_channel = LNWallet.force_close_channel
    schedule_force_closing = LNWallet.schedule_force_closing
    get_first_timestamp = lambda self: 0
    on_peer_successfully_established = LNWallet.on_peer_successfully_established
    get_channel_by_id = LNWallet.get_channel_by_id
    channels_for_peer = LNWallet.channels_for_peer
    calc_routing_hints_for_invoice = LNWallet.calc_routing_hints_for_invoice
    get_channels_for_receiving = LNWallet.get_channels_for_receiving
    handle_error_code_from_failed_htlc = LNWallet.handle_error_code_from_failed_htlc
    is_trampoline_peer = LNWallet.is_trampoline_peer
    wait_for_received_pending_htlcs_to_get_removed = LNWallet.wait_for_received_pending_htlcs_to_get_removed
    #on_event_proxy_set = LNWallet.on_event_proxy_set
    _decode_channel_update_msg = LNWallet._decode_channel_update_msg
    _handle_chanupd_from_failed_htlc = LNWallet._handle_chanupd_from_failed_htlc
    _on_maybe_forwarded_htlc_resolved = LNWallet._on_maybe_forwarded_htlc_resolved
    _force_close_channel = LNWallet._force_close_channel
    suggest_splits = LNWallet.suggest_splits


class MockTransport:
    def __init__(self, name):
        self.queue = asyncio.Queue()  # incoming messages
        self._name = name
        self.peer_addr = None

    def name(self):
        return self._name

    async def read_messages(self):
        while True:
            data = await self.queue.get()
            if isinstance(data, asyncio.Event):  # to artificially delay messages
                await data.wait()
                continue
            yield data

class NoFeaturesTransport(MockTransport):
    """
    This answers the init message with a init that doesn't signal any features.
    Used for testing that we require DATA_LOSS_PROTECT.
    """
    def send_bytes(self, data):
        decoded = decode_msg(data)
        print(decoded)
        if decoded[0] == 'init':
            self.queue.put_nowait(encode_msg('init', lflen=1, gflen=1, localfeatures=b"\x00", globalfeatures=b"\x00"))

class PutIntoOthersQueueTransport(MockTransport):
    def __init__(self, keypair, name):
        super().__init__(name)
        self.other_mock_transport = None
        self.privkey = keypair.privkey

    def send_bytes(self, data):
        self.other_mock_transport.queue.put_nowait(data)

def transport_pair(k1, k2, name1, name2):
    t1 = PutIntoOthersQueueTransport(k1, name1)
    t2 = PutIntoOthersQueueTransport(k2, name2)
    t1.other_mock_transport = t2
    t2.other_mock_transport = t1
    return t1, t2


class PeerInTests(Peer):
    DELAY_INC_MSG_PROCESSING_SLEEP = 0  # disable rate-limiting


high_fee_channel = {
   'local_balance_msat': 10 * bitcoin.COIN * 1000 // 2,
   'remote_balance_msat': 10 * bitcoin.COIN * 1000 // 2,
   'local_base_fee_msat': 500_000,
   'local_fee_rate_millionths': 500,
   'remote_base_fee_msat': 500_000,
   'remote_fee_rate_millionths': 500,
}

low_fee_channel = {
    'local_balance_msat': 10 * bitcoin.COIN * 1000 // 2,
    'remote_balance_msat': 10 * bitcoin.COIN * 1000 // 2,
    'local_base_fee_msat': 1_000,
    'local_fee_rate_millionths': 1,
    'remote_base_fee_msat': 1_000,
    'remote_fee_rate_millionths': 1,
}

depleted_channel = {
    'local_balance_msat': 0,
    'remote_balance_msat': 10 * bitcoin.COIN * 1000,
    'local_base_fee_msat': 1_000,
    'local_fee_rate_millionths': 1,
    'remote_base_fee_msat': 1_000,
    'remote_fee_rate_millionths': 1,
}

GRAPH_DEFINITIONS = {
    'square_graph': {
        'alice': {
            'channels': {
                # we should use copies of channel definitions if
                # we want to independently alter them in a test
                'bob': high_fee_channel.copy(),
                'carol': low_fee_channel.copy(),
            },
        },
        'bob': {
            'channels': {
                'dave': high_fee_channel.copy(),
            },
            'config': {
                'lightning_forward_payments': True,
                'lightning_forward_trampoline_payments': True,
            },
        },
        'carol': {
            'channels': {
                'dave': low_fee_channel.copy(),
            },
            'config': {
                'lightning_forward_payments': True,
                'lightning_forward_trampoline_payments': True,
            },
        },
        'dave': {
        },
    }
}


class Graph(NamedTuple):
    workers: Dict[str, MockLNWallet]
    peers: Dict[Tuple[str, str], Peer]
    channels: Dict[Tuple[str, str], Channel]


class PaymentDone(Exception): pass
class SuccessfulTest(Exception): pass


class TestPeer(TestCaseForTestnet):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()
        self._lnworkers_created = []  # type: List[MockLNWallet]

    def tearDown(self):
        async def cleanup_lnworkers():
            async with OldTaskGroup() as group:
                for lnworker in self._lnworkers_created:
                    await group.spawn(lnworker.stop())
            for lnworker in self._lnworkers_created:
                shutil.rmtree(lnworker._user_dir)
            self._lnworkers_created.clear()
        run(cleanup_lnworkers())
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {}
        super().tearDown()

    def prepare_peers(
            self, alice_channel: Channel, bob_channel: Channel,
            *, k1: Keypair = None, k2: Keypair = None,
    ):
        if k1 is None:
            k1 = keypair()
        if k2 is None:
            k2 = keypair()
        alice_channel.node_id = k2.pubkey
        bob_channel.node_id = k1.pubkey
        t1, t2 = transport_pair(k1, k2, alice_channel.name, bob_channel.name)
        q1, q2 = asyncio.Queue(), asyncio.Queue()
        w1 = MockLNWallet(local_keypair=k1, chans=[alice_channel], tx_queue=q1, name=bob_channel.name, has_anchors=self.TEST_ANCHOR_CHANNELS)
        w2 = MockLNWallet(local_keypair=k2, chans=[bob_channel], tx_queue=q2, name=alice_channel.name, has_anchors=self.TEST_ANCHOR_CHANNELS)
        self._lnworkers_created.extend([w1, w2])
        p1 = PeerInTests(w1, k2.pubkey, t1)
        p2 = PeerInTests(w2, k1.pubkey, t2)
        w1._peers[p1.pubkey] = p1
        w2._peers[p2.pubkey] = p2
        # mark_open won't work if state is already OPEN.
        # so set it to FUNDED
        alice_channel._state = ChannelState.FUNDED
        bob_channel._state = ChannelState.FUNDED
        # this populates the channel graph:
        p1.mark_open(alice_channel)
        p2.mark_open(bob_channel)
        return p1, p2, w1, w2, q1, q2

    def prepare_chans_and_peers_in_graph(self, graph_definition) -> Graph:
        keys = {k: keypair() for k in graph_definition}
        txs_queues = {k: asyncio.Queue() for k in graph_definition}
        channels = {}  # type: Dict[Tuple[str, str], Channel]
        transports = {}
        workers = {}  # type: Dict[str, MockLNWallet]
        peers = {}
        # create channels
        for a, definition in graph_definition.items():
            for b, channel_def in definition.get('channels', {}).items():
                channel_ab, channel_ba = create_test_channels(
                    alice_name=a,
                    bob_name=b,
                    alice_pubkey=keys[a].pubkey,
                    bob_pubkey=keys[b].pubkey,
                    local_msat=channel_def['local_balance_msat'],
                    remote_msat=channel_def['remote_balance_msat'],
                    anchor_outputs=self.TEST_ANCHOR_CHANNELS
                )
                channels[(a, b)], channels[(b, a)] = channel_ab, channel_ba
                transport_ab, transport_ba = transport_pair(keys[a], keys[b], channel_ab.name, channel_ba.name)
                transports[(a, b)], transports[(b, a)] = transport_ab, transport_ba
                # set fees
                channel_ab.forwarding_fee_proportional_millionths = channel_def['local_fee_rate_millionths']
                channel_ab.forwarding_fee_base_msat = channel_def['local_base_fee_msat']
                channel_ba.forwarding_fee_proportional_millionths = channel_def['remote_fee_rate_millionths']
                channel_ba.forwarding_fee_base_msat = channel_def['remote_base_fee_msat']

        # create workers and peers
        for a, definition in graph_definition.items():
            channels_of_node = [c for k, c in channels.items() if k[0] == a]
            workers[a] = MockLNWallet(local_keypair=keys[a], chans=channels_of_node, tx_queue=txs_queues[a], name=a, has_anchors=self.TEST_ANCHOR_CHANNELS)
        self._lnworkers_created.extend(list(workers.values()))

        # create peers
        for ab in channels.keys():
            peers[ab] = Peer(workers[ab[0]], keys[ab[1]].pubkey, transports[ab])

        # add peers to workers
        for a, w in workers.items():
            for ab, peer_ab in peers.items():
                if ab[0] == a:
                    w._peers[peer_ab.pubkey] = peer_ab

        # set forwarding properties
        for a, definition in graph_definition.items():
            for property in definition.get('config', {}).items():
                workers[a].network.config.set_key(*property)

        # mark_open won't work if state is already OPEN.
        # so set it to FUNDED
        for channel_ab in channels.values():
           channel_ab._state = ChannelState.FUNDED

        # this populates the channel graph:
        for ab, peer_ab in peers.items():
            peer_ab.mark_open(channels[ab])

        graph = Graph(
            workers=workers,
            peers=peers,
            channels=channels,
        )
        for a in workers:
            print(f"{a:5s}: {keys[a].pubkey}")
            print(f"       {keys[a].pubkey.hex()}")
        return graph

    @staticmethod
    def prepare_invoice(
            w2: MockLNWallet,  # receiver
            *,
            amount_msat=100_000_000,
            include_routing_hints=False,
    ) -> Tuple[LnAddr, str]:
        amount_btc = amount_msat/Decimal(COIN*1000)
        payment_preimage = os.urandom(32)
        RHASH = sha256(payment_preimage)
        info = PaymentInfo(RHASH, amount_msat, RECEIVED, PR_UNPAID)
        w2.save_preimage(RHASH, payment_preimage)
        w2.save_payment_info(info)
        if include_routing_hints:
            routing_hints, trampoline_hints = w2.calc_routing_hints_for_invoice(amount_msat)
        else:
            routing_hints = []
            trampoline_hints = []
        invoice_features = w2.features.for_invoice()
        if invoice_features.supports(LnFeatures.PAYMENT_SECRET_OPT):
            payment_secret = derive_payment_secret_from_payment_preimage(payment_preimage)
        else:
            payment_secret = None
        lnaddr1 = LnAddr(
                    paymenthash=RHASH,
                    amount=amount_btc,
                    tags=[('c', lnutil.MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE),
                          ('d', 'coffee'),
                          ('9', invoice_features),
                         ] + routing_hints + trampoline_hints,
                    payment_secret=payment_secret,
        )
        invoice = lnencode(lnaddr1, w2.node_keypair.privkey)
        lnaddr2 = lndecode(invoice)  # unlike lnaddr1, this now has a pubkey set
        return lnaddr2, invoice

    def test_reestablish(self):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        for chan in (alice_channel, bob_channel):
            chan.peer_state = PeerState.DISCONNECTED
        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            self.assertEqual(alice_channel.peer_state, PeerState.GOOD)
            self.assertEqual(bob_channel.peer_state, PeerState.GOOD)
            gath.cancel()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p1.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_reestablish_with_old_state(self):
        random_seed = os.urandom(32)
        alice_channel, bob_channel = create_test_channels(random_seed=random_seed, anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        alice_channel_0, bob_channel_0 = create_test_channels(random_seed=random_seed, anchor_outputs=self.TEST_ANCHOR_CHANNELS)  # these are identical
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        lnaddr, pay_req = self.prepare_invoice(w2)
        async def pay():
            result, log = await w1.pay_invoice(pay_req)
            self.assertEqual(result, True)
            gath.cancel()
        gath = asyncio.gather(pay(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel_0, bob_channel)
        for chan in (alice_channel_0, bob_channel):
            chan.peer_state = PeerState.DISCONNECTED
        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel_0),
                p2.reestablish_channel(bob_channel))
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(electrum.lnutil.RemoteMisbehaving):
            run(f())
        self.assertEqual(alice_channel_0.peer_state, PeerState.BAD)
        self.assertEqual(bob_channel._state, ChannelState.FORCE_CLOSING)

    @staticmethod
    def _send_fake_htlc(peer: Peer, chan: Channel) -> UpdateAddHtlc:
        htlc = UpdateAddHtlc(amount_msat=10000, payment_hash=os.urandom(32), cltv_expiry=999, timestamp=1)
        htlc = chan.add_htlc(htlc)
        peer.send_message(
            "update_add_htlc",
            channel_id=chan.channel_id,
            id=htlc.htlc_id,
            cltv_expiry=htlc.cltv_expiry,
            amount_msat=htlc.amount_msat,
            payment_hash=htlc.payment_hash,
            onion_routing_packet=1366 * b"0",
        )
        return htlc

    def test_reestablish_replay_messages_rev_then_sig(self):
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
        chan_AB, chan_BA = create_test_channels()
        k1, k2 = keypair(), keypair()
        # note: we don't start peer.htlc_switch() so that the fake htlcs are left alone.
        async def f():
            p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(chan_AB, chan_BA, k1=k1, k2=k2)
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p2._message_loop())
                await p1.initialized
                await p2.initialized
                self._send_fake_htlc(p2, chan_BA)
                self._send_fake_htlc(p1, chan_AB)
                p2.transport.queue.put_nowait(asyncio.Event())  # break Bob's incoming pipe
                self.assertTrue(p2.maybe_send_commitment(chan_BA))
                await p1.received_commitsig_event.wait()
                await group.cancel_remaining()
            # simulating disconnection. recreate transports.
            p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(chan_AB, chan_BA, k1=k1, k2=k2)
            for chan in (chan_AB, chan_BA):
                chan.peer_state = PeerState.DISCONNECTED
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p2._message_loop())
                with self.assertLogs('electrum', level='INFO') as logs:
                    async with OldTaskGroup() as group2:
                        await group2.spawn(p1.reestablish_channel(chan_AB))
                        await group2.spawn(p2.reestablish_channel(chan_BA))
                self.assertTrue(any(("alice->bob" in msg and
                                     "replaying a revoke_and_ack first" in msg) for msg in logs.output))
                self.assertTrue(any(("alice->bob" in msg and
                                     "replayed 2 unacked messages. ['update_add_htlc', 'commitment_signed']" in msg) for msg in logs.output))
                self.assertEqual(chan_AB.peer_state, PeerState.GOOD)
                self.assertEqual(chan_BA.peer_state, PeerState.GOOD)
                raise SuccessfulTest()
        with self.assertRaises(SuccessfulTest):
            run(f())

    def test_reestablish_replay_messages_sig_then_rev(self):
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
        chan_AB, chan_BA = create_test_channels()
        k1, k2 = keypair(), keypair()
        # note: we don't start peer.htlc_switch() so that the fake htlcs are left alone.
        async def f():
            p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(chan_AB, chan_BA, k1=k1, k2=k2)
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p2._message_loop())
                await p1.initialized
                await p2.initialized
                self._send_fake_htlc(p2, chan_BA)
                self._send_fake_htlc(p1, chan_AB)
                p2.transport.queue.put_nowait(asyncio.Event())  # break Bob's incoming pipe
                self.assertTrue(p1.maybe_send_commitment(chan_AB))
                self.assertTrue(p2.maybe_send_commitment(chan_BA))
                await p1.received_commitsig_event.wait()
                await group.cancel_remaining()
            # simulating disconnection. recreate transports.
            p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(chan_AB, chan_BA, k1=k1, k2=k2)
            for chan in (chan_AB, chan_BA):
                chan.peer_state = PeerState.DISCONNECTED
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p2._message_loop())
                with self.assertLogs('electrum', level='INFO') as logs:
                    async with OldTaskGroup() as group2:
                        await group2.spawn(p1.reestablish_channel(chan_AB))
                        await group2.spawn(p2.reestablish_channel(chan_BA))
                self.assertTrue(any(("alice->bob" in msg and
                                     "replaying a revoke_and_ack last" in msg) for msg in logs.output))
                self.assertTrue(any(("alice->bob" in msg and
                                     "replayed 2 unacked messages. ['update_add_htlc', 'commitment_signed']" in msg) for msg in logs.output))
                self.assertEqual(chan_AB.peer_state, PeerState.GOOD)
                self.assertEqual(chan_BA.peer_state, PeerState.GOOD)
                raise SuccessfulTest()
        with self.assertRaises(SuccessfulTest):
            run(f())

    def _test_simple_payment(self, trampoline: bool):
        """Alice pays Bob a single HTLC via direct channel."""
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        async def turn_on_trampoline_alice():
            if w1.network.channel_db:
                w1.network.channel_db.stop()
                await w1.network.channel_db.stopped_event.wait()
                w1.network.channel_db = None
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr.paymenthash))
            result, log = await w1.pay_invoice(pay_req)
            self.assertTrue(result)
            self.assertEqual(PR_PAID, w2.get_payment_status(lnaddr.paymenthash))
            raise PaymentDone()
        async def f():
            if trampoline:
                await turn_on_trampoline_alice()
            async with OldTaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                lnaddr, pay_req = self.prepare_invoice(w2)
                invoice_features = lnaddr.get_features()
                self.assertFalse(invoice_features.supports(LnFeatures.BASIC_MPP_OPT))
                await group.spawn(pay(lnaddr, pay_req))
        # declare bob as trampoline node
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            'bob': LNPeerAddr(host="127.0.0.1", port=9735, pubkey=w2.node_keypair.pubkey),
        }
        with self.assertRaises(PaymentDone):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_simple_payment(self):
        self._test_simple_payment(trampoline=False)

    @needs_test_with_all_chacha20_implementations
    def test_simple_payment_trampoline(self):
        self._test_simple_payment(trampoline=True)

    @needs_test_with_all_chacha20_implementations
    def test_payment_race(self):
        """Alice and Bob pay each other simultaneously.
        They both send 'update_add_htlc' and receive each other's update
        before sending 'commitment_signed'. Neither party should fulfill
        the respective HTLCs until those are irrevocably committed to.
        """
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        async def pay():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
            # prep
            _maybe_send_commitment1 = p1.maybe_send_commitment
            _maybe_send_commitment2 = p2.maybe_send_commitment
            lnaddr2, pay_req2 = self.prepare_invoice(w2)
            lnaddr1, pay_req1 = self.prepare_invoice(w1)
            # create the htlc queues now (side-effecting defaultdict)
            q1 = w1.sent_htlcs[lnaddr2.paymenthash]
            q2 = w2.sent_htlcs[lnaddr1.paymenthash]
            # alice sends htlc BUT NOT COMMITMENT_SIGNED
            p1.maybe_send_commitment = lambda x: None
            route1 = (await w1.create_routes_from_invoice(lnaddr2.get_amount_msat(), decoded_invoice=lnaddr2))[0][0]
            amount_msat = lnaddr2.get_amount_msat()
            await w1.pay_to_route(
                route=route1,
                amount_msat=amount_msat,
                total_msat=amount_msat,
                amount_receiver_msat=amount_msat,
                payment_hash=lnaddr2.paymenthash,
                min_cltv_expiry=lnaddr2.get_min_final_cltv_expiry(),
                payment_secret=lnaddr2.payment_secret,
                trampoline_fee_level=0,
                trampoline_route=None,
            )
            p1.maybe_send_commitment = _maybe_send_commitment1
            # bob sends htlc BUT NOT COMMITMENT_SIGNED
            p2.maybe_send_commitment = lambda x: None
            route2 = (await w2.create_routes_from_invoice(lnaddr1.get_amount_msat(), decoded_invoice=lnaddr1))[0][0]
            amount_msat = lnaddr1.get_amount_msat()
            await w2.pay_to_route(
                route=route2,
                amount_msat=amount_msat,
                total_msat=amount_msat,
                amount_receiver_msat=amount_msat,
                payment_hash=lnaddr1.paymenthash,
                min_cltv_expiry=lnaddr1.get_min_final_cltv_expiry(),
                payment_secret=lnaddr1.payment_secret,
                trampoline_fee_level=0,
                trampoline_route=None,
            )
            p2.maybe_send_commitment = _maybe_send_commitment2
            # sleep a bit so that they both receive msgs sent so far
            await asyncio.sleep(0.2)
            # now they both send COMMITMENT_SIGNED
            p1.maybe_send_commitment(alice_channel)
            p2.maybe_send_commitment(bob_channel)

            htlc_log1 = await q1.get()
            assert htlc_log1.success
            htlc_log2 = await q2.get()
            assert htlc_log2.success
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
            run(f())

    def test_payments_stresstest(self):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
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
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())
        self.assertEqual(alice_init_balance_msat - num_payments * payment_value_msat, alice_channel.balance(HTLCOwner.LOCAL))
        self.assertEqual(alice_init_balance_msat - num_payments * payment_value_msat, bob_channel.balance(HTLCOwner.REMOTE))
        self.assertEqual(bob_init_balance_msat + num_payments * payment_value_msat, bob_channel.balance(HTLCOwner.LOCAL))
        self.assertEqual(bob_init_balance_msat + num_payments * payment_value_msat, alice_channel.balance(HTLCOwner.REMOTE))

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop(self):
        graph = self.prepare_chans_and_peers_in_graph(GRAPH_DEFINITIONS['square_graph'])
        peers = graph.peers.values()
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
            result, log = await graph.workers['alice'].pay_invoice(pay_req)
            self.assertTrue(result)
            self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
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
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop_with_preselected_path(self):
        graph = self.prepare_chans_and_peers_in_graph(GRAPH_DEFINITIONS['square_graph'])
        peers = graph.peers.values()
        async def pay(pay_req):
            with self.subTest(msg="bad path: edges do not chain together"):
                path = [PathEdge(start_node=graph.workers['alice'].node_keypair.pubkey,
                                 end_node=graph.workers['carol'].node_keypair.pubkey,
                                 short_channel_id=graph.channels[('alice', 'bob')].short_channel_id),
                        PathEdge(start_node=graph.workers['bob'].node_keypair.pubkey,
                                 end_node=graph.workers['dave'].node_keypair.pubkey,
                                 short_channel_id=graph.channels['bob', 'dave'].short_channel_id)]
                with self.assertRaises(LNPathInconsistent):
                    await graph.workers['alice'].pay_invoice(pay_req, full_path=path)
            with self.subTest(msg="bad path: last node id differs from invoice pubkey"):
                path = [PathEdge(start_node=graph.workers['alice'].node_keypair.pubkey,
                                 end_node=graph.workers['bob'].node_keypair.pubkey,
                                 short_channel_id=graph.channels[('alice', 'bob')].short_channel_id)]
                with self.assertRaises(LNPathInconsistent):
                    await graph.workers['alice'].pay_invoice(pay_req, full_path=path)
            with self.subTest(msg="good path"):
                path = [PathEdge(start_node=graph.workers['alice'].node_keypair.pubkey,
                                 end_node=graph.workers['bob'].node_keypair.pubkey,
                                 short_channel_id=graph.channels[('alice', 'bob')].short_channel_id),
                        PathEdge(start_node=graph.workers['bob'].node_keypair.pubkey,
                                 end_node=graph.workers['dave'].node_keypair.pubkey,
                                 short_channel_id=graph.channels['bob', 'dave'].short_channel_id)]
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
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop_temp_node_failure(self):
        graph = self.prepare_chans_and_peers_in_graph(GRAPH_DEFINITIONS['square_graph'])
        graph.workers['bob'].network.config.set_key('test_fail_htlcs_with_temp_node_failure', True)
        graph.workers['carol'].network.config.set_key('test_fail_htlcs_with_temp_node_failure', True)
        peers = graph.peers.values()
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
            result, log = await graph.workers['alice'].pay_invoice(pay_req)
            self.assertFalse(result)
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
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
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop_route_around_failure(self):
        # Alice will pay Dave. Alice first tries A->C->D route, due to lower fees, but Carol
        # will fail the htlc and get blacklisted. Alice will then try A->B->D and succeed.
        graph = self.prepare_chans_and_peers_in_graph(GRAPH_DEFINITIONS['square_graph'])
        graph.workers['carol'].network.config.set_key('test_fail_htlcs_with_temp_node_failure', True)
        peers = graph.peers.values()
        async def pay(lnaddr, pay_req):
            self.assertEqual(500000000000, graph.channels[('alice', 'bob')].balance(LOCAL))
            self.assertEqual(500000000000, graph.channels[('dave', 'bob')].balance(LOCAL))
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
            result, log = await graph.workers['alice'].pay_invoice(pay_req, attempts=2)
            self.assertEqual(2, len(log))
            self.assertTrue(result)
            self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
            self.assertEqual([graph.channels[('alice', 'carol')].short_channel_id, graph.channels[('carol', 'dave')].short_channel_id],
                             [edge.short_channel_id for edge in log[0].route])
            self.assertEqual([graph.channels[('alice', 'bob')].short_channel_id, graph.channels[('bob', 'dave')].short_channel_id],
                             [edge.short_channel_id for edge in log[1].route])
            self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, log[0].failure_msg.code)
            self.assertEqual(499899450000, graph.channels[('alice', 'bob')].balance(LOCAL))
            await asyncio.sleep(0.2)  # wait for COMMITMENT_SIGNED / REVACK msgs to update balance
            self.assertEqual(500100000000, graph.channels[('dave', 'bob')].balance(LOCAL))
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
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_with_temp_channel_failure_and_liquidity_hints(self):
        # prepare channels such that a temporary channel failure happens at c->d
        graph_definition = GRAPH_DEFINITIONS['square_graph'].copy()
        graph_definition['alice']['channels']['carol']['local_balance_msat'] = 200_000_000
        graph_definition['alice']['channels']['carol']['remote_balance_msat'] = 200_000_000
        graph_definition['carol']['channels']['dave']['local_balance_msat'] = 50_000_000
        graph_definition['carol']['channels']['dave']['remote_balance_msat'] = 200_000_000
        graph_definition['alice']['channels']['bob']['local_balance_msat'] = 200_000_000
        graph_definition['alice']['channels']['bob']['remote_balance_msat'] = 200_000_000
        graph_definition['bob']['channels']['dave']['local_balance_msat'] = 200_000_000
        graph_definition['bob']['channels']['dave']['remote_balance_msat'] = 200_000_000
        graph = self.prepare_chans_and_peers_in_graph(graph_definition)

        # the payment happens in two attempts:
        # 1. along a->c->d due to low fees with temp channel failure:
        #   with chanupd: ORPHANED, private channel update
        #   c->d gets a liquidity hint and gets blocked
        # 2. along a->b->d with success
        amount_to_pay = 100_000_000
        peers = graph.peers.values()
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
            result, log = await graph.workers['alice'].pay_invoice(pay_req, attempts=3)
            self.assertTrue(result)
            self.assertEqual(2, len(log))
            self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
            self.assertEqual(OnionFailureCode.TEMPORARY_CHANNEL_FAILURE, log[0].failure_msg.code)

            liquidity_hints = graph.workers['alice'].network.path_finder.liquidity_hints
            pubkey_a = graph.workers['alice'].node_keypair.pubkey
            pubkey_b = graph.workers['bob'].node_keypair.pubkey
            pubkey_c = graph.workers['carol'].node_keypair.pubkey
            pubkey_d = graph.workers['dave'].node_keypair.pubkey
            # check liquidity hints for failing route:
            hint_ac = liquidity_hints.get_hint(graph.channels[('alice', 'carol')].short_channel_id)
            hint_cd = liquidity_hints.get_hint(graph.channels[('carol', 'dave')].short_channel_id)
            self.assertEqual(amount_to_pay, hint_ac.can_send(pubkey_a < pubkey_c))
            self.assertEqual(None, hint_ac.cannot_send(pubkey_a < pubkey_c))
            self.assertEqual(None, hint_cd.can_send(pubkey_c < pubkey_d))
            self.assertEqual(amount_to_pay, hint_cd.cannot_send(pubkey_c < pubkey_d))
            # check liquidity hints for successful route:
            hint_ab = liquidity_hints.get_hint(graph.channels[('alice', 'bob')].short_channel_id)
            hint_bd = liquidity_hints.get_hint(graph.channels[('bob', 'dave')].short_channel_id)
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
            run(f())

    def _run_mpp(self, graph, fail_kwargs, success_kwargs):
        """Tests a multipart payment scenario for failing and successful cases."""
        self.assertEqual(500_000_000_000, graph.channels[('alice', 'bob')].balance(LOCAL))
        self.assertEqual(500_000_000_000, graph.channels[('alice', 'carol')].balance(LOCAL))
        amount_to_pay = 600_000_000_000
        peers = graph.peers.values()
        async def pay(
                attempts=1,
                alice_uses_trampoline=False,
                bob_forwarding=True,
                mpp_invoice=True,
                disable_trampoline_receiving=False,
        ):
            if mpp_invoice:
                graph.workers['dave'].features |= LnFeatures.BASIC_MPP_OPT
            if disable_trampoline_receiving:
                graph.workers['dave'].features &= ~LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT
            if not bob_forwarding:
                graph.workers['bob'].enable_htlc_forwarding = False
            if alice_uses_trampoline:
                if graph.workers['alice'].network.channel_db:
                    graph.workers['alice'].network.channel_db.stop()
                    await graph.workers['alice'].network.channel_db.stopped_event.wait()
                    graph.workers['alice'].network.channel_db = None
            else:
                assert graph.workers['alice'].network.channel_db is not None
            lnaddr, pay_req = self.prepare_invoice(graph.workers['dave'], include_routing_hints=True, amount_msat=amount_to_pay)
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
            result, log = await graph.workers['alice'].pay_invoice(pay_req, attempts=attempts)
            if not bob_forwarding:
                # reset to previous state, sleep 2s so that the second htlc can time out
                graph.workers['bob'].enable_htlc_forwarding = True
                await asyncio.sleep(2)
            if result:
                self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
                raise PaymentDone()
            else:
                raise NoPathFound()

        async def f(kwargs):
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                await group.spawn(pay(**kwargs))

        if fail_kwargs:
            with self.assertRaises(NoPathFound):
                run(f(fail_kwargs))
        if success_kwargs:
            with self.assertRaises(PaymentDone):
                run(f(success_kwargs))

    @needs_test_with_all_chacha20_implementations
    def test_payment_multipart_with_timeout(self):
        graph = self.prepare_chans_and_peers_in_graph(GRAPH_DEFINITIONS['square_graph'])
        self._run_mpp(graph, {'bob_forwarding': False}, {'bob_forwarding': True})

    @needs_test_with_all_chacha20_implementations
    def test_payment_multipart(self):
        graph = self.prepare_chans_and_peers_in_graph(GRAPH_DEFINITIONS['square_graph'])
        self._run_mpp(graph, {'mpp_invoice': False}, {'mpp_invoice': True})

    def _run_trampoline_payment(self, is_legacy, direct, drop_dave= []):
        async def turn_on_trampoline_alice():
            if graph.workers['alice'].network.channel_db:
                graph.workers['alice'].network.channel_db.stop()
                await graph.workers['alice'].network.channel_db.stopped_event.wait()
                graph.workers['alice'].network.channel_db = None

        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
            result, log = await graph.workers['alice'].pay_invoice(pay_req, attempts=10)
            if result:
                self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
                raise PaymentDone()
            else:
                raise NoPathFound()

        def do_drop_dave(t):
            # this will trigger UNKNOWN_NEXT_PEER
            dave_node_id = graph.workers['dave'].node_keypair.pubkey
            graph.workers[t].peers.pop(dave_node_id)

        async def f():
            await turn_on_trampoline_alice()
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                lnaddr, pay_req = self.prepare_invoice(graph.workers['dave'], include_routing_hints=True)
                for p in drop_dave:
                    do_drop_dave(p)
                await group.spawn(pay(lnaddr, pay_req))

        graph_definition = GRAPH_DEFINITIONS['square_graph'].copy()
        if not direct:
            # deplete channel from alice to carol
            graph_definition['alice']['channels']['carol'] = depleted_channel
            # insert a channel from bob to carol
            graph_definition['bob']['channels']['carol'] = high_fee_channel

        graph = self.prepare_chans_and_peers_in_graph(graph_definition)
        peers = graph.peers.values()
        if is_legacy:
            # turn off trampoline features in invoice
            graph.workers['dave'].features = graph.workers['dave'].features ^ LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT

        # declare routing nodes as trampoline nodes
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
            graph.workers['carol'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['carol'].node_keypair.pubkey),
        }

        run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_trampoline_legacy(self):
        with self.assertRaises(PaymentDone):
            self._run_trampoline_payment(is_legacy=True, direct=False)

    @needs_test_with_all_chacha20_implementations
    def test_payment_trampoline_e2e_direct(self):
        with self.assertRaises(PaymentDone):
            self._run_trampoline_payment(is_legacy=False, direct=True)

    @needs_test_with_all_chacha20_implementations
    def test_payment_trampoline_e2e_indirect(self):
        # must use two trampolines
        with self.assertRaises(PaymentDone):
            self._run_trampoline_payment(is_legacy=False, direct=False, drop_dave=['bob'])
        # both trampolines drop dave
        with self.assertRaises(NoPathFound):
            self._run_trampoline_payment(is_legacy=False, direct=False, drop_dave=['bob', 'carol'])

    @needs_test_with_all_chacha20_implementations
    def test_payment_multipart_trampoline_e2e(self):
        graph = self.prepare_chans_and_peers_in_graph(GRAPH_DEFINITIONS['square_graph'])
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
            graph.workers['carol'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['carol'].node_keypair.pubkey),
        }
        # end-to-end trampoline: we attempt
        # * a payment with one trial: fails, because
        #   we need at least one trial because the initial fees are too low
        # * a payment with several trials: should succeed
        self._run_mpp(
            graph,
            fail_kwargs={'alice_uses_trampoline': True, 'attempts': 1},
            success_kwargs={'alice_uses_trampoline': True, 'attempts': 30})

    @needs_test_with_all_chacha20_implementations
    def test_payment_multipart_trampoline_legacy(self):
        graph = self.prepare_chans_and_peers_in_graph(GRAPH_DEFINITIONS['square_graph'])
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
            graph.workers['carol'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['carol'].node_keypair.pubkey),
        }
        # trampoline-to-legacy: this is restricted, as there are no forwarders capable of doing this
        self._run_mpp(
            graph,
            fail_kwargs={'alice_uses_trampoline': True, 'attempts': 30, 'disable_trampoline_receiving': True},
            success_kwargs={})

    @needs_test_with_all_chacha20_implementations
    def test_fail_pending_htlcs_on_shutdown(self):
        """Alice tries to pay Dave via MPP. Dave receives some HTLCs but not all.
        Dave shuts down (stops wallet).
        We test if Dave fails the pending HTLCs during shutdown.
        """
        graph = self.prepare_chans_and_peers_in_graph(GRAPH_DEFINITIONS['square_graph'])
        self.assertEqual(500_000_000_000, graph.channels[('alice', 'bob')].balance(LOCAL))
        self.assertEqual(500_000_000_000, graph.channels[('alice', 'carol')].balance(LOCAL))
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
            hm = graph.channels[('dave', 'carol')].hm
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
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_legacy_shutdown_low(self):
        self._test_shutdown(alice_fee=100, bob_fee=150)

    @needs_test_with_all_chacha20_implementations
    def test_legacy_shutdown_high(self):
        self._test_shutdown(alice_fee=2000, bob_fee=100)

    @needs_test_with_all_chacha20_implementations
    def test_modern_shutdown_with_overlap(self):
        self._test_shutdown(
            alice_fee=1,
            bob_fee=200,
            alice_fee_range={'min_fee_satoshis': 1, 'max_fee_satoshis': 10},
            bob_fee_range={'min_fee_satoshis': 10, 'max_fee_satoshis': 300})

    ## This test works but it is too slow (LN_P2P_NETWORK_TIMEOUT)
    ## because tests do not use a proper LNWorker object
    #@needs_test_with_all_chacha20_implementations
    #def test_modern_shutdown_no_overlap(self):
    #    self.assertRaises(Exception, lambda: asyncio.run(
    #        self._test_shutdown(
    #            alice_fee=1,
    #            bob_fee=200,
    #            alice_fee_range={'min_fee_satoshis': 1, 'max_fee_satoshis': 10},
    #            bob_fee_range={'min_fee_satoshis': 50, 'max_fee_satoshis': 300})
    #    ))

    def _test_shutdown(self, alice_fee, bob_fee, alice_fee_range=None, bob_fee_range=None):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.set_key('test_shutdown_fee', alice_fee)
        w2.network.config.set_key('test_shutdown_fee', bob_fee)
        if alice_fee_range is not None:
            w1.network.config.set_key('test_shutdown_fee_range', alice_fee_range)
        else:
            w1.network.config.set_key('test_shutdown_legacy', True)
        if bob_fee_range is not None:
            w2.network.config.set_key('test_shutdown_fee_range', bob_fee_range)
        else:
            w2.network.config.set_key('test_shutdown_legacy', True)
        w2.enable_htlc_settle = False
        lnaddr, pay_req = self.prepare_invoice(w2)
        async def pay():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
            # alice sends htlc
            route, amount_msat = (await w1.create_routes_from_invoice(lnaddr.get_amount_msat(), decoded_invoice=lnaddr))[0][0:2]
            p1.pay(route=route,
                   chan=alice_channel,
                   amount_msat=lnaddr.get_amount_msat(),
                   total_msat=lnaddr.get_amount_msat(),
                   payment_hash=lnaddr.paymenthash,
                   min_final_cltv_expiry=lnaddr.get_min_final_cltv_expiry(),
                   payment_secret=lnaddr.payment_secret)
            # alice closes
            await p1.close_channel(alice_channel.channel_id)
            gath.cancel()
        async def set_settle():
            await asyncio.sleep(0.1)
            w2.enable_htlc_settle = True
        gath = asyncio.gather(pay(), set_settle(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_warning(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

        async def action():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
            await p1.send_warning(alice_channel.channel_id, 'be warned!', close_connection=True)
        gath = asyncio.gather(action(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(GracefulDisconnect):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_error(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

        async def action():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
            await p1.send_error(alice_channel.channel_id, 'some error happened!', force_close_channel=True)
            assert alice_channel.is_closed()
            gath.cancel()
        gath = asyncio.gather(action(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(GracefulDisconnect):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_close_upfront_shutdown_script(self):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)

        # create upfront shutdown script for bob, alice doesn't use upfront
        # shutdown script
        bob_uss_pub = lnutil.privkey_to_pubkey(os.urandom(32))
        bob_uss_addr = bitcoin.pubkey_to_address('p2wpkh', bh2u(bob_uss_pub))
        bob_uss = bfh(bitcoin.address_to_script(bob_uss_addr))

        # bob commits to close to bob_uss
        alice_channel.config[HTLCOwner.REMOTE].upfront_shutdown_script = bob_uss
        # but bob closes to some receiving address, which we achieve by not
        # setting the upfront shutdown script in the channel config
        bob_channel.config[HTLCOwner.LOCAL].upfront_shutdown_script = b''

        p1, p2, w1, w2, q1, q2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.set_key('dynamic_fees', False)
        w2.network.config.set_key('dynamic_fees', False)
        w1.network.config.set_key('fee_per_kb', 5000)
        w2.network.config.set_key('fee_per_kb', 1000)

        async def test():
            async def close():
                await asyncio.wait_for(p1.initialized, 1)
                await asyncio.wait_for(p2.initialized, 1)
                # bob closes channel with different shutdown script
                await p1.close_channel(alice_channel.channel_id)
                gath.cancel()

            async def main_loop(peer):
                    async with peer.taskgroup as group:
                        await group.spawn(peer._message_loop())
                        await group.spawn(peer.htlc_switch())

            coros = [close(), main_loop(p1), main_loop(p2)]
            gath = asyncio.gather(*coros)
            await gath

        with self.assertRaises(GracefulDisconnect):
            run(test())

        # bob sends the same upfront_shutdown_script has he announced
        alice_channel.config[HTLCOwner.REMOTE].upfront_shutdown_script = bob_uss
        bob_channel.config[HTLCOwner.LOCAL].upfront_shutdown_script = bob_uss

        p1, p2, w1, w2, q1, q2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.set_key('dynamic_fees', False)
        w2.network.config.set_key('dynamic_fees', False)
        w1.network.config.set_key('fee_per_kb', 5000)
        w2.network.config.set_key('fee_per_kb', 1000)

        async def test():
            async def close():
                await asyncio.wait_for(p1.initialized, 1)
                await asyncio.wait_for(p2.initialized, 1)
                await p1.close_channel(alice_channel.channel_id)
                gath.cancel()

            async def main_loop(peer):
                async with peer.taskgroup as group:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())

            coros = [close(), main_loop(p1), main_loop(p2)]
            gath = asyncio.gather(*coros)
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(test())

    def test_channel_usage_after_closing(self):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        p1, p2, w1, w2, q1, q2 = self.prepare_peers(alice_channel, bob_channel)
        lnaddr, pay_req = self.prepare_invoice(w2)

        lnaddr = w1._check_invoice(pay_req)
        route, amount_msat = run(w1.create_routes_from_invoice(lnaddr.get_amount_msat(), decoded_invoice=lnaddr))[0][0:2]
        assert amount_msat == lnaddr.get_amount_msat()

        run(w1.force_close_channel(alice_channel.channel_id))
        # check if a tx (commitment transaction) was broadcasted:
        assert q1.qsize() == 1

        with self.assertRaises(NoPathFound) as e:
            run(w1.create_routes_from_invoice(lnaddr.get_amount_msat(), decoded_invoice=lnaddr))

        peer = w1.peers[route[0].node_id]
        # AssertionError is ok since we shouldn't use old routes, and the
        # route finding should fail when channel is closed
        async def f():
            min_cltv_expiry = lnaddr.get_min_final_cltv_expiry()
            payment_hash = lnaddr.paymenthash
            payment_secret = lnaddr.payment_secret
            pay = w1.pay_to_route(
                route=route,
                amount_msat=amount_msat,
                total_msat=amount_msat,
                amount_receiver_msat=amount_msat,
                payment_hash=payment_hash,
                payment_secret=payment_secret,
                min_cltv_expiry=min_cltv_expiry,
                trampoline_fee_level=0,
                trampoline_route=None,
            )
            await asyncio.gather(pay, p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(PaymentFailure):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_sending_weird_messages_that_should_be_ignored(self):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

        async def send_weird_messages():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
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
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_sending_weird_messages__unknown_even_type(self):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

        async def send_weird_messages():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
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

        with self.assertRaises(lnmsg.UnknownMandatoryMsgType):
            run(f())
        self.assertTrue(isinstance(failing_task.exception(), lnmsg.UnknownMandatoryMsgType))

    @needs_test_with_all_chacha20_implementations
    def test_sending_weird_messages__known_msg_with_insufficient_length(self):
        alice_channel, bob_channel = create_test_channels(anchor_outputs=self.TEST_ANCHOR_CHANNELS)
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

        async def send_weird_messages():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
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

        with self.assertRaises(lnmsg.UnexpectedEndOfStream):
            run(f())
        self.assertTrue(isinstance(failing_task.exception(), lnmsg.UnexpectedEndOfStream))


class TestPeerAnchors(TestCaseForTestnet):
    TEST_ANCHOR_CHANNELS = True


def run(coro):
    return asyncio.run_coroutine_threadsafe(coro, loop=util.get_asyncio_loop()).result()
