import asyncio
import tempfile
from decimal import Decimal
import os
from contextlib import contextmanager
from collections import defaultdict
import logging
import concurrent
from concurrent import futures
import unittest
from typing import Iterable, NamedTuple

from aiorpcx import TaskGroup

from electrum import constants
from electrum.network import Network
from electrum.ecc import ECPrivkey
from electrum import simple_config, lnutil
from electrum.lnaddr import lnencode, LnAddr, lndecode
from electrum.bitcoin import COIN, sha256
from electrum.util import bh2u, create_and_start_event_loop, NetworkRetryManager
from electrum.lnpeer import Peer
from electrum.lnutil import LNPeerAddr, Keypair, privkey_to_pubkey
from electrum.lnutil import LightningPeerConnectionClosed, RemoteMisbehaving
from electrum.lnutil import PaymentFailure, LnFeatures, HTLCOwner
from electrum.lnchannel import ChannelState, PeerState, Channel
from electrum.lnrouter import LNPathFinder, PathEdge, LNPathInconsistent
from electrum.channel_db import ChannelDB
from electrum.lnworker import LNWallet, NoPathFound
from electrum.lnmsg import encode_msg, decode_msg
from electrum.logging import console_stderr_handler, Logger
from electrum.lnworker import PaymentInfo, RECEIVED, PR_UNPAID
from electrum.lnonion import OnionFailureCode

from .test_lnchannel import create_test_channels
from .test_bitcoin import needs_test_with_all_chacha20_implementations
from . import ElectrumTestCase

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
    def __init__(self, tx_queue):
        self.callbacks = defaultdict(list)
        self.lnwatcher = None
        self.interface = None
        user_config = {}
        user_dir = tempfile.mkdtemp(prefix="electrum-lnpeer-test-")
        self.config = simple_config.SimpleConfig(user_config, read_user_dir_function=lambda: user_dir)
        self.asyncio_loop = asyncio.get_event_loop()
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


class MockWallet:

    def set_label(self, x, y):
        pass

    def save_db(self):
        pass

    def add_transaction(self, tx):
        pass

    def is_lightning_backup(self):
        return False


class MockLNWallet(Logger, NetworkRetryManager[LNPeerAddr]):
    def __init__(self, *, local_keypair: Keypair, chans: Iterable['Channel'], tx_queue):
        Logger.__init__(self)
        NetworkRetryManager.__init__(self, max_retry_delay_normal=1, init_retry_delay_normal=1)
        self.node_keypair = local_keypair
        self.network = MockNetwork(tx_queue)
        self.channel_db = self.network.channel_db
        self._channels = {chan.channel_id: chan
                          for chan in chans}
        self.payments = {}
        self.logs = defaultdict(list)
        self.wallet = MockWallet()
        self.features = LnFeatures(0)
        self.features |= LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT
        self.pending_payments = defaultdict(asyncio.Future)
        for chan in chans:
            chan.lnworker = self
        self._peers = {}  # bytes -> Peer
        # used in tests
        self.enable_htlc_settle = asyncio.Event()
        self.enable_htlc_settle.set()

    def get_invoice_status(self, key):
        pass

    @property
    def lock(self):
        return noop_lock()

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

    is_routing = set()
    preimages = {}
    get_payment_info = LNWallet.get_payment_info
    save_payment_info = LNWallet.save_payment_info
    set_invoice_status = LNWallet.set_invoice_status
    set_payment_status = LNWallet.set_payment_status
    get_payment_status = LNWallet.get_payment_status
    await_payment = LNWallet.await_payment
    payment_received = LNWallet.payment_received
    payment_sent = LNWallet.payment_sent
    payment_failed = LNWallet.payment_failed
    save_preimage = LNWallet.save_preimage
    get_preimage = LNWallet.get_preimage
    _create_route_from_invoice = LNWallet._create_route_from_invoice
    _check_invoice = staticmethod(LNWallet._check_invoice)
    _pay_to_route = LNWallet._pay_to_route
    _pay = LNWallet._pay
    force_close_channel = LNWallet.force_close_channel
    try_force_closing = LNWallet.try_force_closing
    get_first_timestamp = lambda self: 0
    on_peer_successfully_established = LNWallet.on_peer_successfully_established
    get_channel_by_id = LNWallet.get_channel_by_id
    channels_for_peer = LNWallet.channels_for_peer
    _calc_routing_hints_for_invoice = LNWallet._calc_routing_hints_for_invoice
    handle_error_code_from_failed_htlc = LNWallet.handle_error_code_from_failed_htlc


class MockTransport:
    def __init__(self, name):
        self.queue = asyncio.Queue()
        self._name = name

    def name(self):
        return self._name

    async def read_messages(self):
        while True:
            yield await self.queue.get()

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
    t1 = PutIntoOthersQueueTransport(k1, name2)
    t2 = PutIntoOthersQueueTransport(k2, name1)
    t1.other_mock_transport = t2
    t2.other_mock_transport = t1
    return t1, t2


class SquareGraph(NamedTuple):
    #        A
    #      /   \
    #     B     C
    #      \   /
    #        D
    w_a: MockLNWallet
    w_b: MockLNWallet
    w_c: MockLNWallet
    w_d: MockLNWallet
    peer_ab: Peer
    peer_ac: Peer
    peer_ba: Peer
    peer_bd: Peer
    peer_ca: Peer
    peer_cd: Peer
    peer_db: Peer
    peer_dc: Peer
    chan_ab: Channel
    chan_ac: Channel
    chan_ba: Channel
    chan_bd: Channel
    chan_ca: Channel
    chan_cd: Channel
    chan_db: Channel
    chan_dc: Channel

    def all_peers(self) -> Iterable[Peer]:
        return self.peer_ab, self.peer_ac, self.peer_ba, self.peer_bd, self.peer_ca, self.peer_cd, self.peer_db, self.peer_dc


class PaymentDone(Exception): pass


class TestPeer(ElectrumTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()
        self.asyncio_loop, self._stop_loop, self._loop_thread = create_and_start_event_loop()

    def tearDown(self):
        super().tearDown()
        self.asyncio_loop.call_soon_threadsafe(self._stop_loop.set_result, 1)
        self._loop_thread.join(timeout=1)

    def prepare_peers(self, alice_channel, bob_channel):
        k1, k2 = keypair(), keypair()
        alice_channel.node_id = k2.pubkey
        bob_channel.node_id = k1.pubkey
        t1, t2 = transport_pair(k1, k2, alice_channel.name, bob_channel.name)
        q1, q2 = asyncio.Queue(), asyncio.Queue()
        w1 = MockLNWallet(local_keypair=k1, chans=[alice_channel], tx_queue=q1)
        w2 = MockLNWallet(local_keypair=k2, chans=[bob_channel], tx_queue=q2)
        p1 = Peer(w1, k2.pubkey, t1)
        p2 = Peer(w2, k1.pubkey, t2)
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

    def prepare_chans_and_peers_in_square(self) -> SquareGraph:
        key_a, key_b, key_c, key_d = [keypair() for i in range(4)]
        chan_ab, chan_ba = create_test_channels(alice_name="alice", bob_name="bob", alice_pubkey=key_a.pubkey, bob_pubkey=key_b.pubkey)
        chan_ac, chan_ca = create_test_channels(alice_name="alice", bob_name="carol", alice_pubkey=key_a.pubkey, bob_pubkey=key_c.pubkey)
        chan_bd, chan_db = create_test_channels(alice_name="bob", bob_name="dave", alice_pubkey=key_b.pubkey, bob_pubkey=key_d.pubkey)
        chan_cd, chan_dc = create_test_channels(alice_name="carol", bob_name="dave", alice_pubkey=key_c.pubkey, bob_pubkey=key_d.pubkey)
        trans_ab, trans_ba = transport_pair(key_a, key_b, chan_ab.name, chan_ba.name)
        trans_ac, trans_ca = transport_pair(key_a, key_c, chan_ac.name, chan_ca.name)
        trans_bd, trans_db = transport_pair(key_b, key_d, chan_bd.name, chan_db.name)
        trans_cd, trans_dc = transport_pair(key_c, key_d, chan_cd.name, chan_dc.name)
        txq_a, txq_b, txq_c, txq_d = [asyncio.Queue() for i in range(4)]
        w_a = MockLNWallet(local_keypair=key_a, chans=[chan_ab, chan_ac], tx_queue=txq_a)
        w_b = MockLNWallet(local_keypair=key_b, chans=[chan_ba, chan_bd], tx_queue=txq_b)
        w_c = MockLNWallet(local_keypair=key_c, chans=[chan_ca, chan_cd], tx_queue=txq_c)
        w_d = MockLNWallet(local_keypair=key_d, chans=[chan_db, chan_dc], tx_queue=txq_d)
        peer_ab = Peer(w_a, key_b.pubkey, trans_ab)
        peer_ac = Peer(w_a, key_c.pubkey, trans_ac)
        peer_ba = Peer(w_b, key_a.pubkey, trans_ba)
        peer_bd = Peer(w_b, key_d.pubkey, trans_bd)
        peer_ca = Peer(w_c, key_a.pubkey, trans_ca)
        peer_cd = Peer(w_c, key_d.pubkey, trans_cd)
        peer_db = Peer(w_d, key_b.pubkey, trans_db)
        peer_dc = Peer(w_d, key_c.pubkey, trans_dc)
        w_a._peers[peer_ab.pubkey] = peer_ab
        w_a._peers[peer_ac.pubkey] = peer_ac
        w_b._peers[peer_ba.pubkey] = peer_ba
        w_b._peers[peer_bd.pubkey] = peer_bd
        w_c._peers[peer_ca.pubkey] = peer_ca
        w_c._peers[peer_cd.pubkey] = peer_cd
        w_d._peers[peer_db.pubkey] = peer_db
        w_d._peers[peer_dc.pubkey] = peer_dc

        w_b.network.config.set_key('lightning_forward_payments', True)
        w_c.network.config.set_key('lightning_forward_payments', True)

        # mark_open won't work if state is already OPEN.
        # so set it to FUNDED
        for chan in [chan_ab, chan_ac, chan_ba, chan_bd, chan_ca, chan_cd, chan_db, chan_dc]:
            chan._state = ChannelState.FUNDED
        # this populates the channel graph:
        peer_ab.mark_open(chan_ab)
        peer_ac.mark_open(chan_ac)
        peer_ba.mark_open(chan_ba)
        peer_bd.mark_open(chan_bd)
        peer_ca.mark_open(chan_ca)
        peer_cd.mark_open(chan_cd)
        peer_db.mark_open(chan_db)
        peer_dc.mark_open(chan_dc)
        return SquareGraph(
            w_a=w_a,
            w_b=w_b,
            w_c=w_c,
            w_d=w_d,
            peer_ab=peer_ab,
            peer_ac=peer_ac,
            peer_ba=peer_ba,
            peer_bd=peer_bd,
            peer_ca=peer_ca,
            peer_cd=peer_cd,
            peer_db=peer_db,
            peer_dc=peer_dc,
            chan_ab=chan_ab,
            chan_ac=chan_ac,
            chan_ba=chan_ba,
            chan_bd=chan_bd,
            chan_ca=chan_ca,
            chan_cd=chan_cd,
            chan_db=chan_db,
            chan_dc=chan_dc,
        )

    @staticmethod
    async def prepare_invoice(
            w2: MockLNWallet,  # receiver
            *,
            amount_sat=100_000,
            include_routing_hints=False,
    ):
        amount_btc = amount_sat/Decimal(COIN)
        payment_preimage = os.urandom(32)
        RHASH = sha256(payment_preimage)
        info = PaymentInfo(RHASH, amount_sat, RECEIVED, PR_UNPAID)
        w2.save_preimage(RHASH, payment_preimage)
        w2.save_payment_info(info)
        if include_routing_hints:
            routing_hints = await w2._calc_routing_hints_for_invoice(amount_sat)
        else:
            routing_hints = []
        lnaddr = LnAddr(
                    paymenthash=RHASH,
                    amount=amount_btc,
                    tags=[('c', lnutil.MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE),
                          ('d', 'coffee')
                         ] + routing_hints)
        return lnencode(lnaddr, w2.node_keypair.privkey)

    def test_reestablish(self):
        alice_channel, bob_channel = create_test_channels()
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
        alice_channel, bob_channel = create_test_channels(random_seed=random_seed)
        alice_channel_0, bob_channel_0 = create_test_channels(random_seed=random_seed)  # these are identical
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        pay_req = run(self.prepare_invoice(w2))
        async def pay():
            result, log = await w1._pay(pay_req)
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
            self.assertEqual(alice_channel_0.peer_state, PeerState.BAD)
            self.assertEqual(bob_channel._state, ChannelState.FORCE_CLOSING)
            # wait so that pending messages are processed
            #await asyncio.sleep(1)
            gath.cancel()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        async def pay(pay_req):
            result, log = await w1._pay(pay_req)
            self.assertTrue(result)
            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                pay_req = await self.prepare_invoice(w2)
                await group.spawn(pay(pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    #@unittest.skip("too expensive")
    #@needs_test_with_all_chacha20_implementations
    def test_payments_stresstest(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        alice_init_balance_msat = alice_channel.balance(HTLCOwner.LOCAL)
        bob_init_balance_msat = bob_channel.balance(HTLCOwner.LOCAL)
        num_payments = 50
        payment_value_sat = 10000  # make it large enough so that there are actually HTLCs on the ctx
        max_htlcs_in_flight = asyncio.Semaphore(5)
        async def single_payment(pay_req):
            async with max_htlcs_in_flight:
                await w1._pay(pay_req)
        async def many_payments():
            async with TaskGroup() as group:
                pay_reqs_tasks = [await group.spawn(self.prepare_invoice(w2, amount_sat=payment_value_sat))
                                  for i in range(num_payments)]
            async with TaskGroup() as group:
                for pay_req_task in pay_reqs_tasks:
                    pay_req = pay_req_task.result()
                    await group.spawn(single_payment(pay_req))
            gath.cancel()
        gath = asyncio.gather(many_payments(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())
        self.assertEqual(alice_init_balance_msat - num_payments * payment_value_sat * 1000, alice_channel.balance(HTLCOwner.LOCAL))
        self.assertEqual(alice_init_balance_msat - num_payments * payment_value_sat * 1000, bob_channel.balance(HTLCOwner.REMOTE))
        self.assertEqual(bob_init_balance_msat + num_payments * payment_value_sat * 1000, bob_channel.balance(HTLCOwner.LOCAL))
        self.assertEqual(bob_init_balance_msat + num_payments * payment_value_sat * 1000, alice_channel.balance(HTLCOwner.REMOTE))

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop(self):
        graph = self.prepare_chans_and_peers_in_square()
        peers = graph.all_peers()
        async def pay(pay_req):
            result, log = await graph.w_a._pay(pay_req)
            self.assertTrue(result)
            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                pay_req = await self.prepare_invoice(graph.w_d, include_routing_hints=True)
                await group.spawn(pay(pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop_with_preselected_path(self):
        graph = self.prepare_chans_and_peers_in_square()
        peers = graph.all_peers()
        async def pay(pay_req):
            with self.subTest(msg="bad path: edges do not chain together"):
                path = [PathEdge(node_id=graph.w_c.node_keypair.pubkey, short_channel_id=graph.chan_ab.short_channel_id),
                        PathEdge(node_id=graph.w_d.node_keypair.pubkey, short_channel_id=graph.chan_bd.short_channel_id)]
                result, log = await graph.w_a._pay(pay_req, full_path=path)
                self.assertFalse(result)
                self.assertTrue(isinstance(log[0].exception, LNPathInconsistent))
            with self.subTest(msg="bad path: last node id differs from invoice pubkey"):
                path = [PathEdge(node_id=graph.w_b.node_keypair.pubkey, short_channel_id=graph.chan_ab.short_channel_id)]
                result, log = await graph.w_a._pay(pay_req, full_path=path)
                self.assertFalse(result)
                self.assertTrue(isinstance(log[0].exception, LNPathInconsistent))
            with self.subTest(msg="good path"):
                path = [PathEdge(node_id=graph.w_b.node_keypair.pubkey, short_channel_id=graph.chan_ab.short_channel_id),
                        PathEdge(node_id=graph.w_d.node_keypair.pubkey, short_channel_id=graph.chan_bd.short_channel_id)]
                result, log = await graph.w_a._pay(pay_req, full_path=path)
                self.assertTrue(result)
                self.assertEqual([edge.short_channel_id for edge in path],
                                 [edge.short_channel_id for edge in log[0].route])
            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                pay_req = await self.prepare_invoice(graph.w_d, include_routing_hints=True)
                await group.spawn(pay(pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop_temp_node_failure(self):
        graph = self.prepare_chans_and_peers_in_square()
        graph.w_b.network.config.set_key('test_fail_htlcs_with_temp_node_failure', True)
        graph.w_c.network.config.set_key('test_fail_htlcs_with_temp_node_failure', True)
        peers = graph.all_peers()
        async def pay(pay_req):
            result, log = await graph.w_a._pay(pay_req)
            self.assertFalse(result)
            self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, log[0].failure_details.failure_msg.code)
            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                pay_req = await self.prepare_invoice(graph.w_d, include_routing_hints=True)
                await group.spawn(pay(pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_close(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.set_key('dynamic_fees', False)
        w2.network.config.set_key('dynamic_fees', False)
        w1.network.config.set_key('fee_per_kb', 5000)
        w2.network.config.set_key('fee_per_kb', 1000)
        w2.enable_htlc_settle.clear()
        pay_req = run(self.prepare_invoice(w2))
        lnaddr = lndecode(pay_req, expected_hrp=constants.net.SEGWIT_HRP)
        async def pay():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
            # alice sends htlc
            route = w1._create_route_from_invoice(decoded_invoice=lnaddr)
            htlc = p1.pay(route=route,
                          chan=alice_channel,
                          amount_msat=lnaddr.get_amount_msat(),
                          payment_hash=lnaddr.paymenthash,
                          min_final_cltv_expiry=lnaddr.get_min_final_cltv_expiry(),
                          payment_secret=lnaddr.payment_secret)
            # alice closes
            await p1.close_channel(alice_channel.channel_id)
            gath.cancel()
        async def set_settle():
            await asyncio.sleep(0.1)
            w2.enable_htlc_settle.set()
        gath = asyncio.gather(pay(), set_settle(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())

    def test_channel_usage_after_closing(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, q1, q2 = self.prepare_peers(alice_channel, bob_channel)
        pay_req = run(self.prepare_invoice(w2))

        addr = w1._check_invoice(pay_req)
        route = w1._create_route_from_invoice(decoded_invoice=addr)

        run(w1.force_close_channel(alice_channel.channel_id))
        # check if a tx (commitment transaction) was broadcasted:
        assert q1.qsize() == 1

        with self.assertRaises(NoPathFound) as e:
            w1._create_route_from_invoice(decoded_invoice=addr)

        peer = w1.peers[route[0].node_id]
        # AssertionError is ok since we shouldn't use old routes, and the
        # route finding should fail when channel is closed
        async def f():
            await asyncio.gather(w1._pay_to_route(route, addr), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(PaymentFailure):
            run(f())


def run(coro):
    return asyncio.run_coroutine_threadsafe(coro, loop=asyncio.get_event_loop()).result()
