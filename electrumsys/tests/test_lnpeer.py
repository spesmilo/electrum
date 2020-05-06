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
from typing import Iterable

from aiorpcx import TaskGroup

from electrumsys import constants
from electrumsys.network import Network
from electrumsys.ecc import ECPrivkey
from electrumsys import simple_config, lnutil
from electrumsys.lnaddr import lnencode, LnAddr, lndecode
from electrumsys.bitcoin import COIN, sha256
from electrumsys.util import bh2u, create_and_start_event_loop, NetworkRetryManager
from electrumsys.lnpeer import Peer
from electrumsys.lnutil import LNPeerAddr, Keypair, privkey_to_pubkey
from electrumsys.lnutil import LightningPeerConnectionClosed, RemoteMisbehaving
from electrumsys.lnutil import PaymentFailure, LnFeatures, HTLCOwner
from electrumsys.lnchannel import ChannelState, PeerState, Channel
from electrumsys.lnrouter import LNPathFinder
from electrumsys.channel_db import ChannelDB
from electrumsys.lnworker import LNWallet, NoPathFound
from electrumsys.lnmsg import encode_msg, decode_msg
from electrumsys.logging import console_stderr_handler, Logger
from electrumsys.lnworker import PaymentInfo, RECEIVED, PR_UNPAID

from .test_lnchannel import create_test_channels
from .test_bitcoin import needs_test_with_all_chacha20_implementations
from . import ElectrumSysTestCase

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
        user_dir = tempfile.mkdtemp(prefix="electrumsys-lnpeer-test-")
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


class PaymentDone(Exception): pass


class TestPeer(ElectrumSysTestCase):

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
                          amount_msat=int(lnaddr.amount * COIN * 1000),
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
