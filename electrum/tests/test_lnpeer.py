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

from aiorpcx import TaskGroup

from electrum import constants
from electrum.network import Network
from electrum.ecc import ECPrivkey
from electrum import simple_config, lnutil
from electrum.lnaddr import lnencode, LnAddr, lndecode
from electrum.bitcoin import COIN, sha256
from electrum.util import bh2u, create_and_start_event_loop
from electrum.lnpeer import Peer
from electrum.lnutil import LNPeerAddr, Keypair, privkey_to_pubkey
from electrum.lnutil import LightningPeerConnectionClosed, RemoteMisbehaving
from electrum.lnutil import PaymentFailure, LnLocalFeatures, HTLCOwner
from electrum.lnchannel import channel_states, peer_states, Channel
from electrum.lnrouter import LNPathFinder
from electrum.channel_db import ChannelDB
from electrum.lnworker import LNWallet, NoPathFound
from electrum.lnmsg import encode_msg, decode_msg
from electrum.logging import console_stderr_handler, Logger
from electrum.lnworker import PaymentInfo, RECEIVED, PR_UNPAID

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
        self.path_finder = LNPathFinder(self.channel_db)
        self.tx_queue = tx_queue

    @property
    def callback_lock(self):
        return noop_lock()

    register_callback = Network.register_callback
    unregister_callback = Network.unregister_callback
    trigger_callback = Network.trigger_callback

    def get_local_height(self):
        return 0

    async def broadcast_transaction(self, tx):
        if self.tx_queue:
            await self.tx_queue.put(tx)

    async def try_broadcasting(self, tx, name):
        self.broadcast_transaction(tx)

class MockWallet:
    def set_label(self, x, y):
        pass
    def save_db(self):
        pass
    def is_lightning_backup(self):
        return False

class MockLNWallet(Logger):
    def __init__(self, remote_keypair, local_keypair, chan: 'Channel', tx_queue):
        Logger.__init__(self)
        self.remote_keypair = remote_keypair
        self.node_keypair = local_keypair
        self.network = MockNetwork(tx_queue)
        self.channels = {chan.channel_id: chan}
        self.payments = {}
        self.logs = defaultdict(list)
        self.wallet = MockWallet()
        self.localfeatures = LnLocalFeatures(0)
        self.localfeatures |= LnLocalFeatures.OPTION_DATA_LOSS_PROTECT_OPT
        self.pending_payments = defaultdict(asyncio.Future)
        chan.lnworker = self
        chan.node_id = remote_keypair.pubkey
        # used in tests
        self.enable_htlc_settle = asyncio.Event()
        self.enable_htlc_settle.set()

    def get_invoice_status(self, key):
        pass

    @property
    def lock(self):
        return noop_lock()

    @property
    def peers(self):
        return {self.remote_keypair.pubkey: self.peer}

    def channels_for_peer(self, pubkey):
        return self.channels

    def get_channel_by_short_id(self, short_channel_id):
        with self.lock:
            for chan in self.channels.values():
                if chan.short_channel_id == short_channel_id:
                    return chan

    def save_channel(self, chan):
        print("Ignoring channel save")

    preimages = {}
    get_payment_info = LNWallet.get_payment_info
    save_payment_info = LNWallet.save_payment_info
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
    def __init__(self, name):
        super().__init__(name)
        self.other_mock_transport = None

    def send_bytes(self, data):
        self.other_mock_transport.queue.put_nowait(data)

def transport_pair(name1, name2):
    t1 = PutIntoOthersQueueTransport(name1)
    t2 = PutIntoOthersQueueTransport(name2)
    t1.other_mock_transport = t2
    t2.other_mock_transport = t1
    return t1, t2

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
        t1, t2 = transport_pair(alice_channel.name, bob_channel.name)
        q1, q2 = asyncio.Queue(), asyncio.Queue()
        w1 = MockLNWallet(k1, k2, alice_channel, tx_queue=q1)
        w2 = MockLNWallet(k2, k1, bob_channel, tx_queue=q2)
        p1 = Peer(w1, k1.pubkey, t1)
        p2 = Peer(w2, k2.pubkey, t2)
        w1.peer = p1
        w2.peer = p2
        # mark_open won't work if state is already OPEN.
        # so set it to FUNDED
        alice_channel._state = channel_states.FUNDED
        bob_channel._state = channel_states.FUNDED
        # this populates the channel graph:
        p1.mark_open(alice_channel)
        p2.mark_open(bob_channel)
        return p1, p2, w1, w2, q1, q2

    @staticmethod
    def prepare_invoice(
            w2,  # receiver
            *,
            amount_sat=100_000,
    ):
        amount_btc = amount_sat/Decimal(COIN)
        payment_preimage = os.urandom(32)
        RHASH = sha256(payment_preimage)
        info = PaymentInfo(RHASH, amount_sat, RECEIVED, PR_UNPAID)
        w2.save_preimage(RHASH, payment_preimage)
        w2.save_payment_info(info)
        lnaddr = LnAddr(
                    RHASH,
                    amount_btc,
                    tags=[('c', lnutil.MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE),
                          ('d', 'coffee')
                         ])
        return lnencode(lnaddr, w2.node_keypair.privkey)

    def test_reestablish(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        for chan in (alice_channel, bob_channel):
            chan.peer_state = peer_states.DISCONNECTED
        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            self.assertEqual(alice_channel.peer_state, peer_states.GOOD)
            self.assertEqual(bob_channel.peer_state, peer_states.GOOD)
            gath.cancel()
        gath = asyncio.gather(reestablish(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p1.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_reestablish_with_old_state(self):
        alice_channel, bob_channel = create_test_channels()
        alice_channel_0, bob_channel_0 = create_test_channels() # these are identical
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        pay_req = self.prepare_invoice(w2)
        async def pay():
            result = await w1._pay(pay_req)
            self.assertEqual(result, True)
            gath.cancel()
        gath = asyncio.gather(pay(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())

        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel_0, bob_channel)
        for chan in (alice_channel_0, bob_channel):
            chan.peer_state = peer_states.DISCONNECTED
        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel_0),
                p2.reestablish_channel(bob_channel))
            self.assertEqual(alice_channel_0.peer_state, peer_states.BAD)
            self.assertEqual(bob_channel._state, channel_states.FORCE_CLOSING)
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
        pay_req = self.prepare_invoice(w2)
        async def pay():
            result = await w1._pay(pay_req)
            self.assertTrue(result)
            gath.cancel()
        gath = asyncio.gather(pay(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())

    #@unittest.skip("too expensive")
    #@needs_test_with_all_chacha20_implementations
    def test_payments_stresstest(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        alice_init_balance_msat = alice_channel.balance(HTLCOwner.LOCAL)
        bob_init_balance_msat = bob_channel.balance(HTLCOwner.LOCAL)
        num_payments = 50
        #pay_reqs1 = [self.prepare_invoice(w1, amount_sat=1) for i in range(num_payments)]
        pay_reqs2 = [self.prepare_invoice(w2, amount_sat=1) for i in range(num_payments)]
        max_htlcs_in_flight = asyncio.Semaphore(5)
        async def single_payment(pay_req):
            async with max_htlcs_in_flight:
                await w1._pay(pay_req)
        async def many_payments():
            async with TaskGroup() as group:
                for pay_req in pay_reqs2:
                    await group.spawn(single_payment(pay_req))
            gath.cancel()
        gath = asyncio.gather(many_payments(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        async def f():
            await gath
        with self.assertRaises(concurrent.futures.CancelledError):
            run(f())
        self.assertEqual(alice_init_balance_msat - num_payments * 1000, alice_channel.balance(HTLCOwner.LOCAL))
        self.assertEqual(alice_init_balance_msat - num_payments * 1000, bob_channel.balance(HTLCOwner.REMOTE))
        self.assertEqual(bob_init_balance_msat + num_payments * 1000, bob_channel.balance(HTLCOwner.LOCAL))
        self.assertEqual(bob_init_balance_msat + num_payments * 1000, alice_channel.balance(HTLCOwner.REMOTE))

    @needs_test_with_all_chacha20_implementations
    def test_close(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.set_key('dynamic_fees', False)
        w2.network.config.set_key('dynamic_fees', False)
        w1.network.config.set_key('fee_per_kb', 5000)
        w2.network.config.set_key('fee_per_kb', 1000)
        w2.enable_htlc_settle.clear()
        pay_req = self.prepare_invoice(w2)
        lnaddr = lndecode(pay_req, expected_hrp=constants.net.SEGWIT_HRP)
        async def pay():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
            # alice sends htlc
            route = await w1._create_route_from_invoice(decoded_invoice=lnaddr)
            htlc = p1.pay(route, alice_channel, int(lnaddr.amount * COIN * 1000), lnaddr.paymenthash, lnaddr.get_min_final_cltv_expiry())
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
        pay_req = self.prepare_invoice(w2)

        addr = w1._check_invoice(pay_req)
        route = run(w1._create_route_from_invoice(decoded_invoice=addr))

        run(w1.force_close_channel(alice_channel.channel_id))
        # check if a tx (commitment transaction) was broadcasted:
        assert q1.qsize() == 1

        with self.assertRaises(NoPathFound) as e:
            run(w1._create_route_from_invoice(decoded_invoice=addr))

        peer = w1.peers[route[0].node_id]
        # AssertionError is ok since we shouldn't use old routes, and the
        # route finding should fail when channel is closed
        async def f():
            await asyncio.gather(w1._pay_to_route(route, addr), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(PaymentFailure):
            run(f())


def run(coro):
    return asyncio.run_coroutine_threadsafe(coro, loop=asyncio.get_event_loop()).result()
