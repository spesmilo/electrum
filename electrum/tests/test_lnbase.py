import unittest
import asyncio
import tempfile
from decimal import Decimal
import os
from contextlib import contextmanager
from collections import defaultdict

from electrum.network import Network
from electrum.ecc import ECPrivkey
from electrum import simple_config, lnutil
from electrum.lnaddr import lnencode, LnAddr, lndecode
from electrum.bitcoin import COIN, sha256
from electrum.util import bh2u

from electrum.lnbase import Peer, decode_msg, gen_msg
from electrum.lnutil import LNPeerAddr, Keypair, privkey_to_pubkey
from electrum.lnutil import LightningPeerConnectionClosed, RemoteMisbehaving
from electrum.lnutil import PaymentFailure
from electrum.lnrouter import ChannelDB, LNPathFinder
from electrum.lnworker import LNWorker

from .test_lnchan import create_test_channels

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
        user_config = {}
        user_dir = tempfile.mkdtemp(prefix="electrum-lnbase-test-")
        self.config = simple_config.SimpleConfig(user_config, read_user_dir_function=lambda: user_dir)
        self.asyncio_loop = asyncio.get_event_loop()
        self.channel_db = ChannelDB(self)
        self.interface = None
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

class MockStorage:
    def put(self, key, value):
        pass

    def get(self, key, default=None):
        pass

    def write(self):
        pass

class MockWallet:
    storage = MockStorage()

class MockLNWorker:
    def __init__(self, remote_keypair, local_keypair, chan, tx_queue):
        self.chan = chan
        self.remote_keypair = remote_keypair
        self.node_keypair = local_keypair
        self.network = MockNetwork(tx_queue)
        self.channels = {self.chan.channel_id: self.chan}
        self.invoices = {}
        self.paying = {}
        self.wallet = MockWallet()

    @property
    def lock(self):
        return noop_lock()

    @property
    def peers(self):
        return {self.remote_keypair.pubkey: self.peer}

    def channels_for_peer(self, pubkey):
        return self.channels

    def save_channel(self, chan):
        print("Ignoring channel save")

    def on_channels_updated(self):
        pass

    get_invoice = LNWorker.get_invoice
    _create_route_from_invoice = LNWorker._create_route_from_invoice
    _check_invoice = staticmethod(LNWorker._check_invoice)
    _pay_to_route = LNWorker._pay_to_route
    force_close_channel = LNWorker.force_close_channel

class MockTransport:
    def __init__(self):
        self.queue = asyncio.Queue()

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
            self.queue.put_nowait(gen_msg('init', lflen=1, gflen=1, localfeatures=b"\x00", globalfeatures=b"\x00"))

class PutIntoOthersQueueTransport(MockTransport):
    def __init__(self):
        super().__init__()
        self.other_mock_transport = None

    def send_bytes(self, data):
        self.other_mock_transport.queue.put_nowait(data)

def transport_pair():
    t1 = PutIntoOthersQueueTransport()
    t2 = PutIntoOthersQueueTransport()
    t1.other_mock_transport = t2
    t2.other_mock_transport = t1
    return t1, t2

class TestPeer(unittest.TestCase):
    def setUp(self):
        self.alice_channel, self.bob_channel = create_test_channels()

    def test_require_data_loss_protect(self):
        mock_lnworker = MockLNWorker(keypair(), keypair(), self.alice_channel, tx_queue=None)
        mock_transport = NoFeaturesTransport()
        p1 = Peer(mock_lnworker, LNPeerAddr("bogus", 1337, b"\x00" * 33), request_initial_sync=False, transport=mock_transport)
        mock_lnworker.peer = p1
        with self.assertRaises(LightningPeerConnectionClosed):
            run(asyncio.wait_for(p1._main_loop(), 1))

    def prepare_peers(self):
        k1, k2 = keypair(), keypair()
        t1, t2 = transport_pair()
        q1, q2 = asyncio.Queue(), asyncio.Queue()
        w1 = MockLNWorker(k1, k2, self.alice_channel, tx_queue=q1)
        w2 = MockLNWorker(k2, k1, self.bob_channel, tx_queue=q2)
        p1 = Peer(w1, LNPeerAddr("bogus1", 1337, k1.pubkey),
                request_initial_sync=False, transport=t1)
        p2 = Peer(w2, LNPeerAddr("bogus2", 1337, k2.pubkey),
                request_initial_sync=False, transport=t2)
        w1.peer = p1
        w2.peer = p2
        # mark_open won't work if state is already OPEN.
        # so set it to OPENING
        self.alice_channel.set_state("OPENING")
        self.bob_channel.set_state("OPENING")
        # this populates the channel graph:
        p1.mark_open(self.alice_channel)
        p2.mark_open(self.bob_channel)
        return p1, p2, w1, w2, q1, q2

    @staticmethod
    def prepare_invoice(w2 # receiver
            ):
        amount_btc = 100000/Decimal(COIN)
        payment_preimage = os.urandom(32)
        RHASH = sha256(payment_preimage)
        addr = LnAddr(
                    RHASH,
                    amount_btc,
                    tags=[('c', lnutil.MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE),
                          ('d', 'coffee')
                         ])
        pay_req = lnencode(addr, w2.node_keypair.privkey)
        w2.invoices[bh2u(RHASH)] = (bh2u(payment_preimage), pay_req)
        return pay_req

    @staticmethod
    def prepare_ln_message_future(w2 # receiver
            ):
        fut = asyncio.Future()
        def evt_set(event, _lnworker, msg):
            fut.set_result(msg)
        w2.network.register_callback(evt_set, ['ln_message'])
        return fut

    def test_payment(self):
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers()
        pay_req = self.prepare_invoice(w2)
        fut = self.prepare_ln_message_future(w2)

        async def pay():
            addr, peer, coro = LNWorker._pay(w1, pay_req)
            await coro
            print("HTLC ADDED")
            self.assertEqual(await fut, 'Payment received')
            gath.cancel()
        gath = asyncio.gather(pay(), p1._main_loop(), p2._main_loop())
        with self.assertRaises(asyncio.CancelledError):
            run(gath)

    def test_channel_usage_after_closing(self):
        p1, p2, w1, w2, q1, q2 = self.prepare_peers()
        pay_req = self.prepare_invoice(w2)

        addr = w1._check_invoice(pay_req)
        route = w1._create_route_from_invoice(decoded_invoice=addr)

        run(w1.force_close_channel(self.alice_channel.channel_id))
        # check if a tx (commitment transaction) was broadcasted:
        assert q1.qsize() == 1

        with self.assertRaises(PaymentFailure) as e:
            w1._create_route_from_invoice(decoded_invoice=addr)
        self.assertEqual(str(e.exception), 'No path found')

        peer = w1.peers[route[0].node_id]
        # AssertionError is ok since we shouldn't use old routes, and the
        # route finding should fail when channel is closed
        with self.assertRaises(AssertionError):
            run(asyncio.gather(w1._pay_to_route(route, addr), p1._main_loop(), p2._main_loop()))

def run(coro):
    asyncio.get_event_loop().run_until_complete(coro)
