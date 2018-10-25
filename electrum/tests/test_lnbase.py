from electrum.lnbase import Peer, decode_msg, gen_msg
from electrum.lnutil import LNPeerAddr, Keypair, privkey_to_pubkey
from electrum.lnutil import LightningPeerConnectionClosed, RemoteMisbehaving
from electrum.ecc import ECPrivkey
from electrum.lnrouter import ChannelDB
import unittest
import asyncio
from electrum import simple_config
import tempfile
from .test_lnchan import create_test_channels

class MockNetwork:
    def __init__(self):
        self.lnwatcher = None
        user_config = {}
        user_dir = tempfile.mkdtemp(prefix="electrum-lnbase-test-")
        self.config = simple_config.SimpleConfig(user_config, read_user_dir_function=lambda: user_dir)
        self.asyncio_loop = asyncio.get_event_loop()
        self.channel_db = ChannelDB(self)
        self.interface = None
    def register_callback(self, cb, trigger_names):
        print("callback registered", repr(trigger_names))
    def trigger_callback(self, trigger_name, obj):
        print("callback triggered", repr(trigger_name))

class MockLNWorker:
    def __init__(self, remote_peer_pubkey, chan):
        self.chan = chan
        self.remote_peer_pubkey = remote_peer_pubkey
        priv = ECPrivkey.generate_random_key().get_secret_bytes()
        self.node_keypair = Keypair(
                pubkey=privkey_to_pubkey(priv),
                privkey=priv)
        self.network = MockNetwork()
    @property
    def peers(self):
        return {self.remote_peer_pubkey: self.peer}
    def channels_for_peer(self, pubkey):
        return {self.chan.channel_id: self.chan}

class MockTransport:
    def __init__(self):
        self.queue = asyncio.Queue()
    async def read_messages(self):
        while True:
            yield await self.queue.get()

class BadFeaturesTransport(MockTransport):
    def send_bytes(self, data):
        decoded = decode_msg(data)
        print(decoded)
        if decoded[0] == 'init':
            self.queue.put_nowait(gen_msg('init', lflen=1, gflen=1, localfeatures=b"\x00", globalfeatures=b"\x00"))

class TestPeer(unittest.TestCase):
    def setUp(self):
        self.alice_channel, self.bob_channel = create_test_channels()
    def test_bad_feature_flags(self):
        # we should require DATA_LOSS_PROTECT
        mock_lnworker = MockLNWorker(b"\x00" * 32, self.alice_channel)
        mock_transport = BadFeaturesTransport()
        p1 = Peer(mock_lnworker, LNPeerAddr("bogus", 1337, b"\x00" * 32), request_initial_sync=False, transport=mock_transport)
        mock_lnworker.peer = p1
        with self.assertRaises(LightningPeerConnectionClosed):
            asyncio.get_event_loop().run_until_complete(asyncio.wait_for(p1._main_loop(), 1))

