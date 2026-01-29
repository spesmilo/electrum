import asyncio
import dataclasses
import shutil
import copy
import tempfile
from decimal import Decimal
import os
from contextlib import contextmanager
from collections import defaultdict
import logging
import concurrent
from concurrent import futures
from functools import lru_cache
from unittest import mock
from typing import Iterable, NamedTuple, Tuple, List, Dict, Sequence, Mapping
from types import MappingProxyType
import time
import statistics

from aiorpcx import timeout_after, TaskTimeout
from electrum_ecc import ECPrivkey

import electrum
import electrum.trampoline
from electrum import bitcoin
from electrum import util
from electrum import constants
from electrum import bip32
from electrum.network import Network, ProxySettings
from electrum import simple_config, lnutil
from electrum.lnaddr import lnencode, LnAddr, lndecode
from electrum.bitcoin import COIN, sha256
from electrum.transaction import Transaction
from electrum.util import NetworkRetryManager, bfh, OldTaskGroup, EventListener, InvoiceError
from electrum.lnpeer import Peer
from electrum.lntransport import LNPeerAddr
from electrum.crypto import privkey_to_pubkey
from electrum.lnutil import Keypair, PaymentFailure, LnFeatures, HTLCOwner, PaymentFeeBudget, RECEIVED
from electrum.lnchannel import ChannelState, PeerState, Channel
from electrum.lnrouter import LNPathFinder, PathEdge, LNPathInconsistent
from electrum.channel_db import ChannelDB
from electrum.lnworker import LNWallet, NoPathFound, SentHtlcInfo, PaySession, LNPeerManager
from electrum.lnmsg import encode_msg, decode_msg
from electrum import lnmsg
from electrum.logging import console_stderr_handler, Logger
from electrum.lnworker import PaymentInfo
from electrum.lnonion import OnionFailureCode, OnionRoutingFailure, OnionHopsDataSingle, OnionPacket
from electrum.lnutil import LOCAL, REMOTE, UpdateAddHtlc, RecvMPPResolution
from electrum.invoices import PR_PAID, PR_UNPAID, Invoice, LN_EXPIRY_NEVER
from electrum.interface import GracefulDisconnect
from electrum.simple_config import SimpleConfig
from electrum.fee_policy import FeeTimeEstimates, FEE_ETA_TARGETS
from electrum.mpp_split import split_amount_normal
from electrum.wallet import Abstract_Wallet, Standard_Wallet

from .test_lnchannel import create_test_channels
from .test_bitcoin import needs_test_with_all_chacha20_implementations
from . import ElectrumTestCase, restore_wallet_from_text__for_unittest


class MockNetwork:
    def __init__(self, *, config: SimpleConfig):
        self.lnwatcher = None
        self.interface = None
        self.fee_estimates = FeeTimeEstimates()
        self.populate_fee_estimates()
        self.config = config
        self.asyncio_loop = util.get_asyncio_loop()
        self.channel_db = ChannelDB(self)
        self.channel_db.data_loaded.set()
        self.path_finder = LNPathFinder(self.channel_db)
        self.lngossip = MockLNGossip()
        self.tx_queue = asyncio.Queue()
        self.proxy = ProxySettings()
        self._blockchain = MockBlockchain()

    def get_local_height(self):
        return self.blockchain().height()

    def blockchain(self):
        return self._blockchain

    async def broadcast_transaction(self, tx):
        await self.tx_queue.put(tx)

    async def try_broadcasting(self, tx, name):
        await self.broadcast_transaction(tx)

    def populate_fee_estimates(self):
        for target in FEE_ETA_TARGETS[:-1]:
            self.fee_estimates.set_data(target, 50000 // target)


class MockBlockchain:
    def __init__(self):
        # Let's return a non-zero, realistic height.
        # 0 might hide relative vs abs locktime confusion bugs.
        self._height = 600_000

    def height(self):
       return self._height

    def is_tip_stale(self):
        return False


class MockLNGossip:
    def get_sync_progress_estimate(self):
        return None, None, None


class MockWalletFactory(electrum.wallet.Wallet):

    @staticmethod
    def wallet_class(wallet_type):
        real_wallet_class = electrum.wallet.Wallet.wallet_class(wallet_type)
        if real_wallet_class is Standard_Wallet:
            return MockStandardWallet
        return real_wallet_class


class MockStandardWallet(Standard_Wallet):
    def _init_lnworker(self):
        ln_xprv = self.db.get('lightning_xprv') or self.db.get('lightning_privkey2')
        assert ln_xprv
        self.lnworker = MockLNWallet(self, ln_xprv)

    def basename(self):
        passphrase = self.db.get("keystore").get("passphrase")
        assert passphrase
        return passphrase  # lol, super secure name

def _create_mock_lnwallet(*, name, has_anchors, data_dir: str) -> 'MockLNWallet':
    config = SimpleConfig({}, read_user_dir_function=lambda: data_dir)
    config.ENABLE_ANCHOR_CHANNELS = has_anchors
    config.INITIAL_TRAMPOLINE_FEE_LEVEL = 0

    network = MockNetwork(config=config)

    wallet = restore_wallet_from_text__for_unittest(
        "9dk", path=None, passphrase=name, config=config,
        wallet_factory=MockWalletFactory,
    )['wallet']  # type: MockStandardWallet
    wallet.is_up_to_date = lambda: True
    wallet.adb.network = wallet.network = network

    lnworker = wallet.lnworker
    assert isinstance(lnworker, MockLNWallet), f"{lnworker=!r}"
    lnworker.lnpeermgr.network = network
    lnworker.logger.info(f"created LNWallet[{name}] with nodeID={lnworker.node_keypair.pubkey.hex()}")
    return lnworker

class MockLNWallet(LNWallet):
    MPP_EXPIRY = 2  # HTLC timestamps are cast to int, so this cannot be 1
    TIMEOUT_SHUTDOWN_FAIL_PENDING_HTLCS = 0
    MPP_SPLIT_PART_FRACTION = 1  # this disables the forced splitting

    def __init__(self, *args, **kwargs):
        LNWallet.__init__(self, *args, **kwargs)
        self.features &= ~LnFeatures.BASIC_MPP_OPT  # by default, disable MPP

    def _add_channel(self, chan: Channel):
        self._channels[chan.channel_id] = chan
        # assert chan.lnworker == self  # this fails as some tests are reusing chans in a weird way
        chan.lnworker = self

    @LNWallet.features.setter
    def features(self, value):
        self.lnpeermgr.features = value

    @property
    def name(self):
        return self.wallet.basename()

    async def stop(self):
        await LNWallet.stop(self)
        if self.channel_db:
            self.channel_db.stop()
            await self.channel_db.stopped_event.wait()

    async def create_routes_from_invoice(self, amount_msat: int, decoded_invoice: LnAddr, *, full_path=None):
        paysession = PaySession(
            payment_hash=decoded_invoice.paymenthash,
            payment_secret=decoded_invoice.payment_secret,
            initial_trampoline_fee_level=0,
            invoice_features=decoded_invoice.get_features(),
            r_tags=decoded_invoice.get_routing_info('r'),
            min_final_cltv_delta=decoded_invoice.get_min_final_cltv_delta(),
            amount_to_pay=amount_msat,
            invoice_pubkey=decoded_invoice.pubkey.serialize(),
            uses_trampoline=False,
            use_two_trampolines=False,
        )
        payment_key = decoded_invoice.paymenthash + decoded_invoice.payment_secret
        self._paysessions[payment_key] = paysession
        return [r async for r in self.create_routes_for_payment(
            amount_msat=amount_msat,
            paysession=paysession,
            full_path=full_path,
            budget=PaymentFeeBudget.from_invoice_amount(invoice_amount_msat=amount_msat, config=self.config),
        )]


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
    'local_balance_msat': 330 * 1000, # local pays anchors
    'remote_balance_msat': 10 * bitcoin.COIN * 1000,
    'local_base_fee_msat': 1_000,
    'local_fee_rate_millionths': 1,
    'remote_base_fee_msat': 1_000,
    'remote_fee_rate_millionths': 1,
}

_GRAPH_DEFINITIONS = {
    # A -- B
    'single_chan' : {
        'alice': {
            'channels': {
                'bob': {
                   'local_balance_msat': 10 * bitcoin.COIN * 1000 // 2,
                   'remote_balance_msat': 10 * bitcoin.COIN * 1000 // 2,
                },
            },
        },
        'bob': {
        },
    },
    #                A
    #     high fee /   \ low fee
    #             B     C
    #     high fee \   / low fee
    #                D
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
                SimpleConfig.EXPERIMENTAL_LN_FORWARD_PAYMENTS: True,
                SimpleConfig.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS: True,
            },
        },
        'carol': {
            'channels': {
                'dave': low_fee_channel.copy(),
            },
            'config': {
                SimpleConfig.EXPERIMENTAL_LN_FORWARD_PAYMENTS: True,
                SimpleConfig.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS: True,
            },
        },
        'dave': {
        },
    },
    # A -- B -- C -- D -- E
    'line_graph': {
        'alice': {
            'channels': {
                'bob': low_fee_channel.copy(),
            },
        },
        'bob': {  # Trampoline Forwarder
            'channels': {
                'carol': low_fee_channel.copy(),
            },
            'config': {
                SimpleConfig.EXPERIMENTAL_LN_FORWARD_PAYMENTS: True,
                SimpleConfig.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS: True,
            },
        },
        'carol': {
            'channels': {
                'dave': low_fee_channel.copy(),
            },
            'config': {
                SimpleConfig.EXPERIMENTAL_LN_FORWARD_PAYMENTS: True,
            },
        },
        'dave': {  # Trampoline Forwarder
            'channels': {
                'edward': low_fee_channel.copy(),
            },
            'config': {
                SimpleConfig.EXPERIMENTAL_LN_FORWARD_PAYMENTS: True,
                SimpleConfig.EXPERIMENTAL_LN_FORWARD_TRAMPOLINE_PAYMENTS: True,
            },
        },
        'edward': {
        },
    },
}


class Graph(NamedTuple):
    workers: Dict[str, MockLNWallet]
    peers: Dict[Tuple[str, str], Peer]
    channels: Dict[Tuple[str, str], Channel]


class PaymentDone(Exception): pass
class PaymentTimeout(Exception): pass
class SuccessfulTest(Exception): pass


def inject_chan_into_gossipdb(*, channel_db: ChannelDB, graph: Graph, node1name: str, node2name: str) -> None:
    chan_ann_raw = graph.channels[(node1name, node2name)].construct_channel_announcement_without_sigs()[0]
    chan_ann_dict = decode_msg(chan_ann_raw)[1]
    channel_db.add_channel_announcements(chan_ann_dict, trusted=True)

    chan_upd1_raw = graph.channels[(node1name, node2name)].get_outgoing_gossip_channel_update()
    chan_upd1_dict = decode_msg(chan_upd1_raw)[1]
    channel_db.add_channel_update(chan_upd1_dict, verify=False)

    chan_upd2_raw = graph.channels[(node2name, node1name)].get_outgoing_gossip_channel_update()
    chan_upd2_dict = decode_msg(chan_upd2_raw)[1]
    channel_db.add_channel_update(chan_upd2_dict, verify=False)


class TestPeer(ElectrumTestCase):
    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()
        self.GRAPH_DEFINITIONS = copy.deepcopy(_GRAPH_DEFINITIONS)

    async def asyncTearDown(self):
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {}
        await super().asyncTearDown()

    @staticmethod
    def prepare_invoice(
            w2: MockLNWallet,  # receiver
            *,
            amount_msat=100_000_000,
            include_routing_hints=False,
            payment_preimage: bytes = None,
            payment_hash: bytes = None,
            invoice_features: LnFeatures = None,
            min_final_cltv_delta: int = None,
            expiry: int = None,
    ) -> Tuple[LnAddr, Invoice]:
        amount_btc = amount_msat/Decimal(COIN*1000)
        if payment_preimage is None and not payment_hash:
            payment_preimage = os.urandom(32)
        if payment_hash is None:
            payment_hash = sha256(payment_preimage)
        if payment_preimage:
            w2.save_preimage(payment_hash, payment_preimage)
        if include_routing_hints:
            routing_hints = w2.calc_routing_hints_for_invoice(amount_msat)
        else:
            routing_hints = []
            trampoline_hints = []
        if invoice_features is None:
            invoice_features = w2.features.for_invoice()
        if invoice_features.supports(LnFeatures.PAYMENT_SECRET_OPT):
            payment_secret = w2.get_payment_secret(payment_hash)
        else:
            payment_secret = None
        if min_final_cltv_delta is None:
            min_final_cltv_delta = lnutil.MIN_FINAL_CLTV_DELTA_ACCEPTED
        info = PaymentInfo(
            payment_hash=payment_hash,
            amount_msat=amount_msat,
            direction=RECEIVED,
            status=PR_UNPAID,
            min_final_cltv_delta=min_final_cltv_delta,
            expiry_delay=expiry or LN_EXPIRY_NEVER,
            invoice_features=invoice_features,
        )
        w2.save_payment_info(info)
        lnaddr1 = LnAddr(
            paymenthash=payment_hash,
            amount=amount_btc,
            tags=[
                ('c', min_final_cltv_delta),
                ('d', 'coffee'),
                ('9', invoice_features),
                ('x', expiry or 3600),
            ] + routing_hints,
            payment_secret=payment_secret,
        )
        invoice = lnencode(lnaddr1, w2.node_keypair.privkey)
        lnaddr2 = lndecode(invoice)  # unlike lnaddr1, this now has a pubkey set
        return lnaddr2, Invoice.from_bech32(invoice)

    async def _activate_trampoline(self, w: MockLNWallet):
        if w.network.channel_db:
            w.network.channel_db.stop()
            await w.network.channel_db.stopped_event.wait()
            w.network.channel_db = None

    def prepare_recipient(self, w2, payment_hash, test_hold_invoice, test_failure):
        if not test_hold_invoice and not test_failure:
            return
        preimage = bytes.fromhex(w2._preimages.pop(payment_hash.hex()))
        if test_hold_invoice:
            async def cb(payment_hash):
                if not test_failure:
                    w2.save_preimage(payment_hash, preimage)
                else:
                    raise OnionRoutingFailure(code=OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, data=b'')
            w2.register_hold_invoice(payment_hash, cb)

    def prepare_lnwallets(self, graph_definition) -> Mapping[str, MockLNWallet]:
        workers = {}  # type: Dict[str, MockLNWallet]
        for a, definition in graph_definition.items():
            workers[a] = self.create_mock_lnwallet(name=a, has_anchors=self.TEST_ANCHOR_CHANNELS)
        return workers

    def prepare_chans_and_peers_in_graph(
        self,
        graph_definition,
        *,
        workers: Dict[str, MockLNWallet] = None,
        channels: Mapping[Tuple[str, str], Channel] = None,
    ) -> Graph:
        # create workers
        if workers is None:
            workers = self.prepare_lnwallets(graph_definition=graph_definition)
        keys = {name: w.node_keypair for name, w in workers.items()}

        if channels is None:
            channels = {}  # type: Dict[Tuple[str, str], Channel]
        transports = {}
        peers = {}

        # create channels
        for a, definition in graph_definition.items():
            for b, channel_def in definition.get('channels', {}).items():
                if ((a, b) in channels) or ((b, a) in channels):
                    # if either chan direction is present, both must be present
                    channel_ab = channels[(a, b)]
                    channel_ba = channels[(b, a)]
                else:  # create new chans now
                    channel_ab, channel_ba = create_test_channels(
                        alice_lnwallet=workers[a],
                        bob_lnwallet=workers[b],
                        local_msat=channel_def['local_balance_msat'],
                        remote_msat=channel_def['remote_balance_msat'],
                        anchor_outputs=self.TEST_ANCHOR_CHANNELS
                    )
                    channels[(a, b)], channels[(b, a)] = channel_ab, channel_ba
                workers[a]._add_channel(channel_ab)
                workers[b]._add_channel(channel_ba)
                transport_ab, transport_ba = transport_pair(keys[a], keys[b], channel_ab.name, channel_ba.name)
                transports[(a, b)], transports[(b, a)] = transport_ab, transport_ba
                # set fees
                if 'local_fee_rate_millionths' in channel_def:
                    channel_ab.forwarding_fee_proportional_millionths = channel_def['local_fee_rate_millionths']
                if 'local_base_fee_msat' in channel_def:
                    channel_ab.forwarding_fee_base_msat = channel_def['local_base_fee_msat']
                if 'remote_fee_rate_millionths' in channel_def:
                    channel_ba.forwarding_fee_proportional_millionths = channel_def['remote_fee_rate_millionths']
                if 'remote_base_fee_msat' in channel_def:
                    channel_ba.forwarding_fee_base_msat = channel_def['remote_base_fee_msat']

        # create peers
        for ab in channels.keys():
            peers[ab] = PeerInTests(workers[ab[0]], keys[ab[1]].pubkey, transports[ab])

        # add peers to workers
        for a, w in workers.items():
            for ab, peer_ab in peers.items():
                if ab[0] == a:
                    w.lnpeermgr._peers[peer_ab.pubkey] = peer_ab

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


class TestPeerDirect(TestPeer):

    def prepare_peers(
            self, alice_channel: Channel, bob_channel: Channel,
    ):
        graph = self.prepare_chans_and_peers_in_graph(
            self.GRAPH_DEFINITIONS['single_chan'],
            channels={('alice', 'bob'): alice_channel, ('bob', 'alice'): bob_channel},
        )
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        return p1, p2, w1, w2

    async def test_reestablish(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel, bob_channel = graph.channels.values()

        for chan in (alice_channel, bob_channel):
            chan.peer_state = PeerState.DISCONNECTED
        async def reestablish():
            await asyncio.gather(
                p1.reestablish_channel(alice_channel),
                p2.reestablish_channel(bob_channel))
            self.assertEqual(alice_channel.peer_state, PeerState.GOOD)
            self.assertEqual(bob_channel.peer_state, PeerState.GOOD)
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
        alice_lnwallet, bob_lnwallet = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan']).values()
        chan_AB, chan_BA = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)
        # note: we don't start peer.htlc_switch() so that the fake htlcs are left alone.
        async def f():
            p1, p2, w1, w2 = self.prepare_peers(chan_AB, chan_BA)
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
            self.logger.info("simulating disconnection. recreating transports.")
            p1, p2, w1, w2 = self.prepare_peers(chan_AB, chan_BA)
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
                await group.cancel_remaining()
            raise SuccessfulTest()
        with self.assertRaises(SuccessfulTest):
            await f()

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
        alice_lnwallet, bob_lnwallet = self.prepare_lnwallets(self.GRAPH_DEFINITIONS['single_chan']).values()
        chan_AB, chan_BA = create_test_channels(alice_lnwallet=alice_lnwallet, bob_lnwallet=bob_lnwallet)
        # note: we don't start peer.htlc_switch() so that the fake htlcs are left alone.
        async def f():
            p1, p2, w1, w2 = self.prepare_peers(chan_AB, chan_BA)
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
            self.logger.info("simulating disconnection. recreating transports.")
            p1, p2, w1, w2 = self.prepare_peers(chan_AB, chan_BA)
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
                await group.cancel_remaining()
            raise SuccessfulTest()
        with self.assertRaises(SuccessfulTest):
            await f()

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
            invoice_features = w2.features.for_invoice() | (1 << 990)  # add undefined even fbit
            lnaddr, pay_req = self.prepare_invoice(w2, invoice_features=invoice_features)
            with self.assertRaises(lnutil.UnknownEvenFeatureBits):
                result, log = await w1.pay_invoice(pay_req)
            # feature bits: not all transitive dependencies are set
            invoice_features = LnFeatures((1 << 8) + (1 << 17))
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
                b11 = lnencode(lnaddr, w2.node_keypair.privkey)
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
                b11 = lnencode(lnaddr, w2.node_keypair.privkey)
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

    async def test_payment_race(self):
        """Alice and Bob pay each other simultaneously.
        They both send 'update_add_htlc' and receive each other's update
        before sending 'commitment_signed'. Neither party should fulfill
        the respective HTLCs until those are irrevocably committed to.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel, bob_channel = graph.channels.values()
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
        alice_channel, bob_channel = graph.channels.values()
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
        alice_channel, bob_channel = graph.channels.values()
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

            while nhtlc_success + nhtlc_failed < 2:
                await htlc_resolved.wait()
            self.assertEqual(0, nhtlc_success)
            self.assertEqual(2, nhtlc_failed)
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

        htlc_resolved = asyncio.Event()
        nhtlc_success = 0
        nhtlc_failed = 0
        async def on_htlc_fulfilled(*args):
            htlc_resolved.set()
            htlc_resolved.clear()
            nonlocal nhtlc_success
            nhtlc_success += 1
        async def on_htlc_failed(*args):
            htlc_resolved.set()
            htlc_resolved.clear()
            nonlocal nhtlc_failed
            nhtlc_failed += 1
        util.register_callback(on_htlc_fulfilled, ["htlc_fulfilled"])
        util.register_callback(on_htlc_failed, ["htlc_failed"])

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
        alice_channel, bob_channel = graph.channels.values()
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

            while nhtlc_success + nhtlc_failed < 2:
                await htlc_resolved.wait()
            self.assertEqual(0, nhtlc_success)
            self.assertEqual(2, nhtlc_failed)
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

        htlc_resolved = asyncio.Event()
        nhtlc_success = 0
        nhtlc_failed = 0
        async def on_htlc_fulfilled(*args):
            htlc_resolved.set()
            htlc_resolved.clear()
            nonlocal nhtlc_success
            nhtlc_success += 1
        async def on_htlc_failed(*args):
            htlc_resolved.set()
            htlc_resolved.clear()
            nonlocal nhtlc_failed
            nhtlc_failed += 1
        util.register_callback(on_htlc_fulfilled, ["htlc_fulfilled"])
        util.register_callback(on_htlc_failed, ["htlc_failed"])

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_dont_settle_partial_mpp_trigger_with_invalid_cltv_htlc(self):
        """Alice gets two htlcs as part of a mpp, one has a cltv too close to expiry and will get failed.
        Test that the other htlc won't get settled if the mpp isn't complete anymore after failing the other htlc.
        """
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel, bob_channel = graph.channels.values()
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

            while nhtlc_success + nhtlc_failed < 2:
                await htlc_resolved.wait()
            # both htlcs of the mpp set should get failed and w2 shouldn't release the preimage
            self.assertEqual(0, nhtlc_success, f"{nhtlc_success=} | {nhtlc_failed=}")
            self.assertEqual(2, nhtlc_failed,  f"{nhtlc_success=} | {nhtlc_failed=}")
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

        htlc_resolved = asyncio.Event()
        nhtlc_success = 0
        nhtlc_failed = 0
        async def on_htlc_fulfilled(*args):
            htlc_resolved.set()
            htlc_resolved.clear()
            nonlocal nhtlc_success
            nhtlc_success += 1
        async def on_htlc_failed(*args):
            htlc_resolved.set()
            htlc_resolved.clear()
            nonlocal nhtlc_failed
            nhtlc_failed += 1
        util.register_callback(on_htlc_fulfilled, ["htlc_fulfilled"])
        util.register_callback(on_htlc_failed, ["htlc_failed"])

        try:
            with self.assertRaises(SuccessfulTest):
                await f()
        finally:
            util.unregister_callback(on_htlc_fulfilled)
            util.unregister_callback(on_htlc_failed)

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
            alice_channel, bob_channel = graph.channels.values()
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
                await asyncio.wait_for(alice_htlc_resolved.wait(), bob_wallet.MPP_EXPIRY * 3)  # this can take some time, esp. on CI
                # check that bob failed the htlc
                assert nhtlc_success == 0 and nhtlc_failed == 2
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

            alice_htlc_resolved = asyncio.Event()
            nhtlc_success = 0
            nhtlc_failed = 0
            async def on_sender_htlc_fulfilled(*args):
                alice_htlc_resolved.set()
                alice_htlc_resolved.clear()
                nonlocal nhtlc_success
                nhtlc_success += 1
            async def on_sender_htlc_failed(*args):
                alice_htlc_resolved.set()
                alice_htlc_resolved.clear()
                nonlocal nhtlc_failed
                nhtlc_failed += 1
            util.register_callback(on_sender_htlc_fulfilled, ["htlc_fulfilled"])
            util.register_callback(on_sender_htlc_failed, ["htlc_failed"])

            try:
                with self.assertRaises(SuccessfulTest):
                    await f()
            finally:
                util.unregister_callback(on_sender_htlc_fulfilled)
                util.unregister_callback(on_sender_htlc_failed)

        for use_trampoline in [True, False]:
            self.logger.debug(f"test_mpp_cleanup_after_expiry: {use_trampoline=}")
            await run_test(use_trampoline)

    async def test_legacy_shutdown_low(self):
        await self._test_shutdown(alice_fee=100, bob_fee=150)

    async def test_legacy_shutdown_high(self):
        await self._test_shutdown(alice_fee=2000, bob_fee=100)

    async def test_modern_shutdown_with_overlap(self):
        await self._test_shutdown(
            alice_fee=1,
            bob_fee=200,
            alice_fee_range={'min_fee_satoshis': 1, 'max_fee_satoshis': 10},
            bob_fee_range={'min_fee_satoshis': 10, 'max_fee_satoshis': 300})

    ## This test works but it is too slow (LN_P2P_NETWORK_TIMEOUT)
    ## because tests do not use a proper LNWorker object
    #def test_modern_shutdown_no_overlap(self):
    #    self.assertRaises(Exception, lambda: asyncio.run(
    #        self._test_shutdown(
    #            alice_fee=1,
    #            bob_fee=200,
    #            alice_fee_range={'min_fee_satoshis': 1, 'max_fee_satoshis': 10},
    #            bob_fee_range={'min_fee_satoshis': 50, 'max_fee_satoshis': 300})
    #    ))

    async def _test_shutdown(self, alice_fee, bob_fee, alice_fee_range=None, bob_fee_range=None):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        alice_channel, bob_channel = graph.channels.values()
        w1.network.config.TEST_SHUTDOWN_FEE = alice_fee
        w2.network.config.TEST_SHUTDOWN_FEE = bob_fee
        if alice_fee_range is not None:
            w1.network.config.TEST_SHUTDOWN_FEE_RANGE = alice_fee_range
        else:
            w1.network.config.TEST_SHUTDOWN_LEGACY = True
        if bob_fee_range is not None:
            w2.network.config.TEST_SHUTDOWN_FEE_RANGE = bob_fee_range
        else:
            w2.network.config.TEST_SHUTDOWN_LEGACY = True
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
            # alice closes
            await p1.close_channel(alice_channel.channel_id)
            gath.cancel()
        async def set_settle():
            await asyncio.sleep(0.1)
            w2.enable_htlc_settle = True
        gath = asyncio.gather(pay(), set_settle(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(asyncio.CancelledError):
            await gath

    async def test_warning(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['single_chan'])
        p1, p2 = graph.peers.values()
        alice_channel, bob_channel = graph.channels.values()

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
        alice_channel, bob_channel = graph.channels.values()

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
        alice_channel, bob_channel = graph.channels.values()
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

            cb_got_called = False
            async def cb(_payment_hash):
                self.logger.debug(f"hold invoice callback called. {bob_w.network.get_local_height()=}")
                nonlocal cb_got_called
                cb_got_called = True

            bob_w.register_hold_invoice(lnaddr.paymenthash, cb)

            async def check_mpp_state():
                async def wait_for_resolution():
                    while True:
                        await asyncio.sleep(0.1)
                        if payment_key not in bob_w.received_mpp_htlcs:
                            continue
                        if not bob_w.received_mpp_htlcs[payment_key].resolution == RecvMPPResolution.SETTLING:
                            continue
                        return
                await util.wait_for2(wait_for_resolution(), timeout=2)
                assert cb_got_called
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
        invoices = []  # type: list[tuple[LnAddr, Invoice]]
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
            self.assertEqual(500000000000, graph.channels[('alice', 'bob')].balance(LOCAL))
            self.assertEqual(500000000000, graph.channels[('dave', 'bob')].balance(LOCAL))
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
            result, log = await graph.workers['alice'].pay_invoice(pay_req, attempts=2)
            self.assertEqual(2, len(log))
            self.assertTrue(result)
            self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash, direction=RECEIVED))
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
            await f()

    async def test_refuse_to_forward_htlc_that_corresponds_to_payreq_we_created(self):
        # This test checks that the following attack does not work:
        #   - Bob creates payment request with HASH1, for 1 BTC; and gives the payreq to Alice
        #   - Alice sends htlc A->B->D, for 100k sat, with HASH1
        #   - Bob must not release the preimage of HASH1
        graph_def = self.GRAPH_DEFINITIONS['square_graph']
        graph_def.pop('carol')
        graph_def['alice']['channels'].pop('carol')
        # now graph is linear: A <-> B <-> D
        graph = self.prepare_chans_and_peers_in_graph(graph_def)
        peers = graph.peers.values()
        async def pay():
            lnaddr1, pay_req1 = self.prepare_invoice(
                graph.workers['bob'],
                amount_msat=100_000_000_000,
            )
            lnaddr2, pay_req2 = self.prepare_invoice(
                graph.workers['dave'],
                amount_msat=100_000_000,
                payment_hash=lnaddr1.paymenthash,  # Dave is cooperating with Alice, and he reuses Bob's hash
                include_routing_hints=True,
            )
            with self.subTest(msg="try to make Bob forward in legacy (non-trampoline) mode"):
                result, log = await graph.workers['alice'].pay_invoice(pay_req2, attempts=1)
                self.assertFalse(result)
                self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, log[0].failure_msg.code)
                self.assertEqual(None, graph.workers['alice'].get_preimage(lnaddr1.paymenthash))
            with self.subTest(msg="try to make Bob forward in trampoline mode"):
                # declare Bob as trampoline forwarding node
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
                }
                await self._activate_trampoline(graph.workers['alice'])
                result, log = await graph.workers['alice'].pay_invoice(pay_req2, attempts=5)
                self.assertFalse(result)
                self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, log[0].failure_msg.code)
                self.assertEqual(None, graph.workers['alice'].get_preimage(lnaddr1.paymenthash))
            raise SuccessfulTest()

        async def f():
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                await group.spawn(pay())

        with self.assertRaises(SuccessfulTest):
            await f()

    async def test_payment_with_temp_channel_failure_and_liquidity_hints(self):
        # prepare channels such that a temporary channel failure happens at c->d
        graph_definition = self.GRAPH_DEFINITIONS['square_graph']
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
            await f()

    async def _run_mpp(self, graph, kwargs):
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
                raise PaymentDone()
            elif len(log) == 1 and log[0].failure_msg.code == OnionFailureCode.MPP_TIMEOUT:
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

    async def test_payment_multipart_trampoline_e2e(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
            graph.workers['carol'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['carol'].node_keypair.pubkey),
        }
        # end-to-end trampoline: we attempt
        # * a payment with one trial: fails, because
        #   we need at least one trial because the initial fees are too low
        # * a payment with several trials: should succeed
        with self.assertRaises(NoPathFound):
            await self._run_mpp(graph, {'alice_uses_trampoline': True, 'attempts': 1})
        with self.assertRaises(PaymentDone):
            await self._run_mpp(graph,{'alice_uses_trampoline': True, 'attempts': 30})

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
            await f()

    async def _run_trampoline_payment(
            self, graph: Graph, *,
            include_routing_hints=True,
            test_hold_invoice=False,
            test_failure=False,
            attempts=2,
            sender_name="alice",
            destination_name="dave",
            tf_names=("bob", "carol"),
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
        for tf_name in tf_names:
            peer_addr = LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers[tf_name].node_keypair.pubkey)
            electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS[graph.workers[tf_name].name] = peer_addr

        await f()

    def create_square_graph(self, *, direct=False, test_mpp_consolidation=False, is_legacy=False):
        graph_definition = self.GRAPH_DEFINITIONS['square_graph']
        if not direct:
            # deplete channel from alice to carol and from bob to dave
            graph_definition['alice']['channels']['carol'] = depleted_channel
            graph_definition['bob']['channels']['dave'] = depleted_channel
            # insert a channel from bob to carol
            graph_definition['bob']['channels']['carol'] = low_fee_channel
            # now the only route possible is alice -> bob -> carol -> dave
        if test_mpp_consolidation:
            # deplete alice to carol so that all htlcs go through bob
            graph_definition['alice']['channels']['carol'] = depleted_channel
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
        bob_alice_channel = graph.channels[('bob', 'alice')]
        htlcs_bob_received_from_alice = bob_alice_channel.hm.all_htlcs_ever()
        bob_carol_channel = graph.channels[('bob', 'carol')]
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
            channel_db=graph.workers['bob'].channel_db, graph=graph,
            node1name='carol', node2name='dave')
        with self.assertRaises(PaymentDone):
            await self._run_trampoline_payment(
                graph, sender_name='alice', destination_name='edward',tf_names=('bob', 'dave'))

    async def test_multi_trampoline_payment(self):
        """
        Alice splits her payment to Dave between two trampoline forwarding nodes Carol and Bob.
        This should test Multi-Trampoline MPP:
        https://github.com/lightning/bolts/blob/bc7a1a0bc97b2293e7f43dd8a06529e5fdcf7cd2/proposals/trampoline.md#multi-trampoline-mpp
        """
        graph_definition = self.GRAPH_DEFINITIONS['square_graph']
        # payment amount is 100_000_000 msat, size the channels so that alice must use both to succeed
        graph_definition['alice']['channels']['bob']['local_balance_msat'] = int(100_000_000 * 0.75)
        graph_definition['alice']['channels']['carol']['local_balance_msat'] = int(100_000_000 * 0.75)
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
                tf_names=('bob', 'carol'),
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
        modified_trampoline_onion = None
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
                    "version": modified_trampoline_onion.version,
                    "public_key": modified_trampoline_onion.public_key,
                    "hops_data": modified_trampoline_onion.hops_data,
                    "hmac": modified_trampoline_onion.hmac,
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
        bob_alice_channel = graph.channels[('bob', 'alice')]
        bob_hm = bob_alice_channel.hm
        assert len(bob_hm.all_htlcs_ever()) == 2
        assert all(bob_hm.was_htlc_failed(htlc_id=htlc.htlc_id, htlc_proposer=HTLCOwner.REMOTE) for (_, htlc) in bob_hm.all_htlcs_ever())

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
                electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
                    graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
                }
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


class TestPeerDirectAnchors(TestPeerDirect):
    TEST_ANCHOR_CHANNELS = True

class TestPeerForwardingAnchors(TestPeerForwarding):
    TEST_ANCHOR_CHANNELS = True


def run(coro):
    return asyncio.run_coroutine_threadsafe(coro, loop=util.get_asyncio_loop()).result()
