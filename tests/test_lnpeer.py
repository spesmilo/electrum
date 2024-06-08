import asyncio
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
from electrum.util import NetworkRetryManager, bfh, OldTaskGroup, EventListener, InvoiceError
from electrum.lnpeer import Peer
from electrum.lnutil import LNPeerAddr, Keypair, privkey_to_pubkey
from electrum.lnutil import PaymentFailure, LnFeatures, HTLCOwner, PaymentFeeBudget
from electrum.lnchannel import ChannelState, PeerState, Channel
from electrum.lnrouter import LNPathFinder, PathEdge, LNPathInconsistent
from electrum.channel_db import ChannelDB
from electrum.lnworker import LNWallet, NoPathFound, SentHtlcInfo, PaySession
from electrum.lnmsg import encode_msg, decode_msg
from electrum import lnmsg
from electrum.logging import console_stderr_handler, Logger
from electrum.lnworker import PaymentInfo, RECEIVED
from electrum.lnonion import OnionFailureCode, OnionRoutingFailure
from electrum.lnutil import UpdateAddHtlc
from electrum.lnutil import LOCAL, REMOTE
from electrum.invoices import PR_PAID, PR_UNPAID
from electrum.interface import GracefulDisconnect
from electrum.simple_config import SimpleConfig

from .test_lnchannel import create_test_channels
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
    def __init__(self, tx_queue, *, config: SimpleConfig):
        self.callbacks = defaultdict(list)
        self.lnwatcher = None
        self.interface = None
        self.config = config
        self.asyncio_loop = util.get_asyncio_loop()
        self.channel_db = ChannelDB(self)
        self.channel_db.data_loaded.set()
        self.path_finder = LNPathFinder(self.channel_db)
        self.lngossip = MockLNGossip()
        self.tx_queue = tx_queue
        self._blockchain = MockBlockchain()

    @property
    def callback_lock(self):
        return noop_lock()

    def get_local_height(self):
        return self.blockchain().height()

    def blockchain(self):
        return self._blockchain

    async def broadcast_transaction(self, tx):
        if self.tx_queue:
            await self.tx_queue.put(tx)

    async def try_broadcasting(self, tx, name):
        await self.broadcast_transaction(tx)


class MockBlockchain:

    def height(self):
        # Let's return a non-zero, realistic height.
        # 0 might hide relative vs abs locktime confusion bugs.
        return 600_000

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

    def get_fingerprint(self):
        return ''


class MockLNGossip:
    def get_sync_progress_estimate(self):
        return None, None, None


class MockLNWallet(Logger, EventListener, NetworkRetryManager[LNPeerAddr]):
    MPP_EXPIRY = 2  # HTLC timestamps are cast to int, so this cannot be 1
    PAYMENT_TIMEOUT = 120
    TIMEOUT_SHUTDOWN_FAIL_PENDING_HTLCS = 0
    MPP_SPLIT_PART_FRACTION = 1  # this disables the forced splitting
    MPP_SPLIT_PART_MINAMT_MSAT = 5_000_000

    def __init__(self, *, local_keypair: Keypair, chans: Iterable['Channel'], tx_queue, name):
        self.name = name
        Logger.__init__(self)
        NetworkRetryManager.__init__(self, max_retry_delay_normal=1, init_retry_delay_normal=1)
        self.node_keypair = local_keypair
        self.payment_secret_key = os.urandom(256) # does not need to be deterministic in tests
        self._user_dir = tempfile.mkdtemp(prefix="electrum-lnpeer-test-")
        self.config = SimpleConfig({}, read_user_dir_function=lambda: self._user_dir)
        self.network = MockNetwork(tx_queue, config=self.config)
        self.taskgroup = OldTaskGroup()
        self.lnwatcher = None
        self.swap_manager = None
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
        self.features |= LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM
        self.features |= LnFeatures.OPTION_CHANNEL_TYPE_OPT
        self.features |= LnFeatures.OPTION_SCID_ALIAS_OPT
        self.pending_payments = defaultdict(asyncio.Future)
        for chan in chans:
            chan.lnworker = self
        self._peers = {}  # bytes -> Peer
        # used in tests
        self.enable_htlc_settle = True
        self.enable_htlc_forwarding = True
        self.received_mpp_htlcs = dict()
        self._paysessions = dict()
        self.sent_htlcs_info = dict()
        self.sent_buckets = defaultdict(set)
        self.active_forwardings = {}
        self.forwarding_failures = {}
        self.inflight_payments = set()
        self.preimages = {}
        self.stopping_soon = False
        self.downstream_to_upstream_htlc = {}
        self.hold_invoice_callbacks = {}
        self.payment_bundles = [] # lists of hashes. todo:persist
        self.config.INITIAL_TRAMPOLINE_FEE_LEVEL = 0

        self.logger.info(f"created LNWallet[{name}] with nodeID={local_keypair.pubkey.hex()}")

    def clear_invoices_cache(self):
        pass

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
            budget=PaymentFeeBudget.default(invoice_amount_msat=amount_msat, config=self.config),
        )]

    get_payments = LNWallet.get_payments
    get_payment_secret = LNWallet.get_payment_secret
    get_payment_info = LNWallet.get_payment_info
    save_payment_info = LNWallet.save_payment_info
    set_invoice_status = LNWallet.set_invoice_status
    set_request_status = LNWallet.set_request_status
    set_payment_status = LNWallet.set_payment_status
    get_payment_status = LNWallet.get_payment_status
    check_mpp_status = LNWallet.check_mpp_status
    htlc_fulfilled = LNWallet.htlc_fulfilled
    htlc_failed = LNWallet.htlc_failed
    save_preimage = LNWallet.save_preimage
    get_preimage = LNWallet.get_preimage
    create_route_for_single_htlc = LNWallet.create_route_for_single_htlc
    create_routes_for_payment = LNWallet.create_routes_for_payment
    _check_invoice = LNWallet._check_invoice
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
    is_forwarded_htlc = LNWallet.is_forwarded_htlc
    notify_upstream_peer = LNWallet.notify_upstream_peer
    _force_close_channel = LNWallet._force_close_channel
    suggest_splits = LNWallet.suggest_splits
    register_hold_invoice = LNWallet.register_hold_invoice
    unregister_hold_invoice = LNWallet.unregister_hold_invoice
    add_payment_info_for_hold_invoice = LNWallet.add_payment_info_for_hold_invoice

    update_mpp_with_received_htlc = LNWallet.update_mpp_with_received_htlc
    set_mpp_resolution = LNWallet.set_mpp_resolution
    is_mpp_amount_reached = LNWallet.is_mpp_amount_reached
    get_first_timestamp_of_mpp = LNWallet.get_first_timestamp_of_mpp
    bundle_payments = LNWallet.bundle_payments
    get_payment_bundle = LNWallet.get_payment_bundle
    _get_payment_key = LNWallet._get_payment_key
    save_forwarding_failure = LNWallet.save_forwarding_failure
    get_forwarding_failure = LNWallet.get_forwarding_failure
    maybe_cleanup_forwarding = LNWallet.maybe_cleanup_forwarding


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

_GRAPH_DEFINITIONS = {
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
    }
}


class Graph(NamedTuple):
    workers: Dict[str, MockLNWallet]
    peers: Dict[Tuple[str, str], Peer]
    channels: Dict[Tuple[str, str], Channel]


class PaymentDone(Exception): pass
class PaymentTimeout(Exception): pass
class SuccessfulTest(Exception): pass


class TestPeer(ElectrumTestCase):
    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()
        self.GRAPH_DEFINITIONS = copy.deepcopy(_GRAPH_DEFINITIONS)
        self._lnworkers_created = []  # type: List[MockLNWallet]

    async def asyncTearDown(self):
        # clean up lnworkers
        async with OldTaskGroup() as group:
            for lnworker in self._lnworkers_created:
                await group.spawn(lnworker.stop())
        for lnworker in self._lnworkers_created:
            shutil.rmtree(lnworker._user_dir)
        self._lnworkers_created.clear()
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
    ) -> Tuple[LnAddr, str]:
        amount_btc = amount_msat/Decimal(COIN*1000)
        if payment_preimage is None and not payment_hash:
            payment_preimage = os.urandom(32)
        if payment_hash is None:
            payment_hash = sha256(payment_preimage)
        info = PaymentInfo(payment_hash, amount_msat, RECEIVED, PR_UNPAID)
        if payment_preimage:
            w2.save_preimage(payment_hash, payment_preimage)
        w2.save_payment_info(info)
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
            min_final_cltv_delta = lnutil.MIN_FINAL_CLTV_DELTA_FOR_INVOICE
        lnaddr1 = LnAddr(
            paymenthash=payment_hash,
            amount=amount_btc,
            tags=[
                ('c', min_final_cltv_delta),
                ('d', 'coffee'),
                ('9', invoice_features),
            ] + routing_hints,
            payment_secret=payment_secret,
        )
        invoice = lnencode(lnaddr1, w2.node_keypair.privkey)
        lnaddr2 = lndecode(invoice)  # unlike lnaddr1, this now has a pubkey set
        return lnaddr2, invoice

    async def _activate_trampoline(self, w: MockLNWallet):
        if w.network.channel_db:
            w.network.channel_db.stop()
            await w.network.channel_db.stopped_event.wait()
            w.network.channel_db = None

    def prepare_recipient(self, w2, payment_hash, test_hold_invoice, test_failure):
        if not test_hold_invoice and not test_failure:
            return
        preimage = bytes.fromhex(w2.preimages.pop(payment_hash.hex()))
        if test_hold_invoice:
            async def cb(payment_hash):
                if not test_failure:
                    w2.save_preimage(payment_hash, preimage)
                else:
                    raise OnionRoutingFailure(code=OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, data=b'')
            w2.register_hold_invoice(payment_hash, cb)


class TestPeerDirect(TestPeer):

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
        alice_channel.storage['node_id'] = alice_channel.node_id
        bob_channel.storage['node_id'] = bob_channel.node_id
        t1, t2 = transport_pair(k1, k2, alice_channel.name, bob_channel.name)
        q1, q2 = asyncio.Queue(), asyncio.Queue()
        w1 = MockLNWallet(local_keypair=k1, chans=[alice_channel], tx_queue=q1, name=bob_channel.name)
        w2 = MockLNWallet(local_keypair=k2, chans=[bob_channel], tx_queue=q2, name=alice_channel.name)
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

    async def test_reestablish(self):
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
        with self.assertRaises(asyncio.CancelledError):
            await gath

    async def test_reestablish_with_old_state(self):
        async def f(alice_slow: bool, bob_slow: bool):
            random_seed = os.urandom(32)
            alice_channel, bob_channel = create_test_channels(random_seed=random_seed)
            alice_channel_0, bob_channel_0 = create_test_channels(random_seed=random_seed)  # these are identical
            p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
            lnaddr, pay_req = self.prepare_invoice(w2)
            async def pay():
                result, log = await w1.pay_invoice(pay_req)
                self.assertEqual(result, True)
                gath.cancel()
            gath = asyncio.gather(pay(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
            with self.assertRaises(asyncio.CancelledError):
                await gath
            p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel_0, bob_channel)
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
            self.logger.info("simulating disconnection. recreating transports.")
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
            self.logger.info("simulating disconnection. recreating transports.")
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
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr.paymenthash))
            result, log = await w1.pay_invoice(pay_req)
            if result is True:
                self.assertEqual(PR_PAID, w2.get_payment_status(lnaddr.paymenthash))
                raise PaymentDone()
            else:
                raise PaymentFailure()
        lnaddr, pay_req = self.prepare_invoice(w2)
        self.prepare_recipient(w2, lnaddr.paymenthash, test_hold_invoice, test_failure)

        if test_bundle:
            lnaddr2, pay_req2 = self.prepare_invoice(w2)
            w2.bundle_payments([lnaddr.paymenthash, lnaddr2.paymenthash])

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
                await group.spawn(pay(lnaddr, pay_req))
                if test_bundle and not test_bundle_timeout:
                    await group.spawn(pay(lnaddr2, pay_req2))

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

    async def test_simple_payment_success_with_hold_invoice(self):
        for test_trampoline in [False, True]:
            with self.assertRaises(PaymentDone):
                await self._test_simple_payment(test_trampoline=test_trampoline, test_hold_invoice=True)

    async def test_simple_payment_failure_with_hold_invoice(self):
        for test_trampoline in [False, True]:
            with self.assertRaises(PaymentFailure):
                await self._test_simple_payment(test_trampoline=test_trampoline, test_hold_invoice=True, test_failure=True)

    async def test_check_invoice_before_payment(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
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

    async def test_payment_race(self):
        """Alice and Bob pay each other simultaneously.
        They both send 'update_add_htlc' and receive each other's update
        before sending 'commitment_signed'. Neither party should fulfill
        the respective HTLCs until those are irrevocably committed to.
        """
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
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
        alice_channel, bob_channel = create_test_channels()
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
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        async def pay():
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr1.paymenthash))
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr2.paymenthash))

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

        try:
            with self.assertRaises(SuccessfulTest):
                await f()
        finally:
            util.unregister_callback(on_htlc_fulfilled)
            util.unregister_callback(on_htlc_failed)

    async def test_payment_recv_mpp_confusion2(self):
        """Regression test for https://github.com/spesmilo/electrum/security/advisories/GHSA-8r85-vp7r-hjxf"""
        # This test checks that the following attack does not work:
        #   - Bob creates invoice: 1 BTC
        #   - Alice sends htlc1: 0.1 BTC  (total_msat=0.2 BTC)
        #   - Alice sends htlc2: 0.1 BTC  (total_msat=1 BTC)
        #   - Bob(victim) reveals preimage and fulfills htlc2 (fails other)
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        async def pay():
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr1.paymenthash))

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

        try:
            with self.assertRaises(SuccessfulTest):
                await f()
        finally:
            util.unregister_callback(on_htlc_fulfilled)
            util.unregister_callback(on_htlc_failed)

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
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
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
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

        async def action():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            await p1.send_warning(alice_channel.channel_id, 'be warned!', close_connection=True)
        gath = asyncio.gather(action(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(GracefulDisconnect):
            await gath

    async def test_error(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

        async def action():
            await util.wait_for2(p1.initialized, 1)
            await util.wait_for2(p2.initialized, 1)
            await p1.send_error(alice_channel.channel_id, 'some error happened!', force_close_channel=True)
            assert alice_channel.is_closed()
            gath.cancel()
        gath = asyncio.gather(action(), p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(GracefulDisconnect):
            await gath

    async def test_close_upfront_shutdown_script(self):
        alice_channel, bob_channel = create_test_channels()

        # create upfront shutdown script for bob, alice doesn't use upfront
        # shutdown script
        bob_uss_pub = lnutil.privkey_to_pubkey(os.urandom(32))
        bob_uss_addr = bitcoin.pubkey_to_address('p2wpkh', bob_uss_pub.hex())
        bob_uss = bitcoin.address_to_script(bob_uss_addr)

        # bob commits to close to bob_uss
        alice_channel.config[HTLCOwner.REMOTE].upfront_shutdown_script = bob_uss
        # but bob closes to some receiving address, which we achieve by not
        # setting the upfront shutdown script in the channel config
        bob_channel.config[HTLCOwner.LOCAL].upfront_shutdown_script = b''

        p1, p2, w1, w2, q1, q2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.FEE_EST_DYNAMIC = False
        w2.network.config.FEE_EST_DYNAMIC = False
        w1.network.config.FEE_EST_STATIC_FEERATE = 5000
        w2.network.config.FEE_EST_STATIC_FEERATE = 1000

        async def test():
            async def close():
                await util.wait_for2(p1.initialized, 1)
                await util.wait_for2(p2.initialized, 1)
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
            await test()

        # bob sends the same upfront_shutdown_script has he announced
        alice_channel.config[HTLCOwner.REMOTE].upfront_shutdown_script = bob_uss
        bob_channel.config[HTLCOwner.LOCAL].upfront_shutdown_script = bob_uss

        p1, p2, w1, w2, q1, q2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.FEE_EST_DYNAMIC = False
        w2.network.config.FEE_EST_DYNAMIC = False
        w1.network.config.FEE_EST_STATIC_FEERATE = 5000
        w2.network.config.FEE_EST_STATIC_FEERATE = 1000

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

    async def test_channel_usage_after_closing(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, q1, q2 = self.prepare_peers(alice_channel, bob_channel)
        lnaddr, pay_req = self.prepare_invoice(w2)

        lnaddr = w1._check_invoice(pay_req)
        shi = (await w1.create_routes_from_invoice(lnaddr.get_amount_msat(), decoded_invoice=lnaddr))[0][0]
        route, amount_msat = shi.route, shi.amount_msat
        assert amount_msat == lnaddr.get_amount_msat()

        await w1.force_close_channel(alice_channel.channel_id)
        # check if a tx (commitment transaction) was broadcasted:
        assert q1.qsize() == 1

        with self.assertRaises(NoPathFound) as e:
            await w1.create_routes_from_invoice(lnaddr.get_amount_msat(), decoded_invoice=lnaddr)

        peer = w1.peers[route[0].node_id]
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
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

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
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

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
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)

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


class TestPeerForwarding(TestPeer):

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
            workers[a] = MockLNWallet(local_keypair=keys[a], chans=channels_of_node, tx_queue=txs_queues[a], name=a)
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

    async def test_payment_multihop(self):
        graph = self.prepare_chans_and_peers_in_graph(self.GRAPH_DEFINITIONS['square_graph'])
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
            self.assertEqual(PR_UNPAID, dave_w.get_payment_status(lnaddr.paymenthash))
            result, log = await alice_w.pay_invoice(pay_req, attempts=attempts)
            if not bob_forwarding:
                # reset to previous state, sleep 2s so that the second htlc can time out
                graph.workers['bob'].enable_htlc_forwarding = True
                await asyncio.sleep(2)
            if result:
                self.assertEqual(PR_PAID, dave_w.get_payment_status(lnaddr.paymenthash))
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
            self, graph, *,
            include_routing_hints=True,
            test_hold_invoice=False,
            test_failure=False,
            attempts=2):

        bob_w = graph.workers['bob']
        carol_w = graph.workers['carol']
        dave_w = graph.workers['dave']

        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
            result, log = await graph.workers['alice'].pay_invoice(pay_req, attempts=attempts)
            if result:
                self.assertEqual(PR_PAID, graph.workers['dave'].get_payment_status(lnaddr.paymenthash))
                self.assertFalse(bool(bob_w.active_forwardings))
                self.assertFalse(bool(carol_w.active_forwardings))
                raise PaymentDone()
            else:
                raise NoPathFound()

        async def f():
            await self._activate_trampoline(graph.workers['alice'])
            async with OldTaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                for peer in peers:
                    await peer.initialized
                lnaddr, pay_req = self.prepare_invoice(dave_w, include_routing_hints=include_routing_hints)
                self.prepare_recipient(dave_w, lnaddr.paymenthash, test_hold_invoice, test_failure)
                await group.spawn(pay(lnaddr, pay_req))

        peers = graph.peers.values()

        # declare routing nodes as trampoline nodes
        electrum.trampoline._TRAMPOLINE_NODES_UNITTESTS = {
            graph.workers['bob'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['bob'].node_keypair.pubkey),
            graph.workers['carol'].name: LNPeerAddr(host="127.0.0.1", port=9735, pubkey=graph.workers['carol'].node_keypair.pubkey),
        }

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
            graph.workers['alice'].network.config.TEST_FORCE_MPP = True
        if is_legacy:
            # turn off trampoline features in invoice
            graph.workers['dave'].features = graph.workers['dave'].features ^ LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM
        return graph

    async def test_trampoline_mpp_consolidation(self):
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=False, test_mpp_consolidation=True, is_legacy=True)
            await self._run_trampoline_payment(graph)

    async def test_trampoline_mpp_consolidation_with_hold_invoice(self):
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=False, test_mpp_consolidation=True, is_legacy=True)
            await self._run_trampoline_payment(graph, test_hold_invoice=True)

    async def test_trampoline_mpp_consolidation_with_hold_invoice_failure(self):
        with self.assertRaises(NoPathFound):
            graph = self.create_square_graph(direct=False, test_mpp_consolidation=True, is_legacy=True)
            await self._run_trampoline_payment(graph, test_hold_invoice=True, test_failure=True)

    async def test_payment_trampoline_legacy(self):
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=False, is_legacy=True)
            await self._run_trampoline_payment(graph, include_routing_hints=True)
        with self.assertRaises(NoPathFound):
            graph = self.create_square_graph(direct=False, is_legacy=True)
            await self._run_trampoline_payment(graph, include_routing_hints=False)

    async def test_payment_trampoline_e2e_direct(self):
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=True, is_legacy=False)
            await self._run_trampoline_payment(graph)

    async def test_payment_trampoline_e2e_indirect(self):
        # must use two trampolines
        with self.assertRaises(PaymentDone):
            graph = self.create_square_graph(direct=False, is_legacy=False)
            await self._run_trampoline_payment(graph)
