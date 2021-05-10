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
from typing import Iterable, NamedTuple, Tuple, List, Dict

from aiorpcx import TaskGroup, timeout_after, TaskTimeout

from electrum import bitcoin
from electrum import constants
from electrum.network import Network
from electrum.ecc import ECPrivkey
from electrum import simple_config, lnutil
from electrum.lnaddr import lnencode, LnAddr, lndecode
from electrum.bitcoin import COIN, sha256
from electrum.util import bh2u, create_and_start_event_loop, NetworkRetryManager, bfh
from electrum.lnpeer import Peer, UpfrontShutdownScriptViolation
from electrum.lnutil import LNPeerAddr, Keypair, privkey_to_pubkey
from electrum.lnutil import LightningPeerConnectionClosed, RemoteMisbehaving
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
from electrum.lnutil import derive_payment_secret_from_payment_preimage
from electrum.lnutil import LOCAL, REMOTE
from electrum.invoices import PR_PAID, PR_UNPAID

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

    def is_mine(self, addr):
        return True


class MockLNWallet(Logger, NetworkRetryManager[LNPeerAddr]):
    MPP_EXPIRY = 2  # HTLC timestamps are cast to int, so this cannot be 1
    TIMEOUT_SHUTDOWN_FAIL_PENDING_HTLCS = 0
    INITIAL_TRAMPOLINE_FEE_LEVEL = 0

    def __init__(self, *, local_keypair: Keypair, chans: Iterable['Channel'], tx_queue, name):
        self.name = name
        Logger.__init__(self)
        NetworkRetryManager.__init__(self, max_retry_delay_normal=1, init_retry_delay_normal=1)
        self.node_keypair = local_keypair
        self.network = MockNetwork(tx_queue)
        self.taskgroup = TaskGroup()
        self.lnwatcher = None
        self.listen_server = None
        self._channels = {chan.channel_id: chan for chan in chans}
        self.payments = {}
        self.logs = defaultdict(list)
        self.wallet = MockWallet()
        self.features = LnFeatures(0)
        self.features |= LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT
        self.features |= LnFeatures.OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT
        self.features |= LnFeatures.VAR_ONION_OPT
        self.features |= LnFeatures.PAYMENT_SECRET_OPT
        self.features |= LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT
        self.pending_payments = defaultdict(asyncio.Future)
        for chan in chans:
            chan.lnworker = self
        self._peers = {}  # bytes -> Peer
        # used in tests
        self.enable_htlc_settle = True
        self.enable_htlc_forwarding = True
        self.received_mpp_htlcs = dict()
        self.sent_htlcs = defaultdict(asyncio.Queue)
        self.sent_htlcs_routes = dict()
        self.sent_buckets = defaultdict(set)
        self.trampoline_forwarding_failures = {}
        self.inflight_payments = set()
        self.preimages = {}
        self.stopping_soon = False

    def get_invoice_status(self, key):
        pass

    @property
    def lock(self):
        return noop_lock()

    @property
    def channel_db(self):
        return self.network.channel_db if self.network else None

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
    try_force_closing = LNWallet.try_force_closing
    get_first_timestamp = lambda self: 0
    on_peer_successfully_established = LNWallet.on_peer_successfully_established
    get_channel_by_id = LNWallet.get_channel_by_id
    channels_for_peer = LNWallet.channels_for_peer
    _calc_routing_hints_for_invoice = LNWallet._calc_routing_hints_for_invoice
    handle_error_code_from_failed_htlc = LNWallet.handle_error_code_from_failed_htlc
    is_trampoline_peer = LNWallet.is_trampoline_peer
    wait_for_received_pending_htlcs_to_get_removed = LNWallet.wait_for_received_pending_htlcs_to_get_removed
    on_proxy_changed = LNWallet.on_proxy_changed
    _decode_channel_update_msg = LNWallet._decode_channel_update_msg
    _handle_chanupd_from_failed_htlc = LNWallet._handle_chanupd_from_failed_htlc


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
    #                A
    #     high fee /   \ low fee
    #             B     C
    #     high fee \   / low fee
    #                D
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

    def all_lnworkers(self) -> Iterable[MockLNWallet]:
        return self.w_a, self.w_b, self.w_c, self.w_d


class PaymentDone(Exception): pass
class SuccessfulTest(Exception): pass


class TestPeer(TestCaseForTestnet):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()
        self.asyncio_loop, self._stop_loop, self._loop_thread = create_and_start_event_loop()
        self._lnworkers_created = []  # type: List[MockLNWallet]

    def tearDown(self):
        async def cleanup_lnworkers():
            async with TaskGroup() as group:
                for lnworker in self._lnworkers_created:
                    await group.spawn(lnworker.stop())
            self._lnworkers_created.clear()
        run(cleanup_lnworkers())

        self.asyncio_loop.call_soon_threadsafe(self._stop_loop.set_result, 1)
        self._loop_thread.join(timeout=1)
        super().tearDown()

    def prepare_peers(self, alice_channel, bob_channel):
        k1, k2 = keypair(), keypair()
        alice_channel.node_id = k2.pubkey
        bob_channel.node_id = k1.pubkey
        t1, t2 = transport_pair(k1, k2, alice_channel.name, bob_channel.name)
        q1, q2 = asyncio.Queue(), asyncio.Queue()
        w1 = MockLNWallet(local_keypair=k1, chans=[alice_channel], tx_queue=q1, name=bob_channel.name)
        w2 = MockLNWallet(local_keypair=k2, chans=[bob_channel], tx_queue=q2, name=alice_channel.name)
        self._lnworkers_created.extend([w1, w2])
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

    def prepare_chans_and_peers_in_square(self, funds_distribution: Dict[str, Tuple[int, int]]=None) -> SquareGraph:
        if not funds_distribution:
            funds_distribution = {}
        key_a, key_b, key_c, key_d = [keypair() for i in range(4)]
        local_balance, remote_balance = funds_distribution.get('ab') or (None, None)
        chan_ab, chan_ba = create_test_channels(
            alice_name="alice", bob_name="bob",
            alice_pubkey=key_a.pubkey, bob_pubkey=key_b.pubkey,
            local_msat=local_balance,
            remote_msat=remote_balance,
        )
        local_balance, remote_balance = funds_distribution.get('ac') or (None, None)
        chan_ac, chan_ca = create_test_channels(
            alice_name="alice", bob_name="carol",
            alice_pubkey=key_a.pubkey, bob_pubkey=key_c.pubkey,
            local_msat=local_balance,
            remote_msat=remote_balance,
        )
        local_balance, remote_balance = funds_distribution.get('bd') or (None, None)
        chan_bd, chan_db = create_test_channels(
            alice_name="bob", bob_name="dave",
            alice_pubkey=key_b.pubkey, bob_pubkey=key_d.pubkey,
            local_msat=local_balance,
            remote_msat=remote_balance,
        )
        local_balance, remote_balance = funds_distribution.get('cd') or (None, None)
        chan_cd, chan_dc = create_test_channels(
            alice_name="carol", bob_name="dave",
            alice_pubkey=key_c.pubkey, bob_pubkey=key_d.pubkey,
            local_msat=local_balance,
            remote_msat=remote_balance,
        )
        trans_ab, trans_ba = transport_pair(key_a, key_b, chan_ab.name, chan_ba.name)
        trans_ac, trans_ca = transport_pair(key_a, key_c, chan_ac.name, chan_ca.name)
        trans_bd, trans_db = transport_pair(key_b, key_d, chan_bd.name, chan_db.name)
        trans_cd, trans_dc = transport_pair(key_c, key_d, chan_cd.name, chan_dc.name)
        txq_a, txq_b, txq_c, txq_d = [asyncio.Queue() for i in range(4)]
        w_a = MockLNWallet(local_keypair=key_a, chans=[chan_ab, chan_ac], tx_queue=txq_a, name="alice")
        w_b = MockLNWallet(local_keypair=key_b, chans=[chan_ba, chan_bd], tx_queue=txq_b, name="bob")
        w_c = MockLNWallet(local_keypair=key_c, chans=[chan_ca, chan_cd], tx_queue=txq_c, name="carol")
        w_d = MockLNWallet(local_keypair=key_d, chans=[chan_db, chan_dc], tx_queue=txq_d, name="dave")
        self._lnworkers_created.extend([w_a, w_b, w_c, w_d])
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

        # forwarding fees, etc
        chan_ab.forwarding_fee_proportional_millionths *= 500
        chan_ab.forwarding_fee_base_msat *= 500
        chan_ba.forwarding_fee_proportional_millionths *= 500
        chan_ba.forwarding_fee_base_msat *= 500
        chan_bd.forwarding_fee_proportional_millionths *= 500
        chan_bd.forwarding_fee_base_msat *= 500
        chan_db.forwarding_fee_proportional_millionths *= 500
        chan_db.forwarding_fee_base_msat *= 500

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
            routing_hints = await w2._calc_routing_hints_for_invoice(amount_msat)
        else:
            routing_hints = []
        trampoline_hints = []
        for r in routing_hints:
            node_id, short_channel_id, fee_base_msat, fee_proportional_millionths, cltv_expiry_delta = r[1][0]
            if len(r[1])== 1 and w2.is_trampoline_peer(node_id):
                trampoline_hints.append(('t', (node_id, fee_base_msat, fee_proportional_millionths, cltv_expiry_delta)))
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
        lnaddr, pay_req = run(self.prepare_invoice(w2))
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
        """Alice pays Bob a single HTLC via direct channel."""
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, w2.get_payment_status(lnaddr.paymenthash))
            result, log = await w1.pay_invoice(pay_req)
            self.assertTrue(result)
            self.assertEqual(PR_PAID, w2.get_payment_status(lnaddr.paymenthash))
            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                lnaddr, pay_req = await self.prepare_invoice(w2)
                invoice_features = lnaddr.get_features()
                self.assertFalse(invoice_features.supports(LnFeatures.BASIC_MPP_OPT))
                await group.spawn(pay(lnaddr, pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_race(self):
        """Alice and Bob pay each other simultaneously.
        They both send 'update_add_htlc' and receive each other's update
        before sending 'commitment_signed'. Neither party should fulfill
        the respective HTLCs until those are irrevocably committed to.
        """
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        async def pay():
            await asyncio.wait_for(p1.initialized, 1)
            await asyncio.wait_for(p2.initialized, 1)
            # prep
            _maybe_send_commitment1 = p1.maybe_send_commitment
            _maybe_send_commitment2 = p2.maybe_send_commitment
            lnaddr2, pay_req2 = await self.prepare_invoice(w2)
            lnaddr1, pay_req1 = await self.prepare_invoice(w1)
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
            async with TaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.01)
                await group.spawn(pay())
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
        payment_value_msat = 10_000_000  # make it large enough so that there are actually HTLCs on the ctx
        max_htlcs_in_flight = asyncio.Semaphore(5)
        async def single_payment(pay_req):
            async with max_htlcs_in_flight:
                await w1.pay_invoice(pay_req)
        async def many_payments():
            async with TaskGroup() as group:
                pay_reqs_tasks = [await group.spawn(self.prepare_invoice(w2, amount_msat=payment_value_msat))
                                  for i in range(num_payments)]
            async with TaskGroup() as group:
                for pay_req_task in pay_reqs_tasks:
                    lnaddr, pay_req = pay_req_task.result()
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
        graph = self.prepare_chans_and_peers_in_square()
        peers = graph.all_peers()
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
            result, log = await graph.w_a.pay_invoice(pay_req)
            self.assertTrue(result)
            self.assertEqual(PR_PAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                lnaddr, pay_req = await self.prepare_invoice(graph.w_d, include_routing_hints=True)
                await group.spawn(pay(lnaddr, pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop_with_preselected_path(self):
        graph = self.prepare_chans_and_peers_in_square()
        peers = graph.all_peers()
        async def pay(pay_req):
            with self.subTest(msg="bad path: edges do not chain together"):
                path = [PathEdge(start_node=graph.w_a.node_keypair.pubkey,
                                 end_node=graph.w_c.node_keypair.pubkey,
                                 short_channel_id=graph.chan_ab.short_channel_id),
                        PathEdge(start_node=graph.w_b.node_keypair.pubkey,
                                 end_node=graph.w_d.node_keypair.pubkey,
                                 short_channel_id=graph.chan_bd.short_channel_id)]
                with self.assertRaises(LNPathInconsistent):
                    await graph.w_a.pay_invoice(pay_req, full_path=path)
            with self.subTest(msg="bad path: last node id differs from invoice pubkey"):
                path = [PathEdge(start_node=graph.w_a.node_keypair.pubkey,
                                 end_node=graph.w_b.node_keypair.pubkey,
                                 short_channel_id=graph.chan_ab.short_channel_id)]
                with self.assertRaises(LNPathInconsistent):
                    await graph.w_a.pay_invoice(pay_req, full_path=path)
            with self.subTest(msg="good path"):
                path = [PathEdge(start_node=graph.w_a.node_keypair.pubkey,
                                 end_node=graph.w_b.node_keypair.pubkey,
                                 short_channel_id=graph.chan_ab.short_channel_id),
                        PathEdge(start_node=graph.w_b.node_keypair.pubkey,
                                 end_node=graph.w_d.node_keypair.pubkey,
                                 short_channel_id=graph.chan_bd.short_channel_id)]
                result, log = await graph.w_a.pay_invoice(pay_req, full_path=path)
                self.assertTrue(result)
                self.assertEqual(
                    [edge.short_channel_id for edge in path],
                    [edge.short_channel_id for edge in log[0].route])
            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                lnaddr, pay_req = await self.prepare_invoice(graph.w_d, include_routing_hints=True)
                await group.spawn(pay(pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop_temp_node_failure(self):
        graph = self.prepare_chans_and_peers_in_square()
        graph.w_b.network.config.set_key('test_fail_htlcs_with_temp_node_failure', True)
        graph.w_c.network.config.set_key('test_fail_htlcs_with_temp_node_failure', True)
        peers = graph.all_peers()
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
            result, log = await graph.w_a.pay_invoice(pay_req)
            self.assertFalse(result)
            self.assertEqual(PR_UNPAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
            self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, log[0].failure_msg.code)
            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                lnaddr, pay_req = await self.prepare_invoice(graph.w_d, include_routing_hints=True)
                await group.spawn(pay(lnaddr, pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_multihop_route_around_failure(self):
        # Alice will pay Dave. Alice first tries A->C->D route, due to lower fees, but Carol
        # will fail the htlc and get blacklisted. Alice will then try A->B->D and succeed.
        graph = self.prepare_chans_and_peers_in_square()
        graph.w_c.network.config.set_key('test_fail_htlcs_with_temp_node_failure', True)
        peers = graph.all_peers()
        async def pay(lnaddr, pay_req):
            self.assertEqual(500000000000, graph.chan_ab.balance(LOCAL))
            self.assertEqual(500000000000, graph.chan_db.balance(LOCAL))
            self.assertEqual(PR_UNPAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
            result, log = await graph.w_a.pay_invoice(pay_req, attempts=2)
            self.assertEqual(2, len(log))
            self.assertTrue(result)
            self.assertEqual(PR_PAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
            self.assertEqual([graph.chan_ac.short_channel_id, graph.chan_cd.short_channel_id],
                             [edge.short_channel_id for edge in log[0].route])
            self.assertEqual([graph.chan_ab.short_channel_id, graph.chan_bd.short_channel_id],
                             [edge.short_channel_id for edge in log[1].route])
            self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, log[0].failure_msg.code)
            self.assertEqual(499899450000, graph.chan_ab.balance(LOCAL))
            await asyncio.sleep(0.2)  # wait for COMMITMENT_SIGNED / REVACK msgs to update balance
            self.assertEqual(500100000000, graph.chan_db.balance(LOCAL))
            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                lnaddr, pay_req = await self.prepare_invoice(graph.w_d, include_routing_hints=True)
                invoice_features = lnaddr.get_features()
                self.assertFalse(invoice_features.supports(LnFeatures.BASIC_MPP_OPT))
                await group.spawn(pay(lnaddr, pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_payment_with_temp_channel_failure_and_liquidty_hints(self):
        # prepare channels such that a temporary channel failure happens at c->d
        funds_distribution = {
            'ac': (200_000_000, 200_000_000),  # low fees
            'cd': (50_000_000, 200_000_000),   # low fees
            'ab': (200_000_000, 200_000_000),  # high fees
            'bd': (200_000_000, 200_000_000),  # high fees
        }
        # the payment happens in two attempts:
        # 1. along a->c->d due to low fees with temp channel failure:
        #   with chanupd: ORPHANED, private channel update
        #   c->d gets a liquidity hint and gets blocked
        # 2. along a->b->d with success
        amount_to_pay = 100_000_000
        graph = self.prepare_chans_and_peers_in_square(funds_distribution)
        peers = graph.all_peers()
        async def pay(lnaddr, pay_req):
            self.assertEqual(PR_UNPAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
            result, log = await graph.w_a.pay_invoice(pay_req, attempts=3)
            self.assertTrue(result)
            self.assertEqual(2, len(log))
            self.assertEqual(PR_PAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
            self.assertEqual(OnionFailureCode.TEMPORARY_CHANNEL_FAILURE, log[0].failure_msg.code)

            liquidity_hints = graph.w_a.network.path_finder.liquidity_hints
            pubkey_a = graph.w_a.node_keypair.pubkey
            pubkey_b = graph.w_b.node_keypair.pubkey
            pubkey_c = graph.w_c.node_keypair.pubkey
            pubkey_d = graph.w_d.node_keypair.pubkey
            # check liquidity hints for failing route:
            hint_ac = liquidity_hints.get_hint(graph.chan_ac.short_channel_id)
            hint_cd = liquidity_hints.get_hint(graph.chan_cd.short_channel_id)
            self.assertEqual(amount_to_pay, hint_ac.can_send(pubkey_a < pubkey_c))
            self.assertEqual(None, hint_ac.cannot_send(pubkey_a < pubkey_c))
            self.assertEqual(None, hint_cd.can_send(pubkey_c < pubkey_d))
            self.assertEqual(amount_to_pay, hint_cd.cannot_send(pubkey_c < pubkey_d))
            # check liquidity hints for successful route:
            hint_ab = liquidity_hints.get_hint(graph.chan_ab.short_channel_id)
            hint_bd = liquidity_hints.get_hint(graph.chan_bd.short_channel_id)
            self.assertEqual(amount_to_pay, hint_ab.can_send(pubkey_a < pubkey_b))
            self.assertEqual(None, hint_ab.cannot_send(pubkey_a < pubkey_b))
            self.assertEqual(amount_to_pay, hint_bd.can_send(pubkey_b < pubkey_d))
            self.assertEqual(None, hint_bd.cannot_send(pubkey_b < pubkey_d))

            raise PaymentDone()
        async def f():
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                lnaddr, pay_req = await self.prepare_invoice(graph.w_d, amount_msat=amount_to_pay, include_routing_hints=True)
                await group.spawn(pay(lnaddr, pay_req))
        with self.assertRaises(PaymentDone):
            run(f())

    def _run_mpp(self, graph, kwargs1, kwargs2):
        self.assertEqual(500_000_000_000, graph.chan_ab.balance(LOCAL))
        self.assertEqual(500_000_000_000, graph.chan_ac.balance(LOCAL))
        amount_to_pay = 600_000_000_000
        peers = graph.all_peers()
        async def pay(attempts=1,
                      alice_uses_trampoline=False,
                      bob_forwarding=True,
                      mpp_invoice=True):
            if mpp_invoice:
                graph.w_d.features |= LnFeatures.BASIC_MPP_OPT
            if not bob_forwarding:
                graph.w_b.enable_htlc_forwarding = False
            if alice_uses_trampoline:
                if graph.w_a.network.channel_db:
                    graph.w_a.network.channel_db.stop()
                    await graph.w_a.network.channel_db.stopped_event.wait()
                    graph.w_a.network.channel_db = None
            else:
                assert graph.w_a.network.channel_db is not None
            lnaddr, pay_req = await self.prepare_invoice(graph.w_d, include_routing_hints=True, amount_msat=amount_to_pay)
            self.assertEqual(PR_UNPAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
            result, log = await graph.w_a.pay_invoice(pay_req, attempts=attempts)
            if not bob_forwarding:
                # reset to previous state, sleep 2s so that the second htlc can time out
                graph.w_b.enable_htlc_forwarding = True
                await asyncio.sleep(2)
            if result:
                self.assertEqual(PR_PAID, graph.w_d.get_payment_status(lnaddr.paymenthash))
                raise PaymentDone()
            else:
                raise NoPathFound()

        async def f(kwargs):
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                await group.spawn(pay(**kwargs))

        with self.assertRaises(NoPathFound):
            run(f(kwargs1))
        with self.assertRaises(PaymentDone):
            run(f(kwargs2))

    @needs_test_with_all_chacha20_implementations
    def test_multipart_payment_with_timeout(self):
        graph = self.prepare_chans_and_peers_in_square()
        self._run_mpp(graph, {'bob_forwarding':False}, {'bob_forwarding':True})

    @needs_test_with_all_chacha20_implementations
    def test_multipart_payment(self):
        graph = self.prepare_chans_and_peers_in_square()
        self._run_mpp(graph, {'mpp_invoice':False}, {'mpp_invoice':True})

    @needs_test_with_all_chacha20_implementations
    def test_multipart_payment_with_trampoline(self):
        # single attempt will fail with insufficient trampoline fee
        graph = self.prepare_chans_and_peers_in_square()
        self._run_mpp(graph, {'alice_uses_trampoline':True, 'attempts':1}, {'alice_uses_trampoline':True, 'attempts':3})

    @needs_test_with_all_chacha20_implementations
    def test_fail_pending_htlcs_on_shutdown(self):
        """Alice tries to pay Dave via MPP. Dave receives some HTLCs but not all.
        Dave shuts down (stops wallet).
        We test if Dave fails the pending HTLCs during shutdown.
        """
        graph = self.prepare_chans_and_peers_in_square()
        self.assertEqual(500_000_000_000, graph.chan_ab.balance(LOCAL))
        self.assertEqual(500_000_000_000, graph.chan_ac.balance(LOCAL))
        amount_to_pay = 600_000_000_000
        peers = graph.all_peers()
        graph.w_d.MPP_EXPIRY = 120
        graph.w_d.TIMEOUT_SHUTDOWN_FAIL_PENDING_HTLCS = 3
        async def pay():
            graph.w_d.features |= LnFeatures.BASIC_MPP_OPT
            graph.w_b.enable_htlc_forwarding = False  # Bob will hold forwarded HTLCs
            assert graph.w_a.network.channel_db is not None
            lnaddr, pay_req = await self.prepare_invoice(graph.w_d, include_routing_hints=True, amount_msat=amount_to_pay)
            try:
                async with timeout_after(0.5):
                    result, log = await graph.w_a.pay_invoice(pay_req, attempts=1)
            except TaskTimeout:
                # by now Dave hopefully received some HTLCs:
                self.assertTrue(len(graph.chan_dc.hm.htlcs(LOCAL)) > 0)
                self.assertTrue(len(graph.chan_dc.hm.htlcs(REMOTE)) > 0)
            else:
                self.fail(f"pay_invoice finished but was not supposed to. result={result}")
            await graph.w_d.stop()
            # Dave is supposed to have failed the pending incomplete MPP HTLCs
            self.assertEqual(0, len(graph.chan_dc.hm.htlcs(LOCAL)))
            self.assertEqual(0, len(graph.chan_dc.hm.htlcs(REMOTE)))
            raise SuccessfulTest()

        async def f():
            async with TaskGroup() as group:
                for peer in peers:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                await group.spawn(pay())

        with self.assertRaises(SuccessfulTest):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_close(self):
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, _q1, _q2 = self.prepare_peers(alice_channel, bob_channel)
        w1.network.config.set_key('dynamic_fees', False)
        w2.network.config.set_key('dynamic_fees', False)
        w1.network.config.set_key('fee_per_kb', 5000)
        w2.network.config.set_key('fee_per_kb', 1000)
        w2.enable_htlc_settle = False
        lnaddr, pay_req = run(self.prepare_invoice(w2))
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
    def test_close_upfront_shutdown_script(self):
        alice_channel, bob_channel = create_test_channels()

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

        with self.assertRaises(UpfrontShutdownScriptViolation):
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
        alice_channel, bob_channel = create_test_channels()
        p1, p2, w1, w2, q1, q2 = self.prepare_peers(alice_channel, bob_channel)
        lnaddr, pay_req = run(self.prepare_invoice(w2))

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
                min_cltv_expiry=min_cltv_expiry)
            await asyncio.gather(pay, p1._message_loop(), p2._message_loop(), p1.htlc_switch(), p2.htlc_switch())
        with self.assertRaises(PaymentFailure):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_sending_weird_messages_that_should_be_ignored(self):
        alice_channel, bob_channel = create_test_channels()
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
            async with TaskGroup() as group:
                for peer in [p1, p2]:
                    await group.spawn(peer._message_loop())
                    await group.spawn(peer.htlc_switch())
                await asyncio.sleep(0.2)
                await group.spawn(send_weird_messages())

        with self.assertRaises(SuccessfulTest):
            run(f())

    @needs_test_with_all_chacha20_implementations
    def test_sending_weird_messages__unknown_even_type(self):
        alice_channel, bob_channel = create_test_channels()
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
            async with TaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                failing_task = await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.2)
                await group.spawn(send_weird_messages())

        with self.assertRaises(lnmsg.UnknownMandatoryMsgType):
            run(f())
        self.assertTrue(isinstance(failing_task.exception(), lnmsg.UnknownMandatoryMsgType))

    @needs_test_with_all_chacha20_implementations
    def test_sending_weird_messages__known_msg_with_insufficient_length(self):
        alice_channel, bob_channel = create_test_channels()
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
            async with TaskGroup() as group:
                await group.spawn(p1._message_loop())
                await group.spawn(p1.htlc_switch())
                failing_task = await group.spawn(p2._message_loop())
                await group.spawn(p2.htlc_switch())
                await asyncio.sleep(0.2)
                await group.spawn(send_weird_messages())

        with self.assertRaises(lnmsg.UnexpectedEndOfStream):
            run(f())
        self.assertTrue(isinstance(failing_task.exception(), lnmsg.UnexpectedEndOfStream))


def run(coro):
    return asyncio.run_coroutine_threadsafe(coro, loop=asyncio.get_event_loop()).result()
