"""A peer that resends the channels we pruned gets dropped and avoided; other peers do not.

Real ChannelDB (sqlite on disk) + real LNGossip + real Peer objects running their real main_loop
over a fake wire. Only the signature checks of gossip are switched off.
"""
import asyncio
import time
from unittest import mock

from electrum import util, constants
from electrum.channel_db import ChannelDB
from electrum.lnworker import LNGossip, LNPeerManager
from electrum.lnpeer import Peer
from electrum.lnmsg import encode_msg, decode_msg
from electrum.lntransport import LNPeerAddr, LNTransport
from electrum.lnutil import ShortChannelID, LnFeatures
from electrum.simple_config import SimpleConfig
from electrum.sql_db import sql
from electrum.util import bfh
from aiorpcx import NetAddress
from electrum_ecc import ECPrivkey
from electrum.crypto import sha256

from . import ElectrumTestCase
from . import lnhelpers


LIMIT = LNGossip.GOSSIP_MAX_PRUNED_CHANS_ANNOUNCED


def scid(number: int) -> ShortChannelID:
    return ShortChannelID(bfh(format(number, '016x')))


_NODES = {}


def node(character: str) -> bytes:
    """a made-up node id that is a valid point"""
    if character not in _NODES:
        _NODES[character] = ECPrivkey(sha256(b'pruned-flood-' + character.encode())).get_public_key_bytes()
    return _NODES[character]


def chan_ann(number: int, n1: bytes = None, n2: bytes = None) -> bytes:
    n1, n2 = sorted([n1 or node('p'), n2 or node('q')])
    return encode_msg(
        'channel_announcement',
        node_signature_1=bytes(64), node_signature_2=bytes(64),
        bitcoin_signature_1=bytes(64), bitcoin_signature_2=bytes(64),
        len=0, features=b'', chain_hash=constants.net.rev_genesis_bytes(), short_channel_id=scid(number),
        node_id_1=n1, node_id_2=n2, bitcoin_key_1=n1, bitcoin_key_2=n2)


def chan_upd(number: int, timestamp: int, direction: int = 0) -> bytes:
    return encode_msg(
        'channel_update', signature=bytes(64), chain_hash=constants.net.rev_genesis_bytes(),
        short_channel_id=scid(number), timestamp=timestamp, message_flags=b'\x00',
        channel_flags=bytes([direction]), cltv_expiry_delta=40, htlc_minimum_msat=1, fee_base_msat=0,
        fee_proportional_millionths=direction)


def query_end() -> bytes:
    return encode_msg('reply_short_channel_ids_end', chain_hash=constants.net.rev_genesis_bytes(),
                      full_information=b'\x01')


class _Wire(LNTransport):
    """A connection we initiated, whose other end is the test."""

    def __init__(self, privkey: bytes, peer_addr: LNPeerAddr):
        self.privkey = privkey
        self.peer_addr = peer_addr
        self.queue = asyncio.Queue()
        self.sent = []
        self.closed = False
        self.num_read = 0

    def name(self):
        return 'wire-' + self.peer_addr.pubkey.hex()[2:8]

    async def handshake(self):
        return None

    def send_bytes(self, msg):
        self.sent.append(msg)

    async def send_bytes_and_drain(self, msg):
        self.sent.append(msg)

    async def read_messages(self):
        while True:
            data = await self.queue.get()
            self.num_read += 1
            yield data

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    def remote_pubkey(self):
        return self.peer_addr.pubkey

    def sent_msgs(self, name: str):
        return [payload for msg_name, payload in map(decode_msg, self.sent) if msg_name == name]

    def feed(self, *msgs: bytes):
        for msg in msgs:
            self.queue.put_nowait(msg)


class _Net:
    interface = None
    daemon = None
    proxy = None
    is_proxy_tor = False

    def __init__(self, config):
        self.config = config
        self.asyncio_loop = util.get_asyncio_loop()
        self.channel_db = None
        self.lngossip = None

    def trigger_callback(self, *args):
        pass

    def register_callback(self, *args):
        pass

    def get_local_height(self):
        return 800_000


class TestPeerThatResendsPrunedChannels(ElectrumTestCase):
    TESTNET = True
    PRUNED = range(1000, 1400)  # 400 channels in the memory of pruned ones
    KNOWN = range(1, 6)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.net = _Net(self.config)
        self.cdb = None
        self.tasks = []
        self.gossips = []

    async def asyncTearDown(self):
        for task in self.tasks:
            task.cancel()
        for g in self.gossips:
            g.lnpeermgr.unregister_callbacks()
            for peer in list(g.lnpeermgr.peers.values()):
                peer.close_and_cleanup()
        await asyncio.sleep(0)
        if self.cdb:
            self.cdb.stop()
            await self.cdb.stopped_event.wait()
        await super().asyncTearDown()

    # ----- helpers

    async def until(self, cond, *, timeout=15, what=''):
        deadline = time.monotonic() + timeout
        while not cond():
            if time.monotonic() > deadline:
                self.fail(f"timed out waiting for: {what}")
            await asyncio.sleep(0.01)

    async def open_db(self) -> ChannelDB:
        self.cdb = cdb = ChannelDB(self.net)
        await cdb.load_data()
        await self.until(cdb.data_loaded.is_set, what='db loaded')
        # only the signatures are not checked
        cdb.verify_channel_announcement = lambda payload: None
        cdb.verify_channel_update = lambda payload, **kwargs: None
        self.net.channel_db = cdb
        return cdb

    async def close_db(self, g: LNGossip = None):
        """as Network.stop_gossip(full_shutdown=True)"""
        if g is not None:
            await g.stop()
            self.net.lngossip = None
        self.cdb.stop()
        await self.cdb.stopped_event.wait()
        self.cdb = self.net.channel_db = None

    async def fill_db(self, *, synced_until: int = None, with_memory: bool = True) -> ChannelDB:
        """Known channels with fresh policies, nodes with addresses, a memory of pruned channels,
        written to disk and loaded again as at a start of the app."""
        cdb = await self.open_db()
        now = int(time.time())
        for n in self.KNOWN:
            for raw in (chan_ann(n, node('f'), node('n')),):
                payload = decode_msg(raw)[1]
                payload['raw'] = raw
                cdb.add_channel_announcements(payload)
            for direction in (0, 1):
                raw = chan_upd(n, now - 7200, direction)
                payload = decode_msg(raw)[1]
                payload['raw'] = raw
                cdb.add_channel_update(payload, verify=False)
        if with_memory:
            cdb._remember_orphaned_channels({scid(n) for n in self.PRUNED})
        if synced_until is not None:
            await cdb.save_synced_until(synced_until)
        # flush what is queued, then restart
        await cdb._db_forget_orphaned_channels(set())
        await self.close_db()
        return await self.open_db()

    def new_gossip(self) -> LNGossip:
        g = LNGossip(self.config)
        g.lnpeermgr.network = self.net
        self.net.lngossip = g
        self.gossips.append(g)
        return g

    async def connect(self, g: LNGossip, character: str, *, listed_ids=(), wait_for_filter=True):
        """A real Peer of LNGossip, up to the point where it has sent its gossip_timestamp_filter."""
        addr = LNPeerAddr(f'203.0.113.{ord(character) % 200 + 1}', 9735, node(character))
        wire = _Wire(g.lnpeermgr.node_keypair.privkey, addr)
        peer = Peer(g, node(character), wire)
        g.lnpeermgr._peers[peer.pubkey] = peer
        task = asyncio.ensure_future(peer.main_loop())
        self.tasks.append(task)
        await self.until(lambda: wire.sent, what='our init')
        wire.feed(wire.sent[0])  # the remote has the same features as we do
        await self.until(lambda: wire.sent_msgs('query_channel_range'), what='query_channel_range')
        query = wire.sent_msgs('query_channel_range')[0]
        ids = b''.join(sorted(bytes(i) for i in listed_ids))
        wire.feed(encode_msg(
            'reply_channel_range', chain_hash=constants.net.rev_genesis_bytes(),
            first_blocknum=query['first_blocknum'], number_of_blocks=query['number_of_blocks'],
            sync_complete=b'\x01', len=1 + len(ids), encoded_short_ids=b'\x00' + ids))
        if wait_for_filter:
            await self.until(lambda: peer.our_gossip_timestamp_filter is not None, what='gossip_timestamp_filter')
        return peer, wire, task

    # ----- the peer that resends the channels we pruned

    async def test_flooder_is_cut_at_the_limit_replaced_and_not_taken_again(self):
        synced_until = int(time.time()) - 3600
        cdb = await self.fill_db(synced_until=synced_until)
        self.assertEqual(synced_until, cdb.synced_until_at_load)
        self.assertEqual(len(self.PRUNED), len(cdb.get_recently_orphaned_channel_ids()))
        g = self.new_gossip()
        g.GOSSIP_BACKLOG_NUM_PEERS = 1  # as gossip_catch_up.catch_up
        backlog_start = synced_until - g.GOSSIP_SYNCED_MARGIN
        flooder, f_wire, f_task = await self.connect(g, 'f')
        normal, n_wire, n_task = await self.connect(g, 'n')
        self.assertEqual([backlog_start], [m['first_timestamp'] for m in f_wire.sent_msgs('gossip_timestamp_filter')])
        self.assertEqual(1, len(n_wire.sent_msgs('gossip_timestamp_filter')))
        self.assertNotEqual(backlog_start, n_wire.sent_msgs('gossip_timestamp_filter')[0]['first_timestamp'])
        # both are "recent peers" now, the flooder's address is the last good one
        self.assertEqual({node('f'), node('n')}, {p.pubkey for p in cdb.get_recent_peers()})
        read_before = f_wire.num_read
        # the flood: announcements without policies, of all the channels we pruned
        f_wire.feed(*[chan_ann(n) for n in self.PRUNED])
        await asyncio.wait_for(flooder.got_disconnected.wait(), 10)
        await asyncio.wait_for(f_task, 10)
        # cut early: at the limit, the rest is not read
        self.assertEqual(LIMIT, f_wire.num_read - read_before)
        self.assertEqual(len(self.PRUNED) - LIMIT, f_wire.queue.qsize())
        self.assertTrue(f_wire.closed)
        self.assertNotIn(node('f'), g.lnpeermgr.peers)
        self.assertEqual(1, g._num_peers_resending_pruned_chans)
        # the normal peer stays, and replaces it as the source of the backlog in the next tick
        self.assertFalse(normal.got_disconnected.is_set())
        g._gossip_sync_tick()
        self.assertEqual(backlog_start, n_wire.sent_msgs('gossip_timestamp_filter')[-1]['first_timestamp'])
        self.assertEqual(2, len(n_wire.sent_msgs('gossip_timestamp_filter')))
        # not taken as a peer again: not from the recent ones, not at random (a new process: no retry delays)
        self.assertTrue(cdb.is_avoided_peer(node('f')))
        g.lnpeermgr._clear_addr_retry_times()
        normal.close_and_cleanup()
        with cdb.lock:
            cdb._nodes[node('f')] = cdb._nodes[node('n')] = cdb._nodes[node('x')] = mock.Mock()
            cdb._addresses[node('x')][NetAddress('203.0.113.250', 9735)] = 0
        taken = set()
        for _ in range(60):
            for addr in await g.lnpeermgr._get_next_peers_to_try():
                taken.add(addr.pubkey)
        self.assertNotIn(node('f'), taken)
        self.assertIn(node('n'), taken)
        # what a wallet uses to reach the peer of its channel is all there
        f_addr = f_wire.peer_addr
        self.assertEqual(f_addr, cdb.get_last_good_address(node('f')))
        self.assertEqual([(f_addr.host, f_addr.port)], [(h, p) for h, p, ts in cdb.get_node_addresses(node('f'))])
        wallet_mgr = LNPeerManager(
            g.lnpeermgr.node_keypair, lnwallet_or_lngossip=mock.Mock(), features=LnFeatures(0), config=self.config)
        self.addCleanup(wallet_mgr.unregister_callbacks)
        wallet_mgr.network = self.net
        wallet_mgr._add_peer = mock.AsyncMock()
        chan = mock.Mock(node_id=node('f'))
        chan.get_peer_addresses.return_value = []
        await LNPeerManager._reestablish_peer_for_given_channel.__wrapped__.__wrapped__(wallet_mgr, chan)
        wallet_mgr._add_peer.assert_awaited_once_with(f_addr.host, f_addr.port, node('f'))
        # ... and a wallet connecting to it does not make it a recent peer again
        cdb.add_recent_peer(f_addr)
        self.assertNotIn(node('f'), {p.pubkey for p in cdb.get_recent_peers()})
        # the next run: the app stops as it does, and starts again
        await self.close_db(g)
        cdb = await self.open_db()
        self.assertTrue(cdb.is_avoided_peer(node('f')))
        self.assertEqual({node('n')}, {p.pubkey for p in cdb.get_recent_peers()})
        self.assertEqual(f_addr, cdb.get_last_good_address(node('f')))
        g2 = self.new_gossip()
        with cdb.lock:
            cdb._nodes[node('f')] = cdb._nodes[node('n')] = mock.Mock()
        taken = set()
        for _ in range(60):
            for addr in await g2.lnpeermgr._get_next_peers_to_try():
                taken.add(addr.pubkey)
        self.assertEqual({node('n')}, taken)

    async def test_flooder_is_cut_at_the_limit_also_while_we_query_it_for_channels(self):
        # (a query can take a minute, and the peer sends megabytes meanwhile)
        cdb = await self.fill_db()
        g = self.new_gossip()
        g.GOSSIP_BACKLOG_NUM_PEERS = 1
        await self.connect(g, 'n')  # the source of the backlog; such a peer is not asked for channels
        g.unknown_ids = {bytes(scid(n)) for n in range(5000, 5004)}
        flooder, wire, task = await self.connect(g, 'f')
        await self.until(lambda: wire.sent_msgs('query_short_channel_ids'), what='our query')
        self.assertTrue(flooder.is_querying_short_channel_ids)
        read_before = wire.num_read
        wire.feed(*[chan_ann(n) for n in self.PRUNED])
        await asyncio.wait_for(flooder.got_disconnected.wait(), 10)
        self.assertEqual(LIMIT, wire.num_read - read_before)
        self.assertTrue(cdb.is_avoided_peer(node('f')))

    # ----- other peers

    async def test_peer_that_sends_pruned_channels_with_fresh_policies_is_never_cut(self):
        # as lnd answers a gossip_timestamp_filter: channel_announcement, channel_update, channel_update
        cdb = await self.fill_db()
        g = self.new_gossip()
        peer, wire, task = await self.connect(g, 'n')
        now = int(time.time())
        for n in self.PRUNED:
            wire.feed(chan_ann(n), chan_upd(n, now - g.max_age - 3600, 0), chan_upd(n, now - 600, 1))
        await self.until(lambda: wire.queue.empty() and peer.recv_gossip_queue.empty(), what='all read')
        await self.until(lambda: g._num_chan_ann >= len(self.PRUNED), what='all processed')
        self.assertFalse(peer.got_disconnected.is_set())
        self.assertEqual(set(), peer.pruned_chans_announced)
        self.assertFalse(cdb.is_avoided_peer(node('n')))
        # and the channels are taken: they are alive
        missing = {scid(n) for n in self.PRUNED} - cdb.get_channel_ids()
        # (a batch can end between an announcement and its policy: that channel is then asked for)
        self.assertLessEqual(len(missing), 3, f"{len(missing)} of {len(self.PRUNED)} not taken")
        self.assertTrue({bytes(i) for i in missing} <= set(g.unknown_ids), "the rest is to be queried")
        self.assertEqual(set(), cdb.get_recently_orphaned_among([bytes(i) for i in missing]))
        self.assertEqual(0, g._num_peers_resending_pruned_chans)

    async def test_peer_that_replies_to_our_query_with_channels_without_policies_is_never_cut(self):
        cdb = await self.fill_db()
        g = self.new_gossip()
        g.GOSSIP_BACKLOG_NUM_PEERS = 1
        await self.connect(g, 'm')  # the source of the backlog; such a peer is not asked for channels
        asked = range(7000, 7400)  # channels peers list that we do not know and did not prune
        await g.add_new_ids([bytes(scid(n)) for n in asked], skip_recently_orphaned=True, listed_by=node('n'))
        await g.add_new_ids([bytes(scid(n)) for n in self.PRUNED], skip_recently_orphaned=True, listed_by=node('n'))
        self.assertEqual({bytes(scid(n)) for n in asked}, g.unknown_ids)  # the pruned ones are not asked for
        peer, wire, task = await self.connect(g, 'n')
        await self.until(lambda: wire.sent_msgs('query_short_channel_ids'), what='our query')
        wire.feed(*[chan_ann(n) for n in asked], query_end())
        await self.until(lambda: wire.queue.empty() and not peer.is_querying_short_channel_ids, what='reply read')
        self.assertFalse(peer.got_disconnected.is_set())
        self.assertEqual(set(), peer.pruned_chans_announced)
        self.assertFalse(cdb.is_avoided_peer(node('n')))

    async def test_peer_that_relays_new_channels_for_a_long_time_is_never_cut(self):
        cdb = await self.fill_db()
        g = self.new_gossip()
        peer, wire, task = await self.connect(g, 'n')
        now = int(time.time())
        # news: new channels with their policies; and now and then a pruned one that got a fresh policy
        for i, n in enumerate(range(20000, 23000)):
            wire.feed(chan_ann(n), chan_upd(n, now, 0))
            if i % 10 == 0:
                pruned = self.PRUNED[(i // 10) % len(self.PRUNED)]
                wire.feed(chan_ann(pruned), chan_upd(pruned, now, 0))
        await self.until(lambda: wire.queue.empty(), what='all read', timeout=60)
        self.assertFalse(peer.got_disconnected.is_set())
        self.assertEqual(set(), peer.pruned_chans_announced)
        self.assertFalse(cdb.is_avoided_peer(node('n')))

    async def test_limit_counts_distinct_channels(self):
        cdb = await self.fill_db()
        g = self.new_gossip()
        peer, wire, task = await self.connect(g, 'n')
        for _ in range(5):
            wire.feed(*[chan_ann(n) for n in self.PRUNED[:LIMIT - 1]])
        await self.until(lambda: wire.queue.empty(), what='all read')
        await asyncio.sleep(0.1)
        self.assertFalse(peer.got_disconnected.is_set())
        self.assertEqual(LIMIT - 1, len(peer.pruned_chans_announced))
        wire.feed(chan_ann(self.PRUNED[LIMIT - 1]))
        await asyncio.wait_for(peer.got_disconnected.wait(), 10)
        self.assertTrue(cdb.is_avoided_peer(node('n')))

    # ----- the shared ChannelDB

    async def test_avoiding_a_peer_leaves_the_other_meta_rows_alone(self):
        long_ago = int(time.time()) - 40 * 24 * 3600  # older than AVOIDED_PEER_PERIOD
        cdb = await self.fill_db(synced_until=long_ago)
        self.assertEqual(long_ago, cdb.synced_until_at_load)
        cdb.avoid_peer(node('f'))
        await cdb._db_forget_orphaned_channels(set())  # (waits for the writes queued so far)
        await self.close_db()
        cdb = await self.open_db()
        self.assertTrue(cdb.is_avoided_peer(node('f')))
        self.assertEqual(long_ago, cdb.synced_until_at_load)

    async def test_wallet_that_connects_to_an_avoided_node_still_records_its_address(self):
        cdb = await self.fill_db()
        old = LNPeerAddr('203.0.113.7', 9735, node('f'))
        with mock.patch('time.time', return_value=time.time() - 3600):
            cdb.add_recent_peer(old)
        cdb.avoid_peer(node('f'))
        moved = LNPeerAddr('203.0.113.8', 9735, node('f'))
        cdb.add_recent_peer(moved)  # LNPeerManager.on_peer_successfully_established, of the wallet
        self.assertEqual(moved, cdb.get_last_good_address(node('f')))
        await cdb._db_forget_orphaned_channels(set())
        await self.close_db()
        cdb = await self.open_db()
        self.assertEqual(moved, cdb.get_last_good_address(node('f')))
        self.assertEqual([], cdb.get_recent_peers())

    async def test_peer_that_gets_the_ids_of_a_query_that_timed_out_is_not_cut(self):
        """The channels of a query that timed out are asked for again; they may have got pruned meanwhile,
        and the peer that answers sends just what we asked it for."""
        cdb = await self.fill_db(with_memory=False)
        g = self.new_gossip()
        g.GOSSIP_BACKLOG_NUM_PEERS = 1
        await self.connect(g, 'm')  # the source of the backlog; such a peer is not asked for channels
        dead = range(7000, 7400)  # channels that peers list, and for which nobody has a policy anymore
        ids = {bytes(scid(n)) for n in dead}
        await g.add_new_ids(ids, skip_recently_orphaned=True, listed_by=node('a'))
        self.assertEqual(ids, g.unknown_ids)
        # a slow peer: it sends the channels, but the end of its reply does not come in time
        with mock.patch.object(Peer, 'QUERY_SHORT_CHANNEL_IDS_TIMEOUT', 8):
            slow, a_wire, a_task = await self.connect(g, 'a')
            await self.until(lambda: a_wire.sent_msgs('query_short_channel_ids'), what='query to the slow peer')
            self.assertEqual(set(), g.unknown_ids)
            a_wire.feed(*[chan_ann(n) for n in dead])
            await self.until(lambda: {scid(n) for n in dead} <= cdb.get_channel_ids(), what='channels added', timeout=7)
            self.assertEqual(0, len(slow.pruned_chans_announced))
            # the maintenance of the db comes around (every 120 s, while no channels wait to be asked for)
            self.tasks.append(asyncio.ensure_future(g.maintain_db()))
            await self.until(lambda: len(cdb.get_recently_orphaned_channel_ids()) == len(dead), what='pruned')
            await self.until(lambda: not slow.answers_channel_queries, what='the query timing out', timeout=10)
        self.assertFalse(slow.got_disconnected.is_set())
        self.assertEqual(ids, cdb.get_recently_orphaned_among(g.unknown_ids))  # they go back, and are pruned
        # a normal peer gets them, and answers our query: announcements, no policies (there are none)
        normal, n_wire, n_task = await self.connect(g, 'n')
        await self.until(lambda: n_wire.sent_msgs('query_short_channel_ids'), what='query to the normal peer')
        queries = n_wire.sent_msgs('query_short_channel_ids')
        asked = set(Peer.decode_short_ids(queries[0]['encoded_short_ids']))
        self.assertEqual(ids, cdb.get_recently_orphaned_among(asked))
        n_wire.feed(*[chan_ann(int.from_bytes(i, 'big')) for i in sorted(asked)], query_end())
        await self.until(lambda: n_wire.queue.empty() and not normal.is_querying_short_channel_ids, what='reply read')
        self.assertFalse(normal.got_disconnected.is_set(), "a normal peer that answered our own query got cut")
        self.assertFalse(cdb.is_avoided_peer(node('n')), "... and is avoided for 30 days")
        self.assertEqual(set(), normal.pruned_chans_announced)
        # nor is the slow one, when the rest of its reply arrives after all
        a_wire.feed(*[chan_ann(n) for n in dead], query_end())
        await self.until(lambda: a_wire.queue.empty(), what='late reply read')
        self.assertFalse(slow.got_disconnected.is_set())
        self.assertEqual(set(), slow.pruned_chans_announced)

    async def test_peer_that_sends_hundreds_of_announcements_before_their_policies_is_taken_for_one(self):
        """The limit of the rule (see LNGossip.on_channel_announced): it relies on a channel's policies
        following its announcement, as lnd sends them. Not so if hundreds of channels that came back to
        life were announced first, and their policies sent after."""
        cdb = await self.fill_db()
        g = self.new_gossip()
        peer, wire, task = await self.connect(g, 'n')
        now = int(time.time())
        wire.feed(*[chan_ann(n) for n in self.PRUNED])
        wire.feed(*[chan_upd(n, now - 600, 0) for n in self.PRUNED])
        await asyncio.wait_for(peer.got_disconnected.wait(), 10)
        self.assertTrue(cdb.is_avoided_peer(node('n')))
        # fewer than the limit are fine
        peer, wire, task = await self.connect(g, 'm')
        some = self.PRUNED[:LIMIT - 1]
        wire.feed(*[chan_ann(n) for n in some])
        wire.feed(*[chan_upd(n, now - 600, 0) for n in some])
        await self.until(lambda: wire.queue.empty(), what='all read')
        self.assertFalse(peer.got_disconnected.is_set())
        self.assertEqual(set(), peer.pruned_chans_announced)

    async def test_avoided_node_is_not_taken_from_the_fallback_nodes_nor_the_dns_seeds(self):
        cdb = await self.open_db()  # an empty db: no recent peers, no nodes to pick at random
        g = self.new_gossip()
        f, n = [LNPeerAddr(f'203.0.113.{i}', 9735, node(character)) for i, character in ((1, 'f'), (2, 'n'))]
        cdb.avoid_peer(node('f'))
        with mock.patch.object(constants.net, 'FALLBACK_LN_NODES', [f, n]):
            taken = [await g.lnpeermgr._get_next_peers_to_try() for _ in range(30)]
        self.assertEqual([[n]] * 30, taken)
        g.lnpeermgr._get_peers_from_dns_seeds = mock.AsyncMock(return_value=[f, n])
        with mock.patch.object(constants.net, 'FALLBACK_LN_NODES', [f]):
            self.assertEqual([n], await g.lnpeermgr._get_next_peers_to_try())

    async def test_avoided_peer_with_a_broken_record_does_not_keep_the_db_from_loading(self):
        cdb = await self.open_db()
        cdb.avoid_peer(node('f'))
        write = sql(lambda db: db.conn.cursor().execute(
            "INSERT INTO meta (key, value) VALUES ('avoided_peer:not-hex', 1), ('avoided_peerx', 2)"))
        await write(cdb)
        await self.close_db()
        cdb = await self.open_db()
        self.assertEqual({node('f')}, set(cdb._avoided_peers))

    async def test_channels_we_ask_a_peer_for_in_a_later_query_do_not_count(self):
        """The peer that gets the ids of a query that timed out has usually answered queries before."""
        cdb = await self.fill_db(with_memory=False)
        g = self.new_gossip()
        g.GOSSIP_BACKLOG_NUM_PEERS = 1
        await self.connect(g, 'm')  # the source of the backlog; such a peer is not asked for channels
        now = int(time.time())
        first = range(6000, 6010)
        g.unknown_ids = {bytes(scid(n)) for n in first}
        normal, wire, task = await self.connect(g, 'n')
        await self.until(lambda: wire.sent_msgs('query_short_channel_ids'), what='first query')
        for n in first:
            wire.feed(chan_ann(n), chan_upd(n, now, 0))
        wire.feed(query_end())
        await self.until(lambda: wire.queue.empty() and not normal.is_querying_short_channel_ids, what='first reply')
        # channels that got pruned while another peer was slow to answer are asked for again
        dead = range(7000, 7400)
        cdb._remember_orphaned_channels({scid(n) for n in dead})
        await g.add_new_ids([bytes(scid(n)) for n in dead])
        await self.until(lambda: len(wire.sent_msgs('query_short_channel_ids')) == 2, what='second query', timeout=5)
        wire.feed(*[chan_ann(n) for n in dead], query_end())
        await self.until(lambda: wire.queue.empty(), what='second reply')
        await asyncio.sleep(0.3)
        self.assertFalse(normal.got_disconnected.is_set(), "a normal peer that answered our own second query got cut")
        self.assertFalse(cdb.is_avoided_peer(node('n')))
        self.assertEqual(set(), normal.pruned_chans_announced)

    async def test_avoided_node_is_taken_at_random_again_after_the_period(self):
        cdb = await self.fill_db()
        with cdb.lock:
            cdb._nodes[node('f')] = mock.Mock()
        self.assertIn(node('f'), cdb.get_200_randomly_sorted_nodes_not_in(set()))
        cdb.avoid_peer(node('f'))
        self.assertNotIn(node('f'), cdb.get_200_randomly_sorted_nodes_not_in(set()))
        with mock.patch('time.time', return_value=time.time() + cdb.AVOIDED_PEER_PERIOD + 1):
            self.assertIn(node('f'), cdb.get_200_randomly_sorted_nodes_not_in(set()))

    async def test_avoided_peer_with_a_broken_record_before_a_good_one(self):
        cdb = await self.open_db()
        write = sql(lambda db: db.conn.cursor().execute(
            "INSERT INTO meta (key, value) VALUES ('avoided_peer:not-hex', ?)", (int(time.time()),)))
        await write(cdb)
        cdb.avoid_peer(node('f'))
        await cdb._db_forget_orphaned_channels(set())  # (waits for the writes queued so far)
        await self.close_db()
        cdb = await self.open_db()
        self.assertEqual({node('f')}, set(cdb._avoided_peers))

    async def test_expired_memory_does_not_count(self):
        cdb = await self.fill_db()
        with cdb.lock:
            for n in self.PRUNED:
                cdb._orphaned_channels[scid(n)] = int(time.time()) - cdb.ORPHANED_CHANNEL_REQUERY_DELAY - 1
        g = self.new_gossip()
        peer, wire, task = await self.connect(g, 'f')
        wire.feed(*[chan_ann(n) for n in self.PRUNED])
        await self.until(lambda: wire.queue.empty(), what='all read')
        await asyncio.sleep(0.1)
        self.assertFalse(peer.got_disconnected.is_set())
        self.assertFalse(cdb.is_avoided_peer(node('f')))


class TestWalletPeerIsNotCut(ElectrumTestCase):
    TESTNET = False

    async def test_channel_peer_of_a_wallet_that_floods_is_not_cut_nor_counted(self):
        graph = lnhelpers.prepare_chans_and_peers_in_graph(self)
        p1, p2 = graph.peers.values()
        w1, w2 = graph.workers.values()
        cdb = w1.network.channel_db
        self.assertIsNotNone(cdb)
        self.assertFalse(w1.uses_trampoline())
        # a real LNGossip on the same network and db as the wallet
        g = LNGossip(w1.config)
        self.addCleanup(g.lnpeermgr.unregister_callbacks)
        g.lnpeermgr.network = w1.network
        w1.network.lngossip = g
        pruned = range(1000, 1400)
        cdb._remember_orphaned_channels({scid(n) for n in pruned})
        self.assertIsNone(p1.our_gossip_timestamp_filter)
        for n in pruned:
            await p1._process_message(chan_ann(n))
        self.assertEqual(set(), p1.pruned_chans_announced)
        self.assertEqual(0, p1.recv_gossip_queue.qsize())
        self.assertFalse(cdb.is_avoided_peer(p1.pubkey))
        self.assertEqual(0, g._num_peers_resending_pruned_chans)
        # the same wallet in trampoline mode: no db at all
        cdb.stop()
        await cdb.stopped_event.wait()
        w1.network.channel_db = None
        self.assertTrue(w1.uses_trampoline())
        for n in pruned:
            await p1._process_message(chan_ann(n))
            await p1._process_message(chan_upd(n, int(time.time())))
        self.assertEqual(set(), p1.pruned_chans_announced)
