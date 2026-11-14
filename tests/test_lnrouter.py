import random
import time
import unittest
from math import inf
from unittest import mock
from typing import Optional
from os import urandom

from electrum import util
from electrum.channel_db import NodeInfo
from electrum.onion_message import is_onion_message_node
from electrum.trampoline import (create_trampoline_onion, _allocate_fee_budget_among_route, PLACEHOLDER_FEE,
                                 get_trampoline_budget)
from electrum.util import bfh
from electrum.lnutil import ShortChannelID, LnFeatures, PaymentFeeBudget
from electrum.lnonion import (OnionHopsDataSingle, new_onion_packet,
                              process_onion_packet, _decode_onion_error, decode_onion_error,
                              OnionFailureCode)
from electrum import bitcoin, lnrouter
from electrum.constants import BitcoinTestnet
from electrum.simple_config import SimpleConfig
from electrum.lnpeer import Peer
from electrum.sql_db import sql
from electrum.lnworker import LNGossip
from electrum.lnmsg import encode_msg
from electrum.lnrouter import (PathEdge, LiquidityHintMgr, DEFAULT_PENALTY_PROPORTIONAL_MILLIONTH,
                               fee_for_edge_msat, LNPaymentTRoute, TrampolineEdge,
                               HINT_DURATION, PAIR_FAILURE_PENALTY_FACTOR, RouteEdge,
                               NODE_FAILURE_MIN_SENDERS, NODE_FAILURE_PENALTY_FACTOR,
                               OFFLINE_NODE_DURATION, MAX_OUTDATED_POLICIES_PER_PAIR)

from . import ElectrumTestCase
from .test_bitcoin import needs_test_with_all_chacha20_implementations


def channel(number: int) -> ShortChannelID:
    return ShortChannelID(bfh(format(number, '016x')))


def node(character: str) -> bytes:
    return b'\x02' + f'{character}'.encode() * 32


def alias(character: str) -> bytes:
    return (character * 8).encode('utf-8')


def node_features(extra: LnFeatures = None) -> bytes:
    lnf = LnFeatures(0) | LnFeatures.VAR_ONION_OPT
    if extra:
        lnf |= extra
    return lnf.to_bytes(8, 'big')


class TestGossipBacklog(ElectrumTestCase):

    def _lngossip(self, *, latest_ts: Optional[int]):
        return mock.Mock(
            spec=LNGossip,
            channel_db=mock.Mock(latest_policy_ts_at_load=latest_ts),
            max_age=LNGossip.max_age,
            GOSSIP_BACKLOG_MARGIN=LNGossip.GOSSIP_BACKLOG_MARGIN,
            GOSSIP_BACKLOG_NUM_PEERS=LNGossip.GOSSIP_BACKLOG_NUM_PEERS,
            _num_gossip_backlog_requests=0,
            _gossip_backlog_ts_is_set=False,
            _gossip_backlog_latest_ts=None,
        )

    async def test_add_new_ids_skips_recently_orphaned_only_on_request(self):
        known, orphaned, new = b'\x01' * 8, b'\x02' * 8, b'\x03' * 8
        g = mock.Mock(
            spec=LNGossip,
            channel_db=mock.Mock(get_channel_ids=lambda: {known}, get_recently_orphaned_channel_ids=lambda: {orphaned}),
            lnpeermgr=mock.Mock(num_peers=lambda: 1),
            unknown_ids=set(),
        )
        await LNGossip.add_new_ids(g, [known, orphaned, new], skip_recently_orphaned=True)
        self.assertEqual({new}, g.unknown_ids)
        # orphaned channel_updates show that the channel is alive after all
        await LNGossip.add_new_ids(g, [orphaned])
        self.assertEqual({new, orphaned}, g.unknown_ids)

    async def test_query_gossip_uses_backlog_start_and_skips_orphaned_after_db_is_loaded(self):
        class StopQueryLoop(Exception): pass
        ids = {b'\x01' * 8}
        gossip = mock.Mock()
        gossip.network.lngossip = gossip
        gossip.channel_db.data_loaded.wait = mock.AsyncMock()
        def check_db_loaded(*args, **kwargs):
            gossip.channel_db.data_loaded.wait.assert_awaited_once()
        gossip.add_new_ids = mock.AsyncMock(side_effect=check_db_loaded)
        gossip.on_channel_range_reply = mock.AsyncMock(side_effect=check_db_loaded)
        gossip.get_gossip_timestamp_filter_start.return_value = 1234
        gossip.get_ids_to_query.side_effect = StopQueryLoop
        peer = mock.Mock(lnworker=gossip, is_initialized=lambda: True)
        peer.get_channel_range = mock.AsyncMock(return_value=(ids, True))
        with self.assertRaises(StopQueryLoop):
            await Peer._query_gossip(peer)
        gossip.add_new_ids.assert_awaited_once_with(ids, skip_recently_orphaned=True)
        gossip.on_channel_range_reply.assert_awaited_once_with(peer.pubkey, ids)
        peer.request_gossip.assert_called_once_with(1234)

    async def test_orphaned_channel_update_still_triggers_a_query(self):
        orphaned_id = b'\x02' * 8
        g = mock.Mock(
            spec=LNGossip,
            logger=mock.Mock(),
            channel_db=mock.Mock(),
            add_new_ids=mock.AsyncMock(),
            _num_chan_ann=0, _num_node_ann=0, _num_chan_upd=0, _num_chan_upd_good=0,
        )
        g.channel_db.data_loaded.wait = mock.AsyncMock()
        g.channel_db.add_channel_updates.return_value = mock.Mock(orphaned=[{'short_channel_id': orphaned_id}], good=[])
        await LNGossip.process_gossip(g, [], [], [{'short_channel_id': orphaned_id}])
        g.add_new_ids.assert_awaited_once_with([orphaned_id])

    def test_empty_db_requests_only_new_gossip(self):
        g = self._lngossip(latest_ts=None)
        with mock.patch('time.time', return_value=1_800_000_000):
            self.assertEqual(1_800_000_000, LNGossip.get_gossip_timestamp_filter_start(g))
        self.assertEqual(0, g._num_gossip_backlog_requests)

    def test_backlog_starts_before_latest_known_update_and_is_requested_from_few_peers(self):
        now = 1_800_000_000
        latest_ts = now - 12 * 3600
        g = self._lngossip(latest_ts=latest_ts)
        with mock.patch('time.time', return_value=now):
            for _ in range(LNGossip.GOSSIP_BACKLOG_NUM_PEERS):
                self.assertEqual(latest_ts - LNGossip.GOSSIP_BACKLOG_MARGIN, LNGossip.get_gossip_timestamp_filter_start(g))
            # further peers would just resend the same backlog
            self.assertEqual(now, LNGossip.get_gossip_timestamp_filter_start(g))

    def test_backlog_start_does_not_move_within_session(self):
        now = 1_800_000_000
        downtime_start = now - 12 * 3600
        g = self._lngossip(latest_ts=downtime_start)
        # gossip received from the first peer, or the update of a failed payment, is newer
        g.channel_db.get_latest_policy_timestamp = lambda: now
        expected = downtime_start - LNGossip.GOSSIP_BACKLOG_MARGIN
        with mock.patch('time.time', return_value=now):
            self.assertEqual(expected, LNGossip.get_gossip_timestamp_filter_start(g))
            self.assertEqual(expected, LNGossip.get_gossip_timestamp_filter_start(g))

    def test_backlog_is_not_older_than_max_age(self):
        now = 1_800_000_000
        g = self._lngossip(latest_ts=now - 10 * LNGossip.max_age)
        with mock.patch('time.time', return_value=now):
            self.assertEqual(now - LNGossip.max_age, LNGossip.get_gossip_timestamp_filter_start(g))


class TestChannelRangeMajority(ElectrumTestCase):

    OLD_HEIGHT = 100
    NUM_PEERS = LNGossip.CHANNEL_RANGE_NUM_PEERS

    def _scid(self, n: int, *, height: int = OLD_HEIGHT) -> ShortChannelID:
        return ShortChannelID.from_components(height, n, 0)

    def _lngossip(self, known, *, local_height: int = 1000, recently_updated=(), latest_policy_ts=None,
                  policy_timestamps=None):
        removed = []
        if latest_policy_ts is None:
            latest_policy_ts = int(time.time())
        if policy_timestamps is not None:
            has_policy_newer_than = lambda scid, ts: policy_timestamps.get(scid, 0) > ts
        else:
            has_policy_newer_than = lambda scid, ts: scid in recently_updated
        g = mock.Mock(
            spec=LNGossip,
            logger=mock.Mock(),
            channel_db=mock.Mock(
                get_channel_ids=lambda: set(known),
                remove_channels_absent_from_peers=removed.extend,
                has_policy_newer_than=has_policy_newer_than,
                get_latest_policy_timestamp=lambda: latest_policy_ts,
                latest_policy_ts_at_load=latest_policy_ts,
            ),
            network=mock.Mock(get_local_height=lambda: local_height),
            CHANNEL_RANGE_NUM_PEERS=LNGossip.CHANNEL_RANGE_NUM_PEERS,
            CHANNEL_RANGE_MIN_PEER_COVERAGE=LNGossip.CHANNEL_RANGE_MIN_PEER_COVERAGE,
            CHANNEL_RANGE_MAX_REMOVED_FRACTION=LNGossip.CHANNEL_RANGE_MAX_REMOVED_FRACTION,
            CHANNEL_RANGE_MIN_CHANNEL_AGE=LNGossip.CHANNEL_RANGE_MIN_CHANNEL_AGE,
            CHANNEL_RANGE_RECENT_POLICY_AGE=LNGossip.CHANNEL_RANGE_RECENT_POLICY_AGE,
            CHANNEL_RANGE_FRESH_DB_AGE=LNGossip.CHANNEL_RANGE_FRESH_DB_AGE,
            _channel_range_counts=None,
            _channel_range_recent_ts=0,
            _channel_range_max_height=0,
            _channel_range_db_is_fresh=False,
            _channel_range_peers=set(),
            _channel_range_done=False,
        )
        return g, removed

    async def _report(self, g, peer_ids_and_lists):
        for peer_id, ids in peer_ids_and_lists:
            await LNGossip.on_channel_range_reply(g, peer_id, set(ids))

    def test_constants(self):
        # a change of these should be a conscious decision
        self.assertEqual(4, LNGossip.CHANNEL_RANGE_NUM_PEERS)
        self.assertEqual(0.9, LNGossip.CHANNEL_RANGE_MIN_PEER_COVERAGE)

    async def test_only_channels_listed_by_a_minority_of_peers_get_removed(self):
        scids = [self._scid(n) for n in range(40)]
        three_of_four, two_of_four = scids[0], scids[1]
        everyone = set(scids[2:])
        g, removed = self._lngossip(scids)
        await self._report(g, [
            (b'a', everyone | {three_of_four, two_of_four}),
            (b'b', everyone | {three_of_four, two_of_four}),
            (b'c', everyone | {three_of_four}),
            (b'd', everyone),
        ])
        self.assertEqual([two_of_four], removed)

    async def test_nothing_is_removed_before_enough_distinct_peers_reported(self):
        scids = [self._scid(n) for n in range(30)]
        g, removed = self._lngossip(scids)
        same_peer_many_times = [(b'a', scids[1:])] * 10
        await self._report(g, same_peer_many_times + [(bytes([i]), scids[1:]) for i in range(1, self.NUM_PEERS - 1)])
        self.assertEqual([], removed)

    async def test_peers_with_an_incomplete_view_do_not_vote(self):
        scids = [self._scid(n) for n in range(30)]
        g, removed = self._lngossip(scids)
        tiny_peers = [(bytes([100 + i]), scids[1:5]) for i in range(5)]
        full_peers = [(bytes([i]), scids) for i in range(self.NUM_PEERS)]
        await self._report(g, tiny_peers)
        self.assertEqual(set(), g._channel_range_peers)
        await self._report(g, full_peers)
        self.assertEqual([], removed)

    async def test_decision_is_made_once_and_further_peers_do_not_change_it(self):
        scids = [self._scid(n) for n in range(30)]
        g, removed = self._lngossip(scids)
        await self._report(g, [(bytes([i]), scids[1:]) for i in range(self.NUM_PEERS)])
        self.assertEqual([scids[0]], removed)
        self.assertTrue(g._channel_range_done)
        await self._report(g, [(b'x', scids[2:]), (b'y', scids[2:]), (b'z', scids[2:])])
        self.assertEqual([scids[0]], removed)

    async def test_young_channels_are_not_removed(self):
        height_limit = 1000 - LNGossip.CHANNEL_RANGE_MIN_CHANNEL_AGE
        young = self._scid(1, height=height_limit + 1)
        old_enough = self._scid(2, height=height_limit)
        others = [self._scid(n) for n in range(10, 40)]
        g, removed = self._lngossip(others + [young, old_enough])
        await self._report(g, [(bytes([i]), others) for i in range(self.NUM_PEERS)])
        self.assertEqual([old_enough], removed)

    async def test_height_is_taken_when_the_first_peer_reports(self):
        # the peers answered for the height we had at that time, even if we catch up later
        height_limit = 1000 - LNGossip.CHANNEL_RANGE_MIN_CHANNEL_AGE
        too_young_at_first_report = self._scid(1, height=height_limit + 1)
        others = [self._scid(n) for n in range(10, 40)]
        g, removed = self._lngossip(others + [too_young_at_first_report], local_height=1000)
        await self._report(g, [(b'a', others)])
        g.network.get_local_height = lambda: 5000
        await self._report(g, [(bytes([i]), others) for i in range(1, self.NUM_PEERS)])
        self.assertEqual([], removed)

    async def test_recently_updated_channels_are_not_removed(self):
        scids = [self._scid(n) for n in range(30)]
        g, removed = self._lngossip(scids, recently_updated={scids[0]})
        await self._report(g, [(bytes([i]), scids[2:]) for i in range(self.NUM_PEERS)])
        self.assertEqual([scids[1]], removed)

    async def test_channels_updated_shortly_before_our_newest_policy_are_not_removed(self):
        # we were offline for 8 hours: what counts as recent is relative to our newest policy.
        # A channel often gets updated shortly before it is closed, so this is a few hours only.
        now = int(time.time())
        latest = now - 8 * 3600
        scids = [self._scid(n) for n in range(30)]
        policy_timestamps = {scid: latest - 3600 for scid in scids}
        policy_timestamps[scids[0]] = latest - LNGossip.CHANNEL_RANGE_RECENT_POLICY_AGE + 600
        policy_timestamps[scids[1]] = latest - LNGossip.CHANNEL_RANGE_RECENT_POLICY_AGE - 600
        g, removed = self._lngossip(scids, latest_policy_ts=latest, policy_timestamps=policy_timestamps)
        await self._report(g, [(bytes([i]), scids[2:]) for i in range(self.NUM_PEERS)])
        self.assertEqual([scids[1]], removed)
        self.assertEqual(3 * 3600, LNGossip.CHANNEL_RANGE_RECENT_POLICY_AGE)
        self.assertEqual(24 * 3600, LNGossip.CHANNEL_RANGE_FRESH_DB_AGE)

    async def test_updates_of_this_session_do_not_move_what_counts_as_recent(self):
        # e.g. the channel_update of a payment that failed before the first reply of a peer
        now = int(time.time())
        last_online = now - 8 * 3600
        scids = [self._scid(n) for n in range(30)]
        policy_timestamps = {scid: last_online - 3600 for scid in scids}
        policy_timestamps[scids[0]] = last_online - 2 * 3600
        g, removed = self._lngossip(scids, latest_policy_ts=last_online, policy_timestamps=policy_timestamps)
        policy_timestamps[scids[5]] = now - 60
        g.channel_db.get_latest_policy_timestamp = lambda: now
        await self._report(g, [(bytes([i]), scids[1:]) for i in range(self.NUM_PEERS)])
        self.assertEqual([], removed)

    async def test_nothing_is_removed_if_our_db_is_outdated(self):
        # after downtime every policy is old, so recent updates cannot protect live channels
        scids = [self._scid(n) for n in range(30)]
        latest = int(time.time()) - LNGossip.CHANNEL_RANGE_FRESH_DB_AGE - 3600
        g, removed = self._lngossip(scids, latest_policy_ts=latest)
        await self._report(g, [(bytes([i]), scids[1:]) for i in range(self.NUM_PEERS)])
        self.assertEqual([], removed)
        self.assertTrue(g._channel_range_done)

    async def test_nothing_is_removed_if_too_many_channels_would_go(self):
        scids = [self._scid(n) for n in range(40)]
        g, removed = self._lngossip(scids)
        without_first_four = scids[4:]
        without_next_four = scids[:4] + scids[8:]
        await self._report(g, [(b'a', without_first_four), (b'b', without_first_four),
                               (b'c', without_next_four), (b'd', without_next_four)])
        self.assertEqual([], removed)
        self.assertTrue(g._channel_range_done)  # and we do not try again with further peers

    async def test_channels_learned_after_the_first_report_are_not_judged(self):
        scids = [self._scid(n) for n in range(30)]
        learned_later = self._scid(99)
        known = list(scids)
        g, removed = self._lngossip([])
        g.channel_db.get_channel_ids = lambda: set(known)
        await self._report(g, [(b'a', scids)])
        known.append(learned_later)
        await self._report(g, [(bytes([i]), scids) for i in range(1, self.NUM_PEERS)])
        self.assertEqual([], removed)


class Test_LNRouter(ElectrumTestCase):
    TESTNET = True

    cdb = None  # type: Optional[lnrouter.ChannelDB]

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.assertIsNone(self.cdb)  # sanity-check side effects from previous tests

    async def asyncTearDown(self):
        # if the test called prepare_graph(), channeldb needs to be cleaned up
        if self.cdb:
            self.cdb.stop()
            await self.cdb.stopped_event.wait()
        await super().asyncTearDown()

    def prepare_graph(self):
        """
        Network topology with channel ids:
                3
            A  ---  B
            |    2/ |
          6 |   E   | 1
            | /5 \7 |
            D  ---  C
                4
        valid routes from A -> E:
        A -3-> B -2-> E
        A -6-> D -5-> E
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B -2-> E
        A -3-> B -1-> C -4-> D -5-> E
        """

        class fake_network:
            config = self.config
            asyncio_loop = util.get_asyncio_loop()
            trigger_callback = lambda *args: None
            register_callback = lambda *args: None
            interface = None

        self.fake_network = fake_network
        fake_network.channel_db = lnrouter.ChannelDB(fake_network())
        fake_network.channel_db.data_loaded.set()
        self.cdb = fake_network.channel_db
        self.path_finder = lnrouter.LNPathFinder(self.cdb)
        self.assertEqual(self.cdb.num_channels, 0)
        self.cdb.add_channel_announcements({
            'node_id_1': node('b'), 'node_id_2': node('c'),
            'bitcoin_key_1': node('b'), 'bitcoin_key_2': node('c'),
            'short_channel_id': channel(1),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.assertEqual(self.cdb.num_channels, 1)
        self.cdb.add_channel_announcements({
            'node_id_1': node('b'), 'node_id_2': node('e'),
            'bitcoin_key_1': node('b'), 'bitcoin_key_2': node('e'),
            'short_channel_id': channel(2),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('a'), 'node_id_2': node('b'),
            'bitcoin_key_1': node('a'), 'bitcoin_key_2': node('b'),
            'short_channel_id': channel(3),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('c'), 'node_id_2': node('d'),
            'bitcoin_key_1': node('c'), 'bitcoin_key_2': node('d'),
            'short_channel_id': channel(4),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('d'), 'node_id_2': node('e'),
            'bitcoin_key_1': node('d'), 'bitcoin_key_2': node('e'),
            'short_channel_id': channel(5),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('a'), 'node_id_2': node('d'),
            'bitcoin_key_1': node('a'), 'bitcoin_key_2': node('d'),
            'short_channel_id': channel(6),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb.add_channel_announcements({
            'node_id_1': node('c'), 'node_id_2': node('e'),
            'bitcoin_key_1': node('c'), 'bitcoin_key_2': node('e'),
            'short_channel_id': channel(7),
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)

        self.cdb.add_node_announcements({
            'node_id': node('a'),
            'alias': alias('a'),
            'addresses': [],
            'features': node_features(LnFeatures.OPTION_ONION_MESSAGE_OPT),
            'timestamp': 0
        })
        self.cdb.add_node_announcements({
            'node_id': node('b'),
            'alias': alias('b'),
            'addresses': [],
            'features': node_features(),
            'timestamp': 0
        })
        self.cdb.add_node_announcements({
            'node_id': node('c'),
            'alias': alias('c'),
            'addresses': [],
            'features': node_features(LnFeatures.OPTION_ONION_MESSAGE_OPT),
            'timestamp': 0
        })
        self.cdb.add_node_announcements({
            'node_id': node('d'),
            'alias': alias('d'),
            'addresses': [],
            'features': node_features(LnFeatures.OPTION_ONION_MESSAGE_OPT),
            'timestamp': 0
        })
        self.cdb.add_node_announcements({
            'node_id': node('e'),
            'alias': alias('e'),
            'addresses': [],
            'features': node_features(),
            'timestamp': 0
        })

        def add_chan_upd(payload):
            self.cdb.add_channel_update(payload, verify=False)

        add_chan_upd({'short_channel_id': channel(1), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(1), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(2), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 99, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(2), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(3), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(3), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(4), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(4), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(5), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(5), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 999, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(6), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 200, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(6), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(7), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})
        add_chan_upd({'short_channel_id': channel(7), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0})

    async def test_orphaned_channels_are_remembered(self):
        self.prepare_graph()
        scid = channel(100)
        self.cdb.add_channel_announcements({
            'node_id_1': node('a'), 'node_id_2': node('e'),
            'bitcoin_key_1': node('a'), 'bitcoin_key_2': node('e'),
            'short_channel_id': scid,
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.assertIn(scid, self.cdb.get_channel_ids())
        self.assertEqual(set(), self.cdb.get_recently_orphaned_channel_ids())
        self.cdb.prune_orphaned_channels()  # we were told about this channel, but got no recent policy
        self.assertNotIn(scid, self.cdb.get_channel_ids())
        self.assertEqual({scid}, self.cdb.get_recently_orphaned_channel_ids())
        # the record is persisted, so that it survives a restart
        read_table = sql(lambda db: list(db.conn.cursor().execute("SELECT short_channel_id FROM orphaned_channel")))
        self.assertEqual([(bytes(scid),)], await read_table(self.cdb))
        # after a restart it is loaded from the db again
        self.cdb.stop()
        await self.cdb.stopped_event.wait()
        self.cdb = lnrouter.ChannelDB(self.fake_network())
        await self.cdb.load_data()
        self.assertEqual({scid}, self.cdb.get_recently_orphaned_channel_ids())
        # and it expires, also from the db
        with mock.patch('time.time', return_value=time.time() + self.cdb.ORPHANED_CHANNEL_REQUERY_DELAY + 1):
            self.assertEqual(set(), self.cdb.get_recently_orphaned_channel_ids())
            self.cdb._remember_orphaned_channels({channel(101)})
        self.assertEqual([channel(101)], list(self.cdb._orphaned_channels))
        self.assertEqual([(bytes(channel(101)),)], await read_table(self.cdb))

    async def test_prune_old_policies_tolerates_policies_removed_concurrently(self):
        self.prepare_graph()
        stale_key = (node('b'), channel(1))
        self.assertIn(stale_key, self.cdb._policies)
        keys = self.cdb.get_old_policies(3600)
        self.cdb.remove_channels_absent_from_peers({channel(1)})
        self.assertNotIn(stale_key, self.cdb._policies)
        with mock.patch.object(self.cdb, 'get_old_policies', return_value=keys):
            self.cdb.prune_old_policies(3600)
        self.assertEqual(0, self.cdb.num_policies)

    async def test_channel_that_got_a_policy_is_not_remembered_as_orphaned_later(self):
        self.prepare_graph()
        scid = channel(100)
        self.cdb.add_channel_announcements({
            'node_id_1': node('a'), 'node_id_2': node('e'),
            'bitcoin_key_1': node('a'), 'bitcoin_key_2': node('e'),
            'short_channel_id': scid,
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        update = {'short_channel_id': scid, 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 1000}
        self.cdb.add_channel_update(update, verify=False)
        self.cdb.prune_orphaned_channels()  # has a policy: not orphaned, and the marks are reset
        self.assertIn(scid, self.cdb.get_channel_ids())
        self.cdb.prune_old_policies(3600)  # later, the policy ages out
        self.cdb.prune_orphaned_channels()
        self.assertNotIn(scid, self.cdb.get_channel_ids())
        self.assertEqual(set(), self.cdb.get_recently_orphaned_channel_ids())

    async def test_channels_not_announced_since_the_last_prune_are_not_remembered_as_orphaned(self):
        # a channel left in the db without policies by an earlier session (e.g. which got killed
        # between processing the announcement and the updates) should get queried again
        self.prepare_graph()
        scid = channel(100)
        self.cdb.add_channel_announcements({
            'node_id_1': node('a'), 'node_id_2': node('e'),
            'bitcoin_key_1': node('a'), 'bitcoin_key_2': node('e'),
            'short_channel_id': scid,
            'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
            'len': 0, 'features': b''
        }, trusted=True)
        self.cdb._chans_announced_since_last_prune.clear()  # as after a restart
        self.cdb.prune_orphaned_channels()
        self.assertNotIn(scid, self.cdb.get_channel_ids())
        self.assertEqual(set(), self.cdb.get_recently_orphaned_channel_ids())

    async def test_channels_with_aged_out_policies_are_not_remembered_as_orphaned(self):
        # after being offline for longer than max_age all policies age out. these channels
        # are probably still alive, so they must get queried again.
        self.prepare_graph()
        self.assertGreater(self.cdb.num_channels, 0)
        self.cdb.prune_orphaned_channels()  # periodic maintenance: nothing to do yet
        self.cdb.prune_old_policies(3600)  # note: all policies in the test graph have timestamp=0
        self.assertEqual(0, self.cdb.num_policies)
        self.cdb.prune_orphaned_channels()
        self.assertEqual(0, self.cdb.num_channels)
        self.assertEqual(set(), self.cdb.get_recently_orphaned_channel_ids())

    async def test_remove_channels_absent_from_peers(self):
        self.prepare_graph()
        num_channels = self.cdb.num_channels
        self.assertIsNotNone(self.cdb.get_policy_for_node(channel(1), node('b')))
        self.cdb.remove_channels_absent_from_peers({channel(1)})
        self.assertEqual(num_channels - 1, self.cdb.num_channels)
        self.assertNotIn(channel(1), self.cdb.get_channel_ids())
        self.assertNotIn((node('b'), channel(1)), self.cdb._policies)
        self.assertNotIn((node('c'), channel(1)), self.cdb._policies)
        self.assertEqual({channel(1)}, self.cdb.get_recently_orphaned_channel_ids())

    async def test_has_policy_newer_than(self):
        self.prepare_graph()
        self.assertFalse(self.cdb.has_policy_newer_than(channel(1), 500))
        self.cdb.add_channel_update({'short_channel_id': channel(1), 'message_flags': b'\x00', 'channel_flags': b'\x01', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 1000}, verify=False)
        self.assertTrue(self.cdb.has_policy_newer_than(channel(1), 500))
        self.assertFalse(self.cdb.has_policy_newer_than(channel(1), 1000))
        self.assertFalse(self.cdb.has_policy_newer_than(channel(999), 0))

    async def test_latest_policy_timestamp_at_load(self):
        class fake_network:
            config = self.config
            asyncio_loop = util.get_asyncio_loop()
            trigger_callback = lambda *args: None
            register_callback = lambda *args: None
            interface = None
        def add_channel(cdb, number, timestamp):
            n1, n2 = sorted([node('a'), node('b')])
            cdb.add_channel_announcements({
                'node_id_1': n1, 'node_id_2': n2, 'bitcoin_key_1': n1, 'bitcoin_key_2': n2,
                'short_channel_id': channel(number), 'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
                'len': 0, 'features': b''}, trusted=True)
            update = {
                'short_channel_id': channel(number), 'message_flags': b'\x00', 'channel_flags': b'\x00',
                'cltv_expiry_delta': 40, 'htlc_minimum_msat': 1, 'fee_base_msat': 0,
                'fee_proportional_millionths': 0, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
                'timestamp': timestamp}
            update['raw'] = encode_msg('channel_update', signature=bytes(64), **update)  # saved to disk
            cdb.add_channel_update(update, verify=False)
        cdb = lnrouter.ChannelDB(fake_network())
        cdb.data_loaded.set()
        add_channel(cdb, 1, 1_700_000_000)
        add_channel(cdb, 2, 1_700_001_000)
        await cdb.load_data()  # returns at once, as loaded; the writes queued before it are done then
        cdb.stop()
        await cdb.stopped_event.wait()
        self.cdb = lnrouter.ChannelDB(fake_network())
        self.assertIsNone(self.cdb.latest_policy_ts_at_load)
        await self.cdb.load_data()
        self.assertEqual(1_700_001_000, self.cdb.latest_policy_ts_at_load)
        add_channel(self.cdb, 3, 1_700_002_000)
        self.assertEqual(1_700_002_000, self.cdb.get_latest_policy_timestamp())
        self.assertEqual(1_700_001_000, self.cdb.latest_policy_ts_at_load)

    async def test_get_latest_policy_timestamp(self):
        self.prepare_graph()
        self.assertEqual(0, self.cdb.get_latest_policy_timestamp())
        policies = self.cdb._policies
        self.cdb._policies = {}
        self.assertIsNone(self.cdb.get_latest_policy_timestamp())
        self.cdb._policies = policies
        self.cdb.add_channel_update({'short_channel_id': channel(1), 'message_flags': b'\x00', 'channel_flags': b'\x00', 'cltv_expiry_delta': 10, 'htlc_minimum_msat': 250, 'fee_base_msat': 100, 'fee_proportional_millionths': 150, 'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 1000}, verify=False)
        self.assertEqual(1000, self.cdb.get_latest_policy_timestamp())

    def _make_graph(self, chans):
        """chans: (number, node_x, node_y, policy from x to y, policy from y to x),
        a policy being (fee_base_msat, fee_proportional_millionths, cltv_delta)"""
        class fake_network:
            config = self.config
            asyncio_loop = util.get_asyncio_loop()
            trigger_callback = lambda *args: None
            register_callback = lambda *args: None
            interface = None
        self.cdb = lnrouter.ChannelDB(fake_network())
        self.cdb.data_loaded.set()
        self.path_finder = lnrouter.LNPathFinder(self.cdb)
        for number, x, y, policy_xy, policy_yx in chans:
            n1, n2 = sorted([x, y])
            self.cdb.add_channel_announcements({
                'node_id_1': n1, 'node_id_2': n2, 'bitcoin_key_1': n1, 'bitcoin_key_2': n2,
                'short_channel_id': channel(number), 'chain_hash': BitcoinTestnet.rev_genesis_bytes(),
                'len': 0, 'features': b''}, trusted=True)
            for start, (fee_base_msat, fee_proportional_millionths, cltv_delta) in ((x, policy_xy), (y, policy_yx)):
                self.cdb.add_channel_update({
                    'short_channel_id': channel(number), 'message_flags': b'\x00',
                    'channel_flags': b'\x00' if start == n1 else b'\x01',
                    'cltv_expiry_delta': cltv_delta, 'htlc_minimum_msat': 1, 'fee_base_msat': fee_base_msat,
                    'fee_proportional_millionths': fee_proportional_millionths,
                    'chain_hash': BitcoinTestnet.rev_genesis_bytes(), 'timestamp': 0}, verify=False)

    async def test_find_path_with_penalty_weight_zero_lets_1_msat_of_fees_outweigh_the_other_costs(self):
        # 100k sat: the other costs of a channel are about 15k msat, but only break ties
        o, p, a, b, w = node('o'), node('p'), node('a'), node('b'), node('w')
        free = (0, 0, 40)
        self._make_graph([
            (31, o, p, free, free),
            (32, p, w, (1000, 0, 40), free),
            (33, p, a, free, free),
            (34, a, b, free, free),
            (35, b, w, (999, 0, 40), free),
        ])
        path = self.path_finder.find_path_for_payment(
            nodeA=o, nodeB=w, invoice_amount_msat=100_000_000, penalty_weight=0)
        self.assertEqual([channel(n) for n in (31, 33, 34, 35)], [edge.short_channel_id for edge in path])

    async def test_find_path_with_penalty_weight_zero_breaks_ties_with_the_cltv_cost(self):
        # same fees and channels; the path over a is found first, but has the longer cltv delta
        o, p, a, b, w = node('o'), node('p'), node('a'), node('b'), node('w')
        free = (0, 0, 40)
        self._make_graph([
            (31, o, p, free, free),
            (32, p, a, (500, 0, 40), free),
            (33, a, w, (500, 0, 144), free),
            (34, p, b, (500, 0, 40), free),
            (35, b, w, (500, 0, 40), free),
        ])
        path = self.path_finder.find_path_for_payment(
            nodeA=o, nodeB=w, invoice_amount_msat=1_000_000, penalty_weight=0)
        self.assertEqual([channel(n) for n in (31, 34, 35)], [edge.short_channel_id for edge in path])

    async def test_find_path_prefers_fewer_hops_over_small_fee_savings(self):
        # every channel of a path is another chance to fail, so a path that is a bit more expensive
        # but has fewer channels of unknown liquidity should be preferred
        sender, short_mid, long_mid1, long_mid2, dest = node('p'), node('q'), node('r'), node('s'), node('w')
        free = (0, 0, 10)
        self._make_graph([
            (31, sender, short_mid, free, free),
            (32, short_mid, dest, (3000, 0, 10), free),  # one hop less, 3 sat more expensive
            (33, sender, long_mid1, free, free),
            (34, long_mid1, long_mid2, free, free),
            (35, long_mid2, dest, free, free),
        ])
        path = self.path_finder.find_path_for_payment(nodeA=sender, nodeB=dest, invoice_amount_msat=13_000_000)
        self.assertEqual([channel(31), channel(32)], [edge.short_channel_id for edge in path])

    async def test_find_path_with_a_higher_penalty_weight_prefers_fewer_channels(self):
        # 20k sat: the penalty is 7 sat per channel of unknown liquidity
        o, p, a, b, w = node('o'), node('p'), node('a'), node('b'), node('w')
        free = (0, 0, 10)
        self._make_graph([
            (31, o, p, free, free),
            (32, p, w, (20_000, 0, 10), free),  # 20 sat, two channels less
            (33, p, a, free, free),
            (34, a, b, free, free),
            (35, b, w, free, free),
        ])
        def find(penalty_weight):
            path = self.path_finder.find_path_for_payment(
                nodeA=o, nodeB=w, invoice_amount_msat=20_000_000, penalty_weight=penalty_weight)
            return [edge.short_channel_id for edge in path]
        self.assertEqual([channel(n) for n in (31, 33, 34, 35)], find(1))
        self.assertEqual([channel(n) for n in (31, 32)], find(3))

    async def test_find_path_hop_penalty_is_small_for_small_amounts(self):
        # for a small payment, the cost of an extra hop must stay small compared to the fees
        sender, p, q, a1, a2, a3, dest = node('o'), node('p'), node('q'), node('r'), node('s'), node('t'), node('w')
        free = (0, 0, 10)
        def fee(sat):
            return (sat * 1000, 0, 10)
        self._make_graph([
            (31, sender, p, free, free),
            (32, p, q, fee(10), free),  # short path: 11 sat
            (33, q, dest, fee(1), free),
            (34, p, a1, fee(1), free),  # long path: 4 sat
            (35, a1, a2, fee(1), free),
            (36, a2, a3, fee(1), free),
            (37, a3, dest, fee(1), free),
        ])
        path = self.path_finder.find_path_for_payment(nodeA=sender, nodeB=dest, invoice_amount_msat=1_000_000)
        self.assertEqual([channel(n) for n in (31, 34, 35, 36, 37)], [edge.short_channel_id for edge in path])

    async def test_find_path_does_not_extend_paths_beyond_the_fee_budget(self):
        # path finding does not use the fees alone: a path with fewer channels can cost more in fees.
        # Paths over the fee budget are not extended, so that here the longer path within it is found.
        o, p, q, a1, a2, w = node('o'), node('p'), node('q'), node('r'), node('s'), node('w')
        free = (0, 0, 40)
        def fee(sat):
            return (int(sat * 1000), 0, 40)
        self._make_graph([
            (31, o, p, free, free),
            (32, p, q, fee(20.5), free),  # short path: 20.5 + 30 = 50.5 sat
            (34, p, a1, fee(19.5), free),  # long path: 19.5 + 30 = 49.5 sat
            (35, a1, a2, free, free),
            (36, a2, q, free, free),
            (37, q, w, fee(30), free),
        ])
        amount_msat = 5_000_000
        def find(max_fee_msat):
            path = self.path_finder.find_path_for_payment(
                nodeA=o, nodeB=w, invoice_amount_msat=amount_msat, max_fee_msat=max_fee_msat)
            return path and [edge.short_channel_id for edge in path]
        self.assertEqual([channel(n) for n in (31, 32, 37)], find(None))
        self.assertEqual([channel(n) for n in (31, 34, 35, 36, 37)], find(50_000))
        self.assertEqual(None, find(49_000))

    async def test_find_path_with_penalty_weight_zero(self):
        # as path finding keeps one path per node, the search with penalties can miss a path within the
        # budget: here, x is reached over the direct channel to w, and from p, that path exceeds a budget
        # of 32 sat, while the one over y does not. The search by fees finds the cheapest path.
        o, p, x, y, w = node('o'), node('p'), node('x'), node('y'), node('w')
        free = (0, 0, 40)
        self._make_graph([
            (31, o, p, free, free),
            (32, p, x, (30_000, 0, 40), free),
            (33, x, w, (3000, 0, 40), free),
            (34, x, y, free, free),
            (35, y, w, free, free),
        ])
        def find():
            path = self.path_finder.find_path_for_payment(
                nodeA=o, nodeB=w, invoice_amount_msat=5_000_000, penalty_weight=0)
            return [edge.short_channel_id for edge in path]
        self.assertEqual([channel(n) for n in (31, 32, 34, 35)], find())
        # channels that cannot send the amount are still excluded
        self.path_finder.liquidity_hints.update_cannot_send(x, y, channel(34), amount_msat=1_000_000)
        self.assertEqual([channel(n) for n in (31, 32, 33)], find())

    async def test_find_path_with_penalty_weight_zero_takes_the_lowest_fees(self):
        o, p, a, b, c, w = node('o'), node('p'), node('a'), node('b'), node('c'), node('w')
        free = (0, 0, 40)
        self._make_graph([
            (31, o, p, free, free),
            (32, p, w, (1000, 0, 40), free),  # 1 sat
            (33, p, a, (100, 0, 40), free),  # 0.9 sat, over two more channels
            (34, a, b, (800, 0, 40), free),
            (35, b, w, free, free),
        ])
        def find():
            path = self.path_finder.find_path_for_payment(
                nodeA=o, nodeB=w, invoice_amount_msat=1_000_000, penalty_weight=0)
            return [edge.short_channel_id for edge in path]
        self.assertEqual([channel(n) for n in (31, 33, 34, 35)], find())

    async def test_find_path_with_penalty_weight_zero_takes_fewer_channels_with_the_same_fees(self):
        # both paths from p cost 0.9 sat. The longer one reaches p first in the search,
        # the shorter one must still be taken.
        o, p, a, b, c, w = node('o'), node('p'), node('a'), node('b'), node('c'), node('w')
        free = (0, 0, 40)
        self._make_graph([
            (31, o, p, free, free),
            (33, p, a, (450, 0, 40), free),
            (34, a, b, (450, 0, 40), free),
            (35, b, w, free, free),
            (36, p, c, (100, 0, 40), free),
            (37, c, w, (800, 0, 40), free),
        ])
        path = self.path_finder.find_path_for_payment(
            nodeA=o, nodeB=w, invoice_amount_msat=1_000_000, penalty_weight=0)
        self.assertEqual([channel(n) for n in (31, 36, 37)], [edge.short_channel_id for edge in path])

    async def test_find_path_tries_other_paths_after_several_nodes_failed_to_forward_to_a_node(self):
        # four nodes can forward to y for free, which can forward to w. After three of them failed
        # to, the more expensive direct channel to w is tried before the fourth one.
        s, h, y, w = node('s'), node('h'), node('y'), node('w')
        xs = [node(c) for c in 'abcd']
        free = (0, 0, 40)
        chans = [(41, s, h, free, free), (42, y, w, free, free), (43, h, w, (10_000, 0, 40), free)]
        for n, x in enumerate(xs):
            chans += [(50 + n, h, x, free, free), (60 + n, x, y, free, free)]
        self._make_graph(chans)
        amount_msat = 1_000_000
        failed = []
        for _ in range(NODE_FAILURE_MIN_SENDERS):
            path = self.path_finder.find_path_for_payment(nodeA=s, nodeB=w, invoice_amount_msat=amount_msat)
            self.assertEqual(y, path[2].end_node)
            route = self.path_finder.create_route_from_path(path)
            self.path_finder.update_liquidity_hints(route, amount_msat, failing_channel=path[2].short_channel_id)
            failed.append(path[1].end_node)
        self.assertEqual(NODE_FAILURE_MIN_SENDERS, len(set(failed)))
        path = self.path_finder.find_path_for_payment(nodeA=s, nodeB=w, invoice_amount_msat=amount_msat)
        self.assertEqual([channel(41), channel(43)], [edge.short_channel_id for edge in path])

    async def test_find_path_tries_parallel_channels_of_a_failed_node_pair_after_other_paths(self):
        s, a, b, c, d = node('s'), node('a'), node('b'), node('c'), node('d')
        free, expensive = (0, 0, 40), (10_000_000, 0, 40)
        self._make_graph([
            (41, s, a, free, free),
            # parallel channels; only the direction b -> a is expensive (the one that does not count)
            (42, a, b, free, expensive),
            (43, a, b, free, expensive),
            (44, b, d, free, free),
            (45, a, c, (3000, 0, 40), free),  # the other path is 3 sat more expensive
            (46, c, d, free, free),
        ])
        amount_msat = 1_000_000
        path = self.path_finder.find_path_for_payment(nodeA=s, nodeB=d, invoice_amount_msat=amount_msat)
        self.assertEqual(b, path[1].end_node)
        failing_channel = path[1].short_channel_id
        route = self.path_finder.create_route_from_path(path)
        self.path_finder.update_liquidity_hints(route, amount_msat, failing_channel=failing_channel)
        path = self.path_finder.find_path_for_payment(nodeA=s, nodeB=d, invoice_amount_msat=amount_msat)
        self.assertEqual([channel(41), channel(45), channel(46)], [edge.short_channel_id for edge in path])
        # without the other path, the parallel channel is still tried
        self.path_finder.add_edge_to_blacklist(channel(45))
        path = self.path_finder.find_path_for_payment(nodeA=s, nodeB=d, invoice_amount_msat=amount_msat)
        other_channel = ({channel(42), channel(43)} - {failing_channel}).pop()
        self.assertEqual([channel(41), other_channel, channel(44)], [edge.short_channel_id for edge in path])

    async def test_find_path_avoids_a_node_that_several_nodes_cannot_forward_to(self):
        s, a, b, e, x, c, d = node('s'), node('a'), node('b'), node('e'), node('x'), node('c'), node('d')
        free = (0, 0, 40)
        self._make_graph([
            (41, s, a, free, free),
            (42, s, b, free, free),
            (43, s, e, free, free),
            (44, a, x, free, free),
            (45, b, x, free, free),
            (46, e, x, free, free),
            (47, x, d, free, free),
            (48, a, c, (3000, 0, 40), free),  # the path without x is 3 sat more expensive
            (49, c, d, free, free),
        ])
        def find(**kwargs):
            path = self.path_finder.find_path_for_payment(nodeA=s, nodeB=d, invoice_amount_msat=1_000_000, **kwargs)
            return [edge.end_node for edge in path]
        def flag_x():
            for reporter in (a, b, e):
                self.path_finder.report_unknown_next_peer(reporter, x)
        self.assertIn(x, find())
        # the same node twice counts once, and expired reports do not count
        self.path_finder.report_unknown_next_peer(a, x)
        self.path_finder.report_unknown_next_peer(a, x)
        self.path_finder.report_unknown_next_peer(b, x)
        self.path_finder.report_unknown_next_peer(e, x, now=int(time.time()) - OFFLINE_NODE_DURATION - 1)
        self.assertIn(x, find())
        self.path_finder.report_unknown_next_peer(e, x)
        self.assertEqual([a, c, d], find())
        self.assertEqual([a, c, d], find(penalty_weight=0.25))
        # until it forwards an htlc, or returns an error
        route = self.path_finder.create_route_from_path([
            PathEdge(start_node=s, end_node=a, short_channel_id=channel(41)),
            PathEdge(start_node=a, end_node=x, short_channel_id=channel(44)),
            PathEdge(start_node=x, end_node=d, short_channel_id=channel(47))])
        self.path_finder.update_liquidity_hints(route, 2_000_000, failing_channel=channel(44))  # failed before x
        self.assertEqual([a, c, d], find())
        self.path_finder.update_liquidity_hints(route, 2_000_000, failing_channel=channel(47))  # x returned the error
        self.assertIn(x, find())
        flag_x()
        self.path_finder.update_liquidity_hints(route, 1_000)  # success
        self.assertIn(x, find())
        flag_x()
        self.assertEqual([a, c, d], find())
        # until the reports expire
        later = int(time.time()) + OFFLINE_NODE_DURATION + 1
        with mock.patch('time.time', return_value=later):
            self.assertIn(x, find())
        # it is still used if there is no other path: unknown_next_peer is also the error for a closed channel
        self.path_finder.add_edge_to_blacklist(channel(48))
        self.assertIn(x, find())
        self.path_finder.clear_blacklist()
        self.assertIn(x, find())

    async def test_find_path_with_the_lowest_fees_through_a_node_that_several_nodes_cannot_forward_to(self):
        # the search for the lowest fees, the last resort of the fee budget, ignores it
        s, m, n, x, y, d = node('s'), node('m'), node('n'), node('x'), node('y'), node('d')
        free, two_sat = (0, 0, 40), (2000, 0, 40)
        self._make_graph([
            (41, s, m, free, free),
            (42, m, n, two_sat, free),
            (43, n, x, free, free),
            (44, x, d, free, free),
            (45, n, y, free, free),
            (46, y, d, two_sat, free),
        ])
        for reporter in (node('a'), node('b'), node('c')):
            self.path_finder.report_unknown_next_peer(reporter, x)
        def find(**kwargs):
            path = self.path_finder.find_path_for_payment(
                nodeA=s, nodeB=d, invoice_amount_msat=1_000_000, max_fee_msat=3000, **kwargs)
            return path and [edge.end_node for edge in path]
        search_info = {}
        self.assertIsNone(find(search_info=search_info))  # the path without x exceeds the budget
        self.assertTrue(search_info['budget_pruned'])
        self.assertEqual([m, n, x, d], find(penalty_weight=0))

    async def test_find_path_uses_the_parallel_route_hint_channel_of_a_failed_node_pair(self):
        # e.g. a receiver with two channels to a node that forwards only over the requested channel
        s, a, x, d = node('s'), node('a'), node('x'), node('d')
        self._make_graph([(41, s, a, (0, 0, 40), (0, 0, 40)), (47, a, x, (0, 0, 40), (0, 0, 40))])
        hints = {scid: RouteEdge(start_node=x, end_node=d, short_channel_id=scid, fee_base_msat=1000,
                                 fee_proportional_millionths=100, cltv_delta=40, node_features=0)
                 for scid in (ShortChannelID.from_components(0, 0, 51), ShortChannelID.from_components(0, 0, 52))}
        amount_msat = 1_000_000
        path = self.path_finder.find_path_for_payment(
            nodeA=s, nodeB=d, invoice_amount_msat=amount_msat, private_route_edges=hints)
        failing_channel = path[-1].short_channel_id
        route = self.path_finder.create_route_from_path(path, private_route_edges=hints)
        self.path_finder.update_liquidity_hints(route, amount_msat, failing_channel=failing_channel)
        path = self.path_finder.find_path_for_payment(
            nodeA=s, nodeB=d, invoice_amount_msat=amount_msat, private_route_edges=hints)
        self.assertIsNotNone(path)
        self.assertEqual((set(hints) - {failing_channel}).pop(), path[-1].short_channel_id)

    def test_liquidity_hints_of_a_node_pair_from_routes(self):
        # the policies of the channels of a route are those used for the hints of the node pairs
        self._make_graph([])
        hints = self.path_finder.liquidity_hints
        s, a, b = node('s'), node('a'), node('b')
        amount_msat = 1_000_000
        policy, more_expensive = (0, 100, 40), (2000, 100, 40)
        def route_over(scid, policy):
            fee_base_msat, fee_proportional_millionths, cltv_delta = policy
            return [RouteEdge(start_node=s, end_node=a, short_channel_id=channel(41), fee_base_msat=0,
                              fee_proportional_millionths=0, cltv_delta=40, node_features=0),
                    RouteEdge(start_node=a, end_node=b, short_channel_id=channel(scid), fee_base_msat=fee_base_msat,
                              fee_proportional_millionths=fee_proportional_millionths, cltv_delta=cltv_delta,
                              node_features=0)]
        default = LiquidityHintMgr().penalty(a, b, channel(49), amount_msat=amount_msat, policy=policy)
        self.path_finder.update_liquidity_hints(route_over(42, policy), amount_msat, failing_channel=channel(42))
        self.assertEqual((1 + PAIR_FAILURE_PENALTY_FACTOR) * default,
                         hints.penalty(a, b, channel(49), amount_msat=amount_msat, policy=policy))
        # a success over a more expensive channel does not contradict it
        self.path_finder.update_liquidity_hints(route_over(48, more_expensive), amount_msat)
        self.assertEqual((1 + PAIR_FAILURE_PENALTY_FACTOR) * default,
                         hints.penalty(a, b, channel(49), amount_msat=amount_msat, policy=policy))
        self.path_finder.update_liquidity_hints(route_over(43, policy), amount_msat)
        self.assertEqual(default, hints.penalty(a, b, channel(49), amount_msat=amount_msat, policy=policy))

    async def test_find_path_for_payment(self):
        self.prepare_graph()
        amount_to_send = 100000

        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual([
            PathEdge(start_node=node('a'), end_node=node('b'), short_channel_id=channel(3)),
            PathEdge(start_node=node('b'), end_node=node('e'), short_channel_id=channel(2)),
        ], path)

        route = self.path_finder.create_route_from_path(path)
        self.assertEqual(node('b'), route[0].node_id)
        self.assertEqual(channel(3), route[0].short_channel_id)

    async def test_find_path_for_payment_with_node_filter(self):
        self.prepare_graph()
        amount_to_send = 100000

        def node_filter(node_id: bytes, node_info: 'NodeInfo'):
            return node_info.node_id != node('b')

        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send,
            node_filter=node_filter)
        self.assertEqual([
            PathEdge(start_node=node('a'), end_node=node('d'), short_channel_id=channel(6)),
            PathEdge(start_node=node('d'), end_node=node('e'), short_channel_id=channel(5)),
        ], path)

        route = self.path_finder.create_route_from_path(path)
        self.assertEqual(node('d'), route[0].node_id)
        self.assertEqual(channel(6), route[0].short_channel_id)

    async def test_find_path_liquidity_hints(self):
        self.prepare_graph()
        amount_to_send = 100000

        """
        assume failure over channel 2, B -> E
        A -3-> B |-2-> E
        A -6-> D -5-> E  <= chosen path
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B -2-> E
        A -3-> B -1-> C -4-> D -5-> E
        """
        self.path_finder.liquidity_hints.update_cannot_send(node('b'), node('e'), channel(2), amount_msat=amount_to_send - 1)
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(6), path[0].short_channel_id)
        self.assertEqual(channel(5), path[1].short_channel_id)

        """
        assume failure over channel 5, D -> E
        A -3-> B |-2-> E
        A -6-> D |-5-> E
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E  <= chosen path
        A -6-> D -4-> C -1-> B |-2-> E
        A -3-> B -1-> C -4-> D |-5-> E
        """
        self.path_finder.liquidity_hints.update_cannot_send(node('d'), node('e'), channel(5), amount_msat=amount_to_send - 1)
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(3), path[0].short_channel_id)
        self.assertEqual(channel(1), path[1].short_channel_id)
        self.assertEqual(channel(7), path[2].short_channel_id)

        """
        assume success over channel 4, D -> C
        A -3-> B |-2-> E
        A -6-> D |-5-> E
        A -6-> D -4-> C -7-> E  <= smaller penalty: chosen path
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B |-2-> E
        A -3-> B -1-> C -4-> D |-5-> E
        """
        self.path_finder.liquidity_hints.update_can_send(node('d'), node('c'), channel(4), amount_msat=amount_to_send + 1000)
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(6), path[0].short_channel_id)
        self.assertEqual(channel(4), path[1].short_channel_id)
        self.assertEqual(channel(7), path[2].short_channel_id)

    async def test_find_path_liquidity_hints_inflight_htlcs(self):
        self.prepare_graph()
        amount_to_send = 100000

        """
        add inflight htlc to channel 2, B -> E
        A -3-> B -2(1)-> E
        A -6-> D -5-> E <= chosen path
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B -2-> E
        A -3-> B -1-> C -4-> D -5-> E
        """
        self.path_finder.liquidity_hints.add_htlc(node('b'), node('e'), channel(2))
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(6), path[0].short_channel_id)
        self.assertEqual(channel(5), path[1].short_channel_id)

        """
        remove inflight htlc from channel 2, B -> E
        A -3-> B -2(0)-> E <= chosen path
        A -6-> D -5-> E
        A -6-> D -4-> C -7-> E
        A -3-> B -1-> C -7-> E
        A -6-> D -4-> C -1-> B -2-> E
        A -3-> B -1-> C -4-> D -5-> E
        """
        self.path_finder.liquidity_hints.remove_htlc(node('b'), node('e'), channel(2))
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('e'),
            invoice_amount_msat=amount_to_send)
        self.assertEqual(channel(3), path[0].short_channel_id)
        self.assertEqual(channel(2), path[1].short_channel_id)

    def test_liquidity_hints(self):
        liquidity_hints = LiquidityHintMgr()
        node_from = bytes(0)
        node_to = bytes(1)
        channel_id = ShortChannelID.from_components(0, 0, 0)
        amount_to_send = 1_000_000

        # check default penalty
        self.assertEqual(
            1000 + 100,  # 0.1% of the amount + 100 ppm
            liquidity_hints.penalty(node_from, node_to, channel_id, amount_msat=amount_to_send)
        )
        liquidity_hints.update_can_send(node_from, node_to, channel_id, amount_msat=1_000_000)
        liquidity_hints.update_cannot_send(node_from, node_to, channel_id, amount_msat=2_000_000)
        hint = liquidity_hints.get_hint(channel_id)
        self.assertEqual(1_000_000, hint.can_send(node_from < node_to))
        self.assertEqual(None, hint.cannot_send(node_to < node_from))
        self.assertEqual(2_000_000, hint.cannot_send(node_from < node_to))
        # the can_send backward hint is set automatically
        self.assertEqual(2_000_000, hint.can_send(node_to < node_from))

        # check penalties
        self.assertEqual(0., liquidity_hints.penalty(node_from, node_to, channel_id, amount_msat=1_000_000))
        self.assertEqual(1650, liquidity_hints.penalty(node_from, node_to, channel_id, amount_msat=1_500_000))  # 0.1% of the amount + 100 ppm
        self.assertEqual(inf, liquidity_hints.penalty(node_from, node_to, channel_id, amount_msat=2_000_000))

        # test that we don't overwrite significant info with less significant info
        liquidity_hints.update_can_send(node_from, node_to, channel_id, amount_msat=500_000)
        hint = liquidity_hints.get_hint(channel_id)
        self.assertEqual(1_000_000, hint.can_send(node_from < node_to))

        # test case when can_send > cannot_send
        liquidity_hints.update_can_send(node_from, node_to, channel_id, amount_msat=3_000_000)
        hint = liquidity_hints.get_hint(channel_id)
        self.assertEqual(3_000_000, hint.can_send(node_from < node_to))
        self.assertEqual(None, hint.cannot_send(node_from < node_to))

        # test inflight htlc
        liquidity_hints.reset_liquidity_hints()
        liquidity_hints.add_htlc(node_from, node_to, channel_id)
        liquidity_hints.get_hint(channel_id)
        # we have got 1100 (attempt) + 1100 (inflight) penalty
        self.assertEqual(2200, liquidity_hints.penalty(node_from, node_to, channel_id, amount_msat=1_000_000))

    def test_liquidity_hints_of_a_node_pair(self):
        # nodes usually forward over any of their channels to the next node whose policy the htlc
        # satisfies (non-strict forwarding), so a failure to forward from A to B tells us something
        # about the parallel channels between them that are not more expensive
        hints = LiquidityHintMgr()
        a, b = node('a'), node('b')
        chan_1, chan_2, chan_3 = channel(1), channel(2), channel(3)
        policy = (1000, 100, 40)  # fee_base_msat, fee_proportional_millionths, cltv_delta
        cheaper, more_expensive, longer_cltv = (0, 100, 40), (1000, 200, 40), (1000, 100, 41)
        def default(amount_msat):
            return LiquidityHintMgr().penalty(a, b, chan_2, amount_msat=amount_msat, policy=policy)
        def pair_failed(amount_msat):
            return (1 + PAIR_FAILURE_PENALTY_FACTOR) * default(amount_msat)
        hints.update_cannot_send(a, b, chan_1, amount_msat=1_000_000, policy=policy)
        self.assertEqual(inf, hints.penalty(a, b, chan_1, amount_msat=1_000_000, policy=policy))
        self.assertEqual(pair_failed(1_000_000), hints.penalty(a, b, chan_2, amount_msat=1_000_000, policy=policy))
        self.assertEqual(pair_failed(2_000_000), hints.penalty(a, b, chan_2, amount_msat=2_000_000, policy=cheaper))
        self.assertEqual(default(999_999), hints.penalty(a, b, chan_2, amount_msat=999_999, policy=policy))
        self.assertEqual(default(1_000_000), hints.penalty(a, b, chan_2, amount_msat=1_000_000, policy=more_expensive))
        self.assertEqual(default(1_000_000), hints.penalty(a, b, chan_2, amount_msat=1_000_000, policy=longer_cltv))
        self.assertEqual(default(1_000_000), hints.penalty(b, a, chan_2, amount_msat=1_000_000, policy=policy))  # other direction
        # more failures, of smaller amounts
        hints.update_cannot_send(a, b, chan_2, amount_msat=500_000, policy=policy)
        hints.update_cannot_send(a, b, chan_1, amount_msat=800_000, policy=policy)
        self.assertEqual(pair_failed(600_000), hints.penalty(a, b, chan_3, amount_msat=600_000, policy=policy))
        # a successful forward contradicts the failure, if it was of at least the failed amount,
        # over a channel not more expensive than the failed one
        hints.update_can_send(a, b, chan_1, amount_msat=400_000, policy=policy)
        self.assertEqual(pair_failed(600_000), hints.penalty(a, b, chan_3, amount_msat=600_000, policy=policy))
        hints.update_can_send(a, b, chan_1, amount_msat=600_000, policy=more_expensive)
        self.assertEqual(pair_failed(600_000), hints.penalty(a, b, chan_3, amount_msat=600_000, policy=policy))
        hints.update_can_send(a, b, chan_1, amount_msat=600_000, policy=policy)
        self.assertEqual(default(600_000), hints.penalty(a, b, chan_3, amount_msat=600_000, policy=policy))
        # a failure without the policy of the channel does not say which parallel channels it applies to
        hints.update_cannot_send(a, b, chan_1, amount_msat=100_000)
        self.assertEqual(default(600_000), hints.penalty(a, b, chan_3, amount_msat=600_000, policy=policy))
        # reset
        hints.update_cannot_send(a, b, chan_1, amount_msat=100_000, policy=policy)
        self.assertEqual(pair_failed(600_000), hints.penalty(a, b, chan_3, amount_msat=600_000, policy=policy))
        hints.reset_liquidity_hints()
        self.assertEqual(default(600_000), hints.penalty(a, b, chan_3, amount_msat=600_000, policy=policy))

    def test_penalty_depends_on_the_amount(self):
        # 0.1% of the amount, at least 0.5 sat and at most 5 sat, plus 100 ppm
        hints = LiquidityHintMgr()
        a, b = node('a'), node('b')
        self.assertEqual(500 + 10, hints.penalty(a, b, channel(1), amount_msat=100_000))
        self.assertEqual(2000 + 200, hints.penalty(a, b, channel(1), amount_msat=2_000_000))
        self.assertEqual(5000 + 2000, hints.penalty(a, b, channel(1), amount_msat=20_000_000))

    def test_penalty_factors_add_up(self):
        # unknown liquidity (1), an htlc in flight (1), close to the known upper bound (2), failed node pair (10)
        hints = LiquidityHintMgr()
        a, b = node('a'), node('b')
        policy = (1000, 100, 40)
        hints.update_cannot_send(a, b, channel(2), amount_msat=1_100_000)
        hints.update_cannot_send(a, b, channel(1), amount_msat=900_000, policy=policy)
        hints.add_htlc(a, b, channel(2))
        self.assertEqual((1000 + 100) * (1 + 1 + 2 + 10),
                         hints.penalty(a, b, channel(2), amount_msat=1_000_000, policy=policy))

    def test_liquidity_hints_of_a_node_that_several_nodes_failed_to_forward_to(self):
        # when several nodes failed to forward an amount to the same node, its inbound liquidity is
        # probably drained, and its other incoming channels will likely fail too.
        # Penalties: for 1_000_000 msat, 1000 + 100 msat, and 11 times that for such a node.
        self.assertEqual((3, 10), (NODE_FAILURE_MIN_SENDERS, NODE_FAILURE_PENALTY_FACTOR))
        hints = LiquidityHintMgr()
        a, b, c, d, y = node('a'), node('b'), node('c'), node('d'), node('y')
        hints.update_cannot_send(a, y, channel(1), amount_msat=1_000_000)
        hints.update_cannot_send(b, y, channel(2), amount_msat=1_000_000)
        self.assertEqual(1100, hints.penalty(d, y, channel(4), amount_msat=1_000_000))
        hints.update_cannot_send(c, y, channel(3), amount_msat=900_000)
        self.assertEqual(12100, hints.penalty(d, y, channel(4), amount_msat=1_000_000))
        # not below the amounts that failed, not from y, not to another node
        self.assertEqual(950 + 95, hints.penalty(d, y, channel(4), amount_msat=950_000))
        self.assertEqual(1100, hints.penalty(y, d, channel(4), amount_msat=1_000_000))
        self.assertEqual(1100, hints.penalty(d, a, channel(4), amount_msat=1_000_000))
        # the other channels of a node that failed too
        self.assertEqual(12100, hints.penalty(c, y, channel(8), amount_msat=1_000_000))
        # a successful forward to y contradicts the failures of up to that amount, included
        hints.update_can_send(d, y, channel(4), amount_msat=900_000)
        self.assertEqual(1100, hints.penalty(d, y, channel(7), amount_msat=1_000_000))
        self.assertEqual(0, hints.penalty(d, y, channel(4), amount_msat=900_000))
        # reset
        hints.update_cannot_send(c, y, channel(3), amount_msat=1_000_000)
        self.assertEqual(12100, hints.penalty(d, y, channel(7), amount_msat=1_000_000))
        hints.reset_liquidity_hints()
        self.assertEqual(1100, hints.penalty(d, y, channel(7), amount_msat=1_000_000))

    def test_liquidity_hints_of_a_node_keep_the_smallest_amount_that_failed_per_node(self):
        hints = LiquidityHintMgr()
        a, b, c, d, y = node('a'), node('b'), node('c'), node('d'), node('y')
        hints.update_cannot_send(a, y, channel(1), amount_msat=1_000_000)
        hints.update_cannot_send(a, y, channel(5), amount_msat=800_000)
        hints.update_cannot_send(b, y, channel(2), amount_msat=800_000)
        hints.update_cannot_send(c, y, channel(3), amount_msat=800_000)
        self.assertEqual(11 * (900 + 90), hints.penalty(d, y, channel(4), amount_msat=900_000))
        hints.update_cannot_send(a, y, channel(6), amount_msat=2_000_000)  # larger: does not replace it
        self.assertEqual(11 * (900 + 90), hints.penalty(d, y, channel(4), amount_msat=900_000))

    def test_liquidity_hints_of_a_node_are_replaced_not_changed(self):
        # as penalty() reads them without the lock
        hints = LiquidityHintMgr()
        a, b, d, y = node('a'), node('b'), node('d'), node('y')
        hints.update_cannot_send(a, y, channel(1), amount_msat=1_000_000)
        published = hints._node_cannot_receive[y]
        before = (published[0], dict(published[1]))
        hints.update_cannot_send(b, y, channel(2), amount_msat=1_000_000)
        hints.update_can_send(d, y, channel(4), amount_msat=500_000)
        hints.update_can_send(d, y, channel(4), amount_msat=2_000_000)
        self.assertEqual(before, (published[0], dict(published[1])))
        self.assertNotIn(y, hints._node_cannot_receive)

    def test_liquidity_hints_of_a_node_keep_a_channel_that_forwarded_the_amount(self):
        # the failures of other nodes to forward to y do not tell anything about this channel to y
        hints = LiquidityHintMgr()
        a, b, c, d, y = node('a'), node('b'), node('c'), node('d'), node('y')
        hints.update_can_send(d, y, channel(4), amount_msat=1_200_000)
        for n, sender in enumerate((a, b, c)):
            hints.update_cannot_send(sender, y, channel(n), amount_msat=1_000_000)
        self.assertEqual(0, hints.penalty(d, y, channel(4), amount_msat=1_000_000))
        self.assertEqual(12100, hints.penalty(d, y, channel(5), amount_msat=1_000_000))

    def test_liquidity_hints_of_a_node_that_several_nodes_failed_to_forward_to_expire(self):
        hints = LiquidityHintMgr()
        a, b, c, d, y = node('a'), node('b'), node('c'), node('d'), node('y')
        for n, sender in enumerate((a, b, c)):
            hints.update_cannot_send(sender, y, channel(n), amount_msat=1_000_000)
        self.assertEqual(12100, hints.penalty(d, y, channel(4), amount_msat=1_000_000))
        later = int(time.time()) + HINT_DURATION + 1
        with mock.patch('electrum.lnrouter.now', return_value=later):
            self.assertEqual(1100, hints.penalty(d, y, channel(4), amount_msat=1_000_000))
            # expired failures are dropped when the node gets another one, which replaces them
            hints.update_cannot_send(a, y, channel(0), amount_msat=2_000_000)
            self.assertEqual([a], list(hints._node_cannot_receive[y][1]))
            hints.update_cannot_send(b, y, channel(1), amount_msat=2_000_000)
            hints.update_cannot_send(c, y, channel(2), amount_msat=2_000_000)
            self.assertEqual(24200, hints.penalty(d, y, channel(4), amount_msat=2_000_000))

    def test_liquidity_hints_of_a_node_pair_compare_fees_at_the_amount_sent(self):
        hints = LiquidityHintMgr()
        a, b = node('a'), node('b')
        high_base, high_proportional = (10_000, 0, 40), (0, 1000, 40)
        hints.update_cannot_send(a, b, channel(1), amount_msat=1_000_000, policy=high_base)
        default = LiquidityHintMgr().penalty(a, b, channel(2), amount_msat=1_000_000, policy=high_proportional)
        # at 1_000_000 msat, high_proportional has the lower fee (1000 msat), at 20_000_000 msat the higher one
        self.assertEqual((1 + PAIR_FAILURE_PENALTY_FACTOR) * default,
                         hints.penalty(a, b, channel(2), amount_msat=1_000_000, policy=high_proportional))
        default = LiquidityHintMgr().penalty(a, b, channel(2), amount_msat=20_000_000, policy=high_proportional)
        self.assertEqual(default, hints.penalty(a, b, channel(2), amount_msat=20_000_000, policy=high_proportional))

    def test_liquidity_hints_of_a_node_pair_override_an_older_success_of_a_parallel_channel(self):
        hints = LiquidityHintMgr()
        a, b = node('a'), node('b')
        policy = (1000, 100, 40)
        hints.update_can_send(a, b, channel(2), amount_msat=2_000_000, policy=policy)
        hints.update_cannot_send(a, b, channel(1), amount_msat=1_000_000, policy=policy)
        default = LiquidityHintMgr().penalty(a, b, channel(2), amount_msat=1_500_000, policy=policy)
        self.assertEqual((1 + PAIR_FAILURE_PENALTY_FACTOR) * default,
                         hints.penalty(a, b, channel(2), amount_msat=1_500_000, policy=policy))

    def test_liquidity_hints_of_a_node_pair_with_an_outdated_policy(self):
        # nodes often change the policies of all their channels to the same node together
        hints = LiquidityHintMgr()
        a, b = node('a'), node('b')
        amount_msat = 1_000_000
        outdated, cheaper, updated, longer_cltv = (1000, 70, 40), (1000, 60, 40), (1000, 80, 40), (1000, 70, 41)
        def default(policy, n_from=a, n_to=b):
            return LiquidityHintMgr().penalty(n_from, n_to, channel(2), amount_msat=amount_msat, policy=policy)
        def penalty(policy, n_from=a, n_to=b):
            return hints.penalty(n_from, n_to, channel(2), amount_msat=amount_msat, policy=policy)
        factor = 1 + PAIR_FAILURE_PENALTY_FACTOR
        hints.update_outdated_policy(a, b, policy=outdated)
        self.assertEqual(factor * default(outdated), penalty(outdated))
        self.assertEqual(factor * default(cheaper), penalty(cheaper))
        self.assertEqual(default(updated), penalty(updated))  # e.g. the channel with the new policy
        self.assertEqual(default(longer_cltv), penalty(longer_cltv))
        self.assertEqual(default(outdated, b, a), penalty(outdated, b, a))  # other direction
        # a later report adds its outdated policy
        hints.update_outdated_policy(a, b, policy=cheaper)
        self.assertEqual(factor * default(outdated), penalty(outdated))
        hints.update_outdated_policy(a, b, policy=(0, 200, 40))
        self.assertEqual(factor * default((0, 200, 40)), penalty((0, 200, 40)))
        self.assertEqual(factor * default(outdated), penalty(outdated))
        self.assertEqual(default((1000, 200, 40)), penalty((1000, 200, 40)))  # e.g. a policy with both changes
        # not a liquidity failure: no node hint
        c, d, e = node('c'), node('d'), node('e')
        for n_from in (c, d, e):
            hints.update_outdated_policy(n_from, b, policy=outdated)
        self.assertEqual(default(outdated, node('f')), penalty(outdated, node('f')))
        # a forward over a more expensive channel, e.g. the one with the new policy, does not change it
        hints.update_can_send(a, b, channel(3), amount_msat=amount_msat, policy=(3000, 70, 40))
        self.assertEqual(factor * default(outdated), penalty(outdated))
        # a forward with a policy that is not more expensive shows that the node pair's policies are current
        hints.update_can_send(a, b, channel(3), amount_msat=amount_msat, policy=outdated)
        self.assertEqual(default(outdated), penalty(outdated))
        # the oldest of more than MAX_OUTDATED_POLICIES_PER_PAIR are dropped
        hints.reset_liquidity_hints()
        dearest = (1000, 100, 40)
        hints.update_outdated_policy(a, b, policy=dearest)
        for ppm in range(10, 10 + 10 * MAX_OUTDATED_POLICIES_PER_PAIR, 10):
            hints.update_outdated_policy(a, b, policy=(1000, ppm, 40))
            self.assertEqual(ppm < 10 * MAX_OUTDATED_POLICIES_PER_PAIR, penalty(dearest) > default(dearest))
        # it expires, unless reported again
        start = int(time.time())
        with mock.patch('electrum.lnrouter.now', return_value=start):
            hints.update_outdated_policy(a, b, policy=outdated)
        with mock.patch('electrum.lnrouter.now', return_value=start + HINT_DURATION - 600):
            hints.update_outdated_policy(a, b, policy=outdated)
        with mock.patch('electrum.lnrouter.now', return_value=start + HINT_DURATION + 1):
            self.assertEqual(factor * default(outdated), penalty(outdated))
        with mock.patch('electrum.lnrouter.now', return_value=start + 2 * HINT_DURATION):
            self.assertEqual(default(outdated), penalty(outdated))
            # and is dropped when another node pair is reported
            hints.update_outdated_policy(c, b, policy=outdated)
            self.assertEqual({(c, b)}, set(hints._pair_outdated_policy))
        hints.update_outdated_policy(a, b, policy=outdated)
        hints.reset_liquidity_hints()
        self.assertEqual(default(outdated), penalty(outdated))

    def test_liquidity_hints_of_a_node_pair_expire(self):
        hints = LiquidityHintMgr()
        a, b = node('a'), node('b')
        policy = (1000, 100, 40)
        def default(amount_msat):
            return LiquidityHintMgr().penalty(a, b, channel(2), amount_msat=amount_msat, policy=policy)
        hints.update_cannot_send(a, b, channel(1), amount_msat=1_000_000, policy=policy)
        self.assertEqual((1 + PAIR_FAILURE_PENALTY_FACTOR) * default(1_000_000),
                         hints.penalty(a, b, channel(2), amount_msat=1_000_000, policy=policy))
        later = int(time.time()) + HINT_DURATION + 1
        with mock.patch('electrum.lnrouter.now', return_value=later):
            self.assertEqual(default(1_000_000), hints.penalty(a, b, channel(2), amount_msat=1_000_000, policy=policy))
            # an expired failure is replaced by a newer one, even of a larger amount
            hints.update_cannot_send(a, b, channel(1), amount_msat=2_000_000, policy=policy)
            self.assertEqual(default(1_500_000), hints.penalty(a, b, channel(2), amount_msat=1_500_000, policy=policy))
            self.assertEqual((1 + PAIR_FAILURE_PENALTY_FACTOR) * default(2_000_000),
                             hints.penalty(a, b, channel(2), amount_msat=2_000_000, policy=policy))

    def test_liquidity_hints_expiry(self):
        liquidity_hints = LiquidityHintMgr()
        node_from = bytes(0)
        node_to = bytes(1)
        channel_id = ShortChannelID.from_components(0, 0, 0)
        mock_time = 1_000_000
        with mock.patch.object(lnrouter, 'now', lambda: mock_time):
            liquidity_hints.update_cannot_send(node_from, node_to, channel_id, amount_msat=1_000_000)
            self.assertEqual(inf, liquidity_hints.penalty(node_from, node_to, channel_id, amount_msat=1_000_000))
            # updating can_send after cannot_send expired must not resurrect the old cannot_send
            mock_time += HINT_DURATION + 1
            liquidity_hints.update_can_send(node_from, node_to, channel_id, amount_msat=10_000)
            hint = liquidity_hints.get_hint(channel_id)
            self.assertEqual(10_000, hint.can_send(node_from < node_to))
            self.assertEqual(None, hint.cannot_send(node_from < node_to))
            self.assertNotEqual(inf, liquidity_hints.penalty(node_from, node_to, channel_id, amount_msat=1_000_000))
            # an expired higher can_send must not block recording a lower can_send
            mock_time += HINT_DURATION + 1
            liquidity_hints.update_can_send(node_from, node_to, channel_id, amount_msat=5_000)
            hint = liquidity_hints.get_hint(channel_id)
            self.assertEqual(5_000, hint.can_send(node_from < node_to))

    def test_reset_liquidity_hints_clears_inflight_htlcs(self):
        liquidity_hints = LiquidityHintMgr()
        node_from, node_to = bytes(0), bytes(1)
        channel_id = ShortChannelID.from_components(0, 0, 0)
        liquidity_hints.add_htlc(node_from, node_to, channel_id)
        liquidity_hints.add_htlc(node_to, node_from, channel_id)
        hint = liquidity_hints.get_hint(channel_id)
        self.assertEqual(1, hint.num_inflight_htlcs(node_from < node_to))
        self.assertEqual(1, hint.num_inflight_htlcs(node_to < node_from))
        liquidity_hints.reset_liquidity_hints()
        self.assertEqual(0, hint.num_inflight_htlcs(node_from < node_to))
        self.assertEqual(0, hint.num_inflight_htlcs(node_to < node_from))

    @needs_test_with_all_chacha20_implementations
    def test_new_onion_packet(self):
        # test vector from bolt-04
        payment_path_pubkeys = [
            bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
            bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991'),
            bfh('02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145'),
        ]
        session_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        associated_data = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        hops_data = [
            OnionHopsDataSingle(
                _raw_bytes_payload=bfh("1202023a98040205dc06080000000000000001"),
            ),
            OnionHopsDataSingle(
                _raw_bytes_payload=bfh("52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f"),
            ),
            OnionHopsDataSingle(
                _raw_bytes_payload=bfh("12020230d4040204e206080000000000000003"),
            ),
            OnionHopsDataSingle(
                _raw_bytes_payload=bfh("1202022710040203e806080000000000000004"),
            ),
            OnionHopsDataSingle(
                _raw_bytes_payload=bfh("fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"),
            ),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data=associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f7f3416a5aa36dc7eeb3ec6d421e9615471ab870a33ac07fa5d5a51df0a8823aabe3fea3f90d387529d4f72837f9e687230371ccd8d263072206dbed0234f6505e21e282abd8c0e4f5b9ff8042800bbab065036eadd0149b37f27dde664725a49866e052e809d2b0198ab9610faa656bbf4ec516763a59f8f42c171b179166ba38958d4f51b39b3e98706e2d14a2dafd6a5df808093abfca5aeaaca16eded5db7d21fb0294dd1a163edf0fb445d5c8d7d688d6dd9c541762bf5a5123bf9939d957fe648416e88f1b0928bfa034982b22548e1a4d922690eecf546275afb233acf4323974680779f1a964cfe687456035cc0fba8a5428430b390f0057b6d1fe9a8875bfa89693eeb838ce59f09d207a503ee6f6299c92d6361bc335fcbf9b5cd44747aadce2ce6069cfdc3d671daef9f8ae590cf93d957c9e873e9a1bc62d9640dc8fc39c14902d49a1c80239b6c5b7fd91d05878cbf5ffc7db2569f47c43d6c0d27c438abff276e87364deb8858a37e5a62c446af95d8b786eaf0b5fcf78d98b41496794f8dcaac4eef34b2acfb94c7e8c32a9e9866a8fa0b6f2a06f00a1ccde569f97eec05c803ba7500acc96691d8898d73d8e6a47b8f43c3d5de74458d20eda61474c426359677001fbd75a74d7d5db6cb4feb83122f133206203e4e2d293f838bf8c8b3a29acb321315100b87e80e0edb272ee80fda944e3fb6084ed4d7f7c7d21c69d9da43d31a90b70693f9b0cc3eac74c11ab8ff655905688916cfa4ef0bd04135f2e50b7c689a21d04e8e981e74c6058188b9b1f9dfc3eec6838e9ffbcf22ce738d8a177c19318dffef090cee67e12de1a3e2a39f61247547ba5257489cbc11d7d91ed34617fcc42f7a9da2e3cf31a94a210a1018143173913c38f60e62b24bf0d7518f38b5bab3e6a1f8aeb35e31d6442c8abb5178efc892d2e787d79c6ad9e2fc271792983fa9955ac4d1d84a36c024071bc6e431b625519d556af38185601f70e29035ea6a09c8b676c9d88cf7e05e0f17098b584c4168735940263f940033a220f40be4c85344128b14beb9e75696db37014107801a59b13e89cd9d2258c169d523be6d31552c44c82ff4bb18ec9f099f3bf0e5b1bb2ba9a87d7e26f98d294927b600b5529c47e04d98956677cbcee8fa2b60f49776d8b8c367465b7c626da53700684fb6c918ead0eab8360e4f60edd25b4f43816a75ecf70f909301825b512469f8389d79402311d8aecb7b3ef8599e79485a4388d87744d899f7c47ee644361e17040a7958c8911be6f463ab6a9b2afacd688ec55ef517b38f1339efc54487232798bb25522ff4572ff68567fe830f92f7b8113efce3e98c3fffbaedce4fd8b50e41da97c0c08e423a72689cc68e68f752a5e3a9003e64e35c957ca2e1c48bb6f64b05f56b70b575ad2f278d57850a7ad568c24a4d32a3d74b29f03dc125488bc7c637da582357f40b0a52d16b3b40bb2c2315d03360bc24209e20972c200566bcf3bbe5c5b0aedd83132a8a4d5b4242ba370b6d67d9b67eb01052d132c7866b9cb502e44796d9d356e4e3cb47cc527322cd24976fe7c9257a2864151a38e568ef7a79f10d6ef27cc04ce382347a2488b1f404fdbf407fe1ca1c9d0d5649e34800e25e18951c98cae9f43555eef65fee1ea8f15828807366c3b612cd5753bf9fb8fced08855f742cddd6f765f74254f03186683d646e6f09ac2805586c7cf11998357cafc5df3f285329366f475130c928b2dceba4aa383758e7a9d20705c4bb9db619e2992f608a1ba65db254bb389468741d0502e2588aeb54390ac600c19af5c8e61383fc1bebe0029e4474051e4ef908828db9cca13277ef65db3fd47ccc2179126aaefb627719f421e20'),
                         packet.to_bytes())

    @needs_test_with_all_chacha20_implementations
    def test_process_onion_packet(self):
        # this test is not from bolt-04, but is based on the one there;
        # here the TLV payloads are all known types. This allows testing
        # decoding the onion and parsing hops_data into known TLV dicts.
        payment_path_pubkeys = [
            bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
            bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991'),
            bfh('02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145'),
        ]
        payment_path_privkeys = [
            bfh('4141414141414141414141414141414141414141414141414141414141414141'),
            bfh('4242424242424242424242424242424242424242424242424242424242424242'),
            bfh('4343434343434343434343434343434343434343434343434343434343434343'),
            bfh('4444444444444444444444444444444444444444444444444444444444444444'),
            bfh('4545454545454545454545454545454545454545454545454545454545454545'),
        ]
        session_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        associated_data = bfh('4242424242424242424242424242424242424242424242424242424242424242')
        hops_data = [
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 15000},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1500},
                'short_channel_id': {'short_channel_id': bfh('0000000000000001')}}),
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 14000},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1400},
                'short_channel_id': {'short_channel_id': bfh('0000000000000002')}}),
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 12500},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1250},
                'short_channel_id': {'short_channel_id': bfh('0000000000000003')}}),
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 10000},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1000},
                'short_channel_id': {'short_channel_id': bfh('0000000000000004')}}),
            OnionHopsDataSingle(payload={
                'amt_to_forward': {'amt_to_forward': 10000},
                'outgoing_cltv_value': {'outgoing_cltv_value': 1000},
                'payment_data': {'payment_secret': bfh('24a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f61704'), 'total_msat': 10000}}),
        ]
        packet = new_onion_packet(payment_path_pubkeys, session_key, hops_data, associated_data=associated_data)
        self.assertEqual(bfh('0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f7f3416a5aa36dc7eeb3ec6d421e9615471ab858ba970cd3cceb768b44e692be2f390c0b7fe70122abae84d7801db070dfb1638cd8d263072206dbed0234f6505e21e282abd8587124c572aad8de04610a136d6c71a7648c0ef66f1b3655d8a9eea1f92349132c93befbd6c37dbfc55615814ae09e4cbef721c01b487007811bbbfdc1fc7bd869aeb70eb08b4140ff5f501394b3653ada2a3b36a263535ea421d26818afb278df46abcec093305b715cac22b0b03645f8f4797cf2987b1bf4bfdd9ed8648ed42ed1a831fc36ccd45416a132580281ddac4e7470e4d2afd675baad9282ec6335403a73e1391427e330996c834db93848b4ae29dd975f678b2f5155ad6865ca23190725d4b7238fb44f0e3762dd59091b45c97d45df8164a15d9ca0329ec76f957b0a0e49ae372154620708df5c0fa991f0dd12b6bff1ebaf9e2376bb64bc24713f7c57da569bcd9c43a50c088416564b786a87d1f40936a051a3dbfe023bd867a5e66148b61cdd24a79f8c18682150e55aa6969ce9becf51f7c69e72deafcd0659f6be4f78463eaef8716e56615c77b3fbea8190806359909dcbec13c1592523b3d2985ec3e83d42cb7286a66a22f58704ddf6979ceb6883ab4ad8ac99d30251035189ffd514e03ce1576844513d66965d4adfc2523f4eee0dede229ab96303e31348c72bc0c8c816c666a904e5ccbabadf5a919720438f4a14dbd4a802f8d4b942f0ca8572f59644c9ac1912c8c8efefc4afa7f19e27411d46b7541c55985e28ce5cd7620b335fea51de55fa00ef977e8522181ad19e5e04f93bcfc83a36edd7e96fe48e846f2e54fe7a7090fe8e46ba72123e1cdee0667777c38c4930e50401074d8ab31a9717457fcefaa46323003af553bee2b49ea7f907eb2ff3301463e64a8c53975c853bbdd2956b9001b5ce1562264963fce84201daaf752de6df7ca31291226969c9851d1fc4ea88ca67d38c38587c2cdd8bc4d3f7bdf705497a1e054246f684554b3b8dfac43194f1eadec7f83b711e663b5645bde6d7f8cefb59758303599fed25c3b4d2e4499d439c915910dd283b3e7118320f1c6e7385009fbcb9ae79bab72a85e644182b4dafc0a173241f2ae68ae6a504f17f102da1e91de4548c7f5bc1c107354519077a4e83407f0d6a8f0975b4ac0c2c7b30637a998dda27b56b56245371296b816876b859677bcf3473a07e0f300e788fdd60c51b1626b46050b182457c6d716994847aaef667ca45b2cede550c92d336ff29ce6effd933b875f81381cda6e59e9727e728a58c0b3e74035beeeb639ab7463744322bf40138b81895e9a8e8850c9513782dc7a79f04380c216cb177951d8940d576486b887a232fcd382adcbd639e70af0c1a08bcf1405496606fce4645aef10d769dc0c010a8a433d8cd24d5943843a89cdbc8d16531db027b312ab2c03a7f1fdb7f2bcb128639c49e86705c948137fd42d0080fda4be4e9ee812057c7974acbf0162730d3b647b355ac1a5adbb2993832eba443b7c9b5a0ae1fc00a6c0c2b0b65b9019690565739d6439bf602066a3a9bd9c67b83606de51792d25ae517cbbdf6e1827fa0e8b2b5c6023cbb1e9f0e10b786dc6fa154e282fd9c90b8d46ca685d0f4434760035073c92d131564b6845ef57457488add4f709073bbb41f5f31f8226904875a9fd9e1b7a2901e71426104d7a298a05af0d4ab549fbd69c539ebe64949a9b6088f16e2e4bc827c305cb8d64536b8364dc3d5f7519c3b431faa38b47a958cf0c6dcabf205280693abf747c262f44cd6ffa11b32fc38d4f9c3631d554d8b57389f1390ac65c06357843ee6d9f289bb054ef25de45c5149c090fe6ddcd4095696dcc9a5cfc09c8bdfd5b83a153'),
                         packet.to_bytes())
        for i, privkey in enumerate(payment_path_privkeys):
            processed_packet = process_onion_packet(packet, privkey, associated_data=associated_data)
            self.assertEqual(hops_data[i].to_bytes(), processed_packet.hop_data.to_bytes())
            packet = processed_packet.next_packet

    def test_create_legacy_trampoline_onion_multiple_rtags(self):
        """Test to verify we don't overfill the trampoline onion with r_tags if there are more tags than available space"""
        dummy_route: LNPaymentTRoute = [
            TrampolineEdge(
                invoice_routing_info=[
                    bfh("010305061295fa30847df41ae6ee809b560e78d65c2a7337a41c725ea3920b65e08a03b62b00003a0002000003e8000000010050"),
                    bfh("01037414fe3dcfedc4a0a0e153205d9a973af5096d1cd1c8c53d07ed12d7dd966f19f424000000000020000003e8000008ca0050"),
                    bfh("01038550162fa86287884a6a052471934abb5cb261c5a2b15386df8104d3c7bcb85dddd92ee1898ee15c000003e8000000010090"),
                    bfh("010244bb7ba2392ab2d493ad04ad4afcd482ca44a2bfe5b42bcc830bfe00e5b08082f424000000000029000003e8000008ca0050")
                ],
                invoice_features=LnFeatures.VAR_ONION_REQ | LnFeatures.PAYMENT_SECRET_REQ | LnFeatures.BASIC_MPP_OPT,
                short_channel_id=ShortChannelID.from_str("0x0x0"),
                start_node=node('a'),
                end_node=node('b'),
                fee_base_msat=0,
                fee_proportional_millionths=0,
                cltv_delta=0,
                node_features=0
            ),
            TrampolineEdge(
                invoice_routing_info=[],
                invoice_features=None,
                short_channel_id=ShortChannelID.from_str("0x0x0"),
                start_node=node('b'),
                end_node=node('c'),
                fee_base_msat=0,
                fee_proportional_millionths=0,
                cltv_delta=0,
                node_features=0
            ),
        ]
        # create a trampoline onion, this shouldn't raise InvalidPayloadSize
        create_trampoline_onion(
            route=dummy_route,
            amount_msat=0,
            final_cltv_abs=0,
            total_msat=0,
            payment_hash=urandom(32),
            payment_secret=urandom(32),
        )

    @needs_test_with_all_chacha20_implementations
    def test_decode_onion_error(self):
        # test vector from bolt-04
        payment_path_pubkeys = [
            bfh('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619'),
            bfh('0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'),
            bfh('027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007'),
            bfh('032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991'),
            bfh('02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145'),
        ]
        session_key = bfh('4141414141414141414141414141414141414141414141414141414141414141')
        error_packet_for_node_0 = bfh('9c5add3963fc7f6ed7f148623c84134b5647e1306419dbe2174e523fa9e2fbed3a06a19f899145610741c83ad40b7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e54554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be5cf638f693ec256aec514620cc28ee4a94bd9565bc4d4962b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb757366067d88c50f7e829138fde4f78d39b5b5802f1b92a8a820865af5cc79f9f30bc3f461c66af95d13e5e1f0381c184572a91dee1c849048a647a1158cf884064deddbf1b0b88dfe2f791428d0ba0f6fb2f04e14081f69165ae66d9297c118f0907705c9c4954a199bae0bb96fad763d690e7daa6cfda59ba7f2c8d11448b604d12d')

        decoded_error, index_of_sender = _decode_onion_error(error_packet_for_node_0, payment_path_pubkeys, session_key)
        self.assertEqual(bfh('4c2fc8bc08510334b6833ad9c3e79cd1b52ae59dfe5c2a4b23ead50f09f7ee0b0002200200fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
                             decoded_error)
        self.assertEqual(4, index_of_sender)

        failure_msg, index_of_sender = decode_onion_error(error_packet_for_node_0, payment_path_pubkeys, session_key)
        self.assertEqual(4, index_of_sender)
        self.assertEqual(OnionFailureCode.TEMPORARY_NODE_FAILURE, failure_msg.code)
        self.assertEqual(b'', failure_msg.data)

    async def test_find_path_for_onion_message(self):
        self.prepare_graph()

        path = self.path_finder.find_path_for_onion_message(nodeA=node('a'), nodeB=node('c'))
        self.assertEqual([
            PathEdge(start_node=node('a'), end_node=node('d'), short_channel_id=channel(6)),
            PathEdge(start_node=node('d'), end_node=node('c'), short_channel_id=channel(4)),
        ], path)

        # node e doesn't support onion messages
        path = self.path_finder.find_path_for_onion_message(nodeA=node('a'), nodeB=node('e'))
        self.assertIsNone(path)

    async def test_find_path_for_onion_message_ignores_amount_constraints(self):
        self.prepare_graph()

        # bump htlc_minimum_msat on channel(4) d->c direction
        key = (node('d'), channel(4))
        self.cdb._policies[key] = self.cdb._policies[key]._replace(htlc_minimum_msat=10_000_000)

        # a small payment can no longer be routed
        path = self.path_finder.find_path_for_payment(
            nodeA=node('a'),
            nodeB=node('c'),
            invoice_amount_msat=1000,
            node_filter=is_onion_message_node,
        )
        self.assertIsNone(path)

        # but an onion message still routes through the same hop
        path = self.path_finder.find_path_for_onion_message(nodeA=node('a'), nodeB=node('c'))
        self.assertEqual([
            PathEdge(start_node=node('a'), end_node=node('d'), short_channel_id=channel(6)),
            PathEdge(start_node=node('d'), end_node=node('c'), short_channel_id=channel(4)),
        ], path)


def _tramp_edge(start: str, end: str, *, fee_base=PLACEHOLDER_FEE, fee_prop=PLACEHOLDER_FEE, cltv=576) -> TrampolineEdge:
    return TrampolineEdge(
        start_node=node(start),
        end_node=node(end),
        short_channel_id=ShortChannelID.from_str("0x0x0"),
        fee_base_msat=fee_base,
        fee_proportional_millionths=fee_prop,
        cltv_delta=cltv,
        node_features=LnFeatures.VAR_ONION_OPT,
    )


class TestAllocateFeeBudget(ElectrumTestCase):
    """Tests for _allocate_fee_budget_among_route (backward-walk allocator)."""

    AMOUNT = 1_000_000  # 1000 sat
    BUDGET = PaymentFeeBudget(fee_msat=10_000, cltv=144)  # 10 sat

    def _allocate(self, route, *, amount=None, budget=None, level=6):
        budget = budget.fee_msat if budget else self.BUDGET.fee_msat
        budget_to_use = get_trampoline_budget(level, budget)
        return _allocate_fee_budget_among_route(
            route,
            usable_budget_msat=budget_to_use,
            amount_msat_for_dest=amount if amount is not None else self.AMOUNT,
        )

    def _realized_fee(self, route, amount=None) -> int:
        amt = amount if amount is not None else self.AMOUNT
        for edge in reversed(route[1:]):
            amt += edge.fee_for_edge(amt)
        return amt - (amount if amount is not None else self.AMOUNT)

    def test_all_placeholders_matches_even_split(self):
        # Route: me -> a -> b -> c (c is receiver). route[1:] has 2 placeholders.
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b'),
            _tramp_edge('b', 'c'),
        ]
        self._allocate(route)
        # At level 6, usable_budget = BUDGET.fee_msat = 10_000; split across 2.
        self.assertEqual(5_000, route[1].fee_base_msat)
        self.assertEqual(5_000, route[2].fee_base_msat)
        self.assertEqual(0, route[1].fee_proportional_millionths)
        self.assertEqual(0, route[2].fee_proportional_millionths)
        self.assertLessEqual(self._realized_fee(route), self.BUDGET.fee_msat)

    def test_known_fee_base_only_deducted_from_budget(self):
        # a->b is KNOWN with fee_base=2000, fee_prop=0; b->c is PLACEHOLDER.
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b', fee_base=2_000, fee_prop=0),
            _tramp_edge('b', 'c'),
        ]
        self._allocate(route)
        # Placeholder gets the full remaining budget (one placeholder, no proportional amplification).
        self.assertEqual(8_000, route[2].fee_base_msat)
        self.assertLessEqual(self._realized_fee(route), self.BUDGET.fee_msat)

    def test_known_proportional_amplifies_placeholder_cost(self):
        # a->b is KNOWN with fee_prop=10% (100_000); b->c is PLACEHOLDER.
        # Any fee f placed at b->c flows through a->b, which charges 10% on top.
        # Budget check:  total_fee_const + (1 + 0.1) * placeholder_fee  <=  10_000
        #   total_fee_const = 0 + amount * 0.1 = 100_000 msat.  That already exceeds budget,
        # so placeholder_fee must be 0 and realized fee > budget (caller's
        # is_route_within_budget will catch it).
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b', fee_base=0, fee_prop=100_000),
            _tramp_edge('b', 'c'),
        ]
        self._allocate(route)
        self.assertEqual(0, route[2].fee_base_msat)

    def test_known_proportional_small_fits_budget(self):
        # Smaller proportional fee that leaves room. a->b: fee_prop = 1%.
        # total_fee_const(amount=1_000_000) = 10_000 (== budget) without placeholders.
        # With smaller proportional (0.5%), total_fee_const = 5_000,
        # leaving budget_residual = 5_000.
        # total_fee_coeff = 1.005, so placeholder_fee = 5_000 / 1.005 ≈ 4975.
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b', fee_base=0, fee_prop=5_000),  # 0.5%
            _tramp_edge('b', 'c'),
        ]
        self._allocate(route)
        f = route[2].fee_base_msat
        self.assertGreater(f, 0)
        self.assertLessEqual(self._realized_fee(route), self.BUDGET.fee_msat)

    def test_known_fee_exceeds_budget_yields_zero_placeholder(self):
        # Known edge with fee_base > entire budget. Placeholder gets 0 instead
        # of going negative.
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b', fee_base=50_000, fee_prop=0),  # way over budget
            _tramp_edge('b', 'c'),
        ]
        self._allocate(route)
        self.assertEqual(0, route[2].fee_base_msat)
        self.assertEqual(0, route[2].fee_proportional_millionths)

    def test_no_placeholders_noop(self):
        # All edges KNOWN: allocator does nothing.
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b', fee_base=1_000, fee_prop=0),
            _tramp_edge('b', 'c', fee_base=2_000, fee_prop=0),
        ]
        self._allocate(route)
        self.assertEqual(1_000, route[1].fee_base_msat)
        self.assertEqual(2_000, route[2].fee_base_msat)

    def test_amount_at_each_hop(self):
        # invoice amt: 1000k msat
        # budget: 10k msat
        #
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b'),
            _tramp_edge('b', 'c', fee_base=1_000, fee_prop=1500),
            _tramp_edge('c', 'd'),
            _tramp_edge('d', 'e', fee_base=1_000, fee_prop=1500),
        ]
        self._allocate(route)
        amount = self.AMOUNT
        amounts_from_destination = iter((
            1000000, # amount for recipient (d -> e)
            1002500, # c -> d
            1004996, # b -> c
            1007503, # a -> b
            1009999 # us -> a
        ))
        for edge in reversed(route[1:]):
            self.assertEqual(amount, next(amounts_from_destination))
            amount += edge.fee_for_edge(amount)
        self.assertEqual([0, 2496, 1000, 2496, 1000], [e.fee_base_msat for e in route])

    @unittest.skip(reason="is a bit slow")
    def test_fuzz(self):
        invoice_amount = 1_000_000

        for round_ in range(10**5):
            budget = PaymentFeeBudget(fee_msat=random.randint(1000, 10*invoice_amount), cltv=144)
            route = [
                _tramp_edge('x', 'x', fee_base=0, fee_prop=0),
            ]
            num_edges = random.randint(1, 10)
            fee_base_min = random.randint(1000, 50000)
            fee_base_max = random.randint(fee_base_min, 50000)
            fee_prop_min = random.randint(1000, 50000)
            fee_prop_max = random.randint(fee_prop_min, 50000)
            for e in range(num_edges):
                if random.random() < 0.5:
                    route.append(_tramp_edge('x', 'x'))
                else:
                    fee_base = random.randint(fee_base_min, fee_base_max)
                    fee_prop = random.randint(fee_prop_min, fee_prop_max)
                    route.append(_tramp_edge('x', 'x', fee_base=fee_base, fee_prop=fee_prop))
            placeholder_fee = self._allocate(route, amount=invoice_amount, budget=budget)

            actual_fees = []
            fwd_amt = invoice_amount
            for e in route[::-1]:
                actual_fee = e.fee_for_edge(fwd_amt)
                fwd_amt += actual_fee
                actual_fees.append(actual_fee)
            actual_fees = actual_fees[::-1]
            # checks
            no_solution = placeholder_fee == 0
            solution_is_exact = (budget.fee_msat - num_edges <= sum(actual_fees) <= budget.fee_msat)
            assert no_solution or solution_is_exact

    def test_level_zero_gives_zero_placeholders(self):
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b'),
            _tramp_edge('b', 'c'),
        ]
        self._allocate(route, level=0)
        self.assertEqual(0, route[1].fee_base_msat)
        self.assertEqual(0, route[2].fee_base_msat)

    def test_placeholder_upstream_of_known(self):
        # Placeholder is UPSTREAM of known edge -> known edge's amount depends on placeholder fee.
        # Route: me -> a -> b -> c. a->b PLACEHOLDER, b->c KNOWN (fee_base=1000, fee_prop=10_000 = 1%).
        # Going backwards: first process b->c (known): total_fee_const = 1000 + 1_000_000 * 0.01 = 11_000.
        # That alone exceeds budget 10_000; placeholder gets 0.
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b'),
            _tramp_edge('b', 'c', fee_base=1_000, fee_prop=10_000),
        ]
        self._allocate(route)
        self.assertEqual(0, route[1].fee_base_msat)

    def test_placeholder_upstream_of_small_known_fits(self):
        # Same shape but small known fee so placeholder gets a positive fee.
        # b->c known: fee_base=500, fee_prop=0. total_fee_const = 500.
        # budget_residual = 9500. a->b placeholder sees
        # total_fee_coeff=1 (no upstream known), so placeholder_fee = 9500.
        route = [
            _tramp_edge('m', 'a', fee_base=0, fee_prop=0, cltv=0),
            _tramp_edge('a', 'b'),
            _tramp_edge('b', 'c', fee_base=500, fee_prop=0),
        ]
        self._allocate(route)
        self.assertEqual(9_500, route[1].fee_base_msat)
        self.assertLessEqual(self._realized_fee(route), self.BUDGET.fee_msat)
