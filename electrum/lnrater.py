# Copyright (C) 2020 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
"""
lnrater.py contains Lightning Network node rating functionality.
"""

import asyncio
from collections import defaultdict
from pprint import pformat
from random import choices
from statistics import mean, median, stdev
from typing import TYPE_CHECKING, Dict, NamedTuple, Tuple, List
import time

from .logging import Logger
from .util import profiler
from .lnrouter import fee_for_edge_msat

if TYPE_CHECKING:
    from .network import Network
    from .channel_db import Policy
    from .lnchannel import ShortChannelID
    from .lnworker import LNWallet


MONTH_IN_BLOCKS = 6 * 24 * 30
# the scores are only updated after this time interval
RATER_UPDATE_TIME_SEC = 10 * 60
# amount used for calculating an effective relative fee
FEE_AMOUNT_MSAT = 100_000_000

# define some numbers for minimal requirements of good nodes
# exclude nodes with less number of channels
EXCLUDE_NUM_CHANNELS = 15
# exclude nodes with less mean capacity
EXCLUDE_MEAN_CAPACITY_MSAT = 1_000_000_000
# exclude nodes which are young
EXCLUDE_NODE_AGE = 2 * MONTH_IN_BLOCKS
# exclude nodes which have young mean channel age
EXCLUDE_MEAN_CHANNEL_AGE = EXCLUDE_NODE_AGE
# exclude nodes which charge a high fee
EXCLUCE_EFFECTIVE_FEE_RATE = 0.001500
# exclude nodes whose last channel open was a long time ago
EXCLUDE_BLOCKS_LAST_CHANNEL = 3 * MONTH_IN_BLOCKS


class NodeStats(NamedTuple):
    number_channels: int
    # capacity related
    total_capacity_msat: int
    median_capacity_msat: float
    mean_capacity_msat: float
    # block height related
    node_age_block_height: int
    mean_channel_age_block_height: float
    blocks_since_last_channel: int
    # fees
    mean_fee_rate: float


def weighted_sum(numbers: List[float], weights: List[float]) -> float:
    running_sum = 0.0
    for n, w in zip(numbers, weights):
        running_sum += n * w
    return running_sum/sum(weights)


class LNRater(Logger):
    def __init__(self, lnworker: 'LNWallet', network: 'Network'):
        """LNRater can be used to suggest nodes to open up channels with.

        The graph is analyzed and some heuristics are applied to sort out nodes
        that are deemed to be bad routers or unmaintained.
        """
        Logger.__init__(self)
        self.lnworker = lnworker
        self.network = network
        self.channel_db = self.network.channel_db

        self._node_stats: Dict[bytes, NodeStats] = {}  # node_id -> NodeStats
        self._node_ratings: Dict[bytes, float] = {}  # node_id -> float
        self._policies_by_nodes: Dict[bytes, List[Tuple[ShortChannelID, Policy]]] = defaultdict(list)  # node_id -> (short_channel_id, policy)
        self._last_analyzed = 0  # timestamp
        self._last_progress_percent = 0

    def maybe_analyze_graph(self):
        loop = asyncio.get_event_loop()
        fut = asyncio.run_coroutine_threadsafe(self._maybe_analyze_graph(), loop)
        fut.result()

    def analyze_graph(self):
        """Forces a graph analysis, e.g., due to external triggers like
        the graph info reaching 50%."""
        loop = asyncio.get_event_loop()
        fut = asyncio.run_coroutine_threadsafe(self._analyze_graph(), loop)
        fut.result()

    async def _maybe_analyze_graph(self):
        """Analyzes the graph when in early sync stage (>30%) or when caching
        time expires."""
        # gather information about graph sync status
        current_channels, total, progress_percent = self.network.lngossip.get_sync_progress_estimate()

        # gossip sync progress state could be None when not started, but channel
        # db already knows something about the graph, which is why we allow to
        # evaluate the graph early
        if progress_percent is not None or self.channel_db.num_nodes > 500:
            progress_percent = progress_percent or 0  # convert None to 0
            now = time.time()
            # graph should have changed significantly during the sync progress
            # or last analysis was a long time ago
            if (30 <= progress_percent and progress_percent - self._last_progress_percent >= 10 or
                    self._last_analyzed + RATER_UPDATE_TIME_SEC < now):
                await self._analyze_graph()
                self._last_progress_percent = progress_percent
                self._last_analyzed = now

    async def _analyze_graph(self):
        await self.channel_db.data_loaded.wait()
        self._collect_policies_by_node()
        loop = asyncio.get_running_loop()
        # the analysis is run in an executor because it's costly
        await loop.run_in_executor(None, self._collect_purged_stats)
        self._rate_nodes()
        now = time.time()
        self._last_analyzed = now

    def _collect_policies_by_node(self):
        policies = self.channel_db.get_node_policies()
        for pv, p in policies.items():
            # append tuples of ShortChannelID and Policy
            self._policies_by_nodes[pv[0]].append((pv[1], p))

    @profiler
    def _collect_purged_stats(self):
        """Traverses through the graph and sorts out nodes."""
        current_height = self.network.get_local_height()
        node_infos = self.channel_db.get_node_infos()

        for n, channel_policies in self._policies_by_nodes.items():
            try:
                # use policies synonymously to channels
                num_channels = len(channel_policies)

                # save some time for nodes we are not interested in:
                if num_channels < EXCLUDE_NUM_CHANNELS:
                    continue

                # analyze block heights
                block_heights = [p[0].block_height for p in channel_policies]
                node_age_bh = current_height - min(block_heights)
                if node_age_bh < EXCLUDE_NODE_AGE:
                    continue
                mean_channel_age_bh = current_height - mean(block_heights)
                if mean_channel_age_bh < EXCLUDE_MEAN_CHANNEL_AGE:
                    continue
                blocks_since_last_channel = current_height - max(block_heights)
                if blocks_since_last_channel > EXCLUDE_BLOCKS_LAST_CHANNEL:
                    continue

                # analyze capacities
                capacities = [p[1].htlc_maximum_msat for p in channel_policies]
                if None in capacities:
                    continue
                total_capacity = sum(capacities)

                mean_capacity = total_capacity / num_channels if num_channels else 0
                if mean_capacity < EXCLUDE_MEAN_CAPACITY_MSAT:
                    continue
                median_capacity = median(capacities)

                # analyze fees
                effective_fee_rates = [fee_for_edge_msat(
                    FEE_AMOUNT_MSAT,
                    p[1].fee_base_msat,
                    p[1].fee_proportional_millionths) / FEE_AMOUNT_MSAT for p in channel_policies]
                mean_fees_rate = mean(effective_fee_rates)
                if mean_fees_rate > EXCLUCE_EFFECTIVE_FEE_RATE:
                    continue

                self._node_stats[n] = NodeStats(
                    number_channels=num_channels,
                    total_capacity_msat=total_capacity,
                    median_capacity_msat=median_capacity,
                    mean_capacity_msat=mean_capacity,
                    node_age_block_height=node_age_bh,
                    mean_channel_age_block_height=mean_channel_age_bh,
                    blocks_since_last_channel=blocks_since_last_channel,
                    mean_fee_rate=mean_fees_rate
                )

            except Exception as e:
                self.logger.exception("Could not use channel policies for "
                                      "calculating statistics.")
                self.logger.debug(pformat(channel_policies))
                continue

        self.logger.info(f"node statistics done, calculated statistics"
                         f"for {len(self._node_stats)} nodes")

    def _rate_nodes(self):
        """Rate nodes by collected statistics."""

        max_capacity = 0
        max_num_chan = 0
        min_fee_rate = float('inf')
        for stats in self._node_stats.values():
            max_capacity = max(max_capacity, stats.total_capacity_msat)
            max_num_chan = max(max_num_chan, stats.number_channels)
            min_fee_rate = min(min_fee_rate, stats.mean_fee_rate)

        for n, stats in self._node_stats.items():
            heuristics = []
            heuristics_weights = []

            # Construct an average score which leads to recommendation of nodes
            # with low fees, large capacity and reasonable number of channels.
            # This is somewhat akin to preferential attachment, but low fee
            # nodes are more favored. Here we make a compromise between user
            # comfort and decentralization, tending towards user comfort.

            # number of channels
            heuristics.append(stats.number_channels / max_num_chan)
            heuristics_weights.append(0.2)
            # total capacity
            heuristics.append(stats.total_capacity_msat / max_capacity)
            heuristics_weights.append(0.8)
            # inverse fees
            fees = min(1E-6, min_fee_rate) / max(1E-10, stats.mean_fee_rate)
            heuristics.append(fees)
            heuristics_weights.append(1.0)

            self._node_ratings[n] = weighted_sum(heuristics, heuristics_weights)

    def suggest_node_channel_open(self) -> Tuple[bytes, NodeStats]:
        node_keys = list(self._node_stats.keys())
        node_ratings = list(self._node_ratings.values())
        channel_peers = self.lnworker.channel_peers()

        while True:
            # randomly pick nodes weighted by node_rating
            pk = choices(node_keys, weights=node_ratings, k=1)[0]

            # don't want to connect to nodes we are already connected to
            if pk not in channel_peers:
                break

        node_infos = self.channel_db.get_node_infos()
        self.logger.info(
            f"node rating for {node_infos[pk].alias}:\n"
            f"{pformat(self._node_stats[pk])} (score {self._node_ratings[pk]})")

        return pk, self._node_stats[pk]

    def suggest_peer(self):
        self.maybe_analyze_graph()
        if self._node_ratings:
            return self.suggest_node_channel_open()[0]
        else:
            return None
