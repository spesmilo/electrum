# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import queue
from collections import defaultdict
from typing import Sequence, List, Tuple, Optional, Dict, NamedTuple, TYPE_CHECKING, Set
import time
import attr

from .util import bh2u, profiler
from .logging import Logger
from .lnutil import (NUM_MAX_EDGES_IN_PAYMENT_PATH, ShortChannelID, LnFeatures,
                     NBLOCK_CLTV_EXPIRY_TOO_FAR_INTO_FUTURE)
from .channel_db import ChannelDB, Policy, NodeInfo

if TYPE_CHECKING:
    from .lnchannel import Channel


class NoChannelPolicy(Exception):
    def __init__(self, short_channel_id: bytes):
        short_channel_id = ShortChannelID.normalize(short_channel_id)
        super().__init__(f'cannot find channel policy for short_channel_id: {short_channel_id}')


class LNPathInconsistent(Exception): pass


def fee_for_edge_msat(forwarded_amount_msat: int, fee_base_msat: int, fee_proportional_millionths: int) -> int:
    return fee_base_msat \
           + (forwarded_amount_msat * fee_proportional_millionths // 1_000_000)


@attr.s(slots=True)
class PathEdge:
    """if you travel through short_channel_id, you will reach node_id"""
    node_id = attr.ib(type=bytes, kw_only=True, repr=lambda val: val.hex())
    short_channel_id = attr.ib(type=ShortChannelID, kw_only=True, repr=lambda val: str(val))


@attr.s
class RouteEdge(PathEdge):
    fee_base_msat = attr.ib(type=int, kw_only=True)
    fee_proportional_millionths = attr.ib(type=int, kw_only=True)
    cltv_expiry_delta = attr.ib(type=int, kw_only=True)
    node_features = attr.ib(type=int, kw_only=True, repr=lambda val: str(int(val)))  # note: for end node!

    def fee_for_edge(self, amount_msat: int) -> int:
        return fee_for_edge_msat(forwarded_amount_msat=amount_msat,
                                 fee_base_msat=self.fee_base_msat,
                                 fee_proportional_millionths=self.fee_proportional_millionths)

    @classmethod
    def from_channel_policy(cls, channel_policy: 'Policy',
                            short_channel_id: bytes, end_node: bytes, *,
                            node_info: Optional[NodeInfo]) -> 'RouteEdge':
        assert isinstance(short_channel_id, bytes)
        assert type(end_node) is bytes
        return RouteEdge(node_id=end_node,
                         short_channel_id=ShortChannelID.normalize(short_channel_id),
                         fee_base_msat=channel_policy.fee_base_msat,
                         fee_proportional_millionths=channel_policy.fee_proportional_millionths,
                         cltv_expiry_delta=channel_policy.cltv_expiry_delta,
                         node_features=node_info.features if node_info else 0)

    def is_sane_to_use(self, amount_msat: int) -> bool:
        # TODO revise ad-hoc heuristics
        # cltv cannot be more than 2 weeks
        if self.cltv_expiry_delta > 14 * 144:
            return False
        total_fee = self.fee_for_edge(amount_msat)
        if not is_fee_sane(total_fee, payment_amount_msat=amount_msat):
            return False
        return True

    def has_feature_varonion(self) -> bool:
        features = self.node_features
        return bool(features & LnFeatures.VAR_ONION_REQ or features & LnFeatures.VAR_ONION_OPT)

    def is_trampoline(self):
        return False

@attr.s
class TrampolineEdge(RouteEdge):
    outgoing_node_id = attr.ib(type=bytes)
    invoice_routing_info = attr.ib(type=bytes)
    invoice_features = attr.ib(type=int)

    def is_trampoline(self):
        return True

LNPaymentPath = Sequence[PathEdge]
LNPaymentRoute = Sequence[RouteEdge]


def is_route_sane_to_use(route: LNPaymentRoute, invoice_amount_msat: int, min_final_cltv_expiry: int) -> bool:
    """Run some sanity checks on the whole route, before attempting to use it.
    called when we are paying; so e.g. lower cltv is better
    """
    if len(route) > NUM_MAX_EDGES_IN_PAYMENT_PATH:
        return False
    amt = invoice_amount_msat
    cltv = min_final_cltv_expiry
    for route_edge in reversed(route[1:]):
        if not route_edge.is_sane_to_use(amt): return False
        amt += route_edge.fee_for_edge(amt)
        cltv += route_edge.cltv_expiry_delta
    total_fee = amt - invoice_amount_msat
    # TODO revise ad-hoc heuristics
    if cltv > NBLOCK_CLTV_EXPIRY_TOO_FAR_INTO_FUTURE:
        return False
    if not is_fee_sane(total_fee, payment_amount_msat=invoice_amount_msat):
        return False
    return True


def is_fee_sane(fee_msat: int, *, payment_amount_msat: int) -> bool:
    # fees <= 5 sat are fine
    if fee_msat <= 5_000:
        return True
    # fees <= 1 % of payment are fine
    if 100 * fee_msat <= payment_amount_msat:
        return True
    return False


BLACKLIST_DURATION = 3600

class LNPathFinder(Logger):

    def __init__(self, channel_db: ChannelDB):
        Logger.__init__(self)
        self.channel_db = channel_db
        self.blacklist = dict() # short_chan_id -> timestamp

    def add_to_blacklist(self, short_channel_id: ShortChannelID):
        self.logger.info(f'blacklisting channel {short_channel_id}')
        now = int(time.time())
        self.blacklist[short_channel_id] = now

    def is_blacklisted(self, short_channel_id: ShortChannelID) -> bool:
        now = int(time.time())
        t = self.blacklist.get(short_channel_id, 0)
        return now - t < BLACKLIST_DURATION

    def _edge_cost(self, short_channel_id: bytes, start_node: bytes, end_node: bytes,
                   payment_amt_msat: int, ignore_costs=False, is_mine=False, *,
                   my_channels: Dict[ShortChannelID, 'Channel'] = None) -> Tuple[float, int]:
        """Heuristic cost (distance metric) of going through a channel.
        Returns (heuristic_cost, fee_for_edge_msat).
        """
        channel_info = self.channel_db.get_channel_info(short_channel_id, my_channels=my_channels)
        if channel_info is None:
            return float('inf'), 0
        channel_policy = self.channel_db.get_policy_for_node(short_channel_id, start_node, my_channels=my_channels)
        if channel_policy is None:
            return float('inf'), 0
        # channels that did not publish both policies often return temporary channel failure
        if self.channel_db.get_policy_for_node(short_channel_id, end_node, my_channels=my_channels) is None \
                and not is_mine:
            return float('inf'), 0
        if channel_policy.is_disabled():
            return float('inf'), 0
        if payment_amt_msat < channel_policy.htlc_minimum_msat:
            return float('inf'), 0  # payment amount too little
        if channel_info.capacity_sat is not None and \
                payment_amt_msat // 1000 > channel_info.capacity_sat:
            return float('inf'), 0  # payment amount too large
        if channel_policy.htlc_maximum_msat is not None and \
                payment_amt_msat > channel_policy.htlc_maximum_msat:
            return float('inf'), 0  # payment amount too large
        node_info = self.channel_db.get_node_info_for_node_id(node_id=end_node)
        route_edge = RouteEdge.from_channel_policy(channel_policy, short_channel_id, end_node,
                                                   node_info=node_info)
        if not route_edge.is_sane_to_use(payment_amt_msat):
            return float('inf'), 0  # thanks but no thanks

        # Distance metric notes:  # TODO constants are ad-hoc
        # ( somewhat based on https://github.com/lightningnetwork/lnd/pull/1358 )
        # - Edges have a base cost. (more edges -> less likely none will fail)
        # - The larger the payment amount, and the longer the CLTV,
        #   the more irritating it is if the HTLC gets stuck.
        # - Paying lower fees is better. :)
        base_cost = 500  # one more edge ~ paying 500 msat more fees
        if ignore_costs:
            return base_cost, 0
        fee_msat = route_edge.fee_for_edge(payment_amt_msat)
        cltv_cost = route_edge.cltv_expiry_delta * payment_amt_msat * 15 / 1_000_000_000
        overall_cost = base_cost + fee_msat + cltv_cost
        return overall_cost, fee_msat

    def get_distances(self, nodeA: bytes, nodeB: bytes,
                      invoice_amount_msat: int, *,
                      my_channels: Dict[ShortChannelID, 'Channel'] = None
                      ) -> Dict[bytes, PathEdge]:
        # note: we don't lock self.channel_db, so while the path finding runs,
        #       the underlying graph could potentially change... (not good but maybe ~OK?)

        # run Dijkstra
        # The search is run in the REVERSE direction, from nodeB to nodeA,
        # to properly calculate compound routing fees.
        distance_from_start = defaultdict(lambda: float('inf'))
        distance_from_start[nodeB] = 0
        prev_node = {}  # type: Dict[bytes, PathEdge]
        nodes_to_explore = queue.PriorityQueue()
        nodes_to_explore.put((0, invoice_amount_msat, nodeB))  # order of fields (in tuple) matters!


        # main loop of search
        while nodes_to_explore.qsize() > 0:
            dist_to_edge_endnode, amount_msat, edge_endnode = nodes_to_explore.get()
            if edge_endnode == nodeA:
                break
            if dist_to_edge_endnode != distance_from_start[edge_endnode]:
                # queue.PriorityQueue does not implement decrease_priority,
                # so instead of decreasing priorities, we add items again into the queue.
                # so there are duplicates in the queue, that we discard now:
                continue
            for edge_channel_id in self.channel_db.get_channels_for_node(edge_endnode, my_channels=my_channels):
                assert isinstance(edge_channel_id, bytes)
                if self.is_blacklisted(edge_channel_id):
                    continue
                channel_info = self.channel_db.get_channel_info(edge_channel_id, my_channels=my_channels)
                edge_startnode = channel_info.node2_id if channel_info.node1_id == edge_endnode else channel_info.node1_id
                is_mine = edge_channel_id in my_channels
                if is_mine:
                    if edge_startnode == nodeA:  # payment outgoing, on our channel
                        if not my_channels[edge_channel_id].can_pay(amount_msat, check_frozen=True):
                            continue
                    else:  # payment incoming, on our channel. (funny business, cycle weirdness)
                        assert edge_endnode == nodeA, (bh2u(edge_startnode), bh2u(edge_endnode))
                        if not my_channels[edge_channel_id].can_receive(amount_msat, check_frozen=True):
                            continue
                edge_cost, fee_for_edge_msat = self._edge_cost(
                    edge_channel_id,
                    start_node=edge_startnode,
                    end_node=edge_endnode,
                    payment_amt_msat=amount_msat,
                    ignore_costs=(edge_startnode == nodeA),
                    is_mine=is_mine,
                    my_channels=my_channels)
                alt_dist_to_neighbour = distance_from_start[edge_endnode] + edge_cost
                if alt_dist_to_neighbour < distance_from_start[edge_startnode]:
                    distance_from_start[edge_startnode] = alt_dist_to_neighbour
                    prev_node[edge_startnode] = PathEdge(node_id=edge_endnode,
                                                         short_channel_id=ShortChannelID(edge_channel_id))
                    amount_to_forward_msat = amount_msat + fee_for_edge_msat
                    nodes_to_explore.put((alt_dist_to_neighbour, amount_to_forward_msat, edge_startnode))

        return prev_node

    @profiler
    def find_path_for_payment(self, nodeA: bytes, nodeB: bytes,
                              invoice_amount_msat: int, *,
                              my_channels: Dict[ShortChannelID, 'Channel'] = None) \
            -> Optional[LNPaymentPath]:
        """Return a path from nodeA to nodeB."""
        assert type(nodeA) is bytes
        assert type(nodeB) is bytes
        assert type(invoice_amount_msat) is int
        if my_channels is None:
            my_channels = {}

        prev_node = self.get_distances(nodeA, nodeB, invoice_amount_msat, my_channels=my_channels)

        if nodeA not in prev_node:
            return None  # no path found

        # backtrack from search_end (nodeA) to search_start (nodeB)
        # FIXME paths cannot be longer than 20 edges (onion packet)...
        edge_startnode = nodeA
        path = []
        while edge_startnode != nodeB:
            edge = prev_node[edge_startnode]
            path += [edge]
            edge_startnode = edge.node_id
        return path

    def create_route_from_path(self, path: Optional[LNPaymentPath], from_node_id: bytes, *,
                               my_channels: Dict[ShortChannelID, 'Channel'] = None) -> LNPaymentRoute:
        assert isinstance(from_node_id, bytes)
        if path is None:
            raise Exception('cannot create route from None path')
        route = []
        prev_node_id = from_node_id
        for edge in path:
            node_id = edge.node_id
            short_channel_id = edge.short_channel_id
            _endnodes = self.channel_db.get_endnodes_for_chan(short_channel_id, my_channels=my_channels)
            if _endnodes and sorted(_endnodes) != sorted([prev_node_id, node_id]):
                raise LNPathInconsistent("edges do not chain together")
            channel_policy = self.channel_db.get_policy_for_node(short_channel_id=short_channel_id,
                                                                 node_id=prev_node_id,
                                                                 my_channels=my_channels)
            if channel_policy is None:
                raise NoChannelPolicy(short_channel_id)
            node_info = self.channel_db.get_node_info_for_node_id(node_id=node_id)
            route.append(RouteEdge.from_channel_policy(channel_policy, short_channel_id, node_id,
                                                       node_info=node_info))
            prev_node_id = node_id
        return route
