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

from .util import bh2u, profiler
from .logging import Logger
from .lnutil import NUM_MAX_EDGES_IN_PAYMENT_PATH, ShortChannelID
from .channel_db import ChannelDB, Policy

if TYPE_CHECKING:
    from .lnchannel import Channel


class NoChannelPolicy(Exception):
    def __init__(self, short_channel_id: bytes):
        short_channel_id = ShortChannelID.normalize(short_channel_id)
        super().__init__(f'cannot find channel policy for short_channel_id: {short_channel_id}')


def fee_for_edge_msat(forwarded_amount_msat: int, fee_base_msat: int, fee_proportional_millionths: int) -> int:
    return fee_base_msat \
           + (forwarded_amount_msat * fee_proportional_millionths // 1_000_000)


class RouteEdge(NamedTuple):
    """if you travel through short_channel_id, you will reach node_id"""
    node_id: bytes
    short_channel_id: ShortChannelID
    fee_base_msat: int
    fee_proportional_millionths: int
    cltv_expiry_delta: int

    def fee_for_edge(self, amount_msat: int) -> int:
        return fee_for_edge_msat(forwarded_amount_msat=amount_msat,
                                 fee_base_msat=self.fee_base_msat,
                                 fee_proportional_millionths=self.fee_proportional_millionths)

    @classmethod
    def from_channel_policy(cls, channel_policy: 'Policy',
                            short_channel_id: bytes, end_node: bytes) -> 'RouteEdge':
        assert isinstance(short_channel_id, bytes)
        assert type(end_node) is bytes
        return RouteEdge(end_node,
                         ShortChannelID.normalize(short_channel_id),
                         channel_policy.fee_base_msat,
                         channel_policy.fee_proportional_millionths,
                         channel_policy.cltv_expiry_delta)

    def is_sane_to_use(self, amount_msat: int) -> bool:
        # TODO revise ad-hoc heuristics
        # cltv cannot be more than 2 weeks
        if self.cltv_expiry_delta > 14 * 144: return False
        total_fee = self.fee_for_edge(amount_msat)
        # fees below 50 sat are fine
        if total_fee > 50_000:
            # fee cannot be higher than amt
            if total_fee > amount_msat: return False
            # fee cannot be higher than 5000 sat
            if total_fee > 5_000_000: return False
            # unless amt is tiny, fee cannot be more than 10%
            if amount_msat > 1_000_000 and total_fee > amount_msat/10: return False
        return True


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
    # cltv cannot be more than 2 months
    if cltv > 60 * 144: return False
    # fees below 50 sat are fine
    if total_fee > 50_000:
        # fee cannot be higher than amt
        if total_fee > invoice_amount_msat: return False
        # fee cannot be higher than 5000 sat
        if total_fee > 5_000_000: return False
        # unless amt is tiny, fee cannot be more than 10%
        if invoice_amount_msat > 1_000_000 and total_fee > invoice_amount_msat/10: return False
    return True


class LNPathFinder(Logger):

    def __init__(self, channel_db: ChannelDB):
        Logger.__init__(self)
        self.channel_db = channel_db
        self.blacklist = set()

    def add_to_blacklist(self, short_channel_id: ShortChannelID):
        self.logger.info(f'blacklisting channel {short_channel_id}')
        self.blacklist.add(short_channel_id)

    def _edge_cost(self, short_channel_id: bytes, start_node: bytes, end_node: bytes,
                   payment_amt_msat: int, ignore_costs=False, is_mine=False) -> Tuple[float, int]:
        """Heuristic cost of going through a channel.
        Returns (heuristic_cost, fee_for_edge_msat).
        """
        channel_info = self.channel_db.get_channel_info(short_channel_id)
        if channel_info is None:
            return float('inf'), 0
        channel_policy = self.channel_db.get_policy_for_node(short_channel_id, start_node)
        if channel_policy is None:
            return float('inf'), 0
        # channels that did not publish both policies often return temporary channel failure
        if self.channel_db.get_policy_for_node(short_channel_id, end_node) is None and not is_mine:
            return float('inf'), 0
        if channel_policy.is_disabled():
            return float('inf'), 0
        route_edge = RouteEdge.from_channel_policy(channel_policy, short_channel_id, end_node)
        if payment_amt_msat < channel_policy.htlc_minimum_msat:
            return float('inf'), 0  # payment amount too little
        if channel_info.capacity_sat is not None and \
                payment_amt_msat // 1000 > channel_info.capacity_sat:
            return float('inf'), 0  # payment amount too large
        if channel_policy.htlc_maximum_msat is not None and \
                payment_amt_msat > channel_policy.htlc_maximum_msat:
            return float('inf'), 0  # payment amount too large
        if not route_edge.is_sane_to_use(payment_amt_msat):
            return float('inf'), 0  # thanks but no thanks
        fee_msat = route_edge.fee_for_edge(payment_amt_msat) if not ignore_costs else 0
        # TODO revise
        # paying 10 more satoshis ~ waiting one more block
        fee_cost = fee_msat / 1000 / 10
        cltv_cost = route_edge.cltv_expiry_delta if not ignore_costs else 0
        return cltv_cost + fee_cost + 1, fee_msat

    @profiler
    def find_path_for_payment(self, nodeA: bytes, nodeB: bytes,
                              invoice_amount_msat: int,
                              my_channels: List['Channel']=None) -> Sequence[Tuple[bytes, bytes]]:
        """Return a path from nodeA to nodeB.

        Returns a list of (node_id, short_channel_id) representing a path.
        To get from node ret[n][0] to ret[n+1][0], use channel ret[n+1][1];
        i.e. an element reads as, "to get to node_id, travel through short_channel_id"
        """
        assert type(nodeA) is bytes
        assert type(nodeB) is bytes
        assert type(invoice_amount_msat) is int
        if my_channels is None: my_channels = []
        my_channels = {chan.short_channel_id: chan for chan in my_channels}

        # FIXME paths cannot be longer than 20 edges (onion packet)...

        # run Dijkstra
        # The search is run in the REVERSE direction, from nodeB to nodeA,
        # to properly calculate compound routing fees.
        distance_from_start = defaultdict(lambda: float('inf'))
        distance_from_start[nodeB] = 0
        prev_node = {}
        nodes_to_explore = queue.PriorityQueue()
        nodes_to_explore.put((0, invoice_amount_msat, nodeB))  # order of fields (in tuple) matters!

        def inspect_edge():
            is_mine = edge_channel_id in my_channels
            if is_mine:
                if edge_startnode == nodeA:  # payment outgoing, on our channel
                    if not my_channels[edge_channel_id].can_pay(amount_msat):
                        return
                else:  # payment incoming, on our channel. (funny business, cycle weirdness)
                    assert edge_endnode == nodeA, (bh2u(edge_startnode), bh2u(edge_endnode))
                    pass  # TODO?
            edge_cost, fee_for_edge_msat = self._edge_cost(
                edge_channel_id,
                start_node=edge_startnode,
                end_node=edge_endnode,
                payment_amt_msat=amount_msat,
                ignore_costs=(edge_startnode == nodeA),
                is_mine=is_mine)
            alt_dist_to_neighbour = distance_from_start[edge_endnode] + edge_cost
            if alt_dist_to_neighbour < distance_from_start[edge_startnode]:
                distance_from_start[edge_startnode] = alt_dist_to_neighbour
                prev_node[edge_startnode] = edge_endnode, edge_channel_id
                amount_to_forward_msat = amount_msat + fee_for_edge_msat
                nodes_to_explore.put((alt_dist_to_neighbour, amount_to_forward_msat, edge_startnode))

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
            for edge_channel_id in self.channel_db.get_channels_for_node(edge_endnode):
                assert isinstance(edge_channel_id, bytes)
                if edge_channel_id in self.blacklist:
                    continue
                channel_info = self.channel_db.get_channel_info(edge_channel_id)
                edge_startnode = channel_info.node2_id if channel_info.node1_id == edge_endnode else channel_info.node1_id
                inspect_edge()
        else:
            return None  # no path found

        # backtrack from search_end (nodeA) to search_start (nodeB)
        edge_startnode = nodeA
        path = []
        while edge_startnode != nodeB:
            edge_endnode, edge_taken = prev_node[edge_startnode]
            path += [(edge_endnode, edge_taken)]
            edge_startnode = edge_endnode
        return path

    def create_route_from_path(self, path, from_node_id: bytes) -> LNPaymentRoute:
        assert isinstance(from_node_id, bytes)
        if path is None:
            raise Exception('cannot create route from None path')
        route = []
        prev_node_id = from_node_id
        for node_id, short_channel_id in path:
            channel_policy = self.channel_db.get_routing_policy_for_channel(prev_node_id, short_channel_id)
            if channel_policy is None:
                raise NoChannelPolicy(short_channel_id)
            route.append(RouteEdge.from_channel_policy(channel_policy, short_channel_id, node_id))
            prev_node_id = node_id
        return route
