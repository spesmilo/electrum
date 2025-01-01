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
from typing import Sequence, Tuple, Optional, Dict, TYPE_CHECKING, Set
import time
import threading
from threading import RLock
from math import inf

import attr

from .util import profiler, with_lock
from .logging import Logger
from .lnutil import (NUM_MAX_EDGES_IN_PAYMENT_PATH, ShortChannelID, LnFeatures,
                     NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE, PaymentFeeBudget)
from .channel_db import ChannelDB, Policy, NodeInfo

if TYPE_CHECKING:
    from .lnchannel import Channel

DEFAULT_PENALTY_BASE_MSAT = 500  # how much base fee we apply for unknown sending capability of a channel
DEFAULT_PENALTY_PROPORTIONAL_MILLIONTH = 100  # how much relative fee we apply for unknown sending capability of a channel
HINT_DURATION = 3600  # how long (in seconds) a liquidity hint remains valid


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
    start_node = attr.ib(type=bytes, kw_only=True, repr=lambda val: val.hex())
    end_node = attr.ib(type=bytes, kw_only=True, repr=lambda val: val.hex())
    short_channel_id = attr.ib(type=ShortChannelID, kw_only=True, repr=lambda val: str(val))

    @property
    def node_id(self) -> bytes:
        # legacy compat  # TODO rm
        return self.end_node

@attr.s
class RouteEdge(PathEdge):
    fee_base_msat = attr.ib(type=int, kw_only=True)                # for start_node
    fee_proportional_millionths = attr.ib(type=int, kw_only=True)  # for start_node
    cltv_delta = attr.ib(type=int, kw_only=True)                   # for start_node
    node_features = attr.ib(type=int, kw_only=True, repr=lambda val: str(int(val)))  # note: for end_node!

    def fee_for_edge(self, amount_msat: int) -> int:
        return fee_for_edge_msat(forwarded_amount_msat=amount_msat,
                                 fee_base_msat=self.fee_base_msat,
                                 fee_proportional_millionths=self.fee_proportional_millionths)

    @classmethod
    def from_channel_policy(
            cls,
            *,
            channel_policy: 'Policy',  # for start_node
            short_channel_id: bytes,
            start_node: bytes,
            end_node: bytes,
            node_info: Optional[NodeInfo],  # for end_node
    ) -> 'RouteEdge':
        assert isinstance(short_channel_id, bytes)
        assert type(start_node) is bytes
        assert type(end_node) is bytes
        return RouteEdge(
            start_node=start_node,
            end_node=end_node,
            short_channel_id=ShortChannelID.normalize(short_channel_id),
            fee_base_msat=channel_policy.fee_base_msat,
            fee_proportional_millionths=channel_policy.fee_proportional_millionths,
            cltv_delta=channel_policy.cltv_delta,
            node_features=node_info.features if node_info else 0)

    def has_feature_varonion(self) -> bool:
        features = LnFeatures(self.node_features)
        return features.supports(LnFeatures.VAR_ONION_OPT)

    def is_trampoline(self) -> bool:
        return False

@attr.s
class TrampolineEdge(RouteEdge):
    invoice_routing_info = attr.ib(type=bytes, default=None)
    invoice_features = attr.ib(type=int, default=None)
    # this is re-defined from parent just to specify a default value:
    short_channel_id = attr.ib(default=ShortChannelID(8), repr=lambda val: str(val))

    def is_trampoline(self):
        return True


LNPaymentPath = Sequence[PathEdge]
LNPaymentRoute = Sequence[RouteEdge]
LNPaymentTRoute = Sequence[TrampolineEdge]


def is_route_within_budget(
    route: LNPaymentRoute,
    *,
    budget: PaymentFeeBudget,
    amount_msat_for_dest: int,  # that final receiver gets
    cltv_delta_for_dest: int,   # that final receiver gets
) -> bool:
    """Run some sanity checks on the whole route, before attempting to use it.
    called when we are paying; so e.g. lower cltv is better
    """
    if len(route) > NUM_MAX_EDGES_IN_PAYMENT_PATH:
        return False
    amt = amount_msat_for_dest
    cltv_cost_of_route = 0  # excluding cltv_delta_for_dest
    for route_edge in reversed(route[1:]):
        amt += route_edge.fee_for_edge(amt)
        cltv_cost_of_route += route_edge.cltv_delta
    fee_cost = amt - amount_msat_for_dest
    # check against budget
    if cltv_cost_of_route > budget.cltv:
        return False
    if fee_cost > budget.fee_msat:
        return False
    # sanity check
    total_cltv_delta = cltv_cost_of_route + cltv_delta_for_dest
    if total_cltv_delta > NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE:
        return False
    return True


class LiquidityHint:
    """Encodes the amounts that can and cannot be sent over the direction of a
    channel.

    A LiquidityHint is the value of a dict, which is keyed to node ids and the
    channel.
    """
    def __init__(self):
        # use "can_send_forward + can_send_backward < cannot_send_forward + cannot_send_backward" as a sanity check?
        self._can_send_forward = None
        self._cannot_send_forward = None
        self._can_send_backward = None
        self._cannot_send_backward = None
        self.hint_timestamp = 0
        self._inflight_htlcs_forward = 0
        self._inflight_htlcs_backward = 0

    def is_hint_invalid(self) -> bool:
        now = int(time.time())
        return now - self.hint_timestamp > HINT_DURATION

    @property
    def can_send_forward(self):
        return None if self.is_hint_invalid() else self._can_send_forward

    @can_send_forward.setter
    def can_send_forward(self, amount):
        # we don't want to record less significant info
        # (sendable amount is lower than known sendable amount):
        if self._can_send_forward and self._can_send_forward > amount:
            return
        self._can_send_forward = amount
        # we make a sanity check that sendable amount is lower than not sendable amount
        if self._cannot_send_forward and self._can_send_forward > self._cannot_send_forward:
            self._cannot_send_forward = None

    @property
    def can_send_backward(self):
        return None if self.is_hint_invalid() else self._can_send_backward

    @can_send_backward.setter
    def can_send_backward(self, amount):
        if self._can_send_backward and self._can_send_backward > amount:
            return
        self._can_send_backward = amount
        if self._cannot_send_backward and self._can_send_backward > self._cannot_send_backward:
            self._cannot_send_backward = None

    @property
    def cannot_send_forward(self):
        return None if self.is_hint_invalid() else self._cannot_send_forward

    @cannot_send_forward.setter
    def cannot_send_forward(self, amount):
        # we don't want to record less significant info
        # (not sendable amount is higher than known not sendable amount):
        if self._cannot_send_forward and self._cannot_send_forward < amount:
            return
        self._cannot_send_forward = amount
        if self._can_send_forward and self._can_send_forward > self._cannot_send_forward:
            self._can_send_forward = None
        # if we can't send over the channel, we should be able to send in the
        # reverse direction
        self.can_send_backward = amount

    @property
    def cannot_send_backward(self):
        return None if self.is_hint_invalid() else self._cannot_send_backward

    @cannot_send_backward.setter
    def cannot_send_backward(self, amount):
        if self._cannot_send_backward and self._cannot_send_backward < amount:
            return
        self._cannot_send_backward = amount
        if self._can_send_backward and self._can_send_backward > self._cannot_send_backward:
            self._can_send_backward = None
        self.can_send_forward = amount

    def can_send(self, is_forward_direction: bool):
        # make info invalid after some time?
        if is_forward_direction:
            return self.can_send_forward
        else:
            return self.can_send_backward

    def cannot_send(self, is_forward_direction: bool):
        # make info invalid after some time?
        if is_forward_direction:
            return self.cannot_send_forward
        else:
            return self.cannot_send_backward

    def update_can_send(self, is_forward_direction: bool, amount: int):
        self.hint_timestamp = int(time.time())
        if is_forward_direction:
            self.can_send_forward = amount
        else:
            self.can_send_backward = amount

    def update_cannot_send(self, is_forward_direction: bool, amount: int):
        self.hint_timestamp = int(time.time())
        if is_forward_direction:
            self.cannot_send_forward = amount
        else:
            self.cannot_send_backward = amount

    def num_inflight_htlcs(self, is_forward_direction: bool) -> int:
        if is_forward_direction:
            return self._inflight_htlcs_forward
        else:
            return self._inflight_htlcs_backward

    def add_htlc(self, is_forward_direction: bool):
        if is_forward_direction:
            self._inflight_htlcs_forward += 1
        else:
            self._inflight_htlcs_backward += 1

    def remove_htlc(self, is_forward_direction: bool):
        if is_forward_direction:
            self._inflight_htlcs_forward = max(0, self._inflight_htlcs_forward - 1)
        else:
            self._inflight_htlcs_backward = max(0, self._inflight_htlcs_forward - 1)

    def __repr__(self):
        return f"forward: can send: {self._can_send_forward} msat, cannot send: {self._cannot_send_forward} msat, htlcs: {self._inflight_htlcs_forward}\n" \
               f"backward: can send: {self._can_send_backward} msat, cannot send: {self._cannot_send_backward} msat, htlcs: {self._inflight_htlcs_backward}\n"


class LiquidityHintMgr:
    """Implements liquidity hints for channels in the graph.

    This class can be used to update liquidity information about channels in the
    graph. Implements a penalty function for edge weighting in the pathfinding
    algorithm that favors channels which can route payments and penalizes
    channels that cannot.
    """
    # TODO: hints based on node pairs only (shadow channels, non-strict forwarding)?
    def __init__(self):
        self.lock = RLock()
        self._liquidity_hints: Dict[ShortChannelID, LiquidityHint] = {}

    @with_lock
    def get_hint(self, channel_id: ShortChannelID) -> LiquidityHint:
        hint = self._liquidity_hints.get(channel_id)
        if not hint:
            hint = LiquidityHint()
            self._liquidity_hints[channel_id] = hint
        return hint

    @with_lock
    def update_can_send(self, node_from: bytes, node_to: bytes, channel_id: ShortChannelID, amount: int):
        hint = self.get_hint(channel_id)
        hint.update_can_send(node_from < node_to, amount)

    @with_lock
    def update_cannot_send(self, node_from: bytes, node_to: bytes, channel_id: ShortChannelID, amount: int):
        hint = self.get_hint(channel_id)
        hint.update_cannot_send(node_from < node_to, amount)

    @with_lock
    def add_htlc(self, node_from: bytes, node_to: bytes, channel_id: ShortChannelID):
        hint = self.get_hint(channel_id)
        hint.add_htlc(node_from < node_to)

    @with_lock
    def remove_htlc(self, node_from: bytes, node_to: bytes, channel_id: ShortChannelID):
        hint = self.get_hint(channel_id)
        hint.remove_htlc(node_from < node_to)

    def penalty(self, node_from: bytes, node_to: bytes, channel_id: ShortChannelID, amount: int) -> float:
        """Gives a penalty when sending from node1 to node2 over channel_id with an
        amount in units of millisatoshi.

        The penalty depends on the can_send and cannot_send values that was
        possibly recorded in previous payment attempts.

        A channel that can send an amount is assigned a penalty of zero, a
        channel that cannot send an amount is assigned an infinite penalty.
        If the sending amount lies between can_send and cannot_send, there's
        uncertainty and we give a default penalty. The default penalty
        serves the function of giving a positive offset (the Dijkstra
        algorithm doesn't work with negative weights), from which we can discount
        from. There is a competition between low-fee channels and channels where
        we know with some certainty that they can support a payment. The penalty
        ultimately boils down to: how much more fees do we want to pay for
        certainty of payment success? This can be tuned via DEFAULT_PENALTY_BASE_MSAT
        and DEFAULT_PENALTY_PROPORTIONAL_MILLIONTH. A base _and_ relative penalty
        was chosen such that the penalty will be able to compete with the regular
        base and relative fees.
        """
        # we only evaluate hints here, so use dict get (to not create many hints with self.get_hint)
        hint = self._liquidity_hints.get(channel_id)
        if not hint:
            can_send, cannot_send, num_inflight_htlcs = None, None, 0
        else:
            can_send = hint.can_send(node_from < node_to)
            cannot_send = hint.cannot_send(node_from < node_to)
            num_inflight_htlcs = hint.num_inflight_htlcs(node_from < node_to)

        if cannot_send is not None and amount >= cannot_send:
            return inf
        if can_send is not None and amount <= can_send:
            return 0
        success_fee = fee_for_edge_msat(amount, DEFAULT_PENALTY_BASE_MSAT, DEFAULT_PENALTY_PROPORTIONAL_MILLIONTH)
        inflight_htlc_fee = num_inflight_htlcs * success_fee
        return success_fee + inflight_htlc_fee

    @with_lock
    def reset_liquidity_hints(self):
        for k, v in self._liquidity_hints.items():
            v.hint_timestamp = 0

    def __repr__(self):
        string = "liquidity hints:\n"
        if self._liquidity_hints:
            for k, v in self._liquidity_hints.items():
                string += f"{k}: {v}\n"
        return string


class LNPathFinder(Logger):

    def __init__(self, channel_db: ChannelDB):
        Logger.__init__(self)
        self.channel_db = channel_db
        self.liquidity_hints = LiquidityHintMgr()
        self._edge_blacklist = dict()  # type: Dict[ShortChannelID, int]  # scid -> expiration
        self._blacklist_lock = threading.Lock()

    def _is_edge_blacklisted(self, short_channel_id: ShortChannelID, *, now: int) -> bool:
        blacklist_expiration = self._edge_blacklist.get(short_channel_id)
        if blacklist_expiration is None:
            return False
        if blacklist_expiration < now:
            return False
            # TODO rm expired entries from cache (note: perf vs thread-safety)
        return True

    def add_edge_to_blacklist(
        self,
        short_channel_id: ShortChannelID,
        *,
        now: int = None,
        duration: int = 3600,  # seconds
    ) -> None:
        if now is None:
            now = int(time.time())
        with self._blacklist_lock:
            blacklist_expiration = self._edge_blacklist.get(short_channel_id, 0)
            self._edge_blacklist[short_channel_id] = max(blacklist_expiration, now + duration)

    def clear_blacklist(self):
        with self._blacklist_lock:
            self._edge_blacklist = dict()

    def update_liquidity_hints(
            self,
            route: LNPaymentRoute,
            amount_msat: int,
            failing_channel: ShortChannelID=None
    ):
        # go through the route and record successes until the failing channel is reached,
        # for the failing channel, add a cannot_send liquidity hint
        # note: actual routable amounts are slightly different than reported here
        # as fees would need to be added
        for r in route:
            if r.short_channel_id != failing_channel:
                self.logger.info(f"report {r.short_channel_id} to be able to forward {amount_msat} msat")
                self.liquidity_hints.update_can_send(r.start_node, r.end_node, r.short_channel_id, amount_msat)
            else:
                self.logger.info(f"report {r.short_channel_id} to be unable to forward {amount_msat} msat")
                self.liquidity_hints.update_cannot_send(r.start_node, r.end_node, r.short_channel_id, amount_msat)
                break
        else:
            assert failing_channel is None

    def update_inflight_htlcs(self, route: LNPaymentRoute, add_htlcs: bool):
        self.logger.info(f"{'Adding' if add_htlcs else 'Removing'} inflight htlcs to graph (liquidity hints).")
        for r in route:
            if add_htlcs:
                self.liquidity_hints.add_htlc(r.start_node, r.end_node, r.short_channel_id)
            else:
                self.liquidity_hints.remove_htlc(r.start_node, r.end_node, r.short_channel_id)

    def _edge_cost(
            self,
            *,
            short_channel_id: ShortChannelID,
            start_node: bytes,
            end_node: bytes,
            payment_amt_msat: int,
            ignore_costs=False,
            is_mine=False,
            my_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
            now: int,  # unix ts
    ) -> Tuple[float, int]:
        """Heuristic cost (distance metric) of going through a channel.
        Returns (heuristic_cost, fee_for_edge_msat).
        """
        if self._is_edge_blacklisted(short_channel_id, now=now):
            return float('inf'), 0
        if private_route_edges is None:
            private_route_edges = {}
        channel_info = self.channel_db.get_channel_info(
            short_channel_id, my_channels=my_channels, private_route_edges=private_route_edges)
        if channel_info is None:
            return float('inf'), 0
        channel_policy = self.channel_db.get_policy_for_node(
            short_channel_id, start_node, my_channels=my_channels, private_route_edges=private_route_edges, now=now)
        if channel_policy is None:
            return float('inf'), 0
        # channels that did not publish both policies often return temporary channel failure
        channel_policy_backwards = self.channel_db.get_policy_for_node(
            short_channel_id, end_node, my_channels=my_channels, private_route_edges=private_route_edges, now=now)
        if (channel_policy_backwards is None
                and not is_mine
                and short_channel_id not in private_route_edges):
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
        route_edge = private_route_edges.get(short_channel_id, None)
        if route_edge is None:
            node_info = self.channel_db.get_node_info_for_node_id(node_id=end_node)
            if node_info:
                # it's ok if we are missing the node_announcement (node_info) for this node,
                # but if we have it, we enforce that they support var_onion_optin
                node_features = LnFeatures(node_info.features)
                if not node_features.supports(LnFeatures.VAR_ONION_OPT):  # note: this is kind of slow. could be cached.
                    return float('inf'), 0
            route_edge = RouteEdge.from_channel_policy(
                channel_policy=channel_policy,
                short_channel_id=short_channel_id,
                start_node=start_node,
                end_node=end_node,
                node_info=node_info)
        # Cap cltv of any given edge at 2 weeks (the cost function would not work well for extreme cases)
        if route_edge.cltv_delta > 14 * 144:
            return float('inf'), 0
        # Distance metric notes:  # TODO constants are ad-hoc
        # ( somewhat based on https://github.com/lightningnetwork/lnd/pull/1358 )
        # - Edges have a base cost. (more edges -> less likely none will fail)
        # - The larger the payment amount, and the longer the CLTV,
        #   the more irritating it is if the HTLC gets stuck.
        # - Paying lower fees is better. :)
        if ignore_costs:
            return DEFAULT_PENALTY_BASE_MSAT, 0
        fee_msat = route_edge.fee_for_edge(payment_amt_msat)
        cltv_cost = route_edge.cltv_delta * payment_amt_msat * 15 / 1_000_000_000
        # the liquidty penalty takes care we favor edges that should be able to forward
        # the payment and penalize edges that cannot
        liquidity_penalty = self.liquidity_hints.penalty(start_node, end_node, short_channel_id, payment_amt_msat)
        overall_cost = fee_msat + cltv_cost + liquidity_penalty
        return overall_cost, fee_msat

    def get_shortest_path_hops(
            self,
            *,
            nodeA: bytes,
            nodeB: bytes,
            invoice_amount_msat: int,
            my_sending_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
    ) -> Dict[bytes, PathEdge]:
        # note: we don't lock self.channel_db, so while the path finding runs,
        #       the underlying graph could potentially change... (not good but maybe ~OK?)

        # run Dijkstra
        # The search is run in the REVERSE direction, from nodeB to nodeA,
        # to properly calculate compound routing fees.
        distance_from_start = defaultdict(lambda: float('inf'))
        distance_from_start[nodeB] = 0
        previous_hops = {}  # type: Dict[bytes, PathEdge]
        nodes_to_explore = queue.PriorityQueue()
        nodes_to_explore.put((0, invoice_amount_msat, nodeB))  # order of fields (in tuple) matters!
        now = int(time.time())

        # main loop of search
        while nodes_to_explore.qsize() > 0:
            dist_to_edge_endnode, amount_msat, edge_endnode = nodes_to_explore.get()
            if edge_endnode == nodeA and previous_hops:  # previous_hops check for circular paths
                self.logger.info("found a path")
                break
            if dist_to_edge_endnode != distance_from_start[edge_endnode]:
                # queue.PriorityQueue does not implement decrease_priority,
                # so instead of decreasing priorities, we add items again into the queue.
                # so there are duplicates in the queue, that we discard now:
                continue

            if nodeA == nodeB:  # we want circular paths
                if not previous_hops:  # in the first node exploration step, we only take receiving channels
                    channels_for_endnode = self.channel_db.get_channels_for_node(
                        edge_endnode, my_channels={}, private_route_edges=private_route_edges)
                else:  # in the next steps, we only take sending channels
                    channels_for_endnode = self.channel_db.get_channels_for_node(
                        edge_endnode, my_channels=my_sending_channels, private_route_edges={})
            else:
                channels_for_endnode = self.channel_db.get_channels_for_node(
                    edge_endnode, my_channels=my_sending_channels, private_route_edges=private_route_edges)

            for edge_channel_id in channels_for_endnode:
                assert isinstance(edge_channel_id, bytes)
                if self._is_edge_blacklisted(edge_channel_id, now=now):
                    continue
                channel_info = self.channel_db.get_channel_info(
                    edge_channel_id, my_channels=my_sending_channels, private_route_edges=private_route_edges)
                if channel_info is None:
                    continue
                edge_startnode = channel_info.node2_id if channel_info.node1_id == edge_endnode else channel_info.node1_id
                is_mine = edge_channel_id in my_sending_channels
                if is_mine:
                    if edge_startnode == nodeA:  # payment outgoing, on our channel
                        if not my_sending_channels[edge_channel_id].can_pay(amount_msat, check_frozen=True):
                            continue
                edge_cost, fee_for_edge_msat = self._edge_cost(
                    short_channel_id=edge_channel_id,
                    start_node=edge_startnode,
                    end_node=edge_endnode,
                    payment_amt_msat=amount_msat,
                    ignore_costs=(edge_startnode == nodeA),
                    is_mine=is_mine,
                    my_channels=my_sending_channels,
                    private_route_edges=private_route_edges,
                    now=now,
                )
                alt_dist_to_neighbour = distance_from_start[edge_endnode] + edge_cost
                if alt_dist_to_neighbour < distance_from_start[edge_startnode]:
                    distance_from_start[edge_startnode] = alt_dist_to_neighbour
                    previous_hops[edge_startnode] = PathEdge(
                        start_node=edge_startnode,
                        end_node=edge_endnode,
                        short_channel_id=ShortChannelID(edge_channel_id))
                    amount_to_forward_msat = amount_msat + fee_for_edge_msat
                    nodes_to_explore.put((alt_dist_to_neighbour, amount_to_forward_msat, edge_startnode))
            # for circular paths, we already explored the end node, but this
            # is also our start node, so set it to unexplored
            if edge_endnode == nodeB and nodeA == nodeB:
                distance_from_start[edge_endnode] = float('inf')
        return previous_hops

    @profiler
    def find_path_for_payment(
            self,
            *,
            nodeA: bytes,
            nodeB: bytes,
            invoice_amount_msat: int,
            my_sending_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
    ) -> Optional[LNPaymentPath]:
        """Return a path from nodeA to nodeB."""
        assert type(nodeA) is bytes
        assert type(nodeB) is bytes
        assert type(invoice_amount_msat) is int
        if my_sending_channels is None:
            my_sending_channels = {}

        previous_hops = self.get_shortest_path_hops(
            nodeA=nodeA,
            nodeB=nodeB,
            invoice_amount_msat=invoice_amount_msat,
            my_sending_channels=my_sending_channels,
            private_route_edges=private_route_edges)

        if nodeA not in previous_hops:
            return None  # no path found

        # backtrack from search_end (nodeA) to search_start (nodeB)
        # FIXME paths cannot be longer than 20 edges (onion packet)...
        edge_startnode = nodeA
        path = []
        while edge_startnode != nodeB or not path:  # second condition for circular paths
            edge = previous_hops[edge_startnode]
            path += [edge]
            edge_startnode = edge.node_id
        return path

    def create_route_from_path(
            self,
            path: Optional[LNPaymentPath],
            *,
            my_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
    ) -> LNPaymentRoute:
        if path is None:
            raise Exception('cannot create route from None path')
        if private_route_edges is None:
            private_route_edges = {}
        route = []
        prev_end_node = path[0].start_node
        for path_edge in path:
            short_channel_id = path_edge.short_channel_id
            _endnodes = self.channel_db.get_endnodes_for_chan(short_channel_id, my_channels=my_channels)
            if _endnodes and sorted(_endnodes) != sorted([path_edge.start_node, path_edge.end_node]):
                raise LNPathInconsistent("endpoints of edge inconsistent with short_channel_id")
            if path_edge.start_node != prev_end_node:
                raise LNPathInconsistent("edges do not chain together")
            route_edge = private_route_edges.get(short_channel_id, None)
            if route_edge is None:
                channel_policy = self.channel_db.get_policy_for_node(
                    short_channel_id=short_channel_id,
                    node_id=path_edge.start_node,
                    my_channels=my_channels)
                if channel_policy is None:
                    raise NoChannelPolicy(short_channel_id)
                node_info = self.channel_db.get_node_info_for_node_id(node_id=path_edge.end_node)
                route_edge = RouteEdge.from_channel_policy(
                    channel_policy=channel_policy,
                    short_channel_id=short_channel_id,
                    start_node=path_edge.start_node,
                    end_node=path_edge.end_node,
                    node_info=node_info)
            route.append(route_edge)
            prev_end_node = path_edge.end_node
        return route

    def find_route(
            self,
            *,
            nodeA: bytes,
            nodeB: bytes,
            invoice_amount_msat: int,
            path = None,
            my_sending_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
    ) -> Optional[LNPaymentRoute]:
        route = None
        if not path:
            path = self.find_path_for_payment(
                nodeA=nodeA,
                nodeB=nodeB,
                invoice_amount_msat=invoice_amount_msat,
                my_sending_channels=my_sending_channels,
                private_route_edges=private_route_edges)
        if path:
            route = self.create_route_from_path(
                path, my_channels=my_sending_channels, private_route_edges=private_route_edges)
        return route
