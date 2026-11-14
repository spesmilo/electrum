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
from typing import Sequence, Tuple, Optional, Dict, TYPE_CHECKING, Set, Callable, NamedTuple
import time
import threading
from threading import RLock
from math import inf
import dataclasses

from .util import profiler, with_lock, now, repr_dataclass
from .logging import Logger
from .lnutil import (NUM_MAX_EDGES_IN_PAYMENT_PATH, ShortChannelID, LnFeatures,
                     NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE, PaymentFeeBudget)
from .channel_db import ChannelDB, Policy, NodeInfo

if TYPE_CHECKING:
    from .lnchannel import Channel

# How much base fee we apply for unknown sending capability of a channel. As this is applied to every channel
# of a path (except our own), it is also the cost of an extra hop, and makes shorter paths preferred, as every
# channel is a chance to fail. It is 0.1% of the amount (like the attempt cost of LND), but not less than
# DEFAULT_PENALTY_BASE_MSAT and not more than MAX_PENALTY_BASE_MSAT: relative to the amount, it stays small
# compared to the fees and the fee budget of small payments.
DEFAULT_PENALTY_BASE_MSAT = 500
MAX_PENALTY_BASE_MSAT = 5000
PENALTY_BASE_MILLIONTHS = 1000
DEFAULT_PENALTY_PROPORTIONAL_MILLIONTH = 100  # how much relative fee we apply for unknown sending capability of a channel
HINT_DURATION = 3600  # how long (in seconds) a liquidity hint remains valid
# a parallel channel of a node pair that failed to forward an amount gets this many times the default penalty
PAIR_FAILURE_PENALTY_FACTOR = 10
# When this many different nodes failed to forward an amount to the same node, its inbound liquidity is
# probably drained (e.g. it receives a lot of payments), and its other incoming channels get this many
# times the default penalty. For a node that every path goes through, such as the destination, this
# does not change which path is preferred, as every path gets it once.
NODE_FAILURE_MIN_SENDERS = 3
NODE_FAILURE_PENALTY_FACTOR = 10
_NO_NODE_FAILURES = (0, {})  # read only
# When this many different nodes cannot forward to a node with unknown_next_peer, the node is likely
# offline: its channels stay in the graph until the disabled channel_updates of its peers reach us.
# For OFFLINE_NODE_DURATION, a path through it gets OFFLINE_NODE_PENALTY_MSAT, so that other paths are
# tried first. It is not excluded (nor penalized when looking for the lowest fees), as unknown_next_peer
# is also the error for a channel that was closed, while the node may be online.
OFFLINE_NODE_MIN_REPORTERS = 3
OFFLINE_NODE_DURATION = 600  # seconds
OFFLINE_NODE_PENALTY_MSAT = 10**12


def penalty_base_msat(amount_msat: int) -> int:
    return min(max(amount_msat * PENALTY_BASE_MILLIONTHS // 1_000_000, DEFAULT_PENALTY_BASE_MSAT), MAX_PENALTY_BASE_MSAT)


# fee_base_msat, fee_proportional_millionths, cltv_delta of a channel direction
EdgePolicy = Tuple[int, int, int]


def is_policy_not_more_expensive(policy: EdgePolicy, than: EdgePolicy, *, amount_msat: int) -> bool:
    """Whether a channel with policy would satisfy an htlc of amount_msat built for a channel with policy than:
    its fee at that amount and its cltv delta are not higher. A node may forward such an htlc over it."""
    fee_base_msat, fee_proportional_millionths, cltv_delta = policy
    than_fee_base_msat, than_fee_proportional_millionths, than_cltv_delta = than
    return (cltv_delta <= than_cltv_delta
            and fee_for_edge_msat(amount_msat, fee_base_msat, fee_proportional_millionths)
            <= fee_for_edge_msat(amount_msat, than_fee_base_msat, than_fee_proportional_millionths))


class NoChannelPolicy(Exception):
    def __init__(self, short_channel_id: bytes):
        short_channel_id = ShortChannelID.normalize(short_channel_id)
        super().__init__(f'cannot find channel policy for short_channel_id: {short_channel_id}')


class LNPathInconsistent(Exception): pass


def fee_for_edge_msat(forwarded_amount_msat: int, fee_base_msat: int, fee_proportional_millionths: int) -> int:
    return fee_base_msat \
           + (forwarded_amount_msat * fee_proportional_millionths // 1_000_000)


@dataclasses.dataclass(slots=True, kw_only=True, repr=False)
class PathEdge:
    start_node: bytes
    end_node: bytes
    short_channel_id: ShortChannelID

    def __repr__(self):
        return repr_dataclass(self, {
            'start_node': bytes.hex,
            'end_node': bytes.hex,
            'short_channel_id': str,
            'node_features': lambda val: str(int(val)),  # RouteEdge
        })

    @property
    def node_id(self) -> bytes:
        # legacy compat  # TODO rm
        return self.end_node

@dataclasses.dataclass(kw_only=True, repr=False)
class RouteEdge(PathEdge):
    fee_base_msat: int                # for start_node
    fee_proportional_millionths: int  # for start_node
    cltv_delta: int                   # for start_node
    node_features: int  # note: for end_node!

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

@dataclasses.dataclass(kw_only=True, repr=False)
class TrampolineEdge(RouteEdge):
    invoice_routing_info: Optional[Sequence[bytes]] = None
    invoice_features: Optional[int] = None
    # this is re-defined from parent just to specify a default value:
    short_channel_id: ShortChannelID = ShortChannelID(8)

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
    we_are_forwarding: bool,    # trampoline: sender must pay first edge
) -> bool:
    """Run some sanity checks on the whole route, before attempting to use it.
    called when we are paying; so e.g. lower cltv is better
    """
    if len(route) > NUM_MAX_EDGES_IN_PAYMENT_PATH:
        return False
    amt = amount_msat_for_dest
    cltv_cost_of_route = 0  # excluding cltv_delta_for_dest
    paying_edges = route[(0 if we_are_forwarding else 1):]
    for route_edge in reversed(paying_edges):
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


class LiquidAmount(NamedTuple):
    amount_msat: int
    timestamp: int

    @classmethod
    def from_amount(cls, amount_msat: int) -> 'LiquidAmount':
        return cls(amount_msat=amount_msat, timestamp=now())

    def get_valid_amount(self) -> Optional[int]:
        return None if self.is_invalid() else self.amount_msat

    def is_invalid(self) -> bool:
        return now() - self.timestamp > HINT_DURATION


class LiquidityHint:
    """Encodes the amounts that can and cannot be sent over the direction of a
    channel.

    A LiquidityHint is the value of a dict, which is keyed to node ids and the
    channel.
    """
    def __init__(self):
        # use "can_send_forward + can_send_backward < cannot_send_forward + cannot_send_backward" as a sanity check?
        self._can_send_forward = None  # type: Optional[LiquidAmount]
        self._cannot_send_forward = None  # type: Optional[LiquidAmount]
        self._can_send_backward = None  # type: Optional[LiquidAmount]
        self._cannot_send_backward = None  # type: Optional[LiquidAmount]
        self._inflight_htlcs_forward = 0
        self._inflight_htlcs_backward = 0

    @property
    def can_send_forward(self) -> Optional[int]:
        la = self._can_send_forward
        return la.get_valid_amount() if la else None

    @can_send_forward.setter
    def can_send_forward(self, amount_msat: int) -> None:
        # we don't want to record less significant info
        # (sendable amount is lower than known sendable amount):
        known = self.can_send_forward
        if known is not None and known > amount_msat:
            return
        self._can_send_forward = LiquidAmount.from_amount(amount_msat)
        # we make a sanity check that sendable amount is lower than not sendable amount
        if self._cannot_send_forward and self._can_send_forward.amount_msat > self._cannot_send_forward.amount_msat:
            self._cannot_send_forward = None

    @property
    def can_send_backward(self) -> Optional[int]:
        la = self._can_send_backward
        return la.get_valid_amount() if la else None

    @can_send_backward.setter
    def can_send_backward(self, amount_msat: int) -> None:
        known = self.can_send_backward
        if known is not None and known > amount_msat:
            return
        self._can_send_backward = LiquidAmount.from_amount(amount_msat)
        if self._cannot_send_backward and self._can_send_backward.amount_msat > self._cannot_send_backward.amount_msat:
            self._cannot_send_backward = None

    @property
    def cannot_send_forward(self) -> Optional[int]:
        la = self._cannot_send_forward
        return la.get_valid_amount() if la else None

    @cannot_send_forward.setter
    def cannot_send_forward(self, amount_msat: int) -> None:
        # we don't want to record less significant info
        # (not sendable amount is higher than known not sendable amount):
        known = self.cannot_send_forward
        if known is not None and known < amount_msat:
            return
        self._cannot_send_forward = LiquidAmount.from_amount(amount_msat)
        if self._can_send_forward and self._can_send_forward.amount_msat > self._cannot_send_forward.amount_msat:
            self._can_send_forward = None
        # if we can't send over the channel, we should be able to send in the
        # reverse direction
        self.can_send_backward = amount_msat

    @property
    def cannot_send_backward(self) -> Optional[int]:
        la = self._cannot_send_backward
        return la.get_valid_amount() if la else None

    @cannot_send_backward.setter
    def cannot_send_backward(self, amount_msat: int) -> None:
        known = self.cannot_send_backward
        if known is not None and known < amount_msat:
            return
        self._cannot_send_backward = LiquidAmount.from_amount(amount_msat)
        if self._can_send_backward and self._can_send_backward.amount_msat > self._cannot_send_backward.amount_msat:
            self._can_send_backward = None
        self.can_send_forward = amount_msat

    def can_send(self, is_forward_direction: bool) -> Optional[int]:
        # make info invalid after some time?
        if is_forward_direction:
            return self.can_send_forward
        else:
            return self.can_send_backward

    def cannot_send(self, is_forward_direction: bool) -> Optional[int]:
        # make info invalid after some time?
        if is_forward_direction:
            return self.cannot_send_forward
        else:
            return self.cannot_send_backward

    def update_can_send(self, is_forward_direction: bool, *, amount_msat: int) -> None:
        if is_forward_direction:
            self.can_send_forward = amount_msat
        else:
            self.can_send_backward = amount_msat

    def update_cannot_send(self, is_forward_direction: bool, *, amount_msat: int) -> None:
        if is_forward_direction:
            self.cannot_send_forward = amount_msat
        else:
            self.cannot_send_backward = amount_msat

    def num_inflight_htlcs(self, is_forward_direction: bool) -> int:
        if is_forward_direction:
            return self._inflight_htlcs_forward
        else:
            return self._inflight_htlcs_backward

    def add_htlc(self, is_forward_direction: bool) -> None:
        if is_forward_direction:
            self._inflight_htlcs_forward += 1
        else:
            self._inflight_htlcs_backward += 1

    def remove_htlc(self, is_forward_direction: bool) -> None:
        if is_forward_direction:
            self._inflight_htlcs_forward = max(0, self._inflight_htlcs_forward - 1)
        else:
            self._inflight_htlcs_backward = max(0, self._inflight_htlcs_backward - 1)

    def reset_amounts(self) -> None:
        self._cannot_send_backward = None
        self._cannot_send_forward = None
        self._can_send_forward = None
        self._can_send_backward = None

    def __repr__(self):
        return f"forward: can send: {self._can_send_forward}, cannot send: {self._cannot_send_forward}, htlcs: {self._inflight_htlcs_forward}\n" \
               f"backward: can send: {self._can_send_backward}, cannot send: {self._cannot_send_backward}, htlcs: {self._inflight_htlcs_backward}\n"


class LiquidityHintMgr:
    """Implements liquidity hints for channels in the graph.

    This class can be used to update liquidity information about channels in the
    graph. Implements a penalty function for edge weighting in the pathfinding
    algorithm that favors channels which can route payments and penalizes
    channels that cannot.
    """
    def __init__(self):
        self.lock = RLock()
        self._liquidity_hints: Dict[ShortChannelID, LiquidityHint] = {}
        # Nodes usually forward over any of their channels to the next node whose policy the htlc satisfies
        # (non-strict forwarding), so when a node cannot forward an amount to the next one, the parallel
        # channels between the two that are not more expensive than the failed one will likely not help either.
        # (node_from, node_to) -> (smallest amount that failed, policy of the channel that failed)
        self._pair_cannot_send: Dict[Tuple[bytes, bytes], Tuple[LiquidAmount, EdgePolicy]] = {}
        # node_to -> (newest timestamp, {node_from: smallest amount that failed}). The values are replaced,
        # not changed, as penalty() reads them without the lock.
        self._node_cannot_receive: Dict[bytes, Tuple[int, Dict[bytes, LiquidAmount]]] = {}

    @with_lock
    def get_hint(self, channel_id: ShortChannelID) -> LiquidityHint:
        hint = self._liquidity_hints.get(channel_id)
        if not hint:
            hint = LiquidityHint()
            self._liquidity_hints[channel_id] = hint
        return hint

    @with_lock
    def update_can_send(
            self, node_from: bytes, node_to: bytes, channel_id: ShortChannelID, *,
            amount_msat: int, policy: Optional[EdgePolicy] = None,
    ) -> None:
        hint = self.get_hint(channel_id)
        hint.update_can_send(node_from < node_to, amount_msat=amount_msat)
        # a forward over a channel that is not more expensive than the one that failed
        # shows that the node pair can send that amount (again)
        pair_cannot_send = self._pair_cannot_send.get((node_from, node_to))
        if pair_cannot_send is not None:
            failed_amount, failed_policy = pair_cannot_send
            if failed_amount.amount_msat <= amount_msat and (
                    policy is None or is_policy_not_more_expensive(policy, failed_policy, amount_msat=amount_msat)):
                del self._pair_cannot_send[(node_from, node_to)]
        # a forward to node_to shows it can receive that amount
        _, node_failures = self._node_cannot_receive.get(node_to, (0, {}))
        if node_failures:
            self._set_node_failures(
                node_to, {n: failed for n, failed in node_failures.items() if failed.amount_msat > amount_msat})

    @with_lock
    def update_cannot_send(
            self, node_from: bytes, node_to: bytes, channel_id: ShortChannelID, *,
            amount_msat: int, policy: Optional[EdgePolicy] = None,
    ) -> None:
        hint = self.get_hint(channel_id)
        hint.update_cannot_send(node_from < node_to, amount_msat=amount_msat)
        _, node_failures = self._node_cannot_receive.get(node_to, (0, {}))
        failed = node_failures.get(node_from)
        if failed is None or failed.is_invalid() or amount_msat <= failed.amount_msat:
            node_failures = {**node_failures, node_from: LiquidAmount.from_amount(amount_msat)}
        self._set_node_failures(node_to, node_failures)
        if policy is None:
            return
        pair_cannot_send = self._pair_cannot_send.get((node_from, node_to))
        if (pair_cannot_send is None or pair_cannot_send[0].is_invalid()
                or amount_msat <= pair_cannot_send[0].amount_msat):
            self._pair_cannot_send[(node_from, node_to)] = (LiquidAmount.from_amount(amount_msat), policy)

    def _set_node_failures(self, node_to: bytes, node_failures: Dict[bytes, LiquidAmount]) -> None:
        # expired failures are dropped here, so that penalty() does not go through them
        node_failures = {n: failed for n, failed in node_failures.items() if not failed.is_invalid()}
        if node_failures:
            newest_ts = max(failed.timestamp for failed in node_failures.values())
            self._node_cannot_receive[node_to] = (newest_ts, node_failures)
        else:
            self._node_cannot_receive.pop(node_to, None)

    @with_lock
    def add_htlc(self, node_from: bytes, node_to: bytes, channel_id: ShortChannelID):
        hint = self.get_hint(channel_id)
        hint.add_htlc(node_from < node_to)

    @with_lock
    def remove_htlc(self, node_from: bytes, node_to: bytes, channel_id: ShortChannelID):
        hint = self.get_hint(channel_id)
        hint.remove_htlc(node_from < node_to)

    def penalty(
        self,
        node_from: bytes,
        node_to: bytes,
        channel_id: ShortChannelID,
        *,
        amount_msat: int,
        policy: Optional[EdgePolicy] = None,
    ) -> float:
        """Gives a penalty when sending from node1 to node2 over channel_id with an
        amount in units of millisatoshi. policy is that of the channel in that direction.

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
        certainty of payment success? This can be tuned via penalty_base_msat
        and DEFAULT_PENALTY_PROPORTIONAL_MILLIONTH. A base _and_ relative penalty
        was chosen such that the penalty will be able to compete with the regular
        base and relative fees.
        """
        # note: self.lock is not taken for performance reasons, as we are called ~100k times per path-finding,
        #       and just acquiring+releasing locks that many times is expensive(?).
        #       (tho find_path_for_payment() could take LiquidityHintMgr.lock for the whole duration of the pathfinding)
        #       We only read the hints, so this should mostly be fine. Except a concurrent update could still happen...
        # note: we only evaluate hints here, so use dict get (to not create many hints with self.get_hint)
        hint = self._liquidity_hints.get(channel_id)
        if not hint:
            can_send, cannot_send, num_inflight_htlcs = None, None, 0
        else:
            can_send = hint.can_send(node_from < node_to)
            cannot_send = hint.cannot_send(node_from < node_to)
            num_inflight_htlcs = hint.num_inflight_htlcs(node_from < node_to)
        assert isinstance(num_inflight_htlcs, int), f"{num_inflight_htlcs=!r} should be an int"
        assert num_inflight_htlcs >= 0, f"{num_inflight_htlcs=!r} should be non-negative"

        # above known liquidity interval: inf
        if cannot_send is not None and amount_msat >= cannot_send:
            return inf
        # A parallel channel of a node pair that failed to forward the amount will likely fail too, but not
        # with nodes that forward only over the requested channel (e.g. Electrum itself): so it is not
        # excluded, but gets a large penalty, to be tried after other paths.
        pair_failed = False
        pair_cannot_send = self._pair_cannot_send.get((node_from, node_to))
        if pair_cannot_send is not None and policy is not None:
            failed_amount, failed_policy = pair_cannot_send
            pair_failed = (amount_msat >= failed_amount.amount_msat and not failed_amount.is_invalid()
                           and is_policy_not_more_expensive(policy, failed_policy, amount_msat=amount_msat))
        node_failed = False
        newest_ts, node_failures = self._node_cannot_receive.get(node_to, _NO_NODE_FAILURES)
        if len(node_failures) >= NODE_FAILURE_MIN_SENDERS and now() - newest_ts <= HINT_DURATION:
            num_failed = 0
            for failed in node_failures.values():
                if amount_msat >= failed.amount_msat and not failed.is_invalid():
                    num_failed += 1
                    if num_failed == NODE_FAILURE_MIN_SENDERS:
                        node_failed = True
                        break
        # below known liquidity interval: free
        if can_send is not None and amount_msat <= can_send and not pair_failed:
            return 0
        # inside known liquidity interval, or liquidity unknown
        likely_cannotsend_factor = 0
        if cannot_send is not None:
            fcan_send = can_send or 0
            # apply extra penalty if we are close to known interval upper bound
            if amount_msat >= fcan_send + 0.8 * (cannot_send - fcan_send):
                likely_cannotsend_factor = 2
        if pair_failed:
            likely_cannotsend_factor += PAIR_FAILURE_PENALTY_FACTOR
        if node_failed:
            likely_cannotsend_factor += NODE_FAILURE_PENALTY_FACTOR
        success_fee = fee_for_edge_msat(amount_msat, penalty_base_msat(amount_msat), DEFAULT_PENALTY_PROPORTIONAL_MILLIONTH)
        return success_fee * (1 + num_inflight_htlcs + likely_cannotsend_factor)

    @with_lock
    def reset_liquidity_hints(self):
        for k, v in self._liquidity_hints.items():
            v.reset_amounts()
            v._inflight_htlcs_forward = 0
            v._inflight_htlcs_backward = 0
        self._pair_cannot_send = {}
        self._node_cannot_receive = {}

    def __repr__(self):
        string = "liquidity hints:\n"
        if self._liquidity_hints:
            for k, v in self._liquidity_hints.items():
                string += f"{k}: {v}\n"
        for (node_from, node_to), (amount, policy) in self._pair_cannot_send.items():
            string += f"{node_from.hex()[:10]} -> {node_to.hex()[:10]}: cannot send {amount}, {policy}\n"
        for node_to, (_, failures) in self._node_cannot_receive.items():
            string += f"-> {node_to.hex()[:10]}: cannot receive from {len(failures)} nodes\n"
        return string


class LNPathFinder(Logger):

    def __init__(self, channel_db: ChannelDB):
        Logger.__init__(self)
        self.channel_db = channel_db
        self.liquidity_hints = LiquidityHintMgr()
        self._edge_blacklist = dict()  # type: Dict[ShortChannelID, int]  # scid -> expiration
        # node -> {node that could not forward to it: expiration}. The values are replaced,
        # not changed, as path finding reads them without the lock.
        self._unknown_next_peer_reports = dict()  # type: Dict[bytes, Dict[bytes, int]]
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
        now: int | None = None,
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
            self._unknown_next_peer_reports = dict()

    def report_unknown_next_peer(self, reporter: bytes, node: bytes, *, now: int | None = None) -> None:
        """reporter could not forward an htlc to node (unknown_next_peer): it is not connected to it,
        or it does not know the channel."""
        if now is None:
            now = int(time.time())
        with self._blacklist_lock:
            reports = {r: exp for r, exp in self._unknown_next_peer_reports.get(node, {}).items() if exp >= now}
            reports[reporter] = now + OFFLINE_NODE_DURATION
            # drop the nodes whose reports all expired
            self._unknown_next_peer_reports = {
                n: r for n, r in self._unknown_next_peer_reports.items() if max(r.values()) >= now}
            self._unknown_next_peer_reports[node] = reports
        if len(reports) >= OFFLINE_NODE_MIN_REPORTERS:
            self.logger.info(f"{node.hex()[:10]} is likely offline: {len(reports)} nodes could not forward to it")

    def report_nodes_online(self, nodes: Sequence[bytes]) -> None:
        """These nodes forwarded an htlc, or returned an error: they are online."""
        with self._blacklist_lock:
            reports = self._unknown_next_peer_reports
            if any(node in reports for node in nodes):
                self._unknown_next_peer_reports = {n: r for n, r in reports.items() if n not in nodes}

    def _is_node_likely_offline(self, node: bytes, *, now: int) -> bool:
        reports = self._unknown_next_peer_reports.get(node)
        if not reports:
            return False
        return sum(1 for exp in reports.values() if exp >= now) >= OFFLINE_NODE_MIN_REPORTERS

    def update_liquidity_hints(
            self,
            route: LNPaymentRoute,
            amount_msat: int,
            failing_channel: ShortChannelID = None,
    ):
        """We mark all channels along the route as able to forward the amount, until
        the failing channel is reached. For the failing channel, add a cannot_send liquidity hint.
        In the case of success (failing_channel=None), we still mark channels of the route
        as being able to send the same amount in the future, as we assume to not know the capacity.

        note: actual routable amounts are slightly different than reported here
              as fees would need to be added.
        """
        # the nodes that forwarded the htlc, or returned the error, are online
        online = []
        for r in route:
            online.append(r.start_node)
            if r.short_channel_id == failing_channel:
                break
        self.report_nodes_online(online)
        for r in route:
            if r.short_channel_id != failing_channel:
                self.logger.info(f"report {r.short_channel_id} to be able to forward {amount_msat} msat")
                self.liquidity_hints.update_can_send(
                    r.start_node, r.end_node, r.short_channel_id, amount_msat=amount_msat,
                    policy=(r.fee_base_msat, r.fee_proportional_millionths, r.cltv_delta))
            else:
                self.logger.info(f"report {r.short_channel_id} to be unable to forward {amount_msat} msat")
                self.liquidity_hints.update_cannot_send(
                    r.start_node, r.end_node, r.short_channel_id, amount_msat=amount_msat,
                    policy=(r.fee_base_msat, r.fee_proportional_millionths, r.cltv_delta))
                break
        else:
            assert failing_channel is None

    def update_num_inflight_htlcs(self, route: LNPaymentRoute, *, add_htlcs: bool) -> None:
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
            ignore_amount_constraints: bool = False,
            is_mine=False,
            my_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
            now: int,  # unix ts
            penalty_weight: float = 1,
    ) -> Tuple[float, int]:
        """Heuristic cost (distance metric) of going through a channel.
        Returns (heuristic_cost, fee_for_edge_msat).
        penalty_weight scales the costs other than the fee. With 0, the cost is the fee,
        and the other costs only break ties.
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
        if not ignore_amount_constraints:
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
        if ignore_costs or ignore_amount_constraints:
            return DEFAULT_PENALTY_BASE_MSAT, 0
        fee_msat = route_edge.fee_for_edge(payment_amt_msat)
        cltv_cost = route_edge.cltv_delta * payment_amt_msat * 15 / 1_000_000_000
        # the liquidty penalty takes care we favor edges that should be able to forward
        # the payment and penalize edges that cannot
        liquidity_penalty = self.liquidity_hints.penalty(
            start_node, end_node, short_channel_id, amount_msat=payment_amt_msat,
            policy=(route_edge.fee_base_msat, route_edge.fee_proportional_millionths, route_edge.cltv_delta))
        if penalty_weight != 1 and liquidity_penalty != inf:
            # (with a weight of 1e-9, the other costs of a path stay below 1 msat for amounts
            #  up to about 0.1 BTC; for larger ones, they may outweigh a difference in fees of a few msat)
            other_costs = (cltv_cost + liquidity_penalty) * (penalty_weight or 1e-9)
            return fee_msat + other_costs, fee_msat
        overall_cost = fee_msat + cltv_cost + liquidity_penalty
        return overall_cost, fee_msat

    def get_shortest_path_hops(
            self,
            *,
            nodeA: bytes, # nodeA is expected to be our node id if channels are passed in my_sending_channels
            nodeB: bytes,
            invoice_amount_msat: Optional[int],
            my_sending_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
            node_filter: Optional[Callable[[bytes, Optional[NodeInfo]], bool]] = None,
            max_fee_msat: Optional[int] = None,
            penalty_weight: float = 1,
            search_info: Optional[dict] = None,
    ) -> Dict[bytes, PathEdge]:
        # note: we don't lock self.channel_db, so while the path finding runs,
        #       the underlying graph could potentially change... (not good but maybe ~OK?)

        # if destination is filtered, there is no route
        if node_filter:
            node_info = self.channel_db.get_node_info_for_node_id(nodeB)
            if not node_filter(nodeB, node_info):
                return {}

        # run Dijkstra
        # The search is run in the REVERSE direction, from nodeB to nodeA,
        # to properly calculate compound routing fees.
        ignore_amount_constraints = invoice_amount_msat is None  # e.g. onion messages
        distance_from_start = defaultdict(lambda: float('inf'))
        distance_from_start[nodeB] = 0
        previous_hops = {}  # type: Dict[bytes, PathEdge]
        nodes_to_explore = queue.PriorityQueue()
        nodes_to_explore.put((0, invoice_amount_msat or 0, nodeB))  # order of fields (in tuple) matters!
        now = int(time.time())

        # main loop of search
        while nodes_to_explore.qsize() > 0:
            dist_to_edge_endnode, amount_msat, edge_endnode = nodes_to_explore.get()
            if edge_endnode == nodeA and previous_hops:  # previous_hops check for circular paths
                self.logger.info(f"found a path. cost={dist_to_edge_endnode:.0f} (fees and penalties, msat)")
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
                if node_filter:
                    node_info = self.channel_db.get_node_info_for_node_id(edge_startnode)
                    if not node_filter(edge_startnode, node_info):
                        continue
                is_mine = edge_channel_id in my_sending_channels
                if edge_startnode == nodeA and my_sending_channels:  # payment outgoing, on our channel
                    if edge_channel_id not in my_sending_channels:
                        continue
                    if not ignore_amount_constraints \
                            and not my_sending_channels[edge_channel_id].can_pay(amount_msat, check_frozen=True):
                        # note: in case of MPP, we might be constructing multiple routes for different HTLCs around the same time,
                        #       and only a tiny bit later will the HTLCs get added to the channels. If another HTLC has not been
                        #       added yet but we already selected to use the same channel for it, this "can_pay()" can return a false positive.
                        continue
                edge_cost, fee_for_edge_msat = self._edge_cost(
                    short_channel_id=edge_channel_id,
                    start_node=edge_startnode,
                    end_node=edge_endnode,
                    payment_amt_msat=amount_msat,
                    ignore_costs=(edge_startnode == nodeA),
                    ignore_amount_constraints=ignore_amount_constraints,
                    is_mine=is_mine,
                    my_channels=my_sending_channels,
                    private_route_edges=private_route_edges,
                    now=now,
                    penalty_weight=penalty_weight,
                )
                if penalty_weight and self._is_node_likely_offline(edge_startnode, now=now):
                    edge_cost += OFFLINE_NODE_PENALTY_MSAT
                amount_to_forward_msat = amount_msat + fee_for_edge_msat
                if max_fee_msat is not None and amount_to_forward_msat - invoice_amount_msat > max_fee_msat:
                    # The path would exceed the fee budget: don't extend it, so that the node can be
                    # reached over another path within the budget. Note: as we keep one path per node,
                    # we can still miss one within the budget, unless the cost is the fee (penalty_weight=0).
                    if search_info is not None:
                        search_info['budget_pruned'] = True
                    continue
                alt_dist_to_neighbour = distance_from_start[edge_endnode] + edge_cost
                if alt_dist_to_neighbour < distance_from_start[edge_startnode]:
                    distance_from_start[edge_startnode] = alt_dist_to_neighbour
                    previous_hops[edge_startnode] = PathEdge(
                        start_node=edge_startnode,
                        end_node=edge_endnode,
                        short_channel_id=ShortChannelID(edge_channel_id))
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
            invoice_amount_msat: Optional[int],
            my_sending_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
            node_filter: Optional[Callable[[bytes, Optional[NodeInfo]], bool]] = None,
            max_fee_msat: Optional[int] = None,
            penalty_weight: float = 1,
            search_info: Optional[dict] = None,
    ) -> Optional[LNPaymentPath]:
        """Return a path from nodeA to nodeB.
        With max_fee_msat, paths whose fees (not counting the first channel) exceed it are not considered,
        and search_info['budget_pruned'] is set if a path was left out because of it.
        penalty_weight scales the costs other than the fees (liquidity penalties, cltv). With 0, return the
        path with the lowest fees among channels that can be used, the other costs only breaking ties.
        """
        assert type(nodeA) is bytes
        assert type(nodeB) is bytes
        assert type(invoice_amount_msat) is int or invoice_amount_msat is None
        if my_sending_channels is None:
            my_sending_channels = {}

        previous_hops = self.get_shortest_path_hops(
            nodeA=nodeA,
            nodeB=nodeB,
            invoice_amount_msat=invoice_amount_msat,
            my_sending_channels=my_sending_channels,
            private_route_edges=private_route_edges,
            node_filter=node_filter,
            max_fee_msat=max_fee_msat,
            penalty_weight=penalty_weight,
            search_info=search_info)

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

    def find_path_for_onion_message(
            self,
            *,
            nodeA: bytes,
            nodeB: bytes,
            my_sending_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
    ) -> Optional[LNPaymentPath]:
        from .onion_message import is_onion_message_node
        def _node_filter(edge_startnode, node_info):
            if edge_startnode == nodeA:
                return True  # assume the sending node does support onion messages
            return is_onion_message_node(edge_startnode, node_info)
        return self.find_path_for_payment(
            nodeA=nodeA,
            nodeB=nodeB,
            my_sending_channels=my_sending_channels,
            private_route_edges=private_route_edges,
            node_filter=_node_filter,
            invoice_amount_msat=None,
        )

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
            path: Optional[Sequence[PathEdge]] = None,
            my_sending_channels: Dict[ShortChannelID, 'Channel'] = None,
            private_route_edges: Dict[ShortChannelID, RouteEdge] = None,
            max_fee_msat: Optional[int] = None,
            penalty_weight: float = 1,
            search_info: Optional[dict] = None,
    ) -> Optional[LNPaymentRoute]:
        route = None
        if not path:
            path = self.find_path_for_payment(
                nodeA=nodeA,
                nodeB=nodeB,
                invoice_amount_msat=invoice_amount_msat,
                my_sending_channels=my_sending_channels,
                private_route_edges=private_route_edges,
                max_fee_msat=max_fee_msat,
                penalty_weight=penalty_weight,
                search_info=search_info)
        if path:
            route = self.create_route_from_path(
                path, my_channels=my_sending_channels, private_route_edges=private_route_edges)
        return route
