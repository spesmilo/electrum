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
import os
import json
import threading
from collections import namedtuple, defaultdict
from typing import Sequence, List, Tuple, Optional, Dict, NamedTuple
import binascii
import base64
import asyncio

from . import constants
from .util import PrintError, bh2u, profiler, get_headers_dir, bfh, is_ip_address, list_enabled_bits
from .storage import JsonDB
from .lnchannelverifier import LNChannelVerifier, verify_sig_for_channel_update
from .crypto import Hash
from . import ecc
from .lnutil import LN_GLOBAL_FEATURES_KNOWN_SET, LNPeerAddr, NUM_MAX_EDGES_IN_PAYMENT_PATH


class UnknownEvenFeatureBits(Exception): pass


class NotFoundChanAnnouncementForUpdate(Exception): pass


class ChannelInfo(PrintError):

    def __init__(self, channel_announcement_payload):
        self.features_len = channel_announcement_payload['len']
        self.features = channel_announcement_payload['features']
        enabled_features = list_enabled_bits(int.from_bytes(self.features, "big"))
        for fbit in enabled_features:
            if (1 << fbit) not in LN_GLOBAL_FEATURES_KNOWN_SET and fbit % 2 == 0:
                raise UnknownEvenFeatureBits()

        self.channel_id = channel_announcement_payload['short_channel_id']
        self.node_id_1 = channel_announcement_payload['node_id_1']
        self.node_id_2 = channel_announcement_payload['node_id_2']
        assert type(self.node_id_1) is bytes
        assert type(self.node_id_2) is bytes
        assert list(sorted([self.node_id_1, self.node_id_2])) == [self.node_id_1, self.node_id_2]

        self.bitcoin_key_1 = channel_announcement_payload['bitcoin_key_1']
        self.bitcoin_key_2 = channel_announcement_payload['bitcoin_key_2']

        # this field does not get persisted
        self.msg_payload = channel_announcement_payload

        self.capacity_sat = None
        self.policy_node1 = None
        self.policy_node2 = None

    def to_json(self) -> dict:
        d = {}
        d['short_channel_id'] = bh2u(self.channel_id)
        d['node_id_1'] = bh2u(self.node_id_1)
        d['node_id_2'] = bh2u(self.node_id_2)
        d['len'] = bh2u(self.features_len)
        d['features'] = bh2u(self.features)
        d['bitcoin_key_1'] = bh2u(self.bitcoin_key_1)
        d['bitcoin_key_2'] = bh2u(self.bitcoin_key_2)
        d['policy_node1'] = self.policy_node1
        d['policy_node2'] = self.policy_node2
        d['capacity_sat'] = self.capacity_sat
        return d

    @classmethod
    def from_json(cls, d: dict):
        d2 = {}
        d2['short_channel_id'] = bfh(d['short_channel_id'])
        d2['node_id_1'] = bfh(d['node_id_1'])
        d2['node_id_2'] = bfh(d['node_id_2'])
        d2['len'] = bfh(d['len'])
        d2['features'] = bfh(d['features'])
        d2['bitcoin_key_1'] = bfh(d['bitcoin_key_1'])
        d2['bitcoin_key_2'] = bfh(d['bitcoin_key_2'])
        ci = ChannelInfo(d2)
        ci.capacity_sat = d['capacity_sat']
        ci.policy_node1 = ChannelInfoDirectedPolicy.from_json(d['policy_node1'])
        ci.policy_node2 = ChannelInfoDirectedPolicy.from_json(d['policy_node2'])
        return ci

    def set_capacity(self, capacity):
        self.capacity_sat = capacity

    def on_channel_update(self, msg_payload, trusted=False):
        assert self.channel_id == msg_payload['short_channel_id']
        flags = int.from_bytes(msg_payload['channel_flags'], 'big')
        direction = flags & ChannelInfoDirectedPolicy.FLAG_DIRECTION
        new_policy = ChannelInfoDirectedPolicy(msg_payload)
        if direction == 0:
            old_policy = self.policy_node1
            node_id = self.node_id_1
        else:
            old_policy = self.policy_node2
            node_id = self.node_id_2
        if old_policy and old_policy.timestamp >= new_policy.timestamp:
            return  # ignore
        if not trusted and not verify_sig_for_channel_update(msg_payload, node_id):
            return  # ignore
        # save new policy
        if direction == 0:
            self.policy_node1 = new_policy
        else:
            self.policy_node2 = new_policy

    def get_policy_for_node(self, node_id: bytes) -> Optional['ChannelInfoDirectedPolicy']:
        if node_id == self.node_id_1:
            return self.policy_node1
        elif node_id == self.node_id_2:
            return self.policy_node2
        else:
            raise Exception('node_id {} not in channel {}'.format(node_id, self.channel_id))


class ChannelInfoDirectedPolicy:

    FLAG_DIRECTION = 1 << 0
    FLAG_DISABLE   = 1 << 1

    def __init__(self, channel_update_payload):
        cltv_expiry_delta           = channel_update_payload['cltv_expiry_delta']
        htlc_minimum_msat           = channel_update_payload['htlc_minimum_msat']
        fee_base_msat               = channel_update_payload['fee_base_msat']
        fee_proportional_millionths = channel_update_payload['fee_proportional_millionths']
        channel_flags               = channel_update_payload['channel_flags']
        timestamp                   = channel_update_payload['timestamp']
        htlc_maximum_msat           = channel_update_payload.get('htlc_maximum_msat')  # optional

        self.cltv_expiry_delta           = int.from_bytes(cltv_expiry_delta, "big")
        self.htlc_minimum_msat           = int.from_bytes(htlc_minimum_msat, "big")
        self.htlc_maximum_msat           = int.from_bytes(htlc_maximum_msat, "big") if htlc_maximum_msat else None
        self.fee_base_msat               = int.from_bytes(fee_base_msat, "big")
        self.fee_proportional_millionths = int.from_bytes(fee_proportional_millionths, "big")
        self.channel_flags               = int.from_bytes(channel_flags, "big")
        self.timestamp                   = int.from_bytes(timestamp, "big")

        self.disabled = self.channel_flags & self.FLAG_DISABLE

    def to_json(self) -> dict:
        d = {}
        d['cltv_expiry_delta'] = self.cltv_expiry_delta
        d['htlc_minimum_msat'] = self.htlc_minimum_msat
        d['fee_base_msat'] = self.fee_base_msat
        d['fee_proportional_millionths'] = self.fee_proportional_millionths
        d['channel_flags'] = self.channel_flags
        d['timestamp'] = self.timestamp
        if self.htlc_maximum_msat:
            d['htlc_maximum_msat'] = self.htlc_maximum_msat
        return d

    @classmethod
    def from_json(cls, d: dict):
        if d is None: return None
        d2 = {}
        d2['cltv_expiry_delta'] = d['cltv_expiry_delta'].to_bytes(2, "big")
        d2['htlc_minimum_msat'] = d['htlc_minimum_msat'].to_bytes(8, "big")
        d2['htlc_maximum_msat'] = d['htlc_maximum_msat'].to_bytes(8, "big") if d.get('htlc_maximum_msat') else None
        d2['fee_base_msat'] = d['fee_base_msat'].to_bytes(4, "big")
        d2['fee_proportional_millionths'] = d['fee_proportional_millionths'].to_bytes(4, "big")
        d2['channel_flags'] = d['channel_flags'].to_bytes(1, "big")
        d2['timestamp'] = d['timestamp'].to_bytes(4, "big")
        return ChannelInfoDirectedPolicy(d2)


class NodeInfo(PrintError):

    def __init__(self, node_announcement_payload, addresses_already_parsed=False):
        self.pubkey = node_announcement_payload['node_id']
        self.features_len = node_announcement_payload['flen']
        self.features = node_announcement_payload['features']
        enabled_features = list_enabled_bits(int.from_bytes(self.features, "big"))
        for fbit in enabled_features:
            if (1 << fbit) not in LN_GLOBAL_FEATURES_KNOWN_SET and fbit % 2 == 0:
                raise UnknownEvenFeatureBits()
        if not addresses_already_parsed:
            self.addresses = self.parse_addresses_field(node_announcement_payload['addresses'])
        else:
            self.addresses = node_announcement_payload['addresses']
        self.alias = node_announcement_payload['alias'].rstrip(b'\x00')
        self.timestamp = int.from_bytes(node_announcement_payload['timestamp'], "big")

    @classmethod
    def parse_addresses_field(cls, addresses_field):
        buf = addresses_field
        def read(n):
            nonlocal buf
            data, buf = buf[0:n], buf[n:]
            return data
        addresses = []
        while buf:
            atype = ord(read(1))
            if atype == 0:
                pass
            elif atype == 1:  # IPv4
                ipv4_addr = '.'.join(map(lambda x: '%d' % x, read(4)))
                port = int.from_bytes(read(2), 'big')
                if is_ip_address(ipv4_addr) and port != 0:
                    addresses.append((ipv4_addr, port))
            elif atype == 2:  # IPv6
                ipv6_addr = b':'.join([binascii.hexlify(read(2)) for i in range(8)])
                ipv6_addr = ipv6_addr.decode('ascii')
                port = int.from_bytes(read(2), 'big')
                if is_ip_address(ipv6_addr) and port != 0:
                    addresses.append((ipv6_addr, port))
            elif atype == 3:  # onion v2
                host = base64.b32encode(read(10)) + b'.onion'
                host = host.decode('ascii').lower()
                port = int.from_bytes(read(2), 'big')
                addresses.append((host, port))
            elif atype == 4:  # onion v3
                host = base64.b32encode(read(35)) + b'.onion'
                host = host.decode('ascii').lower()
                port = int.from_bytes(read(2), 'big')
                addresses.append((host, port))
            else:
                # unknown address type
                # we don't know how long it is -> have to escape
                # if there are other addresses we could have parsed later, they are lost.
                break
        return addresses

    def to_json(self) -> dict:
        d = {}
        d['node_id'] = bh2u(self.pubkey)
        d['flen'] = bh2u(self.features_len)
        d['features'] = bh2u(self.features)
        d['addresses'] = self.addresses
        d['alias'] = bh2u(self.alias)
        d['timestamp'] = self.timestamp
        return d

    @classmethod
    def from_json(cls, d: dict):
        if d is None: return None
        d2 = {}
        d2['node_id'] = bfh(d['node_id'])
        d2['flen'] = bfh(d['flen'])
        d2['features'] = bfh(d['features'])
        d2['addresses'] = d['addresses']
        d2['alias'] = bfh(d['alias'])
        d2['timestamp'] = d['timestamp'].to_bytes(4, "big")
        return NodeInfo(d2, addresses_already_parsed=True)


class ChannelDB(JsonDB):

    NUM_MAX_RECENT_PEERS = 20

    def __init__(self, network):
        self.network = network

        path = os.path.join(get_headers_dir(network.config), 'channel_db')
        JsonDB.__init__(self, path)

        self.lock = threading.RLock()
        self._id_to_channel_info = {}  # type: Dict[bytes, ChannelInfo]
        self._channels_for_node = defaultdict(set)  # node -> set(short_channel_id)
        self.nodes = {}  # node_id -> NodeInfo
        self._recent_peers = []
        self._last_good_address = {}  # node_id -> LNPeerAddr

        # (intentionally not persisted)
        self._channel_updates_for_private_channels = {}  # type: Dict[Tuple[bytes, bytes], ChannelInfoDirectedPolicy]

        self.ca_verifier = LNChannelVerifier(network, self)

        self.load_data()

    def load_data(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding='utf-8') as f:
                raw = f.read()
                self.data = json.loads(raw)
        # channels
        channel_infos = self.get('channel_infos', {})
        for short_channel_id, channel_info_d in channel_infos.items():
            channel_info = ChannelInfo.from_json(channel_info_d)
            short_channel_id = bfh(short_channel_id)
            self.add_verified_channel_info(short_channel_id, channel_info)
        # nodes
        node_infos = self.get('node_infos', {})
        for node_id, node_info_d in node_infos.items():
            node_info = NodeInfo.from_json(node_info_d)
            node_id = bfh(node_id)
            self.nodes[node_id] = node_info
        # recent peers
        recent_peers = self.get('recent_peers', {})
        for host, port, pubkey in recent_peers:
            peer = LNPeerAddr(str(host), int(port), bfh(pubkey))
            self._recent_peers.append(peer)
        # last good address
        last_good_addr = self.get('last_good_address', {})
        for node_id, host_and_port in last_good_addr.items():
            host, port = host_and_port
            self._last_good_address[bfh(node_id)] = LNPeerAddr(str(host), int(port), bfh(node_id))

    def save_data(self):
        with self.lock:
            # channels
            channel_infos = {}
            for short_channel_id, channel_info in self._id_to_channel_info.items():
                channel_infos[bh2u(short_channel_id)] = channel_info
            self.put('channel_infos', channel_infos)
            # nodes
            node_infos = {}
            for node_id, node_info in self.nodes.items():
                node_infos[bh2u(node_id)] = node_info
            self.put('node_infos', node_infos)
            # recent peers
            recent_peers = []
            for peer in self._recent_peers:
                recent_peers.append(
                    [str(peer.host), int(peer.port), bh2u(peer.pubkey)])
            self.put('recent_peers', recent_peers)
            # last good address
            last_good_addr = {}
            for node_id, peer in self._last_good_address.items():
                last_good_addr[bh2u(node_id)] = [str(peer.host), int(peer.port)]
            self.put('last_good_address', last_good_addr)
        self.write()

    def __len__(self):
        # number of channels
        return len(self._id_to_channel_info)

    def get_channel_info(self, channel_id: bytes) -> Optional[ChannelInfo]:
        return self._id_to_channel_info.get(channel_id, None)

    def get_channels_for_node(self, node_id):
        """Returns the set of channels that have node_id as one of the endpoints."""
        return self._channels_for_node[node_id]

    def add_verified_channel_info(self, short_channel_id: bytes, channel_info: ChannelInfo):
        with self.lock:
            self._id_to_channel_info[short_channel_id] = channel_info
            self._channels_for_node[channel_info.node_id_1].add(short_channel_id)
            self._channels_for_node[channel_info.node_id_2].add(short_channel_id)
        self.network.trigger_callback('ln_status')

    def get_recent_peers(self):
        with self.lock:
            return list(self._recent_peers)

    def add_recent_peer(self, peer: LNPeerAddr):
        with self.lock:
            # list is ordered
            if peer in self._recent_peers:
                self._recent_peers.remove(peer)
            self._recent_peers.insert(0, peer)
            self._recent_peers = self._recent_peers[:self.NUM_MAX_RECENT_PEERS]
            self._last_good_address[peer.pubkey] = peer

    def get_last_good_address(self, node_id: bytes) -> Optional[LNPeerAddr]:
        return self._last_good_address.get(node_id, None)

    def on_channel_announcement(self, msg_payload, trusted=False):
        short_channel_id = msg_payload['short_channel_id']
        if short_channel_id in self._id_to_channel_info:
            return
        if constants.net.rev_genesis_bytes() != msg_payload['chain_hash']:
            #self.print_error("ChanAnn has unexpected chain_hash {}".format(bh2u(msg_payload['chain_hash'])))
            return
        try:
            channel_info = ChannelInfo(msg_payload)
        except UnknownEvenFeatureBits:
            return
        if trusted:
            self.add_verified_channel_info(short_channel_id, channel_info)
        else:
            self.ca_verifier.add_new_channel_info(channel_info)

    def on_channel_update(self, msg_payload, trusted=False):
        short_channel_id = msg_payload['short_channel_id']
        if constants.net.rev_genesis_bytes() != msg_payload['chain_hash']:
            return
        # try finding channel in pending db
        channel_info = self.ca_verifier.get_pending_channel_info(short_channel_id)
        if channel_info is None:
            # try finding channel in verified db
            channel_info = self._id_to_channel_info.get(short_channel_id, None)
        if channel_info is None:
            self.print_error("could not find", short_channel_id)
            raise NotFoundChanAnnouncementForUpdate()
        channel_info.on_channel_update(msg_payload, trusted=trusted)

    def on_node_announcement(self, msg_payload):
        pubkey = msg_payload['node_id']
        signature = msg_payload['signature']
        h = Hash(msg_payload['raw'][66:])
        if not ecc.verify_signature(pubkey, signature, h):
            return
        old_node_info = self.nodes.get(pubkey, None)
        try:
            new_node_info = NodeInfo(msg_payload)
        except UnknownEvenFeatureBits:
            return
        # TODO if this message is for a new node, and if we have no associated
        # channels for this node, we should ignore the message and return here,
        # to mitigate DOS. but race condition: the channels we have for this
        # node, might be under verification in self.ca_verifier, what then?
        if old_node_info and old_node_info.timestamp >= new_node_info.timestamp:
            return  # ignore
        self.nodes[pubkey] = new_node_info

    def get_routing_policy_for_channel(self, start_node_id: bytes,
                                       short_channel_id: bytes) -> Optional[ChannelInfoDirectedPolicy]:
        if not start_node_id or not short_channel_id: return None
        channel_info = self.get_channel_info(short_channel_id)
        if channel_info is not None:
            return channel_info.get_policy_for_node(start_node_id)
        return self._channel_updates_for_private_channels.get((start_node_id, short_channel_id))

    def add_channel_update_for_private_channel(self, msg_payload: dict, start_node_id: bytes):
        if not verify_sig_for_channel_update(msg_payload, start_node_id):
            return  # ignore
        short_channel_id = msg_payload['short_channel_id']
        policy = ChannelInfoDirectedPolicy(msg_payload)
        self._channel_updates_for_private_channels[(start_node_id, short_channel_id)] = policy

    def remove_channel(self, short_channel_id):
        try:
            channel_info = self._id_to_channel_info[short_channel_id]
        except KeyError:
            self.print_error('cannot find channel {}'.format(short_channel_id))
            return
        self._id_to_channel_info.pop(short_channel_id, None)
        for node in (channel_info.node_id_1, channel_info.node_id_2):
            try:
                self._channels_for_node[node].remove(short_channel_id)
            except KeyError:
                pass

    def print_graph(self, full_ids=False):
        # used for debugging.
        # FIXME there is a race here - iterables could change size from another thread
        def other_node_id(node_id, channel_id):
            channel_info = self._id_to_channel_info[channel_id]
            if node_id == channel_info.node_id_1:
                other = channel_info.node_id_2
            else:
                other = channel_info.node_id_1
            return other if full_ids else other[-4:]

        self.print_msg('node: {(channel, other_node), ...}')
        for node_id, short_channel_ids in list(self._channels_for_node.items()):
            short_channel_ids = {(bh2u(cid), bh2u(other_node_id(node_id, cid)))
                                 for cid in short_channel_ids}
            node_id = bh2u(node_id) if full_ids else bh2u(node_id[-4:])
            self.print_msg('{}: {}'.format(node_id, short_channel_ids))

        self.print_msg('channel: node1, node2, direction')
        for short_channel_id, channel_info in list(self._id_to_channel_info.items()):
            node1 = channel_info.node_id_1
            node2 = channel_info.node_id_2
            direction1 = channel_info.get_policy_for_node(node1) is not None
            direction2 = channel_info.get_policy_for_node(node2) is not None
            if direction1 and direction2:
                direction = 'both'
            elif direction1:
                direction = 'forward'
            elif direction2:
                direction = 'backward'
            else:
                direction = 'none'
            self.print_msg('{}: {}, {}, {}'
                           .format(bh2u(short_channel_id),
                                   bh2u(node1) if full_ids else bh2u(node1[-4:]),
                                   bh2u(node2) if full_ids else bh2u(node2[-4:]),
                                   direction))


class RouteEdge(NamedTuple("RouteEdge", [('node_id', bytes),
                                         ('short_channel_id', bytes),
                                         ('fee_base_msat', int),
                                         ('fee_proportional_millionths', int),
                                         ('cltv_expiry_delta', int)])):
    """if you travel through short_channel_id, you will reach node_id"""

    def fee_for_edge(self, amount_msat: int) -> int:
        return self.fee_base_msat \
               + (amount_msat * self.fee_proportional_millionths // 1_000_000)

    @classmethod
    def from_channel_policy(cls, channel_policy: ChannelInfoDirectedPolicy,
                            short_channel_id: bytes, end_node: bytes) -> 'RouteEdge':
        return RouteEdge(end_node,
                         short_channel_id,
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


def is_route_sane_to_use(route: List[RouteEdge], invoice_amount_msat: int, min_final_cltv_expiry: int) -> bool:
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


class LNPathFinder(PrintError):

    def __init__(self, channel_db: ChannelDB):
        self.channel_db = channel_db
        self.blacklist = set()

    def _edge_cost(self, short_channel_id: bytes, start_node: bytes, end_node: bytes,
                   payment_amt_msat: int, ignore_costs=False) -> Tuple[float, int]:
        """Heuristic cost of going through a channel.
        Returns (heuristic_cost, fee_for_edge_msat).
        """
        channel_info = self.channel_db.get_channel_info(short_channel_id)  # type: ChannelInfo
        if channel_info is None:
            return float('inf'), 0

        channel_policy = channel_info.get_policy_for_node(start_node)
        if channel_policy is None: return float('inf'), 0
        if channel_policy.disabled: return float('inf'), 0
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
                              my_channels: List=None) -> Sequence[Tuple[bytes, bytes]]:
        """Return a path from nodeA to nodeB.

        Returns a list of (node_id, short_channel_id) representing a path.
        To get from node ret[n][0] to ret[n+1][0], use channel ret[n+1][1];
        i.e. an element reads as, "to get to node_id, travel through short_channel_id"
        """
        assert type(invoice_amount_msat) is int
        if my_channels is None: my_channels = []
        unable_channels = set(map(lambda x: x.short_channel_id,
                                  filter(lambda x: not x.can_pay(invoice_amount_msat), my_channels)))

        # FIXME paths cannot be longer than 21 edges (onion packet)...

        # run Dijkstra
        # The search is run in the REVERSE direction, from nodeB to nodeA,
        # to properly calculate compound routing fees.
        distance_from_start = defaultdict(lambda: float('inf'))
        distance_from_start[nodeB] = 0
        prev_node = {}
        nodes_to_explore = queue.PriorityQueue()
        nodes_to_explore.put((0, invoice_amount_msat, nodeB))  # order of fields (in tuple) matters!

        while nodes_to_explore.qsize() > 0:
            dist_to_cur_node, amount_msat, cur_node = nodes_to_explore.get()
            if cur_node == nodeA:
                break
            if dist_to_cur_node != distance_from_start[cur_node]:
                # queue.PriorityQueue does not implement decrease_priority,
                # so instead of decreasing priorities, we add items again into the queue.
                # so there are duplicates in the queue, that we discard now:
                continue
            for edge_channel_id in self.channel_db.get_channels_for_node(cur_node):
                if edge_channel_id in self.blacklist or edge_channel_id in unable_channels:
                    continue
                channel_info = self.channel_db.get_channel_info(edge_channel_id)
                neighbour = channel_info.node_id_2 if channel_info.node_id_1 == cur_node else channel_info.node_id_1
                ignore_costs = neighbour == nodeA  # no fees when using our own channel
                edge_cost, fee_for_edge_msat = self._edge_cost(edge_channel_id,
                                                               start_node=neighbour,
                                                               end_node=cur_node,
                                                               payment_amt_msat=amount_msat,
                                                               ignore_costs=ignore_costs)
                alt_dist_to_neighbour = distance_from_start[cur_node] + edge_cost
                if alt_dist_to_neighbour < distance_from_start[neighbour]:
                    distance_from_start[neighbour] = alt_dist_to_neighbour
                    prev_node[neighbour] = cur_node, edge_channel_id
                    amount_to_forward_msat = amount_msat + fee_for_edge_msat
                    nodes_to_explore.put((alt_dist_to_neighbour, amount_to_forward_msat, neighbour))
        else:
            return None  # no path found

        # backtrack from search_end (nodeA) to search_start (nodeB)
        cur_node = nodeA
        path = []
        while cur_node != nodeB:
            prev_node_id, edge_taken = prev_node[cur_node]
            path += [(prev_node_id, edge_taken)]
            cur_node = prev_node_id
        return path

    def create_route_from_path(self, path, from_node_id: bytes) -> List[RouteEdge]:
        assert type(from_node_id) is bytes
        if path is None:
            raise Exception('cannot create route from None path')
        route = []
        prev_node_id = from_node_id
        for node_id, short_channel_id in path:
            channel_policy = self.channel_db.get_routing_policy_for_channel(prev_node_id, short_channel_id)
            if channel_policy is None:
                raise Exception(f'cannot find channel policy for short_channel_id: {bh2u(short_channel_id)}')
            route.append(RouteEdge.from_channel_policy(channel_policy, short_channel_id, node_id))
            prev_node_id = node_id
        return route
