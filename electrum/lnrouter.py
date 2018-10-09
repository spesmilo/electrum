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
from .lnutil import LN_GLOBAL_FEATURE_BITS, LNPeerAddr


class UnknownEvenFeatureBits(Exception): pass


class NotFoundChanAnnouncementForUpdate(Exception): pass


class ChannelInfo(PrintError):

    def __init__(self, channel_announcement_payload):
        self.features_len = channel_announcement_payload['len']
        self.features = channel_announcement_payload['features']
        enabled_features = list_enabled_bits(int.from_bytes(self.features, "big"))
        for fbit in enabled_features:
            if fbit not in LN_GLOBAL_FEATURE_BITS and fbit % 2 == 0:
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
        flags = int.from_bytes(msg_payload['flags'], 'big')
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

    def get_policy_for_node(self, node_id: bytes) -> 'ChannelInfoDirectedPolicy':
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
        flags                       = channel_update_payload['flags']
        timestamp                   = channel_update_payload['timestamp']

        self.cltv_expiry_delta           = int.from_bytes(cltv_expiry_delta, "big")
        self.htlc_minimum_msat           = int.from_bytes(htlc_minimum_msat, "big")
        self.fee_base_msat               = int.from_bytes(fee_base_msat, "big")
        self.fee_proportional_millionths = int.from_bytes(fee_proportional_millionths, "big")
        self.flags                       = int.from_bytes(flags, "big")
        self.timestamp                   = int.from_bytes(timestamp, "big")

        self.disabled = self.flags & self.FLAG_DISABLE

    def to_json(self) -> dict:
        d = {}
        d['cltv_expiry_delta'] = self.cltv_expiry_delta
        d['htlc_minimum_msat'] = self.htlc_minimum_msat
        d['fee_base_msat'] = self.fee_base_msat
        d['fee_proportional_millionths'] = self.fee_proportional_millionths
        d['flags'] = self.flags
        d['timestamp'] = self.timestamp
        return d

    @classmethod
    def from_json(cls, d: dict):
        if d is None: return None
        d2 = {}
        d2['cltv_expiry_delta'] = d['cltv_expiry_delta'].to_bytes(2, "big")
        d2['htlc_minimum_msat'] = d['htlc_minimum_msat'].to_bytes(8, "big")
        d2['fee_base_msat'] = d['fee_base_msat'].to_bytes(4, "big")
        d2['fee_proportional_millionths'] = d['fee_proportional_millionths'].to_bytes(4, "big")
        d2['flags'] = d['flags'].to_bytes(2, "big")
        d2['timestamp'] = d['timestamp'].to_bytes(4, "big")
        return ChannelInfoDirectedPolicy(d2)


class NodeInfo(PrintError):

    def __init__(self, node_announcement_payload, addresses_already_parsed=False):
        self.pubkey = node_announcement_payload['node_id']
        self.features_len = node_announcement_payload['flen']
        self.features = node_announcement_payload['features']
        enabled_features = list_enabled_bits(int.from_bytes(self.features, "big"))
        for fbit in enabled_features:
            if fbit not in LN_GLOBAL_FEATURE_BITS and fbit % 2 == 0:
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

        self.ca_verifier = LNChannelVerifier(network, self)
        # FIXME if the channel verifier raises, it kills network.main_taskgroup
        asyncio.run_coroutine_threadsafe(self.network.add_job(self.ca_verifier.main()), network.asyncio_loop)

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
    pass


class LNPathFinder(PrintError):

    def __init__(self, channel_db):
        self.channel_db = channel_db
        self.blacklist = set()

    def _edge_cost(self, short_channel_id: bytes, start_node: bytes, payment_amt_msat: int,
                   ignore_cltv=False) -> float:
        """Heuristic cost of going through a channel.
        direction: 0 or 1. --- 0 means node_id_1 -> node_id_2
        """
        channel_info = self.channel_db.get_channel_info(short_channel_id)
        if channel_info is None:
            return float('inf')

        channel_policy = channel_info.get_policy_for_node(start_node)
        if channel_policy is None: return float('inf')
        if channel_policy.disabled: return float('inf')
        cltv_expiry_delta           = channel_policy.cltv_expiry_delta
        htlc_minimum_msat           = channel_policy.htlc_minimum_msat
        fee_base_msat               = channel_policy.fee_base_msat
        fee_proportional_millionths = channel_policy.fee_proportional_millionths
        if payment_amt_msat is not None:
            if payment_amt_msat < htlc_minimum_msat:
                return float('inf')  # payment amount too little
            if channel_info.capacity_sat is not None and \
                    payment_amt_msat // 1000 > channel_info.capacity_sat:
                return float('inf')  # payment amount too large
        amt = payment_amt_msat or 50000 * 1000  # guess for typical payment amount
        fee_msat = fee_base_msat + amt * fee_proportional_millionths / 1000000
        # TODO revise
        # paying 10 more satoshis ~ waiting one more block
        fee_cost = fee_msat / 1000 / 10
        cltv_cost = cltv_expiry_delta if not ignore_cltv else 0
        return cltv_cost + fee_cost + 1

    @profiler
    def find_path_for_payment(self, from_node_id: bytes, to_node_id: bytes,
                              amount_msat: int=None) -> Sequence[Tuple[bytes, bytes]]:
        """Return a path between from_node_id and to_node_id.

        Returns a list of (node_id, short_channel_id) representing a path.
        To get from node ret[n][0] to ret[n+1][0], use channel ret[n+1][1];
        i.e. an element reads as, "to get to node_id, travel through short_channel_id"
        """
        if amount_msat is not None: assert type(amount_msat) is int
        # TODO find multiple paths??

        # run Dijkstra
        distance_from_start = defaultdict(lambda: float('inf'))
        distance_from_start[from_node_id] = 0
        prev_node = {}
        nodes_to_explore = queue.PriorityQueue()
        nodes_to_explore.put((0, from_node_id))

        while nodes_to_explore.qsize() > 0:
            dist_to_cur_node, cur_node = nodes_to_explore.get()
            if cur_node == to_node_id:
                break
            if dist_to_cur_node != distance_from_start[cur_node]:
                # queue.PriorityQueue does not implement decrease_priority,
                # so instead of decreasing priorities, we add items again into the queue.
                # so there are duplicates in the queue, that we discard now:
                continue
            for edge_channel_id in self.channel_db.get_channels_for_node(cur_node):
                if edge_channel_id in self.blacklist: continue
                channel_info = self.channel_db.get_channel_info(edge_channel_id)
                node1, node2 = channel_info.node_id_1, channel_info.node_id_2
                neighbour = node2 if node1 == cur_node else node1
                ignore_cltv_delta_in_edge_cost = cur_node == from_node_id
                edge_cost = self._edge_cost(edge_channel_id, cur_node, amount_msat,
                                            ignore_cltv=ignore_cltv_delta_in_edge_cost)
                alt_dist_to_neighbour = distance_from_start[cur_node] + edge_cost
                if alt_dist_to_neighbour < distance_from_start[neighbour]:
                    distance_from_start[neighbour] = alt_dist_to_neighbour
                    prev_node[neighbour] = cur_node, edge_channel_id
                    nodes_to_explore.put((alt_dist_to_neighbour, neighbour))
        else:
            return None  # no path found

        # backtrack from end to start
        cur_node = to_node_id
        path = []
        while cur_node != from_node_id:
            prev_node_id, edge_taken = prev_node[cur_node]
            path += [(cur_node, edge_taken)]
            cur_node = prev_node_id
        path.reverse()
        return path

    def create_route_from_path(self, path, from_node_id: bytes) -> List[RouteEdge]:
        assert type(from_node_id) is bytes
        if path is None:
            raise Exception('cannot create route from None path')
        route = []
        prev_node_id = from_node_id
        for node_id, short_channel_id in path:
            channel_info = self.channel_db.get_channel_info(short_channel_id)
            if channel_info is None:
                raise Exception('cannot find channel info for short_channel_id: {}'.format(bh2u(short_channel_id)))
            channel_policy = channel_info.get_policy_for_node(prev_node_id)
            if channel_policy is None:
                raise Exception('cannot find channel policy for short_channel_id: {}'.format(bh2u(short_channel_id)))
            route.append(RouteEdge(node_id,
                                   short_channel_id,
                                   channel_policy.fee_base_msat,
                                   channel_policy.fee_proportional_millionths,
                                   channel_policy.cltv_expiry_delta))
            prev_node_id = node_id
        return route
