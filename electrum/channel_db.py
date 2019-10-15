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

import time
import random
import os
from collections import defaultdict
from typing import Sequence, List, Tuple, Optional, Dict, NamedTuple, TYPE_CHECKING, Set
import binascii
import base64
import asyncio


from .sql_db import SqlDB, sql
from . import constants
from .util import bh2u, profiler, get_headers_dir, bfh, is_ip_address, list_enabled_bits
from .logging import Logger
from .lnutil import LN_GLOBAL_FEATURES_KNOWN_SET, LNPeerAddr, format_short_channel_id, ShortChannelID
from .lnverifier import LNChannelVerifier, verify_sig_for_channel_update

if TYPE_CHECKING:
    from .network import Network


class UnknownEvenFeatureBits(Exception): pass

def validate_features(features : int):
    enabled_features = list_enabled_bits(features)
    for fbit in enabled_features:
        if (1 << fbit) not in LN_GLOBAL_FEATURES_KNOWN_SET and fbit % 2 == 0:
            raise UnknownEvenFeatureBits()


FLAG_DISABLE   = 1 << 1
FLAG_DIRECTION = 1 << 0

class ChannelInfo(NamedTuple):
    short_channel_id: ShortChannelID
    node1_id: bytes
    node2_id: bytes
    capacity_sat: Optional[int]

    @staticmethod
    def from_msg(payload):
        features = int.from_bytes(payload['features'], 'big')
        validate_features(features)
        channel_id = payload['short_channel_id']
        node_id_1 = payload['node_id_1']
        node_id_2 = payload['node_id_2']
        assert list(sorted([node_id_1, node_id_2])) == [node_id_1, node_id_2]
        capacity_sat = None
        return ChannelInfo(
            short_channel_id = ShortChannelID.normalize(channel_id),
            node1_id = node_id_1,
            node2_id = node_id_2,
            capacity_sat = capacity_sat
        )


class Policy(NamedTuple):
    key: bytes
    cltv_expiry_delta: int
    htlc_minimum_msat: int
    htlc_maximum_msat: Optional[int]
    fee_base_msat: int
    fee_proportional_millionths: int
    channel_flags: int
    message_flags: int
    timestamp: int

    @staticmethod
    def from_msg(payload):
        return Policy(
            key                         = payload['short_channel_id'] + payload['start_node'],
            cltv_expiry_delta           = int.from_bytes(payload['cltv_expiry_delta'], "big"),
            htlc_minimum_msat           = int.from_bytes(payload['htlc_minimum_msat'], "big"),
            htlc_maximum_msat           = int.from_bytes(payload['htlc_maximum_msat'], "big") if 'htlc_maximum_msat' in payload else None,
            fee_base_msat               = int.from_bytes(payload['fee_base_msat'], "big"),
            fee_proportional_millionths = int.from_bytes(payload['fee_proportional_millionths'], "big"),
            message_flags               = int.from_bytes(payload['message_flags'], "big"),
            channel_flags               = int.from_bytes(payload['channel_flags'], "big"),
            timestamp                   = int.from_bytes(payload['timestamp'], "big")
        )

    def is_disabled(self):
        return self.channel_flags & FLAG_DISABLE

    @property
    def short_channel_id(self) -> ShortChannelID:
        return ShortChannelID.normalize(self.key[0:8])

    @property
    def start_node(self):
        return self.key[8:]



class NodeInfo(NamedTuple):
    node_id: bytes
    features: int
    timestamp: int
    alias: str

    @staticmethod
    def from_msg(payload):
        node_id = payload['node_id']
        features = int.from_bytes(payload['features'], "big")
        validate_features(features)
        addresses = NodeInfo.parse_addresses_field(payload['addresses'])
        alias = payload['alias'].rstrip(b'\x00')
        timestamp = int.from_bytes(payload['timestamp'], "big")
        return NodeInfo(node_id=node_id, features=features, timestamp=timestamp, alias=alias), [
            Address(host=host, port=port, node_id=node_id, last_connected_date=None) for host, port in addresses]

    @staticmethod
    def parse_addresses_field(addresses_field):
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


class Address(NamedTuple):
    node_id: bytes
    host: str
    port: int
    last_connected_date: Optional[int]


class CategorizedChannelUpdates(NamedTuple):
    orphaned: List    # no channel announcement for channel update
    expired: List     # update older than two weeks
    deprecated: List  # update older than database entry
    good: List        # good updates
    to_delete: List   # database entries to delete


# TODO It would make more sense to store the raw gossip messages in the db.
#      That is pretty much a pre-requisite of actively participating in gossip.

create_channel_info = """
CREATE TABLE IF NOT EXISTS channel_info (
short_channel_id VARCHAR(64),
node1_id VARCHAR(66),
node2_id VARCHAR(66),
capacity_sat INTEGER,
PRIMARY KEY(short_channel_id)
)"""

create_policy = """
CREATE TABLE IF NOT EXISTS policy (
key VARCHAR(66),
cltv_expiry_delta INTEGER NOT NULL,
htlc_minimum_msat INTEGER NOT NULL,
htlc_maximum_msat INTEGER,
fee_base_msat INTEGER NOT NULL,
fee_proportional_millionths INTEGER NOT NULL,
channel_flags INTEGER NOT NULL,
message_flags INTEGER NOT NULL,
timestamp INTEGER NOT NULL,
PRIMARY KEY(key)
)"""

create_address = """
CREATE TABLE IF NOT EXISTS address (
node_id VARCHAR(66),
host STRING(256),
port INTEGER NOT NULL,
timestamp INTEGER,
PRIMARY KEY(node_id, host, port)
)"""

create_node_info = """
CREATE TABLE IF NOT EXISTS node_info (
node_id VARCHAR(66),
features INTEGER NOT NULL,
timestamp INTEGER NOT NULL,
alias STRING(64),
PRIMARY KEY(node_id)
)"""


class ChannelDB(SqlDB):

    NUM_MAX_RECENT_PEERS = 20

    def __init__(self, network: 'Network'):
        path = os.path.join(get_headers_dir(network.config), 'channel_db')
        super().__init__(network, path, commit_interval=100)
        self.num_nodes = 0
        self.num_channels = 0
        self._channel_updates_for_private_channels = {}  # type: Dict[Tuple[bytes, bytes], dict]
        self.ca_verifier = LNChannelVerifier(network, self)
        # initialized in load_data
        self._channels = {}  # type: Dict[bytes, ChannelInfo]
        self._policies = {}
        self._nodes = {}
        # node_id -> (host, port, ts)
        self._addresses = defaultdict(set)  # type: Dict[bytes, Set[Tuple[str, int, int]]]
        self._channels_for_node = defaultdict(set)
        self.data_loaded = asyncio.Event()
        self.network = network # only for callback

    def update_counts(self):
        self.num_nodes = len(self._nodes)
        self.num_channels = len(self._channels)
        self.num_policies = len(self._policies)
        self.network.trigger_callback('channel_db', self.num_nodes, self.num_channels, self.num_policies)

    def get_channel_ids(self):
        return set(self._channels.keys())

    def add_recent_peer(self, peer: LNPeerAddr):
        now = int(time.time())
        node_id = peer.pubkey
        self._addresses[node_id].add((peer.host, peer.port, now))
        self.save_node_address(node_id, peer, now)

    def get_200_randomly_sorted_nodes_not_in(self, node_ids):
        unshuffled = set(self._nodes.keys()) - node_ids
        return random.sample(unshuffled, min(200, len(unshuffled)))

    def get_last_good_address(self, node_id) -> Optional[LNPeerAddr]:
        r = self._addresses.get(node_id)
        if not r:
            return None
        addr = sorted(list(r), key=lambda x: x[2])[0]
        host, port, timestamp = addr
        return LNPeerAddr(host, port, node_id)

    def get_recent_peers(self):
        assert self.data_loaded.is_set(), "channelDB load_data did not finish yet!"
        r = [self.get_last_good_address(x) for x in self._addresses.keys()]
        r = r[-self.NUM_MAX_RECENT_PEERS:]
        return r

    def add_channel_announcement(self, msg_payloads, trusted=True):
        if type(msg_payloads) is dict:
            msg_payloads = [msg_payloads]
        added = 0
        for msg in msg_payloads:
            short_channel_id = ShortChannelID(msg['short_channel_id'])
            if short_channel_id in self._channels:
                continue
            if constants.net.rev_genesis_bytes() != msg['chain_hash']:
                self.logger.info("ChanAnn has unexpected chain_hash {}".format(bh2u(msg['chain_hash'])))
                continue
            try:
                channel_info = ChannelInfo.from_msg(msg)
            except UnknownEvenFeatureBits:
                self.logger.info("unknown feature bits")
                continue
            added += 1
            self._channels[short_channel_id] = channel_info
            self._channels_for_node[channel_info.node1_id].add(channel_info.short_channel_id)
            self._channels_for_node[channel_info.node2_id].add(channel_info.short_channel_id)
            self.save_channel(channel_info)
            if not trusted:
                self.ca_verifier.add_new_channel_info(channel_info.short_channel_id, msg)

        self.update_counts()
        self.logger.debug('add_channel_announcement: %d/%d'%(added, len(msg_payloads)))

    def print_change(self, old_policy: Policy, new_policy: Policy):
        # print what changed between policies
        if old_policy.cltv_expiry_delta != new_policy.cltv_expiry_delta:
            self.logger.info(f'cltv_expiry_delta: {old_policy.cltv_expiry_delta} -> {new_policy.cltv_expiry_delta}')
        if old_policy.htlc_minimum_msat != new_policy.htlc_minimum_msat:
            self.logger.info(f'htlc_minimum_msat: {old_policy.htlc_minimum_msat} -> {new_policy.htlc_minimum_msat}')
        if old_policy.htlc_maximum_msat != new_policy.htlc_maximum_msat:
            self.logger.info(f'htlc_maximum_msat: {old_policy.htlc_maximum_msat} -> {new_policy.htlc_maximum_msat}')
        if old_policy.fee_base_msat != new_policy.fee_base_msat:
            self.logger.info(f'fee_base_msat: {old_policy.fee_base_msat} -> {new_policy.fee_base_msat}')
        if old_policy.fee_proportional_millionths != new_policy.fee_proportional_millionths:
            self.logger.info(f'fee_proportional_millionths: {old_policy.fee_proportional_millionths} -> {new_policy.fee_proportional_millionths}')
        if old_policy.channel_flags != new_policy.channel_flags:
            self.logger.info(f'channel_flags: {old_policy.channel_flags} -> {new_policy.channel_flags}')
        if old_policy.message_flags != new_policy.message_flags:
            self.logger.info(f'message_flags: {old_policy.message_flags} -> {new_policy.message_flags}')

    def add_channel_updates(self, payloads, max_age=None, verify=True) -> CategorizedChannelUpdates:
        orphaned = []
        expired = []
        deprecated = []
        good = []
        to_delete = []
        # filter orphaned and expired first
        known = []
        now = int(time.time())
        for payload in payloads:
            short_channel_id = ShortChannelID(payload['short_channel_id'])
            timestamp = int.from_bytes(payload['timestamp'], "big")
            if max_age and now - timestamp > max_age:
                expired.append(payload)
                continue
            channel_info = self._channels.get(short_channel_id)
            if not channel_info:
                orphaned.append(payload)
                continue
            flags = int.from_bytes(payload['channel_flags'], 'big')
            direction = flags & FLAG_DIRECTION
            start_node = channel_info.node1_id if direction == 0 else channel_info.node2_id
            payload['start_node'] = start_node
            known.append(payload)
        # compare updates to existing database entries
        for payload in known:
            timestamp = int.from_bytes(payload['timestamp'], "big")
            start_node = payload['start_node']
            short_channel_id = ShortChannelID(payload['short_channel_id'])
            key = (start_node, short_channel_id)
            old_policy = self._policies.get(key)
            if old_policy and timestamp <= old_policy.timestamp:
                deprecated.append(payload)
                continue
            good.append(payload)
            if verify:
                self.verify_channel_update(payload)
            policy = Policy.from_msg(payload)
            self._policies[key] = policy
            self.save_policy(policy)
        #
        self.update_counts()
        return CategorizedChannelUpdates(
            orphaned=orphaned,
            expired=expired,
            deprecated=deprecated,
            good=good,
            to_delete=to_delete,
        )

    def add_channel_update(self, payload):
        # called from add_own_channel
        # the update may be categorized as deprecated because of caching
        categorized_chan_upds = self.add_channel_updates([payload], verify=False)

    def create_database(self):
        c = self.conn.cursor()
        c.execute(create_node_info)
        c.execute(create_address)
        c.execute(create_policy)
        c.execute(create_channel_info)
        self.conn.commit()

    @sql
    def save_policy(self, policy):
        c = self.conn.cursor()
        c.execute("""REPLACE INTO policy (key, cltv_expiry_delta, htlc_minimum_msat, htlc_maximum_msat, fee_base_msat, fee_proportional_millionths, channel_flags, message_flags, timestamp) VALUES (?,?,?,?,?,?,?,?,?)""", list(policy))

    @sql
    def delete_policy(self, node_id, short_channel_id):
        key = short_channel_id + node_id
        c = self.conn.cursor()
        c.execute("""DELETE FROM policy WHERE key=?""", (key,))

    @sql
    def save_channel(self, channel_info):
        c = self.conn.cursor()
        c.execute("REPLACE INTO channel_info (short_channel_id, node1_id, node2_id, capacity_sat) VALUES (?,?,?,?)", list(channel_info))

    @sql
    def delete_channel(self, short_channel_id):
        c = self.conn.cursor()
        c.execute("""DELETE FROM channel_info WHERE short_channel_id=?""", (short_channel_id,))

    @sql
    def save_node(self, node_info):
        c = self.conn.cursor()
        c.execute("REPLACE INTO node_info (node_id, features, timestamp, alias) VALUES (?,?,?,?)", list(node_info))

    @sql
    def save_node_address(self, node_id, peer, now):
        c = self.conn.cursor()
        c.execute("REPLACE INTO address (node_id, host, port, timestamp) VALUES (?,?,?,?)", (node_id, peer.host, peer.port, now))

    @sql
    def save_node_addresses(self, node_id, node_addresses):
        c = self.conn.cursor()
        for addr in node_addresses:
            c.execute("SELECT * FROM address WHERE node_id=? AND host=? AND port=?", (addr.node_id, addr.host, addr.port))
            r = c.fetchall()
            if r == []:
                c.execute("INSERT INTO address (node_id, host, port, timestamp) VALUES (?,?,?,?)", (addr.node_id, addr.host, addr.port, 0))

    def verify_channel_update(self, payload):
        short_channel_id = payload['short_channel_id']
        short_channel_id = ShortChannelID(short_channel_id)
        if constants.net.rev_genesis_bytes() != payload['chain_hash']:
            raise Exception('wrong chain hash')
        if not verify_sig_for_channel_update(payload, payload['start_node']):
            raise Exception(f'failed verifying channel update for {short_channel_id}')

    def add_node_announcement(self, msg_payloads):
        if type(msg_payloads) is dict:
            msg_payloads = [msg_payloads]
        old_addr = None
        new_nodes = {}
        for msg_payload in msg_payloads:
            try:
                node_info, node_addresses = NodeInfo.from_msg(msg_payload)
            except UnknownEvenFeatureBits:
                continue
            node_id = node_info.node_id
            # Ignore node if it has no associated channel (DoS protection)
            if node_id not in self._channels_for_node:
                #self.logger.info('ignoring orphan node_announcement')
                continue
            node = self._nodes.get(node_id)
            if node and node.timestamp >= node_info.timestamp:
                continue
            node = new_nodes.get(node_id)
            if node and node.timestamp >= node_info.timestamp:
                continue
            # save
            self._nodes[node_id] = node_info
            self.save_node(node_info)
            for addr in node_addresses:
                self._addresses[node_id].add((addr.host, addr.port, 0))
            self.save_node_addresses(node_id, node_addresses)

        self.logger.debug("on_node_announcement: %d/%d"%(len(new_nodes), len(msg_payloads)))
        self.update_counts()

    def get_routing_policy_for_channel(self, start_node_id: bytes,
                                       short_channel_id: bytes) -> Optional[Policy]:
        if not start_node_id or not short_channel_id: return None
        channel_info = self.get_channel_info(short_channel_id)
        if channel_info is not None:
            return self.get_policy_for_node(short_channel_id, start_node_id)
        msg = self._channel_updates_for_private_channels.get((start_node_id, short_channel_id))
        if not msg:
            return None
        return Policy.from_msg(msg) # won't actually be written to DB

    def get_old_policies(self, delta):
        now = int(time.time())
        return list(k for k, v in list(self._policies.items()) if v.timestamp <= now - delta)

    def prune_old_policies(self, delta):
        l = self.get_old_policies(delta)
        if l:
            for k in l:
                self._policies.pop(k)
                self.delete_policy(*k)
            self.update_counts()
            self.logger.info(f'Deleting {len(l)} old policies')

    def get_orphaned_channels(self):
        ids = set(x[1] for x in self._policies.keys())
        return list(x for x in self._channels.keys() if x not in ids)

    def prune_orphaned_channels(self):
        l = self.get_orphaned_channels()
        if l:
            for short_channel_id in l:
                self.remove_channel(short_channel_id)
                self.delete_channel(short_channel_id)
            self.update_counts()
            self.logger.info(f'Deleting {len(l)} orphaned channels')

    def add_channel_update_for_private_channel(self, msg_payload: dict, start_node_id: bytes):
        if not verify_sig_for_channel_update(msg_payload, start_node_id):
            return  # ignore
        short_channel_id = ShortChannelID(msg_payload['short_channel_id'])
        msg_payload['start_node'] = start_node_id
        self._channel_updates_for_private_channels[(start_node_id, short_channel_id)] = msg_payload

    def remove_channel(self, short_channel_id: ShortChannelID):
        channel_info = self._channels.pop(short_channel_id, None)
        if channel_info:
            self._channels_for_node[channel_info.node1_id].remove(channel_info.short_channel_id)
            self._channels_for_node[channel_info.node2_id].remove(channel_info.short_channel_id)

    def get_node_addresses(self, node_id):
        return self._addresses.get(node_id)

    @sql
    @profiler
    def load_data(self):
        c = self.conn.cursor()
        c.execute("""SELECT * FROM address""")
        for x in c:
            node_id, host, port, timestamp = x
            self._addresses[node_id].add((str(host), int(port), int(timestamp or 0)))
        c.execute("""SELECT * FROM channel_info""")
        for x in c:
            x = (ShortChannelID.normalize(x[0]), *x[1:])
            ci = ChannelInfo(*x)
            self._channels[ci.short_channel_id] = ci
        c.execute("""SELECT * FROM node_info""")
        for x in c:
            ni = NodeInfo(*x)
            self._nodes[ni.node_id] = ni
        c.execute("""SELECT * FROM policy""")
        for x in c:
            p = Policy(*x)
            self._policies[(p.start_node, p.short_channel_id)] = p
        for channel_info in self._channels.values():
            self._channels_for_node[channel_info.node1_id].add(channel_info.short_channel_id)
            self._channels_for_node[channel_info.node2_id].add(channel_info.short_channel_id)
        self.logger.info(f'load data {len(self._channels)} {len(self._policies)} {len(self._channels_for_node)}')
        self.update_counts()
        self.count_incomplete_channels()
        self.data_loaded.set()

    def count_incomplete_channels(self):
        out = set()
        for short_channel_id, ci in self._channels.items():
            p1 = self.get_policy_for_node(short_channel_id, ci.node1_id)
            p2 = self.get_policy_for_node(short_channel_id, ci.node2_id)
            if p1 is None or p2 is not None:
                out.add(short_channel_id)
        self.logger.info(f'semi-orphaned: {len(out)}')

    def get_policy_for_node(self, short_channel_id: bytes, node_id: bytes) -> Optional['Policy']:
        return self._policies.get((node_id, short_channel_id))

    def get_channel_info(self, channel_id: bytes) -> ChannelInfo:
        return self._channels.get(channel_id)

    def get_channels_for_node(self, node_id) -> Set[bytes]:
        """Returns the set of channels that have node_id as one of the endpoints."""
        return self._channels_for_node.get(node_id) or set()
