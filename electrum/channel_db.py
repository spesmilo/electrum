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
import threading
from enum import IntEnum


from .sql_db import SqlDB, sql
from . import constants, util
from .util import bh2u, profiler, get_headers_dir, bfh, is_ip_address, list_enabled_bits
from .logging import Logger
from .lnutil import (LNPeerAddr, format_short_channel_id, ShortChannelID,
                     validate_features, IncompatibleOrInsaneFeatures)
from .lnverifier import LNChannelVerifier, verify_sig_for_channel_update
from .lnmsg import decode_msg

if TYPE_CHECKING:
    from .network import Network
    from .lnchannel import Channel


FLAG_DISABLE   = 1 << 1
FLAG_DIRECTION = 1 << 0

class ChannelInfo(NamedTuple):
    short_channel_id: ShortChannelID
    node1_id: bytes
    node2_id: bytes
    capacity_sat: Optional[int]

    @staticmethod
    def from_msg(payload: dict) -> 'ChannelInfo':
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

    @staticmethod
    def from_raw_msg(raw: bytes) -> 'ChannelInfo':
        payload_dict = decode_msg(raw)[1]
        return ChannelInfo.from_msg(payload_dict)


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
    def from_msg(payload: dict) -> 'Policy':
        return Policy(
            key                         = payload['short_channel_id'] + payload['start_node'],
            cltv_expiry_delta           = payload['cltv_expiry_delta'],
            htlc_minimum_msat           = payload['htlc_minimum_msat'],
            htlc_maximum_msat           = payload.get('htlc_maximum_msat', None),
            fee_base_msat               = payload['fee_base_msat'],
            fee_proportional_millionths = payload['fee_proportional_millionths'],
            message_flags               = int.from_bytes(payload['message_flags'], "big"),
            channel_flags               = int.from_bytes(payload['channel_flags'], "big"),
            timestamp                   = payload['timestamp'],
        )

    @staticmethod
    def from_raw_msg(key:bytes, raw: bytes) -> 'Policy':
        payload = decode_msg(raw)[1]
        payload['start_node'] = key[8:]
        return Policy.from_msg(payload)

    def is_disabled(self):
        return self.channel_flags & FLAG_DISABLE

    @property
    def short_channel_id(self) -> ShortChannelID:
        return ShortChannelID.normalize(self.key[0:8])

    @property
    def start_node(self) -> bytes:
        return self.key[8:]



class NodeInfo(NamedTuple):
    node_id: bytes
    features: int
    timestamp: int
    alias: str

    @staticmethod
    def from_msg(payload) -> Tuple['NodeInfo', Sequence['LNPeerAddr']]:
        node_id = payload['node_id']
        features = int.from_bytes(payload['features'], "big")
        validate_features(features)
        addresses = NodeInfo.parse_addresses_field(payload['addresses'])
        peer_addrs = []
        for host, port in addresses:
            try:
                peer_addrs.append(LNPeerAddr(host=host, port=port, pubkey=node_id))
            except ValueError:
                pass
        alias = payload['alias'].rstrip(b'\x00')
        try:
            alias = alias.decode('utf8')
        except:
            alias = ''
        timestamp = payload['timestamp']
        node_info = NodeInfo(node_id=node_id, features=features, timestamp=timestamp, alias=alias)
        return node_info, peer_addrs

    @staticmethod
    def from_raw_msg(raw: bytes) -> Tuple['NodeInfo', Sequence['LNPeerAddr']]:
        payload_dict = decode_msg(raw)[1]
        return NodeInfo.from_msg(payload_dict)

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


class UpdateStatus(IntEnum):
    ORPHANED   = 0
    EXPIRED    = 1
    DEPRECATED = 2
    UNCHANGED  = 3
    GOOD       = 4

class CategorizedChannelUpdates(NamedTuple):
    orphaned: List    # no channel announcement for channel update
    expired: List     # update older than two weeks
    deprecated: List  # update older than database entry
    unchanged: List   # unchanged policies
    good: List        # good updates


create_channel_info = """
CREATE TABLE IF NOT EXISTS channel_info (
short_channel_id BLOB(8),
msg BLOB,
PRIMARY KEY(short_channel_id)
)"""

create_policy = """
CREATE TABLE IF NOT EXISTS policy (
key BLOB(41),
msg BLOB,
PRIMARY KEY(key)
)"""

create_address = """
CREATE TABLE IF NOT EXISTS address (
node_id BLOB(33),
host STRING(256),
port INTEGER NOT NULL,
timestamp INTEGER,
PRIMARY KEY(node_id, host, port)
)"""

create_node_info = """
CREATE TABLE IF NOT EXISTS node_info (
node_id BLOB(33),
msg BLOB,
PRIMARY KEY(node_id)
)"""


class ChannelDB(SqlDB):

    NUM_MAX_RECENT_PEERS = 20

    def __init__(self, network: 'Network'):
        path = os.path.join(get_headers_dir(network.config), 'gossip_db')
        super().__init__(network.asyncio_loop, path, commit_interval=100)
        self.lock = threading.RLock()
        self.num_nodes = 0
        self.num_channels = 0
        self._channel_updates_for_private_channels = {}  # type: Dict[Tuple[bytes, bytes], dict]
        self.ca_verifier = LNChannelVerifier(network, self)

        # initialized in load_data
        # note: modify/iterate needs self.lock
        self._channels = {}  # type: Dict[ShortChannelID, ChannelInfo]
        self._policies = {}  # type: Dict[Tuple[bytes, ShortChannelID], Policy]  # (node_id, scid) -> Policy
        self._nodes = {}  # type: Dict[bytes, NodeInfo]  # node_id -> NodeInfo
        # node_id -> (host, port, ts)
        self._addresses = defaultdict(set)  # type: Dict[bytes, Set[Tuple[str, int, int]]]
        self._channels_for_node = defaultdict(set)  # type: Dict[bytes, Set[ShortChannelID]]
        self._recent_peers = []  # type: List[bytes]  # list of node_ids
        self._chans_with_0_policies = set()  # type: Set[ShortChannelID]
        self._chans_with_1_policies = set()  # type: Set[ShortChannelID]
        self._chans_with_2_policies = set()  # type: Set[ShortChannelID]

        self.data_loaded = asyncio.Event()
        self.network = network # only for callback

    def update_counts(self):
        self.num_nodes = len(self._nodes)
        self.num_channels = len(self._channels)
        self.num_policies = len(self._policies)
        util.trigger_callback('channel_db', self.num_nodes, self.num_channels, self.num_policies)
        util.trigger_callback('ln_gossip_sync_progress')

    def get_channel_ids(self):
        with self.lock:
            return set(self._channels.keys())

    def add_recent_peer(self, peer: LNPeerAddr):
        now = int(time.time())
        node_id = peer.pubkey
        with self.lock:
            self._addresses[node_id].add((peer.host, peer.port, now))
            # list is ordered
            if node_id in self._recent_peers:
                self._recent_peers.remove(node_id)
            self._recent_peers.insert(0, node_id)
            self._recent_peers = self._recent_peers[:self.NUM_MAX_RECENT_PEERS]
        self._db_save_node_address(peer, now)

    def get_200_randomly_sorted_nodes_not_in(self, node_ids):
        with self.lock:
            unshuffled = set(self._nodes.keys()) - node_ids
        return random.sample(unshuffled, min(200, len(unshuffled)))

    def get_last_good_address(self, node_id) -> Optional[LNPeerAddr]:
        r = self._addresses.get(node_id)
        if not r:
            return None
        addr = sorted(list(r), key=lambda x: x[2])[0]
        host, port, timestamp = addr
        try:
            return LNPeerAddr(host, port, node_id)
        except ValueError:
            return None

    def get_recent_peers(self):
        if not self.data_loaded.is_set():
            raise Exception("channelDB data not loaded yet!")
        with self.lock:
            ret = [self.get_last_good_address(node_id)
                   for node_id in self._recent_peers]
            return ret

    # note: currently channel announcements are trusted by default (trusted=True);
    #       they are not SPV-verified. Verifying them would make the gossip sync
    #       even slower; especially as servers will start throttling us.
    #       It would probably put significant strain on servers if all clients
    #       verified the complete gossip.
    def add_channel_announcement(self, msg_payloads, *, trusted=True):
        # note: signatures have already been verified.
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
            except IncompatibleOrInsaneFeatures as e:
                self.logger.info(f"unknown or insane feature bits: {e!r}")
                continue
            if trusted:
                added += 1
                self.add_verified_channel_info(msg)
            else:
                added += self.ca_verifier.add_new_channel_info(short_channel_id, msg)

        self.update_counts()
        self.logger.debug('add_channel_announcement: %d/%d'%(added, len(msg_payloads)))

    def add_verified_channel_info(self, msg: dict, *, capacity_sat: int = None) -> None:
        try:
            channel_info = ChannelInfo.from_msg(msg)
        except IncompatibleOrInsaneFeatures:
            return
        channel_info = channel_info._replace(capacity_sat=capacity_sat)
        with self.lock:
            self._channels[channel_info.short_channel_id] = channel_info
            self._channels_for_node[channel_info.node1_id].add(channel_info.short_channel_id)
            self._channels_for_node[channel_info.node2_id].add(channel_info.short_channel_id)
        self._update_num_policies_for_chan(channel_info.short_channel_id)
        if 'raw' in msg:
            self._db_save_channel(channel_info.short_channel_id, msg['raw'])

    def policy_changed(self, old_policy: Policy, new_policy: Policy, verbose: bool) -> bool:
        changed = False
        if old_policy.cltv_expiry_delta != new_policy.cltv_expiry_delta:
            changed |= True
            if verbose:
                self.logger.info(f'cltv_expiry_delta: {old_policy.cltv_expiry_delta} -> {new_policy.cltv_expiry_delta}')
        if old_policy.htlc_minimum_msat != new_policy.htlc_minimum_msat:
            changed |= True
            if verbose:
                self.logger.info(f'htlc_minimum_msat: {old_policy.htlc_minimum_msat} -> {new_policy.htlc_minimum_msat}')
        if old_policy.htlc_maximum_msat != new_policy.htlc_maximum_msat:
            changed |= True
            if verbose:
                self.logger.info(f'htlc_maximum_msat: {old_policy.htlc_maximum_msat} -> {new_policy.htlc_maximum_msat}')
        if old_policy.fee_base_msat != new_policy.fee_base_msat:
            changed |= True
            if verbose:
                self.logger.info(f'fee_base_msat: {old_policy.fee_base_msat} -> {new_policy.fee_base_msat}')
        if old_policy.fee_proportional_millionths != new_policy.fee_proportional_millionths:
            changed |= True
            if verbose:
                self.logger.info(f'fee_proportional_millionths: {old_policy.fee_proportional_millionths} -> {new_policy.fee_proportional_millionths}')
        if old_policy.channel_flags != new_policy.channel_flags:
            changed |= True
            if verbose:
                self.logger.info(f'channel_flags: {old_policy.channel_flags} -> {new_policy.channel_flags}')
        if old_policy.message_flags != new_policy.message_flags:
            changed |= True
            if verbose:
                self.logger.info(f'message_flags: {old_policy.message_flags} -> {new_policy.message_flags}')
        if not changed and verbose:
            self.logger.info(f'policy unchanged: {old_policy.timestamp} -> {new_policy.timestamp}')
        return changed

    def add_channel_update(self, payload, max_age=None, verify=False, verbose=True):
        now = int(time.time())
        short_channel_id = ShortChannelID(payload['short_channel_id'])
        timestamp = payload['timestamp']
        if max_age and now - timestamp > max_age:
            return UpdateStatus.EXPIRED
        if timestamp - now > 60:
            return UpdateStatus.DEPRECATED
        channel_info = self._channels.get(short_channel_id)
        if not channel_info:
            return UpdateStatus.ORPHANED
        flags = int.from_bytes(payload['channel_flags'], 'big')
        direction = flags & FLAG_DIRECTION
        start_node = channel_info.node1_id if direction == 0 else channel_info.node2_id
        payload['start_node'] = start_node
        # compare updates to existing database entries
        timestamp = payload['timestamp']
        start_node = payload['start_node']
        short_channel_id = ShortChannelID(payload['short_channel_id'])
        key = (start_node, short_channel_id)
        old_policy = self._policies.get(key)
        if old_policy and timestamp <= old_policy.timestamp + 60:
            return UpdateStatus.DEPRECATED
        if verify:
            self.verify_channel_update(payload)
        policy = Policy.from_msg(payload)
        with self.lock:
            self._policies[key] = policy
        self._update_num_policies_for_chan(short_channel_id)
        if 'raw' in payload:
            self._db_save_policy(policy.key, payload['raw'])
        if old_policy and not self.policy_changed(old_policy, policy, verbose):
            return UpdateStatus.UNCHANGED
        else:
            return UpdateStatus.GOOD

    def add_channel_updates(self, payloads, max_age=None) -> CategorizedChannelUpdates:
        orphaned = []
        expired = []
        deprecated = []
        unchanged = []
        good = []
        for payload in payloads:
            r = self.add_channel_update(payload, max_age=max_age, verbose=False)
            if r == UpdateStatus.ORPHANED:
                orphaned.append(payload)
            elif r == UpdateStatus.EXPIRED:
                expired.append(payload)
            elif r == UpdateStatus.DEPRECATED:
                deprecated.append(payload)
            elif r == UpdateStatus.UNCHANGED:
                unchanged.append(payload)
            elif r == UpdateStatus.GOOD:
                good.append(payload)
        self.update_counts()
        return CategorizedChannelUpdates(
            orphaned=orphaned,
            expired=expired,
            deprecated=deprecated,
            unchanged=unchanged,
            good=good)


    def create_database(self):
        c = self.conn.cursor()
        c.execute(create_node_info)
        c.execute(create_address)
        c.execute(create_policy)
        c.execute(create_channel_info)
        self.conn.commit()

    @sql
    def _db_save_policy(self, key: bytes, msg: bytes):
        # 'msg' is a 'channel_update' message
        c = self.conn.cursor()
        c.execute("""REPLACE INTO policy (key, msg) VALUES (?,?)""", [key, msg])

    @sql
    def _db_delete_policy(self, node_id: bytes, short_channel_id: ShortChannelID):
        key = short_channel_id + node_id
        c = self.conn.cursor()
        c.execute("""DELETE FROM policy WHERE key=?""", (key,))

    @sql
    def _db_save_channel(self, short_channel_id: ShortChannelID, msg: bytes):
        # 'msg' is a 'channel_announcement' message
        c = self.conn.cursor()
        c.execute("REPLACE INTO channel_info (short_channel_id, msg) VALUES (?,?)", [short_channel_id, msg])

    @sql
    def _db_delete_channel(self, short_channel_id: ShortChannelID):
        c = self.conn.cursor()
        c.execute("""DELETE FROM channel_info WHERE short_channel_id=?""", (short_channel_id,))

    @sql
    def _db_save_node_info(self, node_id: bytes, msg: bytes):
        # 'msg' is a 'node_announcement' message
        c = self.conn.cursor()
        c.execute("REPLACE INTO node_info (node_id, msg) VALUES (?,?)", [node_id, msg])

    @sql
    def _db_save_node_address(self, peer: LNPeerAddr, timestamp: int):
        c = self.conn.cursor()
        c.execute("REPLACE INTO address (node_id, host, port, timestamp) VALUES (?,?,?,?)",
                  (peer.pubkey, peer.host, peer.port, timestamp))

    @sql
    def _db_save_node_addresses(self, node_addresses: Sequence[LNPeerAddr]):
        c = self.conn.cursor()
        for addr in node_addresses:
            c.execute("SELECT * FROM address WHERE node_id=? AND host=? AND port=?", (addr.pubkey, addr.host, addr.port))
            r = c.fetchall()
            if r == []:
                c.execute("INSERT INTO address (node_id, host, port, timestamp) VALUES (?,?,?,?)", (addr.pubkey, addr.host, addr.port, 0))

    def verify_channel_update(self, payload):
        short_channel_id = payload['short_channel_id']
        short_channel_id = ShortChannelID(short_channel_id)
        if constants.net.rev_genesis_bytes() != payload['chain_hash']:
            raise Exception('wrong chain hash')
        if not verify_sig_for_channel_update(payload, payload['start_node']):
            raise Exception(f'failed verifying channel update for {short_channel_id}')

    def add_node_announcement(self, msg_payloads):
        # note: signatures have already been verified.
        if type(msg_payloads) is dict:
            msg_payloads = [msg_payloads]
        new_nodes = {}
        for msg_payload in msg_payloads:
            try:
                node_info, node_addresses = NodeInfo.from_msg(msg_payload)
            except IncompatibleOrInsaneFeatures:
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
            with self.lock:
                self._nodes[node_id] = node_info
            if 'raw' in msg_payload:
                self._db_save_node_info(node_id, msg_payload['raw'])
            with self.lock:
                for addr in node_addresses:
                    self._addresses[node_id].add((addr.host, addr.port, 0))
            self._db_save_node_addresses(node_addresses)

        self.logger.debug("on_node_announcement: %d/%d"%(len(new_nodes), len(msg_payloads)))
        self.update_counts()

    def get_old_policies(self, delta) -> Sequence[Tuple[bytes, ShortChannelID]]:
        with self.lock:
            _policies = self._policies.copy()
        now = int(time.time())
        return list(k for k, v in _policies.items() if v.timestamp <= now - delta)

    def prune_old_policies(self, delta):
        old_policies = self.get_old_policies(delta)
        if old_policies:
            for key in old_policies:
                node_id, scid = key
                with self.lock:
                    self._policies.pop(key)
                self._db_delete_policy(*key)
                self._update_num_policies_for_chan(scid)
            self.update_counts()
            self.logger.info(f'Deleting {len(old_policies)} old policies')

    def prune_orphaned_channels(self):
        with self.lock:
            orphaned_chans = self._chans_with_0_policies.copy()
        if orphaned_chans:
            for short_channel_id in orphaned_chans:
                self.remove_channel(short_channel_id)
            self.update_counts()
            self.logger.info(f'Deleting {len(orphaned_chans)} orphaned channels')

    def add_channel_update_for_private_channel(self, msg_payload: dict, start_node_id: bytes):
        if not verify_sig_for_channel_update(msg_payload, start_node_id):
            return  # ignore
        short_channel_id = ShortChannelID(msg_payload['short_channel_id'])
        msg_payload['start_node'] = start_node_id
        self._channel_updates_for_private_channels[(start_node_id, short_channel_id)] = msg_payload

    def remove_channel(self, short_channel_id: ShortChannelID):
        # FIXME what about rm-ing policies?
        with self.lock:
            channel_info = self._channels.pop(short_channel_id, None)
            if channel_info:
                self._channels_for_node[channel_info.node1_id].remove(channel_info.short_channel_id)
                self._channels_for_node[channel_info.node2_id].remove(channel_info.short_channel_id)
        self._update_num_policies_for_chan(short_channel_id)
        # delete from database
        self._db_delete_channel(short_channel_id)

    def get_node_addresses(self, node_id):
        return self._addresses.get(node_id)

    @sql
    @profiler
    def load_data(self):
        # Note: this method takes several seconds... mostly due to lnmsg.decode_msg being slow.
        #       I believe lnmsg (and lightning.json) will need a rewrite anyway, so instead of tweaking
        #       load_data() here, that should be done. see #6006
        c = self.conn.cursor()
        c.execute("""SELECT * FROM address""")
        for x in c:
            node_id, host, port, timestamp = x
            self._addresses[node_id].add((str(host), int(port), int(timestamp or 0)))
        def newest_ts_for_node_id(node_id):
            newest_ts = 0
            for host, port, ts in self._addresses[node_id]:
                newest_ts = max(newest_ts, ts)
            return newest_ts
        sorted_node_ids = sorted(self._addresses.keys(), key=newest_ts_for_node_id, reverse=True)
        self._recent_peers = sorted_node_ids[:self.NUM_MAX_RECENT_PEERS]
        c.execute("""SELECT * FROM channel_info""")
        for short_channel_id, msg in c:
            try:
                ci = ChannelInfo.from_raw_msg(msg)
            except IncompatibleOrInsaneFeatures:
                continue
            self._channels[ShortChannelID.normalize(short_channel_id)] = ci
        c.execute("""SELECT * FROM node_info""")
        for node_id, msg in c:
            try:
                node_info, node_addresses = NodeInfo.from_raw_msg(msg)
            except IncompatibleOrInsaneFeatures:
                continue
            # don't load node_addresses because they dont have timestamps
            self._nodes[node_id] = node_info
        c.execute("""SELECT * FROM policy""")
        for key, msg in c:
            p = Policy.from_raw_msg(key, msg)
            self._policies[(p.start_node, p.short_channel_id)] = p
        for channel_info in self._channels.values():
            self._channels_for_node[channel_info.node1_id].add(channel_info.short_channel_id)
            self._channels_for_node[channel_info.node2_id].add(channel_info.short_channel_id)
            self._update_num_policies_for_chan(channel_info.short_channel_id)
        self.logger.info(f'load data {len(self._channels)} {len(self._policies)} {len(self._channels_for_node)}')
        self.update_counts()
        (nchans_with_0p, nchans_with_1p, nchans_with_2p) = self.get_num_channels_partitioned_by_policy_count()
        self.logger.info(f'num_channels_partitioned_by_policy_count. '
                         f'0p: {nchans_with_0p}, 1p: {nchans_with_1p}, 2p: {nchans_with_2p}')
        self.data_loaded.set()
        util.trigger_callback('gossip_db_loaded')

    def _update_num_policies_for_chan(self, short_channel_id: ShortChannelID) -> None:
        channel_info = self.get_channel_info(short_channel_id)
        if channel_info is None:
            with self.lock:
                self._chans_with_0_policies.discard(short_channel_id)
                self._chans_with_1_policies.discard(short_channel_id)
                self._chans_with_2_policies.discard(short_channel_id)
            return
        p1 = self.get_policy_for_node(short_channel_id, channel_info.node1_id)
        p2 = self.get_policy_for_node(short_channel_id, channel_info.node2_id)
        with self.lock:
            self._chans_with_0_policies.discard(short_channel_id)
            self._chans_with_1_policies.discard(short_channel_id)
            self._chans_with_2_policies.discard(short_channel_id)
            if p1 is not None and p2 is not None:
                self._chans_with_2_policies.add(short_channel_id)
            elif p1 is None and p2 is None:
                self._chans_with_0_policies.add(short_channel_id)
            else:
                self._chans_with_1_policies.add(short_channel_id)

    def get_num_channels_partitioned_by_policy_count(self) -> Tuple[int, int, int]:
        nchans_with_0p = len(self._chans_with_0_policies)
        nchans_with_1p = len(self._chans_with_1_policies)
        nchans_with_2p = len(self._chans_with_2_policies)
        return nchans_with_0p, nchans_with_1p, nchans_with_2p

    def get_policy_for_node(self, short_channel_id: bytes, node_id: bytes, *,
                            my_channels: Dict[ShortChannelID, 'Channel'] = None) -> Optional['Policy']:
        channel_info = self.get_channel_info(short_channel_id)
        if channel_info is not None:  # publicly announced channel
            policy = self._policies.get((node_id, short_channel_id))
            if policy:
                return policy
        else:  # private channel
            chan_upd_dict = self._channel_updates_for_private_channels.get((node_id, short_channel_id))
            if chan_upd_dict:
                return Policy.from_msg(chan_upd_dict)
        # check if it's one of our own channels
        if not my_channels:
            return
        chan = my_channels.get(short_channel_id)  # type: Optional[Channel]
        if not chan:
            return
        if node_id == chan.node_id:  # incoming direction (to us)
            remote_update_raw = chan.get_remote_update()
            if not remote_update_raw:
                return
            now = int(time.time())
            remote_update_decoded = decode_msg(remote_update_raw)[1]
            remote_update_decoded['timestamp'] = now
            remote_update_decoded['start_node'] = node_id
            return Policy.from_msg(remote_update_decoded)
        elif node_id == chan.get_local_pubkey():  # outgoing direction (from us)
            local_update_decoded = decode_msg(chan.get_outgoing_gossip_channel_update())[1]
            local_update_decoded['start_node'] = node_id
            return Policy.from_msg(local_update_decoded)

    def get_channel_info(self, short_channel_id: ShortChannelID, *,
                         my_channels: Dict[ShortChannelID, 'Channel'] = None) -> Optional[ChannelInfo]:
        ret = self._channels.get(short_channel_id)
        if ret:
            return ret
        # check if it's one of our own channels
        if not my_channels:
            return
        chan = my_channels.get(short_channel_id)  # type: Optional[Channel]
        ci = ChannelInfo.from_raw_msg(chan.construct_channel_announcement_without_sigs())
        return ci._replace(capacity_sat=chan.constraints.capacity)

    def get_channels_for_node(self, node_id: bytes, *,
                              my_channels: Dict[ShortChannelID, 'Channel'] = None) -> Set[bytes]:
        """Returns the set of short channel IDs where node_id is one of the channel participants."""
        if not self.data_loaded.is_set():
            raise Exception("channelDB data not loaded yet!")
        relevant_channels = self._channels_for_node.get(node_id) or set()
        relevant_channels = set(relevant_channels)  # copy
        # add our own channels  # TODO maybe slow?
        for chan in (my_channels.values() or []):
            if node_id in (chan.node_id, chan.get_local_pubkey()):
                relevant_channels.add(chan.short_channel_id)
        return relevant_channels

    def get_endnodes_for_chan(self, short_channel_id: ShortChannelID, *,
                              my_channels: Dict[ShortChannelID, 'Channel'] = None) -> Optional[Tuple[bytes, bytes]]:
        channel_info = self.get_channel_info(short_channel_id)
        if channel_info is not None:  # publicly announced channel
            return channel_info.node1_id, channel_info.node2_id
        # check if it's one of our own channels
        if not my_channels:
            return
        chan = my_channels.get(short_channel_id)  # type: Optional[Channel]
        if not chan:
            return
        return chan.get_local_pubkey(), chan.node_id

    def get_node_info_for_node_id(self, node_id: bytes) -> Optional['NodeInfo']:
        return self._nodes.get(node_id)
