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

from datetime import datetime
import time
import random
import queue
import os
import json
import threading
import concurrent
from collections import defaultdict
from typing import Sequence, List, Tuple, Optional, Dict, NamedTuple, TYPE_CHECKING, Set
import binascii
import base64

from sqlalchemy import Column, ForeignKey, Integer, String, Boolean
from sqlalchemy.orm.query import Query
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import not_, or_

from .sql_db import SqlDB, sql
from . import constants
from .util import bh2u, profiler, get_headers_dir, bfh, is_ip_address, list_enabled_bits, print_msg, chunks
from .logging import Logger
from .storage import JsonDB
from .lnverifier import LNChannelVerifier, verify_sig_for_channel_update
from .crypto import sha256d
from . import ecc
from .lnutil import (LN_GLOBAL_FEATURES_KNOWN_SET, LNPeerAddr, NUM_MAX_EDGES_IN_PAYMENT_PATH,
                     NotFoundChanAnnouncementForUpdate)
from .lnmsg import encode_msg

if TYPE_CHECKING:
    from .lnchannel import Channel
    from .network import Network

class UnknownEvenFeatureBits(Exception): pass

def validate_features(features : int):
    enabled_features = list_enabled_bits(features)
    for fbit in enabled_features:
        if (1 << fbit) not in LN_GLOBAL_FEATURES_KNOWN_SET and fbit % 2 == 0:
            raise UnknownEvenFeatureBits()

Base = declarative_base()

FLAG_DISABLE   = 1 << 1
FLAG_DIRECTION = 1 << 0

class ChannelInfo(Base):
    __tablename__ = 'channel_info'
    short_channel_id = Column(String(64), primary_key=True)
    node1_id = Column(String(66), ForeignKey('node_info.node_id'), nullable=False)
    node2_id = Column(String(66), ForeignKey('node_info.node_id'), nullable=False)
    capacity_sat = Column(Integer)
    msg_payload_hex = Column(String(1024), nullable=False)
    trusted = Column(Boolean, nullable=False)

    @staticmethod
    def from_msg(payload):
        features = int.from_bytes(payload['features'], 'big')
        validate_features(features)
        channel_id = payload['short_channel_id'].hex()
        node_id_1 = payload['node_id_1'].hex()
        node_id_2 = payload['node_id_2'].hex()
        assert list(sorted([node_id_1, node_id_2])) == [node_id_1, node_id_2]
        msg_payload_hex = encode_msg('channel_announcement', **payload).hex()
        capacity_sat = None
        return ChannelInfo(short_channel_id = channel_id, node1_id = node_id_1,
                node2_id = node_id_2, capacity_sat = capacity_sat, msg_payload_hex = msg_payload_hex,
                trusted = False)

    @property
    def msg_payload(self):
        return bytes.fromhex(self.msg_payload_hex)


class Policy(Base):
    __tablename__ = 'policy'
    start_node                  = Column(String(66), ForeignKey('node_info.node_id'), primary_key=True)
    short_channel_id            = Column(String(64), ForeignKey('channel_info.short_channel_id'), primary_key=True)
    cltv_expiry_delta           = Column(Integer, nullable=False)
    htlc_minimum_msat           = Column(Integer, nullable=False)
    htlc_maximum_msat           = Column(Integer)
    fee_base_msat               = Column(Integer, nullable=False)
    fee_proportional_millionths = Column(Integer, nullable=False)
    channel_flags               = Column(Integer, nullable=False)
    timestamp                   = Column(Integer, nullable=False)

    @staticmethod
    def from_msg(payload):
        cltv_expiry_delta           = int.from_bytes(payload['cltv_expiry_delta'], "big")
        htlc_minimum_msat           = int.from_bytes(payload['htlc_minimum_msat'], "big")
        htlc_maximum_msat           = int.from_bytes(payload['htlc_maximum_msat'], "big") if 'htlc_maximum_msat' in payload else None
        fee_base_msat               = int.from_bytes(payload['fee_base_msat'], "big")
        fee_proportional_millionths = int.from_bytes(payload['fee_proportional_millionths'], "big")
        channel_flags               = int.from_bytes(payload['channel_flags'], "big")
        timestamp                   = int.from_bytes(payload['timestamp'], "big")
        start_node                  = payload['start_node'].hex()
        short_channel_id            = payload['short_channel_id'].hex()

        return Policy(start_node=start_node,
                short_channel_id=short_channel_id,
                cltv_expiry_delta=cltv_expiry_delta,
                htlc_minimum_msat=htlc_minimum_msat,
                fee_base_msat=fee_base_msat,
                fee_proportional_millionths=fee_proportional_millionths,
                channel_flags=channel_flags,
                timestamp=timestamp,
                htlc_maximum_msat=htlc_maximum_msat)

    def is_disabled(self):
        return self.channel_flags & FLAG_DISABLE

class NodeInfo(Base):
    __tablename__ = 'node_info'
    node_id = Column(String(66), primary_key=True, sqlite_on_conflict_primary_key='REPLACE')
    features = Column(Integer, nullable=False)
    timestamp = Column(Integer, nullable=False)
    alias = Column(String(64), nullable=False)

    @staticmethod
    def from_msg(payload):
        node_id = payload['node_id'].hex()
        features = int.from_bytes(payload['features'], "big")
        validate_features(features)
        addresses = NodeInfo.parse_addresses_field(payload['addresses'])
        alias = payload['alias'].rstrip(b'\x00').hex()
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

class Address(Base):
    __tablename__ = 'address'
    node_id = Column(String(66), ForeignKey('node_info.node_id'), primary_key=True)
    host = Column(String(256), primary_key=True)
    port = Column(Integer, primary_key=True)
    last_connected_date = Column(Integer(), nullable=True)



class ChannelDB(SqlDB):

    NUM_MAX_RECENT_PEERS = 20

    def __init__(self, network: 'Network'):
        path = os.path.join(get_headers_dir(network.config), 'channel_db')
        super().__init__(network, path, Base)
        self.num_nodes = 0
        self.num_channels = 0
        self._channel_updates_for_private_channels = {}  # type: Dict[Tuple[bytes, bytes], dict]
        self.ca_verifier = LNChannelVerifier(network, self)
        self.update_counts()

    @sql
    def update_counts(self):
        self._update_counts()

    def _update_counts(self):
        self.num_channels = self.DBSession.query(ChannelInfo).count()
        self.num_policies = self.DBSession.query(Policy).count()
        self.num_nodes = self.DBSession.query(NodeInfo).count()

    @sql
    def known_ids(self):
        known = self.DBSession.query(ChannelInfo.short_channel_id).all()
        return set(bfh(r.short_channel_id) for r in known)

    @sql
    def add_recent_peer(self, peer: LNPeerAddr):
        now = int(time.time())
        node_id = peer.pubkey.hex()
        addr = self.DBSession.query(Address).filter_by(node_id=node_id, host=peer.host, port=peer.port).one_or_none()
        if addr:
            addr.last_connected_date = now
        else:
            addr = Address(node_id=node_id, host=peer.host, port=peer.port, last_connected_date=now)
            self.DBSession.add(addr)
        self.DBSession.commit()

    @sql
    def get_200_randomly_sorted_nodes_not_in(self, node_ids_bytes):
        unshuffled = self.DBSession \
            .query(NodeInfo) \
            .filter(not_(NodeInfo.node_id.in_(x.hex() for x in node_ids_bytes))) \
            .limit(200) \
            .all()
        return random.sample(unshuffled, len(unshuffled))

    @sql
    def nodes_get(self, node_id):
        return self.DBSession \
            .query(NodeInfo) \
            .filter_by(node_id = node_id.hex()) \
            .one_or_none()

    @sql
    def get_last_good_address(self, node_id) -> Optional[LNPeerAddr]:
        r = self.DBSession.query(Address).filter_by(node_id=node_id.hex()).order_by(Address.last_connected_date.desc()).all()
        if not r:
            return None
        addr = r[0]
        return LNPeerAddr(addr.host, addr.port, bytes.fromhex(addr.node_id))

    @sql
    def get_recent_peers(self):
        r = self.DBSession.query(Address).filter(Address.last_connected_date.isnot(None)).order_by(Address.last_connected_date.desc()).limit(self.NUM_MAX_RECENT_PEERS).all()
        return [LNPeerAddr(x.host, x.port, bytes.fromhex(x.node_id)) for x in r]

    @sql
    def missing_channel_announcements(self) -> Set[int]:
        expr = not_(Policy.short_channel_id.in_(self.DBSession.query(ChannelInfo.short_channel_id)))
        return set(x[0] for x in self.DBSession.query(Policy.short_channel_id).filter(expr).all())

    @sql
    def missing_channel_updates(self) -> Set[int]:
        expr = not_(ChannelInfo.short_channel_id.in_(self.DBSession.query(Policy.short_channel_id)))
        return set(x[0] for x in self.DBSession.query(ChannelInfo.short_channel_id).filter(expr).all())

    @sql
    def add_verified_channel_info(self, short_id, capacity):
        # called from lnchannelverifier
        channel_info = self.DBSession.query(ChannelInfo).filter_by(short_channel_id = short_id.hex()).one_or_none()
        channel_info.trusted = True
        channel_info.capacity = capacity
        self.DBSession.commit()

    @sql
    @profiler
    def on_channel_announcement(self, msg_payloads, trusted=True):
        if type(msg_payloads) is dict:
            msg_payloads = [msg_payloads]
        new_channels = {}
        for msg in msg_payloads:
            short_channel_id = bh2u(msg['short_channel_id'])
            if self.DBSession.query(ChannelInfo).filter_by(short_channel_id=short_channel_id).count():
                continue
            if constants.net.rev_genesis_bytes() != msg['chain_hash']:
                self.logger.info("ChanAnn has unexpected chain_hash {}".format(bh2u(msg['chain_hash'])))
                continue
            try:
                channel_info = ChannelInfo.from_msg(msg)
            except UnknownEvenFeatureBits:
                self.logger.info("unknown feature bits")
                continue
            channel_info.trusted = trusted
            new_channels[short_channel_id] = channel_info
            if not trusted:
                self.ca_verifier.add_new_channel_info(channel_info.short_channel_id, channel_info.msg_payload)
        for channel_info in new_channels.values():
            self.DBSession.add(channel_info)
        self.DBSession.commit()
        self._update_counts()
        self.logger.debug('on_channel_announcement: %d/%d'%(len(new_channels), len(msg_payloads)))

    @sql
    def get_last_timestamp(self):
        return self._get_last_timestamp()

    def _get_last_timestamp(self):
        from sqlalchemy.sql import func
        r = self.DBSession.query(func.max(Policy.timestamp).label('max_timestamp')).one()
        return r.max_timestamp or 0

    def print_change(self, old_policy, new_policy):
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

    @sql
    def get_info_for_updates(self, payloads):
        short_channel_ids = [payload['short_channel_id'].hex() for payload in payloads]
        channel_infos_list = self.DBSession.query(ChannelInfo).filter(ChannelInfo.short_channel_id.in_(short_channel_ids)).all()
        channel_infos = {bfh(x.short_channel_id): x for x in channel_infos_list}
        return channel_infos

    @sql
    def get_policies_for_updates(self, payloads):
        out = {}
        for payload in payloads:
            short_channel_id = payload['short_channel_id'].hex()
            start_node = payload['start_node'].hex()
            policy = self.DBSession.query(Policy).filter_by(short_channel_id=short_channel_id, start_node=start_node).one_or_none()
            if policy:
                out[short_channel_id+start_node] = policy
        return out

    @profiler
    def filter_channel_updates(self, payloads, max_age=None):
        orphaned = []      # no channel announcement for channel update
        expired = []       # update older than two weeks
        deprecated = []    # update older than database entry
        good = {}          # good updates
        to_delete = []     # database entries to delete
        # filter orphaned and expired first
        known = []
        now = int(time.time())
        channel_infos = self.get_info_for_updates(payloads)
        for payload in payloads:
            short_channel_id = payload['short_channel_id']
            timestamp = int.from_bytes(payload['timestamp'], "big")
            if max_age and now - timestamp > max_age:
                expired.append(short_channel_id)
                continue
            channel_info = channel_infos.get(short_channel_id)
            if not channel_info:
                orphaned.append(short_channel_id)
                continue
            flags = int.from_bytes(payload['channel_flags'], 'big')
            direction = flags & FLAG_DIRECTION
            start_node = channel_info.node1_id if direction == 0 else channel_info.node2_id
            payload['start_node'] = bfh(start_node)
            known.append(payload)
        # compare updates to existing database entries
        old_policies = self.get_policies_for_updates(known)
        for payload in known:
            timestamp = int.from_bytes(payload['timestamp'], "big")
            start_node = payload['start_node']
            short_channel_id = payload['short_channel_id']
            key = (short_channel_id+start_node).hex()
            old_policy = old_policies.get(key)
            if old_policy:
                if timestamp <= old_policy.timestamp:
                    deprecated.append(short_channel_id)
                else:
                    good[key] = payload
                    to_delete.append(old_policy)
            else:
                good[key] = payload
        good = list(good.values())
        return orphaned, expired, deprecated, good, to_delete

    def add_channel_update(self, payload):
        orphaned, expired, deprecated, good, to_delete = self.filter_channel_updates([payload])
        assert len(good) == 1
        self.update_policies(good, to_delete)

    @sql
    @profiler
    def update_policies(self, to_add, to_delete):
        for policy in to_delete:
            self.DBSession.delete(policy)
        self.DBSession.commit()
        for payload in to_add:
            policy = Policy.from_msg(payload)
            self.DBSession.add(policy)
        self.DBSession.commit()
        self._update_counts()

    @sql
    @profiler
    def on_node_announcement(self, msg_payloads):
        if type(msg_payloads) is dict:
            msg_payloads = [msg_payloads]
        old_addr = None
        new_nodes = {}
        new_addresses = {}
        for msg_payload in msg_payloads:
            try:
                node_info, node_addresses = NodeInfo.from_msg(msg_payload)
            except UnknownEvenFeatureBits:
                continue
            node_id = node_info.node_id
            # Ignore node if it has no associated channel (DoS protection)
            # FIXME this is slow
            expr = or_(ChannelInfo.node1_id==node_id, ChannelInfo.node2_id==node_id)
            if len(self.DBSession.query(ChannelInfo.short_channel_id).filter(expr).limit(1).all()) == 0:
                #self.logger.info('ignoring orphan node_announcement')
                continue
            node = self.DBSession.query(NodeInfo).filter_by(node_id=node_id).one_or_none()
            if node and node.timestamp >= node_info.timestamp:
                continue
            node = new_nodes.get(node_id)
            if node and node.timestamp >= node_info.timestamp:
                continue
            new_nodes[node_id] = node_info
            for addr in node_addresses:
                new_addresses[(addr.node_id,addr.host,addr.port)] = addr
        self.logger.debug("on_node_announcement: %d/%d"%(len(new_nodes), len(msg_payloads)))
        for node_info in new_nodes.values():
            self.DBSession.add(node_info)
        for new_addr in new_addresses.values():
            old_addr = self.DBSession.query(Address).filter_by(node_id=new_addr.node_id, host=new_addr.host, port=new_addr.port).one_or_none()
            if not old_addr:
                self.DBSession.add(new_addr)
        self.DBSession.commit()
        self._update_counts()

    def get_routing_policy_for_channel(self, start_node_id: bytes,
                                       short_channel_id: bytes) -> Optional[bytes]:
        if not start_node_id or not short_channel_id: return None
        channel_info = self.get_channel_info(short_channel_id)
        if channel_info is not None:
            return self.get_policy_for_node(short_channel_id, start_node_id)
        msg = self._channel_updates_for_private_channels.get((start_node_id, short_channel_id))
        if not msg:
            return None
        return Policy.from_msg(msg) # won't actually be written to DB

    @sql
    @profiler
    def get_old_policies(self, delta):
        timestamp = int(time.time()) - delta
        old_policies = self.DBSession.query(Policy.short_channel_id).filter(Policy.timestamp <= timestamp)
        return old_policies.distinct().count()

    @sql
    @profiler
    def prune_old_policies(self, delta):
        # note: delete queries are order sensitive
        timestamp = int(time.time()) - delta
        old_policies = self.DBSession.query(Policy.short_channel_id).filter(Policy.timestamp <= timestamp)
        delete_old_channels = ChannelInfo.__table__.delete().where(ChannelInfo.short_channel_id.in_(old_policies))
        delete_old_policies = Policy.__table__.delete().where(Policy.timestamp <= timestamp)
        self.DBSession.execute(delete_old_channels)
        self.DBSession.execute(delete_old_policies)
        self.DBSession.commit()
        self._update_counts()

    @sql
    @profiler
    def get_orphaned_channels(self):
        subquery = self.DBSession.query(Policy.short_channel_id)
        orphaned = self.DBSession.query(ChannelInfo).filter(not_(ChannelInfo.short_channel_id.in_(subquery)))
        return orphaned.count()

    @sql
    @profiler
    def prune_orphaned_channels(self):
        subquery = self.DBSession.query(Policy.short_channel_id)
        delete_orphaned = ChannelInfo.__table__.delete().where(not_(ChannelInfo.short_channel_id.in_(subquery)))
        self.DBSession.execute(delete_orphaned)
        self.DBSession.commit()
        self._update_counts()

    def add_channel_update_for_private_channel(self, msg_payload: dict, start_node_id: bytes):
        if not verify_sig_for_channel_update(msg_payload, start_node_id):
            return  # ignore
        short_channel_id = msg_payload['short_channel_id']
        msg_payload['start_node'] = start_node_id
        self._channel_updates_for_private_channels[(start_node_id, short_channel_id)] = msg_payload

    @sql
    def remove_channel(self, short_channel_id):
        r = self.DBSession.query(ChannelInfo).filter_by(short_channel_id = short_channel_id.hex()).one_or_none()
        if not r:
            return
        self.DBSession.delete(r)
        self.DBSession.commit()

    def print_graph(self, full_ids=False):
        # used for debugging.
        # FIXME there is a race here - iterables could change size from another thread
        def other_node_id(node_id, channel_id):
            channel_info = self.get_channel_info(channel_id)
            if node_id == channel_info.node1_id:
                other = channel_info.node2_id
            else:
                other = channel_info.node1_id
            return other if full_ids else other[-4:]

        print_msg('nodes')
        for node in self.DBSession.query(NodeInfo).all():
            print_msg(node)

        print_msg('channels')
        for channel_info in self.DBSession.query(ChannelInfo).all():
            short_channel_id = channel_info.short_channel_id
            node1 = channel_info.node1_id
            node2 = channel_info.node2_id
            direction1 = self.get_policy_for_node(channel_info, node1) is not None
            direction2 = self.get_policy_for_node(channel_info, node2) is not None
            if direction1 and direction2:
                direction = 'both'
            elif direction1:
                direction = 'forward'
            elif direction2:
                direction = 'backward'
            else:
                direction = 'none'
            print_msg('{}: {}, {}, {}'
                           .format(bh2u(short_channel_id),
                                   bh2u(node1) if full_ids else bh2u(node1[-4:]),
                                   bh2u(node2) if full_ids else bh2u(node2[-4:]),
                                   direction))


    @sql
    def get_node_addresses(self, node_info):
        return self.DBSession.query(Address).join(NodeInfo).filter_by(node_id = node_info.node_id).all()

    @sql
    @profiler
    def load_data(self):
        r = self.DBSession.query(ChannelInfo).all()
        self._channels = dict([(bfh(x.short_channel_id), x) for x in r])
        r = self.DBSession.query(Policy).filter_by().all()
        self._policies = dict([((bfh(x.start_node), bfh(x.short_channel_id)), x) for x in r])
        self._channels_for_node = defaultdict(set)
        for channel_info in self._channels.values():
            self._channels_for_node[bfh(channel_info.node1_id)].add(bfh(channel_info.short_channel_id))
            self._channels_for_node[bfh(channel_info.node2_id)].add(bfh(channel_info.short_channel_id))
        self.logger.info(f'load data {len(self._channels)} {len(self._policies)} {len(self._channels_for_node)}')

    def get_policy_for_node(self, short_channel_id: bytes, node_id: bytes) -> Optional['Policy']:
        return self._policies.get((node_id, short_channel_id))

    def get_channel_info(self, channel_id: bytes):
        return self._channels.get(channel_id)

    def get_channels_for_node(self, node_id) -> Set[bytes]:
        """Returns the set of channels that have node_id as one of the endpoints."""
        return self._channels_for_node.get(node_id) or set()



