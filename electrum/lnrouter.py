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

import datetime
import random
import queue
import os
import json
import threading
from collections import defaultdict
from typing import Sequence, List, Tuple, Optional, Dict, NamedTuple, TYPE_CHECKING
import binascii
import base64
import asyncio

from sqlalchemy import create_engine, Column, ForeignKey, Integer, String, DateTime, Boolean
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.query import Query
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import not_, or_
from sqlalchemy.orm import scoped_session

from . import constants
from .util import PrintError, bh2u, profiler, get_headers_dir, bfh, is_ip_address, list_enabled_bits
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
class NoChannelPolicy(Exception):
    def __init__(self, short_channel_id: bytes):
        super().__init__(f'cannot find channel policy for short_channel_id: {bh2u(short_channel_id)}')

def validate_features(features : int):
    enabled_features = list_enabled_bits(features)
    for fbit in enabled_features:
        if (1 << fbit) not in LN_GLOBAL_FEATURES_KNOWN_SET and fbit % 2 == 0:
            raise UnknownEvenFeatureBits()

Base = declarative_base()
session_factory = sessionmaker()
DBSession = scoped_session(session_factory)

FLAG_DISABLE   = 1 << 1
FLAG_DIRECTION = 1 << 0

class ChannelInfoInDB(Base):
    __tablename__ = 'channel_info'
    short_channel_id = Column(String(64), primary_key=True)
    node1_id = Column(String(66), ForeignKey('node_info.node_id'), nullable=False)
    node2_id = Column(String(66), ForeignKey('node_info.node_id'), nullable=False)
    capacity_sat = Column(Integer)
    msg_payload_hex = Column(String(1024), nullable=False)
    trusted = Column(Boolean, nullable=False)

    @staticmethod
    def from_msg(channel_announcement_payload):
        features = int.from_bytes(channel_announcement_payload['features'], 'big')
        validate_features(features)

        channel_id = channel_announcement_payload['short_channel_id'].hex()
        node_id_1 = channel_announcement_payload['node_id_1'].hex()
        node_id_2 = channel_announcement_payload['node_id_2'].hex()
        assert list(sorted([node_id_1, node_id_2])) == [node_id_1, node_id_2]

        msg_payload_hex = encode_msg('channel_announcement', **channel_announcement_payload).hex()

        capacity_sat = None

        return ChannelInfoInDB(short_channel_id = channel_id, node1_id = node_id_1,
                node2_id = node_id_2, capacity_sat = capacity_sat, msg_payload_hex = msg_payload_hex,
                trusted = False)

    @property
    def msg_payload(self):
        return bytes.fromhex(self.msg_payload_hex)

    def on_channel_update(self, msg: dict, trusted=False):
        assert self.short_channel_id == msg['short_channel_id'].hex()
        flags = int.from_bytes(msg['channel_flags'], 'big')
        direction = flags & FLAG_DIRECTION
        if direction == 0:
            node_id = self.node1_id
        else:
            node_id = self.node2_id
        new_policy = Policy.from_msg(msg, node_id, self.short_channel_id)
        old_policy = DBSession.query(Policy).filter_by(short_channel_id = self.short_channel_id, start_node=node_id).one_or_none()
        if not old_policy:
            DBSession.add(new_policy)
            return
        if old_policy.timestamp >= new_policy.timestamp:
            return  # ignore
        if not trusted and not verify_sig_for_channel_update(msg, bytes.fromhex(node_id)):
            return  # ignore
        old_policy.cltv_expiry_delta           = new_policy.cltv_expiry_delta
        old_policy.htlc_minimum_msat           = new_policy.htlc_minimum_msat
        old_policy.htlc_maximum_msat           = new_policy.htlc_maximum_msat
        old_policy.fee_base_msat               = new_policy.fee_base_msat
        old_policy.fee_proportional_millionths = new_policy.fee_proportional_millionths
        old_policy.channel_flags               = new_policy.channel_flags
        old_policy.timestamp                   = new_policy.timestamp

    def get_policy_for_node(self, node) -> Optional['Policy']:
        """
        raises when initiator/non-initiator both unequal node
        """
        if node.hex() not in (self.node1_id, self.node2_id):
            raise Exception("the given node is not a party in this channel")
        n1 = DBSession.query(Policy).filter_by(short_channel_id = self.short_channel_id, start_node = self.node1_id).one_or_none()
        if n1:
            return n1
        n2 = DBSession.query(Policy).filter_by(short_channel_id = self.short_channel_id, start_node = self.node2_id).one_or_none()
        return n2

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
    timestamp                   = Column(DateTime, nullable=False)

    @staticmethod
    def from_msg(channel_update_payload, start_node, short_channel_id):
        cltv_expiry_delta           = channel_update_payload['cltv_expiry_delta']
        htlc_minimum_msat           = channel_update_payload['htlc_minimum_msat']
        fee_base_msat               = channel_update_payload['fee_base_msat']
        fee_proportional_millionths = channel_update_payload['fee_proportional_millionths']
        channel_flags               = channel_update_payload['channel_flags']
        timestamp                   = channel_update_payload['timestamp']
        htlc_maximum_msat           = channel_update_payload.get('htlc_maximum_msat')  # optional

        cltv_expiry_delta           = int.from_bytes(cltv_expiry_delta, "big")
        htlc_minimum_msat           = int.from_bytes(htlc_minimum_msat, "big")
        htlc_maximum_msat           = int.from_bytes(htlc_maximum_msat, "big") if htlc_maximum_msat else None
        fee_base_msat               = int.from_bytes(fee_base_msat, "big")
        fee_proportional_millionths = int.from_bytes(fee_proportional_millionths, "big")
        channel_flags               = int.from_bytes(channel_flags, "big")
        timestamp                   = datetime.datetime.fromtimestamp(int.from_bytes(timestamp, "big"))

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

class NodeInfoInDB(Base):
    __tablename__ = 'node_info'
    node_id = Column(String(66), primary_key=True, sqlite_on_conflict_primary_key='REPLACE')
    features = Column(Integer, nullable=False)
    timestamp = Column(Integer, nullable=False)
    alias = Column(String(64), nullable=False)

    def get_addresses(self):
        return DBSession.query(AddressInDB).join(NodeInfoInDB).filter_by(node_id = self.node_id).all()

    @staticmethod
    def from_msg(node_announcement_payload, addresses_already_parsed=False):
        node_id = node_announcement_payload['node_id'].hex()
        features = int.from_bytes(node_announcement_payload['features'], "big")
        validate_features(features)
        if not addresses_already_parsed:
            addresses = NodeInfoInDB.parse_addresses_field(node_announcement_payload['addresses'])
        else:
            addresses = node_announcement_payload['addresses']
        alias = node_announcement_payload['alias'].rstrip(b'\x00').hex()
        timestamp = datetime.datetime.fromtimestamp(int.from_bytes(node_announcement_payload['timestamp'], "big"))
        return NodeInfoInDB(node_id=node_id, features=features, timestamp=timestamp, alias=alias), [AddressInDB(host=host, port=port, node_id=node_id, last_connected_date=datetime.datetime.now()) for host, port in addresses]

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

class AddressInDB(Base):
    __tablename__ = 'address'
    node_id = Column(String(66), ForeignKey('node_info.node_id'), primary_key=True)
    host = Column(String(256), primary_key=True)
    port = Column(Integer, primary_key=True)
    last_connected_date = Column(DateTime(), nullable=False)

class ChannelDB:

    NUM_MAX_RECENT_PEERS = 20

    def __init__(self, network: 'Network'):
        self.network = network

        self.num_nodes = 0
        self.num_channels = 0

        self.path = os.path.join(get_headers_dir(network.config), 'channel_db.sqlite3')

        # (intentionally not persisted)
        self._channel_updates_for_private_channels = {}  # type: Dict[Tuple[bytes, bytes], dict]

        self.ca_verifier = LNChannelVerifier(network, self)

        self.network.run_from_another_thread(self.sqlinit())

    async def sqlinit(self):
        """
        this has to run on the async thread since that is where
        the lnpeer loop is running from, which will do call in here
        """
        engine = create_engine('sqlite:///' + self.path, pool_reset_on_return=None, poolclass=StaticPool)#, echo=True)
        DBSession.remove()
        DBSession.configure(bind=engine, autoflush=False)

        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)

    def update_counts(self):
        self.num_channels = DBSession.query(ChannelInfoInDB).count()
        self.num_nodes = DBSession.query(NodeInfoInDB).count()

    def add_recent_peer(self, peer : LNPeerAddr):
        addr = DBSession.query(AddressInDB).filter_by(node_id = peer.pubkey.hex()).one_or_none()
        if addr is None:
            addr = AddressInDB(node_id = peer.pubkey.hex(), host = peer.host, port = peer.port, last_connected_date = datetime.datetime.now())
        else:
            addr.last_connected_date = datetime.datetime.now()
        DBSession.add(addr)
        DBSession.commit()

    def get_200_randomly_sorted_nodes_not_in(self, node_ids_bytes):
        unshuffled = DBSession \
            .query(NodeInfoInDB) \
            .filter(not_(NodeInfoInDB.node_id.in_(x.hex() for x in node_ids_bytes))) \
            .limit(200) \
            .all()
        return random.sample(unshuffled, len(unshuffled))

    def nodes_get(self, node_id):
        return self.network.run_from_another_thread(self._nodes_get(node_id))

    async def _nodes_get(self, node_id):
        return DBSession \
            .query(NodeInfoInDB) \
            .filter_by(node_id = node_id.hex()) \
            .one_or_none()

    def get_last_good_address(self, node_id) -> Optional[LNPeerAddr]:
        adr_db = DBSession \
            .query(AddressInDB) \
            .filter_by(node_id = node_id.hex()) \
            .order_by(AddressInDB.last_connected_date.desc()) \
            .one_or_none()
        if not adr_db:
            return None
        return LNPeerAddr(adr_db.host, adr_db.port, bytes.fromhex(adr_db.node_id))

    def get_recent_peers(self):
        return [LNPeerAddr(x.host, x.port, bytes.fromhex(x.node_id)) for x in DBSession \
            .query(AddressInDB) \
            .select_from(NodeInfoInDB) \
            .order_by(AddressInDB.last_connected_date.desc()) \
            .limit(self.NUM_MAX_RECENT_PEERS)]

    def get_channel_info(self, channel_id: bytes):
        return self.chan_query_for_id(channel_id).one_or_none()

    def get_channels_for_node(self, node_id):
        """Returns the set of channels that have node_id as one of the endpoints."""
        condition = or_(
                 ChannelInfoInDB.node1_id == node_id.hex(),
                 ChannelInfoInDB.node2_id == node_id.hex())
        rows = DBSession.query(ChannelInfoInDB).filter(condition).all()
        return [bytes.fromhex(x.short_channel_id) for x in rows]

    def add_verified_channel_info(self, short_id, capacity):
        # called from lnchannelverifier
        channel_info = self.get_channel_info(short_id)
        channel_info.trusted = True
        channel_info.capacity = capacity
        DBSession.commit()

    @profiler
    def on_channel_announcement(self, msg_payloads, trusted=False):
        if type(msg_payloads) is dict:
            msg_payloads = [msg_payloads]
        for msg in msg_payloads:
            short_channel_id = msg['short_channel_id']
            if DBSession.query(ChannelInfoInDB).filter_by(short_channel_id = bh2u(short_channel_id)).count():
                continue
            if constants.net.rev_genesis_bytes() != msg['chain_hash']:
                #self.print_error("ChanAnn has unexpected chain_hash {}".format(bh2u(msg_payload['chain_hash'])))
                continue
            try:
                channel_info = ChannelInfoInDB.from_msg(msg)
            except UnknownEvenFeatureBits:
                continue
            channel_info.trusted = trusted
            DBSession.add(channel_info)
            if not trusted: self.ca_verifier.add_new_channel_info(channel_info.short_channel_id, channel_info.msg_payload)
        DBSession.commit()
        self.network.trigger_callback('ln_status')
        self.update_counts()

    @profiler
    def on_channel_update(self, msg_payloads, trusted=False):
        if type(msg_payloads) is dict:
            msg_payloads = [msg_payloads]
        short_channel_ids = [msg_payload['short_channel_id'].hex() for msg_payload in msg_payloads]
        channel_infos_list = DBSession.query(ChannelInfoInDB).filter(ChannelInfoInDB.short_channel_id.in_(short_channel_ids)).all()
        channel_infos = {bfh(x.short_channel_id): x for x in channel_infos_list}
        for msg_payload in msg_payloads:
            short_channel_id = msg_payload['short_channel_id']
            if constants.net.rev_genesis_bytes() != msg_payload['chain_hash']:
                continue
            channel_info = channel_infos.get(short_channel_id)
            channel_info.on_channel_update(msg_payload, trusted=trusted)
        DBSession.commit()

    @profiler
    def on_node_announcement(self, msg_payloads):
        if type(msg_payloads) is dict:
            msg_payloads = [msg_payloads]
        addresses = DBSession.query(AddressInDB).all()
        have_addr = {}
        for addr in addresses:
            have_addr[(addr.node_id, addr.host, addr.port)] = addr

        nodes = DBSession.query(NodeInfoInDB).all()
        timestamps = {}
        for node in nodes:
            no_millisecs = node.timestamp[:len("0000-00-00 00:00:00")]
            timestamps[bfh(node.node_id)] = datetime.datetime.strptime(no_millisecs, "%Y-%m-%d %H:%M:%S")
        old_addr = None
        for msg_payload in msg_payloads:
            pubkey = msg_payload['node_id']
            signature = msg_payload['signature']
            h = sha256d(msg_payload['raw'][66:])
            if not ecc.verify_signature(pubkey, signature, h):
                continue
            try:
                new_node_info, addresses = NodeInfoInDB.from_msg(msg_payload)
            except UnknownEvenFeatureBits:
                continue
            if timestamps.get(pubkey) and timestamps[pubkey] >= new_node_info.timestamp:
                continue  # ignore
            DBSession.add(new_node_info)
            for new_addr in addresses:
                key = (new_addr.node_id, new_addr.host, new_addr.port)
                old_addr = have_addr.get(key)
                if old_addr:
                    # since old_addr is embedded in have_addr,
                    # it will still live when commmit is called
                    old_addr.last_connected_date = new_addr.last_connected_date
                    del new_addr
                else:
                    DBSession.add(new_addr)
                    have_addr[key] = new_addr
            # TODO if this message is for a new node, and if we have no associated
            # channels for this node, we should ignore the message and return here,
            # to mitigate DOS. but race condition: the channels we have for this
            # node, might be under verification in self.ca_verifier, what then?
        del nodes, addresses
        if old_addr:
            del old_addr
        DBSession.commit()
        self.network.trigger_callback('ln_status')
        self.update_counts()

    def get_routing_policy_for_channel(self, start_node_id: bytes,
                                       short_channel_id: bytes) -> Optional[bytes]:
        if not start_node_id or not short_channel_id: return None
        channel_info = self.get_channel_info(short_channel_id)
        if channel_info is not None:
            return channel_info.get_policy_for_node(start_node_id)
        msg = self._channel_updates_for_private_channels.get((start_node_id, short_channel_id))
        if not msg: return None
        return Policy.from_msg(msg, None, short_channel_id) # won't actually be written to DB

    def add_channel_update_for_private_channel(self, msg_payload: dict, start_node_id: bytes):
        if not verify_sig_for_channel_update(msg_payload, start_node_id):
            return  # ignore
        short_channel_id = msg_payload['short_channel_id']
        self._channel_updates_for_private_channels[(start_node_id, short_channel_id)] = msg_payload

    def remove_channel(self, short_channel_id):
        self.chan_query_for_id(short_channel_id).delete('evaluate')
        DBSession.commit()

    def chan_query_for_id(self, short_channel_id) -> Query:
        return DBSession.query(ChannelInfoInDB).filter_by(short_channel_id = short_channel_id.hex())

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

        self.print_msg('nodes')
        for node in DBSession.query(NodeInfoInDB).all():
            self.print_msg(node)

        self.print_msg('channels')
        for channel_info in DBSession.query(ChannelInfoInDB).all():
            node1 = channel_info.node1_id
            node2 = channel_info.node2_id
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
    def from_channel_policy(cls, channel_policy: 'Policy',
                            short_channel_id: bytes, end_node: bytes) -> 'RouteEdge':
        assert type(short_channel_id) is bytes
        assert type(end_node) is bytes
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
        if channel_policy.is_disabled(): return float('inf'), 0
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

        # FIXME paths cannot be longer than 21 edges (onion packet)...

        # run Dijkstra
        # The search is run in the REVERSE direction, from nodeB to nodeA,
        # to properly calculate compound routing fees.
        distance_from_start = defaultdict(lambda: float('inf'))
        distance_from_start[nodeB] = 0
        prev_node = {}
        nodes_to_explore = queue.PriorityQueue()
        nodes_to_explore.put((0, invoice_amount_msat, nodeB))  # order of fields (in tuple) matters!

        def inspect_edge():
            if edge_channel_id in my_channels:
                if edge_startnode == nodeA:  # payment outgoing, on our channel
                    if not my_channels[edge_channel_id].can_pay(amount_msat):
                        return
                else:  # payment incoming, on our channel. (funny business, cycle weirdness)
                    assert edge_endnode == nodeA, (bh2u(edge_startnode), bh2u(edge_endnode))
                    pass  # TODO?
            edge_cost, fee_for_edge_msat = self._edge_cost(edge_channel_id,
                                                           start_node=edge_startnode,
                                                           end_node=edge_endnode,
                                                           payment_amt_msat=amount_msat,
                                                           ignore_costs=(edge_startnode == nodeA))
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
                assert type(edge_channel_id) is bytes
                if edge_channel_id in self.blacklist: continue
                channel_info = self.channel_db.get_channel_info(edge_channel_id)
                edge_startnode = bfh(channel_info.node2_id) if bfh(channel_info.node1_id) == edge_endnode else bfh(channel_info.node1_id)
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

    def create_route_from_path(self, path, from_node_id: bytes) -> List[RouteEdge]:
        assert type(from_node_id) is bytes
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
