# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import os
from decimal import Decimal
import random
import time
import operator
import enum
from enum import IntEnum, Enum
from typing import (Optional, Sequence, Tuple, List, Set, Dict, TYPE_CHECKING,
                    NamedTuple, Union, Mapping, Any, Iterable, AsyncGenerator, DefaultDict, Callable, Awaitable)
import threading
import socket
import json
from datetime import datetime, timezone
from functools import partial, cached_property
from collections import defaultdict
import concurrent
from concurrent import futures
import urllib.parse
import itertools

import aiohttp
import dns.resolver
import dns.exception
from aiorpcx import run_in_thread, NetAddress, ignore_after

from . import constants, util
from . import keystore
from .util import profiler, chunks, OldTaskGroup
from .invoices import Invoice, PR_UNPAID, PR_EXPIRED, PR_PAID, PR_INFLIGHT, PR_FAILED, PR_ROUTING, LN_EXPIRY_NEVER
from .invoices import BaseInvoice
from .util import NetworkRetryManager, JsonRPCClient, NotEnoughFunds
from .util import EventListener, event_listener
from .keystore import BIP32_KeyStore
from .bitcoin import COIN
from .bitcoin import opcodes, make_op_return, address_to_scripthash
from .transaction import Transaction
from .transaction import get_script_type_from_output_script
from .crypto import sha256
from .bip32 import BIP32Node
from .util import bfh, InvoiceError, resolve_dns_srv, is_ip_address, log_exceptions
from .crypto import chacha20_encrypt, chacha20_decrypt
from .util import ignore_exceptions, make_aiohttp_session
from .util import timestamp_to_datetime, random_shuffled_copy
from .util import MyEncoder, is_private_netaddress, UnrelatedTransactionException
from .logging import Logger
from .lntransport import LNTransport, LNResponderTransport, LNTransportBase
from .lnpeer import Peer, LN_P2P_NETWORK_TIMEOUT
from .lnaddr import lnencode, LnAddr, lndecode
from .ecc import ecdsa_der_sig_from_ecdsa_sig64
from .lnchannel import Channel, AbstractChannel
from .lnchannel import ChannelState, PeerState, HTLCWithStatus
from .lnrater import LNRater
from . import lnutil
from .lnutil import funding_output_script
from .lnutil import serialize_htlc_key, deserialize_htlc_key
from .bitcoin import DummyAddress
from .lnutil import (Outpoint, LNPeerAddr,
                     get_compressed_pubkey_from_bech32, extract_nodeid,
                     PaymentFailure, split_host_port, ConnStringFormatError,
                     generate_keypair, LnKeyFamily, LOCAL, REMOTE,
                     MIN_FINAL_CLTV_DELTA_FOR_INVOICE,
                     NUM_MAX_EDGES_IN_PAYMENT_PATH, SENT, RECEIVED, HTLCOwner,
                     UpdateAddHtlc, Direction, LnFeatures, ShortChannelID,
                     HtlcLog, derive_payment_secret_from_payment_preimage,
                     NoPathFound, InvalidGossipMsg)
from .lnutil import ln_compare_features, IncompatibleLightningFeatures, PaymentFeeBudget
from .transaction import PartialTxOutput, PartialTransaction, PartialTxInput
from .lnonion import decode_onion_error, OnionFailureCode, OnionRoutingFailure, OnionPacket
from .lnmsg import decode_msg
from .i18n import _
from .lnrouter import (RouteEdge, LNPaymentRoute, LNPaymentPath, is_route_within_budget,
                       NoChannelPolicy, LNPathInconsistent)
from .address_synchronizer import TX_HEIGHT_LOCAL, TX_TIMESTAMP_INF
from . import lnsweep
from .lnwatcher import LNWalletWatcher
from .crypto import pw_encode_with_version_and_mac, pw_decode_with_version_and_mac
from .lnutil import ImportedChannelBackupStorage, OnchainChannelBackupStorage
from .lnchannel import ChannelBackup
from .channel_db import UpdateStatus, ChannelDBNotLoaded
from .channel_db import get_mychannel_info, get_mychannel_policy
from .submarine_swaps import HttpSwapManager
from .channel_db import ChannelInfo, Policy
from .mpp_split import suggest_splits, SplitConfigRating
from .trampoline import create_trampoline_route_and_onion, is_legacy_relay

if TYPE_CHECKING:
    from .network import Network
    from .wallet import Abstract_Wallet
    from .channel_db import ChannelDB
    from .simple_config import SimpleConfig


SAVED_PR_STATUS = [PR_PAID, PR_UNPAID] # status that are persisted

NUM_PEERS_TARGET = 4

# onchain channel backup data
CB_VERSION = 0
CB_MAGIC_BYTES = bytes([0, 0, 0, CB_VERSION])


FALLBACK_NODE_LIST_TESTNET = (
    LNPeerAddr(host='203.132.95.10', port=9735, pubkey=bfh('038863cf8ab91046230f561cd5b386cbff8309fa02e3f0c3ed161a3aeb64a643b9')),
    LNPeerAddr(host='2401:d002:4402:0:bf1d:986a:7598:6d49', port=9735, pubkey=bfh('038863cf8ab91046230f561cd5b386cbff8309fa02e3f0c3ed161a3aeb64a643b9')),
    LNPeerAddr(host='50.116.3.223', port=9734, pubkey=bfh('03236a685d30096b26692dce0cf0fa7c8528bdf61dbf5363a3ef6d5c92733a3016')),
    LNPeerAddr(host='3.16.119.191', port=9735, pubkey=bfh('03d5e17a3c213fe490e1b0c389f8cfcfcea08a29717d50a9f453735e0ab2a7c003')),
    LNPeerAddr(host='34.250.234.192', port=9735, pubkey=bfh('03933884aaf1d6b108397e5efe5c86bcf2d8ca8d2f700eda99db9214fc2712b134')),
    LNPeerAddr(host='88.99.209.230', port=9735, pubkey=bfh('0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7')),
    LNPeerAddr(host='160.16.233.215', port=9735, pubkey=bfh('023ea0a53af875580899da0ab0a21455d9c19160c4ea1b7774c9d4be6810b02d2c')),
    LNPeerAddr(host='197.155.6.173', port=9735, pubkey=bfh('0269a94e8b32c005e4336bfb743c08a6e9beb13d940d57c479d95c8e687ccbdb9f')),
    LNPeerAddr(host='2c0f:fb18:406::4', port=9735, pubkey=bfh('0269a94e8b32c005e4336bfb743c08a6e9beb13d940d57c479d95c8e687ccbdb9f')),
    LNPeerAddr(host='163.172.94.64', port=9735, pubkey=bfh('030f0bf260acdbd3edcad84d7588ec7c5df4711e87e6a23016f989b8d3a4147230')),
    LNPeerAddr(host='23.237.77.12', port=9735, pubkey=bfh('02312627fdf07fbdd7e5ddb136611bdde9b00d26821d14d94891395452f67af248')),
    LNPeerAddr(host='197.155.6.172', port=9735, pubkey=bfh('02ae2f22b02375e3e9b4b4a2db4f12e1b50752b4062dbefd6e01332acdaf680379')),
    LNPeerAddr(host='2c0f:fb18:406::3', port=9735, pubkey=bfh('02ae2f22b02375e3e9b4b4a2db4f12e1b50752b4062dbefd6e01332acdaf680379')),
    LNPeerAddr(host='23.239.23.44', port=9740, pubkey=bfh('034fe52e98a0e9d3c21b767e1b371881265d8c7578c21f5afd6d6438da10348b36')),
    LNPeerAddr(host='2600:3c01::f03c:91ff:fe05:349c', port=9740, pubkey=bfh('034fe52e98a0e9d3c21b767e1b371881265d8c7578c21f5afd6d6438da10348b36')),
)

FALLBACK_NODE_LIST_MAINNET = [
    LNPeerAddr(host='172.81.181.3', port=9735, pubkey=bfh('0214382bdce7750dfcb8126df8e2b12de38536902dc36abcebdaeefdeca1df8284')),
    LNPeerAddr(host='35.230.100.60', port=9735, pubkey=bfh('023f5e3582716bed96f6f26cfcd8037e07474d7b4743afdc8b07e692df63464d7e')),
    LNPeerAddr(host='40.69.71.114', port=9735, pubkey=bfh('028303182c9885da93b3b25c9621d22cf34475e63c123942e402ab530c0556e675')),
    LNPeerAddr(host='94.177.171.73', port=9735, pubkey=bfh('0276e09a267592e7451a939c932cf685f0754de382a3ca85d2fb3a864d4c365ad5')),
    LNPeerAddr(host='34.236.113.58', port=9735, pubkey=bfh('02fa50c72ee1e2eb5f1b6d9c3032080c4c864373c4201dfa2966aa34eee1051f97')),
    LNPeerAddr(host='52.50.244.44', port=9735, pubkey=bfh('030c3f19d742ca294a55c00376b3b355c3c90d61c6b6b39554dbc7ac19b141c14f')),
    LNPeerAddr(host='157.245.68.47', port=9735, pubkey=bfh('03c2abfa93eacec04721c019644584424aab2ba4dff3ac9bdab4e9c97007491dda')),
    LNPeerAddr(host='18.221.23.28', port=9735, pubkey=bfh('03abf6f44c355dec0d5aa155bdbdd6e0c8fefe318eff402de65c6eb2e1be55dc3e')),
    LNPeerAddr(host='52.224.178.244', port=9735, pubkey=bfh('026b105ac13212c48714c6be9b11577a9ce10f10e1c88a45ce217e6331209faf8b')),
    LNPeerAddr(host='34.239.230.56', port=9735, pubkey=bfh('03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f')),
    LNPeerAddr(host='46.229.165.136', port=9735, pubkey=bfh('0390b5d4492dc2f5318e5233ab2cebf6d48914881a33ef6a9c6bcdbb433ad986d0')),
    LNPeerAddr(host='157.230.28.160', port=9735, pubkey=bfh('0279c22ed7a068d10dc1a38ae66d2d6461e269226c60258c021b1ddcdfe4b00bc4')),
    LNPeerAddr(host='74.108.13.152', port=9735, pubkey=bfh('0331f80652fb840239df8dc99205792bba2e559a05469915804c08420230e23c7c')),
    LNPeerAddr(host='167.172.44.148', port=9735, pubkey=bfh('0395033b252c6f40e3756984162d68174e2bd8060a129c0d3462a9370471c6d28f')),
    LNPeerAddr(host='138.68.14.104', port=9735, pubkey=bfh('03bb88ccc444534da7b5b64b4f7b15e1eccb18e102db0e400d4b9cfe93763aa26d')),
    LNPeerAddr(host='3.124.63.44', port=9735, pubkey=bfh('0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3')),
    LNPeerAddr(host='2001:470:8:2e1::43', port=9735, pubkey=bfh('03baa70886d9200af0ffbd3f9e18d96008331c858456b16e3a9b41e735c6208fef')),
    LNPeerAddr(host='2601:186:c100:6bcd:219:d1ff:fe75:dc2f', port=9735, pubkey=bfh('0298f6074a454a1f5345cb2a7c6f9fce206cd0bf675d177cdbf0ca7508dd28852f')),
    LNPeerAddr(host='2001:41d0:e:734::1', port=9735, pubkey=bfh('03a503d8e30f2ff407096d235b5db63b4fcf3f89a653acb6f43d3fc492a7674019')),
    LNPeerAddr(host='2a01:4f9:2b:2254::2', port=9735, pubkey=bfh('02f3069a342ae2883a6f29e275f06f28a56a6ea2e2d96f5888a3266444dcf542b6')),
    LNPeerAddr(host='2a02:8070:24c1:100:528c:2997:6dbc:a054', port=9735, pubkey=bfh('02a45def9ae014fdd2603dd7033d157faa3a55a72b06a63ae22ef46d9fafdc6e8d')),
    LNPeerAddr(host='2600:3c01::f03c:91ff:fe05:349c', port=9736, pubkey=bfh('02731b798b39a09f9f14e90ee601afb6ebb796d6e5797de14582a978770b33700f')),
    LNPeerAddr(host='2a00:8a60:e012:a00::21', port=9735, pubkey=bfh('027ce055380348d7812d2ae7745701c9f93e70c1adeb2657f053f91df4f2843c71')),
    LNPeerAddr(host='2604:a880:400:d1::8bd:1001', port=9735, pubkey=bfh('03649c72a4816f0cd546f84aafbd657e92a30ab474de7ab795e8b5650a427611f7')),
    LNPeerAddr(host='2a01:4f8:c0c:7b31::1', port=9735, pubkey=bfh('02c16cca44562b590dd279c942200bdccfd4f990c3a69fad620c10ef2f8228eaff')),
    LNPeerAddr(host='2001:41d0:1:b40d::1', port=9735, pubkey=bfh('026726a4b043d413b45b334876d17b8a98848129604429ec65532ba286a42efeac')),
]


from .trampoline import trampolines_by_id, hardcoded_trampoline_nodes, is_hardcoded_trampoline


class PaymentDirection(IntEnum):
    SENT = 0
    RECEIVED = 1
    SELF_PAYMENT = 2
    FORWARDING = 3


class PaymentInfo(NamedTuple):
    payment_hash: bytes
    amount_msat: Optional[int]
    direction: int
    status: int


class RecvMPPResolution(Enum):
    WAITING = enum.auto()
    EXPIRED = enum.auto()
    ACCEPTED = enum.auto()
    FAILED = enum.auto()


class ReceivedMPPStatus(NamedTuple):
    resolution: RecvMPPResolution
    expected_msat: int
    htlc_set: Set[Tuple[ShortChannelID, UpdateAddHtlc]]


SentHtlcKey = Tuple[bytes, ShortChannelID, int]  # RHASH, scid, htlc_id


class SentHtlcInfo(NamedTuple):
    route: LNPaymentRoute
    payment_secret_orig: bytes
    payment_secret_bucket: bytes
    amount_msat: int
    bucket_msat: int
    amount_receiver_msat: int
    trampoline_fee_level: Optional[int]
    trampoline_route: Optional[LNPaymentRoute]


class ErrorAddingPeer(Exception): pass


# set some feature flags as baseline for both LNWallet and LNGossip
# note that e.g. DATA_LOSS_PROTECT is needed for LNGossip as many peers require it
BASE_FEATURES = (
    LnFeatures(0)
    | LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT
    | LnFeatures.OPTION_STATIC_REMOTEKEY_OPT
    | LnFeatures.VAR_ONION_OPT
    | LnFeatures.PAYMENT_SECRET_OPT
    | LnFeatures.OPTION_UPFRONT_SHUTDOWN_SCRIPT_OPT
)

# we do not want to receive unrequested gossip (see lnpeer.maybe_save_remote_update)
LNWALLET_FEATURES = (
    BASE_FEATURES
    | LnFeatures.OPTION_DATA_LOSS_PROTECT_REQ
    | LnFeatures.OPTION_STATIC_REMOTEKEY_REQ
    | LnFeatures.GOSSIP_QUERIES_REQ
    | LnFeatures.VAR_ONION_REQ
    | LnFeatures.PAYMENT_SECRET_REQ
    | LnFeatures.BASIC_MPP_OPT
    | LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM
    | LnFeatures.OPTION_SHUTDOWN_ANYSEGWIT_OPT
    | LnFeatures.OPTION_CHANNEL_TYPE_OPT
    | LnFeatures.OPTION_SCID_ALIAS_OPT
    | LnFeatures.OPTION_SUPPORT_LARGE_CHANNEL_OPT
)

LNGOSSIP_FEATURES = (
    BASE_FEATURES
    | LnFeatures.GOSSIP_QUERIES_OPT
    | LnFeatures.GOSSIP_QUERIES_REQ
)


class LNWorker(Logger, EventListener, NetworkRetryManager[LNPeerAddr]):

    def __init__(self, node_keypair, features: LnFeatures, *, config: 'SimpleConfig'):
        Logger.__init__(self)
        NetworkRetryManager.__init__(
            self,
            max_retry_delay_normal=3600,
            init_retry_delay_normal=600,
            max_retry_delay_urgent=300,
            init_retry_delay_urgent=4,
        )
        self.lock = threading.RLock()
        self.node_keypair = node_keypair
        self._peers = {}  # type: Dict[bytes, Peer]  # pubkey -> Peer  # needs self.lock
        self.taskgroup = OldTaskGroup()
        self.listen_server = None  # type: Optional[asyncio.AbstractServer]
        self.features = features
        self.network = None  # type: Optional[Network]
        self.config = config
        self.stopping_soon = False  # whether we are being shut down
        self._labels_cache = {} # txid -> str
        self.register_callbacks()

    @property
    def channel_db(self):
        return self.network.channel_db if self.network else None

    def uses_trampoline(self):
        return not bool(self.channel_db)

    @property
    def peers(self) -> Mapping[bytes, Peer]:
        """Returns a read-only copy of peers."""
        with self.lock:
            return self._peers.copy()

    def channels_for_peer(self, node_id: bytes) -> Dict[bytes, Channel]:
        return {}

    def get_node_alias(self, node_id: bytes) -> Optional[str]:
        """Returns the alias of the node, or None if unknown."""
        node_alias = None
        if not self.uses_trampoline():
            node_info = self.channel_db.get_node_info_for_node_id(node_id)
            if node_info:
                node_alias = node_info.alias
        else:
            for k, v in hardcoded_trampoline_nodes().items():
                if v.pubkey.startswith(node_id):
                    node_alias = k
                    break
        return node_alias

    async def maybe_listen(self):
        # FIXME: only one LNWorker can listen at a time (single port)
        listen_addr = self.config.LIGHTNING_LISTEN
        if listen_addr:
            self.logger.info(f'lightning_listen enabled. will try to bind: {listen_addr!r}')
            try:
                netaddr = NetAddress.from_string(listen_addr)
            except Exception as e:
                self.logger.error(f"failed to parse config key '{self.config.cv.LIGHTNING_LISTEN.key()}'. got: {e!r}")
                return
            addr = str(netaddr.host)
            async def cb(reader, writer):
                transport = LNResponderTransport(self.node_keypair.privkey, reader, writer)
                try:
                    node_id = await transport.handshake()
                except Exception as e:
                    self.logger.info(f'handshake failure from incoming connection: {e!r}')
                    return
                await self._add_peer_from_transport(node_id=node_id, transport=transport)
            try:
                self.listen_server = await asyncio.start_server(cb, addr, netaddr.port)
            except OSError as e:
                self.logger.error(f"cannot listen for lightning p2p. error: {e!r}")

    async def main_loop(self):
        self.logger.info("starting taskgroup.")
        try:
            async with self.taskgroup as group:
                await group.spawn(asyncio.Event().wait)  # run forever (until cancel)
        except Exception as e:
            self.logger.exception("taskgroup died.")
        finally:
            self.logger.info("taskgroup stopped.")

    async def _maintain_connectivity(self):
        while True:
            await asyncio.sleep(1)
            if self.stopping_soon:
                return
            now = time.time()
            if len(self._peers) >= NUM_PEERS_TARGET:
                continue
            peers = await self._get_next_peers_to_try()
            for peer in peers:
                if self._can_retry_addr(peer, now=now):
                    try:
                        await self._add_peer(peer.host, peer.port, peer.pubkey)
                    except ErrorAddingPeer as e:
                        self.logger.info(f"failed to add peer: {peer}. exc: {e!r}")

    async def _add_peer(self, host: str, port: int, node_id: bytes) -> Peer:
        if node_id in self._peers:
            return self._peers[node_id]
        port = int(port)
        peer_addr = LNPeerAddr(host, port, node_id)
        self._trying_addr_now(peer_addr)
        self.logger.info(f"adding peer {peer_addr}")
        if node_id == self.node_keypair.pubkey:
            raise ErrorAddingPeer("cannot connect to self")
        transport = LNTransport(self.node_keypair.privkey, peer_addr,
                                proxy=self.network.proxy)
        peer = await self._add_peer_from_transport(node_id=node_id, transport=transport)
        assert peer
        return peer

    async def _add_peer_from_transport(self, *, node_id: bytes, transport: LNTransportBase) -> Optional[Peer]:
        with self.lock:
            existing_peer = self._peers.get(node_id)
            if existing_peer:
                # Two instances of the same wallet are attempting to connect simultaneously.
                # If we let the new connection replace the existing one, the two instances might
                # both keep trying to reconnect, resulting in neither being usable.
                if existing_peer.is_initialized():
                    # give priority to the existing connection
                    return
                else:
                    # Use the new connection. (e.g. old peer might be an outgoing connection
                    # for an outdated host/port that will never connect)
                    existing_peer.close_and_cleanup()
            peer = Peer(self, node_id, transport)
            assert node_id not in self._peers
            self._peers[node_id] = peer
        await self.taskgroup.spawn(peer.main_loop())
        return peer

    def peer_closed(self, peer: Peer) -> None:
        with self.lock:
            peer2 = self._peers.get(peer.pubkey)
            if peer2 is peer:
                self._peers.pop(peer.pubkey)

    def num_peers(self) -> int:
        return sum([p.is_initialized() for p in self.peers.values()])

    def start_network(self, network: 'Network'):
        assert network
        assert self.network is None, "already started"
        self.network = network
        self._add_peers_from_config()
        asyncio.run_coroutine_threadsafe(self.main_loop(), self.network.asyncio_loop)

    async def stop(self):
        if self.listen_server:
            self.listen_server.close()
        self.unregister_callbacks()
        await self.taskgroup.cancel_remaining()

    def _add_peers_from_config(self):
        peer_list = self.config.LIGHTNING_PEERS or []
        for host, port, pubkey in peer_list:
            asyncio.run_coroutine_threadsafe(
                self._add_peer(host, int(port), bfh(pubkey)),
                self.network.asyncio_loop)

    def is_good_peer(self, peer: LNPeerAddr) -> bool:
        # the purpose of this method is to filter peers that advertise the desired feature bits
        # it is disabled for now, because feature bits published in node announcements seem to be unreliable
        return True
        node_id = peer.pubkey
        node = self.channel_db._nodes.get(node_id)
        if not node:
            return False
        try:
            ln_compare_features(self.features, node.features)
        except IncompatibleLightningFeatures:
            return False
        #self.logger.info(f'is_good {peer.host}')
        return True

    def on_peer_successfully_established(self, peer: Peer) -> None:
        if isinstance(peer.transport, LNTransport):
            peer_addr = peer.transport.peer_addr
            # reset connection attempt count
            self._on_connection_successfully_established(peer_addr)
            if not self.uses_trampoline():
                # add into channel db
                self.channel_db.add_recent_peer(peer_addr)
            # save network address into channels we might have with peer
            for chan in peer.channels.values():
                chan.add_or_update_peer_addr(peer_addr)

    async def _get_next_peers_to_try(self) -> Sequence[LNPeerAddr]:
        now = time.time()
        await self.channel_db.data_loaded.wait()
        # first try from recent peers
        recent_peers = self.channel_db.get_recent_peers()
        for peer in recent_peers:
            if not peer:
                continue
            if peer.pubkey in self._peers:
                continue
            if not self._can_retry_addr(peer, now=now):
                continue
            if not self.is_good_peer(peer):
                continue
            return [peer]
        # try random peer from graph
        unconnected_nodes = self.channel_db.get_200_randomly_sorted_nodes_not_in(self.peers.keys())
        if unconnected_nodes:
            for node_id in unconnected_nodes:
                addrs = self.channel_db.get_node_addresses(node_id)
                if not addrs:
                    continue
                host, port, timestamp = self.choose_preferred_address(list(addrs))
                try:
                    peer = LNPeerAddr(host, port, node_id)
                except ValueError:
                    continue
                if not self._can_retry_addr(peer, now=now):
                    continue
                if not self.is_good_peer(peer):
                    continue
                #self.logger.info('taking random ln peer from our channel db')
                return [peer]

        # getting desperate... let's try hardcoded fallback list of peers
        if constants.net in (constants.BitcoinTestnet,):
            fallback_list = FALLBACK_NODE_LIST_TESTNET
        elif constants.net in (constants.BitcoinMainnet,):
            fallback_list = FALLBACK_NODE_LIST_MAINNET
        else:
            return []  # regtest??

        fallback_list = [peer for peer in fallback_list if self._can_retry_addr(peer, now=now)]
        if fallback_list:
            return [random.choice(fallback_list)]

        # last resort: try dns seeds (BOLT-10)
        return await run_in_thread(self._get_peers_from_dns_seeds)

    def _get_peers_from_dns_seeds(self) -> Sequence[LNPeerAddr]:
        # NOTE: potentially long blocking call, do not run directly on asyncio event loop.
        # Return several peers to reduce the number of dns queries.
        if not constants.net.LN_DNS_SEEDS:
            return []
        dns_seed = random.choice(constants.net.LN_DNS_SEEDS)
        self.logger.info('asking dns seed "{}" for ln peers'.format(dns_seed))
        try:
            # note: this might block for several seconds
            # this will include bech32-encoded-pubkeys and ports
            srv_answers = resolve_dns_srv('r{}.{}'.format(
                constants.net.LN_REALM_BYTE, dns_seed))
        except dns.exception.DNSException as e:
            self.logger.info(f'failed querying (1) dns seed "{dns_seed}" for ln peers: {repr(e)}')
            return []
        random.shuffle(srv_answers)
        num_peers = 2 * NUM_PEERS_TARGET
        srv_answers = srv_answers[:num_peers]
        # we now have pubkeys and ports but host is still needed
        peers = []
        for srv_ans in srv_answers:
            try:
                # note: this might block for several seconds
                answers = dns.resolver.resolve(srv_ans['host'])
            except dns.exception.DNSException as e:
                self.logger.info(f'failed querying (2) dns seed "{dns_seed}" for ln peers: {repr(e)}')
                continue
            try:
                ln_host = str(answers[0])
                port = int(srv_ans['port'])
                bech32_pubkey = srv_ans['host'].split('.')[0]
                pubkey = get_compressed_pubkey_from_bech32(bech32_pubkey)
                peers.append(LNPeerAddr(ln_host, port, pubkey))
            except Exception as e:
                self.logger.info(f'error with parsing peer from dns seed: {repr(e)}')
                continue
        self.logger.info(f'got {len(peers)} ln peers from dns seed')
        return peers

    @staticmethod
    def choose_preferred_address(addr_list: Sequence[Tuple[str, int, int]]) -> Tuple[str, int, int]:
        assert len(addr_list) >= 1
        # choose the most recent one that is an IP
        for host, port, timestamp in sorted(addr_list, key=lambda a: -a[2]):
            if is_ip_address(host):
                return host, port, timestamp
        # otherwise choose one at random
        # TODO maybe filter out onion if not on tor?
        choice = random.choice(addr_list)
        return choice

    @event_listener
    def on_event_proxy_set(self, *args):
        for peer in self.peers.values():
            peer.close_and_cleanup()
        self._clear_addr_retry_times()

    @log_exceptions
    async def add_peer(self, connect_str: str) -> Peer:
        node_id, rest = extract_nodeid(connect_str)
        peer = self._peers.get(node_id)
        if not peer:
            if rest is not None:
                host, port = split_host_port(rest)
            else:
                if self.uses_trampoline():
                    addr = trampolines_by_id().get(node_id)
                    if not addr:
                        raise ConnStringFormatError(_('Address unknown for node:') + ' ' + node_id.hex())
                    host, port = addr.host, addr.port
                else:
                    addrs = self.channel_db.get_node_addresses(node_id)
                    if not addrs:
                        raise ConnStringFormatError(_('Don\'t know any addresses for node:') + ' ' + node_id.hex())
                    host, port, timestamp = self.choose_preferred_address(list(addrs))
            port = int(port)

            if not self.network.proxy:
                # Try DNS-resolving the host (if needed). This is simply so that
                # the caller gets a nice exception if it cannot be resolved.
                # (we don't do the DNS lookup if a proxy is set, to avoid a DNS-leak)
                if host.endswith('.onion'):
                    raise ConnStringFormatError(_('.onion address, but no proxy configured'))
                try:
                    await asyncio.get_running_loop().getaddrinfo(host, port)
                except socket.gaierror:
                    raise ConnStringFormatError(_('Hostname does not resolve (getaddrinfo failed)'))

            # add peer
            peer = await self._add_peer(host, port, node_id)
        return peer


class LNGossip(LNWorker):
    max_age = 14*24*3600
    LOGGING_SHORTCUT = 'g'

    def __init__(self, config: 'SimpleConfig'):
        seed = os.urandom(32)
        node = BIP32Node.from_rootseed(seed, xtype='standard')
        xprv = node.to_xprv()
        node_keypair = generate_keypair(BIP32Node.from_xkey(xprv), LnKeyFamily.NODE_KEY)
        LNWorker.__init__(self, node_keypair, LNGOSSIP_FEATURES, config=config)
        self.unknown_ids = set()

    def start_network(self, network: 'Network'):
        super().start_network(network)
        for coro in [
                self._maintain_connectivity(),
                self.maintain_db(),
        ]:
            tg_coro = self.taskgroup.spawn(coro)
            asyncio.run_coroutine_threadsafe(tg_coro, self.network.asyncio_loop)

    async def maintain_db(self):
        await self.channel_db.data_loaded.wait()
        while True:
            if len(self.unknown_ids) == 0:
                self.channel_db.prune_old_policies(self.max_age)
                self.channel_db.prune_orphaned_channels()
            await asyncio.sleep(120)

    async def add_new_ids(self, ids: Iterable[bytes]):
        known = self.channel_db.get_channel_ids()
        new = set(ids) - set(known)
        self.unknown_ids.update(new)
        util.trigger_callback('unknown_channels', len(self.unknown_ids))
        util.trigger_callback('gossip_peers', self.num_peers())
        util.trigger_callback('ln_gossip_sync_progress')

    def get_ids_to_query(self) -> Sequence[bytes]:
        N = 500
        l = list(self.unknown_ids)
        self.unknown_ids = set(l[N:])
        util.trigger_callback('unknown_channels', len(self.unknown_ids))
        util.trigger_callback('ln_gossip_sync_progress')
        return l[0:N]

    def get_sync_progress_estimate(self) -> Tuple[Optional[int], Optional[int], Optional[int]]:
        """Estimates the gossip synchronization process and returns the number
        of synchronized channels, the total channels in the network and a
        rescaled percentage of the synchronization process."""
        if self.num_peers() == 0:
            return None, None, None
        nchans_with_0p, nchans_with_1p, nchans_with_2p = self.channel_db.get_num_channels_partitioned_by_policy_count()
        num_db_channels = nchans_with_0p + nchans_with_1p + nchans_with_2p
        # some channels will never have two policies (only one is in gossip?...)
        # so if we have at least 1 policy for a channel, we consider that channel "complete" here
        current_est = num_db_channels - nchans_with_0p
        total_est = len(self.unknown_ids) + num_db_channels

        progress = current_est / total_est if total_est and current_est else 0
        progress_percent = (1.0 / 0.95 * progress) * 100
        progress_percent = min(progress_percent, 100)
        progress_percent = round(progress_percent)
        # take a minimal number of synchronized channels to get a more accurate
        # percentage estimate
        if current_est < 200:
            progress_percent = 0
        return current_est, total_est, progress_percent

    async def process_gossip(self, chan_anns, node_anns, chan_upds):
        # note: we run in the originating peer's TaskGroup, so we can safely raise here
        #       and disconnect only from that peer
        await self.channel_db.data_loaded.wait()
        self.logger.debug(f'process_gossip {len(chan_anns)} {len(node_anns)} {len(chan_upds)}')
        # channel announcements
        def process_chan_anns():
            for payload in chan_anns:
                self.channel_db.verify_channel_announcement(payload)
            self.channel_db.add_channel_announcements(chan_anns)
        await run_in_thread(process_chan_anns)
        # node announcements
        def process_node_anns():
            for payload in node_anns:
                self.channel_db.verify_node_announcement(payload)
            self.channel_db.add_node_announcements(node_anns)
        await run_in_thread(process_node_anns)
        # channel updates
        categorized_chan_upds = await run_in_thread(partial(
            self.channel_db.add_channel_updates,
            chan_upds,
            max_age=self.max_age))
        orphaned = categorized_chan_upds.orphaned
        if orphaned:
            self.logger.info(f'adding {len(orphaned)} unknown channel ids')
            orphaned_ids = [c['short_channel_id'] for c in orphaned]
            await self.add_new_ids(orphaned_ids)
        if categorized_chan_upds.good:
            self.logger.debug(f'process_gossip: {len(categorized_chan_upds.good)}/{len(chan_upds)}')


class PaySession(Logger):
    def __init__(
            self,
            *,
            payment_hash: bytes,
            payment_secret: bytes,
            initial_trampoline_fee_level: int,
            invoice_features: int,
            r_tags,
            min_final_cltv_delta: int,  # delta for last node (typically from invoice)
            amount_to_pay: int,  # total payment amount final receiver will get
            invoice_pubkey: bytes,
            uses_trampoline: bool,  # whether sender uses trampoline or gossip
            use_two_trampolines: bool,  # whether legacy payments will try to use two trampolines
    ):
        assert payment_hash
        assert payment_secret
        self.payment_hash = payment_hash
        self.payment_secret = payment_secret
        self.payment_key = payment_hash + payment_secret
        Logger.__init__(self)

        self.invoice_features = LnFeatures(invoice_features)
        self.r_tags = r_tags
        self.min_final_cltv_delta = min_final_cltv_delta
        self.amount_to_pay = amount_to_pay
        self.invoice_pubkey = invoice_pubkey

        self.sent_htlcs_q = asyncio.Queue()  # type: asyncio.Queue[HtlcLog]
        self.start_time = time.time()

        self.uses_trampoline = uses_trampoline
        self.trampoline_fee_level = initial_trampoline_fee_level
        self.failed_trampoline_routes = []
        self.use_two_trampolines = use_two_trampolines
        self._sent_buckets = dict()  # psecret_bucket -> (amount_sent, amount_failed)

        self._amount_inflight = 0  # what we sent in htlcs (that receiver gets, without fees)
        self._nhtlcs_inflight = 0
        self.is_active = True  # is still trying to send new htlcs?

    def diagnostic_name(self):
        pkey = sha256(self.payment_key)
        return f"{self.payment_hash[:4].hex()}-{pkey[:2].hex()}"

    def maybe_raise_trampoline_fee(self, htlc_log: HtlcLog):
        if htlc_log.trampoline_fee_level == self.trampoline_fee_level:
            self.trampoline_fee_level += 1
            self.failed_trampoline_routes = []
            self.logger.info(f'raising trampoline fee level {self.trampoline_fee_level}')
        else:
            self.logger.info(f'NOT raising trampoline fee level, already at {self.trampoline_fee_level}')

    def handle_failed_trampoline_htlc(self, *, htlc_log: HtlcLog, failure_msg: OnionRoutingFailure):
        # FIXME The trampoline nodes in the path are chosen randomly.
        #       Some of the errors might depend on how we have chosen them.
        #       Having more attempts is currently useful in part because of the randomness,
        #       instead we should give feedback to create_routes_for_payment.
        # Sometimes the trampoline node fails to send a payment and returns
        # TEMPORARY_CHANNEL_FAILURE, while it succeeds with a higher trampoline fee.
        if failure_msg.code in (
                OnionFailureCode.TRAMPOLINE_FEE_INSUFFICIENT,
                OnionFailureCode.TRAMPOLINE_EXPIRY_TOO_SOON,
                OnionFailureCode.TEMPORARY_CHANNEL_FAILURE):
            # TODO: parse the node policy here (not returned by eclair yet)
            # TODO: erring node is always the first trampoline even if second
            #  trampoline demands more fees, we can't influence this
            self.maybe_raise_trampoline_fee(htlc_log)
        elif self.use_two_trampolines:
            self.use_two_trampolines = False
        elif failure_msg.code in (
                OnionFailureCode.UNKNOWN_NEXT_PEER,
                OnionFailureCode.TEMPORARY_NODE_FAILURE):
            trampoline_route = htlc_log.route
            r = [hop.end_node.hex() for hop in trampoline_route]
            self.logger.info(f'failed trampoline route: {r}')
            if r not in self.failed_trampoline_routes:
                self.failed_trampoline_routes.append(r)
            else:
                pass  # maybe the route was reused between different MPP parts
        else:
            raise PaymentFailure(failure_msg.code_name())

    async def wait_for_one_htlc_to_resolve(self) -> HtlcLog:
        self.logger.info(f"waiting... amount_inflight={self._amount_inflight}. nhtlcs_inflight={self._nhtlcs_inflight}")
        htlc_log = await self.sent_htlcs_q.get()
        self._amount_inflight -= htlc_log.amount_msat
        self._nhtlcs_inflight -= 1
        if self._amount_inflight < 0 or self._nhtlcs_inflight < 0:
            raise Exception(f"amount_inflight={self._amount_inflight}, nhtlcs_inflight={self._nhtlcs_inflight}. both should be >= 0 !")
        return htlc_log

    def add_new_htlc(self, sent_htlc_info: SentHtlcInfo):
        self._nhtlcs_inflight += 1
        self._amount_inflight += sent_htlc_info.amount_receiver_msat
        if self._amount_inflight > self.amount_to_pay:  # safety belts
            raise Exception(f"amount_inflight={self._amount_inflight} > amount_to_pay={self.amount_to_pay}")
        shi = sent_htlc_info
        bkey = shi.payment_secret_bucket
        # if we sent MPP to a trampoline, add item to sent_buckets
        if self.uses_trampoline and shi.amount_msat != shi.bucket_msat:
            if bkey not in self._sent_buckets:
                self._sent_buckets[bkey] = (0, 0)
            amount_sent, amount_failed = self._sent_buckets[bkey]
            amount_sent += shi.amount_receiver_msat
            self._sent_buckets[bkey] = amount_sent, amount_failed

    def on_htlc_fail_get_fail_amt_to_propagate(self, sent_htlc_info: SentHtlcInfo) -> Optional[int]:
        shi = sent_htlc_info
        # check sent_buckets if we use trampoline
        bkey = shi.payment_secret_bucket
        if self.uses_trampoline and bkey in self._sent_buckets:
            amount_sent, amount_failed = self._sent_buckets[bkey]
            amount_failed += shi.amount_receiver_msat
            self._sent_buckets[bkey] = amount_sent, amount_failed
            if amount_sent != amount_failed:
                self.logger.info('bucket still active...')
                return None
            self.logger.info('bucket failed')
            return amount_sent
        # not using trampoline buckets
        return shi.amount_receiver_msat

    def get_outstanding_amount_to_send(self) -> int:
        return self.amount_to_pay - self._amount_inflight

    def can_be_deleted(self) -> bool:
        """Returns True iff finished sending htlcs AND all pending htlcs have resolved."""
        if self.is_active:
            return False
        # note: no one is consuming from sent_htlcs_q anymore
        nhtlcs_resolved = self.sent_htlcs_q.qsize()
        assert nhtlcs_resolved <= self._nhtlcs_inflight
        return nhtlcs_resolved == self._nhtlcs_inflight


class LNWallet(LNWorker):

    lnwatcher: Optional['LNWalletWatcher']
    MPP_EXPIRY = 120
    TIMEOUT_SHUTDOWN_FAIL_PENDING_HTLCS = 3  # seconds
    PAYMENT_TIMEOUT = 120
    MPP_SPLIT_PART_FRACTION = 0.2
    MPP_SPLIT_PART_MINAMT_MSAT = 5_000_000

    def __init__(self, wallet: 'Abstract_Wallet', xprv):
        self.wallet = wallet
        self.config = wallet.config
        self.db = wallet.db
        self.node_keypair = generate_keypair(BIP32Node.from_xkey(xprv), LnKeyFamily.NODE_KEY)
        self.backup_key = generate_keypair(BIP32Node.from_xkey(xprv), LnKeyFamily.BACKUP_CIPHER).privkey
        self.payment_secret_key = generate_keypair(BIP32Node.from_xkey(xprv), LnKeyFamily.PAYMENT_SECRET_KEY).privkey
        Logger.__init__(self)
        features = LNWALLET_FEATURES
        if self.config.ACCEPT_ZEROCONF_CHANNELS:
            features |= LnFeatures.OPTION_ZEROCONF_OPT
        LNWorker.__init__(self, self.node_keypair, features, config=self.config)
        self.lnwatcher = None
        self.lnrater: LNRater = None
        self.payment_info = self.db.get_dict('lightning_payments')     # RHASH -> amount, direction, is_paid
        self.preimages = self.db.get_dict('lightning_preimages')   # RHASH -> preimage
        self._bolt11_cache = {}
        # note: this sweep_address is only used as fallback; as it might result in address-reuse
        self.logs = defaultdict(list)  # type: Dict[str, List[HtlcLog]]  # key is RHASH  # (not persisted)
        # used in tests
        self.enable_htlc_settle = True
        self.enable_htlc_forwarding = True

        # note: accessing channels (besides simple lookup) needs self.lock!
        self._channels = {}  # type: Dict[bytes, Channel]
        channels = self.db.get_dict("channels")
        for channel_id, c in random_shuffled_copy(channels.items()):
            self._channels[bfh(channel_id)] = Channel(c, lnworker=self)

        self._channel_backups = {}  # type: Dict[bytes, ChannelBackup]
        # order is important: imported should overwrite onchain
        for name in ["onchain_channel_backups", "imported_channel_backups"]:
            channel_backups = self.db.get_dict(name)
            for channel_id, storage in channel_backups.items():
                self._channel_backups[bfh(channel_id)] = ChannelBackup(storage, lnworker=self)

        self._paysessions = dict()                      # type: Dict[bytes, PaySession]
        self.sent_htlcs_info = dict()                   # type: Dict[SentHtlcKey, SentHtlcInfo]
        self.received_mpp_htlcs = dict()              # type: Dict[bytes, ReceivedMPPStatus]  # payment_key -> ReceivedMPPStatus

        # detect inflight payments
        self.inflight_payments = set()        # (not persisted) keys of invoices that are in PR_INFLIGHT state
        for payment_hash in self.get_payments(status='inflight').keys():
            self.set_invoice_status(payment_hash.hex(), PR_INFLIGHT)

        # payment forwarding
        self.active_forwardings = self.db.get_dict('active_forwardings')    # type: Dict[str, List[str]]        # Dict: payment_key -> list of htlc_keys
        self.forwarding_failures = self.db.get_dict('forwarding_failures')  # type: Dict[str, Tuple[str, str]]  # Dict: payment_key -> (error_bytes, error_message)
        self.downstream_to_upstream_htlc = {}                               # type: Dict[str, str]              # Dict: htlc_key -> htlc_key (not persisted)

        # payment_hash -> callback:
        self.hold_invoice_callbacks = {}                # type: Dict[bytes, Callable[[bytes], Awaitable[None]]]
        self.payment_bundles = []                       # lists of hashes. todo:persist
        self.swap_manager = HttpSwapManager(wallet=self.wallet, lnworker=self)


    def has_deterministic_node_id(self) -> bool:
        return bool(self.db.get('lightning_xprv'))

    def can_have_recoverable_channels(self) -> bool:
        return (self.has_deterministic_node_id()
                and not self.config.LIGHTNING_LISTEN)

    def has_recoverable_channels(self) -> bool:
        """Whether *future* channels opened by this wallet would be recoverable
        from seed (via putting OP_RETURN outputs into funding txs).
        """
        return (self.can_have_recoverable_channels()
                and self.config.LIGHTNING_USE_RECOVERABLE_CHANNELS)

    @property
    def channels(self) -> Mapping[bytes, Channel]:
        """Returns a read-only copy of channels."""
        with self.lock:
            return self._channels.copy()

    @property
    def channel_backups(self) -> Mapping[bytes, ChannelBackup]:
        """Returns a read-only copy of channels."""
        with self.lock:
            return self._channel_backups.copy()

    def get_channel_objects(self) -> Mapping[bytes, AbstractChannel]:
        r = self.channel_backups
        r.update(self.channels)
        return r

    def get_channel_by_id(self, channel_id: bytes) -> Optional[Channel]:
        return self._channels.get(channel_id, None)

    def diagnostic_name(self):
        return self.wallet.diagnostic_name()

    @ignore_exceptions
    @log_exceptions
    async def sync_with_local_watchtower(self):
        watchtower = self.network.local_watchtower
        if watchtower:
            while True:
                for chan in self.channels.values():
                    await self.sync_channel_with_watchtower(chan, watchtower.sweepstore)
                await asyncio.sleep(5)

    @ignore_exceptions
    @log_exceptions
    async def sync_with_remote_watchtower(self):
        while True:
            # periodically poll if the user updated 'watchtower_url'
            await asyncio.sleep(5)
            watchtower_url = self.config.WATCHTOWER_CLIENT_URL
            if not watchtower_url:
                continue
            parsed_url = urllib.parse.urlparse(watchtower_url)
            if not (parsed_url.scheme == 'https' or is_private_netaddress(parsed_url.hostname)):
                self.logger.warning(f"got watchtower URL for remote tower but we won't use it! "
                                    f"can only use HTTPS (except if private IP): not using {watchtower_url!r}")
                continue
            # try to sync with the remote watchtower
            try:
                async with make_aiohttp_session(proxy=self.network.proxy) as session:
                    watchtower = JsonRPCClient(session, watchtower_url)
                    watchtower.add_method('get_ctn')
                    watchtower.add_method('add_sweep_tx')
                    for chan in self.channels.values():
                        await self.sync_channel_with_watchtower(chan, watchtower)
            except aiohttp.client_exceptions.ClientConnectorError:
                self.logger.info(f'could not contact remote watchtower {watchtower_url}')

    async def sync_channel_with_watchtower(self, chan: Channel, watchtower):
        outpoint = chan.funding_outpoint.to_str()
        addr = chan.get_funding_address()
        current_ctn = chan.get_oldest_unrevoked_ctn(REMOTE)
        watchtower_ctn = await watchtower.get_ctn(outpoint, addr)
        for ctn in range(watchtower_ctn + 1, current_ctn):
            sweeptxs = chan.create_sweeptxs(ctn)
            for tx in sweeptxs:
                await watchtower.add_sweep_tx(outpoint, ctn, tx.inputs()[0].prevout.to_str(), tx.serialize())

    def start_network(self, network: 'Network'):
        super().start_network(network)
        self.lnwatcher = LNWalletWatcher(self, network)
        self.swap_manager.start_network(network=network, lnwatcher=self.lnwatcher)
        self.lnrater = LNRater(self, network)

        for chan in self.channels.values():
            if chan.need_to_subscribe():
                self.lnwatcher.add_channel(chan.funding_outpoint.to_str(), chan.get_funding_address())
        for cb in self.channel_backups.values():
            if cb.need_to_subscribe():
                self.lnwatcher.add_channel(cb.funding_outpoint.to_str(), cb.get_funding_address())

        for coro in [
                self.maybe_listen(),
                self.lnwatcher.trigger_callbacks(), # shortcut (don't block) if funding tx locked and verified
                self.reestablish_peers_and_channels(),
                self.sync_with_local_watchtower(),
                self.sync_with_remote_watchtower(),
        ]:
            tg_coro = self.taskgroup.spawn(coro)
            asyncio.run_coroutine_threadsafe(tg_coro, self.network.asyncio_loop)

    async def stop(self):
        self.stopping_soon = True
        if self.listen_server:  # stop accepting new peers
            self.listen_server.close()
        async with ignore_after(self.TIMEOUT_SHUTDOWN_FAIL_PENDING_HTLCS):
            await self.wait_for_received_pending_htlcs_to_get_removed()
        await LNWorker.stop(self)
        if self.lnwatcher:
            await self.lnwatcher.stop()
            self.lnwatcher = None
        if self.swap_manager:  # may not be present in tests
            await self.swap_manager.stop()

    async def wait_for_received_pending_htlcs_to_get_removed(self):
        assert self.stopping_soon is True
        # We try to fail pending MPP HTLCs, and wait a bit for them to get removed.
        # Note: even without MPP, if we just failed/fulfilled an HTLC, it is good
        #       to wait a bit for it to become irrevocably removed.
        # Note: we don't wait for *all htlcs* to get removed, only for those
        #       that we can already fail/fulfill. e.g. forwarded htlcs cannot be removed
        async with OldTaskGroup() as group:
            for peer in self.peers.values():
                await group.spawn(peer.wait_one_htlc_switch_iteration())
        while True:
            if all(not peer.received_htlcs_pending_removal for peer in self.peers.values()):
                break
            async with OldTaskGroup(wait=any) as group:
                for peer in self.peers.values():
                    await group.spawn(peer.received_htlc_removed_event.wait())

    def peer_closed(self, peer):
        for chan in self.channels_for_peer(peer.pubkey).values():
            chan.peer_state = PeerState.DISCONNECTED
            util.trigger_callback('channel', self.wallet, chan)
        super().peer_closed(peer)

    def get_payments(self, *, status=None) -> Mapping[bytes, List[HTLCWithStatus]]:
        out = defaultdict(list)
        for chan in self.channels.values():
            d = chan.get_payments(status=status)
            for payment_hash, plist in d.items():
                out[payment_hash] += plist
        return out

    def get_payment_value(
            self, info: Optional['PaymentInfo'],
            plist: List[HTLCWithStatus]) -> Tuple[PaymentDirection, int, Optional[int], int]:
        """ fee_msat is included in amount_msat"""
        assert plist
        amount_msat = sum(int(x.direction) * x.htlc.amount_msat for x in plist)
        if all(x.direction == SENT for x in plist):
            direction = PaymentDirection.SENT
            fee_msat = (- info.amount_msat - amount_msat) if info else None
        elif all(x.direction == RECEIVED for x in plist):
            direction = PaymentDirection.RECEIVED
            fee_msat = None
        elif amount_msat < 0:
            direction = PaymentDirection.SELF_PAYMENT
            fee_msat = - amount_msat
        else:
            direction = PaymentDirection.FORWARDING
            fee_msat = - amount_msat
        timestamp = min([htlc_with_status.htlc.timestamp for htlc_with_status in plist])
        return direction, amount_msat, fee_msat, timestamp

    def get_lightning_history(self):
        out = {}
        for payment_hash, plist in self.get_payments(status='settled').items():
            if len(plist) == 0:
                continue
            key = payment_hash.hex()
            info = self.get_payment_info(payment_hash)
            direction, amount_msat, fee_msat, timestamp = self.get_payment_value(info, plist)
            label = self.wallet.get_label_for_rhash(key)
            if not label and direction == PaymentDirection.FORWARDING:
                label = _('Forwarding')
            preimage = self.get_preimage(payment_hash).hex()
            item = {
                'type': 'payment',
                'label': label,
                'timestamp': timestamp or 0,
                'date': timestamp_to_datetime(timestamp),
                'direction': direction,
                'amount_msat': amount_msat,
                'fee_msat': fee_msat,
                'payment_hash': key,
                'preimage': preimage,
            }
            # add group_id to swap transactions
            swap = self.swap_manager.get_swap(payment_hash)
            if swap:
                if swap.is_reverse:
                    item['group_id'] = swap.spending_txid
                else:
                    item['group_id'] = swap.funding_txid
            # done
            out[payment_hash] = item
        return out

    def get_label_for_txid(self, txid: str) -> str:
        return self._labels_cache.get(txid)

    def get_onchain_history(self):
        current_height = self.wallet.adb.get_local_height()
        out = {}
        # add funding events
        for chan in itertools.chain(self.channels.values(), self.channel_backups.values()):  # type: AbstractChannel
            item = chan.get_funding_height()
            if item is None:
                continue
            funding_txid, funding_height, funding_timestamp = item
            tx_height = self.wallet.adb.get_tx_height(funding_txid)
            self._labels_cache[funding_txid] = _('Open channel') + ' ' + chan.get_id_for_log()
            item = {
                'channel_id': chan.channel_id.hex(),
                'type': 'channel_opening',
                'label': self.get_label_for_txid(funding_txid),
                'txid': funding_txid,
                'amount_msat': chan.balance(LOCAL, ctn=0),
                'direction': PaymentDirection.RECEIVED,
                'timestamp': tx_height.timestamp,
                'monotonic_timestamp': tx_height.timestamp or TX_TIMESTAMP_INF,
                'date': timestamp_to_datetime(tx_height.timestamp),
                'fee_sat': None,
                'fee_msat': None,
                'height': tx_height.height,
                'confirmations': tx_height.conf,
                'txpos_in_block': tx_height.txpos,
            }  # FIXME this data structure needs to be kept in ~sync with wallet.get_onchain_history
            out[funding_txid] = item
            item = chan.get_closing_height()
            if item is None:
                continue
            closing_txid, closing_height, closing_timestamp = item
            tx_height = self.wallet.adb.get_tx_height(closing_txid)
            self._labels_cache[closing_txid] = _('Close channel') + ' ' + chan.get_id_for_log()
            item = {
                'channel_id': chan.channel_id.hex(),
                'txid': closing_txid,
                'label': self.get_label_for_txid(closing_txid),
                'type': 'channel_closure',
                'amount_msat': -chan.balance_minus_outgoing_htlcs(LOCAL),
                'direction': PaymentDirection.SENT,
                'timestamp': tx_height.timestamp,
                'monotonic_timestamp': tx_height.timestamp or TX_TIMESTAMP_INF,
                'date': timestamp_to_datetime(tx_height.timestamp),
                'fee_sat': None,
                'fee_msat': None,
                'height': tx_height.height,
                'confirmations': tx_height.conf,
                'txpos_in_block': tx_height.txpos,
            }  # FIXME this data structure needs to be kept in ~sync with wallet.get_onchain_history
            out[closing_txid] = item
        # add info about submarine swaps
        settled_payments = self.get_payments(status='settled')
        for payment_hash_hex, swap in self.swap_manager.swaps.items():
            txid = swap.spending_txid if swap.is_reverse else swap.funding_txid
            if txid is None:
                continue
            payment_hash = bytes.fromhex(payment_hash_hex)
            if payment_hash in settled_payments:
                plist = settled_payments[payment_hash]
                info = self.get_payment_info(payment_hash)
                direction, amount_msat, fee_msat, timestamp = self.get_payment_value(info, plist)
            else:
                amount_msat = 0

            if swap.is_reverse:
                group_label = 'Reverse swap' + ' ' + self.config.format_amount_and_units(swap.lightning_amount)
            else:
                group_label = 'Forward swap' + ' ' + self.config.format_amount_and_units(swap.onchain_amount)
            self._labels_cache[txid] = group_label

            label = _('Claim transaction') if swap.is_reverse else _('Funding transaction')
            delta = current_height - swap.locktime
            if self.wallet.adb.is_mine(swap.lockup_address):
                tx_height = self.wallet.adb.get_tx_height(swap.funding_txid)
                if swap.is_reverse and tx_height.height <= 0:
                    label += ' (%s)' % _('waiting for funding tx confirmation')
                if not swap.is_reverse and not swap.is_redeemed and swap.spending_txid is None and delta < 0:
                    label += f' (refundable in {-delta} blocks)' # fixme: only if unspent
            out[txid] = {
                'group_id': txid,
                'amount_msat': 0, # must be zero for onchain tx
                'type': 'swap',
                'label': label,
            }
            if not swap.is_reverse:
                # if the spending_tx is in the wallet, this will add it
                # to the group (see wallet.get_full_history)
                out[swap.spending_txid] = {
                    'group_id': txid,
                    'amount_msat': 0, # must be zero for onchain tx
                    'type': 'swap',
                    'label': _('Refund transaction'),
                }
        return out

    def get_history(self):
        out = list(self.get_lightning_history().values()) + list(self.get_onchain_history().values())
        # sort by timestamp
        out.sort(key=lambda x: (x.get('timestamp') or float("inf")))
        balance_msat = 0
        for item in out:
            balance_msat += item['amount_msat']
            item['balance_msat'] = balance_msat
        return out

    def channel_peers(self) -> List[bytes]:
        node_ids = [chan.node_id for chan in self.channels.values() if not chan.is_closed()]
        return node_ids

    def channels_for_peer(self, node_id):
        assert type(node_id) is bytes
        return {chan_id: chan for (chan_id, chan) in self.channels.items()
                if chan.node_id == node_id}

    def channel_state_changed(self, chan: Channel):
        if type(chan) is Channel:
            self.save_channel(chan)
        self.clear_invoices_cache()
        util.trigger_callback('channel', self.wallet, chan)

    def save_channel(self, chan: Channel):
        assert type(chan) is Channel
        if chan.config[REMOTE].next_per_commitment_point == chan.config[REMOTE].current_per_commitment_point:
            raise Exception("Tried to save channel with next_point == current_point, this should not happen")
        self.wallet.save_db()
        util.trigger_callback('channel', self.wallet, chan)

    def channel_by_txo(self, txo: str) -> Optional[AbstractChannel]:
        for chan in self.channels.values():
            if chan.funding_outpoint.to_str() == txo:
                return chan
        for chan in self.channel_backups.values():
            if chan.funding_outpoint.to_str() == txo:
                return chan

    async def handle_onchain_state(self, chan: Channel):
        if type(chan) is ChannelBackup:
            util.trigger_callback('channel', self.wallet, chan)
            return

        if (chan.get_state() in (ChannelState.OPEN, ChannelState.SHUTDOWN)
                and chan.should_be_closed_due_to_expiring_htlcs(self.network.get_local_height())):
            self.logger.info(f"force-closing due to expiring htlcs")
            await self.schedule_force_closing(chan.channel_id)

        elif chan.get_state() == ChannelState.FUNDED:
            peer = self._peers.get(chan.node_id)
            if peer and peer.is_initialized() and chan.peer_state == PeerState.GOOD:
                peer.send_channel_ready(chan)

        elif chan.get_state() == ChannelState.OPEN:
            peer = self._peers.get(chan.node_id)
            if peer and peer.is_initialized() and chan.peer_state == PeerState.GOOD:
                peer.maybe_update_fee(chan)
                peer.maybe_send_announcement_signatures(chan)

        elif chan.get_state() == ChannelState.FORCE_CLOSING:
            force_close_tx = chan.force_close_tx()
            txid = force_close_tx.txid()
            height = self.lnwatcher.adb.get_tx_height(txid).height
            if height == TX_HEIGHT_LOCAL:
                self.logger.info('REBROADCASTING CLOSING TX')
                await self.network.try_broadcasting(force_close_tx, 'force-close')

    def get_peer_by_scid_alias(self, scid_alias: bytes) -> Optional[Peer]:
        for nodeid, peer in self.peers.items():
            if scid_alias == self._scid_alias_of_node(nodeid):
                return peer

    def _scid_alias_of_node(self, nodeid: bytes) -> bytes:
        # scid alias for just-in-time channels
        return sha256(b'Electrum' + nodeid)[0:8]

    def get_scid_alias(self) -> bytes:
        return self._scid_alias_of_node(self.node_keypair.pubkey)

    @log_exceptions
    async def open_channel_just_in_time(
        self,
        *,
        next_peer: Peer,
        next_amount_msat_htlc: int,
        next_cltv_abs: int,
        payment_hash: bytes,
        next_onion: OnionPacket,
    ) -> str:
        # if an exception is raised during negotiation, we raise an OnionRoutingFailure.
        # this will cancel the incoming HTLC
        try:
            funding_sat = 2 * (next_amount_msat_htlc // 1000) # try to fully spend htlcs
            password = self.wallet.get_unlocked_password() if self.wallet.has_password() else None
            channel_opening_fee = next_amount_msat_htlc // 100
            if channel_opening_fee // 1000 < self.config.ZEROCONF_MIN_OPENING_FEE:
                self.logger.info(f'rejecting JIT channel: payment too low')
                raise OnionRoutingFailure(code=OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, data=b'payment too low')
            self.logger.info(f'channel opening fee (sats): {channel_opening_fee//1000}')
            next_chan, funding_tx = await self.open_channel_with_peer(
                next_peer, funding_sat,
                push_sat=0,
                zeroconf=True,
                public=False,
                opening_fee=channel_opening_fee,
                password=password,
            )
            async def wait_for_channel():
                while not next_chan.is_open():
                    await asyncio.sleep(1)
            await util.wait_for2(wait_for_channel(), LN_P2P_NETWORK_TIMEOUT)
            next_chan.save_remote_scid_alias(self._scid_alias_of_node(next_peer.pubkey))
            self.logger.info(f'JIT channel is open')
            next_amount_msat_htlc -= channel_opening_fee
            # fixme: some checks are missing
            htlc = next_peer.send_htlc(
                chan=next_chan,
                payment_hash=payment_hash,
                amount_msat=next_amount_msat_htlc,
                cltv_abs=next_cltv_abs,
                onion=next_onion)
            async def wait_for_preimage():
                while self.get_preimage(payment_hash) is None:
                    await asyncio.sleep(1)
            await util.wait_for2(wait_for_preimage(), LN_P2P_NETWORK_TIMEOUT)
        except OnionRoutingFailure:
            raise
        except Exception:
            raise OnionRoutingFailure(code=OnionFailureCode.TEMPORARY_NODE_FAILURE, data=b'')
        # We have been paid and can broadcast
        # todo: if broadcasting raise an exception, we should try to rebroadcast
        await self.network.broadcast_transaction(funding_tx)
        htlc_key = serialize_htlc_key(next_chan.get_scid_or_local_alias(), htlc.htlc_id)
        return htlc_key

    @log_exceptions
    async def open_channel_with_peer(
            self, peer, funding_sat, *,
            push_sat: int = 0,
            public: bool = False,
            zeroconf: bool = False,
            opening_fee: int = None,
            password=None):
        coins = self.wallet.get_spendable_coins(None)
        node_id = peer.pubkey
        funding_tx = self.mktx_for_open_channel(
            coins=coins,
            funding_sat=funding_sat,
            node_id=node_id,
            fee_est=None)
        chan, funding_tx = await self._open_channel_coroutine(
            peer=peer,
            funding_tx=funding_tx,
            funding_sat=funding_sat,
            push_sat=push_sat,
            public=public,
            zeroconf=zeroconf,
            opening_fee=opening_fee,
            password=password)
        return chan, funding_tx

    @log_exceptions
    async def _open_channel_coroutine(
            self, *,
            peer: Peer,
            funding_tx: PartialTransaction,
            funding_sat: int,
            push_sat: int,
            public: bool,
            zeroconf=False,
            opening_fee=None,
            password: Optional[str]) -> Tuple[Channel, PartialTransaction]:

        coro = peer.channel_establishment_flow(
            funding_tx=funding_tx,
            funding_sat=funding_sat,
            push_msat=push_sat * 1000,
            public=public,
            zeroconf=zeroconf,
            opening_fee=opening_fee,
            temp_channel_id=os.urandom(32))
        chan, funding_tx = await util.wait_for2(coro, LN_P2P_NETWORK_TIMEOUT)
        util.trigger_callback('channels_updated', self.wallet)
        self.wallet.adb.add_transaction(funding_tx)  # save tx as local into the wallet
        self.wallet.sign_transaction(funding_tx, password)
        self.wallet.set_label(funding_tx.txid(), _('Open channel'))
        if funding_tx.is_complete() and not zeroconf:
            await self.network.try_broadcasting(funding_tx, 'open_channel')
        return chan, funding_tx

    def add_channel(self, chan: Channel):
        with self.lock:
            self._channels[chan.channel_id] = chan
        self.lnwatcher.add_channel(chan.funding_outpoint.to_str(), chan.get_funding_address())

    def add_new_channel(self, chan: Channel):
        self.add_channel(chan)
        channels_db = self.db.get_dict('channels')
        channels_db[chan.channel_id.hex()] = chan.storage
        for addr in chan.get_wallet_addresses_channel_might_want_reserved():
            self.wallet.set_reserved_state_of_address(addr, reserved=True)
        try:
            self.save_channel(chan)
        except Exception:
            chan.set_state(ChannelState.REDEEMED)
            self.remove_channel(chan.channel_id)
            raise

    def cb_data(self, node_id):
        return CB_MAGIC_BYTES + node_id[0:16]

    def decrypt_cb_data(self, encrypted_data, funding_address):
        funding_scripthash = bytes.fromhex(address_to_scripthash(funding_address))
        nonce = funding_scripthash[0:12]
        return chacha20_decrypt(key=self.backup_key, data=encrypted_data, nonce=nonce)

    def encrypt_cb_data(self, data, funding_address):
        funding_scripthash = bytes.fromhex(address_to_scripthash(funding_address))
        nonce = funding_scripthash[0:12]
        # note: we are only using chacha20 instead of chacha20+poly1305 to save onchain space
        #       (not have the 16 byte MAC). Otherwise, the latter would be preferable.
        return chacha20_encrypt(key=self.backup_key, data=data, nonce=nonce)

    def mktx_for_open_channel(
            self, *,
            coins: Sequence[PartialTxInput],
            funding_sat: int,
            node_id: bytes,
            fee_est=None) -> PartialTransaction:
        outputs = [PartialTxOutput.from_address_and_value(DummyAddress.CHANNEL, funding_sat)]
        if self.has_recoverable_channels():
            dummy_scriptpubkey = make_op_return(self.cb_data(node_id))
            outputs.append(PartialTxOutput(scriptpubkey=dummy_scriptpubkey, value=0))
        tx = self.wallet.make_unsigned_transaction(
            coins=coins,
            outputs=outputs,
            fee=fee_est)
        tx.set_rbf(False)
        return tx

    def suggest_funding_amount(self, amount_to_pay, coins):
        """ whether we can pay amount_sat after opening a new channel"""
        num_sats_can_send = int(self.num_sats_can_send())
        lightning_needed = amount_to_pay - num_sats_can_send
        assert lightning_needed > 0
        min_funding_sat = lightning_needed + (lightning_needed // 20) + 1000 # safety margin
        min_funding_sat = max(min_funding_sat, 100_000) # at least 1mBTC
        if min_funding_sat > self.config.LIGHTNING_MAX_FUNDING_SAT:
            return
        fee_est = partial(self.config.estimate_fee, allow_fallback_to_static_rates=True)  # to avoid NoDynamicFeeEstimates
        try:
            self.mktx_for_open_channel(coins=coins, funding_sat=min_funding_sat, node_id=bytes(32), fee_est=fee_est)
            funding_sat = min_funding_sat
        except NotEnoughFunds:
            return
        # if available, suggest twice that amount:
        if 2 * min_funding_sat <= self.config.LIGHTNING_MAX_FUNDING_SAT:
            try:
                self.mktx_for_open_channel(coins=coins, funding_sat=2*min_funding_sat, node_id=bytes(32), fee_est=fee_est)
                funding_sat = 2 * min_funding_sat
            except NotEnoughFunds:
                pass
        return funding_sat, min_funding_sat

    def open_channel(
            self, *,
            connect_str: str,
            funding_tx: PartialTransaction,
            funding_sat: int,
            push_amt_sat: int,
            public: bool = False,
            password: str = None) -> Tuple[Channel, PartialTransaction]:

        if funding_sat > self.config.LIGHTNING_MAX_FUNDING_SAT:
            raise Exception(_("Requested channel capacity is over maximum."))

        fut = asyncio.run_coroutine_threadsafe(self.add_peer(connect_str), self.network.asyncio_loop)
        try:
            peer = fut.result()
        except concurrent.futures.TimeoutError:
            raise Exception(_("add peer timed out"))
        coro = self._open_channel_coroutine(
            peer=peer,
            funding_tx=funding_tx,
            funding_sat=funding_sat,
            push_sat=push_amt_sat,
            public=public,
            password=password)
        fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
        try:
            chan, funding_tx = fut.result()
        except concurrent.futures.TimeoutError:
            raise Exception(_("open_channel timed out"))
        return chan, funding_tx

    def get_channel_by_short_id(self, short_channel_id: bytes) -> Optional[Channel]:
        # First check against *real* SCIDs.
        # This e.g. protects against maliciously chosen SCID aliases, and accidental collisions.
        for chan in self.channels.values():
            if chan.short_channel_id == short_channel_id:
                return chan
        # Now we also consider aliases.
        # TODO we should split this as this search currently ignores the "direction"
        #      of the aliases. We should only look at either the remote OR the local alias,
        #      depending on context.
        for chan in self.channels.values():
            if chan.get_remote_scid_alias() == short_channel_id:
                return chan
            if chan.get_local_scid_alias() == short_channel_id:
                return chan

    def can_pay_invoice(self, invoice: Invoice) -> bool:
        assert invoice.is_lightning()
        return (invoice.get_amount_sat() or 0) <= self.num_sats_can_send()

    @log_exceptions
    async def pay_invoice(
            self, invoice: str, *,
            amount_msat: int = None,
            attempts: int = None,  # used only in unit tests
            full_path: LNPaymentPath = None,
            channels: Optional[Sequence[Channel]] = None,
    ) -> Tuple[bool, List[HtlcLog]]:

        lnaddr = self._check_invoice(invoice, amount_msat=amount_msat)
        min_final_cltv_delta = lnaddr.get_min_final_cltv_delta()
        payment_hash = lnaddr.paymenthash
        key = payment_hash.hex()
        payment_secret = lnaddr.payment_secret
        invoice_pubkey = lnaddr.pubkey.serialize()
        invoice_features = lnaddr.get_features()
        r_tags = lnaddr.get_routing_info('r')
        amount_to_pay = lnaddr.get_amount_msat()
        status = self.get_payment_status(payment_hash)
        if status == PR_PAID:
            raise PaymentFailure(_("This invoice has been paid already"))
        if status == PR_INFLIGHT:
            raise PaymentFailure(_("A payment was already initiated for this invoice"))
        if payment_hash in self.get_payments(status='inflight'):
            raise PaymentFailure(_("A previous attempt to pay this invoice did not clear"))
        info = PaymentInfo(payment_hash, amount_to_pay, SENT, PR_UNPAID)
        self.save_payment_info(info)
        self.wallet.set_label(key, lnaddr.get_description())
        self.set_invoice_status(key, PR_INFLIGHT)
        budget = PaymentFeeBudget.default(invoice_amount_msat=amount_to_pay, config=self.config)
        success = False
        try:
            await self.pay_to_node(
                node_pubkey=invoice_pubkey,
                payment_hash=payment_hash,
                payment_secret=payment_secret,
                amount_to_pay=amount_to_pay,
                min_final_cltv_delta=min_final_cltv_delta,
                r_tags=r_tags,
                invoice_features=invoice_features,
                attempts=attempts,
                full_path=full_path,
                channels=channels,
                budget=budget,
            )
            success = True
        except PaymentFailure as e:
            self.logger.info(f'payment failure: {e!r}')
            reason = str(e)
        except ChannelDBNotLoaded as e:
            self.logger.info(f'payment failure: {e!r}')
            reason = str(e)
        finally:
            self.logger.info(f"pay_invoice ending session for RHASH={payment_hash.hex()}. {success=}")
        if success:
            self.set_invoice_status(key, PR_PAID)
            util.trigger_callback('payment_succeeded', self.wallet, key)
        else:
            self.set_invoice_status(key, PR_UNPAID)
            util.trigger_callback('payment_failed', self.wallet, key, reason)
        log = self.logs[key]
        return success, log

    async def pay_to_node(
            self, *,
            node_pubkey: bytes,
            payment_hash: bytes,
            payment_secret: bytes,
            amount_to_pay: int,  # in msat
            min_final_cltv_delta: int,
            r_tags,
            invoice_features: int,
            attempts: int = None,
            full_path: LNPaymentPath = None,
            fwd_trampoline_onion: OnionPacket = None,
            budget: PaymentFeeBudget,
            channels: Optional[Sequence[Channel]] = None,
            fw_payment_key = None,# for forwarding
    ) -> None:

        assert budget
        assert budget.fee_msat >= 0, budget
        assert budget.cltv >= 0, budget

        payment_key = payment_hash + payment_secret
        assert payment_key not in self._paysessions
        self._paysessions[payment_key] = paysession = PaySession(
            payment_hash=payment_hash,
            payment_secret=payment_secret,
            initial_trampoline_fee_level=self.config.INITIAL_TRAMPOLINE_FEE_LEVEL,
            invoice_features=invoice_features,
            r_tags=r_tags,
            min_final_cltv_delta=min_final_cltv_delta,
            amount_to_pay=amount_to_pay,
            invoice_pubkey=node_pubkey,
            uses_trampoline=self.uses_trampoline(),
            use_two_trampolines=self.config.LIGHTNING_LEGACY_ADD_TRAMPOLINE,
        )
        self.logs[payment_hash.hex()] = log = []  # TODO incl payment_secret in key (re trampoline forwarding)

        paysession.logger.info(
            f"pay_to_node starting session for RHASH={payment_hash.hex()}. "
            f"using_trampoline={self.uses_trampoline()}. "
            f"invoice_features={paysession.invoice_features.get_names()}. "
            f"{amount_to_pay=} msat. {budget=}")
        if not self.uses_trampoline():
            self.logger.info(
                f"gossip_db status. sync progress: {self.network.lngossip.get_sync_progress_estimate()}. "
                f"num_nodes={self.channel_db.num_nodes}, "
                f"num_channels={self.channel_db.num_channels}, "
                f"num_policies={self.channel_db.num_policies}.")

        # when encountering trampoline forwarding difficulties in the legacy case, we
        # sometimes need to fall back to a single trampoline forwarder, at the expense
        # of privacy
        try:
            while True:
                if (amount_to_send := paysession.get_outstanding_amount_to_send()) > 0:
                    # 1. create a set of routes for remaining amount.
                    # note: path-finding runs in a separate thread so that we don't block the asyncio loop
                    # graph updates might occur during the computation
                    remaining_fee_budget_msat = (budget.fee_msat * amount_to_send) // amount_to_pay
                    routes = self.create_routes_for_payment(
                        paysession=paysession,
                        amount_msat=amount_to_send,
                        full_path=full_path,
                        fwd_trampoline_onion=fwd_trampoline_onion,
                        channels=channels,
                        budget=budget._replace(fee_msat=remaining_fee_budget_msat),
                    )
                    # 2. send htlcs
                    async for sent_htlc_info, cltv_delta, trampoline_onion in routes:
                        await self.pay_to_route(
                            paysession=paysession,
                            sent_htlc_info=sent_htlc_info,
                            min_final_cltv_delta=cltv_delta,
                            trampoline_onion=trampoline_onion,
                            fw_payment_key=fw_payment_key,
                        )
                    # invoice_status is triggered in self.set_invoice_status when it actually changes.
                    # It is also triggered here to update progress for a lightning payment in the GUI
                    # (e.g. attempt counter)
                    util.trigger_callback('invoice_status', self.wallet, payment_hash.hex(), PR_INFLIGHT)
                # 3. await a queue
                htlc_log = await paysession.wait_for_one_htlc_to_resolve()  # TODO maybe wait a bit, more failures might come
                log.append(htlc_log)
                if htlc_log.success:
                    if self.network.path_finder:
                        # TODO: report every route to liquidity hints for mpp
                        # in the case of success, we report channels of the
                        # route as being able to send the same amount in the future,
                        # as we assume to not know the capacity
                        self.network.path_finder.update_liquidity_hints(htlc_log.route, htlc_log.amount_msat)
                        # remove inflight htlcs from liquidity hints
                        self.network.path_finder.update_inflight_htlcs(htlc_log.route, add_htlcs=False)
                    return
                # htlc failed
                # if we get a tmp channel failure, it might work to split the amount and try more routes
                # if we get a channel update, we might retry the same route and amount
                route = htlc_log.route
                sender_idx = htlc_log.sender_idx
                failure_msg = htlc_log.failure_msg
                if sender_idx is None:
                    raise PaymentFailure(failure_msg.code_name())
                erring_node_id = route[sender_idx].node_id
                code, data = failure_msg.code, failure_msg.data
                self.logger.info(f"UPDATE_FAIL_HTLC. code={repr(code)}. "
                                 f"decoded_data={failure_msg.decode_data()}. data={data.hex()!r}")
                self.logger.info(f"error reported by {erring_node_id.hex()}")
                if code == OnionFailureCode.MPP_TIMEOUT:
                    raise PaymentFailure(failure_msg.code_name())
                # errors returned by the next trampoline.
                if fwd_trampoline_onion and code in [
                        OnionFailureCode.TRAMPOLINE_FEE_INSUFFICIENT,
                        OnionFailureCode.TRAMPOLINE_EXPIRY_TOO_SOON]:
                    raise failure_msg
                # trampoline
                if self.uses_trampoline():
                    paysession.handle_failed_trampoline_htlc(
                        htlc_log=htlc_log, failure_msg=failure_msg)
                else:
                    self.handle_error_code_from_failed_htlc(
                        route=route, sender_idx=sender_idx, failure_msg=failure_msg, amount=htlc_log.amount_msat)
                # max attempts or timeout
                if (attempts is not None and len(log) >= attempts) or (attempts is None and time.time() - paysession.start_time > self.PAYMENT_TIMEOUT):
                    raise PaymentFailure('Giving up after %d attempts'%len(log))
        finally:
            paysession.is_active = False
            if paysession.can_be_deleted():
                self._paysessions.pop(payment_key)
            paysession.logger.info(f"pay_to_node ending session for RHASH={payment_hash.hex()}")

    async def pay_to_route(
            self, *,
            paysession: PaySession,
            sent_htlc_info: SentHtlcInfo,
            min_final_cltv_delta: int,
            trampoline_onion: Optional[OnionPacket] = None,
            fw_payment_key: str = None,
    ) -> None:
        """Sends a single HTLC."""
        shi = sent_htlc_info
        del sent_htlc_info  # just renamed
        short_channel_id = shi.route[0].short_channel_id
        chan = self.get_channel_by_short_id(short_channel_id)
        assert chan, ShortChannelID(short_channel_id)
        peer = self._peers.get(shi.route[0].node_id)
        if not peer:
            raise PaymentFailure('Dropped peer')
        await peer.initialized
        htlc = peer.pay(
            route=shi.route,
            chan=chan,
            amount_msat=shi.amount_msat,
            total_msat=shi.bucket_msat,
            payment_hash=paysession.payment_hash,
            min_final_cltv_delta=min_final_cltv_delta,
            payment_secret=shi.payment_secret_bucket,
            trampoline_onion=trampoline_onion)

        key = (paysession.payment_hash, short_channel_id, htlc.htlc_id)
        self.sent_htlcs_info[key] = shi
        paysession.add_new_htlc(shi)
        if fw_payment_key:
            htlc_key = serialize_htlc_key(short_channel_id, htlc.htlc_id)
            self.logger.info(f'adding active forwarding {fw_payment_key}')
            self.active_forwardings[fw_payment_key].append(htlc_key)
        if self.network.path_finder:
            # add inflight htlcs to liquidity hints
            self.network.path_finder.update_inflight_htlcs(shi.route, add_htlcs=True)
        util.trigger_callback('htlc_added', chan, htlc, SENT)

    def handle_error_code_from_failed_htlc(
            self,
            *,
            route: LNPaymentRoute,
            sender_idx: int,
            failure_msg: OnionRoutingFailure,
            amount: int) -> None:

        assert self.channel_db  # cannot be in trampoline mode
        assert self.network.path_finder

        # remove inflight htlcs from liquidity hints
        self.network.path_finder.update_inflight_htlcs(route, add_htlcs=False)

        code, data = failure_msg.code, failure_msg.data
        # TODO can we use lnmsg.OnionWireSerializer here?
        # TODO update onion_wire.csv
        # handle some specific error codes
        failure_codes = {
            OnionFailureCode.TEMPORARY_CHANNEL_FAILURE: 0,
            OnionFailureCode.AMOUNT_BELOW_MINIMUM: 8,
            OnionFailureCode.FEE_INSUFFICIENT: 8,
            OnionFailureCode.INCORRECT_CLTV_EXPIRY: 4,
            OnionFailureCode.EXPIRY_TOO_SOON: 0,
            OnionFailureCode.CHANNEL_DISABLED: 2,
        }
        try:
            failing_channel = route[sender_idx + 1].short_channel_id
        except IndexError:
            raise PaymentFailure(f'payment destination reported error: {failure_msg.code_name()}') from None

        # TODO: handle unknown next peer?
        # handle failure codes that include a channel update
        if code in failure_codes:
            offset = failure_codes[code]
            channel_update_len = int.from_bytes(data[offset:offset+2], byteorder="big")
            channel_update_as_received = data[offset+2: offset+2+channel_update_len]
            payload = self._decode_channel_update_msg(channel_update_as_received)
            if payload is None:
                self.logger.info(f'could not decode channel_update for failed htlc: '
                                 f'{channel_update_as_received.hex()}')
                blacklist = True
            elif payload.get('short_channel_id') != failing_channel:
                self.logger.info(f'short_channel_id in channel_update does not match our route')
                blacklist = True
            else:
                # apply the channel update or get blacklisted
                blacklist, update = self._handle_chanupd_from_failed_htlc(
                    payload, route=route, sender_idx=sender_idx, failure_msg=failure_msg)
                # we interpret a temporary channel failure as a liquidity issue
                # in the channel and update our liquidity hints accordingly
                if code == OnionFailureCode.TEMPORARY_CHANNEL_FAILURE:
                    self.network.path_finder.update_liquidity_hints(
                        route,
                        amount,
                        failing_channel=ShortChannelID(failing_channel))
                # if we can't decide on some action, we are stuck
                if not (blacklist or update):
                    raise PaymentFailure(failure_msg.code_name())
        # for errors that do not include a channel update
        else:
            blacklist = True
        if blacklist:
            self.network.path_finder.add_edge_to_blacklist(short_channel_id=failing_channel)

    def _handle_chanupd_from_failed_htlc(
        self, payload, *,
        route: LNPaymentRoute,
        sender_idx: int,
        failure_msg: OnionRoutingFailure,
    ) -> Tuple[bool, bool]:
        blacklist = False
        update = False
        try:
            r = self.channel_db.add_channel_update(payload, verify=True)
        except InvalidGossipMsg:
            return True, False  # blacklist
        short_channel_id = ShortChannelID(payload['short_channel_id'])
        if r == UpdateStatus.GOOD:
            self.logger.info(f"applied channel update to {short_channel_id}")
            # TODO: add test for this
            # FIXME: this does not work for our own unannounced channels.
            for chan in self.channels.values():
                if chan.short_channel_id == short_channel_id:
                    chan.set_remote_update(payload)
            update = True
        elif r == UpdateStatus.ORPHANED:
            # maybe it is a private channel (and data in invoice was outdated)
            self.logger.info(f"Could not find {short_channel_id}. maybe update is for private channel?")
            start_node_id = route[sender_idx].node_id
            cache_ttl = None
            if failure_msg.code == OnionFailureCode.CHANNEL_DISABLED:
                # eclair sends CHANNEL_DISABLED if its peer is offline. E.g. we might be trying to pay
                # a mobile phone with the app closed. So we cache this with a short TTL.
                cache_ttl = self.channel_db.PRIVATE_CHAN_UPD_CACHE_TTL_SHORT
            update = self.channel_db.add_channel_update_for_private_channel(payload, start_node_id, cache_ttl=cache_ttl)
            blacklist = not update
        elif r == UpdateStatus.EXPIRED:
            blacklist = True
        elif r == UpdateStatus.DEPRECATED:
            self.logger.info(f'channel update is not more recent.')
            blacklist = True
        elif r == UpdateStatus.UNCHANGED:
            blacklist = True
        return blacklist, update

    @classmethod
    def _decode_channel_update_msg(cls, chan_upd_msg: bytes) -> Optional[Dict[str, Any]]:
        channel_update_as_received = chan_upd_msg
        channel_update_typed = (258).to_bytes(length=2, byteorder="big") + channel_update_as_received
        # note: some nodes put channel updates in error msgs with the leading msg_type already there.
        #       we try decoding both ways here.
        try:
            message_type, payload = decode_msg(channel_update_typed)
            if payload['chain_hash'] != constants.net.rev_genesis_bytes(): raise Exception()
            payload['raw'] = channel_update_typed
            return payload
        except Exception:  # FIXME: too broad
            try:
                message_type, payload = decode_msg(channel_update_as_received)
                if payload['chain_hash'] != constants.net.rev_genesis_bytes(): raise Exception()
                payload['raw'] = channel_update_as_received
                return payload
            except Exception:
                return None

    def _check_invoice(self, invoice: str, *, amount_msat: int = None) -> LnAddr:
        """Parses and validates a bolt11 invoice str into a LnAddr.
        Includes pre-payment checks external to the parser.
        """
        addr = lndecode(invoice)
        if addr.is_expired():
            raise InvoiceError(_("This invoice has expired"))
        # check amount
        if amount_msat:  # replace amt in invoice. main usecase is paying zero amt invoices
            existing_amt_msat = addr.get_amount_msat()
            if existing_amt_msat and amount_msat < existing_amt_msat:
                raise Exception("cannot pay lower amt than what is originally in LN invoice")
            addr.amount = Decimal(amount_msat) / COIN / 1000
        if addr.amount is None:
            raise InvoiceError(_("Missing amount"))
        # check cltv
        if addr.get_min_final_cltv_delta() > lnutil.NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE:
            raise InvoiceError("{}\n{}".format(
                _("Invoice wants us to risk locking funds for unreasonably long."),
                f"min_final_cltv_delta: {addr.get_min_final_cltv_delta()}"))
        # check features
        addr.validate_and_compare_features(self.features)
        return addr

    def is_trampoline_peer(self, node_id: bytes) -> bool:
        # until trampoline is advertised in lnfeatures, check against hardcoded list
        if is_hardcoded_trampoline(node_id):
            return True
        peer = self._peers.get(node_id)
        if not peer:
            return False
        return (peer.their_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ECLAIR)\
                or peer.their_features.supports(LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM))

    def suggest_peer(self) -> Optional[bytes]:
        if not self.uses_trampoline():
            return self.lnrater.suggest_peer()
        else:
            return random.choice(list(hardcoded_trampoline_nodes().values())).pubkey

    def suggest_splits(
        self,
        *,
        amount_msat: int,
        final_total_msat: int,
        my_active_channels: Sequence[Channel],
        invoice_features: LnFeatures,
        r_tags,
    ) -> List['SplitConfigRating']:
        channels_with_funds = {
            (chan.channel_id, chan.node_id): int(chan.available_to_spend(HTLCOwner.LOCAL))
            for chan in my_active_channels
        }
        self.logger.info(f"channels_with_funds: {channels_with_funds}")
        exclude_single_part_payments = False
        if self.uses_trampoline():
            # in the case of a legacy payment, we don't allow splitting via different
            # trampoline nodes, because of https://github.com/ACINQ/eclair/issues/2127
            is_legacy, _ = is_legacy_relay(invoice_features, r_tags)
            exclude_multinode_payments = is_legacy
            # we don't split within a channel when sending to a trampoline node,
            # the trampoline node will split for us
            exclude_single_channel_splits = True
        else:
            exclude_multinode_payments = False
            exclude_single_channel_splits = False
            if invoice_features.supports(LnFeatures.BASIC_MPP_OPT) and not self.config.TEST_FORCE_DISABLE_MPP:
                # if amt is still large compared to total_msat, split it:
                if (amount_msat / final_total_msat > self.MPP_SPLIT_PART_FRACTION
                        and amount_msat > self.MPP_SPLIT_PART_MINAMT_MSAT):
                    exclude_single_part_payments = True

        def get_splits():
            return suggest_splits(
                amount_msat,
                channels_with_funds,
                exclude_single_part_payments=exclude_single_part_payments,
                exclude_multinode_payments=exclude_multinode_payments,
                exclude_single_channel_splits=exclude_single_channel_splits
            )

        split_configurations = get_splits()
        if not split_configurations and exclude_single_part_payments:
            exclude_single_part_payments = False
            split_configurations = get_splits()
        self.logger.info(f'suggest_split {amount_msat} returned {len(split_configurations)} configurations')
        return split_configurations

    async def create_routes_for_payment(
            self, *,
            paysession: PaySession,
            amount_msat: int,        # part of payment amount we want routes for now
            fwd_trampoline_onion: OnionPacket = None,
            full_path: LNPaymentPath = None,
            channels: Optional[Sequence[Channel]] = None,
            budget: PaymentFeeBudget,
    ) -> AsyncGenerator[Tuple[SentHtlcInfo, int, Optional[OnionPacket]], None]:

        """Creates multiple routes for splitting a payment over the available
        private channels.

        We first try to conduct the payment over a single channel. If that fails
        and mpp is supported by the receiver, we will split the payment."""
        trampoline_features = LnFeatures.VAR_ONION_OPT
        local_height = self.network.get_local_height()
        if channels:
            my_active_channels = channels
        else:
            my_active_channels = [
                chan for chan in self.channels.values() if
                chan.is_active() and not chan.is_frozen_for_sending()]
        # try random order
        random.shuffle(my_active_channels)
        split_configurations = self.suggest_splits(
            amount_msat=amount_msat,
            final_total_msat=paysession.amount_to_pay,
            my_active_channels=my_active_channels,
            invoice_features=paysession.invoice_features,
            r_tags=paysession.r_tags,
        )
        for sc in split_configurations:
            is_multichan_mpp = len(sc.config.items()) > 1
            is_mpp = sc.config.number_parts() > 1
            if is_mpp and not paysession.invoice_features.supports(LnFeatures.BASIC_MPP_OPT):
                continue
            if not is_mpp and self.config.TEST_FORCE_MPP:
                continue
            if is_mpp and self.config.TEST_FORCE_DISABLE_MPP:
                continue
            self.logger.info(f"trying split configuration: {sc.config.values()} rating: {sc.rating}")
            routes = []
            try:
                if self.uses_trampoline():
                    per_trampoline_channel_amounts = defaultdict(list)
                    # categorize by trampoline nodes for trampoline mpp construction
                    for (chan_id, _), part_amounts_msat in sc.config.items():
                        chan = self.channels[chan_id]
                        for part_amount_msat in part_amounts_msat:
                            per_trampoline_channel_amounts[chan.node_id].append((chan_id, part_amount_msat))
                    # for each trampoline forwarder, construct mpp trampoline
                    for trampoline_node_id, trampoline_parts in per_trampoline_channel_amounts.items():
                        per_trampoline_amount = sum([x[1] for x in trampoline_parts])
                        trampoline_route, trampoline_onion, per_trampoline_amount_with_fees, per_trampoline_cltv_delta = create_trampoline_route_and_onion(
                            amount_msat=per_trampoline_amount,
                            total_msat=paysession.amount_to_pay,
                            min_final_cltv_delta=paysession.min_final_cltv_delta,
                            my_pubkey=self.node_keypair.pubkey,
                            invoice_pubkey=paysession.invoice_pubkey,
                            invoice_features=paysession.invoice_features,
                            node_id=trampoline_node_id,
                            r_tags=paysession.r_tags,
                            payment_hash=paysession.payment_hash,
                            payment_secret=paysession.payment_secret,
                            local_height=local_height,
                            trampoline_fee_level=paysession.trampoline_fee_level,
                            use_two_trampolines=paysession.use_two_trampolines,
                            failed_routes=paysession.failed_trampoline_routes,
                            budget=budget._replace(fee_msat=budget.fee_msat // len(per_trampoline_channel_amounts)),
                        )
                        # node_features is only used to determine is_tlv
                        per_trampoline_secret = os.urandom(32)
                        per_trampoline_fees = per_trampoline_amount_with_fees - per_trampoline_amount
                        self.logger.info(f'created route with trampoline fee level={paysession.trampoline_fee_level}')
                        self.logger.info(f'trampoline hops: {[hop.end_node.hex() for hop in trampoline_route]}')
                        self.logger.info(f'per trampoline fees: {per_trampoline_fees}')
                        for chan_id, part_amount_msat in trampoline_parts:
                            chan = self.channels[chan_id]
                            margin = chan.available_to_spend(LOCAL, strict=True) - part_amount_msat
                            delta_fee = min(per_trampoline_fees, margin)
                            # TODO: distribute trampoline fee over several channels?
                            part_amount_msat_with_fees = part_amount_msat + delta_fee
                            per_trampoline_fees -= delta_fee
                            route = [
                                RouteEdge(
                                    start_node=self.node_keypair.pubkey,
                                    end_node=trampoline_node_id,
                                    short_channel_id=chan.short_channel_id,
                                    fee_base_msat=0,
                                    fee_proportional_millionths=0,
                                    cltv_delta=0,
                                    node_features=trampoline_features)
                            ]
                            self.logger.info(f'adding route {part_amount_msat} {delta_fee} {margin}')
                            shi = SentHtlcInfo(
                                route=route,
                                payment_secret_orig=paysession.payment_secret,
                                payment_secret_bucket=per_trampoline_secret,
                                amount_msat=part_amount_msat_with_fees,
                                bucket_msat=per_trampoline_amount_with_fees,
                                amount_receiver_msat=part_amount_msat,
                                trampoline_fee_level=paysession.trampoline_fee_level,
                                trampoline_route=trampoline_route,
                            )
                            routes.append((shi, per_trampoline_cltv_delta, trampoline_onion))
                        if per_trampoline_fees != 0:
                            self.logger.info('not enough margin to pay trampoline fee')
                            raise NoPathFound()
                else:
                    # We atomically loop through a split configuration. If there was
                    # a failure to find a path for a single part, we try the next configuration
                    for (chan_id, _), part_amounts_msat in sc.config.items():
                        for part_amount_msat in part_amounts_msat:
                            channel = self.channels[chan_id]
                            route = await run_in_thread(
                                partial(
                                    self.create_route_for_single_htlc,
                                    amount_msat=part_amount_msat,
                                    invoice_pubkey=paysession.invoice_pubkey,
                                    min_final_cltv_delta=paysession.min_final_cltv_delta,
                                    r_tags=paysession.r_tags,
                                    invoice_features=paysession.invoice_features,
                                    my_sending_channels=[channel] if is_multichan_mpp else my_active_channels,
                                    full_path=full_path,
                                    budget=budget._replace(fee_msat=budget.fee_msat // sc.config.number_parts()),
                                )
                            )
                            shi = SentHtlcInfo(
                                route=route,
                                payment_secret_orig=paysession.payment_secret,
                                payment_secret_bucket=paysession.payment_secret,
                                amount_msat=part_amount_msat,
                                bucket_msat=paysession.amount_to_pay,
                                amount_receiver_msat=part_amount_msat,
                                trampoline_fee_level=None,
                                trampoline_route=None,
                            )
                            routes.append((shi, paysession.min_final_cltv_delta, fwd_trampoline_onion))
            except NoPathFound:
                continue
            for route in routes:
                yield route
            return
        raise NoPathFound()

    @profiler
    def create_route_for_single_htlc(
            self, *,
            amount_msat: int,  # that final receiver gets
            invoice_pubkey: bytes,
            min_final_cltv_delta: int,
            r_tags,
            invoice_features: int,
            my_sending_channels: List[Channel],
            full_path: Optional[LNPaymentPath],
            budget: PaymentFeeBudget,
    ) -> LNPaymentRoute:

        my_sending_aliases = set(chan.get_local_scid_alias() for chan in my_sending_channels)
        my_sending_channels = {chan.short_channel_id: chan for chan in my_sending_channels
            if chan.short_channel_id is not None}
        # Collect all private edges from route hints.
        # Note: if some route hints are multiple edges long, and these paths cross each other,
        #       we allow our path finding to cross the paths; i.e. the route hints are not isolated.
        private_route_edges = {}  # type: Dict[ShortChannelID, RouteEdge]
        for private_path in r_tags:
            # we need to shift the node pubkey by one towards the destination:
            private_path_nodes = [edge[0] for edge in private_path][1:] + [invoice_pubkey]
            private_path_rest = [edge[1:] for edge in private_path]
            start_node = private_path[0][0]
            # remove aliases from direct routes
            if len(private_path) == 1 and private_path[0][1] in my_sending_aliases:
                self.logger.info(f'create_route: skipping alias {ShortChannelID(private_path[0][1])}')
                continue
            for end_node, edge_rest in zip(private_path_nodes, private_path_rest):
                short_channel_id, fee_base_msat, fee_proportional_millionths, cltv_delta = edge_rest
                short_channel_id = ShortChannelID(short_channel_id)
                # if we have a routing policy for this edge in the db, that takes precedence,
                # as it is likely from a previous failure
                channel_policy = self.channel_db.get_policy_for_node(
                    short_channel_id=short_channel_id,
                    node_id=start_node,
                    my_channels=my_sending_channels)
                if channel_policy:
                    fee_base_msat = channel_policy.fee_base_msat
                    fee_proportional_millionths = channel_policy.fee_proportional_millionths
                    cltv_delta = channel_policy.cltv_delta
                node_info = self.channel_db.get_node_info_for_node_id(node_id=end_node)
                route_edge = RouteEdge(
                        start_node=start_node,
                        end_node=end_node,
                        short_channel_id=short_channel_id,
                        fee_base_msat=fee_base_msat,
                        fee_proportional_millionths=fee_proportional_millionths,
                        cltv_delta=cltv_delta,
                        node_features=node_info.features if node_info else 0)
                private_route_edges[route_edge.short_channel_id] = route_edge
                start_node = end_node
        # now find a route, end to end: between us and the recipient
        try:
            route = self.network.path_finder.find_route(
                nodeA=self.node_keypair.pubkey,
                nodeB=invoice_pubkey,
                invoice_amount_msat=amount_msat,
                path=full_path,
                my_sending_channels=my_sending_channels,
                private_route_edges=private_route_edges)
        except NoChannelPolicy as e:
            raise NoPathFound() from e
        if not route:
            raise NoPathFound()
        if not is_route_within_budget(
            route, budget=budget, amount_msat_for_dest=amount_msat, cltv_delta_for_dest=min_final_cltv_delta,
        ):
            self.logger.info(f"rejecting route (exceeds budget): {route=}. {budget=}")
            raise NoPathFound()
        assert len(route) > 0
        if route[-1].end_node != invoice_pubkey:
            raise LNPathInconsistent("last node_id != invoice pubkey")
        # add features from invoice
        route[-1].node_features |= invoice_features
        return route

    def clear_invoices_cache(self):
        self._bolt11_cache.clear()

    def get_bolt11_invoice(
            self, *,
            payment_hash: bytes,
            amount_msat: Optional[int],
            message: str,
            expiry: int,  # expiration of invoice (in seconds, relative)
            fallback_address: Optional[str],
            channels: Optional[Sequence[Channel]] = None,
            min_final_cltv_expiry_delta: Optional[int] = None,
    ) -> Tuple[LnAddr, str]:
        assert isinstance(payment_hash, bytes), f"expected bytes, but got {type(payment_hash)}"

        pair = self._bolt11_cache.get(payment_hash)
        if pair:
            lnaddr, invoice = pair
            assert lnaddr.get_amount_msat() == amount_msat
            return pair

        assert amount_msat is None or amount_msat > 0
        timestamp = int(time.time())
        routing_hints = self.calc_routing_hints_for_invoice(amount_msat, channels=channels)
        self.logger.info(f"creating bolt11 invoice with routing_hints: {routing_hints}")
        invoice_features = self.features.for_invoice()
        if not self.uses_trampoline():
            invoice_features &= ~ LnFeatures.OPTION_TRAMPOLINE_ROUTING_OPT_ELECTRUM
        payment_secret = self.get_payment_secret(payment_hash)
        amount_btc = amount_msat/Decimal(COIN*1000) if amount_msat else None
        if expiry == 0:
            expiry = LN_EXPIRY_NEVER
        if min_final_cltv_expiry_delta is None:
            min_final_cltv_expiry_delta = MIN_FINAL_CLTV_DELTA_FOR_INVOICE
        lnaddr = LnAddr(
            paymenthash=payment_hash,
            amount=amount_btc,
            tags=[
                ('d', message),
                ('c', min_final_cltv_expiry_delta),
                ('x', expiry),
                ('9', invoice_features),
                ('f', fallback_address),
            ] + routing_hints,
            date=timestamp,
            payment_secret=payment_secret)
        invoice = lnencode(lnaddr, self.node_keypair.privkey)
        pair = lnaddr, invoice
        self._bolt11_cache[payment_hash] = pair
        return pair

    def get_payment_secret(self, payment_hash):
        return sha256(sha256(self.payment_secret_key) + payment_hash)

    def _get_payment_key(self, payment_hash: bytes) -> bytes:
        """Return payment bucket key.
        We bucket htlcs based on payment_hash+payment_secret. payment_secret is included
        as it changes over a trampoline path (in the outer onion), and these paths can overlap.
        """
        payment_secret = self.get_payment_secret(payment_hash)
        return payment_hash + payment_secret

    def create_payment_info(self, *, amount_msat: Optional[int], write_to_disk=True) -> bytes:
        payment_preimage = os.urandom(32)
        payment_hash = sha256(payment_preimage)
        info = PaymentInfo(payment_hash, amount_msat, RECEIVED, PR_UNPAID)
        self.save_preimage(payment_hash, payment_preimage, write_to_disk=False)
        self.save_payment_info(info, write_to_disk=False)
        if write_to_disk:
            self.wallet.save_db()
        return payment_hash

    def bundle_payments(self, hash_list):
        payment_keys = [self._get_payment_key(x) for x in hash_list]
        self.payment_bundles.append(payment_keys)

    def get_payment_bundle(self, payment_key):
        for key_list in self.payment_bundles:
            if payment_key in key_list:
                return key_list

    def save_preimage(self, payment_hash: bytes, preimage: bytes, *, write_to_disk: bool = True):
        if sha256(preimage) != payment_hash:
            raise Exception("tried to save incorrect preimage for payment_hash")
        self.preimages[payment_hash.hex()] = preimage.hex()
        if write_to_disk:
            self.wallet.save_db()

    def get_preimage(self, payment_hash: bytes) -> Optional[bytes]:
        assert isinstance(payment_hash, bytes), f"expected bytes, but got {type(payment_hash)}"
        preimage_hex = self.preimages.get(payment_hash.hex())
        if preimage_hex is None:
            return None
        preimage_bytes = bytes.fromhex(preimage_hex)
        if sha256(preimage_bytes) != payment_hash:
            raise Exception("found incorrect preimage for payment_hash")
        return preimage_bytes

    def get_payment_info(self, payment_hash: bytes) -> Optional[PaymentInfo]:
        """returns None if payment_hash is a payment we are forwarding"""
        key = payment_hash.hex()
        with self.lock:
            if key in self.payment_info:
                amount_msat, direction, status = self.payment_info[key]
                return PaymentInfo(payment_hash, amount_msat, direction, status)

    def add_payment_info_for_hold_invoice(self, payment_hash: bytes, lightning_amount_sat: int):
        info = PaymentInfo(payment_hash, lightning_amount_sat * 1000, RECEIVED, PR_UNPAID)
        self.save_payment_info(info, write_to_disk=False)

    def register_hold_invoice(self, payment_hash: bytes, cb: Callable[[bytes], Awaitable[None]]):
        self.hold_invoice_callbacks[payment_hash] = cb

    def unregister_hold_invoice(self, payment_hash: bytes):
        self.hold_invoice_callbacks.pop(payment_hash)

    def save_payment_info(self, info: PaymentInfo, *, write_to_disk: bool = True) -> None:
        key = info.payment_hash.hex()
        assert info.status in SAVED_PR_STATUS
        with self.lock:
            self.payment_info[key] = info.amount_msat, info.direction, info.status
        if write_to_disk:
            self.wallet.save_db()

    def check_mpp_status(
            self, *,
            payment_secret: bytes,
            short_channel_id: ShortChannelID,
            htlc: UpdateAddHtlc,
            expected_msat: int,
    ) -> RecvMPPResolution:
        """Returns the status of the incoming htlc set the given *htlc* belongs to.

        ACCEPTED simply means the mpp set is complete, and we can proceed with further
        checks before fulfilling (or failing) the htlcs.
        In particular, note that hold-invoice-htlcs typically remain in the ACCEPTED state
        for quite some time -- not in the "WAITING" state (which would refer to the mpp set
        not yet being complete!).
        """
        payment_hash = htlc.payment_hash
        payment_key = payment_hash + payment_secret
        self.update_mpp_with_received_htlc(
            payment_key=payment_key, scid=short_channel_id, htlc=htlc, expected_msat=expected_msat)
        mpp_resolution = self.received_mpp_htlcs[payment_key].resolution
        # if still waiting, calc resolution now:
        if mpp_resolution == RecvMPPResolution.WAITING:
            bundle = self.get_payment_bundle(payment_key)
            if bundle:
                payment_keys = bundle
            else:
                payment_keys = [payment_key]
            first_timestamp = min([self.get_first_timestamp_of_mpp(pkey) for pkey in payment_keys])
            if self.get_payment_status(payment_hash) == PR_PAID:
                mpp_resolution = RecvMPPResolution.ACCEPTED
            elif self.stopping_soon:
                # try to time out pending HTLCs before shutting down
                mpp_resolution = RecvMPPResolution.EXPIRED
            elif all([self.is_mpp_amount_reached(pkey) for pkey in payment_keys]):
                mpp_resolution = RecvMPPResolution.ACCEPTED
            elif time.time() - first_timestamp > self.MPP_EXPIRY:
                mpp_resolution = RecvMPPResolution.EXPIRED
            # save resolution, if any.
            if mpp_resolution != RecvMPPResolution.WAITING:
                for pkey in payment_keys:
                    if pkey in self.received_mpp_htlcs:
                        self.set_mpp_resolution(payment_key=pkey, resolution=mpp_resolution)

        return mpp_resolution

    def update_mpp_with_received_htlc(
        self,
        *,
        payment_key: bytes,
        scid: ShortChannelID,
        htlc: UpdateAddHtlc,
        expected_msat: int,
    ):
        # add new htlc to set
        mpp_status = self.received_mpp_htlcs.get(payment_key)
        if mpp_status is None:
            mpp_status = ReceivedMPPStatus(
                resolution=RecvMPPResolution.WAITING,
                expected_msat=expected_msat,
                htlc_set=set(),
            )
        if expected_msat != mpp_status.expected_msat:
            self.logger.info(
                f"marking received mpp as failed. inconsistent total_msats in bucket. {payment_key.hex()=}")
            mpp_status = mpp_status._replace(resolution=RecvMPPResolution.FAILED)
        key = (scid, htlc)
        if key not in mpp_status.htlc_set:
            mpp_status.htlc_set.add(key)  # side-effecting htlc_set
        self.received_mpp_htlcs[payment_key] = mpp_status

    def set_mpp_resolution(self, *, payment_key: bytes, resolution: RecvMPPResolution):
        mpp_status = self.received_mpp_htlcs[payment_key]
        self.received_mpp_htlcs[payment_key] = mpp_status._replace(resolution=resolution)

    def is_mpp_amount_reached(self, payment_key: bytes) -> bool:
        mpp_status = self.received_mpp_htlcs.get(payment_key)
        if not mpp_status:
            return False
        total = sum([_htlc.amount_msat for scid, _htlc in mpp_status.htlc_set])
        return total >= mpp_status.expected_msat

    def get_first_timestamp_of_mpp(self, payment_key: bytes) -> int:
        mpp_status = self.received_mpp_htlcs.get(payment_key)
        if not mpp_status:
            return int(time.time())
        return min([_htlc.timestamp for scid, _htlc in mpp_status.htlc_set])

    def maybe_cleanup_forwarding(
            self,
            payment_key_hex: str,
            short_channel_id: ShortChannelID,
            htlc: UpdateAddHtlc,
    ) -> None:

        is_htlc_key = ':' in payment_key_hex
        if not is_htlc_key:
            payment_key = bytes.fromhex(payment_key_hex)
            mpp_status = self.received_mpp_htlcs.get(payment_key)
            if not mpp_status or mpp_status.resolution == RecvMPPResolution.WAITING:
                # After restart, self.received_mpp_htlcs needs to be reconstructed
                self.logger.info(f'maybe_cleanup_forwarding: mpp_status not ready')
                return
            htlc_key = (short_channel_id, htlc)
            mpp_status.htlc_set.remove(htlc_key)  # side-effecting htlc_set
            if mpp_status.htlc_set:
                return
            self.logger.info('cleaning up mpp')
            self.received_mpp_htlcs.pop(payment_key)

        self.active_forwardings.pop(payment_key_hex, None)
        self.forwarding_failures.pop(payment_key_hex, None)

    def get_payment_status(self, payment_hash: bytes) -> int:
        info = self.get_payment_info(payment_hash)
        return info.status if info else PR_UNPAID

    def get_invoice_status(self, invoice: BaseInvoice) -> int:
        invoice_id = invoice.rhash
        if invoice_id in self.inflight_payments:
            return PR_INFLIGHT
        # status may be PR_FAILED
        status = self.get_payment_status(bytes.fromhex(invoice_id))
        if status == PR_UNPAID and invoice_id in self.logs:
            status = PR_FAILED
        return status

    def set_invoice_status(self, key: str, status: int) -> None:
        if status == PR_INFLIGHT:
            self.inflight_payments.add(key)
        elif key in self.inflight_payments:
            self.inflight_payments.remove(key)
        if status in SAVED_PR_STATUS:
            self.set_payment_status(bfh(key), status)
        util.trigger_callback('invoice_status', self.wallet, key, status)
        self.logger.info(f"invoice status triggered (2) for key {key} and status {status}")
        # liquidity changed
        self.clear_invoices_cache()

    def set_request_status(self, payment_hash: bytes, status: int) -> None:
        if self.get_payment_status(payment_hash) == status:
            return
        self.set_payment_status(payment_hash, status)
        request_id = payment_hash.hex()
        req = self.wallet.get_request(request_id)
        if req is None:
            return
        util.trigger_callback('request_status', self.wallet, request_id, status)

    def set_payment_status(self, payment_hash: bytes, status: int) -> None:
        info = self.get_payment_info(payment_hash)
        if info is None:
            # if we are forwarding
            return
        info = info._replace(status=status)
        self.save_payment_info(info)

    def is_forwarded_htlc(self, htlc_key) -> Optional[str]:
        """Returns whether this was a forwarded HTLC."""
        for payment_key, htlcs in self.active_forwardings.items():
            if htlc_key in htlcs:
                return payment_key

    def notify_upstream_peer(self, htlc_key: str) -> None:
        """Called when an HTLC we offered on chan gets irrevocably fulfilled or failed.
        If we find this was a forwarded HTLC, the upstream peer is notified.
        """
        upstream_key = self.downstream_to_upstream_htlc.pop(htlc_key, None)
        if not upstream_key:
            return
        upstream_chan_scid, _ = deserialize_htlc_key(upstream_key)
        upstream_chan = self.get_channel_by_short_id(upstream_chan_scid)
        upstream_peer = self.peers.get(upstream_chan.node_id) if upstream_chan else None
        if upstream_peer:
            upstream_peer.downstream_htlc_resolved_event.set()
            upstream_peer.downstream_htlc_resolved_event.clear()

    def htlc_fulfilled(self, chan: Channel, payment_hash: bytes, htlc_id: int):

        util.trigger_callback('htlc_fulfilled', payment_hash, chan, htlc_id)
        htlc_key = serialize_htlc_key(chan.get_scid_or_local_alias(), htlc_id)
        fw_key = self.is_forwarded_htlc(htlc_key)
        if fw_key:
            fw_htlcs = self.active_forwardings[fw_key]
            fw_htlcs.remove(htlc_key)

        if shi := self.sent_htlcs_info.get((payment_hash, chan.short_channel_id, htlc_id)):
            chan.pop_onion_key(htlc_id)
            payment_key = payment_hash + shi.payment_secret_orig
            paysession = self._paysessions[payment_key]
            q = paysession.sent_htlcs_q
            htlc_log = HtlcLog(
                success=True,
                route=shi.route,
                amount_msat=shi.amount_receiver_msat,
                trampoline_fee_level=shi.trampoline_fee_level)
            q.put_nowait(htlc_log)
            if paysession.can_be_deleted():
                self._paysessions.pop(payment_key)
                paysession_active = False
            else:
                paysession_active = True
        else:
            if fw_key:
                paysession_active = False
            else:
                key = payment_hash.hex()
                self.set_invoice_status(key, PR_PAID)
                util.trigger_callback('payment_succeeded', self.wallet, key)

        if fw_key:
            fw_htlcs = self.active_forwardings[fw_key]
            if len(fw_htlcs) == 0 and not paysession_active:
                self.notify_upstream_peer(htlc_key)


    def htlc_failed(
            self,
            chan: Channel,
            payment_hash: bytes,
            htlc_id: int,
            error_bytes: Optional[bytes],
            failure_message: Optional['OnionRoutingFailure']):

        util.trigger_callback('htlc_failed', payment_hash, chan, htlc_id)
        htlc_key = serialize_htlc_key(chan.get_scid_or_local_alias(), htlc_id)
        fw_key = self.is_forwarded_htlc(htlc_key)
        if fw_key:
            fw_htlcs = self.active_forwardings[fw_key]
            fw_htlcs.remove(htlc_key)

        if shi := self.sent_htlcs_info.get((payment_hash, chan.short_channel_id, htlc_id)):
            onion_key = chan.pop_onion_key(htlc_id)
            payment_okey = payment_hash + shi.payment_secret_orig
            paysession = self._paysessions[payment_okey]
            q = paysession.sent_htlcs_q
            # detect if it is part of a bucket
            # if yes, wait until the bucket completely failed
            route = shi.route
            if error_bytes:
                # TODO "decode_onion_error" might raise, catch and maybe blacklist/penalise someone?
                try:
                    failure_message, sender_idx = decode_onion_error(
                        error_bytes,
                        [x.node_id for x in route],
                        onion_key)
                except Exception as e:
                    sender_idx = None
                    failure_message = OnionRoutingFailure(OnionFailureCode.INVALID_ONION_PAYLOAD, str(e).encode())
            else:
                # probably got "update_fail_malformed_htlc". well... who to penalise now?
                assert failure_message is not None
                sender_idx = None
            self.logger.info(f"htlc_failed {failure_message}")
            amount_receiver_msat = paysession.on_htlc_fail_get_fail_amt_to_propagate(shi)
            if amount_receiver_msat is None:
                return
            if shi.trampoline_route:
                route = shi.trampoline_route
            htlc_log = HtlcLog(
                success=False,
                route=route,
                amount_msat=amount_receiver_msat,
                error_bytes=error_bytes,
                failure_msg=failure_message,
                sender_idx=sender_idx,
                trampoline_fee_level=shi.trampoline_fee_level)
            q.put_nowait(htlc_log)
            if paysession.can_be_deleted():
                self._paysessions.pop(payment_okey)
                paysession_active = False
            else:
                paysession_active = True
        else:
            if fw_key:
                paysession_active = False
            else:
                self.logger.info(f"received unknown htlc_failed, probably from previous session (phash={payment_hash.hex()})")
                key = payment_hash.hex()
                self.set_invoice_status(key, PR_UNPAID)
                util.trigger_callback('payment_failed', self.wallet, key, '')

        if fw_key:
            fw_htlcs = self.active_forwardings[fw_key]
            can_forward_failure = (len(fw_htlcs) == 0) and not paysession_active
            if can_forward_failure:
                self.save_forwarding_failure(fw_key, error_bytes=error_bytes, failure_message=failure_message)
                self.notify_upstream_peer(htlc_key)
            else:
                self.logger.info(f"waiting for other htlcs to fail (phash={payment_hash.hex()})")

    def calc_routing_hints_for_invoice(self, amount_msat: Optional[int], channels=None):
        """calculate routing hints (BOLT-11 'r' field)"""
        routing_hints = []
        if self.config.ZEROCONF_TRUSTED_NODE:
            node_id, rest = extract_nodeid(self.config.ZEROCONF_TRUSTED_NODE)
            alias_or_scid = self.get_scid_alias()
            routing_hints.append(('r', [(node_id, alias_or_scid, 0, 0, 144)]))
            # no need for more
            channels = []
        else:
            if channels is None:
                channels = list(self.get_channels_for_receiving(amount_msat))
                random.shuffle(channels)  # let's not leak channel order
            scid_to_my_channels = {
                chan.short_channel_id: chan for chan in channels
                if chan.short_channel_id is not None
            }
        for chan in channels:
            alias_or_scid = chan.get_remote_scid_alias() or chan.short_channel_id
            assert isinstance(alias_or_scid, bytes), alias_or_scid
            channel_info = get_mychannel_info(chan.short_channel_id, scid_to_my_channels)
            # note: as a fallback, if we don't have a channel update for the
            # incoming direction of our private channel, we fill the invoice with garbage.
            # the sender should still be able to pay us, but will incur an extra round trip
            # (they will get the channel update from the onion error)
            # at least, that's the theory. https://github.com/lightningnetwork/lnd/issues/2066
            fee_base_msat = fee_proportional_millionths = 0
            cltv_delta = 1  # lnd won't even try with zero
            missing_info = True
            if channel_info:
                policy = get_mychannel_policy(channel_info.short_channel_id, chan.node_id, scid_to_my_channels)
                if policy:
                    fee_base_msat = policy.fee_base_msat
                    fee_proportional_millionths = policy.fee_proportional_millionths
                    cltv_delta = policy.cltv_delta
                    missing_info = False
            if missing_info:
                self.logger.info(
                    f"Warning. Missing channel update for our channel {chan.short_channel_id}; "
                    f"filling invoice with incorrect data.")
            routing_hints.append(('r', [(
                chan.node_id,
                alias_or_scid,
                fee_base_msat,
                fee_proportional_millionths,
                cltv_delta)]))
        return routing_hints

    def delete_payment_info(self, payment_hash_hex: str):
        # This method is called when an invoice or request is deleted by the user.
        # The GUI only lets the user delete invoices or requests that have not been paid.
        # Once an invoice/request has been paid, it is part of the history,
        # and get_lightning_history assumes that payment_info is there.
        assert self.get_payment_status(bytes.fromhex(payment_hash_hex)) != PR_PAID
        with self.lock:
            self.payment_info.pop(payment_hash_hex, None)

    def get_balance(self, frozen=False):
        with self.lock:
            return Decimal(sum(
                chan.balance(LOCAL) if not chan.is_closed() and (chan.is_frozen_for_sending() if frozen else True) else 0
                for chan in self.channels.values())) / 1000

    def get_channels_for_sending(self):
        for c in self.channels.values():
            if c.is_active() and not c.is_frozen_for_sending():
                if self.channel_db or self.is_trampoline_peer(c.node_id):
                    yield c

    def fee_estimate(self, amount_sat):
        # Here we have to guess a fee, because some callers (submarine swaps)
        # use this method to initiate a payment, which would otherwise fail.
        fee_base_msat = 5000               # FIXME ehh.. there ought to be a better way...
        fee_proportional_millionths = 500  # FIXME
        # inverse of fee_for_edge_msat
        amount_msat = amount_sat * 1000
        amount_minus_fees = (amount_msat - fee_base_msat) * 1_000_000 // ( 1_000_000 + fee_proportional_millionths)
        return Decimal(amount_msat - amount_minus_fees) / 1000

    def num_sats_can_send(self, deltas=None) -> Decimal:
        """
        without trampoline, sum of all channel capacity
        with trampoline, MPP must use a single trampoline
        """
        if deltas is None:
            deltas = {}
        def send_capacity(chan):
            if chan in deltas:
                delta_msat = deltas[chan] * 1000
                if delta_msat > chan.available_to_spend(REMOTE):
                    delta_msat = 0
            else:
                delta_msat = 0
            return chan.available_to_spend(LOCAL) + delta_msat
        can_send_dict = defaultdict(int)
        with self.lock:
            for c in self.get_channels_for_sending():
                if not self.uses_trampoline():
                    can_send_dict[0] += send_capacity(c)
                else:
                    can_send_dict[c.node_id] += send_capacity(c)
        can_send = max(can_send_dict.values()) if can_send_dict else 0
        can_send_sat = Decimal(can_send)/1000
        can_send_sat -= self.fee_estimate(can_send_sat)
        return max(can_send_sat, 0)

    def get_channels_for_receiving(self, amount_msat=None) -> Sequence[Channel]:
        if not amount_msat:  # assume we want to recv a large amt, e.g. finding max.
            amount_msat = float('inf')
        with self.lock:
            channels = list(self.channels.values())
            # we exclude channels that cannot *right now* receive (e.g. peer offline)
            channels = [chan for chan in channels
                        if (chan.is_open() and not chan.is_frozen_for_receiving())]
            # Filter out nodes that have low receive capacity compared to invoice amt.
            # Even with MPP, below a certain threshold, including these channels probably
            # hurts more than help, as they lead to many failed attempts for the sender.
            channels = sorted(channels, key=lambda chan: -chan.available_to_spend(REMOTE))
            selected_channels = []
            running_sum = 0
            cutoff_factor = 0.2  # heuristic
            for chan in channels:
                recv_capacity = chan.available_to_spend(REMOTE)
                chan_can_handle_payment_as_single_part = recv_capacity >= amount_msat
                chan_small_compared_to_running_sum = recv_capacity < cutoff_factor * running_sum
                if not chan_can_handle_payment_as_single_part and chan_small_compared_to_running_sum:
                    break
                running_sum += recv_capacity
                selected_channels.append(chan)
            channels = selected_channels
            del selected_channels
            # cap max channels to include to keep QR code reasonably scannable
            channels = channels[:10]
            return channels

    def num_sats_can_receive(self, deltas=None) -> Decimal:
        """
        We no longer assume the sender to send MPP on different channels,
        because channel liquidities are hard to guess
        """
        if deltas is None:
            deltas = {}
        def recv_capacity(chan):
            if chan in deltas:
                delta_msat = deltas[chan] * 1000
                if delta_msat > chan.available_to_spend(LOCAL):
                    delta_msat = 0
            else:
                delta_msat = 0
            return chan.available_to_spend(REMOTE) + delta_msat
        with self.lock:
            recv_channels = self.get_channels_for_receiving()
            recv_chan_msats = [recv_capacity(chan) for chan in recv_channels]
        if not recv_chan_msats:
            return Decimal(0)
        can_receive_msat = max(recv_chan_msats)
        return Decimal(can_receive_msat) / 1000


    def _suggest_channels_for_rebalance(self, direction, amount_sat) -> Sequence[Tuple[Channel, int]]:
        """
        Suggest a channel and amount to send/receive with that channel, so that we will be able to receive/send amount_sat
        This is used when suggesting a swap or rebalance in order to receive a payment
        """
        with self.lock:
            func = self.num_sats_can_send if direction == SENT else self.num_sats_can_receive
            suggestions = []
            channels = self.get_channels_for_sending() if direction == SENT else self.get_channels_for_receiving()
            for chan in channels:
                available_sat = chan.available_to_spend(LOCAL if direction == SENT else REMOTE) // 1000
                delta = amount_sat - available_sat
                delta += self.fee_estimate(amount_sat)
                # add safety margin
                delta += delta // 100 + 1
                if func(deltas={chan:delta}) >= amount_sat:
                    suggestions.append((chan, delta))
                elif direction==RECEIVED and func(deltas={chan:2*delta}) >= amount_sat:
                    # MPP heuristics has a 0.5 slope
                    suggestions.append((chan, 2*delta))
        if not suggestions:
            raise NotEnoughFunds
        return suggestions

    def _suggest_rebalance(self, direction, amount_sat):
        """
        Suggest a rebalance in order to be able to send or receive amount_sat.
        Returns (from_channel, to_channel, amount to shuffle)
        """
        try:
            suggestions = self._suggest_channels_for_rebalance(direction, amount_sat)
        except NotEnoughFunds:
            return False
        for chan2, delta in suggestions:
            # margin for fee caused by rebalancing
            delta += self.fee_estimate(amount_sat)
            # find other channel or trampoline that can send delta
            for chan1 in self.channels.values():
                if chan1.is_frozen_for_sending() or not chan1.is_active():
                    continue
                if chan1 == chan2:
                    continue
                if self.uses_trampoline() and chan1.node_id == chan2.node_id:
                    continue
                if direction == SENT:
                    if chan1.can_pay(delta*1000):
                        return (chan1, chan2, delta)
                else:
                    if chan1.can_receive(delta*1000):
                        return (chan2, chan1, delta)
            else:
                continue
        else:
            return False

    def num_sats_can_rebalance(self, chan1, chan2):
        # TODO: we should be able to spend 'max', with variable fee
        n1 = chan1.available_to_spend(LOCAL)
        n1 -= self.fee_estimate(n1)
        n2 = chan2.available_to_spend(REMOTE)
        amount_sat = min(n1, n2) // 1000
        return amount_sat

    def suggest_rebalance_to_send(self, amount_sat):
        return self._suggest_rebalance(SENT, amount_sat)

    def suggest_rebalance_to_receive(self, amount_sat):
        return self._suggest_rebalance(RECEIVED, amount_sat)

    def suggest_swap_to_send(self, amount_sat, coins):
        # fixme: if swap_amount_sat is lower than the minimum swap amount, we need to propose a higher value
        assert amount_sat > self.num_sats_can_send()
        try:
            suggestions = self._suggest_channels_for_rebalance(SENT, amount_sat)
        except NotEnoughFunds:
            return
        for chan, swap_recv_amount in suggestions:
            # check that we can send onchain
            swap_server_mining_fee = 10000 # guessing, because we have not called get_pairs yet
            swap_funding_sat = swap_recv_amount + swap_server_mining_fee
            swap_output = PartialTxOutput.from_address_and_value(DummyAddress.SWAP, int(swap_funding_sat))
            if not self.wallet.can_pay_onchain([swap_output], coins=coins):
                continue
            return (chan, swap_recv_amount)

    def suggest_swap_to_receive(self, amount_sat):
        assert amount_sat > self.num_sats_can_receive()
        try:
            suggestions = self._suggest_channels_for_rebalance(RECEIVED, amount_sat)
        except NotEnoughFunds:
            return
        for chan, swap_recv_amount in suggestions:
            return (chan, swap_recv_amount)

    async def rebalance_channels(self, chan1: Channel, chan2: Channel, *, amount_msat: int):
        if chan1 == chan2:
            raise Exception('Rebalance requires two different channels')
        if self.uses_trampoline() and chan1.node_id == chan2.node_id:
            raise Exception('Rebalance requires channels from different trampolines')
        payment_hash = self.create_payment_info(amount_msat=amount_msat)
        lnaddr, invoice = self.get_bolt11_invoice(
            payment_hash=payment_hash,
            amount_msat=amount_msat,
            message='rebalance',
            expiry=3600,
            fallback_address=None,
            channels=[chan2],
        )
        return await self.pay_invoice(
            invoice, channels=[chan1])

    def can_receive_invoice(self, invoice: BaseInvoice) -> bool:
        assert invoice.is_lightning()
        return (invoice.get_amount_sat() or 0) <= self.num_sats_can_receive()

    async def close_channel(self, chan_id):
        chan = self._channels[chan_id]
        peer = self._peers[chan.node_id]
        return await peer.close_channel(chan_id)

    def _force_close_channel(self, chan_id: bytes) -> Transaction:
        chan = self._channels[chan_id]
        tx = chan.force_close_tx()
        # We set the channel state to make sure we won't sign new commitment txs.
        # We expect the caller to try to broadcast this tx, after which it is
        # not safe to keep using the channel even if the broadcast errors (server could be lying).
        # Until the tx is seen in the mempool, there will be automatic rebroadcasts.
        chan.set_state(ChannelState.FORCE_CLOSING)
        # Add local tx to wallet to also allow manual rebroadcasts.
        try:
            self.wallet.adb.add_transaction(tx)
        except UnrelatedTransactionException:
            pass  # this can happen if (~all the balance goes to REMOTE)
        return tx

    async def force_close_channel(self, chan_id: bytes) -> str:
        """Force-close the channel. Network-related exceptions are propagated to the caller.
        (automatic rebroadcasts will be scheduled)
        """
        # note: as we are async, it can take a few event loop iterations between the caller
        #       "calling us" and us getting to run, and we only set the channel state now:
        tx = self._force_close_channel(chan_id)
        await self.network.broadcast_transaction(tx)
        return tx.txid()

    def schedule_force_closing(self, chan_id: bytes) -> 'asyncio.Task[bool]':
        """Schedules a task to force-close the channel and returns it.
        Network-related exceptions are suppressed.
        (automatic rebroadcasts will be scheduled)
        Note: this method is intentionally not async so that callers have a guarantee
              that the channel state is set immediately.
        """
        tx = self._force_close_channel(chan_id)
        return asyncio.create_task(self.network.try_broadcasting(tx, 'force-close'))

    def remove_channel(self, chan_id):
        chan = self.channels[chan_id]
        assert chan.can_be_deleted()
        with self.lock:
            self._channels.pop(chan_id)
            self.db.get('channels').pop(chan_id.hex())
        for addr in chan.get_wallet_addresses_channel_might_want_reserved():
            self.wallet.set_reserved_state_of_address(addr, reserved=False)

        util.trigger_callback('channels_updated', self.wallet)
        util.trigger_callback('wallet_updated', self.wallet)

    @ignore_exceptions
    @log_exceptions
    async def reestablish_peer_for_given_channel(self, chan: Channel) -> None:
        now = time.time()
        peer_addresses = []
        if self.uses_trampoline():
            addr = trampolines_by_id().get(chan.node_id)
            if addr:
                peer_addresses.append(addr)
        else:
            # will try last good address first, from gossip
            last_good_addr = self.channel_db.get_last_good_address(chan.node_id)
            if last_good_addr:
                peer_addresses.append(last_good_addr)
            # will try addresses for node_id from gossip
            addrs_from_gossip = self.channel_db.get_node_addresses(chan.node_id) or []
            for host, port, ts in addrs_from_gossip:
                peer_addresses.append(LNPeerAddr(host, port, chan.node_id))
        # will try addresses stored in channel storage
        peer_addresses += list(chan.get_peer_addresses())
        # Done gathering addresses.
        # Now select first one that has not failed recently.
        for peer in peer_addresses:
            if self._can_retry_addr(peer, urgent=True, now=now):
                await self._add_peer(peer.host, peer.port, peer.pubkey)
                return

    async def reestablish_peers_and_channels(self):
        while True:
            await asyncio.sleep(1)
            if self.stopping_soon:
                return
            if self.config.ZEROCONF_TRUSTED_NODE:
                peer = LNPeerAddr.from_str(self.config.ZEROCONF_TRUSTED_NODE)
                if self._can_retry_addr(peer, urgent=True):
                    await self._add_peer(peer.host, peer.port, peer.pubkey)
            for chan in self.channels.values():
                # reestablish
                # note: we delegate filtering out uninteresting chans to this:
                if not chan.should_try_to_reestablish_peer():
                    continue
                peer = self._peers.get(chan.node_id, None)
                if peer:
                    await peer.taskgroup.spawn(peer.reestablish_channel(chan))
                else:
                    await self.taskgroup.spawn(self.reestablish_peer_for_given_channel(chan))

    def current_target_feerate_per_kw(self) -> int:
        from .simple_config import FEE_LN_ETA_TARGET, FEERATE_FALLBACK_STATIC_FEE
        from .simple_config import FEERATE_PER_KW_MIN_RELAY_LIGHTNING
        if constants.net is constants.BitcoinRegtest:
            feerate_per_kvbyte = self.network.config.FEE_EST_STATIC_FEERATE
        else:
            feerate_per_kvbyte = self.network.config.eta_target_to_fee(FEE_LN_ETA_TARGET)
            if feerate_per_kvbyte is None:
                feerate_per_kvbyte = FEERATE_FALLBACK_STATIC_FEE
        return max(FEERATE_PER_KW_MIN_RELAY_LIGHTNING, feerate_per_kvbyte // 4)

    def current_low_feerate_per_kw(self) -> int:
        from .simple_config import FEE_LN_LOW_ETA_TARGET
        from .simple_config import FEERATE_PER_KW_MIN_RELAY_LIGHTNING
        if constants.net is constants.BitcoinRegtest:
            feerate_per_kvbyte = 0
        else:
            feerate_per_kvbyte = self.network.config.eta_target_to_fee(FEE_LN_LOW_ETA_TARGET) or 0
        low_feerate_per_kw = max(FEERATE_PER_KW_MIN_RELAY_LIGHTNING, feerate_per_kvbyte // 4)
        # make sure this is never higher than the target feerate:
        low_feerate_per_kw = min(low_feerate_per_kw, self.current_target_feerate_per_kw())
        return low_feerate_per_kw

    def create_channel_backup(self, channel_id: bytes):
        chan = self._channels[channel_id]
        # do not backup old-style channels
        assert chan.is_static_remotekey_enabled()
        peer_addresses = list(chan.get_peer_addresses())
        peer_addr = peer_addresses[0]
        return ImportedChannelBackupStorage(
            node_id = chan.node_id,
            privkey = self.node_keypair.privkey,
            funding_txid = chan.funding_outpoint.txid,
            funding_index = chan.funding_outpoint.output_index,
            funding_address = chan.get_funding_address(),
            host = peer_addr.host,
            port = peer_addr.port,
            is_initiator = chan.constraints.is_initiator,
            channel_seed = chan.config[LOCAL].channel_seed,
            local_delay = chan.config[LOCAL].to_self_delay,
            remote_delay = chan.config[REMOTE].to_self_delay,
            remote_revocation_pubkey = chan.config[REMOTE].revocation_basepoint.pubkey,
            remote_payment_pubkey = chan.config[REMOTE].payment_basepoint.pubkey,
            local_payment_pubkey=chan.config[LOCAL].payment_basepoint.pubkey,
        )

    def export_channel_backup(self, channel_id):
        xpub = self.wallet.get_fingerprint()
        backup_bytes = self.create_channel_backup(channel_id).to_bytes()
        assert backup_bytes == ImportedChannelBackupStorage.from_bytes(backup_bytes).to_bytes(), "roundtrip failed"
        encrypted = pw_encode_with_version_and_mac(backup_bytes, xpub)
        assert backup_bytes == pw_decode_with_version_and_mac(encrypted, xpub), "encrypt failed"
        return 'channel_backup:' + encrypted

    async def request_force_close(self, channel_id: bytes, *, connect_str=None) -> None:
        if channel_id in self.channels:
            chan = self.channels[channel_id]
            peer = self._peers.get(chan.node_id)
            chan.should_request_force_close = True
            if peer:
                peer.close_and_cleanup()  # to force a reconnect
        elif connect_str:
            peer = await self.add_peer(connect_str)
            await peer.request_force_close(channel_id)
        elif channel_id in self.channel_backups:
            await self._request_force_close_from_backup(channel_id)
        else:
            raise Exception(f'Unknown channel {channel_id.hex()}')

    def import_channel_backup(self, data):
        xpub = self.wallet.get_fingerprint()
        cb_storage = ImportedChannelBackupStorage.from_encrypted_str(data, password=xpub)
        channel_id = cb_storage.channel_id()
        if channel_id.hex() in self.db.get_dict("channels"):
            raise Exception('Channel already in wallet')
        self.logger.info(f'importing channel backup: {channel_id.hex()}')
        d = self.db.get_dict("imported_channel_backups")
        d[channel_id.hex()] = cb_storage
        with self.lock:
            cb = ChannelBackup(cb_storage, lnworker=self)
            self._channel_backups[channel_id] = cb
        self.wallet.save_db()
        util.trigger_callback('channels_updated', self.wallet)
        self.lnwatcher.add_channel(cb.funding_outpoint.to_str(), cb.get_funding_address())

    def has_conflicting_backup_with(self, remote_node_id: bytes):
        """ Returns whether we have an active channel with this node on another device, using same local node id. """
        channel_backup_peers = [
            cb.node_id for cb in self.channel_backups.values()
            if (not cb.is_closed() and cb.get_local_pubkey() == self.node_keypair.pubkey)]
        return any(remote_node_id.startswith(cb_peer_nodeid) for cb_peer_nodeid in channel_backup_peers)

    def remove_channel_backup(self, channel_id):
        chan = self.channel_backups[channel_id]
        assert chan.can_be_deleted()
        found = False
        onchain_backups = self.db.get_dict("onchain_channel_backups")
        imported_backups = self.db.get_dict("imported_channel_backups")
        if channel_id.hex() in onchain_backups:
            onchain_backups.pop(channel_id.hex())
            found = True
        if channel_id.hex() in imported_backups:
            imported_backups.pop(channel_id.hex())
            found = True
        if not found:
            raise Exception('Channel not found')
        with self.lock:
            self._channel_backups.pop(channel_id)
        self.wallet.save_db()
        util.trigger_callback('channels_updated', self.wallet)

    @log_exceptions
    async def _request_force_close_from_backup(self, channel_id: bytes):
        cb = self.channel_backups.get(channel_id)
        if not cb:
            raise Exception(f'channel backup not found {self.channel_backups}')
        cb = cb.cb # storage
        self.logger.info(f'requesting channel force close: {channel_id.hex()}')
        if isinstance(cb, ImportedChannelBackupStorage):
            node_id = cb.node_id
            privkey = cb.privkey
            addresses = [(cb.host, cb.port, 0)]
        else:
            assert isinstance(cb, OnchainChannelBackupStorage)
            privkey = self.node_keypair.privkey
            for pubkey, peer_addr in trampolines_by_id().items():
                if pubkey.startswith(cb.node_id_prefix):
                    node_id = pubkey
                    addresses = [(peer_addr.host, peer_addr.port, 0)]
                    break
            else:
                # we will try with gossip (see below)
                addresses = []

        async def _request_fclose(addresses):
            for host, port, timestamp in addresses:
                peer_addr = LNPeerAddr(host, port, node_id)
                transport = LNTransport(privkey, peer_addr, proxy=self.network.proxy)
                peer = Peer(self, node_id, transport, is_channel_backup=True)
                try:
                    async with OldTaskGroup(wait=any) as group:
                        await group.spawn(peer._message_loop())
                        await group.spawn(peer.request_force_close(channel_id))
                    return True
                except Exception as e:
                    self.logger.info(f'failed to connect {host} {e}')
                    continue
            else:
                return False
        # try first without gossip db
        success = await _request_fclose(addresses)
        if success:
            return
        # try with gossip db
        if self.uses_trampoline():
            raise Exception(_('Please enable gossip'))
        node_id = self.network.channel_db.get_node_by_prefix(cb.node_id_prefix)
        addresses_from_gossip = self.network.channel_db.get_node_addresses(node_id)
        if not addresses_from_gossip:
            raise Exception('Peer not found in gossip database')
        success = await _request_fclose(addresses_from_gossip)
        if not success:
            raise Exception('failed to connect')

    def maybe_add_backup_from_tx(self, tx):
        funding_address = None
        node_id_prefix = None
        for i, o in enumerate(tx.outputs()):
            script_type = get_script_type_from_output_script(o.scriptpubkey)
            if script_type == 'p2wsh':
                funding_index = i
                funding_address = o.address
                for o2 in tx.outputs():
                    if o2.scriptpubkey.startswith(bytes([opcodes.OP_RETURN])):
                        encrypted_data = o2.scriptpubkey[2:]
                        data = self.decrypt_cb_data(encrypted_data, funding_address)
                        if data.startswith(CB_MAGIC_BYTES):
                            node_id_prefix = data[4:]
        if node_id_prefix is None:
            return
        funding_txid = tx.txid()
        cb_storage = OnchainChannelBackupStorage(
            node_id_prefix = node_id_prefix,
            funding_txid = funding_txid,
            funding_index = funding_index,
            funding_address = funding_address,
            is_initiator = True)
        channel_id = cb_storage.channel_id().hex()
        if channel_id in self.db.get_dict("channels"):
            return
        self.logger.info(f"adding backup from tx")
        d = self.db.get_dict("onchain_channel_backups")
        d[channel_id] = cb_storage
        cb = ChannelBackup(cb_storage, lnworker=self)
        self.wallet.save_db()
        with self.lock:
            self._channel_backups[bfh(channel_id)] = cb
        util.trigger_callback('channels_updated', self.wallet)
        self.lnwatcher.add_channel(cb.funding_outpoint.to_str(), cb.get_funding_address())

    def save_forwarding_failure(
            self, payment_key:str, *,
            error_bytes: Optional[bytes] = None,
            failure_message: Optional['OnionRoutingFailure'] = None):
        error_hex = error_bytes.hex() if error_bytes else None
        failure_hex = failure_message.to_bytes().hex() if failure_message else None
        self.forwarding_failures[payment_key] = (error_hex, failure_hex)

    def get_forwarding_failure(self, payment_key: str) -> Tuple[Optional[bytes], Optional['OnionRoutingFailure']]:
        error_hex, failure_hex = self.forwarding_failures.get(payment_key, (None, None))
        error_bytes = bytes.fromhex(error_hex) if error_hex else None
        failure_message = OnionRoutingFailure.from_bytes(bytes.fromhex(failure_hex)) if failure_hex else None
        return error_bytes, failure_message

