# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import os
from decimal import Decimal
import random
import time
from typing import Optional, Sequence, Tuple, List, Dict, TYPE_CHECKING, NamedTuple, Union, Mapping, Any
import threading
import socket
import aiohttp
import json
from datetime import datetime, timezone
from functools import partial
from collections import defaultdict
import concurrent
from concurrent import futures
import urllib.parse

import dns.resolver
import dns.exception
from aiorpcx import run_in_thread, TaskGroup

from . import constants, util
from . import keystore
from .util import profiler
from .invoices import PR_TYPE_LN, PR_UNPAID, PR_EXPIRED, PR_PAID, PR_INFLIGHT, PR_FAILED, PR_ROUTING, LNInvoice, LN_EXPIRY_NEVER
from .util import NetworkRetryManager, JsonRPCClient
from .lnutil import LN_MAX_FUNDING_SAT
from .keystore import BIP32_KeyStore
from .bitcoin import COIN
from .transaction import Transaction
from .crypto import sha256
from .bip32 import BIP32Node
from .util import bh2u, bfh, InvoiceError, resolve_dns_srv, is_ip_address, log_exceptions
from .util import ignore_exceptions, make_aiohttp_session, SilentTaskGroup
from .util import timestamp_to_datetime, random_shuffled_copy
from .util import MyEncoder, is_private_netaddress
from .logging import Logger
from .lntransport import LNTransport, LNResponderTransport
from .lnpeer import Peer, LN_P2P_NETWORK_TIMEOUT
from .lnaddr import lnencode, LnAddr, lndecode
from .ecc import der_sig_from_sig_string
from .lnchannel import Channel
from .lnchannel import ChannelState, PeerState
from . import lnutil
from .lnutil import funding_output_script
from .bitcoin import redeem_script_to_address
from .lnutil import (Outpoint, LNPeerAddr,
                     get_compressed_pubkey_from_bech32, extract_nodeid,
                     PaymentFailure, split_host_port, ConnStringFormatError,
                     generate_keypair, LnKeyFamily, LOCAL, REMOTE,
                     MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE,
                     NUM_MAX_EDGES_IN_PAYMENT_PATH, SENT, RECEIVED, HTLCOwner,
                     UpdateAddHtlc, Direction, LnFeatures,
                     ShortChannelID, PaymentAttemptLog, PaymentAttemptFailureDetails,
                     BarePaymentAttemptLog, derive_payment_secret_from_payment_preimage)
from .lnutil import ln_dummy_address, ln_compare_features, IncompatibleLightningFeatures
from .transaction import PartialTxOutput, PartialTransaction, PartialTxInput
from .lnonion import OnionFailureCode, process_onion_packet, OnionPacket
from .lnmsg import decode_msg
from .i18n import _
from .lnrouter import (RouteEdge, LNPaymentRoute, LNPaymentPath, is_route_sane_to_use,
                       NoChannelPolicy, LNPathInconsistent)
from .address_synchronizer import TX_HEIGHT_LOCAL
from . import lnsweep
from .lnwatcher import LNWalletWatcher
from .crypto import pw_encode_with_version_and_mac, pw_decode_with_version_and_mac
from .lnutil import ChannelBackupStorage
from .lnchannel import ChannelBackup
from .channel_db import UpdateStatus
from .submarine_swaps import SwapManager

if TYPE_CHECKING:
    from .network import Network
    from .wallet import Abstract_Wallet


SAVED_PR_STATUS = [PR_PAID, PR_UNPAID, PR_INFLIGHT] # status that are persisted


NUM_PEERS_TARGET = 4


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


class PaymentInfo(NamedTuple):
    payment_hash: bytes
    amount: Optional[int]  # in satoshis  # TODO make it msat and rename to amount_msat
    direction: int
    status: int


class NoPathFound(PaymentFailure):
    def __str__(self):
        return _('No path found')


class LNWorker(Logger, NetworkRetryManager[LNPeerAddr]):

    def __init__(self, xprv):
        Logger.__init__(self)
        NetworkRetryManager.__init__(
            self,
            max_retry_delay_normal=3600,
            init_retry_delay_normal=600,
            max_retry_delay_urgent=300,
            init_retry_delay_urgent=4,
        )
        self.lock = threading.RLock()
        self.node_keypair = generate_keypair(BIP32Node.from_xkey(xprv), LnKeyFamily.NODE_KEY)
        self._peers = {}  # type: Dict[bytes, Peer]  # pubkey -> Peer  # needs self.lock
        self.taskgroup = SilentTaskGroup()
        # set some feature flags as baseline for both LNWallet and LNGossip
        # note that e.g. DATA_LOSS_PROTECT is needed for LNGossip as many peers require it
        self.features = LnFeatures(0)
        self.features |= LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT
        self.features |= LnFeatures.OPTION_STATIC_REMOTEKEY_OPT
        self.features |= LnFeatures.VAR_ONION_OPT
        self.features |= LnFeatures.PAYMENT_SECRET_OPT

        util.register_callback(self.on_proxy_changed, ['proxy_set'])

    @property
    def peers(self) -> Mapping[bytes, Peer]:
        """Returns a read-only copy of peers."""
        with self.lock:
            return self._peers.copy()

    def channels_for_peer(self, node_id):
        return {}

    async def maybe_listen(self):
        # FIXME: only one LNWorker can listen at a time (single port)
        listen_addr = self.config.get('lightning_listen')
        if listen_addr:
            addr, port = listen_addr.rsplit(':', 2)
            if addr[0] == '[':
                # ipv6
                addr = addr[1:-1]
            async def cb(reader, writer):
                transport = LNResponderTransport(self.node_keypair.privkey, reader, writer)
                try:
                    node_id = await transport.handshake()
                except:
                    self.logger.info('handshake failure from incoming connection')
                    return
                peer = Peer(self, node_id, transport)
                with self.lock:
                    self._peers[node_id] = peer
                await self.taskgroup.spawn(peer.main_loop())
            try:
                # FIXME: server.close(), server.wait_closed(), etc... ?
                # TODO: onion hidden service?
                server = await asyncio.start_server(cb, addr, int(port))
            except OSError as e:
                self.logger.error(f"cannot listen for lightning p2p. error: {e!r}")

    @ignore_exceptions  # don't kill outer taskgroup
    async def main_loop(self):
        self.logger.info("starting taskgroup.")
        try:
            async with self.taskgroup as group:
                await group.spawn(self._maintain_connectivity())
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.exception("taskgroup died.")
        finally:
            self.logger.info("taskgroup stopped.")

    async def _maintain_connectivity(self):
        while True:
            await asyncio.sleep(1)
            now = time.time()
            if len(self._peers) >= NUM_PEERS_TARGET:
                continue
            peers = await self._get_next_peers_to_try()
            for peer in peers:
                if self._can_retry_addr(peer, now=now):
                    await self._add_peer(peer.host, peer.port, peer.pubkey)

    async def _add_peer(self, host: str, port: int, node_id: bytes) -> Peer:
        if node_id in self._peers:
            return self._peers[node_id]
        port = int(port)
        peer_addr = LNPeerAddr(host, port, node_id)
        transport = LNTransport(self.node_keypair.privkey, peer_addr,
                                proxy=self.network.proxy)
        self._trying_addr_now(peer_addr)
        self.logger.info(f"adding peer {peer_addr}")
        peer = Peer(self, node_id, transport)
        await self.taskgroup.spawn(peer.main_loop())
        with self.lock:
            self._peers[node_id] = peer
        return peer

    def peer_closed(self, peer: Peer) -> None:
        with self.lock:
            self._peers.pop(peer.pubkey, None)

    def num_peers(self) -> int:
        return sum([p.is_initialized() for p in self.peers.values()])

    def start_network(self, network: 'Network'):
        assert network
        self.network = network
        self.config = network.config
        self.channel_db = self.network.channel_db
        self._add_peers_from_config()
        asyncio.run_coroutine_threadsafe(self.main_loop(), self.network.asyncio_loop)

    def stop(self):
        asyncio.run_coroutine_threadsafe(self.taskgroup.cancel_remaining(), self.network.asyncio_loop)
        util.unregister_callback(self.on_proxy_changed)

    def _add_peers_from_config(self):
        peer_list = self.config.get('lightning_peers', [])
        for host, port, pubkey in peer_list:
            asyncio.run_coroutine_threadsafe(
                self._add_peer(host, int(port), bfh(pubkey)),
                self.network.asyncio_loop)

    def is_good_peer(self, peer):
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
            # add into channel db
            if self.channel_db:
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
        if constants.net in (constants.BitcoinTestnet, ):
            fallback_list = FALLBACK_NODE_LIST_TESTNET
        elif constants.net in (constants.BitcoinMainnet, ):
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
                answers = dns.resolver.query(srv_ans['host'])
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
        # choose first one that is an IP
        for host, port, timestamp in addr_list:
            if is_ip_address(host):
                return host, port, timestamp
        # otherwise choose one at random
        # TODO maybe filter out onion if not on tor?
        choice = random.choice(addr_list)
        return choice

    def on_proxy_changed(self, event, *args):
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
                addrs = self.channel_db.get_node_addresses(node_id)
                if not addrs:
                    raise ConnStringFormatError(_('Don\'t know any addresses for node:') + ' ' + bh2u(node_id))
                host, port, timestamp = self.choose_preferred_address(list(addrs))
            port = int(port)
            # Try DNS-resolving the host (if needed). This is simply so that
            # the caller gets a nice exception if it cannot be resolved.
            try:
                await asyncio.get_event_loop().getaddrinfo(host, port)
            except socket.gaierror:
                raise ConnStringFormatError(_('Hostname does not resolve (getaddrinfo failed)'))
            # add peer
            peer = await self._add_peer(host, port, node_id)
        return peer


class LNGossip(LNWorker):
    max_age = 14*24*3600
    LOGGING_SHORTCUT = 'g'

    def __init__(self):
        seed = os.urandom(32)
        node = BIP32Node.from_rootseed(seed, xtype='standard')
        xprv = node.to_xprv()
        super().__init__(xprv)
        self.features |= LnFeatures.GOSSIP_QUERIES_OPT
        self.features |= LnFeatures.GOSSIP_QUERIES_REQ
        self.unknown_ids = set()

    def start_network(self, network: 'Network'):
        assert network
        super().start_network(network)
        asyncio.run_coroutine_threadsafe(self.taskgroup.spawn(self.maintain_db()), self.network.asyncio_loop)

    async def maintain_db(self):
        await self.channel_db.load_data()
        while True:
            if len(self.unknown_ids) == 0:
                self.channel_db.prune_old_policies(self.max_age)
                self.channel_db.prune_orphaned_channels()
            await asyncio.sleep(120)

    async def add_new_ids(self, ids):
        known = self.channel_db.get_channel_ids()
        new = set(ids) - set(known)
        self.unknown_ids.update(new)
        util.trigger_callback('unknown_channels', len(self.unknown_ids))
        util.trigger_callback('gossip_peers', self.num_peers())
        util.trigger_callback('ln_gossip_sync_progress')

    def get_ids_to_query(self):
        N = 500
        l = list(self.unknown_ids)
        self.unknown_ids = set(l[N:])
        util.trigger_callback('unknown_channels', len(self.unknown_ids))
        util.trigger_callback('ln_gossip_sync_progress')
        return l[0:N]

    def get_sync_progress_estimate(self) -> Tuple[Optional[int], Optional[int]]:
        if self.num_peers() == 0:
            return None, None
        nchans_with_0p, nchans_with_1p, nchans_with_2p = self.channel_db.get_num_channels_partitioned_by_policy_count()
        num_db_channels = nchans_with_0p + nchans_with_1p + nchans_with_2p
        # some channels will never have two policies (only one is in gossip?...)
        # so if we have at least 1 policy for a channel, we consider that channel "complete" here
        current_est = num_db_channels - nchans_with_0p
        total_est = len(self.unknown_ids) + num_db_channels
        return current_est, total_est


class LNWallet(LNWorker):

    lnwatcher: Optional['LNWalletWatcher']

    def __init__(self, wallet: 'Abstract_Wallet', xprv):
        Logger.__init__(self)
        self.wallet = wallet
        self.db = wallet.db
        self.config = wallet.config
        LNWorker.__init__(self, xprv)
        self.lnwatcher = None
        self.features |= LnFeatures.OPTION_DATA_LOSS_PROTECT_REQ
        self.features |= LnFeatures.OPTION_STATIC_REMOTEKEY_REQ
        self.payments = self.db.get_dict('lightning_payments')     # RHASH -> amount, direction, is_paid  # FIXME amt should be msat
        self.preimages = self.db.get_dict('lightning_preimages')   # RHASH -> preimage
        self.sweep_address = wallet.get_new_sweep_address_for_channel()  # TODO possible address-reuse
        self.logs = defaultdict(list)  # type: Dict[str, List[PaymentAttemptLog]]  # key is RHASH  # (not persisted)
        self.is_routing = set()        # (not persisted) keys of invoices that are in PR_ROUTING state
        # used in tests
        self.enable_htlc_settle = asyncio.Event()
        self.enable_htlc_settle.set()

        # note: accessing channels (besides simple lookup) needs self.lock!
        self._channels = {}  # type: Dict[bytes, Channel]
        channels = self.db.get_dict("channels")
        for channel_id, c in random_shuffled_copy(channels.items()):
            self._channels[bfh(channel_id)] = Channel(c, sweep_address=self.sweep_address, lnworker=self)

        self.pending_payments = defaultdict(asyncio.Future)  # type: Dict[bytes, asyncio.Future[BarePaymentAttemptLog]]

    @property
    def channels(self) -> Mapping[bytes, Channel]:
        """Returns a read-only copy of channels."""
        with self.lock:
            return self._channels.copy()

    def get_channel_by_id(self, channel_id: bytes) -> Optional[Channel]:
        return self._channels.get(channel_id, None)

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
            watchtower_url = self.config.get('watchtower_url')
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
        assert network
        self.lnwatcher = LNWalletWatcher(self, network)
        self.lnwatcher.start_network(network)
        self.network = network
        self.swap_manager = SwapManager(self.wallet, network)

        for chan in self.channels.values():
            self.lnwatcher.add_channel(chan.funding_outpoint.to_str(), chan.get_funding_address())

        super().start_network(network)
        for coro in [
                self.maybe_listen(),
                self.lnwatcher.on_network_update('network_updated'), # shortcut (don't block) if funding tx locked and verified
                self.reestablish_peers_and_channels(),
                self.sync_with_local_watchtower(),
                self.sync_with_remote_watchtower(),
        ]:
            tg_coro = self.taskgroup.spawn(coro)
            asyncio.run_coroutine_threadsafe(tg_coro, self.network.asyncio_loop)

    def stop(self):
        super().stop()
        self.lnwatcher.stop()
        self.lnwatcher = None

    def peer_closed(self, peer):
        for chan in self.channels_for_peer(peer.pubkey).values():
            chan.peer_state = PeerState.DISCONNECTED
            util.trigger_callback('channel', self.wallet, chan)
        super().peer_closed(peer)

    def get_settled_payments(self):
        # return one item per payment_hash
        # note: with AMP we will have several channels per payment
        out = defaultdict(list)
        for chan in self.channels.values():
            d = chan.get_settled_payments()
            for k, v in d.items():
                out[k] += v
        return out

    def get_payment_value(self, info: Optional['PaymentInfo'], plist):
        amount_msat = 0
        fee_msat = None
        for chan_id, htlc, _direction in plist:
            amount_msat += int(_direction) * htlc.amount_msat
            if _direction == SENT and info and info.amount:
                fee_msat = (fee_msat or 0) - info.amount*1000 - amount_msat
        timestamp = min([htlc.timestamp for chan_id, htlc, _direction in plist])
        return amount_msat, fee_msat, timestamp

    def get_lightning_history(self):
        out = {}
        for key, plist in self.get_settled_payments().items():
            if len(plist) == 0:
                continue
            payment_hash = bytes.fromhex(key)
            info = self.get_payment_info(payment_hash)
            amount_msat, fee_msat, timestamp = self.get_payment_value(info, plist)
            if info is not None:
                label = self.wallet.get_label(key)
                direction = ('sent' if info.direction == SENT else 'received') if len(plist)==1 else 'self-payment'
            else:
                direction = 'forwarding'
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
                    item['group_label'] = 'Reverse swap' + ' ' + self.config.format_amount_and_units(swap.lightning_amount)
                else:
                    item['group_id'] = swap.funding_txid
                    item['group_label'] = 'Forward swap' + ' ' + self.config.format_amount_and_units(swap.onchain_amount)
            # done
            out[payment_hash] = item
        return out

    def get_onchain_history(self):
        out = {}
        # add funding events
        for chan in self.channels.values():
            item = chan.get_funding_height()
            if item is None:
                continue
            funding_txid, funding_height, funding_timestamp = item
            item = {
                'channel_id': bh2u(chan.channel_id),
                'type': 'channel_opening',
                'label': self.wallet.get_label(funding_txid) or (_('Open channel') + ' ' + chan.get_id_for_log()),
                'txid': funding_txid,
                'amount_msat': chan.balance(LOCAL, ctn=0),
                'direction': 'received',
                'timestamp': funding_timestamp,
                'fee_msat': None,
            }
            out[funding_txid] = item
            item = chan.get_closing_height()
            if item is None:
                continue
            closing_txid, closing_height, closing_timestamp = item
            item = {
                'channel_id': bh2u(chan.channel_id),
                'txid': closing_txid,
                'label': self.wallet.get_label(closing_txid) or (_('Close channel') + ' ' + chan.get_id_for_log()),
                'type': 'channel_closure',
                'amount_msat': -chan.balance_minus_outgoing_htlcs(LOCAL),
                'direction': 'sent',
                'timestamp': closing_timestamp,
                'fee_msat': None,
            }
            out[closing_txid] = item
        # add info about submarine swaps
        settled_payments = self.get_settled_payments()
        current_height = self.network.get_local_height()
        for payment_hash_hex, swap in self.swap_manager.swaps.items():
            txid = swap.spending_txid if swap.is_reverse else swap.funding_txid
            if txid is None:
                continue
            if payment_hash_hex in settled_payments:
                plist = settled_payments[payment_hash_hex]
                info = self.get_payment_info(bytes.fromhex(payment_hash_hex))
                amount_msat, fee_msat, timestamp = self.get_payment_value(info, plist)
            else:
                amount_msat = 0
            label = 'Reverse swap' if swap.is_reverse else 'Forward swap'
            delta = current_height - swap.locktime
            if not swap.is_redeemed and swap.spending_txid is None and delta < 0:
                label += f' (refundable in {-delta} blocks)' # fixme: only if unspent
            out[txid] = {
                'txid': txid,
                'group_id': txid,
                'amount_msat': 0,
                #'amount_msat': amount_msat, # must not be added
                'type': 'swap',
                'label': self.wallet.get_label(txid) or label,
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

    def suggest_peer(self):
        r = []
        for node_id, peer in self.peers.items():
            if not peer.is_initialized():
                continue
            if not all([chan.is_closed() for chan in peer.channels.values()]):
                continue
            r.append(node_id)
        return random.choice(r) if r else None

    def channels_for_peer(self, node_id):
        assert type(node_id) is bytes
        return {chan_id: chan for (chan_id, chan) in self.channels.items()
                if chan.node_id == node_id}

    def channel_state_changed(self, chan):
        self.save_channel(chan)
        util.trigger_callback('channel', self.wallet, chan)

    def save_channel(self, chan):
        assert type(chan) is Channel
        if chan.config[REMOTE].next_per_commitment_point == chan.config[REMOTE].current_per_commitment_point:
            raise Exception("Tried to save channel with next_point == current_point, this should not happen")
        self.wallet.save_db()
        util.trigger_callback('channel', self.wallet, chan)

    def channel_by_txo(self, txo):
        for chan in self.channels.values():
            if chan.funding_outpoint.to_str() == txo:
                return chan

    async def on_channel_update(self, chan):

        if chan.get_state() == ChannelState.OPEN and chan.should_be_closed_due_to_expiring_htlcs(self.network.get_local_height()):
            self.logger.info(f"force-closing due to expiring htlcs")
            await self.try_force_closing(chan.channel_id)

        elif chan.get_state() == ChannelState.FUNDED:
            peer = self._peers.get(chan.node_id)
            if peer and peer.is_initialized():
                peer.send_funding_locked(chan)

        elif chan.get_state() == ChannelState.OPEN:
            peer = self._peers.get(chan.node_id)
            if peer:
                await peer.maybe_update_fee(chan)
                conf = self.lnwatcher.get_tx_height(chan.funding_outpoint.txid).conf
                peer.on_network_update(chan, conf)

        elif chan.get_state() == ChannelState.FORCE_CLOSING:
            force_close_tx = chan.force_close_tx()
            txid = force_close_tx.txid()
            height = self.lnwatcher.get_tx_height(txid).height
            if height == TX_HEIGHT_LOCAL:
                self.logger.info('REBROADCASTING CLOSING TX')
                await self.network.try_broadcasting(force_close_tx, 'force-close')

    @log_exceptions
    async def _open_channel_coroutine(self, *, connect_str: str, funding_tx: PartialTransaction,
                                      funding_sat: int, push_sat: int,
                                      password: Optional[str]) -> Tuple[Channel, PartialTransaction]:
        peer = await self.add_peer(connect_str)
        # will raise if init fails
        await asyncio.wait_for(peer.initialized, LN_P2P_NETWORK_TIMEOUT)
        chan, funding_tx = await peer.channel_establishment_flow(
            password=password,
            funding_tx=funding_tx,
            funding_sat=funding_sat,
            push_msat=push_sat * 1000,
            temp_channel_id=os.urandom(32))
        util.trigger_callback('channels_updated', self.wallet)
        self.wallet.add_transaction(funding_tx)  # save tx as local into the wallet
        self.wallet.set_label(funding_tx.txid(), _('Open channel'))
        if funding_tx.is_complete():
            await self.network.try_broadcasting(funding_tx, 'open_channel')
        return chan, funding_tx

    def add_channel(self, chan):
        with self.lock:
            self._channels[chan.channel_id] = chan
        self.lnwatcher.add_channel(chan.funding_outpoint.to_str(), chan.get_funding_address())

    def add_new_channel(self, chan):
        self.add_channel(chan)
        channels_db = self.db.get_dict('channels')
        channels_db[chan.channel_id.hex()] = chan.storage
        for addr in chan.get_wallet_addresses_channel_might_want_reserved():
            self.wallet.set_reserved_state_of_address(addr, reserved=True)
        self.wallet.save_backup()

    def mktx_for_open_channel(self, *, coins: Sequence[PartialTxInput], funding_sat: int,
                              fee_est=None) -> PartialTransaction:
        dummy_address = ln_dummy_address()
        outputs = [PartialTxOutput.from_address_and_value(dummy_address, funding_sat)]
        tx = self.wallet.make_unsigned_transaction(
            coins=coins,
            outputs=outputs,
            fee=fee_est)
        tx.set_rbf(False)
        return tx

    def open_channel(self, *, connect_str: str, funding_tx: PartialTransaction,
                     funding_sat: int, push_amt_sat: int, password: str = None,
                     timeout: Optional[int] = 20) -> Tuple[Channel, PartialTransaction]:
        if funding_sat > LN_MAX_FUNDING_SAT:
            raise Exception(_("Requested channel capacity is over protocol allowed maximum."))
        coro = self._open_channel_coroutine(connect_str=connect_str, funding_tx=funding_tx, funding_sat=funding_sat,
                                            push_sat=push_amt_sat, password=password)
        fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
        try:
            chan, funding_tx = fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise Exception(_("open_channel timed out"))
        return chan, funding_tx

    def pay(self, invoice: str, *, amount_msat: int = None, attempts: int = 1) -> Tuple[bool, List[PaymentAttemptLog]]:
        """
        Can be called from other threads
        """
        coro = self._pay(invoice, amount_msat=amount_msat, attempts=attempts)
        fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
        return fut.result()

    def get_channel_by_short_id(self, short_channel_id: bytes) -> Optional[Channel]:
        for chan in self.channels.values():
            if chan.short_channel_id == short_channel_id:
                return chan

    @log_exceptions
    async def _pay(
            self,
            invoice: str,
            *,
            amount_msat: int = None,
            attempts: int = 1,
            full_path: LNPaymentPath = None,
    ) -> Tuple[bool, List[PaymentAttemptLog]]:
        lnaddr = self._check_invoice(invoice, amount_msat=amount_msat)
        payment_hash = lnaddr.paymenthash
        key = payment_hash.hex()
        amount = int(lnaddr.amount * COIN)
        status = self.get_payment_status(payment_hash)
        if status == PR_PAID:
            raise PaymentFailure(_("This invoice has been paid already"))
        if status == PR_INFLIGHT:
            raise PaymentFailure(_("A payment was already initiated for this invoice"))
        info = PaymentInfo(lnaddr.paymenthash, amount, SENT, PR_UNPAID)
        self.save_payment_info(info)
        self.wallet.set_label(key, lnaddr.get_description())
        self.logs[key] = log = []
        success = False
        reason = ''
        for i in range(attempts):
            try:
                # note: path-finding runs in a separate thread so that we don't block the asyncio loop
                # graph updates might occur during the computation
                self.set_invoice_status(key, PR_ROUTING)
                util.trigger_callback('invoice_status', key)
                route = await run_in_thread(partial(self._create_route_from_invoice, lnaddr, full_path=full_path))
                self.set_invoice_status(key, PR_INFLIGHT)
                util.trigger_callback('invoice_status', key)
                payment_attempt_log = await self._pay_to_route(route, lnaddr)
            except Exception as e:
                log.append(PaymentAttemptLog(success=False, exception=e))
                self.set_invoice_status(key, PR_UNPAID)
                reason = str(e)
                break
            log.append(payment_attempt_log)
            success = payment_attempt_log.success
            if success:
                break
        else:
            reason = _('Failed after {} attempts').format(attempts)
        util.trigger_callback('invoice_status', key)
        if success:
            util.trigger_callback('payment_succeeded', self.wallet, key)
        else:
            util.trigger_callback('payment_failed', self.wallet, key, reason)
        return success, log

    async def _pay_to_route(self, route: LNPaymentRoute, lnaddr: LnAddr) -> PaymentAttemptLog:
        short_channel_id = route[0].short_channel_id
        chan = self.get_channel_by_short_id(short_channel_id)
        peer = self._peers.get(route[0].node_id)
        if not peer:
            raise Exception('Dropped peer')
        await peer.initialized
        htlc = peer.pay(route=route,
                        chan=chan,
                        amount_msat=lnaddr.get_amount_msat(),
                        payment_hash=lnaddr.paymenthash,
                        min_final_cltv_expiry=lnaddr.get_min_final_cltv_expiry(),
                        payment_secret=lnaddr.payment_secret)
        util.trigger_callback('htlc_added', chan, htlc, SENT)
        payment_attempt = await self.await_payment(lnaddr.paymenthash)
        if payment_attempt.success:
            failure_log = None
        else:
            if payment_attempt.error_bytes:
                # TODO "decode_onion_error" might raise, catch and maybe blacklist/penalise someone?
                failure_msg, sender_idx = chan.decode_onion_error(payment_attempt.error_bytes, route, htlc.htlc_id)
                is_blacklisted = self.handle_error_code_from_failed_htlc(failure_msg, sender_idx, route, peer)
                if is_blacklisted:
                    # blacklist channel after reporter node
                    # TODO this should depend on the error (even more granularity)
                    # also, we need finer blacklisting (directed edges; nodes)
                    try:
                        short_chan_id = route[sender_idx + 1].short_channel_id
                    except IndexError:
                        self.logger.info("payment destination reported error")
                    else:
                        self.network.path_finder.add_to_blacklist(short_chan_id)
            else:
                # probably got "update_fail_malformed_htlc". well... who to penalise now?
                assert payment_attempt.failure_message is not None
                sender_idx = None
                failure_msg = payment_attempt.failure_message
                is_blacklisted = False
            failure_log = PaymentAttemptFailureDetails(sender_idx=sender_idx,
                                                       failure_msg=failure_msg,
                                                       is_blacklisted=is_blacklisted)
        return PaymentAttemptLog(route=route,
                                 success=payment_attempt.success,
                                 preimage=payment_attempt.preimage,
                                 failure_details=failure_log)

    def handle_error_code_from_failed_htlc(self, failure_msg, sender_idx, route, peer):
        code, data = failure_msg.code, failure_msg.data
        self.logger.info(f"UPDATE_FAIL_HTLC {repr(code)} {data}")
        self.logger.info(f"error reported by {bh2u(route[sender_idx].node_id)}")
        # handle some specific error codes
        failure_codes = {
            OnionFailureCode.TEMPORARY_CHANNEL_FAILURE: 0,
            OnionFailureCode.AMOUNT_BELOW_MINIMUM: 8,
            OnionFailureCode.FEE_INSUFFICIENT: 8,
            OnionFailureCode.INCORRECT_CLTV_EXPIRY: 4,
            OnionFailureCode.EXPIRY_TOO_SOON: 0,
            OnionFailureCode.CHANNEL_DISABLED: 2,
        }
        if code in failure_codes:
            offset = failure_codes[code]
            channel_update_len = int.from_bytes(data[offset:offset+2], byteorder="big")
            channel_update_as_received = data[offset+2: offset+2+channel_update_len]
            payload = self._decode_channel_update_msg(channel_update_as_received)
            if payload is None:
                self.logger.info(f'could not decode channel_update for failed htlc: {channel_update_as_received.hex()}')
                return True
            r = self.channel_db.add_channel_update(payload)
            blacklist = False
            short_channel_id = ShortChannelID(payload['short_channel_id'])
            if r == UpdateStatus.GOOD:
                self.logger.info(f"applied channel update to {short_channel_id}")
                peer.maybe_save_remote_update(payload)
            elif r == UpdateStatus.ORPHANED:
                # maybe it is a private channel (and data in invoice was outdated)
                self.logger.info(f"Could not find {short_channel_id}. maybe update is for private channel?")
                start_node_id = route[sender_idx].node_id
                self.channel_db.add_channel_update_for_private_channel(payload, start_node_id)
            elif r == UpdateStatus.EXPIRED:
                blacklist = True
            elif r == UpdateStatus.DEPRECATED:
                self.logger.info(f'channel update is not more recent.')
                blacklist = True
            elif r == UpdateStatus.UNCHANGED:
                blacklist = True
        else:
            blacklist = True
        return blacklist

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
        except:  # FIXME: too broad
            try:
                message_type, payload = decode_msg(channel_update_as_received)
                if payload['chain_hash'] != constants.net.rev_genesis_bytes(): raise Exception()
                payload['raw'] = channel_update_as_received
                return payload
            except:
                return None

    @staticmethod
    def _check_invoice(invoice: str, *, amount_msat: int = None) -> LnAddr:
        addr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        if addr.is_expired():
            raise InvoiceError(_("This invoice has expired"))
        if amount_msat:  # replace amt in invoice. main usecase is paying zero amt invoices
            existing_amt_msat = addr.get_amount_msat()
            if existing_amt_msat and amount_msat < existing_amt_msat:
                raise Exception("cannot pay lower amt than what is originally in LN invoice")
            addr.amount = Decimal(amount_msat) / COIN / 1000
        if addr.amount is None:
            raise InvoiceError(_("Missing amount"))
        if addr.get_min_final_cltv_expiry() > lnutil.NBLOCK_CLTV_EXPIRY_TOO_FAR_INTO_FUTURE:
            raise InvoiceError("{}\n{}".format(
                _("Invoice wants us to risk locking funds for unreasonably long."),
                f"min_final_cltv_expiry: {addr.get_min_final_cltv_expiry()}"))
        return addr

    @profiler
    def _create_route_from_invoice(self, decoded_invoice: 'LnAddr',
                                   *, full_path: LNPaymentPath = None) -> LNPaymentRoute:
        amount_msat = decoded_invoice.get_amount_msat()
        invoice_pubkey = decoded_invoice.pubkey.serialize()
        # use 'r' field from invoice
        route = None  # type: Optional[LNPaymentRoute]
        # only want 'r' tags
        r_tags = list(filter(lambda x: x[0] == 'r', decoded_invoice.tags))
        # strip the tag type, it's implicitly 'r' now
        r_tags = list(map(lambda x: x[1], r_tags))
        # if there are multiple hints, we will use the first one that works,
        # from a random permutation
        random.shuffle(r_tags)
        channels = list(self.channels.values())
        scid_to_my_channels = {chan.short_channel_id: chan for chan in channels
                               if chan.short_channel_id is not None}
        for private_route in r_tags:
            if len(private_route) == 0:
                continue
            if len(private_route) > NUM_MAX_EDGES_IN_PAYMENT_PATH:
                continue
            border_node_pubkey = private_route[0][0]
            if full_path:
                # user pre-selected path. check that end of given path coincides with private_route:
                if [edge.short_channel_id for edge in full_path[-len(private_route):]] != [edge[1] for edge in private_route]:
                    continue
                path = full_path[:-len(private_route)]
            else:
                # find path now on public graph, to border node
                path = self.network.path_finder.find_path_for_payment(self.node_keypair.pubkey, border_node_pubkey, amount_msat,
                                                                      my_channels=scid_to_my_channels)
            if not path:
                continue
            try:
                route = self.network.path_finder.create_route_from_path(path, self.node_keypair.pubkey,
                                                                        my_channels=scid_to_my_channels)
            except NoChannelPolicy:
                continue
            # we need to shift the node pubkey by one towards the destination:
            private_route_nodes = [edge[0] for edge in private_route][1:] + [invoice_pubkey]
            private_route_rest = [edge[1:] for edge in private_route]
            prev_node_id = border_node_pubkey
            for node_pubkey, edge_rest in zip(private_route_nodes, private_route_rest):
                short_channel_id, fee_base_msat, fee_proportional_millionths, cltv_expiry_delta = edge_rest
                short_channel_id = ShortChannelID(short_channel_id)
                # if we have a routing policy for this edge in the db, that takes precedence,
                # as it is likely from a previous failure
                channel_policy = self.channel_db.get_policy_for_node(short_channel_id=short_channel_id,
                                                                     node_id=prev_node_id,
                                                                     my_channels=scid_to_my_channels)
                if channel_policy:
                    fee_base_msat = channel_policy.fee_base_msat
                    fee_proportional_millionths = channel_policy.fee_proportional_millionths
                    cltv_expiry_delta = channel_policy.cltv_expiry_delta
                node_info = self.channel_db.get_node_info_for_node_id(node_id=node_pubkey)
                route.append(RouteEdge(node_id=node_pubkey,
                                       short_channel_id=short_channel_id,
                                       fee_base_msat=fee_base_msat,
                                       fee_proportional_millionths=fee_proportional_millionths,
                                       cltv_expiry_delta=cltv_expiry_delta,
                                       node_features=node_info.features if node_info else 0))
                prev_node_id = node_pubkey
            # test sanity
            if not is_route_sane_to_use(route, amount_msat, decoded_invoice.get_min_final_cltv_expiry()):
                self.logger.info(f"rejecting insane route {route}")
                route = None
                continue
            break
        # if could not find route using any hint; try without hint now
        if route is None:
            if full_path:  # user pre-selected path
                path = full_path
            else:  # find path now
                path = self.network.path_finder.find_path_for_payment(self.node_keypair.pubkey, invoice_pubkey, amount_msat,
                                                                      my_channels=scid_to_my_channels)
            if not path:
                raise NoPathFound()
            route = self.network.path_finder.create_route_from_path(path, self.node_keypair.pubkey,
                                                                    my_channels=scid_to_my_channels)
            if not is_route_sane_to_use(route, amount_msat, decoded_invoice.get_min_final_cltv_expiry()):
                self.logger.info(f"rejecting insane route {route}")
                raise NoPathFound()
        assert len(route) > 0
        if route[-1].node_id != invoice_pubkey:
            raise LNPathInconsistent("last node_id != invoice pubkey")
        # add features from invoice
        invoice_features = decoded_invoice.get_tag('9') or 0
        route[-1].node_features |= invoice_features
        return route

    def add_request(self, amount_sat, message, expiry) -> str:
        coro = self._add_request_coro(amount_sat, message, expiry)
        fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
        try:
            return fut.result(timeout=5)
        except concurrent.futures.TimeoutError:
            raise Exception(_("add invoice timed out"))

    @log_exceptions
    async def create_invoice(self, amount_sat: Optional[int], message, expiry: int):
        timestamp = int(time.time())
        routing_hints = await self._calc_routing_hints_for_invoice(amount_sat)
        if not routing_hints:
            self.logger.info("Warning. No routing hints added to invoice. "
                             "Other clients will likely not be able to send to us.")
        payment_preimage = os.urandom(32)
        payment_hash = sha256(payment_preimage)
        info = PaymentInfo(payment_hash, amount_sat, RECEIVED, PR_UNPAID)
        amount_btc = amount_sat/Decimal(COIN) if amount_sat else None
        if expiry == 0:
            expiry = LN_EXPIRY_NEVER
        lnaddr = LnAddr(paymenthash=payment_hash,
                        amount=amount_btc,
                        tags=[('d', message),
                              ('c', MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE),
                              ('x', expiry),
                              ('9', self.features.for_invoice())]
                        + routing_hints,
                        date=timestamp,
                        payment_secret=derive_payment_secret_from_payment_preimage(payment_preimage))
        invoice = lnencode(lnaddr, self.node_keypair.privkey)
        self.save_preimage(payment_hash, payment_preimage)
        self.save_payment_info(info)
        return lnaddr, invoice

    async def _add_request_coro(self, amount_sat: Optional[int], message, expiry: int) -> str:
        lnaddr, invoice = await self.create_invoice(amount_sat, message, expiry)
        key = bh2u(lnaddr.paymenthash)
        req = LNInvoice.from_bech32(invoice)
        self.wallet.add_payment_request(req)
        self.wallet.set_label(key, message)
        return key

    def save_preimage(self, payment_hash: bytes, preimage: bytes):
        assert sha256(preimage) == payment_hash
        self.preimages[bh2u(payment_hash)] = bh2u(preimage)
        self.wallet.save_db()

    def get_preimage(self, payment_hash: bytes) -> Optional[bytes]:
        r = self.preimages.get(bh2u(payment_hash))
        return bfh(r) if r else None

    def get_payment_info(self, payment_hash: bytes) -> Optional[PaymentInfo]:
        """returns None if payment_hash is a payment we are forwarding"""
        key = payment_hash.hex()
        with self.lock:
            if key in self.payments:
                amount, direction, status = self.payments[key]
                return PaymentInfo(payment_hash, amount, direction, status)

    def save_payment_info(self, info: PaymentInfo) -> None:
        key = info.payment_hash.hex()
        assert info.status in SAVED_PR_STATUS
        with self.lock:
            self.payments[key] = info.amount, info.direction, info.status
        self.wallet.save_db()

    def get_payment_status(self, payment_hash):
        info = self.get_payment_info(payment_hash)
        return info.status if info else PR_UNPAID

    def get_invoice_status(self, invoice):
        key = invoice.rhash
        log = self.logs[key]
        if key in self.is_routing:
            return PR_ROUTING
        # status may be PR_FAILED
        status = self.get_payment_status(bfh(key))
        if status == PR_UNPAID and log:
            status = PR_FAILED
        return status

    def set_invoice_status(self, key, status):
        if status == PR_ROUTING:
            self.is_routing.add(key)
        elif key in self.is_routing:
            self.is_routing.remove(key)
        if status in SAVED_PR_STATUS:
            self.set_payment_status(bfh(key), status)

    async def await_payment(self, payment_hash: bytes) -> BarePaymentAttemptLog:
        payment_attempt = await self.pending_payments[payment_hash]
        self.pending_payments.pop(payment_hash)
        return payment_attempt

    def set_payment_status(self, payment_hash: bytes, status):
        info = self.get_payment_info(payment_hash)
        if info is None:
            # if we are forwarding
            return
        info = info._replace(status=status)
        self.save_payment_info(info)

    def payment_failed(self, chan, payment_hash: bytes, error_bytes: bytes, failure_message):
        self.set_payment_status(payment_hash, PR_UNPAID)
        f = self.pending_payments.get(payment_hash)
        if f and not f.cancelled():
            payment_attempt = BarePaymentAttemptLog(
                success=False,
                error_bytes=error_bytes,
                failure_message=failure_message)
            f.set_result(payment_attempt)
        else:
            chan.logger.info('received unexpected payment_failed, probably from previous session')
            key = payment_hash.hex()
            util.trigger_callback('invoice_status', key)
            util.trigger_callback('payment_failed', self.wallet, key, '')
        util.trigger_callback('ln_payment_failed', payment_hash, chan.channel_id)

    def payment_sent(self, chan, payment_hash: bytes):
        self.set_payment_status(payment_hash, PR_PAID)
        preimage = self.get_preimage(payment_hash)
        f = self.pending_payments.get(payment_hash)
        if f and not f.cancelled():
            payment_attempt = BarePaymentAttemptLog(
                success=True,
                preimage=preimage)
            f.set_result(payment_attempt)
        else:
            chan.logger.info('received unexpected payment_sent, probably from previous session')
            key = payment_hash.hex()
            util.trigger_callback('invoice_status', key)
            util.trigger_callback('payment_succeeded', self.wallet, key)
        util.trigger_callback('ln_payment_completed', payment_hash, chan.channel_id)

    def payment_received(self, chan, payment_hash: bytes):
        self.set_payment_status(payment_hash, PR_PAID)
        util.trigger_callback('request_status', payment_hash.hex(), PR_PAID)
        util.trigger_callback('ln_payment_completed', payment_hash, chan.channel_id)

    async def _calc_routing_hints_for_invoice(self, amount_sat: Optional[int]):
        """calculate routing hints (BOLT-11 'r' field)"""
        routing_hints = []
        channels = list(self.channels.values())
        random.shuffle(channels)  # not sure this has any benefit but let's not leak channel order
        scid_to_my_channels = {chan.short_channel_id: chan for chan in channels
                               if chan.short_channel_id is not None}
        if amount_sat:
            amount_msat = 1000 * amount_sat
        else:
            # for no amt invoices, check if channel can receive at least 1 msat
            amount_msat = 1
        # note: currently we add *all* our channels; but this might be a privacy leak?
        for chan in channels:
            # do minimal filtering of channels.
            # we include channels that cannot *right now* receive (e.g. peer disconnected or balance insufficient)
            if not (chan.is_open() and not chan.is_frozen_for_receiving()):
                continue
            if amount_msat > 1000 * chan.constraints.capacity:
                continue
            chan_id = chan.short_channel_id
            assert isinstance(chan_id, bytes), chan_id
            channel_info = self.channel_db.get_channel_info(chan_id, my_channels=scid_to_my_channels)
            # note: as a fallback, if we don't have a channel update for the
            # incoming direction of our private channel, we fill the invoice with garbage.
            # the sender should still be able to pay us, but will incur an extra round trip
            # (they will get the channel update from the onion error)
            # at least, that's the theory. https://github.com/lightningnetwork/lnd/issues/2066
            fee_base_msat = fee_proportional_millionths = 0
            cltv_expiry_delta = 1  # lnd won't even try with zero
            missing_info = True
            if channel_info:
                policy = self.channel_db.get_policy_for_node(channel_info.short_channel_id, chan.node_id,
                                                             my_channels=scid_to_my_channels)
                if policy:
                    fee_base_msat = policy.fee_base_msat
                    fee_proportional_millionths = policy.fee_proportional_millionths
                    cltv_expiry_delta = policy.cltv_expiry_delta
                    missing_info = False
            if missing_info:
                self.logger.info(f"Warning. Missing channel update for our channel {chan_id}; "
                                 f"filling invoice with incorrect data.")
            routing_hints.append(('r', [(chan.node_id,
                                         chan_id,
                                         fee_base_msat,
                                         fee_proportional_millionths,
                                         cltv_expiry_delta)]))
        return routing_hints

    def delete_payment(self, payment_hash_hex: str):
        try:
            with self.lock:
                del self.payments[payment_hash_hex]
        except KeyError:
            return
        self.wallet.save_db()

    def get_balance(self):
        with self.lock:
            return Decimal(sum(chan.balance(LOCAL) if not chan.is_closed() else 0
                               for chan in self.channels.values())) / 1000

    def num_sats_can_send(self) -> Union[Decimal, int]:
        with self.lock:
            return Decimal(max(chan.available_to_spend(LOCAL) if chan.is_open() else 0
                               for chan in self.channels.values()))/1000 if self.channels else 0

    def num_sats_can_receive(self) -> Union[Decimal, int]:
        with self.lock:
            return Decimal(max(chan.available_to_spend(REMOTE) if chan.is_open() else 0
                               for chan in self.channels.values()))/1000 if self.channels else 0

    def can_pay_invoice(self, invoice: LNInvoice) -> bool:
        return invoice.get_amount_sat() <= self.num_sats_can_send()

    def can_receive_invoice(self, invoice: LNInvoice) -> bool:
        return invoice.get_amount_sat() <= self.num_sats_can_receive()

    async def close_channel(self, chan_id):
        chan = self._channels[chan_id]
        peer = self._peers[chan.node_id]
        return await peer.close_channel(chan_id)

    async def force_close_channel(self, chan_id):
        # returns txid or raises
        chan = self._channels[chan_id]
        tx = chan.force_close_tx()
        await self.network.broadcast_transaction(tx)
        chan.set_state(ChannelState.FORCE_CLOSING)
        return tx.txid()

    async def try_force_closing(self, chan_id):
        # fails silently but sets the state, so that we will retry later
        chan = self._channels[chan_id]
        tx = chan.force_close_tx()
        chan.set_state(ChannelState.FORCE_CLOSING)
        await self.network.try_broadcasting(tx, 'force-close')

    def remove_channel(self, chan_id):
        chan = self._channels[chan_id]
        assert chan.get_state() == ChannelState.REDEEMED
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
            for chan in self.channels.values():
                if chan.is_closed():
                    continue
                # reestablish
                if not chan.should_try_to_reestablish_peer():
                    continue
                peer = self._peers.get(chan.node_id, None)
                if peer:
                    await peer.taskgroup.spawn(peer.reestablish_channel(chan))
                else:
                    await self.taskgroup.spawn(self.reestablish_peer_for_given_channel(chan))

    def current_feerate_per_kw(self):
        from .simple_config import FEE_LN_ETA_TARGET, FEERATE_FALLBACK_STATIC_FEE, FEERATE_REGTEST_HARDCODED
        if constants.net is constants.BitcoinRegtest:
            return FEERATE_REGTEST_HARDCODED // 4
        feerate_per_kvbyte = self.network.config.eta_target_to_fee(FEE_LN_ETA_TARGET)
        if feerate_per_kvbyte is None:
            feerate_per_kvbyte = FEERATE_FALLBACK_STATIC_FEE
        return max(253, feerate_per_kvbyte // 4)

    def create_channel_backup(self, channel_id):
        chan = self._channels[channel_id]
        # do not backup old-style channels
        assert chan.is_static_remotekey_enabled()
        peer_addresses = list(chan.get_peer_addresses())
        peer_addr = peer_addresses[0]
        return ChannelBackupStorage(
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
            remote_payment_pubkey = chan.config[REMOTE].payment_basepoint.pubkey)

    def export_channel_backup(self, channel_id):
        xpub = self.wallet.get_fingerprint()
        backup_bytes = self.create_channel_backup(channel_id).to_bytes()
        assert backup_bytes == ChannelBackupStorage.from_bytes(backup_bytes).to_bytes(), "roundtrip failed"
        encrypted = pw_encode_with_version_and_mac(backup_bytes, xpub)
        assert backup_bytes == pw_decode_with_version_and_mac(encrypted, xpub), "encrypt failed"
        return 'channel_backup:' + encrypted


class LNBackups(Logger):

    lnwatcher: Optional['LNWalletWatcher']

    def __init__(self, wallet: 'Abstract_Wallet'):
        Logger.__init__(self)
        self.features = LnFeatures(0)
        self.features |= LnFeatures.OPTION_DATA_LOSS_PROTECT_OPT
        self.features |= LnFeatures.OPTION_STATIC_REMOTEKEY_OPT
        self.lock = threading.RLock()
        self.wallet = wallet
        self.db = wallet.db
        self.lnwatcher = None
        self.channel_backups = {}
        for channel_id, cb in random_shuffled_copy(self.db.get_dict("channel_backups").items()):
            self.channel_backups[bfh(channel_id)] = ChannelBackup(cb, sweep_address=self.sweep_address, lnworker=self)

    @property
    def sweep_address(self) -> str:
        # TODO possible address-reuse
        return self.wallet.get_new_sweep_address_for_channel()

    def channel_state_changed(self, chan):
        util.trigger_callback('channel', self.wallet, chan)

    def peer_closed(self, chan):
        pass

    async def on_channel_update(self, chan):
        util.trigger_callback('channel', self.wallet, chan)

    def channel_by_txo(self, txo):
        with self.lock:
            channel_backups = list(self.channel_backups.values())
        for chan in channel_backups:
            if chan.funding_outpoint.to_str() == txo:
                return chan

    def on_peer_successfully_established(self, peer: Peer) -> None:
        pass

    def channels_for_peer(self, node_id):
        return {}

    def start_network(self, network: 'Network'):
        assert network
        self.lnwatcher = LNWalletWatcher(self, network)
        self.lnwatcher.start_network(network)
        self.network = network
        for cb in self.channel_backups.values():
            self.lnwatcher.add_channel(cb.funding_outpoint.to_str(), cb.get_funding_address())

    def stop(self):
        self.lnwatcher.stop()
        self.lnwatcher = None

    def import_channel_backup(self, data):
        assert data.startswith('channel_backup:')
        encrypted = data[15:]
        xpub = self.wallet.get_fingerprint()
        decrypted = pw_decode_with_version_and_mac(encrypted, xpub)
        cb_storage = ChannelBackupStorage.from_bytes(decrypted)
        channel_id = cb_storage.channel_id().hex()
        if channel_id in self.db.get_dict("channels"):
            raise Exception('Channel already in wallet')
        d = self.db.get_dict("channel_backups")
        d[channel_id] = cb_storage
        self.channel_backups[bfh(channel_id)] = cb = ChannelBackup(cb_storage, sweep_address=self.sweep_address, lnworker=self)
        self.wallet.save_db()
        util.trigger_callback('channels_updated', self.wallet)
        self.lnwatcher.add_channel(cb.funding_outpoint.to_str(), cb.get_funding_address())

    def remove_channel_backup(self, channel_id):
        d = self.db.get_dict("channel_backups")
        if channel_id.hex() not in d:
            raise Exception('Channel not found')
        d.pop(channel_id.hex())
        self.channel_backups.pop(channel_id)
        self.wallet.save_db()
        util.trigger_callback('channels_updated', self.wallet)

    @log_exceptions
    async def request_force_close(self, channel_id):
        cb = self.channel_backups[channel_id].cb
        # TODO also try network addresses from gossip db (as it might have changed)
        peer_addr = LNPeerAddr(cb.host, cb.port, cb.node_id)
        transport = LNTransport(cb.privkey, peer_addr,
                                proxy=self.network.proxy)
        peer = Peer(self, cb.node_id, transport)
        async with TaskGroup() as group:
            await group.spawn(peer._message_loop())
            await group.spawn(peer.trigger_force_close(channel_id))
            # TODO force-exit taskgroup, to clean-up
