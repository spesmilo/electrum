# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import os
from decimal import Decimal
import random
import time
from typing import Optional, Sequence, Tuple, List, Dict, TYPE_CHECKING
import threading
import socket
import json
from datetime import datetime, timezone
from functools import partial
from collections import defaultdict
import concurrent
from concurrent import futures

import dns.resolver
import dns.exception

from . import constants
from . import keystore
from .util import profiler
from .util import PR_UNPAID, PR_EXPIRED, PR_PAID, PR_INFLIGHT, PR_FAILED
from .util import PR_TYPE_LN
from .lnutil import LN_MAX_FUNDING_SAT
from .keystore import BIP32_KeyStore
from .bitcoin import COIN
from .transaction import Transaction
from .crypto import sha256
from .bip32 import BIP32Node
from .util import bh2u, bfh, InvoiceError, resolve_dns_srv, is_ip_address, log_exceptions
from .util import ignore_exceptions, make_aiohttp_session
from .util import timestamp_to_datetime
from .logging import Logger
from .lntransport import LNTransport, LNResponderTransport
from .lnpeer import Peer, LN_P2P_NETWORK_TIMEOUT
from .lnaddr import lnencode, LnAddr, lndecode
from .ecc import der_sig_from_sig_string
from .ecc_fast import is_using_fast_ecc
from .lnchannel import Channel, ChannelJsonEncoder
from .lnchannel import channel_states, peer_states
from . import lnutil
from .lnutil import funding_output_script
from .bitcoin import redeem_script_to_address
from .lnutil import (Outpoint, LNPeerAddr,
                     get_compressed_pubkey_from_bech32, extract_nodeid,
                     PaymentFailure, split_host_port, ConnStringFormatError,
                     generate_keypair, LnKeyFamily, LOCAL, REMOTE,
                     UnknownPaymentHash, MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE,
                     NUM_MAX_EDGES_IN_PAYMENT_PATH, SENT, RECEIVED, HTLCOwner,
                     UpdateAddHtlc, Direction, LnLocalFeatures, format_short_channel_id,
                     ShortChannelID, PaymentAttemptLog, PaymentAttemptFailureDetails)
from .lnutil import ln_dummy_address
from .transaction import PartialTxOutput, PartialTransaction, PartialTxInput
from .lnonion import OnionFailureCode
from .lnmsg import decode_msg
from .i18n import _
from .lnrouter import RouteEdge, LNPaymentRoute, is_route_sane_to_use
from .address_synchronizer import TX_HEIGHT_LOCAL
from . import lnsweep
from .lnwatcher import LNWatcher

if TYPE_CHECKING:
    from .network import Network
    from .wallet import Abstract_Wallet
    from .lnsweep import SweepInfo


NUM_PEERS_TARGET = 4
PEER_RETRY_INTERVAL = 600  # seconds
PEER_RETRY_INTERVAL_FOR_CHANNELS = 30  # seconds
GRAPH_DOWNLOAD_SECONDS = 600

FALLBACK_NODE_LIST_TESTNET = (
    LNPeerAddr(host='203.132.95.10', port=9735, pubkey=bfh('038863cf8ab91046230f561cd5b386cbff8309fa02e3f0c3ed161a3aeb64a643b9')),
    LNPeerAddr(host='50.116.3.223', port=9734, pubkey=bfh('03236a685d30096b26692dce0cf0fa7c8528bdf61dbf5363a3ef6d5c92733a3016')),
    LNPeerAddr(host='3.16.119.191', port=9735, pubkey=bfh('03d5e17a3c213fe490e1b0c389f8cfcfcea08a29717d50a9f453735e0ab2a7c003')),
    LNPeerAddr(host='34.250.234.192', port=9735, pubkey=bfh('03933884aaf1d6b108397e5efe5c86bcf2d8ca8d2f700eda99db9214fc2712b134')),
    LNPeerAddr(host='88.99.209.230', port=9735, pubkey=bfh('0260d9119979caedc570ada883ff614c6efb93f7f7382e25d73ecbeba0b62df2d7')),
    LNPeerAddr(host='160.16.233.215', port=9735, pubkey=bfh('023ea0a53af875580899da0ab0a21455d9c19160c4ea1b7774c9d4be6810b02d2c')),
    LNPeerAddr(host='197.155.6.173', port=9735, pubkey=bfh('0269a94e8b32c005e4336bfb743c08a6e9beb13d940d57c479d95c8e687ccbdb9f')),
    LNPeerAddr(host='163.172.94.64', port=9735, pubkey=bfh('030f0bf260acdbd3edcad84d7588ec7c5df4711e87e6a23016f989b8d3a4147230')),
    LNPeerAddr(host='23.237.77.12', port=9735, pubkey=bfh('02312627fdf07fbdd7e5ddb136611bdde9b00d26821d14d94891395452f67af248')),
    LNPeerAddr(host='197.155.6.173', port=9735, pubkey=bfh('0269a94e8b32c005e4336bfb743c08a6e9beb13d940d57c479d95c8e687ccbdb9f')),
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
]

encoder = ChannelJsonEncoder()


from typing import NamedTuple

class PaymentInfo(NamedTuple):
    payment_hash: bytes
    amount: int
    direction: int
    status: int


class NoPathFound(PaymentFailure):
    def __str__(self):
        return _('No path found')


class LNWorker(Logger):

    def __init__(self, xprv):
        Logger.__init__(self)
        self.node_keypair = generate_keypair(keystore.from_xprv(xprv), LnKeyFamily.NODE_KEY, 0)
        self.peers = {}  # type: Dict[bytes, Peer]  # pubkey -> Peer
        # set some feature flags as baseline for both LNWallet and LNGossip
        # note that e.g. DATA_LOSS_PROTECT is needed for LNGossip as many peers require it
        self.localfeatures = LnLocalFeatures(0)
        self.localfeatures |= LnLocalFeatures.OPTION_DATA_LOSS_PROTECT_OPT

    def channels_for_peer(self, node_id):
        return {}

    async def maybe_listen(self):
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
                self.peers[node_id] = peer
                await self.network.main_taskgroup.spawn(peer.main_loop())
            await asyncio.start_server(cb, addr, int(port))

    @log_exceptions
    async def main_loop(self):
        while True:
            await asyncio.sleep(1)
            now = time.time()
            if len(self.peers) >= NUM_PEERS_TARGET:
                continue
            peers = await self._get_next_peers_to_try()
            for peer in peers:
                last_tried = self._last_tried_peer.get(peer, 0)
                if last_tried + PEER_RETRY_INTERVAL < now:
                    await self._add_peer(peer.host, peer.port, peer.pubkey)

    async def _add_peer(self, host, port, node_id):
        if node_id in self.peers:
            return self.peers[node_id]
        port = int(port)
        peer_addr = LNPeerAddr(host, port, node_id)
        transport = LNTransport(self.node_keypair.privkey, peer_addr)
        self._last_tried_peer[peer_addr] = time.time()
        self.logger.info(f"adding peer {peer_addr}")
        peer = Peer(self, node_id, transport)
        await self.network.main_taskgroup.spawn(peer.main_loop())
        self.peers[node_id] = peer
        return peer

    def num_peers(self):
        return sum([p.initialized.is_set() for p in self.peers.values()])

    def start_network(self, network: 'Network'):
        assert network
        self.network = network
        self.config = network.config
        daemon = network.daemon
        self.channel_db = self.network.channel_db
        self._last_tried_peer = {}  # type: Dict[LNPeerAddr, float]  # LNPeerAddr -> unix timestamp
        self._add_peers_from_config()
        asyncio.run_coroutine_threadsafe(daemon.taskgroup.spawn(self.main_loop()), self.network.asyncio_loop)

    def _add_peers_from_config(self):
        peer_list = self.config.get('lightning_peers', [])
        for host, port, pubkey in peer_list:
            asyncio.run_coroutine_threadsafe(
                self._add_peer(host, int(port), bfh(pubkey)),
                self.network.asyncio_loop)

    async def _get_next_peers_to_try(self) -> Sequence[LNPeerAddr]:
        now = time.time()
        await self.channel_db.data_loaded.wait()
        recent_peers = self.channel_db.get_recent_peers()
        # maintenance for last tried times
        # due to this, below we can just test membership in _last_tried_peer
        for peer in list(self._last_tried_peer):
            if now >= self._last_tried_peer[peer] + PEER_RETRY_INTERVAL:
                del self._last_tried_peer[peer]
        # first try from recent peers
        for peer in recent_peers:
            if peer.pubkey in self.peers:
                continue
            if peer in self._last_tried_peer:
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
                if peer in self._last_tried_peer:
                    continue
                #self.logger.info('taking random ln peer from our channel db')
                return [peer]

        # TODO remove this. For some reason the dns seeds seem to ignore the realm byte
        # and only return mainnet nodes. so for the time being dns seeding is disabled:
        if constants.net in (constants.BitcoinTestnet, ):
            return [random.choice(FALLBACK_NODE_LIST_TESTNET)]
        elif constants.net in (constants.BitcoinMainnet, ):
            return [random.choice(FALLBACK_NODE_LIST_MAINNET)]
        else:
            return []

        # try peers from dns seed.
        # return several peers to reduce the number of dns queries.
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
            except dns.exception.DNSException:
                continue
            try:
                ln_host = str(answers[0])
                port = int(srv_ans['port'])
                bech32_pubkey = srv_ans['host'].split('.')[0]
                pubkey = get_compressed_pubkey_from_bech32(bech32_pubkey)
                peers.append(LNPeerAddr(ln_host, port, pubkey))
            except Exception as e:
                self.logger.info('error with parsing peer from dns seed: {}'.format(e))
                continue
        self.logger.info('got {} ln peers from dns seed'.format(len(peers)))
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


class LNGossip(LNWorker):
    max_age = 14*24*3600

    def __init__(self, network):
        seed = os.urandom(32)
        node = BIP32Node.from_rootseed(seed, xtype='standard')
        xprv = node.to_xprv()
        super().__init__(xprv)
        self.localfeatures |= LnLocalFeatures.GOSSIP_QUERIES_OPT
        self.localfeatures |= LnLocalFeatures.GOSSIP_QUERIES_REQ
        self.unknown_ids = set()
        assert is_using_fast_ecc(), "verifying LN gossip msgs without libsecp256k1 is hopeless"

    def start_network(self, network: 'Network'):
        assert network
        super().start_network(network)
        asyncio.run_coroutine_threadsafe(network.daemon.taskgroup.spawn(self.maintain_db()), self.network.asyncio_loop)

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
        self.network.trigger_callback('unknown_channels', len(self.unknown_ids))
        self.network.trigger_callback('gossip_peers', self.num_peers())

    def get_ids_to_query(self):
        N = 500
        l = list(self.unknown_ids)
        self.unknown_ids = set(l[N:])
        self.network.trigger_callback('unknown_channels', len(self.unknown_ids))
        return l[0:N]

    def peer_closed(self, peer):
        self.peers.pop(peer.pubkey)


class LNWallet(LNWorker):

    def __init__(self, wallet: 'Abstract_Wallet', xprv):
        Logger.__init__(self)
        self.wallet = wallet
        self.storage = wallet.storage
        self.config = wallet.config
        LNWorker.__init__(self, xprv)
        self.ln_keystore = keystore.from_xprv(xprv)
        self.localfeatures |= LnLocalFeatures.OPTION_DATA_LOSS_PROTECT_REQ
        self.payments = self.storage.get('lightning_payments', {})        # RHASH -> amount, direction, is_paid
        self.preimages = self.storage.get('lightning_preimages', {})      # RHASH -> preimage
        self.sweep_address = wallet.get_receiving_address()
        self.lock = threading.RLock()
        self.logs = defaultdict(list)  # type: Dict[str, List[PaymentAttemptLog]]  # key is RHASH

        # note: accessing channels (besides simple lookup) needs self.lock!
        self.channels = {}  # type: Dict[bytes, Channel]
        for x in wallet.storage.get("channels", []):
            c = Channel(x, sweep_address=self.sweep_address, lnworker=self)
            self.channels[c.channel_id] = c
        # timestamps of opening and closing transactions
        self.channel_timestamps = self.storage.get('lightning_channel_timestamps', {})
        self.pending_payments = defaultdict(asyncio.Future)

    @ignore_exceptions
    @log_exceptions
    async def sync_with_local_watchtower(self):
        watchtower = self.network.local_watchtower
        if watchtower:
            while True:
                with self.lock:
                    channels = list(self.channels.values())
                for chan in channels:
                    await self.sync_channel_with_watchtower(chan, watchtower.sweepstore)
                await asyncio.sleep(5)

    @ignore_exceptions
    @log_exceptions
    async def sync_with_remote_watchtower(self):
        import aiohttp
        from jsonrpcclient.clients.aiohttp_client import AiohttpClient
        class myAiohttpClient(AiohttpClient):
            async def request(self, *args, **kwargs):
                r = await super().request(*args, **kwargs)
                return r.data.result
        while True:
            await asyncio.sleep(5)
            watchtower_url = self.config.get('watchtower_url')
            if not watchtower_url:
                continue
            with self.lock:
                channels = list(self.channels.values())
            try:
                async with make_aiohttp_session(proxy=self.network.proxy) as session:
                    watchtower = myAiohttpClient(session, watchtower_url)
                    for chan in channels:
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
        self.lnwatcher = LNWatcher(network)
        self.lnwatcher.start_network(network)
        self.network = network
        daemon = network.daemon
        self.network.register_callback(self.on_update_open_channel, ['update_open_channel'])
        self.network.register_callback(self.on_update_closed_channel, ['update_closed_channel'])
        for chan_id, chan in self.channels.items():
            self.lnwatcher.add_channel(chan.funding_outpoint.to_str(), chan.get_funding_address())

        super().start_network(network)
        for coro in [
                self.maybe_listen(),
                self.lnwatcher.on_network_update('network_updated'), # shortcut (don't block) if funding tx locked and verified
                self.reestablish_peers_and_channels(),
                self.sync_with_local_watchtower(),
                self.sync_with_remote_watchtower(),
        ]:
            # FIXME: exceptions in those coroutines will cancel daemon.taskgroup
            asyncio.run_coroutine_threadsafe(daemon.taskgroup.spawn(coro), self.network.asyncio_loop)

    def peer_closed(self, peer):
        for chan in self.channels_for_peer(peer.pubkey).values():
            chan.peer_state = peer_states.DISCONNECTED
            self.network.trigger_callback('channel', chan)
        self.peers.pop(peer.pubkey)

    def get_channel_status(self, chan):
        # status displayed in the GUI
        cs = chan.get_state()
        if chan.is_closed():
            return cs.name
        peer = self.peers.get(chan.node_id)
        ps = chan.peer_state
        if ps != peer_states.GOOD:
            return ps.name
        return cs.name

    def payment_completed(self, chan: Channel, direction: Direction,
                          htlc: UpdateAddHtlc):
        chan_id = chan.channel_id
        preimage = self.get_preimage(htlc.payment_hash)
        timestamp = int(time.time())
        self.network.trigger_callback('ln_payment_completed', timestamp, direction, htlc, preimage, chan_id)

    def get_payments(self):
        # return one item per payment_hash
        # note: with AMP we will have several channels per payment
        out = defaultdict(list)
        with self.lock:
            channels = list(self.channels.values())
        for chan in channels:
            d = chan.get_payments()
            for k, v in d.items():
                out[k].append(v)
        return out

    def parse_bech32_invoice(self, invoice):
        lnaddr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        amount = int(lnaddr.amount * COIN) if lnaddr.amount else None
        return {
            'type': PR_TYPE_LN,
            'invoice': invoice,
            'amount': amount,
            'message': lnaddr.get_description(),
            'time': lnaddr.date,
            'exp': lnaddr.get_expiry(),
            'pubkey': bh2u(lnaddr.pubkey.serialize()),
            'rhash': lnaddr.paymenthash.hex(),
        }

    def get_unsettled_payments(self):
        out = []
        for payment_hash, plist in self.get_payments().items():
            if len(plist) != 1:
                continue
            chan_id, htlc, _direction, status = plist[0]
            if _direction != SENT:
                continue
            if status == 'settled':
                continue
            amount = htlc.amount_msat//1000
            item = {
                'is_lightning': True,
                'status': status,
                'key': payment_hash,
                'amount': amount,
                'timestamp': htlc.timestamp,
                'label': self.wallet.get_label(payment_hash)
            }
            out.append(item)
        return out

    def get_history(self):
        out = []
        for key, plist in self.get_payments().items():
            plist = list(filter(lambda x: x[3] == 'settled', plist))
            if len(plist) == 0:
                continue
            elif len(plist) == 1:
                chan_id, htlc, _direction, status = plist[0]
                direction = 'sent' if _direction == SENT else 'received'
                amount_msat = int(_direction) * htlc.amount_msat
                timestamp = htlc.timestamp
                label = self.wallet.get_label(key)
                if _direction == SENT:
                    try:
                        inv = self.get_payment_info(bfh(key))
                        fee_msat = - inv.amount*1000 - amount_msat if inv.amount else None
                    except UnknownPaymentHash:
                        fee_msat = None
                else:
                    fee_msat = None
            else:
                # assume forwarding
                direction = 'forwarding'
                amount_msat = sum([int(_direction) * htlc.amount_msat for chan_id, htlc, _direction, status in plist])
                status = ''
                label = _('Forwarding')
                timestamp = min([htlc.timestamp for chan_id, htlc, _direction, status in plist])
                fee_msat = None # fixme

            item = {
                'type': 'payment',
                'label': label,
                'timestamp': timestamp or 0,
                'date': timestamp_to_datetime(timestamp),
                'direction': direction,
                'status': status,
                'amount_msat': amount_msat,
                'fee_msat': fee_msat,
                'payment_hash': key,
            }
            out.append(item)
        # add funding events
        with self.lock:
            channels = list(self.channels.values())
        for chan in channels:
            item = self.channel_timestamps.get(chan.channel_id.hex())
            if item is None:
                continue
            funding_txid, funding_height, funding_timestamp, closing_txid, closing_height, closing_timestamp = item
            item = {
                'channel_id': bh2u(chan.channel_id),
                'type': 'channel_opening',
                'label': _('Open channel'),
                'txid': funding_txid,
                'amount_msat': chan.balance(LOCAL, ctn=0),
                'direction': 'received',
                'timestamp': funding_timestamp,
                'fee_msat': None,
            }
            out.append(item)
            if not chan.is_closed():
                continue
            item = {
                'channel_id': bh2u(chan.channel_id),
                'txid': closing_txid,
                'label': _('Close channel'),
                'type': 'channel_closure',
                'amount_msat': -chan.balance_minus_outgoing_htlcs(LOCAL),
                'direction': 'sent',
                'timestamp': closing_timestamp,
                'fee_msat': None,
            }
            out.append(item)
        # sort by timestamp
        out.sort(key=lambda x: (x.get('timestamp') or float("inf")))
        balance_msat = 0
        for item in out:
            balance_msat += item['amount_msat']
            item['balance_msat'] = balance_msat
        return out

    def get_and_inc_counter_for_channel_keys(self):
        with self.lock:
            ctr = self.storage.get('lightning_channel_key_der_ctr', -1)
            ctr += 1
            self.storage.put('lightning_channel_key_der_ctr', ctr)
            self.storage.write()
            return ctr

    def suggest_peer(self):
        r = []
        for node_id, peer in self.peers.items():
            if not peer.initialized.is_set():
                continue
            if not all([chan.is_closed() for chan in peer.channels.values()]):
                continue
            r.append(node_id)
        return random.choice(r) if r else None

    def channels_for_peer(self, node_id):
        assert type(node_id) is bytes
        with self.lock:
            return {x: y for (x, y) in self.channels.items() if y.node_id == node_id}

    def save_channel(self, chan):
        assert type(chan) is Channel
        if chan.config[REMOTE].next_per_commitment_point == chan.config[REMOTE].current_per_commitment_point:
            raise Exception("Tried to save channel with next_point == current_point, this should not happen")
        with self.lock:
            self.channels[chan.channel_id] = chan
            self.save_channels()
        self.network.trigger_callback('channel', chan)

    def save_channels(self):
        with self.lock:
            dumped = [x.serialize() for x in self.channels.values()]
        self.storage.put("channels", dumped)
        self.storage.write()

    def save_short_chan_id(self, chan):
        """
        Checks if Funding TX has been mined. If it has, save the short channel ID in chan;
        if it's also deep enough, also save to disk.
        Returns tuple (mined_deep_enough, num_confirmations).
        """
        funding_txid = chan.funding_outpoint.txid
        funding_idx = chan.funding_outpoint.output_index
        conf = self.lnwatcher.get_tx_height(funding_txid).conf
        if conf < chan.constraints.funding_txn_minimum_depth:
            self.logger.info(f"funding tx is still not at sufficient depth. actual depth: {conf}")
            return
        assert conf > 0
        # check funding_tx amount and script
        funding_tx = self.lnwatcher.db.get_transaction(funding_txid)
        if not funding_tx:
            self.logger.info(f"no funding_tx {funding_txid}")
            return
        outp = funding_tx.outputs()[funding_idx]
        redeem_script = funding_output_script(chan.config[REMOTE], chan.config[LOCAL])
        funding_address = redeem_script_to_address('p2wsh', redeem_script)
        funding_sat = chan.constraints.capacity
        if not (outp.address == funding_address and outp.value == funding_sat):
            self.logger.info('funding outpoint mismatch')
            return
        block_height, tx_pos = self.lnwatcher.get_txpos(chan.funding_outpoint.txid)
        assert tx_pos >= 0
        chan.short_channel_id = ShortChannelID.from_components(
            block_height, tx_pos, chan.funding_outpoint.output_index)
        self.logger.info(f"save_short_channel_id: {chan.short_channel_id}")
        self.save_channel(chan)

    def channel_by_txo(self, txo):
        with self.lock:
            channels = list(self.channels.values())
        for chan in channels:
            if chan.funding_outpoint.to_str() == txo:
                return chan

    @ignore_exceptions
    @log_exceptions
    async def on_update_open_channel(self, event, funding_outpoint, funding_txid, funding_height):
        chan = self.channel_by_txo(funding_outpoint)
        if not chan:
            return

        # save timestamp regardless of state, so that funding tx is returned in get_history
        self.channel_timestamps[bh2u(chan.channel_id)] = chan.funding_outpoint.txid, funding_height.height, funding_height.timestamp, None, None, None
        self.storage.put('lightning_channel_timestamps', self.channel_timestamps)

        if chan.get_state() == channel_states.OPEN and self.should_channel_be_closed_due_to_expiring_htlcs(chan):
            self.logger.info(f"force-closing due to expiring htlcs")
            await self.force_close_channel(chan.channel_id)
            return

        if chan.get_state() == channel_states.OPENING:
            if chan.short_channel_id is None:
                self.save_short_chan_id(chan)
            if chan.short_channel_id:
                chan.set_state(channel_states.FUNDED)

        if chan.get_state() == channel_states.FUNDED:
            peer = self.peers.get(chan.node_id)
            if peer and peer.initialized.is_set():
                peer.send_funding_locked(chan)

        elif chan.get_state() == channel_states.OPEN:
            peer = self.peers.get(chan.node_id)
            if peer is None:
                self.logger.info("peer not found for {}".format(bh2u(chan.node_id)))
                return
            if event == 'fee':
                await peer.bitcoin_fee_update(chan)
            conf = self.lnwatcher.get_tx_height(chan.funding_outpoint.txid).conf
            peer.on_network_update(chan, conf)

        elif chan.get_state() == channel_states.FORCE_CLOSING:
            txid = chan.force_close_tx().txid()
            height = self.lnwatcher.get_tx_height(txid).height
            self.logger.info(f"force closing tx {txid}, height {height}")
            if height == TX_HEIGHT_LOCAL:
                self.logger.info('REBROADCASTING CLOSING TX')
                await self.force_close_channel(chan.channel_id)

    @ignore_exceptions
    @log_exceptions
    async def on_update_closed_channel(self, event, funding_outpoint, spenders, funding_txid, funding_height, closing_txid, closing_height, closing_tx, keep_watching):
        chan = self.channel_by_txo(funding_outpoint)
        if not chan:
            return

        # fixme: this is wasteful
        self.channel_timestamps[bh2u(chan.channel_id)] = funding_txid, funding_height.height, funding_height.timestamp, closing_txid, closing_height.height, closing_height.timestamp
        self.storage.put('lightning_channel_timestamps', self.channel_timestamps)

        # remove from channel_db
        if chan.short_channel_id is not None:
            self.channel_db.remove_channel(chan.short_channel_id)

        if chan.get_state() < channel_states.CLOSED:
            chan.set_state(channel_states.CLOSED)

        if chan.get_state() == channel_states.CLOSED and not keep_watching:
            chan.set_state(channel_states.REDEEMED)

        # detect who closed and set sweep_info
        sweep_info_dict = chan.sweep_ctx(closing_tx)
        self.logger.info(f'sweep_info_dict length: {len(sweep_info_dict)}')
        # create and broadcast transaction
        for prevout, sweep_info in sweep_info_dict.items():
            name = sweep_info.name
            spender_txid = spenders.get(prevout)
            if spender_txid is not None:
                # TODO handle exceptions for network.get_transaction
                # TODO don't do network request every time... save tx at least in memory, or maybe wallet file?
                spender_tx = await self.network.get_transaction(spender_txid)
                spender_tx = Transaction(spender_tx)
                e_htlc_tx = chan.sweep_htlc(closing_tx, spender_tx)
                if e_htlc_tx:
                    spender2 = spenders.get(spender_txid+':0')
                    if spender2:
                        self.logger.info(f'htlc is already spent {name}: {prevout}')
                    else:
                        self.logger.info(f'trying to redeem htlc {name}: {prevout}')
                        await self.try_redeem(spender_txid+':0', e_htlc_tx)
                else:
                    self.logger.info(f'outpoint already spent {name}: {prevout}')
            else:
                self.logger.info(f'trying to redeem {name}: {prevout}')
                await self.try_redeem(prevout, sweep_info)

    @log_exceptions
    async def try_redeem(self, prevout: str, sweep_info: 'SweepInfo') -> None:
        name = sweep_info.name
        prev_txid, prev_index = prevout.split(':')
        broadcast = True
        if sweep_info.cltv_expiry:
            local_height = self.network.get_local_height()
            remaining = sweep_info.cltv_expiry - local_height
            if remaining > 0:
                self.logger.info('waiting for {}: CLTV ({} > {}), prevout {}'
                                 .format(name, local_height, sweep_info.cltv_expiry, prevout))
                broadcast = False
        if sweep_info.csv_delay:
            prev_height = self.lnwatcher.get_tx_height(prev_txid)
            remaining = sweep_info.csv_delay - prev_height.conf
            if remaining > 0:
                self.logger.info('waiting for {}: CSV ({} >= {}), prevout: {}'
                                 .format(name, prev_height.conf, sweep_info.csv_delay, prevout))
                broadcast = False
        tx = sweep_info.gen_tx()
        if tx is None:
            self.logger.info(f'{name} could not claim output: {prevout}, dust')
        self.wallet.set_label(tx.txid(), name)
        if broadcast:
            try:
                await self.network.broadcast_transaction(tx)
            except Exception as e:
                self.logger.info(f'could NOT publish {name} for prevout: {prevout}, {str(e)}')
            else:
                self.logger.info(f'success: broadcasting {name} for prevout: {prevout}')
        else:
            # it's OK to add local transaction, the fee will be recomputed
            try:
                self.wallet.add_future_tx(tx, remaining)
                self.logger.info(f'adding future tx: {name}. prevout: {prevout}')
            except Exception as e:
                self.logger.info(f'could not add future tx: {name}. prevout: {prevout} {str(e)}')

    def should_channel_be_closed_due_to_expiring_htlcs(self, chan: Channel) -> bool:
        local_height = self.network.get_local_height()
        htlcs_we_could_reclaim = {}  # type: Dict[Tuple[Direction, int], UpdateAddHtlc]
        # If there is a received HTLC for which we already released the preimage
        # but the remote did not revoke yet, and the CLTV of this HTLC is dangerously close
        # to the present, then unilaterally close channel
        recv_htlc_deadline = lnutil.NBLOCK_DEADLINE_BEFORE_EXPIRY_FOR_RECEIVED_HTLCS
        for sub, dir, ctn in ((LOCAL, RECEIVED, chan.get_latest_ctn(LOCAL)),
                              (REMOTE, SENT, chan.get_oldest_unrevoked_ctn(LOCAL)),
                              (REMOTE, SENT, chan.get_latest_ctn(LOCAL)),):
            for htlc_id, htlc in chan.hm.htlcs_by_direction(subject=sub, direction=dir, ctn=ctn).items():
                if not chan.hm.was_htlc_preimage_released(htlc_id=htlc_id, htlc_sender=REMOTE):
                    continue
                if htlc.cltv_expiry - recv_htlc_deadline > local_height:
                    continue
                htlcs_we_could_reclaim[(RECEIVED, htlc_id)] = htlc
        # If there is an offered HTLC which has already expired (+ some grace period after), we
        # will unilaterally close the channel and time out the HTLC
        offered_htlc_deadline = lnutil.NBLOCK_DEADLINE_AFTER_EXPIRY_FOR_OFFERED_HTLCS
        for sub, dir, ctn in ((LOCAL, SENT, chan.get_latest_ctn(LOCAL)),
                              (REMOTE, RECEIVED, chan.get_oldest_unrevoked_ctn(LOCAL)),
                              (REMOTE, RECEIVED, chan.get_latest_ctn(LOCAL)),):
            for htlc_id, htlc in chan.hm.htlcs_by_direction(subject=sub, direction=dir, ctn=ctn).items():
                if htlc.cltv_expiry + offered_htlc_deadline > local_height:
                    continue
                htlcs_we_could_reclaim[(SENT, htlc_id)] = htlc

        total_value_sat = sum([htlc.amount_msat // 1000 for htlc in htlcs_we_could_reclaim.values()])
        num_htlcs = len(htlcs_we_could_reclaim)
        min_value_worth_closing_channel_over_sat = max(num_htlcs * 10 * chan.config[REMOTE].dust_limit_sat,
                                                       500_000)
        return total_value_sat > min_value_worth_closing_channel_over_sat

    @log_exceptions
    async def _open_channel_coroutine(self, *, connect_str: str, funding_tx: PartialTransaction,
                                      funding_sat: int, push_sat: int,
                                      password: Optional[str]) -> Tuple[Channel, PartialTransaction]:
        peer = await self.add_peer(connect_str)
        # peer might just have been connected to
        await asyncio.wait_for(peer.initialized.wait(), LN_P2P_NETWORK_TIMEOUT)
        chan, funding_tx = await peer.channel_establishment_flow(
            password,
            funding_tx=funding_tx,
            funding_sat=funding_sat,
            push_msat=push_sat * 1000,
            temp_channel_id=os.urandom(32))
        self.save_channel(chan)
        self.lnwatcher.add_channel(chan.funding_outpoint.to_str(), chan.get_funding_address())
        self.network.trigger_callback('channels_updated', self.wallet)
        self.wallet.add_transaction(funding_tx)  # save tx as local into the wallet
        self.wallet.set_label(funding_tx.txid(), _('Open channel'))
        if funding_tx.is_complete():
            # TODO make more robust (timeout low? server returns error?)
            await asyncio.wait_for(self.network.broadcast_transaction(funding_tx), LN_P2P_NETWORK_TIMEOUT)
        return chan, funding_tx

    @log_exceptions
    async def add_peer(self, connect_str: str) -> Peer:
        node_id, rest = extract_nodeid(connect_str)
        peer = self.peers.get(node_id)
        if not peer:
            if rest is not None:
                host, port = split_host_port(rest)
            else:
                addrs = self.channel_db.get_node_addresses(node_id)
                if not addrs:
                    raise ConnStringFormatError(_('Don\'t know any addresses for node:') + ' ' + bh2u(node_id))
                host, port, timestamp = self.choose_preferred_address(addrs)
            try:
                socket.getaddrinfo(host, int(port))
            except socket.gaierror:
                raise ConnStringFormatError(_('Hostname does not resolve (getaddrinfo failed)'))
            # add peer
            peer = await self._add_peer(host, port, node_id)
        return peer

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

    def pay(self, invoice, amount_sat=None, attempts=1):
        """
        Can be called from other threads
        """
        coro = self._pay(invoice, amount_sat, attempts)
        fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
        success = fut.result()

    def get_channel_by_short_id(self, short_channel_id: ShortChannelID) -> Channel:
        with self.lock:
            for chan in self.channels.values():
                if chan.short_channel_id == short_channel_id:
                    return chan

    async def _pay(self, invoice, amount_sat=None, attempts=1) -> bool:
        lnaddr = self._check_invoice(invoice, amount_sat)
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
        log = self.logs[key]
        success = False
        for i in range(attempts):
            try:
                route = await self._create_route_from_invoice(decoded_invoice=lnaddr)
            except NoPathFound as e:
                log.append(PaymentAttemptLog(success=False, exception=e))
                break
            self.network.trigger_callback('invoice_status', key, PR_INFLIGHT)
            payment_attempt_log = await self._pay_to_route(route, lnaddr)
            log.append(payment_attempt_log)
            success = payment_attempt_log.success
            if success:
                break
        self.network.trigger_callback('invoice_status', key, PR_PAID if success else PR_FAILED)
        return success

    async def _pay_to_route(self, route: LNPaymentRoute, lnaddr: LnAddr) -> PaymentAttemptLog:
        short_channel_id = route[0].short_channel_id
        chan = self.get_channel_by_short_id(short_channel_id)
        if not chan:
            self.channel_db.remove_channel(short_channel_id)
            raise Exception(f"PathFinder returned path with short_channel_id "
                            f"{short_channel_id} that is not in channel list")
        self.set_payment_status(lnaddr.paymenthash, PR_INFLIGHT)
        peer = self.peers[route[0].node_id]
        htlc = await peer.pay(route, chan, int(lnaddr.amount * COIN * 1000), lnaddr.paymenthash, lnaddr.get_min_final_cltv_expiry())
        self.network.trigger_callback('htlc_added', htlc, lnaddr, SENT)
        success, preimage, reason = await self.await_payment(lnaddr.paymenthash)
        if success:
            failure_log = None
        else:
            failure_msg, sender_idx = chan.decode_onion_error(reason, route, htlc.htlc_id)
            blacklist = self.handle_error_code_from_failed_htlc(failure_msg, sender_idx, route, peer)
            if blacklist:
                # blacklist channel after reporter node
                # TODO this should depend on the error (even more granularity)
                # also, we need finer blacklisting (directed edges; nodes)
                try:
                    short_chan_id = route[sender_idx + 1].short_channel_id
                except IndexError:
                    self.logger.info("payment destination reported error")
                else:
                    self.network.path_finder.add_to_blacklist(short_chan_id)
            failure_log = PaymentAttemptFailureDetails(sender_idx=sender_idx,
                                                       failure_msg=failure_msg,
                                                       is_blacklisted=blacklist)
        return PaymentAttemptLog(route=route,
                                 success=success,
                                 preimage=preimage,
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
            channel_update_typed = (258).to_bytes(length=2, byteorder="big") + channel_update_as_received
            # note: some nodes put channel updates in error msgs with the leading msg_type already there.
            #       we try decoding both ways here.
            try:
                message_type, payload = decode_msg(channel_update_typed)
                payload['raw'] = channel_update_typed
            except:  # FIXME: too broad
                message_type, payload = decode_msg(channel_update_as_received)
                payload['raw'] = channel_update_as_received
            categorized_chan_upds = self.channel_db.add_channel_updates([payload])
            blacklist = False
            if categorized_chan_upds.good:
                self.logger.info("applied channel update on our db")
                peer.maybe_save_remote_update(payload)
            elif categorized_chan_upds.orphaned:
                # maybe it is a private channel (and data in invoice was outdated)
                self.logger.info("maybe channel update is for private channel?")
                start_node_id = route[sender_idx].node_id
                self.channel_db.add_channel_update_for_private_channel(payload, start_node_id)
            elif categorized_chan_upds.expired:
                blacklist = True
            elif categorized_chan_upds.deprecated:
                self.logger.info(f'channel update is not more recent.')
                blacklist = True
        else:
            blacklist = True
        return blacklist

    @staticmethod
    def _check_invoice(invoice, amount_sat=None):
        addr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        if addr.is_expired():
            raise InvoiceError(_("This invoice has expired"))
        if amount_sat:
            addr.amount = Decimal(amount_sat) / COIN
        if addr.amount is None:
            raise InvoiceError(_("Missing amount"))
        if addr.get_min_final_cltv_expiry() > 60 * 144:
            raise InvoiceError("{}\n{}".format(
                _("Invoice wants us to risk locking funds for unreasonably long."),
                f"min_final_cltv_expiry: {addr.get_min_final_cltv_expiry()}"))
        return addr

    async def _create_route_from_invoice(self, decoded_invoice) -> LNPaymentRoute:
        amount_msat = int(decoded_invoice.amount * COIN * 1000)
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
        with self.lock:
            channels = list(self.channels.values())
        for private_route in r_tags:
            if len(private_route) == 0:
                continue
            if len(private_route) > NUM_MAX_EDGES_IN_PAYMENT_PATH:
                continue
            border_node_pubkey = private_route[0][0]
            path = self.network.path_finder.find_path_for_payment(self.node_keypair.pubkey, border_node_pubkey, amount_msat, channels)
            if not path:
                continue
            route = self.network.path_finder.create_route_from_path(path, self.node_keypair.pubkey)
            # we need to shift the node pubkey by one towards the destination:
            private_route_nodes = [edge[0] for edge in private_route][1:] + [invoice_pubkey]
            private_route_rest = [edge[1:] for edge in private_route]
            prev_node_id = border_node_pubkey
            for node_pubkey, edge_rest in zip(private_route_nodes, private_route_rest):
                short_channel_id, fee_base_msat, fee_proportional_millionths, cltv_expiry_delta = edge_rest
                short_channel_id = ShortChannelID(short_channel_id)
                # if we have a routing policy for this edge in the db, that takes precedence,
                # as it is likely from a previous failure
                channel_policy = self.channel_db.get_routing_policy_for_channel(prev_node_id, short_channel_id)
                if channel_policy:
                    fee_base_msat = channel_policy.fee_base_msat
                    fee_proportional_millionths = channel_policy.fee_proportional_millionths
                    cltv_expiry_delta = channel_policy.cltv_expiry_delta
                route.append(RouteEdge(node_pubkey, short_channel_id, fee_base_msat, fee_proportional_millionths,
                                       cltv_expiry_delta))
                prev_node_id = node_pubkey
            # test sanity
            if not is_route_sane_to_use(route, amount_msat, decoded_invoice.get_min_final_cltv_expiry()):
                self.logger.info(f"rejecting insane route {route}")
                route = None
                continue
            break
        # if could not find route using any hint; try without hint now
        if route is None:
            path = self.network.path_finder.find_path_for_payment(self.node_keypair.pubkey, invoice_pubkey, amount_msat, channels)
            if not path:
                raise NoPathFound()
            route = self.network.path_finder.create_route_from_path(path, self.node_keypair.pubkey)
            if not is_route_sane_to_use(route, amount_msat, decoded_invoice.get_min_final_cltv_expiry()):
                self.logger.info(f"rejecting insane route {route}")
                raise NoPathFound()
        return route

    def add_request(self, amount_sat, message, expiry):
        coro = self._add_request_coro(amount_sat, message, expiry)
        fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
        try:
            return fut.result(timeout=5)
        except concurrent.futures.TimeoutError:
            raise Exception(_("add invoice timed out"))

    @log_exceptions
    async def _add_request_coro(self, amount_sat, message, expiry):
        timestamp = int(time.time())
        routing_hints = await self._calc_routing_hints_for_invoice(amount_sat)
        if not routing_hints:
            self.logger.info("Warning. No routing hints added to invoice. "
                             "Other clients will likely not be able to send to us.")
        payment_preimage = os.urandom(32)
        payment_hash = sha256(payment_preimage)
        info = PaymentInfo(payment_hash, amount_sat, RECEIVED, PR_UNPAID)
        amount_btc = amount_sat/Decimal(COIN) if amount_sat else None
        lnaddr = LnAddr(payment_hash, amount_btc,
                        tags=[('d', message),
                              ('c', MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE),
                              ('x', expiry)]
                        + routing_hints,
                        date = timestamp)
        invoice = lnencode(lnaddr, self.node_keypair.privkey)
        key = bh2u(lnaddr.paymenthash)
        req = {
            'type': PR_TYPE_LN,
            'amount': amount_sat,
            'time': lnaddr.date,
            'exp': expiry,
            'message': message,
            'rhash': key,
            'invoice': invoice
        }
        self.save_preimage(payment_hash, payment_preimage)
        self.save_payment_info(info)
        self.wallet.add_payment_request(req)
        self.wallet.set_label(key, message)
        return key

    def save_preimage(self, payment_hash: bytes, preimage: bytes):
        assert sha256(preimage) == payment_hash
        self.preimages[bh2u(payment_hash)] = bh2u(preimage)
        self.storage.put('lightning_preimages', self.preimages)
        self.storage.write()

    def get_preimage(self, payment_hash: bytes) -> bytes:
        return bfh(self.preimages.get(bh2u(payment_hash)))

    def get_payment_info(self, payment_hash: bytes) -> PaymentInfo:
        key = payment_hash.hex()
        with self.lock:
            if key not in self.payments:
                raise UnknownPaymentHash(payment_hash)
            amount, direction, status = self.payments[key]
            return PaymentInfo(payment_hash, amount, direction, status)

    def save_payment_info(self, info: PaymentInfo) -> None:
        key = info.payment_hash.hex()
        assert info.status in [PR_PAID, PR_UNPAID, PR_INFLIGHT]
        with self.lock:
            self.payments[key] = info.amount, info.direction, info.status
        self.storage.put('lightning_payments', self.payments)
        self.storage.write()

    def get_payment_status(self, payment_hash):
        try:
            info = self.get_payment_info(payment_hash)
            status = info.status
        except UnknownPaymentHash:
            status = PR_UNPAID
        return status

    async def await_payment(self, payment_hash):
        success, preimage, reason = await self.pending_payments[payment_hash]
        self.pending_payments.pop(payment_hash)
        return success, preimage, reason

    def set_payment_status(self, payment_hash: bytes, status):
        try:
            info = self.get_payment_info(payment_hash)
        except UnknownPaymentHash:
            # if we are forwarding
            return
        info = info._replace(status=status)
        self.save_payment_info(info)

    def payment_failed(self, payment_hash: bytes, reason):
        self.set_payment_status(payment_hash, PR_UNPAID)
        self.pending_payments[payment_hash].set_result((False, None, reason))

    def payment_sent(self, payment_hash: bytes):
        self.set_payment_status(payment_hash, PR_PAID)
        preimage = self.get_preimage(payment_hash)
        self.pending_payments[payment_hash].set_result((True, preimage, None))

    def payment_received(self, payment_hash: bytes):
        self.set_payment_status(payment_hash, PR_PAID)
        self.network.trigger_callback('request_status', payment_hash.hex(), PR_PAID)

    async def _calc_routing_hints_for_invoice(self, amount_sat):
        """calculate routing hints (BOLT-11 'r' field)"""
        routing_hints = []
        with self.lock:
            channels = list(self.channels.values())
        # note: currently we add *all* our channels; but this might be a privacy leak?
        for chan in channels:
            # check channel is open
            if chan.get_state() != channel_states.OPEN:
                continue
            # check channel has sufficient balance
            # FIXME because of on-chain fees of ctx, this check is insufficient
            if amount_sat and chan.balance(REMOTE) // 1000 < amount_sat:
                continue
            chan_id = chan.short_channel_id
            assert isinstance(chan_id, bytes), chan_id
            channel_info = self.channel_db.get_channel_info(chan_id)
            # note: as a fallback, if we don't have a channel update for the
            # incoming direction of our private channel, we fill the invoice with garbage.
            # the sender should still be able to pay us, but will incur an extra round trip
            # (they will get the channel update from the onion error)
            # at least, that's the theory. https://github.com/lightningnetwork/lnd/issues/2066
            fee_base_msat = fee_proportional_millionths = 0
            cltv_expiry_delta = 1  # lnd won't even try with zero
            missing_info = True
            if channel_info:
                policy = self.channel_db.get_policy_for_node(channel_info.short_channel_id, chan.node_id)
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
        self.storage.put('lightning_payments', self.payments)
        self.storage.write()

    def get_balance(self):
        with self.lock:
            return Decimal(sum(chan.balance(LOCAL) if not chan.is_closed() else 0 for chan in self.channels.values()))/1000

    def list_channels(self):
        with self.lock:
            # we output the funding_outpoint instead of the channel_id because lnd uses channel_point (funding outpoint) to identify channels
            for channel_id, chan in self.channels.items():
                yield {
                    'local_htlcs': json.loads(encoder.encode(chan.hm.log[LOCAL])),
                    'remote_htlcs': json.loads(encoder.encode(chan.hm.log[REMOTE])),
                    'channel_id': format_short_channel_id(chan.short_channel_id) if chan.short_channel_id else None,
                    'full_channel_id': bh2u(chan.channel_id),
                    'channel_point': chan.funding_outpoint.to_str(),
                    'state': chan.get_state().name,
                    'remote_pubkey': bh2u(chan.node_id),
                    'local_balance': chan.balance(LOCAL)//1000,
                    'remote_balance': chan.balance(REMOTE)//1000,
                }

    async def close_channel(self, chan_id):
        chan = self.channels[chan_id]
        peer = self.peers[chan.node_id]
        return await peer.close_channel(chan_id)

    async def force_close_channel(self, chan_id):
        chan = self.channels[chan_id]
        tx = chan.force_close_tx()
        chan.set_state(channel_states.FORCE_CLOSING)
        try:
            await self.network.broadcast_transaction(tx)
        except Exception as e:
            self.logger.info(f'could NOT publish {tx.txid()}, {str(e)}')
            return
        return tx.txid()

    def remove_channel(self, chan_id):
        # TODO: assert that closing tx is deep-mined and htlcs are swept
        chan = self.channels[chan_id]
        assert chan.is_closed()
        with self.lock:
            self.channels.pop(chan_id)
        self.save_channels()
        self.network.trigger_callback('channels_updated', self.wallet)
        self.network.trigger_callback('wallet_updated', self.wallet)

    @ignore_exceptions
    @log_exceptions
    async def reestablish_peer_for_given_channel(self, chan):
        now = time.time()
        # try last good address first
        peer = self.channel_db.get_last_good_address(chan.node_id)
        if peer:
            last_tried = self._last_tried_peer.get(peer, 0)
            if last_tried + PEER_RETRY_INTERVAL_FOR_CHANNELS < now:
                await self._add_peer(peer.host, peer.port, peer.pubkey)
                return
        # try random address for node_id
        addresses = self.channel_db.get_node_addresses(chan.node_id)
        if not addresses:
            return
        host, port, t = random.choice(list(addresses))
        peer = LNPeerAddr(host, port, chan.node_id)
        last_tried = self._last_tried_peer.get(peer, 0)
        if last_tried + PEER_RETRY_INTERVAL_FOR_CHANNELS < now:
            await self._add_peer(host, port, chan.node_id)

    async def reestablish_peers_and_channels(self):
        while True:
            await asyncio.sleep(1)
            # wait until on-chain state is synchronized
            if not (self.wallet.is_up_to_date() and self.lnwatcher.is_up_to_date()):
                continue
            with self.lock:
                channels = list(self.channels.values())
            for chan in channels:
                if chan.is_closed():
                    continue
                if constants.net is not constants.BitcoinRegtest:
                    chan_feerate = chan.get_latest_feerate(LOCAL)
                    ratio = chan_feerate / self.current_feerate_per_kw()
                    if ratio < 0.5:
                        self.logger.warning(f"fee level for channel {bh2u(chan.channel_id)} is {chan_feerate} sat/kiloweight, "
                                            f"current recommended feerate is {self.current_feerate_per_kw()} sat/kiloweight, consider force closing!")
                # reestablish
                if not chan.should_try_to_reestablish_peer():
                    continue
                peer = self.peers.get(chan.node_id, None)
                if peer:
                    await peer.group.spawn(peer.reestablish_channel(chan))
                else:
                    await self.network.main_taskgroup.spawn(
                        self.reestablish_peer_for_given_channel(chan))

    def current_feerate_per_kw(self):
        from .simple_config import FEE_LN_ETA_TARGET, FEERATE_FALLBACK_STATIC_FEE, FEERATE_REGTEST_HARDCODED
        if constants.net is constants.BitcoinRegtest:
            return FEERATE_REGTEST_HARDCODED // 4
        feerate_per_kvbyte = self.network.config.eta_target_to_fee(FEE_LN_ETA_TARGET)
        if feerate_per_kvbyte is None:
            feerate_per_kvbyte = FEERATE_FALLBACK_STATIC_FEE
        return max(253, feerate_per_kvbyte // 4)
