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

import dns.resolver
import dns.exception

from . import constants
from . import keystore
from .keystore import BIP32_KeyStore
from .bitcoin import COIN
from .crypto import sha256
from .bip32 import bip32_root
from .util import bh2u, bfh, PrintError, InvoiceError, resolve_dns_srv, is_ip_address, log_exceptions
from .lntransport import LNResponderTransport
from .lnbase import Peer
from .lnaddr import lnencode, LnAddr, lndecode
from .ecc import der_sig_from_sig_string
from .lnchan import Channel, ChannelJsonEncoder, UpdateAddHtlc
from .lnutil import (Outpoint, calc_short_channel_id, LNPeerAddr,
                     get_compressed_pubkey_from_bech32, extract_nodeid,
                     PaymentFailure, split_host_port, ConnStringFormatError,
                     generate_keypair, LnKeyFamily, LOCAL, REMOTE,
                     UnknownPaymentHash, MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE,
                     NUM_MAX_EDGES_IN_PAYMENT_PATH, SENT, RECEIVED, HTLCOwner)
from .i18n import _
from .lnrouter import RouteEdge, is_route_sane_to_use
from .address_synchronizer import TX_HEIGHT_LOCAL

if TYPE_CHECKING:
    from .network import Network
    from .wallet import Abstract_Wallet


NUM_PEERS_TARGET = 4
PEER_RETRY_INTERVAL = 600  # seconds
PEER_RETRY_INTERVAL_FOR_CHANNELS = 30  # seconds
GRAPH_DOWNLOAD_SECONDS = 600

FALLBACK_NODE_LIST_TESTNET = (
    LNPeerAddr('ecdsa.net', 9735, bfh('038370f0e7a03eded3e1d41dc081084a87f0afa1c5b22090b4f3abb391eb15d8ff')),
    LNPeerAddr('165.227.30.200', 9735, bfh('023ea0a53af875580899da0ab0a21455d9c19160c4ea1b7774c9d4be6810b02d2c')),
)
FALLBACK_NODE_LIST_MAINNET = (
    LNPeerAddr('104.198.32.198', 9735, bfh('02f6725f9c1c40333b67faea92fd211c183050f28df32cac3f9d69685fe9665432')), # Blockstream
    LNPeerAddr('13.80.67.162', 9735, bfh('02c0ac82c33971de096d87ce5ed9b022c2de678f08002dc37fdb1b6886d12234b5')),   # Stampery
)

encoder = ChannelJsonEncoder()

class LNWorker(PrintError):

    def __init__(self, wallet: 'Abstract_Wallet', network: 'Network'):
        self.wallet = wallet
        # invoices we are currently trying to pay (might be pending HTLCs on a commitment transaction)
        self.paying = self.wallet.storage.get('lightning_payments_inflight', {}) # type: Dict[bytes, Tuple[str, Optional[int], bytes]]
        self.sweep_address = wallet.get_receiving_address()
        self.network = network
        self.channel_db = self.network.channel_db
        self.lock = threading.RLock()
        self.ln_keystore = self._read_ln_keystore()
        self.node_keypair = generate_keypair(self.ln_keystore, LnKeyFamily.NODE_KEY, 0)
        self.config = network.config
        self.peers = {}  # type: Dict[bytes, Peer]  # pubkey -> Peer
        self.channels = {}  # type: Dict[bytes, Channel]
        for x in wallet.storage.get("channels", []):
            c = Channel(x, payment_completed=self.payment_completed)
            self.channels[c.channel_id] = c

            c.lnwatcher = network.lnwatcher
            c.sweep_address = self.sweep_address
        self.invoices = wallet.storage.get('lightning_invoices', {})  # type: Dict[str, Tuple[str,str]]  # RHASH -> (preimage, invoice)
        for chan_id, chan in self.channels.items():
            self.network.lnwatcher.watch_channel(chan.get_funding_address(), chan.funding_outpoint.to_str())
        self._last_tried_peer = {}  # LNPeerAddr -> unix timestamp
        self._add_peers_from_config()
        # wait until we see confirmations
        self.network.register_callback(self.on_network_update, ['wallet_updated', 'network_updated', 'verified', 'fee'])  # thread safe
        self.network.register_callback(self.on_channel_txo, ['channel_txo'])
        asyncio.run_coroutine_threadsafe(self.network.main_taskgroup.spawn(self.main_loop()), self.network.asyncio_loop)
        self.first_timestamp_requested = None

    def get_first_timestamp(self):
        first_request = False
        if self.first_timestamp_requested is None:
            self.first_timestamp_requested = time.time()
            first_request = True
        first_timestamp = self.wallet.storage.get('lightning_gossip_until', 0)
        if first_timestamp == 0:
            self.print_error('requesting whole channel graph')
        else:
            self.print_error('requesting channel graph since', datetime.fromtimestamp(first_timestamp).ctime())
        if first_request:
            asyncio.run_coroutine_threadsafe(self.save_gossip_timestamp(), self.network.asyncio_loop)
        return first_timestamp

    @log_exceptions
    async def save_gossip_timestamp(self):
        while True:
            await asyncio.sleep(GRAPH_DOWNLOAD_SECONDS)
            yesterday = int(time.time()) - 24*60*60 # now minus a day
            self.wallet.storage.put('lightning_gossip_until', yesterday)
            self.wallet.storage.write()
            self.print_error('saved lightning gossip timestamp')

    def payment_completed(self, chan, direction, htlc, preimage):
        chan_id = chan.channel_id
        if direction == SENT:
            assert htlc.payment_hash not in self.invoices
            self.paying.pop(bh2u(htlc.payment_hash))
            self.wallet.storage.put('lightning_payments_inflight', self.paying)
        l = self.wallet.storage.get('lightning_payments_completed', [])
        if not preimage:
            preimage, _addr = self.get_invoice(htlc.payment_hash)
        tupl = (time.time(), direction, json.loads(encoder.encode(htlc)), bh2u(preimage), bh2u(chan_id))
        l.append(tupl)
        self.wallet.storage.put('lightning_payments_completed', l)
        self.wallet.storage.write()
        self.network.trigger_callback('ln_payment_completed', tupl[0], direction, htlc, preimage, chan_id)

    def list_invoices(self):
        report = self._list_invoices()
        if report['settled']:
            yield 'Settled invoices:'
            yield '-----------------'
            for date, direction, htlc, preimage in sorted(report['settled']):
                # astimezone converts to local time
                # replace removes the tz info since we don't need to display it
                yield 'Paid at: ' + date.astimezone().replace(tzinfo=None).isoformat(sep=' ', timespec='minutes')
                yield 'We paid' if direction == SENT else 'They paid'
                yield str(htlc)
                yield 'Preimage: ' + (bh2u(preimage) if preimage else 'Not available') # if delete_invoice was called
                yield ''
        if report['unsettled']:
            yield 'Your unsettled invoices:'
            yield '------------------------'
            for addr, preimage, pay_req in report['unsettled']:
                yield pay_req
                yield str(addr)
                yield 'Preimage: ' + bh2u(preimage)
                yield ''
        if report['inflight']:
            yield 'Outgoing payments in progress:'
            yield '------------------------------'
            for addr, htlc, direction in report['inflight']:
                yield str(addr)
                yield str(htlc)
                yield ''

    def _list_invoices(self, chan_id=None):
        invoices  = dict(self.invoices)
        completed = self.wallet.storage.get('lightning_payments_completed', [])
        settled = []
        unsettled = []
        inflight = []
        for date, direction, htlc, hex_preimage, hex_chan_id in completed:
            if chan_id is not None:
                if bfh(hex_chan_id) != chan_id:
                    continue
            htlcobj = UpdateAddHtlc(*htlc)
            if direction == RECEIVED:
                preimage = bfh(invoices.pop(bh2u(htlcobj.payment_hash))[0])
            else:
                preimage = bfh(hex_preimage)
            # FIXME use fromisoformat when minimum Python is 3.7
            settled.append((datetime.fromtimestamp(date, timezone.utc), HTLCOwner(direction), htlcobj, preimage))
        for preimage, pay_req in invoices.values():
            addr = lndecode(pay_req, expected_hrp=constants.net.SEGWIT_HRP)
            unsettled.append((addr, bfh(preimage), pay_req))
        for pay_req, amount_sat, this_chan_id in self.paying.values():
            if chan_id is not None and this_chan_id != chan_id:
                continue
            addr = lndecode(pay_req, expected_hrp=constants.net.SEGWIT_HRP)
            if amount_sat is not None:
                addr.amount = Decimal(amount_sat) / COIN
            htlc = self.find_htlc_for_addr(addr, None if chan_id is None else [chan_id])
            if not htlc:
                self.print_error('Warning, in flight HTLC not found in any channel')
            inflight.append((addr, htlc, direction))
        return {'settled': settled, 'unsettled': unsettled, 'inflight': inflight}

    def find_htlc_for_addr(self, addr, whitelist=None):
        channels = [y for x,y in self.channels.items() if x in whitelist or whitelist is None]
        for chan in channels:
            for htlc in chan.log[LOCAL].adds.values():
                if htlc.payment_hash == addr.paymenthash:
                    return htlc

    def _read_ln_keystore(self) -> BIP32_KeyStore:
        xprv = self.wallet.storage.get('lightning_privkey2')
        if xprv is None:
            # TODO derive this deterministically from wallet.keystore at keystore generation time
            # probably along a hardened path ( lnd-equivalent would be m/1017'/coinType'/ )
            seed = os.urandom(32)
            xprv, xpub = bip32_root(seed, xtype='standard')
            self.wallet.storage.put('lightning_privkey2', xprv)
            self.wallet.storage.write()
        return keystore.from_xprv(xprv)

    def get_and_inc_counter_for_channel_keys(self):
        with self.lock:
            ctr = self.wallet.storage.get('lightning_channel_key_der_ctr', -1)
            ctr += 1
            self.wallet.storage.put('lightning_channel_key_der_ctr', ctr)
            self.wallet.storage.write()
            return ctr

    def _add_peers_from_config(self):
        peer_list = self.config.get('lightning_peers', [])
        for host, port, pubkey in peer_list:
            asyncio.run_coroutine_threadsafe(
                self.add_peer(host, int(port), bfh(pubkey)),
                self.network.asyncio_loop)


    def suggest_peer(self):
        for node_id, peer in self.peers.items():
            if not(peer.initialized.done()):
                continue
            if not all([chan.get_state() in ['CLOSED'] for chan in peer.channels.values()]):
                continue
            return node_id

    def channels_for_peer(self, node_id):
        assert type(node_id) is bytes
        with self.lock:
            return {x: y for (x, y) in self.channels.items() if y.node_id == node_id}

    async def add_peer(self, host, port, node_id):
        port = int(port)
        peer_addr = LNPeerAddr(host, port, node_id)
        if node_id in self.peers:
            return
        self._last_tried_peer[peer_addr] = time.time()
        self.print_error("adding peer", peer_addr)
        peer = Peer(self, peer_addr, request_initial_sync=self.config.get("request_initial_sync", True))
        await self.network.main_taskgroup.spawn(peer.main_loop())
        self.peers[node_id] = peer
        self.network.trigger_callback('ln_status')
        return peer

    def save_channel(self, openchannel):
        assert type(openchannel) is Channel
        if openchannel.config[REMOTE].next_per_commitment_point == openchannel.config[REMOTE].current_per_commitment_point:
            raise Exception("Tried to save channel with next_point == current_point, this should not happen")
        with self.lock:
            self.channels[openchannel.channel_id] = openchannel
            dumped = [x.serialize() for x in self.channels.values()]
        self.wallet.storage.put("channels", dumped)
        self.wallet.storage.write()
        self.network.trigger_callback('channel', openchannel)

    def save_short_chan_id(self, chan):
        """
        Checks if Funding TX has been mined. If it has, save the short channel ID in chan;
        if it's also deep enough, also save to disk.
        Returns tuple (mined_deep_enough, num_confirmations).
        """
        assert chan.get_state() in ["OPEN", "OPENING"]
        lnwatcher = self.network.lnwatcher
        conf = lnwatcher.get_tx_height(chan.funding_outpoint.txid).conf
        if conf > 0:
            block_height, tx_pos = lnwatcher.get_txpos(chan.funding_outpoint.txid)
            assert tx_pos >= 0
            chan.short_channel_id_predicted = calc_short_channel_id(block_height, tx_pos, chan.funding_outpoint.output_index)
        if conf >= chan.constraints.funding_txn_minimum_depth > 0:
            chan.short_channel_id = chan.short_channel_id_predicted
            self.save_channel(chan)
            self.on_channels_updated()
            return True, conf
        return False, conf

    def on_channel_txo(self, event, txo, is_spent: bool):
        with self.lock:
            channels = list(self.channels.values())
        for chan in channels:
            if chan.funding_outpoint.to_str() == txo:
                break
        else:
            return
        chan.set_funding_txo_spentness(is_spent)
        if is_spent:
            if chan.get_state() != 'FORCE_CLOSING':
                chan.set_state("CLOSED")
                self.on_channels_updated()
            self.channel_db.remove_channel(chan.short_channel_id)
        self.network.trigger_callback('channel', chan)

    @log_exceptions
    async def on_network_update(self, event, *args):
        # TODO
        # Race discovered in save_channel (assertion failing):
        # since short_channel_id could be changed while saving.
        with self.lock:
            channels = list(self.channels.values())
        lnwatcher = self.network.lnwatcher
        if event in ('verified', 'wallet_updated'):
            if args[0] != lnwatcher:
                return
        for chan in channels:
            if chan.get_state() == "OPENING":
                res, depth = self.save_short_chan_id(chan)
                if not res:
                    self.print_error("network update but funding tx is still not at sufficient depth. actual depth: " + str(depth))
                    continue
                # this results in the channel being marked OPEN
                peer = self.peers[chan.node_id]
                peer.funding_locked(chan)
            elif chan.get_state() == "OPEN":
                peer = self.peers.get(chan.node_id)
                if peer is None:
                    self.print_error("peer not found for {}".format(bh2u(chan.node_id)))
                    return
                if event == 'fee':
                    await peer.bitcoin_fee_update(chan)
                conf = lnwatcher.get_tx_height(chan.funding_outpoint.txid).conf
                peer.on_network_update(chan, conf)
            elif chan.get_state() == 'FORCE_CLOSING':
                txid = chan.force_close_tx().txid()
                height = lnwatcher.get_tx_height(txid).height
                self.print_error("force closing tx", txid, "height", height)
                if height == TX_HEIGHT_LOCAL:
                    self.print_error('REBROADCASTING CLOSING TX')
                    await self.force_close_channel(chan.channel_id)

    async def _open_channel_coroutine(self, peer, local_amount_sat, push_sat, password):
        # peer might just have been connected to
        await asyncio.wait_for(peer.initialized, 5)
        chan = await peer.channel_establishment_flow(
            password,
            funding_sat=local_amount_sat + push_sat,
            push_msat=push_sat * 1000,
            temp_channel_id=os.urandom(32))
        self.save_channel(chan)
        self.network.lnwatcher.watch_channel(chan.get_funding_address(), chan.funding_outpoint.to_str())
        self.on_channels_updated()
        return chan

    def on_channels_updated(self):
        self.network.trigger_callback('channels')

    @staticmethod
    def choose_preferred_address(addr_list: List[Tuple[str, int]]) -> Tuple[str, int]:
        # choose first one that is an IP
        for host, port in addr_list:
            if is_ip_address(host):
                return host, port
        # otherwise choose one at random
        # TODO maybe filter out onion if not on tor?
        return random.choice(addr_list)

    def open_channel(self, connect_contents, local_amt_sat, push_amt_sat, password=None, timeout=5):
        node_id, rest = extract_nodeid(connect_contents)
        peer = self.peers.get(node_id)
        if not peer:
            all_nodes = self.network.channel_db.nodes
            node_info = all_nodes.get(node_id, None)
            if rest is not None:
                host, port = split_host_port(rest)
            elif node_info and len(node_info.addresses) > 0:
                host, port = self.choose_preferred_address(node_info.addresses)
            else:
                raise ConnStringFormatError(_('Unknown node:') + ' ' + bh2u(node_id))
            try:
                socket.getaddrinfo(host, int(port))
            except socket.gaierror:
                raise ConnStringFormatError(_('Hostname does not resolve (getaddrinfo failed)'))
            peer_future = asyncio.run_coroutine_threadsafe(self.add_peer(host, port, node_id),
                                                           self.network.asyncio_loop)
            peer = peer_future.result(timeout)
        coro = self._open_channel_coroutine(peer, local_amt_sat, push_amt_sat, password)
        f = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
        chan = f.result(timeout)
        return bh2u(chan.node_id)

    def pay(self, invoice, amount_sat=None):
        """
        This is not merged with _pay so that we can run the test with
        one thread only.
        """
        addr, peer, coro = self._pay(invoice, amount_sat)
        fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
        return addr, peer, fut

    def _pay(self, invoice, amount_sat=None):
        addr = self._check_invoice(invoice, amount_sat)
        route = self._create_route_from_invoice(decoded_invoice=addr)
        peer = self.peers[route[0].node_id]
        for chan in self.channels.values():
            if chan.short_channel_id == route[0].short_channel_id:
                chan_id = chan.channel_id
                break
        else:
            assert False, 'Found route with short channel ID we don\'t have: ' + repr(route[0].short_channel_id)
        self.paying[bh2u(addr.paymenthash)] = (invoice, amount_sat, chan_id)
        self.wallet.storage.put('lightning_payments_inflight', self.paying)
        self.wallet.storage.write()
        return addr, peer, self._pay_to_route(route, addr)

    async def _pay_to_route(self, route, addr):
        short_channel_id = route[0].short_channel_id
        with self.lock:
            channels = list(self.channels.values())
        for chan in channels:
            if chan.short_channel_id == short_channel_id:
                break
        else:
            raise Exception("PathFinder returned path with short_channel_id {} that is not in channel list".format(bh2u(short_channel_id)))
        peer = self.peers[route[0].node_id]
        htlc = await peer.pay(route, chan, int(addr.amount * COIN * 1000), addr.paymenthash, addr.get_min_final_cltv_expiry())
        self.network.trigger_callback('htlc_added', htlc, addr, SENT)

    @staticmethod
    def _check_invoice(invoice, amount_sat=None):
        addr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        if amount_sat:
            addr.amount = Decimal(amount_sat) / COIN
        if addr.amount is None:
            raise InvoiceError(_("Missing amount"))
        if addr.get_min_final_cltv_expiry() > 60 * 144:
            raise InvoiceError("{}\n{}".format(
                _("Invoice wants us to risk locking funds for unreasonably long."),
                f"min_final_cltv_expiry: {addr.get_min_final_cltv_expiry()}"))
        return addr

    def _create_route_from_invoice(self, decoded_invoice) -> List[RouteEdge]:
        amount_msat = int(decoded_invoice.amount * COIN * 1000)
        invoice_pubkey = decoded_invoice.pubkey.serialize()
        # use 'r' field from invoice
        route = None  # type: List[RouteEdge]
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
            if len(private_route) == 0: continue
            if len(private_route) > NUM_MAX_EDGES_IN_PAYMENT_PATH: continue
            border_node_pubkey = private_route[0][0]
            path = self.network.path_finder.find_path_for_payment(self.node_keypair.pubkey, border_node_pubkey, amount_msat, channels)
            if not path: continue
            route = self.network.path_finder.create_route_from_path(path, self.node_keypair.pubkey)
            # we need to shift the node pubkey by one towards the destination:
            private_route_nodes = [edge[0] for edge in private_route][1:] + [invoice_pubkey]
            private_route_rest = [edge[1:] for edge in private_route]
            prev_node_id = border_node_pubkey
            for node_pubkey, edge_rest in zip(private_route_nodes, private_route_rest):
                short_channel_id, fee_base_msat, fee_proportional_millionths, cltv_expiry_delta = edge_rest
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
                self.print_error(f"rejecting insane route {route}")
                route = None
                continue
            break
        # if could not find route using any hint; try without hint now
        if route is None:
            path = self.network.path_finder.find_path_for_payment(self.node_keypair.pubkey, invoice_pubkey, amount_msat, channels)
            if not path:
                raise PaymentFailure(_("No path found"))
            route = self.network.path_finder.create_route_from_path(path, self.node_keypair.pubkey)
            if not is_route_sane_to_use(route, amount_msat, decoded_invoice.get_min_final_cltv_expiry()):
                self.print_error(f"rejecting insane route {route}")
                raise PaymentFailure(_("No path found"))
        return route

    def add_invoice(self, amount_sat, message):
        payment_preimage = os.urandom(32)
        RHASH = sha256(payment_preimage)
        amount_btc = amount_sat/Decimal(COIN) if amount_sat else None
        routing_hints = self._calc_routing_hints_for_invoice(amount_sat)
        if not routing_hints:
            self.print_error("Warning. No routing hints added to invoice. "
                             "Other clients will likely not be able to send to us.")
        pay_req = lnencode(LnAddr(RHASH, amount_btc,
                                  tags=[('d', message),
                                        ('c', MIN_FINAL_CLTV_EXPIRY_FOR_INVOICE)]
                                       + routing_hints),
                           self.node_keypair.privkey)
        self.invoices[bh2u(RHASH)] = (bh2u(payment_preimage), pay_req)
        self.wallet.storage.put('lightning_invoices', self.invoices)
        self.wallet.storage.write()
        return pay_req

    def get_invoice(self, payment_hash: bytes) -> Tuple[bytes, LnAddr]:
        try:
            preimage_hex, pay_req = self.invoices[bh2u(payment_hash)]
            preimage = bfh(preimage_hex)
            assert sha256(preimage) == payment_hash
            return preimage, lndecode(pay_req, expected_hrp=constants.net.SEGWIT_HRP)
        except KeyError as e:
            raise UnknownPaymentHash(payment_hash) from e

    def _calc_routing_hints_for_invoice(self, amount_sat):
        """calculate routing hints (BOLT-11 'r' field)"""
        routing_hints = []
        with self.lock:
            channels = list(self.channels.values())
        # note: currently we add *all* our channels; but this might be a privacy leak?
        for chan in channels:
            # check channel is open
            if chan.get_state() != "OPEN": continue
            # check channel has sufficient balance
            # FIXME because of on-chain fees of ctx, this check is insufficient
            if amount_sat and chan.balance(REMOTE) // 1000 < amount_sat: continue
            chan_id = chan.short_channel_id
            assert type(chan_id) is bytes, chan_id
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
                policy = channel_info.get_policy_for_node(chan.node_id)
                if policy:
                    fee_base_msat = policy.fee_base_msat
                    fee_proportional_millionths = policy.fee_proportional_millionths
                    cltv_expiry_delta = policy.cltv_expiry_delta
                    missing_info = False
            if missing_info:
                self.print_error(f"Warning. Missing channel update for our channel {bh2u(chan_id)}; "
                                 f"filling invoice with incorrect data.")
            routing_hints.append(('r', [(chan.node_id,
                                         chan_id,
                                         fee_base_msat,
                                         fee_proportional_millionths,
                                         cltv_expiry_delta)]))
        return routing_hints

    def delete_invoice(self, payment_hash_hex: str):
        # FIXME we will now LOSE the preimage!! is this feature a good idea?
        # maybe instead of deleting, we could have a feature to "hide" invoices (e.g. for GUI)
        try:
            del self.invoices[payment_hash_hex]
        except KeyError:
            return
        self.wallet.storage.put('lightning_invoices', self.invoices)
        self.wallet.storage.write()

    def list_channels(self):
        with self.lock:
            # we output the funding_outpoint instead of the channel_id because lnd uses channel_point (funding outpoint) to identify channels
            for channel_id, chan in self.channels.items():
                yield {
                    'local_htlcs':  json.loads(encoder.encode(chan.log[LOCAL ]._asdict())),
                    'remote_htlcs': json.loads(encoder.encode(chan.log[REMOTE]._asdict())),
                    'channel_id': bh2u(chan.short_channel_id),
                    'channel_point': chan.funding_outpoint.to_str(),
                    'state': chan.get_state(),
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
        chan.set_state('FORCE_CLOSING')
        self.save_channel(chan)
        self.on_channels_updated()
        return await self.network.broadcast_transaction(tx)

    def _get_next_peers_to_try(self) -> Sequence[LNPeerAddr]:
        now = time.time()
        recent_peers = self.channel_db.get_recent_peers()
        # maintenance for last tried times
        # due to this, below we can just test membership in _last_tried_peer
        for peer in list(self._last_tried_peer):
            if now >= self._last_tried_peer[peer] + PEER_RETRY_INTERVAL:
                del self._last_tried_peer[peer]
        # first try from recent peers
        for peer in recent_peers:
            if peer.pubkey in self.peers: continue
            if peer in self._last_tried_peer: continue
            return [peer]
        # try random peer from graph
        all_nodes = self.channel_db.nodes
        if all_nodes:
            #self.print_error('trying to get ln peers from channel db')
            node_ids = list(all_nodes)
            max_tries = min(200, len(all_nodes))
            for i in range(max_tries):
                node_id = random.choice(node_ids)
                node = all_nodes.get(node_id)
                if node is None: continue
                addresses = node.addresses
                if not addresses: continue
                host, port = self.choose_preferred_address(addresses)
                peer = LNPeerAddr(host, port, node_id)
                if peer.pubkey in self.peers: continue
                if peer in self._last_tried_peer: continue
                self.print_error('taking random ln peer from our channel db')
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
        self.print_error('asking dns seed "{}" for ln peers'.format(dns_seed))
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
                self.print_error('error with parsing peer from dns seed: {}'.format(e))
                continue
        self.print_error('got {} ln peers from dns seed'.format(len(peers)))
        return peers

    async def reestablish_peers_and_channels(self):
        async def reestablish_peer_for_given_channel():
            # try last good address first
            peer = self.channel_db.get_last_good_address(chan.node_id)
            if peer:
                last_tried = self._last_tried_peer.get(peer, 0)
                if last_tried + PEER_RETRY_INTERVAL_FOR_CHANNELS < now:
                    await self.add_peer(peer.host, peer.port, peer.pubkey)
                    return
            # try random address for node_id
            node_info = self.channel_db.nodes.get(chan.node_id, None)
            if not node_info: return
            addresses = node_info.addresses
            if not addresses: return
            host, port = random.choice(addresses)
            peer = LNPeerAddr(host, port, chan.node_id)
            last_tried = self._last_tried_peer.get(peer, 0)
            if last_tried + PEER_RETRY_INTERVAL_FOR_CHANNELS < now:
                await self.add_peer(host, port, chan.node_id)

        with self.lock:
            channels = list(self.channels.values())
        now = time.time()
        for chan in channels:
            if not chan.should_try_to_reestablish_peer():
                continue
            peer = self.peers.get(chan.node_id, None)
            if peer is None:
                await reestablish_peer_for_given_channel()
            else:
                coro = peer.reestablish_channel(chan)
                asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    async def main_loop(self):
        await self.on_network_update('network_updated')  # shortcut (don't block) if funding tx locked and verified
        await self.network.lnwatcher.on_network_update('network_updated')  # ping watcher to check our channels
        listen_addr = self.config.get('lightning_listen')
        if listen_addr:
            adr, colon, port = listen_addr.rpartition(':')
            if adr[0] == '[':
                # ipv6
                adr = adr[1:-1]
            async def cb(reader, writer):
                t = LNResponderTransport(self.node_keypair.privkey, reader, writer)
                node_id = await t.handshake()
                # FIXME extract host and port from transport
                peer = Peer(self, LNPeerAddr("bogus", 1337, node_id),
                            request_initial_sync=self.config.get("request_initial_sync", True),
                            transport=t)
                self.peers[node_id] = peer
                await self.network.main_taskgroup.spawn(peer.main_loop())
                self.network.trigger_callback('ln_status')

            await asyncio.start_server(cb, adr, int(port))
        while True:
            await asyncio.sleep(1)
            now = time.time()
            await self.reestablish_peers_and_channels()
            if len(self.peers) >= NUM_PEERS_TARGET:
                continue
            peers = self._get_next_peers_to_try()
            for peer in peers:
                last_tried = self._last_tried_peer.get(peer, 0)
                if last_tried + PEER_RETRY_INTERVAL < now:
                    await self.add_peer(peer.host, peer.port, peer.pubkey)
