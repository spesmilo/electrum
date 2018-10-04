import asyncio
import os
from decimal import Decimal
import random
import time
from typing import Optional, Sequence, Tuple, List
import threading
from functools import partial
import socket

import dns.resolver
import dns.exception

from . import constants
from .bitcoin import sha256, COIN
from .util import bh2u, bfh, PrintError, InvoiceError, resolve_dns_srv, is_ip_address
from .lnbase import Peer, privkey_to_pubkey, aiosafe
from .lnaddr import lnencode, LnAddr, lndecode
from .ecc import der_sig_from_sig_string
from .lnhtlc import HTLCStateMachine
from .lnutil import (Outpoint, calc_short_channel_id, LNPeerAddr,
                     get_compressed_pubkey_from_bech32, extract_nodeid,
                     PaymentFailure, split_host_port, ConnStringFormatError)
from electrum.lnaddr import lndecode
from .i18n import _


NUM_PEERS_TARGET = 4
PEER_RETRY_INTERVAL = 600  # seconds
PEER_RETRY_INTERVAL_FOR_CHANNELS = 30  # seconds

FALLBACK_NODE_LIST = (
    LNPeerAddr('ecdsa.net', 9735, bfh('038370f0e7a03eded3e1d41dc081084a87f0afa1c5b22090b4f3abb391eb15d8ff')),
)

class LNWorker(PrintError):

    def __init__(self, wallet, network):
        self.wallet = wallet
        self.sweep_address = wallet.get_receiving_address()
        self.network = network
        self.channel_db = self.network.channel_db
        self.lock = threading.RLock()
        pk = wallet.storage.get('lightning_privkey')
        if pk is None:
            pk = bh2u(os.urandom(32))
            wallet.storage.put('lightning_privkey', pk)
            wallet.storage.write()
        self.privkey = bfh(pk)
        self.pubkey = privkey_to_pubkey(self.privkey)
        self.config = network.config
        self.peers = {}  # pubkey -> Peer
        self.channels = {x.channel_id: x for x in map(HTLCStateMachine, wallet.storage.get("channels", []))}
        for c in self.channels.values():
            c.lnwatcher = network.lnwatcher
        self.invoices = wallet.storage.get('lightning_invoices', {})
        for chan_id, chan in self.channels.items():
            self.network.lnwatcher.watch_channel(chan, self.sweep_address, partial(self.on_channel_utxos, chan))
        self._last_tried_peer = {}  # LNPeerAddr -> unix timestamp
        self._add_peers_from_config()
        # wait until we see confirmations
        self.network.register_callback(self.on_network_update, ['network_updated', 'verified', 'fee'])  # thread safe
        asyncio.run_coroutine_threadsafe(self.network.main_taskgroup.spawn(self.main_loop()), self.network.asyncio_loop)

    def _add_peers_from_config(self):
        peer_list = self.config.get('lightning_peers', [])
        for host, port, pubkey in peer_list:
            self.add_peer(host, int(port), bfh(pubkey))

    def suggest_peer(self):
        for node_id, peer in self.peers.items():
            if len(peer.channels) > 0:
                continue
            if not(peer.initialized.done()):
                continue
            return node_id

    def channels_for_peer(self, node_id):
        assert type(node_id) is bytes
        with self.lock:
            return {x: y for (x, y) in self.channels.items() if y.node_id == node_id}

    def add_peer(self, host, port, node_id):
        port = int(port)
        peer_addr = LNPeerAddr(host, port, node_id)
        if node_id in self.peers:
            return
        self._last_tried_peer[peer_addr] = time.time()
        self.print_error("adding peer", peer_addr)
        peer = Peer(self, host, port, node_id, request_initial_sync=self.config.get("request_initial_sync", True))
        asyncio.run_coroutine_threadsafe(self.network.main_taskgroup.spawn(peer.main_loop()), self.network.asyncio_loop)
        self.peers[node_id] = peer
        self.network.trigger_callback('ln_status')
        return peer

    def save_channel(self, openchannel):
        assert type(openchannel) is HTLCStateMachine
        if openchannel.remote_state.next_per_commitment_point == openchannel.remote_state.current_per_commitment_point:
            raise Exception("Tried to save channel with next_point == current_point, this should not happen")
        with self.lock:
            self.channels[openchannel.channel_id] = openchannel
            dumped = [x.serialize() for x in self.channels.values()]
        self.wallet.storage.put("channels", dumped)
        self.wallet.storage.write()
        self.network.trigger_callback('channel', openchannel)

    def save_short_chan_id(self, chan):
        """
        Checks if the Funding TX has been mined. If it has save the short channel ID to disk and return the new OpenChannel.

        If the Funding TX has not been mined, return None
        """
        assert chan.get_state() in ["OPEN", "OPENING"]
        peer = self.peers[chan.node_id]
        addr_sync = self.network.lnwatcher.addr_sync
        conf = addr_sync.get_tx_height(chan.funding_outpoint.txid).conf
        if conf >= chan.constraints.funding_txn_minimum_depth:
            block_height, tx_pos = addr_sync.get_txpos(chan.funding_outpoint.txid)
            if tx_pos == -1:
                self.print_error('funding tx is not yet SPV verified.. but there are '
                                 'already enough confirmations (currently {})'.format(conf))
                return False, conf
            chan.short_channel_id = calc_short_channel_id(block_height, tx_pos, chan.funding_outpoint.output_index)
            self.save_channel(chan)
            return True, conf
        return False, conf

    def on_channel_utxos(self, chan, is_funding_txo_spent: bool):
        chan.set_funding_txo_spentness(is_funding_txo_spent)
        if is_funding_txo_spent:
            chan.set_state("CLOSED")
            self.channel_db.remove_channel(chan.short_channel_id)
        self.network.trigger_callback('channel', chan)

    @aiosafe
    async def on_network_update(self, event, *args):
        # TODO
        # Race discovered in save_channel (assertion failing):
        # since short_channel_id could be changed while saving.
        with self.lock:
            channels = list(self.channels.values())
        addr_sync = self.network.lnwatcher.addr_sync
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
                conf = addr_sync.get_tx_height(chan.funding_outpoint.txid).conf
                peer.on_network_update(chan, conf)

    async def _open_channel_coroutine(self, peer, local_amount_sat, push_sat, password):
        # peer might just have been connected to
        await asyncio.wait_for(peer.initialized, 5)

        openingchannel = await peer.channel_establishment_flow(password,
                                                               funding_sat=local_amount_sat + push_sat,
                                                               push_msat=push_sat * 1000,
                                                               temp_channel_id=os.urandom(32),
                                                               sweep_address=self.sweep_address)
        if not openingchannel:
            self.print_error("Channel_establishment_flow returned None")
            return
        self.save_channel(openingchannel)
        self.network.lnwatcher.watch_channel(openingchannel, self.sweep_address, partial(self.on_channel_utxos, openingchannel))
        self.on_channels_updated()

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

    def open_channel(self, connect_contents, local_amt_sat, push_amt_sat, pw):
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
            peer = self.add_peer(host, port, node_id)
        coro = self._open_channel_coroutine(peer, local_amt_sat, push_amt_sat, None if pw == "" else pw)
        return asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    def pay(self, invoice, amount_sat=None):
        addr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        payment_hash = addr.paymenthash
        invoice_pubkey = addr.pubkey.serialize()
        amount_sat = (addr.amount * COIN) if addr.amount else amount_sat
        if amount_sat is None:
            raise InvoiceError(_("Missing amount"))
        amount_msat = int(amount_sat * 1000)
        path = self.network.path_finder.find_path_for_payment(self.pubkey, invoice_pubkey, amount_msat)
        if path is None:
            raise PaymentFailure(_("No path found"))
        node_id, short_channel_id = path[0]
        peer = self.peers[node_id]
        with self.lock:
            channels = list(self.channels.values())
        for chan in channels:
            if chan.short_channel_id == short_channel_id:
                break
        else:
            raise Exception("ChannelDB returned path with short_channel_id {} that is not in channel list".format(bh2u(short_channel_id)))
        coro = peer.pay(path, chan, amount_msat, payment_hash, invoice_pubkey, addr.min_final_cltv_expiry)
        return addr, peer, asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    def add_invoice(self, amount_sat, message):
        payment_preimage = os.urandom(32)
        RHASH = sha256(payment_preimage)
        amount_btc = amount_sat/Decimal(COIN) if amount_sat else None
        pay_req = lnencode(LnAddr(RHASH, amount_btc, tags=[('d', message)]), self.privkey)
        self.invoices[bh2u(payment_preimage)] = pay_req
        self.wallet.storage.put('lightning_invoices', self.invoices)
        self.wallet.storage.write()
        return pay_req

    def delete_invoice(self, payreq_key):
        try:
            del self.invoices[payreq_key]
        except KeyError:
            return
        self.wallet.storage.put('lightning_invoices', self.invoices)
        self.wallet.storage.write()

    def list_channels(self):
        with self.lock:
            # we output the funding_outpoint instead of the channel_id because lnd uses channel_point (funding outpoint) to identify channels
            return [(chan.funding_outpoint.to_str(), chan.get_state()) for channel_id, chan in self.channels.items()]

    async def close_channel(self, chan_id):
        chan = self.channels[chan_id]
        # local_commitment always gives back the next expected local_commitment,
        # but in this case, we want the current one. So substract one ctn number
        old_local_state = chan.local_state
        chan.local_state=chan.local_state._replace(ctn=chan.local_state.ctn - 1)
        tx = chan.pending_local_commitment
        chan.local_state = old_local_state
        tx.sign({bh2u(chan.local_config.multisig_key.pubkey): (chan.local_config.multisig_key.privkey, True)})
        remote_sig = chan.local_state.current_commitment_signature
        remote_sig = der_sig_from_sig_string(remote_sig) + b"\x01"
        none_idx = tx._inputs[0]["signatures"].index(None)
        tx.add_signature_to_txin(0, none_idx, bh2u(remote_sig))
        assert tx.is_complete()
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
            return [random.choice(FALLBACK_NODE_LIST)]
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

    def reestablish_peers_and_channels(self):
        def reestablish_peer_for_given_channel():
            # try last good address first
            peer = self.channel_db.get_last_good_address(chan.node_id)
            if peer:
                last_tried = self._last_tried_peer.get(peer, 0)
                if last_tried + PEER_RETRY_INTERVAL_FOR_CHANNELS < now:
                    self.add_peer(peer.host, peer.port, peer.pubkey)
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
                self.add_peer(host, port, chan.node_id)

        with self.lock:
            channels = list(self.channels.values())
        now = time.time()
        for chan in channels:
            if not chan.should_try_to_reestablish_peer():
                continue
            peer = self.peers.get(chan.node_id, None)
            if peer is None:
                reestablish_peer_for_given_channel()
            else:
                coro = peer.reestablish_channel(chan)
                asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    async def main_loop(self):
        await self.on_network_update('network_updated')  # shortcut (don't block) if funding tx locked and verified
        await self.network.lnwatcher.on_network_update('network_updated')  # ping watcher to check our channels
        while True:
            await asyncio.sleep(1)
            now = time.time()
            for node_id, peer in list(self.peers.items()):
                if peer.exception:
                    self.print_error("removing peer", peer.host)
                    peer.close_and_cleanup()
                    self.peers.pop(node_id)
            self.reestablish_peers_and_channels()
            if len(self.peers) >= NUM_PEERS_TARGET:
                continue
            peers = self._get_next_peers_to_try()
            for peer in peers:
                last_tried = self._last_tried_peer.get(peer, 0)
                if last_tried + PEER_RETRY_INTERVAL < now:
                    self.add_peer(peer.host, peer.port, peer.pubkey)
