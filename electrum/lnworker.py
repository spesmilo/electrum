import asyncio
import os
from decimal import Decimal
import random
import time
from typing import Optional, Sequence

import dns.resolver
import dns.exception

from . import constants
from .bitcoin import sha256, COIN
from .util import bh2u, bfh, PrintError, InvoiceError, resolve_dns_srv
from .lnbase import Peer, privkey_to_pubkey, aiosafe
from .lnaddr import lnencode, LnAddr, lndecode
from .ecc import der_sig_from_sig_string
from .lnhtlc import HTLCStateMachine
from .lnutil import Outpoint, calc_short_channel_id, LNPeerAddr, get_compressed_pubkey_from_bech32
from .lnwatcher import LNChanCloseHandler
from .i18n import _


NUM_PEERS_TARGET = 4
PEER_RETRY_INTERVAL = 600  # seconds

FALLBACK_NODE_LIST = (
    LNPeerAddr('ecdsa.net', 9735, bfh('038370f0e7a03eded3e1d41dc081084a87f0afa1c5b22090b4f3abb391eb15d8ff')),
)


class LNWorker(PrintError):

    def __init__(self, wallet, network):
        self.wallet = wallet
        self.network = network
        self.channel_db = self.network.channel_db
        pk = wallet.storage.get('lightning_privkey')
        if pk is None:
            pk = bh2u(os.urandom(32))
            wallet.storage.put('lightning_privkey', pk)
            wallet.storage.write()
        self.privkey = bfh(pk)
        self.pubkey = privkey_to_pubkey(self.privkey)
        self.config = network.config
        self.peers = {}
        self.channels = {x.channel_id: x for x in map(HTLCStateMachine, wallet.storage.get("channels", []))}
        self.invoices = wallet.storage.get('lightning_invoices', {})
        for chan_id, chan in self.channels.items():
            self.network.lnwatcher.watch_channel(chan, self.on_channel_utxos)
        self._last_tried_peer = {}  # LNPeerAddr -> unix timestamp
        # TODO peers that we have channels with should also be added now
        # but we don't store their IP/port yet.. also what if it changes?
        # need to listen for node_announcements and save the new IP/port
        self._add_peers_from_config()
        # wait until we see confirmations
        self.network.register_callback(self.on_network_update, ['updated', 'verified', 'fee_histogram']) # thread safe
        self.on_network_update('updated') # shortcut (don't block) if funding tx locked and verified
        self.network.futures.append(asyncio.run_coroutine_threadsafe(self.main_loop(), asyncio.get_event_loop()))

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
        return {x: y for (x, y) in self.channels.items() if y.node_id == node_id}

    def add_peer(self, host, port, node_id):
        port = int(port)
        peer = Peer(self, host, port, node_id, request_initial_sync=self.config.get("request_initial_sync", True))
        self.network.futures.append(asyncio.run_coroutine_threadsafe(peer.main_loop(), asyncio.get_event_loop()))
        self.peers[node_id] = peer
        self.network.trigger_callback('ln_status')

    def save_channel(self, openchannel):
        assert type(openchannel) is HTLCStateMachine
        self.channels[openchannel.channel_id] = openchannel
        if openchannel.remote_state.next_per_commitment_point == openchannel.remote_state.current_per_commitment_point:
            raise Exception("Tried to save channel with next_point == current_point, this should not happen")
        dumped = [x.serialize() for x in self.channels.values()]
        self.wallet.storage.put("channels", dumped)
        self.wallet.storage.write()
        self.network.trigger_callback('channel', openchannel)

    def save_short_chan_id(self, chan):
        """
        Checks if the Funding TX has been mined. If it has save the short channel ID to disk and return the new OpenChannel.

        If the Funding TX has not been mined, return None
        """
        assert chan.state in ["OPEN", "OPENING"]
        peer = self.peers[chan.node_id]
        conf = self.wallet.get_tx_height(chan.funding_outpoint.txid)[1]
        if conf >= chan.constraints.funding_txn_minimum_depth:
            block_height, tx_pos = self.wallet.get_txpos(chan.funding_outpoint.txid)
            if tx_pos == -1:
                self.print_error('funding tx is not yet SPV verified.. but there are '
                                 'already enough confirmations (currently {})'.format(conf))
                return False
            chan.short_channel_id = calc_short_channel_id(block_height, tx_pos, chan.funding_outpoint.output_index)
            self.save_channel(chan)
            return True
        return False

    def on_channel_utxos(self, chan, utxos):
        outpoints = [Outpoint(x["tx_hash"], x["tx_pos"]) for x in utxos]
        if chan.funding_outpoint not in outpoints:
            chan.state = "CLOSED"
            # FIXME is this properly GC-ed? (or too soon?)
            LNChanCloseHandler(self.network, self.wallet, chan)
        elif chan.state == 'DISCONNECTED':
            if chan.node_id not in self.peers:
                self.print_error("received channel_utxos for channel which does not have peer (errored?)")
                return
            peer = self.peers[chan.node_id]
            coro = peer.reestablish_channel(chan)
            asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
        self.network.trigger_callback('channel', chan)

    def on_network_update(self, event, *args):
        """ called from network thread """
        # Race discovered in save_channel (assertion failing):
        # since short_channel_id could be changed while saving.
        # Mitigated by posting to loop:
        async def network_jobs():
            for chan in self.channels.values():
                if chan.state == "OPENING":
                    res = self.save_short_chan_id(chan)
                    if not res:
                        self.print_error("network update but funding tx is still not at sufficient depth")
                        continue
                    # this results in the channel being marked OPEN
                    peer = self.peers[chan.node_id]
                    peer.funding_locked(chan)
                elif chan.state == "OPEN":
                    peer = self.peers.get(chan.node_id)
                    if peer is None:
                        self.print_error("peer not found for {}".format(bh2u(chan.node_id)))
                        return
                    if event == 'fee_histogram':
                        peer.on_bitcoin_fee_update(chan)
                    conf = self.wallet.get_tx_height(chan.funding_outpoint.txid)[1]
                    peer.on_network_update(chan, conf)
        asyncio.run_coroutine_threadsafe(network_jobs(), self.network.asyncio_loop).result()

    async def _open_channel_coroutine(self, node_id, local_amount_sat, push_sat, password):
        peer = self.peers[node_id]
        openingchannel = await peer.channel_establishment_flow(self.wallet, self.config, password, local_amount_sat + push_sat, push_sat * 1000, temp_channel_id=os.urandom(32))
        if not openingchannel:
            self.print_error("Channel_establishment_flow returned None")
            return
        self.save_channel(openingchannel)
        self.network.lnwatcher.watch_channel(openingchannel, self.on_channel_utxos)
        self.on_channels_updated()

    def on_channels_updated(self):
        self.network.trigger_callback('channels')

    def open_channel(self, node_id, local_amt_sat, push_amt_sat, pw):
        coro = self._open_channel_coroutine(node_id, local_amt_sat, push_amt_sat, None if pw == "" else pw)
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
            raise Exception("No path found")
        node_id, short_channel_id = path[0]
        peer = self.peers[node_id]
        for chan in self.channels.values():
            if chan.short_channel_id == short_channel_id:
                break
        else:
            raise Exception("ChannelDB returned path with short_channel_id that is not in channel list")
        coro = peer.pay(path, chan, amount_msat, payment_hash, invoice_pubkey, addr.min_final_cltv_expiry)
        return asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

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
        return [str(x) for x in self.channels]

    def close_channel(self, chan_id):
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
        return self.network.broadcast_transaction(tx)

    def _get_next_peers_to_try(self) -> Sequence[LNPeerAddr]:
        now = time.time()
        recent_peers = self.channel_db.get_recent_peers()
        # maintenance for last tried times
        for peer in list(self._last_tried_peer):
            if now >= self._last_tried_peer[peer] + PEER_RETRY_INTERVAL:
                del self._last_tried_peer[peer]
        # first try from recent peers
        for peer in recent_peers:
            if peer in self.peers:
                continue
            if peer in self._last_tried_peer:
                # due to maintenance above, this means we tried recently
                continue
            return [peer]
        # try random peer from graph
        all_nodes = self.channel_db.nodes
        if all_nodes:
            self.print_error('trying to get ln peers from channel db')
            node_ids = list(all_nodes)
            max_tries = min(200, len(all_nodes))
            for i in range(max_tries):
                node_id = random.choice(node_ids)
                node = all_nodes.get(node_id)
                if node is None: continue
                addresses = node.addresses
                if not addresses: continue
                host, port = addresses[0]
                peer = LNPeerAddr(host, port, node_id)
                if peer in self._last_tried_peer:
                    continue
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
            else:
                ln_host = str(answers[0])
                port = int(srv_ans['port'])
                bech32_pubkey = srv_ans['host'].split('.')[0]
                pubkey = get_compressed_pubkey_from_bech32(bech32_pubkey)
                peers.append(LNPeerAddr(ln_host, port, pubkey))
        self.print_error('got {} ln peers from dns seed'.format(len(peers)))
        return peers

    @aiosafe
    async def main_loop(self):
        while True:
            await asyncio.sleep(1)
            for k, peer in list(self.peers.items()):
                if peer.exception:
                    self.print_error("removing peer", peer.host)
                    self.peers.pop(k)
            if len(self.peers) >= NUM_PEERS_TARGET:
                continue
            peers = self._get_next_peers_to_try()
            for peer in peers:
                self._last_tried_peer[peer] = time.time()
                self.print_error("trying node", peer)
                self.add_peer(peer.host, peer.port, peer.pubkey)
