import json
import binascii
import asyncio
import os
from decimal import Decimal
import threading
from collections import defaultdict

from . import constants
from .bitcoin import sha256, COIN
from .util import bh2u, bfh, PrintError
from .constants import set_testnet, set_simnet
from .lnbase import Peer, privkey_to_pubkey
from .lightning_payencode.lnaddr import lnencode, LnAddr, lndecode
from .ecc import der_sig_from_sig_string
from .transaction import Transaction
from .lnhtlc import HTLCStateMachine
from .lnutil import Outpoint, calc_short_channel_id

# hardcoded nodes
node_list = [
    ('ecdsa.net', '9735', '038370f0e7a03eded3e1d41dc081084a87f0afa1c5b22090b4f3abb391eb15d8ff'),
]

class LNWorker(PrintError):

    def __init__(self, wallet, network):
        self.wallet = wallet
        self.network = network
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
        peer_list = network.config.get('lightning_peers', node_list)
        self.channel_state = {chan.channel_id: "DISCONNECTED" for chan in self.channels.values()}
        for chan_id, chan in self.channels.items():
            self.network.lnwatcher.watch_channel(chan, self.on_channel_utxos)
        for host, port, pubkey in peer_list:
            self.add_peer(host, int(port), bfh(pubkey))
        # wait until we see confirmations
        self.network.register_callback(self.on_network_update, ['updated', 'verified']) # thread safe
        self.on_network_update('updated') # shortcut (don't block) if funding tx locked and verified

    def channels_for_peer(self, node_id):
        assert type(node_id) is bytes
        return {x: y for (x, y) in self.channels.items() if y.node_id == node_id}

    def add_peer(self, host, port, node_id):
        peer = Peer(self, host, int(port), node_id, request_initial_sync=self.config.get("request_initial_sync", True))
        self.network.futures.append(asyncio.run_coroutine_threadsafe(peer.main_loop(), asyncio.get_event_loop()))
        self.peers[node_id] = peer
        self.lock = threading.Lock()

    def save_channel(self, openchannel):
        assert type(openchannel) is HTLCStateMachine
        if openchannel.channel_id not in self.channel_state:
            self.channel_state[openchannel.channel_id] = "OPENING"
        self.channels[openchannel.channel_id] = openchannel
        for node_id, peer in self.peers.items():
            peer.channels = self.channels_for_peer(node_id)
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
        assert self.channel_state[chan.channel_id] in ["OPEN", "OPENING"]
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
            self.channel_state[chan.channel_id] = "CLOSED"
        elif self.channel_state[chan.channel_id] == 'DISCONNECTED':
            peer = self.peers[chan.node_id]
            coro = peer.reestablish_channel(chan)
            asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    def on_network_update(self, event, *args):
        for chan in self.channels.values():
            peer = self.peers[chan.node_id]
            if self.channel_state[chan.channel_id] == "OPENING":
                res = self.save_short_chan_id(chan)
                if not res:
                    self.print_error("network update but funding tx is still not at sufficient depth")
                    continue
                # this results in the channel being marked OPEN
                peer.funding_locked(chan)
            elif self.channel_state[chan.channel_id] == "OPEN":
                conf = self.wallet.get_tx_height(chan.funding_outpoint.txid)[1]
                peer.on_network_update(chan, conf)

    async def _open_channel_coroutine(self, node_id, amount_sat, push_sat, password):
        if node_id not in self.peers:
            node = self.network.lightning_nodes.get(node_id)
            if node is None:
                return "node not found, peers available are: " + str(self.network.lightning_nodes.keys())
            host, port = node['addresses'][0]
            self.add_peer(host, port, node_id)
        peer = self.peers[node_id]
        openingchannel = await peer.channel_establishment_flow(self.wallet, self.config, password, amount_sat, push_sat * 1000, temp_channel_id=os.urandom(32))
        self.save_channel(openingchannel)
        self.on_channels_updated()

    def on_channels_updated(self):
        self.network.trigger_callback('channels')

    def open_channel(self, node_id, local_amt_sat, push_amt_sat, pw):
        coro = self._open_channel_coroutine(node_id, local_amt_sat, push_amt_sat, None if pw == "" else pw)
        return asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    def pay(self, invoice):
        addr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        payment_hash = addr.paymenthash
        invoice_pubkey = addr.pubkey.serialize()
        amount_msat = int(addr.amount * COIN * 1000)
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
        tx = chan.local_commitment
        chan.local_state = old_local_state
        tx.sign({bh2u(chan.local_config.multisig_key.pubkey): (chan.local_config.multisig_key.privkey, True)})
        remote_sig = chan.local_state.current_commitment_signature
        remote_sig = der_sig_from_sig_string(remote_sig) + b"\x01"
        none_idx = tx._inputs[0]["signatures"].index(None)
        tx.add_signature_to_txin(0, none_idx, bh2u(remote_sig))
        assert tx.is_complete()
        return self.network.broadcast_transaction(tx)
