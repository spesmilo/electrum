import traceback
import sys
import json
import binascii
import asyncio
import time
import os
from decimal import Decimal
import binascii
import asyncio
import threading
from collections import defaultdict

from . import constants
from .bitcoin import sha256, COIN
from .util import bh2u, bfh, PrintError
from .constants import set_testnet, set_simnet
from .simple_config import SimpleConfig
from .network import Network
from .storage import WalletStorage
from .wallet import Wallet
from .lnbase import Peer, Outpoint, ChannelConfig, LocalState, RemoteState, Keypair, OnlyPubkeyKeypair, OpenChannel, ChannelConstraints, RevocationStore, aiosafe, calc_short_channel_id, privkey_to_pubkey
from .lightning_payencode.lnaddr import lnencode, LnAddr, lndecode
from . import lnrouter


is_key = lambda k: k.endswith("_basepoint") or k.endswith("_key")

def maybeDecode(k, v):
    if k in ["node_id", "short_channel_id", "pubkey", "privkey", "last_per_commitment_point", "next_per_commitment_point", "per_commitment_secret_seed"] and v is not None:
        return binascii.unhexlify(v)
    return v

def decodeAll(v):
    return {i: maybeDecode(i, j) for i, j in v.items()} if isinstance(v, dict) else v

def typeWrap(k, v, local):
    if is_key(k):
        if local:
            return Keypair(**v)
        else:
            return OnlyPubkeyKeypair(**v)
    return v

def reconstruct_namedtuples(openingchannel):
    openingchannel = decodeAll(openingchannel)
    openingchannel=OpenChannel(**openingchannel)
    openingchannel = openingchannel._replace(funding_outpoint=Outpoint(**openingchannel.funding_outpoint))
    new_local_config = {k: typeWrap(k, decodeAll(v), True) for k, v in openingchannel.local_config.items()}
    openingchannel = openingchannel._replace(local_config=ChannelConfig(**new_local_config))
    new_remote_config = {k: typeWrap(k, decodeAll(v), False) for k, v in openingchannel.remote_config.items()}
    openingchannel = openingchannel._replace(remote_config=ChannelConfig(**new_remote_config))
    new_local_state = decodeAll(openingchannel.local_state)
    openingchannel = openingchannel._replace(local_state=LocalState(**new_local_state))
    new_remote_state = decodeAll(openingchannel.remote_state)
    new_remote_state["revocation_store"] = RevocationStore.from_json_obj(new_remote_state["revocation_store"])
    openingchannel = openingchannel._replace(remote_state=RemoteState(**new_remote_state))
    openingchannel = openingchannel._replace(constraints=ChannelConstraints(**openingchannel.constraints))
    return openingchannel

def serialize_channels(channels):
    serialized_channels = []
    for chan in channels:
        namedtuples_to_dict = lambda v: {i: j._asdict() if isinstance(j, tuple) else j for i, j in v._asdict().items()}
        serialized_channels.append({k: namedtuples_to_dict(v) if isinstance(v, tuple) else v for k, v in chan._asdict().items()})
    class MyJsonEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, bytes):
                return binascii.hexlify(o).decode("ascii")
            if isinstance(o, RevocationStore):
                return o.serialize()
            return super(MyJsonEncoder, self)
    dumped = MyJsonEncoder().encode(serialized_channels)
    roundtripped = json.loads(dumped)
    reconstructed = [reconstruct_namedtuples(x) for x in roundtripped]
    if reconstructed != channels:
        raise Exception("Channels did not roundtrip serialization without changes:\n" + repr(reconstructed) + "\n" + repr(channels))
    return roundtripped




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
        self.config = network.config
        self.peers = {}
        # view of the network
        self.nodes = {}  # received node announcements
        self.channel_db = lnrouter.ChannelDB()
        self.path_finder = lnrouter.LNPathFinder(self.channel_db)
        self.channels = [reconstruct_namedtuples(x) for x in wallet.storage.get("channels", {})]
        self.invoices = wallet.storage.get('lightning_invoices', {})
        peer_list = network.config.get('lightning_peers', node_list)
        self.channel_state = {chan.channel_id: "OPENING" for chan in self.channels}
        for host, port, pubkey in peer_list:
            self.add_peer(host, int(port), pubkey)

        self.callbacks = defaultdict(list)
        # wait until we see confirmations
        self.network.register_callback(self.on_network_update, ['updated', 'verified']) # thread safe
        self.on_network_update('updated') # shortcut (don't block) if funding tx locked and verified

    def add_peer(self, host, port, pubkey):
        node_id = bfh(pubkey)
        channels = list(filter(lambda x: x.node_id == node_id, self.channels))
        peer = Peer(host, int(port), node_id, self.privkey, self.network, self.channel_db, self.path_finder, self.channel_state, channels, self.invoices, request_initial_sync=True)
        self.network.futures.append(asyncio.run_coroutine_threadsafe(peer.main_loop(), asyncio.get_event_loop()))
        self.peers[node_id] = peer
        self.lock = threading.Lock()

    def save_channel(self, openchannel):
        if openchannel.channel_id not in self.channel_state:
            self.channel_state[openchannel.channel_id] = "OPENING"
        self.channels = [openchannel] # TODO multiple channels
        dumped = serialize_channels(self.channels)
        self.wallet.storage.put("channels", dumped)
        self.wallet.storage.write()
        self.trigger_callback('channel_updated', {"chan_id": openchannel.channel_id})

    def save_short_chan_id(self, chan):
        """
        Checks if the Funding TX has been mined. If it has save the short channel ID to disk and return the new OpenChannel.

        If the Funding TX has not been mined, return None
        """
        assert self.channel_state[chan.channel_id] == "OPENING"
        peer = self.peers[chan.node_id]
        conf = self.wallet.get_tx_height(chan.funding_outpoint.txid)[1]
        if conf >= chan.constraints.funding_txn_minimum_depth:
            block_height, tx_pos = self.wallet.get_txpos(chan.funding_outpoint.txid)
            if tx_pos == -1:
                self.print_error('funding tx is not yet SPV verified.. but there are '
                                 'already enough confirmations (currently {})'.format(conf))
                return None
            chan = chan._replace(short_channel_id = calc_short_channel_id(block_height, tx_pos, chan.funding_outpoint.output_index))
            self.save_channel(chan)
            return chan
        return None

    def on_network_update(self, event, *args):
        for chan in self.channels:
            if self.channel_state[chan.channel_id] == "OPEN":
                continue
            chan = self.save_short_chan_id(chan)
            if not chan:
                self.print_error("network update but funding tx is still not at sufficient depth")
                continue
            peer = self.peers[chan.node_id]
            asyncio.run_coroutine_threadsafe(self.wait_funding_locked_and_mark_open(peer, chan), asyncio.get_event_loop())

    # aiosafe because we don't wait for result
    @aiosafe
    async def wait_funding_locked_and_mark_open(self, peer, chan):
        if self.channel_state[chan.channel_id] == "OPEN":
            return
        if not chan.local_state.funding_locked_received:
            chan = await peer.funding_locked(chan)
            self.save_channel(chan)
            self.print_error("CHANNEL OPENING COMPLETED")
        self.channel_state[chan.channel_id] = "OPEN"

    # not aiosafe because we call .result() which will propagate an exception
    async def _open_channel_coroutine(self, node_id, amount_sat, push_sat, password):
        peer = self.peers[bfh(node_id)]
        openingchannel = await peer.channel_establishment_flow(self.wallet, self.config, password, amount_sat, push_sat * 1000, temp_channel_id=os.urandom(32))
        self.print_error("SAVING OPENING CHANNEL")
        self.save_channel(openingchannel)
        self.on_channels_updated()

    def on_channels_updated(self):
        std_chan = [{"chan_id": chan.channel_id} for chan in self.channels]
        self.trigger_callback('channels_updated', {'channels':std_chan})

    def open_channel(self, node_id, local_amt_sat, push_amt_sat, pw):
        coro = self._open_channel_coroutine(node_id, local_amt_sat, push_amt_sat, None if pw == "" else pw)
        return asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop).result()

    def pay(self, invoice):
        coro = self._pay_coroutine(invoice)
        return asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    # not aiosafe because we call .result() which will propagate an exception
    async def _pay_coroutine(self, invoice):
        openchannel = self.channels[0]
        addr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        payment_hash = addr.paymenthash
        pubkey = addr.pubkey.serialize()
        msat_amt = int(addr.amount * COIN * 1000)
        peer = self.peers[openchannel.node_id]
        openchannel = await peer.pay(self.wallet, openchannel, msat_amt, payment_hash, pubkey, addr.min_final_cltv_expiry)
        self.save_channel(openchannel)

    def add_invoice(self, amount_sat, message='one cup of coffee'):
        is_open = lambda chan: self.channel_state[chan] == "OPEN"
        # TODO doesn't account for fees!!!
        #if not any(openchannel.remote_state.amount_msat >= amount_sat * 1000 for openchannel in self.channels if is_open(chan)):
        #    return "Not making invoice, no channel has enough balance"
        payment_preimage = os.urandom(32)
        RHASH = sha256(payment_preimage)
        pay_req = lnencode(LnAddr(RHASH, amount_sat/Decimal(COIN), tags=[('d', message)]), self.privkey)
        decoded = lndecode(pay_req, expected_hrp=constants.net.SEGWIT_HRP)
        assert decoded.pubkey.serialize() == privkey_to_pubkey(self.privkey)
        self.invoices[bh2u(payment_preimage)] = pay_req
        self.wallet.storage.put('lightning_invoices', self.invoices)
        self.wallet.storage.write()
        return pay_req

    def list_channels(self):
        return serialize_channels(self.channels)

    def register_callback(self, callback, events):
        with self.lock:
            for event in events:
                self.callbacks[event].append(callback)

    def unregister_callback(self, callback):
        with self.lock:
            for callbacks in self.callbacks.values():
                if callback in callbacks:
                    callbacks.remove(callback)

    def trigger_callback(self, event, *args):
        with self.lock:
            callbacks = self.callbacks[event][:]
        [callback(*args) for callback in callbacks]
