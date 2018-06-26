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
from .lnbase import Peer, Outpoint, ChannelConfig, LocalState, RemoteState, Keypair, OnlyPubkeyKeypair, OpenChannel, ChannelConstraints, RevocationStore, calc_short_channel_id, privkey_to_pubkey
from .lightning_payencode.lnaddr import lnencode, LnAddr, lndecode
from .ecc import ECPrivkey, CURVE_ORDER, der_sig_from_sig_string
from .transaction import Transaction

is_key = lambda k: k.endswith("_basepoint") or k.endswith("_key")

def maybeDecode(k, v):
    if k in ["node_id", "channel_id", "short_channel_id", "pubkey", "privkey", "current_per_commitment_point", "next_per_commitment_point", "per_commitment_secret_seed", "current_commitment_signature"] and v is not None:
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

def serialize_channels(channels_dict):
    serialized_channels = []
    for chan in channels_dict.values():
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
    reconstructed = set(reconstruct_namedtuples(x) for x in roundtripped)
    if reconstructed != set(channels_dict.values()):
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
        self.pubkey = ECPrivkey(self.privkey).get_public_key_bytes()
        self.config = network.config
        self.peers = {}
        # view of the network
        self.nodes = {}  # received node announcements
        self.channels = {x.channel_id: x for x in map(reconstruct_namedtuples, wallet.storage.get("channels", []))}
        self.invoices = wallet.storage.get('lightning_invoices', {})
        peer_list = network.config.get('lightning_peers', node_list)
        self.channel_state = {chan.channel_id: "DISCONNECTED" for chan in self.channels.values()}
        for chan_id, chan in self.channels.items():
            self.network.lnwatcher.watch_channel(chan, self.on_channel_utxos)
        for host, port, pubkey in peer_list:
            self.add_peer(host, int(port), pubkey)
        # wait until we see confirmations
        self.network.register_callback(self.on_network_update, ['updated', 'verified']) # thread safe
        self.on_network_update('updated') # shortcut (don't block) if funding tx locked and verified

    def channels_for_peer(self, node_id):
        assert type(node_id) is bytes
        return {x: y for (x, y) in self.channels.items() if y.node_id == node_id}

    def add_peer(self, host, port, pubkey):
        node_id = bfh(pubkey)
        peer = Peer(self, host, int(port), node_id, request_initial_sync=self.config.get("request_initial_sync", True))
        self.network.futures.append(asyncio.run_coroutine_threadsafe(peer.main_loop(), asyncio.get_event_loop()))
        self.peers[node_id] = peer
        self.lock = threading.Lock()

    def save_channel(self, openchannel):
        if openchannel.channel_id not in self.channel_state:
            self.channel_state[openchannel.channel_id] = "OPENING"
        self.channels[openchannel.channel_id] = openchannel
        for node_id, peer in self.peers.items():
            peer.channels = self.channels_for_peer(node_id)
        if openchannel.remote_state.next_per_commitment_point == openchannel.remote_state.current_per_commitment_point:
            raise Exception("Tried to save channel with next_point == current_point, this should not happen")
        dumped = serialize_channels(self.channels)
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
                return None
            chan = chan._replace(short_channel_id = calc_short_channel_id(block_height, tx_pos, chan.funding_outpoint.output_index))
            self.save_channel(chan)
            return chan
        return None

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
                chan = self.save_short_chan_id(chan)
                if not chan:
                    self.print_error("network update but funding tx is still not at sufficient depth")
                    continue
                # this results in the channel being marked OPEN
                peer.funding_locked(chan)
            elif self.channel_state[chan.channel_id] == "OPEN":
                conf = self.wallet.get_tx_height(chan.funding_outpoint.txid)[1]
                peer.on_network_update(chan, conf)

    # not aiosafe because we call .result() which will propagate an exception
    async def _open_channel_coroutine(self, node_id, amount_sat, push_sat, password):
        if node_id == "":
            peer = next(iter(self.peers.values()))
        else:
            peer = self.peers[bfh(node_id)]
        openingchannel = await peer.channel_establishment_flow(self.wallet, self.config, password, amount_sat, push_sat * 1000, temp_channel_id=os.urandom(32))
        self.print_error("SAVING OPENING CHANNEL")
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
        is_open = lambda chan: self.channel_state[chan.channel_id] == "OPEN"
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

    def close_channel(self, chan_id):
        from .lnhtlc import HTLCStateMachine
        chan = self.channels[chan_id]
        # local_commitment always gives back the next expected local_commitment,
        # but in this case, we want the current one. So substract one ctn number
        tx = HTLCStateMachine(chan._replace(local_state=chan.local_state._replace(ctn=chan.local_state.ctn - 1))).local_commitment
        tx.sign({bh2u(chan.local_config.multisig_key.pubkey): (chan.local_config.multisig_key.privkey, True)})
        remote_sig = chan.local_state.current_commitment_signature
        remote_sig = der_sig_from_sig_string(remote_sig) + b"\x01"
        none_idx = tx._inputs[0]["signatures"].index(None)
        tx.add_signature_to_txin(0, none_idx, bh2u(remote_sig))
        assert tx.is_complete()
        return self.network.broadcast_transaction(tx)
