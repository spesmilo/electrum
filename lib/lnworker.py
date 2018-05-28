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


from .bitcoin import sha256, COIN
from .util import bh2u, bfh
from .constants import set_testnet, set_simnet
from .simple_config import SimpleConfig
from .network import Network
from .storage import WalletStorage
from .wallet import Wallet
from .lnbase import Peer, Outpoint, ChannelConfig, LocalState, RemoteState, Keypair, OnlyPubkeyKeypair, OpenChannel, ChannelConstraints, RevocationStore, aiosafe
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



class LNWorker:

    def __init__(self, wallet, network):
        self.wallet = wallet
        self.network = network
        self.privkey = sha256(b"0123456789")
        self.config = network.config
        self.peers = {}
        # view of the network
        self.nodes = {}  # received node announcements
        self.channel_db = lnrouter.ChannelDB()
        self.path_finder = lnrouter.LNPathFinder(self.channel_db)

        self.channels = wallet.storage.get("channels", {})
        peer_list = network.config.get('lightning_peers', node_list)
        for host, port, pubkey in peer_list:
            self.add_peer(host, port, pubkey)
        # wait until we see confirmations
        self.network.register_callback(self.on_network_update, ['updated', 'verified']) # thread safe
        self.on_network_update('updated') # shortcut (don't block) if funding tx locked and verified

    def add_peer(self, host, port, pubkey):
        peer = Peer(host, int(port), binascii.unhexlify(pubkey), self.privkey,
                    self.network, self.channel_db, self.path_finder)
        self.network.futures.append(asyncio.run_coroutine_threadsafe(peer.main_loop(), asyncio.get_event_loop()))
        self.peers[pubkey] = peer

    def save_channel(self, openchannel):
        dumped = serialize_channels([openchannel])
        self.wallet.storage.put("channels", dumped)
        self.wallet.storage.write()

    def on_network_update(self, event, *args):
        for chan in self.channels:
            peer = self.peers[chan.node_id]
            conf = wallet.get_tx_height(chan.funding_outpoint.txid)[1]
            if conf >= chan.constraints.funding_txn_minimum_depth:
                block_height, tx_pos = wallet.get_txpos(chan.funding_outpoint.txid)
                if tx_pos == -1:
                    self.print_error('funding tx is not yet SPV verified.. but there are '
                                     'already enough confirmations (currently {})'.format(conf))
                    return
                asyncio.run_coroutine_threadsafe(self.set_local_funding_locked_result(peer, chan, block_height, txpos), asyncio.get_event_loop())

    async def set_local_funding_locked_result(self, peer, chan, block_height, txpos):
        channel_id = chan.channel_id
        try:
            peer.local_funding_locked[channel_id].set_result(short_channel_id)
        except (asyncio.InvalidStateError, KeyError) as e:
            # FIXME race condition if updates come in quickly, set_result might be called multiple times
            # or self.local_funding_locked[channel_id] might be deleted already
            self.print_error('local_funding_locked.set_result error for channel {}: {}'.format(channel_id, e))
        short_channel_id = calc_short_channel_id(block_height, tx_pos, chan.funding_outpoint.output_index)
        openchannel = await peer.on_funding_locked(openingchannel, self.wallet)
        self.save_channel(openchannel)

    @aiosafe
    async def _open_channel_coroutine(self, node_id, amount, push_msat, password):
        peer = self.peers[node_id]
        openingchannel = await peer.channel_establishment_flow(self.wallet, self.config, password, amount, push_msat, temp_channel_id=os.urandom(32))
        self.save_channel(openingchannel)

    def open_channel(self, node_id, local_amt, push_amt, emit_function, pw):
        coro = self._open_channel_coroutine(node_id, local_amt, push_amt, None if pw == "" else pw)
        asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

        #chan = fut.result()
        # https://api.lightning.community/#listchannels
        #std_chan = {"chan_id": chan.channel_id}
        #emit_function({"channels": [std_chan]})

    def list_channels(self):
        return self.channels

    @aiosafe
    async def reestablish_channel(self):
        if self.channels is None or len(self.channels) < 1:
            raise Exception("Can't reestablish: No channel saved")
        openchannel = self.channels[0]
        openchannel = reconstruct_namedtuples(openchannel)
        openchannel = await peer.reestablish_channel(openchannel)
        self.save_channel(openchannel)

    @aiosafe
    async def pay(self):
        addr = lndecode(sys.argv[6], expected_hrp="sb" if sys.argv[2] == "simnet" else "tb")
        payment_hash = addr.paymenthash
        pubkey = addr.pubkey.serialize()
        msat_amt = int(addr.amount * COIN * 1000)
        openchannel = await peer.pay(wallet, openchannel, msat_amt, payment_hash, pubkey, addr.min_final_cltv_expiry)
        self.save_channel(openchannel)

    @aiosafe
    async def get_paid(self):
        payment_preimage = os.urandom(32)
        RHASH = sha256(payment_preimage)
        expected_received_sat = 200000
        expected_received_msat = expected_received_sat * 1000
        pay_req = lnencode(LnAddr(RHASH, amount=1/Decimal(COIN)*expected_received_sat, tags=[('d', 'one cup of coffee')]), peer.privkey[:32])
        print("payment request", pay_req)
        openchannel = await peer.receive_commitment_revoke_ack(openchannel, expected_received_msat, payment_preimage)
        self.save_channel(openchannel)


    def subscribe_payment_received_from_other_thread(self, emit_function):
        pass

    def subscribe_channel_list_updates_from_other_thread(self, emit_function):
        pass

    def subscribe_single_channel_update_from_other_thread(self, emit_function):
        pass

    def add_invoice_from_other_thread(self, amt):
        pass

    def subscribe_invoice_added_from_other_thread(self, emit_function):
        pass

    def pay_invoice_from_other_thread(self, lnaddr):
        pass


