#!/usr/bin/env python3
"""
  Lightning network interface for Electrum
  Derived from https://gist.github.com/AdamISZ/046d05c156aaeb56cc897f85eecb3eb8
"""

from collections import namedtuple, defaultdict, OrderedDict, defaultdict
from .lnutil import Outpoint, ChannelConfig, LocalState, RemoteState, Keypair, OnlyPubkeyKeypair, ChannelConstraints, RevocationStore
from .lnutil import sign_and_get_sig_string, funding_output_script, get_ecdh, get_per_commitment_secret_from_seed
from .lnutil import secret_to_pubkey, LNPeerAddr, PaymentFailure
from .lnutil import LOCAL, REMOTE
from .bitcoin import COIN

from ecdsa.util import sigdecode_der, sigencode_string_canonize, sigdecode_string
import queue
import traceback
import json
import asyncio
from concurrent.futures import FIRST_COMPLETED
import os
import time
import binascii
import hashlib
import hmac
import cryptography.hazmat.primitives.ciphers.aead as AEAD

from . import bitcoin
from . import ecc
from . import crypto
from .crypto import sha256
from . import constants
from . import transaction
from .util import PrintError, bh2u, print_error, bfh, aiosafe
from .transaction import opcodes, Transaction, TxOutput
from .lnonion import new_onion_packet, OnionHopsDataSingle, OnionPerHop, decode_onion_error, ONION_FAILURE_CODE_MAP
from .lnaddr import lndecode
from .lnhtlc import HTLCStateMachine, RevokeAndAck

def channel_id_from_funding_tx(funding_txid, funding_index):
    funding_txid_bytes = bytes.fromhex(funding_txid)[::-1]
    i = int.from_bytes(funding_txid_bytes, 'big') ^ funding_index
    return i.to_bytes(32, 'big'), funding_txid_bytes

class LightningError(Exception):
    pass

class LightningPeerConnectionClosed(LightningError):
    pass

message_types = {}

def handlesingle(x, ma):
    """
    Evaluate a term of the simple language used
    to specify lightning message field lengths.

    If `x` is an integer, it is returned as is,
    otherwise it is treated as a variable and
    looked up in `ma`.

    It the value in `ma` was no integer, it is
    assumed big-endian bytes and decoded.

    Returns int
    """
    try:
        x = int(x)
    except ValueError:
        x = ma[x]
    try:
        x = int(x)
    except ValueError:
        x = int.from_bytes(x, byteorder='big')
    return x

def calcexp(exp, ma):
    """
    Evaluate simple mathematical expression given
    in `exp` with variables assigned in the dict `ma`

    Returns int
    """
    exp = str(exp)
    if "*" in exp:
        assert "+" not in exp
        result = 1
        for term in exp.split("*"):
            result *= handlesingle(term, ma)
        return result
    return sum(handlesingle(x, ma) for x in exp.split("+"))

def make_handler(k, v):
    """
    Generate a message handler function (taking bytes)
    for message type `k` with specification `v`

    Check lib/lightning.json, `k` could be 'init',
    and `v` could be

      { type: 16, payload: { 'gflen': ..., ... }, ... }

    Returns function taking bytes
    """
    def handler(data):
        nonlocal k, v
        ma = {}
        pos = 0
        for fieldname in v["payload"]:
            poslenMap = v["payload"][fieldname]
            if "feature" in poslenMap and pos == len(data):
                continue
            #print(poslenMap["position"], ma)
            assert pos == calcexp(poslenMap["position"], ma)
            length = poslenMap["length"]
            length = calcexp(length, ma)
            ma[fieldname] = data[pos:pos+length]
            pos += length
        assert pos == len(data), (k, pos, len(data))
        return k, ma
    return handler

path = os.path.join(os.path.dirname(__file__), 'lightning.json')
with open(path) as f:
    structured = json.loads(f.read(), object_pairs_hook=OrderedDict)

for k in structured:
    v = structured[k]
    # these message types are skipped since their types collide
    # (for example with pong, which also uses type=19)
    # we don't need them yet
    if k in ["final_incorrect_cltv_expiry", "final_incorrect_htlc_amount"]:
        continue
    if len(v["payload"]) == 0:
        continue
    try:
        num = int(v["type"])
    except ValueError:
        #print("skipping", k)
        continue
    byts = num.to_bytes(2, 'big')
    assert byts not in message_types, (byts, message_types[byts].__name__, k)
    names = [x.__name__ for x in message_types.values()]
    assert k + "_handler" not in names, (k, names)
    message_types[byts] = make_handler(k, v)
    message_types[byts].__name__ = k + "_handler"

assert message_types[b"\x00\x10"].__name__ == "init_handler"

def decode_msg(data):
    """
    Decode Lightning message by reading the first
    two bytes to determine message type.

    Returns message type string and parsed message contents dict
    """
    typ = data[:2]
    k, parsed = message_types[typ](data[2:])
    return k, parsed

def gen_msg(msg_type, **kwargs):
    """
    Encode kwargs into a Lightning message (bytes)
    of the type given in the msg_type string
    """
    typ = structured[msg_type]
    data = int(typ["type"]).to_bytes(2, 'big')
    lengths = {}
    for k in typ["payload"]:
        poslenMap = typ["payload"][k]
        if "feature" in poslenMap: continue
        leng = calcexp(poslenMap["length"], lengths)
        try:
            clone = dict(lengths)
            clone.update(kwargs)
            leng = calcexp(poslenMap["length"], clone)
        except KeyError:
            pass
        try:
            param = kwargs[k]
        except KeyError:
            param = 0
        try:
            if not isinstance(param, bytes):
                assert isinstance(param, int), "field {} is neither bytes or int".format(k)
                param = param.to_bytes(leng, 'big')
        except ValueError:
            raise Exception("{} does not fit in {} bytes".format(k, leng))
        lengths[k] = len(param)
        if lengths[k] != leng:
            raise Exception("field {} is {} bytes long, should be {} bytes long".format(k, lengths[k], leng))
        data += param
    return data


class HandshakeState(object):
    prologue = b"lightning"
    protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256"
    handshake_version = b"\x00"

    def __init__(self, responder_pub):
        self.responder_pub = responder_pub
        self.h = sha256(self.protocol_name)
        self.ck = self.h
        self.update(self.prologue)
        self.update(self.responder_pub)

    def update(self, data):
        self.h = sha256(self.h + data)
        return self.h


class HandshakeFailed(Exception): pass


def get_nonce_bytes(n):
    """BOLT 8 requires the nonce to be 12 bytes, 4 bytes leading
    zeroes and 8 bytes little endian encoded 64 bit integer.
    """
    return b"\x00"*4 + n.to_bytes(8, 'little')

def aead_encrypt(k, nonce, associated_data, data):
    nonce_bytes = get_nonce_bytes(nonce)
    a = AEAD.ChaCha20Poly1305(k)
    return a.encrypt(nonce_bytes, data, associated_data)

def aead_decrypt(k, nonce, associated_data, data):
    nonce_bytes = get_nonce_bytes(nonce)
    a = AEAD.ChaCha20Poly1305(k)
    #raises InvalidTag exception if it's not valid
    return a.decrypt(nonce_bytes, data, associated_data)

def get_bolt8_hkdf(salt, ikm):
    """RFC5869 HKDF instantiated in the specific form
    used in Lightning BOLT 8:
    Extract and expand to 64 bytes using HMAC-SHA256,
    with info field set to a zero length string as per BOLT8
    Return as two 32 byte fields.
    """
    #Extract
    prk = hmac.new(salt, msg=ikm, digestmod=hashlib.sha256).digest()
    assert len(prk) == 32
    #Expand
    info = b""
    T0 = b""
    T1 = hmac.new(prk, T0 + info + b"\x01", digestmod=hashlib.sha256).digest()
    T2 = hmac.new(prk, T1 + info + b"\x02", digestmod=hashlib.sha256).digest()
    assert len(T1 + T2) == 64
    return T1, T2

def act1_initiator_message(hs, epriv, epub):
    hs.update(epub)
    ss = get_ecdh(epriv, hs.responder_pub)
    ck2, temp_k1 = get_bolt8_hkdf(hs.ck, ss)
    hs.ck = ck2
    c = aead_encrypt(temp_k1, 0, hs.h, b"")
    #for next step if we do it
    hs.update(c)
    msg = hs.handshake_version + epub + c
    assert len(msg) == 50
    return msg

def privkey_to_pubkey(priv: bytes) -> bytes:
    return ecc.ECPrivkey(priv[:32]).get_public_key_bytes()

def create_ephemeral_key() -> (bytes, bytes):
    privkey = ecc.ECPrivkey.generate_random_key()
    return privkey.get_secret_bytes(), privkey.get_public_key_bytes()


class Peer(PrintError):

    def __init__(self, lnworker, host, port, pubkey, request_initial_sync=False):
        self.exception = None # set by aiosafe
        self.host = host
        self.port = port
        self.pubkey = pubkey
        self.peer_addr = LNPeerAddr(host, port, pubkey)
        self.lnworker = lnworker
        self.privkey = lnworker.privkey
        self.network = lnworker.network
        self.lnwatcher = lnworker.network.lnwatcher
        self.channel_db = lnworker.network.channel_db
        self.read_buffer = b''
        self.ping_time = 0
        self.initialized = asyncio.Future()
        self.channel_accepted = defaultdict(asyncio.Queue)
        self.channel_reestablished = defaultdict(asyncio.Future)
        self.funding_signed = defaultdict(asyncio.Queue)
        self.revoke_and_ack = defaultdict(asyncio.Queue)
        self.update_fulfill_htlc = defaultdict(asyncio.Queue)
        self.commitment_signed = defaultdict(asyncio.Queue)
        self.announcement_signatures = defaultdict(asyncio.Queue)
        self.update_fail_htlc = defaultdict(asyncio.Queue)
        self.closing_signed = defaultdict(asyncio.Queue)
        self.localfeatures = (0x08 if request_initial_sync else 0)
        self.invoices = lnworker.invoices
        self.attempted_route = {}

    @property
    def channels(self):
        return self.lnworker.channels_for_peer(self.pubkey)

    def diagnostic_name(self):
        return 'lnbase:' + str(self.host)

    def ping_if_required(self):
        if time.time() - self.ping_time > 120:
            self.send_message(gen_msg('ping', num_pong_bytes=4, byteslen=4))
            self.ping_time = time.time()

    def send_message(self, msg):
        message_type, payload = decode_msg(msg)
        self.print_error("Sending '%s'"%message_type.upper())
        l = len(msg).to_bytes(2, 'big')
        lc = aead_encrypt(self.sk, self.sn(), b'', l)
        c = aead_encrypt(self.sk, self.sn(), b'', msg)
        assert len(lc) == 18
        assert len(c) == len(msg) + 16
        self.writer.write(lc+c)

    async def read_message(self):
        rn_l, rk_l = self.rn()
        rn_m, rk_m = self.rn()
        while True:
            if len(self.read_buffer) >= 18:
                lc = self.read_buffer[:18]
                l = aead_decrypt(rk_l, rn_l, b'', lc)
                length = int.from_bytes(l, 'big')
                offset = 18 + length + 16
                if len(self.read_buffer) >= offset:
                    c = self.read_buffer[18:offset]
                    self.read_buffer = self.read_buffer[offset:]
                    msg = aead_decrypt(rk_m, rn_m, b'', c)
                    return msg
            try:
                s = await self.reader.read(2**10)
            except:
                s = None
            if not s:
                raise LightningPeerConnectionClosed()
            self.read_buffer += s

    async def handshake(self):
        hs = HandshakeState(self.pubkey)
        # Get a new ephemeral key
        epriv, epub = create_ephemeral_key()

        msg = act1_initiator_message(hs, epriv, epub)
        # act 1
        self.writer.write(msg)
        rspns = await self.reader.read(2**10)
        if len(rspns) != 50:
            raise HandshakeFailed("Lightning handshake act 1 response has bad length, are you sure this is the right pubkey? " + str(bh2u(self.pubkey)))
        hver, alice_epub, tag = rspns[0], rspns[1:34], rspns[34:]
        if bytes([hver]) != hs.handshake_version:
            raise HandshakeFailed("unexpected handshake version: {}".format(hver))
        # act 2
        hs.update(alice_epub)
        ss = get_ecdh(epriv, alice_epub)
        ck, temp_k2 = get_bolt8_hkdf(hs.ck, ss)
        hs.ck = ck
        p = aead_decrypt(temp_k2, 0, hs.h, tag)
        hs.update(tag)
        # act 3
        my_pubkey = privkey_to_pubkey(self.privkey)
        c = aead_encrypt(temp_k2, 1, hs.h, my_pubkey)
        hs.update(c)
        ss = get_ecdh(self.privkey[:32], alice_epub)
        ck, temp_k3 = get_bolt8_hkdf(hs.ck, ss)
        hs.ck = ck
        t = aead_encrypt(temp_k3, 0, hs.h, b'')
        self.sk, self.rk = get_bolt8_hkdf(hs.ck, b'')
        msg = hs.handshake_version + c + t
        self.writer.write(msg)
        # init counters
        self._sn = 0
        self._rn = 0
        self.r_ck = ck
        self.s_ck = ck

    def rn(self):
        o = self._rn, self.rk
        self._rn += 1
        if self._rn == 1000:
            self.r_ck, self.rk = get_bolt8_hkdf(self.r_ck, self.rk)
            self._rn = 0
        return o

    def sn(self):
        o = self._sn
        self._sn += 1
        if self._sn == 1000:
            self.s_ck, self.sk = get_bolt8_hkdf(self.s_ck, self.sk)
            self._sn = 0
        return o

    def process_message(self, message):
        message_type, payload = decode_msg(message)
        #self.print_error("Received '%s'" % message_type.upper())
        try:
            f = getattr(self, 'on_' + message_type)
        except AttributeError:
            self.print_error("Received '%s'" % message_type.upper(), payload)
            return
        # raw message is needed to check signature
        if message_type=='node_announcement':
            payload['raw'] = message
        f(payload)

    def on_error(self, payload):
        self.print_error("error", payload["data"].decode("ascii"))

    def on_ping(self, payload):
        l = int.from_bytes(payload['num_pong_bytes'], 'big')
        self.send_message(gen_msg('pong', byteslen=l))

    def on_accept_channel(self, payload):
        temp_chan_id = payload["temporary_channel_id"]
        if temp_chan_id not in self.channel_accepted: raise Exception("Got unknown accept_channel")
        self.channel_accepted[temp_chan_id].put_nowait(payload)

    def on_funding_signed(self, payload):
        channel_id = payload['channel_id']
        if channel_id not in self.funding_signed: raise Exception("Got unknown funding_signed")
        self.funding_signed[channel_id].put_nowait(payload)

    def on_node_announcement(self, payload):
        self.channel_db.on_node_announcement(payload)
        self.network.trigger_callback('ln_status')

    def on_init(self, payload):
        pass

    def on_channel_update(self, payload):
        self.channel_db.on_channel_update(payload)

    def on_channel_announcement(self, payload):
        self.channel_db.on_channel_announcement(payload)

    def on_announcement_signatures(self, payload):
        channel_id = payload['channel_id']
        chan = self.channels[payload['channel_id']]
        if chan.local_state.was_announced:
            h, local_node_sig, local_bitcoin_sig = self.send_announcement_signatures(chan)
        else:
            self.announcement_signatures[channel_id].put_nowait(payload)

    async def initialize(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self.handshake()
        # send init
        self.send_message(gen_msg("init", gflen=0, lflen=1, localfeatures=self.localfeatures))
        # read init
        msg = await self.read_message()
        self.process_message(msg)
        self.initialized.set_result(True)

    @aiosafe
    async def main_loop(self):
        await asyncio.wait_for(self.initialize(), 5)
        self.channel_db.add_recent_peer(self.peer_addr)
        # loop
        while True:
            self.ping_if_required()
            msg = await self.read_message()
            await self.process_message(msg)

    def close_and_cleanup(self):
        try:
            self.writer.close()
        except:
            pass
        for chan in self.channels.values():
            chan.set_state('DISCONNECTED')
            self.network.trigger_callback('channel', chan)

    @aiosafe
    async def channel_establishment_flow(self, wallet, config, password, funding_sat, push_msat, temp_channel_id, sweep_address):
        await self.initialized
        # see lnd/keychain/derivation.go
        keyfamilymultisig = 0
        keyfamilyrevocationbase = 1
        keyfamilyhtlcbase = 2
        keyfamilypaymentbase = 3
        keyfamilydelaybase = 4
        keyfamilyrevocationroot = 5
        keyfamilynodekey = 6 # TODO currently unused
        # amounts
        local_feerate = self.current_feerate_per_kw()
        # key derivation
        keypair_generator = lambda family, i: Keypair(*wallet.keystore.get_keypair([family, i], password))
        local_config=ChannelConfig(
            payment_basepoint=keypair_generator(keyfamilypaymentbase, 0),
            multisig_key=keypair_generator(keyfamilymultisig, 0),
            htlc_basepoint=keypair_generator(keyfamilyhtlcbase, 0),
            delayed_basepoint=keypair_generator(keyfamilydelaybase, 0),
            revocation_basepoint=keypair_generator(keyfamilyrevocationbase, 0),
            to_self_delay=143,
            dust_limit_sat=546,
            max_htlc_value_in_flight_msat=0xffffffffffffffff,
            max_accepted_htlcs=5,
            initial_msat=funding_sat * 1000 - push_msat,
        )
        # TODO derive this?
        per_commitment_secret_seed = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100.to_bytes(32, 'big')
        per_commitment_secret_index = RevocationStore.START_INDEX
        # for the first commitment transaction
        per_commitment_secret_first = get_per_commitment_secret_from_seed(per_commitment_secret_seed, per_commitment_secret_index)
        per_commitment_point_first = secret_to_pubkey(int.from_bytes(per_commitment_secret_first, 'big'))
        msg = gen_msg(
            "open_channel",
            temporary_channel_id=temp_channel_id,
            chain_hash=constants.net.rev_genesis_bytes(),
            funding_satoshis=funding_sat,
            push_msat=push_msat,
            dust_limit_satoshis=local_config.dust_limit_sat,
            feerate_per_kw=local_feerate,
            max_accepted_htlcs=local_config.max_accepted_htlcs,
            funding_pubkey=local_config.multisig_key.pubkey,
            revocation_basepoint=local_config.revocation_basepoint.pubkey,
            htlc_basepoint=local_config.htlc_basepoint.pubkey,
            payment_basepoint=local_config.payment_basepoint.pubkey,
            delayed_payment_basepoint=local_config.delayed_basepoint.pubkey,
            first_per_commitment_point=per_commitment_point_first,
            to_self_delay=local_config.to_self_delay,
            max_htlc_value_in_flight_msat=local_config.max_htlc_value_in_flight_msat,
            channel_flags=0x01, # publicly announcing channel
            channel_reserve_satoshis=546
        )
        self.send_message(msg)
        payload = await self.channel_accepted[temp_channel_id].get()
        remote_per_commitment_point = payload['first_per_commitment_point']
        remote_config=ChannelConfig(
            payment_basepoint=OnlyPubkeyKeypair(payload['payment_basepoint']),
            multisig_key=OnlyPubkeyKeypair(payload["funding_pubkey"]),
            htlc_basepoint=OnlyPubkeyKeypair(payload['htlc_basepoint']),
            delayed_basepoint=OnlyPubkeyKeypair(payload['delayed_payment_basepoint']),
            revocation_basepoint=OnlyPubkeyKeypair(payload['revocation_basepoint']),
            to_self_delay=int.from_bytes(payload['to_self_delay'], byteorder='big'),
            dust_limit_sat=int.from_bytes(payload['dust_limit_satoshis'], byteorder='big'),
            max_htlc_value_in_flight_msat=int.from_bytes(payload['max_htlc_value_in_flight_msat'], 'big'),
            max_accepted_htlcs=int.from_bytes(payload["max_accepted_htlcs"], 'big'),
            initial_msat=push_msat
        )
        funding_txn_minimum_depth = int.from_bytes(payload['minimum_depth'], 'big')
        assert remote_config.dust_limit_sat < 600
        assert int.from_bytes(payload['htlc_minimum_msat'], 'big') < 600 * 1000
        assert remote_config.max_htlc_value_in_flight_msat >= 198 * 1000 * 1000, remote_config.max_htlc_value_in_flight_msat
        self.print_error('remote delay', remote_config.to_self_delay)
        self.print_error('funding_txn_minimum_depth', funding_txn_minimum_depth)
        # create funding tx
        redeem_script = funding_output_script(local_config, remote_config)
        funding_address = bitcoin.redeem_script_to_address('p2wsh', redeem_script)
        funding_output = TxOutput(bitcoin.TYPE_ADDRESS, funding_address, funding_sat)
        funding_tx = wallet.mktx([funding_output], password, config, 1000)
        funding_txid = funding_tx.txid()
        funding_index = funding_tx.outputs().index(funding_output)
        # compute amounts
        local_amount = funding_sat*1000 - push_msat
        remote_amount = push_msat
        # remote commitment transaction
        channel_id, funding_txid_bytes = channel_id_from_funding_tx(funding_txid, funding_index)
        their_revocation_store = RevocationStore()
        chan = {
                "node_id": self.pubkey,
                "channel_id": channel_id,
                "short_channel_id": None,
                "funding_outpoint": Outpoint(funding_txid, funding_index),
                "local_config": local_config,
                "remote_config": remote_config,
                "remote_state": RemoteState(
                    ctn = -1,
                    next_per_commitment_point=remote_per_commitment_point,
                    current_per_commitment_point=None,
                    amount_msat=remote_amount,
                    revocation_store=their_revocation_store,
                    next_htlc_id = 0,
                    feerate=local_feerate
                ),
                "local_state": LocalState(
                    ctn = -1,
                    per_commitment_secret_seed=per_commitment_secret_seed,
                    amount_msat=local_amount,
                    next_htlc_id = 0,
                    funding_locked_received = False,
                    was_announced = False,
                    current_commitment_signature = None,
                    current_htlc_signatures = None,
                    feerate=local_feerate
                ),
                "constraints": ChannelConstraints(capacity=funding_sat, is_initiator=True, funding_txn_minimum_depth=funding_txn_minimum_depth),
                "remote_commitment_to_be_revoked": None,
        }
        m = HTLCStateMachine(chan)
        m.lnwatcher = self.lnwatcher
        m.sweep_address = sweep_address
        sig_64, _ = m.sign_next_commitment()
        self.send_message(gen_msg("funding_created",
            temporary_channel_id=temp_channel_id,
            funding_txid=funding_txid_bytes,
            funding_output_index=funding_index,
            signature=sig_64))
        payload = await self.funding_signed[channel_id].get()
        self.print_error('received funding_signed')
        remote_sig = payload['signature']
        m.receive_new_commitment(remote_sig, [])
        # broadcast funding tx
        success, _txid = await self.network.broadcast_transaction(funding_tx)
        assert success, success
        m.remote_commitment_to_be_revoked = m.pending_remote_commitment
        m.remote_state = m.remote_state._replace(ctn=0)
        m.local_state = m.local_state._replace(ctn=0, current_commitment_signature=remote_sig)
        m.set_state('OPENING')
        return m

    @aiosafe
    async def reestablish_channel(self, chan):
        await self.initialized
        chan_id = chan.channel_id
        if chan.get_state() != 'DISCONNECTED':
            self.print_error('reestablish_channel was called but channel {} already in state {}'
                             .format(chan_id, chan.get_state()))
            return
        chan.set_state('REESTABLISHING')
        self.network.trigger_callback('channel', chan)
        self.send_message(gen_msg("channel_reestablish",
            channel_id=chan_id,
            next_local_commitment_number=chan.local_state.ctn+1,
            next_remote_revocation_number=chan.remote_state.ctn
        ))
        await self.channel_reestablished[chan_id]
        chan.set_state('OPENING')
        if chan.local_state.funding_locked_received and chan.short_channel_id:
            self.mark_open(chan)
        self.network.trigger_callback('channel', chan)

    def on_channel_reestablish(self, payload):
        chan_id = payload["channel_id"]
        self.print_error("Received channel_reestablish", bh2u(chan_id))
        chan = self.channels.get(chan_id)
        if not chan:
            print("Warning: received unknown channel_reestablish", bh2u(chan_id))
            return
        channel_reestablish_msg = payload
        remote_ctn = int.from_bytes(channel_reestablish_msg["next_local_commitment_number"], 'big')
        if remote_ctn != chan.remote_state.ctn + 1:
            raise Exception("expected remote ctn {}, got {}".format(chan.remote_state.ctn + 1, remote_ctn))
        local_ctn = int.from_bytes(channel_reestablish_msg["next_remote_revocation_number"], 'big')
        if local_ctn != chan.local_state.ctn:
            raise Exception("expected local ctn {}, got {}".format(chan.local_state.ctn, local_ctn))
        try:
            their = channel_reestablish_msg["my_current_per_commitment_point"]
        except KeyError: # no data_protect option
            self.channel_reestablished[chan_id].set_result(True)
            return
        our = chan.remote_state.current_per_commitment_point
        if our is None:
            our = chan.remote_state.next_per_commitment_point
        if our != their:
            raise Exception("Remote PCP mismatch: {} {}".format(bh2u(our), bh2u(their)))
        self.channel_reestablished[chan_id].set_result(True)

    def funding_locked(self, chan):
        channel_id = chan.channel_id
        per_commitment_secret_index = RevocationStore.START_INDEX - 1
        per_commitment_point_second = secret_to_pubkey(int.from_bytes(
            get_per_commitment_secret_from_seed(chan.local_state.per_commitment_secret_seed, per_commitment_secret_index), 'big'))
        self.send_message(gen_msg("funding_locked", channel_id=channel_id, next_per_commitment_point=per_commitment_point_second))
        if chan.local_state.funding_locked_received:
            self.mark_open(chan)

    def on_funding_locked(self, payload):
        channel_id = payload['channel_id']
        chan = self.channels.get(channel_id)
        if not chan:
            print(self.channels)
            raise Exception("Got unknown funding_locked", channel_id)
        if not chan.local_state.funding_locked_received:
            our_next_point = chan.remote_state.next_per_commitment_point
            their_next_point = payload["next_per_commitment_point"]
            new_remote_state = chan.remote_state._replace(next_per_commitment_point=their_next_point, current_per_commitment_point=our_next_point)
            new_local_state = chan.local_state._replace(funding_locked_received = True)
            chan.remote_state=new_remote_state
            chan.local_state=new_local_state
            self.lnworker.save_channel(chan)
        if chan.short_channel_id:
            self.mark_open(chan)

    def on_network_update(self, chan, funding_tx_depth):
        """
        Only called when the channel is OPEN.

        Runs on the Network thread.
        """
        if not chan.local_state.was_announced and funding_tx_depth >= 6:
            chan.local_state=chan.local_state._replace(was_announced=True)
            coro = self.handle_announcements(chan)
            self.lnworker.save_channel(chan)
            asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    @aiosafe
    async def handle_announcements(self, chan):
        h, local_node_sig, local_bitcoin_sig = self.send_announcement_signatures(chan)
        announcement_signatures_msg = await self.announcement_signatures[chan.channel_id].get()
        remote_node_sig = announcement_signatures_msg["node_signature"]
        remote_bitcoin_sig = announcement_signatures_msg["bitcoin_signature"]
        if not ecc.verify_signature(chan.remote_config.multisig_key.pubkey, remote_bitcoin_sig, h):
            raise Exception("bitcoin_sig invalid in announcement_signatures")
        if not ecc.verify_signature(self.pubkey, remote_node_sig, h):
            raise Exception("node_sig invalid in announcement_signatures")

        node_sigs = [local_node_sig, remote_node_sig]
        bitcoin_sigs = [local_bitcoin_sig, remote_bitcoin_sig]
        node_ids = [privkey_to_pubkey(self.privkey), self.pubkey]
        bitcoin_keys = [chan.local_config.multisig_key.pubkey, chan.remote_config.multisig_key.pubkey]

        if node_ids[0] > node_ids[1]:
            node_sigs.reverse()
            bitcoin_sigs.reverse()
            node_ids.reverse()
            bitcoin_keys.reverse()

        channel_announcement = gen_msg("channel_announcement",
            node_signatures_1=node_sigs[0],
            node_signatures_2=node_sigs[1],
            bitcoin_signature_1=bitcoin_sigs[0],
            bitcoin_signature_2=bitcoin_sigs[1],
            len=0,
            #features not set (defaults to zeros)
            chain_hash=constants.net.rev_genesis_bytes(),
            short_channel_id=chan.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1]
        )

        self.send_message(channel_announcement)

        print("SENT CHANNEL ANNOUNCEMENT")

    def mark_open(self, chan):
        if chan.get_state() == "OPEN":
            return
        # NOTE: even closed channels will be temporarily marked "OPEN"
        assert chan.local_state.funding_locked_received
        chan.set_state("OPEN")
        self.network.trigger_callback('channel', chan)
        # add channel to database
        node_ids = [self.pubkey, self.lnworker.pubkey]
        bitcoin_keys = [chan.local_config.multisig_key.pubkey, chan.remote_config.multisig_key.pubkey]
        sorted_node_ids = list(sorted(node_ids))
        if sorted_node_ids != node_ids:
            node_ids = sorted_node_ids
            bitcoin_keys.reverse()
        now = int(time.time()).to_bytes(4, byteorder="big")
        self.channel_db.on_channel_announcement({"short_channel_id": chan.short_channel_id, "node_id_1": node_ids[0], "node_id_2": node_ids[1],
                                                 'chain_hash': constants.net.rev_genesis_bytes(), 'len': b'\x00\x00', 'features': b'',
                                                 'bitcoin_key_1': bitcoin_keys[0], 'bitcoin_key_2': bitcoin_keys[1]},
                                                trusted=True)
        self.channel_db.on_channel_update({"short_channel_id": chan.short_channel_id, 'flags': b'\x01', 'cltv_expiry_delta': b'\x90',
                                           'htlc_minimum_msat': b'\x03\xe8', 'fee_base_msat': b'\x03\xe8', 'fee_proportional_millionths': b'\x01',
                                           'chain_hash': constants.net.rev_genesis_bytes(), 'timestamp': now},
                                          trusted=True)
        self.channel_db.on_channel_update({"short_channel_id": chan.short_channel_id, 'flags': b'\x00', 'cltv_expiry_delta': b'\x90',
                                           'htlc_minimum_msat': b'\x03\xe8', 'fee_base_msat': b'\x03\xe8', 'fee_proportional_millionths': b'\x01',
                                           'chain_hash': constants.net.rev_genesis_bytes(), 'timestamp': now},
                                          trusted=True)

        self.print_error("CHANNEL OPENING COMPLETED")

    def send_announcement_signatures(self, chan):

        bitcoin_keys = [chan.local_config.multisig_key.pubkey,
                        chan.remote_config.multisig_key.pubkey]

        node_ids = [privkey_to_pubkey(self.privkey),
                    self.pubkey]

        sorted_node_ids = list(sorted(node_ids))
        if sorted_node_ids != node_ids:
            node_ids = sorted_node_ids
            bitcoin_keys.reverse()

        chan_ann = gen_msg("channel_announcement",
            len=0,
            #features not set (defaults to zeros)
            chain_hash=constants.net.rev_genesis_bytes(),
            short_channel_id=chan.short_channel_id,
            node_id_1=node_ids[0],
            node_id_2=node_ids[1],
            bitcoin_key_1=bitcoin_keys[0],
            bitcoin_key_2=bitcoin_keys[1]
        )
        to_hash = chan_ann[256+2:]
        h = bitcoin.Hash(to_hash)
        bitcoin_signature = ecc.ECPrivkey(chan.local_config.multisig_key.privkey).sign(h, sigencode_string_canonize, sigdecode_string)
        node_signature = ecc.ECPrivkey(self.privkey).sign(h, sigencode_string_canonize, sigdecode_string)
        self.send_message(gen_msg("announcement_signatures",
            channel_id=chan.channel_id,
            short_channel_id=chan.short_channel_id,
            node_signature=node_signature,
            bitcoin_signature=bitcoin_signature
        ))

        return h, node_signature, bitcoin_signature

    def on_update_fail_htlc(self, payload):
        channel_id = payload["channel_id"]
        htlc_id = int.from_bytes(payload["id"], "big")
        key = (channel_id, htlc_id)
        route = self.attempted_route[key]
        failure_msg, sender_idx = decode_onion_error(payload["reason"], [x.node_id for x in route], self.secret_key)
        code = failure_msg.code
        code_name = ONION_FAILURE_CODE_MAP.get(code, 'unknown_error!!')
        data = failure_msg.data
        print("UPDATE_FAIL_HTLC", code_name, code, data)
        try:
            short_chan_id = route[sender_idx + 1].short_channel_id
        except IndexError:
            print("payment destination reported error")
        else:
            # TODO this should depend on the error
            # also, we need finer blacklisting (directed edges; nodes)
            self.network.path_finder.blacklist.add(short_chan_id)

        self.update_fail_htlc[payload["channel_id"]].put_nowait("HTLC failure with code {} ({})".format(code, code_name))

    @aiosafe
    async def pay(self, path, chan, amount_msat, payment_hash, pubkey_in_invoice, min_final_cltv_expiry):
        # FIXME aiosafe is breaking "raise PaymentFailure"
        assert chan.get_state() == "OPEN", chan.get_state()
        assert amount_msat > 0, "amount_msat is not greater zero"

        height = self.network.get_local_height()
        route = self.network.path_finder.create_route_from_path(path, self.lnworker.pubkey)
        hops_data = []
        sum_of_deltas = sum(route_edge.channel_policy.cltv_expiry_delta for route_edge in route[1:])
        total_fee = 0
        final_cltv_expiry_without_deltas = (height + min_final_cltv_expiry)
        final_cltv_expiry_with_deltas = final_cltv_expiry_without_deltas + sum_of_deltas
        for idx, route_edge in enumerate(route[1:]):
            hops_data += [OnionHopsDataSingle(OnionPerHop(route_edge.short_channel_id, amount_msat.to_bytes(8, "big"), final_cltv_expiry_without_deltas.to_bytes(4, "big")))]
            total_fee += route_edge.channel_policy.fee_base_msat + ( amount_msat * route_edge.channel_policy.fee_proportional_millionths // 1000000 )
        associated_data = payment_hash
        self.secret_key = os.urandom(32)
        hops_data += [OnionHopsDataSingle(OnionPerHop(b"\x00"*8, amount_msat.to_bytes(8, "big"), (final_cltv_expiry_without_deltas).to_bytes(4, "big")))]
        onion = new_onion_packet([x.node_id for x in route], self.secret_key, hops_data, associated_data)
        amount_msat += total_fee
        # FIXME this below will probably break with multiple HTLCs
        msat_local = chan.balance(LOCAL) - amount_msat
        msat_remote = chan.balance(REMOTE) + amount_msat
        htlc = {'amount_msat':amount_msat, 'payment_hash':payment_hash, 'cltv_expiry':final_cltv_expiry_with_deltas}

        # FIXME if we raise here, this channel will not get blacklisted, and the payment can never succeed,
        # as we will just keep retrying this same path. using the current blacklisting is not a solution as
        # then no other payment can use this channel either.
        # we need finer blacklisting -- e.g. a blacklist for just this "payment session"?
        # or blacklist entries could store an msat value and also expire
        if len(chan.htlcs_in_local) + 1 > chan.remote_config.max_accepted_htlcs:
            raise PaymentFailure('too many HTLCs already in channel')
        if chan.htlcsum(chan.htlcs_in_local) + amount_msat > chan.remote_config.max_htlc_value_in_flight_msat:
            raise PaymentFailure('HTLC value sum would exceed max allowed: {} msat'.format(chan.remote_config.max_htlc_value_in_flight_msat))
        if msat_local < 0:
            # FIXME what about channel_reserve_satoshis? will the remote fail the channel if we go below? test.
            raise PaymentFailure('not enough local balance')

        htlc_id = chan.add_htlc(htlc)
        self.send_message(gen_msg("update_add_htlc", channel_id=chan.channel_id, id=htlc_id, cltv_expiry=final_cltv_expiry_with_deltas, amount_msat=amount_msat, payment_hash=payment_hash, onion_routing_packet=onion.to_bytes()))

        self.attempted_route[(chan.channel_id, htlc_id)] = route

        sig_64, htlc_sigs = chan.sign_next_commitment()
        self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=len(htlc_sigs), htlc_signature=b"".join(htlc_sigs)))
        await self.receive_revoke(chan)
        await self.receive_commitment(chan)
        self.revoke(chan)

        fulfill_coro = asyncio.ensure_future(self.update_fulfill_htlc[chan.channel_id].get())
        failure_coro = asyncio.ensure_future(self.update_fail_htlc[chan.channel_id].get())

        done, pending = await asyncio.wait([fulfill_coro, failure_coro], return_when=FIRST_COMPLETED)
        # TODO what if HTLC gets stuck in multihop payment (A->B->C->D->E; on the way back C goes offline)
        payment_succeeded = False
        if failure_coro.done():
            fulfill_coro.cancel()
            sig_64, htlc_sigs = chan.sign_next_commitment()
            self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=len(htlc_sigs), htlc_signature=b"".join(htlc_sigs)))
            await self.receive_revoke(chan)
            chan.fail_htlc(htlc)
            await self.receive_commitment(chan)
            self.revoke(chan)
            sig_64, htlc_sigs = chan.sign_next_commitment()
            res = failure_coro.result()
        else:
            failure_coro.cancel()
            update_fulfill_htlc_msg = fulfill_coro.result()
            preimage = update_fulfill_htlc_msg["payment_preimage"]
            chan.receive_htlc_settle(preimage, int.from_bytes(update_fulfill_htlc_msg["id"], "big"))
            await self.receive_commitment(chan)
            self.revoke(chan)
            # FIXME why is this not using the HTLC state machine?
            bare_ctx = chan.make_commitment(chan.remote_state.ctn + 1, False, chan.remote_state.next_per_commitment_point,
                msat_remote, msat_local)
            self.lnwatcher.process_new_offchain_ctx(chan, bare_ctx, ours=False)
            sig_64 = sign_and_get_sig_string(bare_ctx, chan.local_config, chan.remote_config)
            res = bh2u(preimage)
            payment_succeeded = True

        self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=0))
        await self.receive_revoke(chan)
        self.lnworker.save_channel(chan)

        if payment_succeeded:
            return res
        else:
            raise PaymentFailure(res)

    async def receive_revoke(self, m):
        revoke_and_ack_msg = await self.revoke_and_ack[m.channel_id].get()
        m.receive_revocation(RevokeAndAck(revoke_and_ack_msg["per_commitment_secret"], revoke_and_ack_msg["next_per_commitment_point"]))

    def revoke(self, m):
        rev, _ = m.revoke_current_commitment()
        self.send_message(gen_msg("revoke_and_ack",
            channel_id=m.channel_id,
            per_commitment_secret=rev.per_commitment_secret,
            next_per_commitment_point=rev.next_per_commitment_point))

    async def receive_commitment(self, m, commitment_signed_msg=None):
        if commitment_signed_msg is None:
            commitment_signed_msg = await self.commitment_signed[m.channel_id].get()
        data = commitment_signed_msg["htlc_signature"]
        htlc_sigs = [data[i:i+64] for i in range(0, len(data), 64)]
        m.receive_new_commitment(commitment_signed_msg["signature"], htlc_sigs)
        return len(htlc_sigs)

    @aiosafe
    async def receive_commitment_revoke_ack(self, htlc, decoded, payment_preimage):
        chan = self.channels[htlc['channel_id']]
        channel_id = chan.channel_id
        expected_received_msat = int(decoded.amount * bitcoin.COIN * 1000)
        htlc_id = int.from_bytes(htlc["id"], 'big')
        assert htlc_id == chan.remote_state.next_htlc_id, (htlc_id, chan.remote_state.next_htlc_id)

        assert chan.get_state() == "OPEN"

        cltv_expiry = int.from_bytes(htlc["cltv_expiry"], 'big')
        # TODO verify sanity of their cltv expiry
        amount_msat = int.from_bytes(htlc["amount_msat"], 'big')
        assert amount_msat == expected_received_msat
        payment_hash = htlc["payment_hash"]

        htlc = {'amount_msat': amount_msat, 'payment_hash':payment_hash, 'cltv_expiry':cltv_expiry}

        chan.receive_htlc(htlc)

        assert (await self.receive_commitment(chan)) <= 1

        self.revoke(chan)

        sig_64, htlc_sigs = chan.sign_next_commitment()
        htlc_sig = b''.join(htlc_sigs)
        self.send_message(gen_msg("commitment_signed", channel_id=channel_id, signature=sig_64, num_htlcs=len(htlc_sigs), htlc_signature=htlc_sig))

        await self.receive_revoke(chan)

        self.send_message(gen_msg("update_fulfill_htlc", channel_id=channel_id, id=htlc_id, payment_preimage=payment_preimage))

        # remote commitment transaction without htlcs
        # FIXME why is this not using the HTLC state machine?
        bare_ctx = chan.make_commitment(chan.remote_state.ctn + 1, False, chan.remote_state.next_per_commitment_point,
            chan.balance(REMOTE) - expected_received_msat, chan.balance(LOCAL) + expected_received_msat)
        self.lnwatcher.process_new_offchain_ctx(chan, bare_ctx, ours=False)
        sig_64 = sign_and_get_sig_string(bare_ctx, chan.local_config, chan.remote_config)
        self.send_message(gen_msg("commitment_signed", channel_id=channel_id, signature=sig_64, num_htlcs=0))

        revoke_coro = asyncio.ensure_future(self.revoke_and_ack[chan.channel_id].get())
        commit_coro = asyncio.ensure_future(self.commitment_signed[chan.channel_id].get())
        _done, _pending = await asyncio.wait([revoke_coro, commit_coro], return_when=FIRST_COMPLETED)

        def process_revoke(revoke_and_ack_msg):
            chan.receive_revocation(RevokeAndAck(revoke_and_ack_msg["per_commitment_secret"], revoke_and_ack_msg["next_per_commitment_point"]))

        if commit_coro.done():
            # this branch is taken with lnd after a fee update (initiated by us, of course)
            await self.receive_commitment(chan, commit_coro.result())
            chan.settle_htlc(payment_preimage, htlc_id)
            await revoke_coro
            process_revoke(revoke_coro.result())
            self.revoke(chan)
            await self.receive_commitment(chan)
            self.revoke(chan)
            sig_64, htlc_sigs = chan.sign_next_commitment()

            self.send_message(gen_msg("commitment_signed", channel_id=chan.channel_id, signature=sig_64, num_htlcs=len(htlc_sigs), htlc_signature=b"".join(htlc_sigs)))
            await self.receive_revoke(chan)
        elif revoke_coro.done():
            chan.settle_htlc(payment_preimage, htlc_id)
            process_revoke(revoke_coro.result())

            await commit_coro
            await self.receive_commitment(chan, commit_coro.result())
            self.revoke(chan)

        self.lnworker.save_channel(chan)

    def on_commitment_signed(self, payload):
        self.print_error("commitment_signed", payload)
        channel_id = payload['channel_id']
        chan = self.channels[channel_id]
        chan.local_state=chan.local_state._replace(
            current_commitment_signature=payload['signature'],
            current_htlc_signatures=payload['htlc_signature'])
        self.lnworker.save_channel(chan)
        self.commitment_signed[channel_id].put_nowait(payload)

    def on_update_fulfill_htlc(self, payload):
        self.print_error("update_fulfill")
        channel_id = payload["channel_id"]
        self.update_fulfill_htlc[channel_id].put_nowait(payload)

    def on_update_fail_malformed_htlc(self, payload):
        self.on_error(payload)

    def on_update_add_htlc(self, payload):
        # no onion routing for the moment: we assume we are the end node
        self.print_error('on_update_add_htlc', payload)
        # check if this in our list of requests
        payment_hash = payload["payment_hash"]
        for k in self.invoices.keys():
            preimage = bfh(k)
            if sha256(preimage) == payment_hash:
                req = self.invoices[k]
                decoded = lndecode(req, expected_hrp=constants.net.SEGWIT_HRP)
                coro = self.receive_commitment_revoke_ack(payload, decoded, preimage)
                asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
                break
        else:
            assert False

    def on_revoke_and_ack(self, payload):
        print("got revoke_and_ack")
        channel_id = payload["channel_id"]
        self.revoke_and_ack[channel_id].put_nowait(payload)

    def on_update_fee(self, payload):
        channel_id = payload["channel_id"]
        self.channels[channel_id].receive_update_fee(int.from_bytes(payload["feerate_per_kw"], "big"))

    def on_bitcoin_fee_update(self, chan):
        """
        called when our fee estimates change
        """
        if not chan.constraints.is_initiator:
            # TODO force close if initiator does not update_fee enough
            return

        feerate_per_kw = self.current_feerate_per_kw()
        self.print_error("current feerate", chan.remote_state.feerate)
        self.print_error("new feerate", feerate_per_kw)
        if feerate_per_kw < chan.remote_state.feerate / 2:
            self.print_error("FEES HAVE FALLEN")
            chan.update_fee(feerate_per_kw)
        elif feerate_per_kw > chan.remote_state.feerate * 2:
            self.print_error("FEES HAVE RISEN")
            chan.update_fee(feerate_per_kw)
        else:
            return

        self.send_message(gen_msg("update_fee", channel_id=chan.channel_id, feerate_per_kw=feerate_per_kw))
        self.lnworker.save_channel(chan)

    def current_feerate_per_kw(self):
        from .simple_config import FEE_LN_ETA_TARGET, FEERATE_FALLBACK_STATIC_FEE
        feerate_per_kvbyte = self.network.config.eta_target_to_fee(FEE_LN_ETA_TARGET)
        if feerate_per_kvbyte is None:
            feerate_per_kvbyte = FEERATE_FALLBACK_STATIC_FEE
        return max(253, feerate_per_kvbyte // 4)

    def on_closing_signed(self, payload):
        chan_id = payload["channel_id"]
        if chan_id not in self.closing_signed: raise Exception("Got unknown closing_signed")
        self.closing_signed[chan_id].put_nowait(payload)

    async def on_shutdown(self, payload):
        coro = self.shutdown_coroutine(payload)
        asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)

    async def shutdown_coroutine(self, payload):
        # length of scripts allowed in BOLT-02
        if int.from_bytes(payload['len'], 'big') not in (3+20+2, 2+20+1, 2+20, 2+32):
            raise Exception('scriptpubkey length in received shutdown message invalid: ' + str(payload['len']))
        chan = self.channels[payload['channel_id']]
        scriptpubkey = bfh(bitcoin.address_to_script(chan.sweep_address))
        self.send_message(gen_msg('shutdown', channel_id=chan.channel_id, len=len(scriptpubkey), scriptpubkey=scriptpubkey))
        signature, fee = chan.make_closing_tx(scriptpubkey, payload['scriptpubkey'])
        self.send_message(gen_msg('closing_signed', channel_id=chan.channel_id, fee_satoshis=fee, signature=signature))
        while chan.get_state() != 'CLOSED':
            try:
                closing_signed = await asyncio.wait_for(self.closing_signed[chan.channel_id].get(), 1)
            except asyncio.TimeoutError:
                pass
            else:
                fee = closing_signed['fee_satoshis']
                signature, _ = chan.make_closing_tx(scriptpubkey, payload['scriptpubkey'], fee_sat=fee)
                self.send_message(gen_msg('closing_signed', channel_id=chan.channel_id, fee_satoshis=fee, signature=signature))
        self.print_error('REMOTE PEER CLOSED CHANNEL')
