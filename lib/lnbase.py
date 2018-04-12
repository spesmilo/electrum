#!/usr/bin/env python3
"""
  Lightning network interface for Electrum
  Derived from https://gist.github.com/AdamISZ/046d05c156aaeb56cc897f85eecb3eb8
"""

import itertools
import json
from collections import OrderedDict
import asyncio
import sys
import os
import time
import binascii
import hashlib
import hmac
import cryptography.hazmat.primitives.ciphers.aead as AEAD

from .bitcoin import public_key_from_private_key, ser_to_point, point_to_ser, string_to_number, deserialize_privkey, EC_KEY, rev_hex
from . import bitcoin
from .constants import set_testnet, set_simnet
from . import constants
from .util import PrintError
from .wallet import Wallet
from .storage import WalletStorage

tcp_socket_timeout = 10
server_response_timeout = 60

class LightningError(Exception):
    pass

message_types = {}

def handlesingle(x, ma):
    try:
        x = int(x)
    except ValueError:
        x = ma[x]
    try:
        x = int(x)
    except ValueError:
        x = int.from_bytes(x, byteorder="big")
    return x

def calcexp(exp, ma):
    exp = str(exp)
    assert "*" not in exp
    return sum(handlesingle(x, ma) for x in exp.split("+"))

def make_handler(k, v):
    def handler(data):
        nonlocal k, v
        ma = {}
        pos = 0
        for fieldname in v["payload"]:
            poslenMap = v["payload"][fieldname]
            if "feature" in poslenMap: continue
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
    if k in ["final_incorrect_cltv_expiry", "final_incorrect_htlc_amount"]:
        continue
    if len(v["payload"]) == 0:
        continue
    try:
        num = int(v["type"])
    except ValueError:
        #print("skipping", k)
        continue
    byts = num.to_bytes(byteorder="big",length=2)
    assert byts not in message_types, (byts, message_types[byts].__name__, k)
    names = [x.__name__ for x in message_types.values()]
    assert k + "_handler" not in names, (k, names)
    message_types[byts] = make_handler(k, v)
    message_types[byts].__name__ = k + "_handler"

assert message_types[b"\x00\x10"].__name__ == "init_handler"

def decode_msg(data):
    typ = data[:2]
    k, parsed = message_types[typ](data[2:])
    return k, parsed

def gen_msg(msg_type, **kwargs):
    typ = structured[msg_type]
    data = int(typ["type"]).to_bytes(byteorder="big", length=2)
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
            if not isinstance(param, bytes): param = param.to_bytes(length=leng, byteorder="big")
        except ValueError:
            raise Exception("{} does not fit in {} bytes".format(k, leng))
        lengths[k] = len(param)
        data += param
    return data

def encode(n, s):
    """Return a bytestring version of the integer
    value n, with a string length of s
    """
    return n.to_bytes(length=s, byteorder="big")


def H256(data):
    return hashlib.sha256(data).digest()

class HandshakeState(object):
    prologue = b"lightning"
    protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256"
    handshake_version = b"\x00"
    def __init__(self, responder_pub):
        self.responder_pub = responder_pub
        self.h = H256(self.protocol_name)
        self.ck = self.h
        self.update(self.prologue)
        self.update(self.responder_pub)

    def update(self, data):
        self.h = H256(self.h + data)
        return self.h
        
def get_nonce_bytes(n):
    """BOLT 8 requires the nonce to be 12 bytes, 4 bytes leading
    zeroes and 8 bytes little endian encoded 64 bit integer.
    """
    nb = b"\x00"*4
    #Encode the integer as an 8 byte byte-string
    nb2 = encode(n, 8)
    nb2 = bytearray(nb2)
    #Little-endian is required here
    nb2.reverse()
    return nb + nb2

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

def get_ecdh(priv, pub):
    s = string_to_number(priv)
    pk = ser_to_point(pub)
    pt = point_to_ser(pk * s)
    return H256(pt)

def act1_initiator_message(hs, my_privkey):
    #Get a new ephemeral key
    epriv, epub = create_ephemeral_key(my_privkey)
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

def privkey_to_pubkey(priv):
    pub = public_key_from_private_key(priv[:32], True)
    return bytes.fromhex(pub)
    
def create_ephemeral_key(privkey):
    pub = privkey_to_pubkey(privkey)
    return (privkey[:32], pub)

def get_unused_public_keys():
    xprv, xpub = bitcoin.bip32_root(b"testseed", "p2wpkh")
    for i in itertools.count():
        childxpub = bitcoin.bip32_public_derivation(xpub, "m/", "m/42/"+str(i))
        _, _, _, _, child_c, child_cK = bitcoin.deserialize_xpub(childxpub)
        yield child_cK

class Peer(PrintError):

    def __init__(self, privkey, host, port, pubkey):
        self.host = host
        self.port = port
        self.privkey = privkey
        self.pubkey = pubkey
        self.read_buffer = b''
        self.ping_time = 0
        self.temporary_channel_id_to_incoming_accept_channel = {}
        self.init_message_received_future = asyncio.Future()

    def diagnostic_name(self):
        return self.host

    def ping_if_required(self):
        if time.time() - self.ping_time > 120:
            self.send_message(gen_msg('ping', num_pong_bytes=4, byteslen=4))
            self.ping_time = time.time()

    def send_message(self, msg):
        message_type, payload = decode_msg(msg)
        self.print_error("Sending '%s'"%message_type.upper(), payload)
        l = encode(len(msg), 2)
        lc = aead_encrypt(self.sk, self.sn, b'', l)
        c = aead_encrypt(self.sk, self.sn+1, b'', msg)
        assert len(lc) == 18
        assert len(c) == len(msg) + 16
        self.writer.write(lc+c)
        self.sn += 2

    async def read_message(self):
        while True:
            self.read_buffer += await self.reader.read(2**10)
            lc = self.read_buffer[:18]
            l = aead_decrypt(self.rk, self.rn, b'', lc)
            length = int.from_bytes(l, byteorder="big")
            offset = 18 + length + 16
            if len(self.read_buffer) < offset:
                continue
            c = self.read_buffer[18:offset]
            self.read_buffer = self.read_buffer[offset:]
            msg = aead_decrypt(self.rk, self.rn+1, b'', c)
            self.rn += 2
            return msg

    async def handshake(self):
        hs = HandshakeState(self.pubkey)
        msg = act1_initiator_message(hs, self.privkey)
        # act 1
        self.writer.write(msg)
        rspns = await self.reader.read(2**10)
        assert len(rspns) == 50
        hver, alice_epub, tag = rspns[0], rspns[1:34], rspns[34:]
        assert bytes([hver]) == hs.handshake_version
        # act 2
        hs.update(alice_epub)
        myepriv, myepub = create_ephemeral_key(self.privkey)
        ss = get_ecdh(myepriv, alice_epub)
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
        self.sn = 0
        self.rn = 0

    def process_message(self, message):
        message_type, payload = decode_msg(message)
        self.print_error("Received '%s'" % message_type.upper(), payload)
        try:
            f = getattr(self, 'on_' + message_type)
        except AttributeError:
            return
        f(payload)

    def on_error(self, payload):
        self.temporary_channel_id_to_incoming_accept_channel[payload["channel_id"]].set_exception(LightningError(payload["data"]))

    def on_ping(self, payload):
        l = int.from_bytes(payload['num_pong_bytes'], byteorder="big")
        self.send_message(gen_msg('pong', byteslen=l))

    def on_accept_channel(self, payload):
        self.temporary_channel_id_to_incoming_accept_channel[payload["temporary_channel_id"]].set_result(payload)

    def on_funding_signed(self, payload):
        sig = payload['signature']
        channel_id = payload['channel_id']
        tx = self.channels[channel_id]
        self.network.broadcast(tx)

    def on_funding_locked(self, payload):
        pass

    #def open_channel(self, funding_sat, push_msat):
    #    self.send_message(gen_msg('open_channel', funding_satoshis=funding_sat, push_msat=push_msat))

    async def main_loop(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self.handshake()
        # send init
        self.send_message(gen_msg("init", gflen=0, lflen=0))
        # read init
        msg = await self.read_message()
        self.process_message(msg)
        # initialized
        self.init_message_received_future.set_result(msg)
        # loop
        while True:
            self.ping_if_required()
            msg = await self.read_message()
            self.process_message(msg)
        # close socket
        self.print_error('closing lnbase')
        self.writer.close()

    async def channel_establishment_flow(self, wallet):
        await self.init_message_received_future
        pubkeys = get_unused_public_keys()
        temp_channel_id = os.urandom(32)
        msg = gen_msg("open_channel", temporary_channel_id=temp_channel_id, chain_hash=bytes.fromhex(rev_hex(constants.net.GENESIS)), funding_satoshis=20000, max_accepted_htlcs=5, funding_pubkey=next(pubkeys), revocation_basepoint=next(pubkeys), htlc_basepoint=next(pubkeys), payment_basepoint=next(pubkeys), delayed_payment_basepoint=next(pubkeys), first_per_commitment_point=next(pubkeys))
        self.temporary_channel_id_to_incoming_accept_channel[temp_channel_id] = asyncio.Future()
        self.send_message(msg)
        try:
            accept_channel = await self.temporary_channel_id_to_incoming_accept_channel[temp_channel_id]
        finally:
            del self.temporary_channel_id_to_incoming_accept_channel[temp_channel_id]

        raise Exception("TODO: create funding transaction using wallet")


# replacement for lightningCall
class LNWorker:

    def __init__(self, wallet, network):
        self.wallet = wallet
        self.network = network
        host, port, pubkey = ('ecdsa.net', '9735', '038370f0e7a03eded3e1d41dc081084a87f0afa1c5b22090b4f3abb391eb15d8ff')
        pubkey = binascii.unhexlify(pubkey)
        port = int(port)
        privkey = b"\x21"*32 + b"\x01"
        self.peer = Peer(privkey, host, port, pubkey)
        self.network.futures.append(asyncio.run_coroutine_threadsafe(self.peer.main_loop(), asyncio.get_event_loop()))

    def openchannel(self):
        # todo: get utxo from wallet
        # submit coro to asyncio main loop
        self.peer.open_channel()

    def blocking_test_run(self):
        start = time.time()
        fut = asyncio.ensure_future(self._test())
        asyncio.get_event_loop().run_until_complete(fut)
        fut.exception()
        return "blocking test run took: " + str(time.time() - start)

    async def _test(self):
        await self.peer.channel_establishment_flow(self.wallet)



node_list = [
    ('ecdsa.net', '9735', '038370f0e7a03eded3e1d41dc081084a87f0afa1c5b22090b4f3abb391eb15d8ff'),
    ('77.58.162.148', '9735', '022bb78ab9df617aeaaf37f6644609abb7295fad0c20327bccd41f8d69173ccb49')
]


if __name__ == "__main__":
    if len(sys.argv) > 2:
        host, port, pubkey = sys.argv[2:5]
    else:
        host, port, pubkey = node_list[0]
    if sys.argv[1] not in ["simnet", "testnet"]: raise Exception("first argument must be simnet or testnet")
    if sys.argv[1] == "simnet":
        set_simnet()
    else:
        set_testnet()
    pubkey = binascii.unhexlify(pubkey)
    port = int(port)
    privkey = b"\x21"*32 + b"\x01"
    peer = Peer(privkey, host, port, pubkey)
    loop.run_until_complete(peer.main_loop())
    loop.close()
