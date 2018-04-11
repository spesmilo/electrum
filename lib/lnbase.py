#!/usr/bin/env python3
"""
  Lightning network interface for Electrum
  Derived from https://gist.github.com/AdamISZ/046d05c156aaeb56cc897f85eecb3eb8
"""

import json
from collections import OrderedDict
import asyncio
import sys
import os
import binascii
import hashlib
import hmac
import cryptography.hazmat.primitives.ciphers.aead as AEAD

from electrum.bitcoin import public_key_from_private_key, ser_to_point, point_to_ser, string_to_number
from electrum.bitcoin import int_to_hex, bfh, rev_hex
from electrum.util import PrintError

tcp_socket_timeout = 10
server_response_timeout = 60

###############################

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
        print("msg type", k)
        ma = {}
        pos = 0
        for fieldname in v["payload"]:
            poslenMap = v["payload"][fieldname]
            #print(poslenMap["position"], ma)
            assert pos == calcexp(poslenMap["position"], ma)
            length = poslenMap["length"]
            length = calcexp(length, ma)
            ma[fieldname] = data[pos:pos+length]
            pos += length
        assert pos == len(data), (k, pos, len(data))
        return ma
    return handler

path = os.path.join(os.path.dirname(__file__), 'lightning.json')
with open(path) as f:
    structured = json.loads(f.read(), object_pairs_hook=OrderedDict)

for k in structured:
    v = structured[k]
    if k in ["open_channel","final_incorrect_cltv_expiry", "final_incorrect_htlc_amount"]:
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
    parsed = message_types[typ](data[2:])
    return parsed

def gen_msg(msg_type, **kwargs):
    typ = structured[msg_type]
    data = int(typ["type"]).to_bytes(byteorder="big", length=2)
    lengths = {}
    for k in typ["payload"]:
        poslenMap = typ["payload"][k]
        leng = calcexp(poslenMap["length"], lengths)
        try:
            leng = kwargs[poslenMap["length"]]
        except:
            pass
        try:
            param = kwargs[k]
        except KeyError:
            param = 0
        try:
            param = param.to_bytes(length=leng, byteorder="big")
        except:
            raise Exception("{} does not fit in {} bytes".format(k, leng))
        lengths[k] = len(param)
        data += param
    return data

###############################


def decode(string):
    """Return the integer value of the
    bytestring b
    """
    if isinstance(string, str):
        string = bytes(bytearray.fromhex(string))
    result = 0
    while len(string) > 0:
        result *= 256
        result += string[0]
        string = string[1:]
    return result


def encode(n, s):
    """Return a bytestring version of the integer
    value n, with a string length of s
    """
    return bfh(rev_hex(int_to_hex(n, s)))


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

def process_message(message):
    print("Received %d bytes: "%len(message), binascii.hexlify(message))



class Peer(PrintError):

    def __init__(self, privkey, host, port, pubkey):
        self.host = host
        self.port = port
        self.privkey = privkey
        self.pubkey = pubkey
        self.read_buffer = b''

    def send_message(self, msg):
        print("Sending %d bytes: "%len(msg), binascii.hexlify(msg))
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
            length = decode(l)
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

    async def main_loop(self, loop):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port, loop=loop)
        await self.handshake()
        # read init
        msg = await self.read_message()
        process_message(msg)
        # send init
        init_msg = gen_msg("init", gflen=0, lflen=0)
        self.send_message(init_msg)
        # send ping
        ping_msg = gen_msg("ping", num_pong_bytes=4, byteslen=4)
        self.send_message(ping_msg)
        # read pong
        msg = await self.read_message()
        process_message(msg)
        # close socket
        self.writer.close()
    
    def run(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.main_loop(loop))
        loop.close()


node_list = [
    ('ecdsa.net', '9735', '038370f0e7a03eded3e1d41dc081084a87f0afa1c5b22090b4f3abb391eb15d8ff'),
    ('77.58.162.148', '9735', '022bb78ab9df617aeaaf37f6644609abb7295fad0c20327bccd41f8d69173ccb49')
    ]


if __name__ == "__main__":
    if len(sys.argv) > 1:
        host, port, pubkey = sys.argv[1:4]
    else:
        host, port, pubkey = node_list[0]
    pubkey = binascii.unhexlify(pubkey)
    port = int(port)
    privkey = b"\x21"*32 + b"\x01"
    peer = Peer(privkey, host, port, pubkey)
    peer.run()
