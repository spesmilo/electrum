# Copyright (C) 2018 Adam Gibson (waxwing)
# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

# Derived from https://gist.github.com/AdamISZ/046d05c156aaeb56cc897f85eecb3eb8

import hashlib
from asyncio import StreamReader, StreamWriter

import cryptography.hazmat.primitives.ciphers.aead as AEAD

from .crypto import sha256, hmac_oneshot
from .lnutil import (get_ecdh, privkey_to_pubkey, LightningPeerConnectionClosed,
                     HandshakeFailed)
from . import ecc
from .util import bh2u

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
    prk = hmac_oneshot(salt, msg=ikm, digest=hashlib.sha256)
    assert len(prk) == 32
    #Expand
    info = b""
    T0 = b""
    T1 = hmac_oneshot(prk, T0 + info + b"\x01", digest=hashlib.sha256)
    T2 = hmac_oneshot(prk, T1 + info + b"\x02", digest=hashlib.sha256)
    assert len(T1 + T2) == 64
    return T1, T2

def act1_initiator_message(hs, epriv, epub):
    ss = get_ecdh(epriv, hs.responder_pub)
    ck2, temp_k1 = get_bolt8_hkdf(hs.ck, ss)
    hs.ck = ck2
    c = aead_encrypt(temp_k1, 0, hs.update(epub), b"")
    #for next step if we do it
    hs.update(c)
    msg = hs.handshake_version + epub + c
    assert len(msg) == 50
    return msg, temp_k1


def create_ephemeral_key() -> (bytes, bytes):
    privkey = ecc.ECPrivkey.generate_random_key()
    return privkey.get_secret_bytes(), privkey.get_public_key_bytes()

class LNTransportBase:

    def __init__(self, reader: StreamReader, writer: StreamWriter):
        self.reader = reader
        self.writer = writer

    def send_bytes(self, msg):
        l = len(msg).to_bytes(2, 'big')
        lc = aead_encrypt(self.sk, self.sn(), b'', l)
        c = aead_encrypt(self.sk, self.sn(), b'', msg)
        assert len(lc) == 18
        assert len(c) == len(msg) + 16
        self.writer.write(lc+c)

    async def read_messages(self):
        read_buffer = b''
        while True:
            rn_l, rk_l = self.rn()
            rn_m, rk_m = self.rn()
            while True:
                if len(read_buffer) >= 18:
                    lc = read_buffer[:18]
                    l = aead_decrypt(rk_l, rn_l, b'', lc)
                    length = int.from_bytes(l, 'big')
                    offset = 18 + length + 16
                    if len(read_buffer) >= offset:
                        c = read_buffer[18:offset]
                        read_buffer = read_buffer[offset:]
                        msg = aead_decrypt(rk_m, rn_m, b'', c)
                        yield msg
                        break
                try:
                    s = await self.reader.read(2**10)
                except:
                    s = None
                if not s:
                    raise LightningPeerConnectionClosed()
                read_buffer += s

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

    def init_counters(self, ck):
        # init counters
        self._sn = 0
        self._rn = 0
        self.r_ck = ck
        self.s_ck = ck

    def close(self):
        self.writer.close()


class LNResponderTransport(LNTransportBase):
    def __init__(self, privkey: bytes, reader: StreamReader, writer: StreamWriter):
        LNTransportBase.__init__(self, reader, writer)
        self.privkey = privkey

    async def handshake(self, **kwargs):
        hs = HandshakeState(privkey_to_pubkey(self.privkey))

        act1 = b''
        while len(act1) < 50:
            act1 += await self.reader.read(50 - len(act1))
        if len(act1) != 50:
            raise HandshakeFailed('responder: short act 1 read, length is ' + str(len(act1)))
        if bytes([act1[0]]) != HandshakeState.handshake_version:
            raise HandshakeFailed('responder: bad handshake version in act 1')
        c = act1[-16:]
        re = act1[1:34]
        h = hs.update(re)
        ss = get_ecdh(self.privkey, re)
        ck, temp_k1 = get_bolt8_hkdf(sha256(HandshakeState.protocol_name), ss)
        _p = aead_decrypt(temp_k1, 0, h, c)
        hs.update(c)

        # act 2
        if 'epriv' not in kwargs:
            epriv, epub = create_ephemeral_key()
        else:
            epriv = kwargs['epriv']
            epub = ecc.ECPrivkey(epriv).get_public_key_bytes()
        hs.ck = ck
        hs.responder_pub = re

        msg, temp_k2 = act1_initiator_message(hs, epriv, epub)
        self.writer.write(msg)

        # act 3
        act3 = b''
        while len(act3) < 66:
            act3 += await self.reader.read(66 - len(act3))
        if len(act3) != 66:
            raise HandshakeFailed('responder: short act 3 read, length is ' + str(len(act3)))
        if bytes([act3[0]]) != HandshakeState.handshake_version:
            raise HandshakeFailed('responder: bad handshake version in act 3')
        c = act3[1:50]
        t = act3[-16:]
        rs = aead_decrypt(temp_k2, 1, hs.h, c)
        ss = get_ecdh(epriv, rs)
        ck, temp_k3 = get_bolt8_hkdf(hs.ck, ss)
        _p = aead_decrypt(temp_k3, 0, hs.update(c), t)
        self.rk, self.sk = get_bolt8_hkdf(ck, b'')
        self.init_counters(ck)
        return rs

class LNTransport(LNTransportBase):
    def __init__(self, privkey: bytes, remote_pubkey: bytes,
                 reader: StreamReader, writer: StreamWriter):
        LNTransportBase.__init__(self, reader, writer)
        assert type(privkey) is bytes and len(privkey) == 32
        self.privkey = privkey
        self.remote_pubkey = remote_pubkey

    async def handshake(self):
        hs = HandshakeState(self.remote_pubkey)
        # Get a new ephemeral key
        epriv, epub = create_ephemeral_key()

        msg, _temp_k1 = act1_initiator_message(hs, epriv, epub)
        # act 1
        self.writer.write(msg)
        rspns = await self.reader.read(2**10)
        if len(rspns) != 50:
            raise HandshakeFailed(f"Lightning handshake act 1 response has bad length, are you sure this is the right pubkey? {bh2u(self.remote_pubkey)}")
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
        msg = hs.handshake_version + c + t
        self.writer.write(msg)
        self.sk, self.rk = get_bolt8_hkdf(hs.ck, b'')
        self.init_counters(ck)
