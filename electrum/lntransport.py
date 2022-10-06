# Copyright (C) 2018 Adam Gibson (waxwing)
# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

# Derived from https://gist.github.com/AdamISZ/046d05c156aaeb56cc897f85eecb3eb8

import re
import hashlib
import asyncio
from asyncio import Queue
from typing import Optional


from functools import cached_property, partial
from typing import NamedTuple, List, Tuple, Mapping, Optional, TYPE_CHECKING, Union, Dict, Set, Sequence

from aiorpcx import NetAddress
from aiorpcx.util import NetAddress
from aiorpcx.session import SessionKind, SessionBase
from aiorpcx.framing import FramerBase
from aiorpcx.rawsocket import RSTransport, ConnectionLostError

import electrum_ecc as ecc

from .crypto import sha256, hmac_oneshot, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from .crypto import get_ecdh, privkey_to_pubkey

from .util import MySocksProxy, log_exceptions
from .logging import Logger



class QueueFramer(FramerBase):

    def __init__(self):
        self.queue = Queue()

    def frame(self, message):
        raise NotImplementedError

    def received_message(self, msg):
        self.queue.put_nowait(msg)

    async def receive_message(self):
        msg = await self.queue.get()
        return msg

    def fail(self, exception):
        self.exception = exception


class LNSession(SessionBase):
    pass


class LightningPeerConnectionClosed(Exception): pass
class HandshakeFailed(Exception): pass
class ConnStringFormatError(Exception): pass

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

def aead_encrypt(key: bytes, nonce: int, associated_data: bytes, data: bytes) -> bytes:
    nonce_bytes = get_nonce_bytes(nonce)
    return chacha20_poly1305_encrypt(key=key,
                                     nonce=nonce_bytes,
                                     associated_data=associated_data,
                                     data=data)

def aead_decrypt(key: bytes, nonce: int, associated_data: bytes, data: bytes) -> bytes:
    nonce_bytes = get_nonce_bytes(nonce)
    return chacha20_poly1305_decrypt(key=key,
                                     nonce=nonce_bytes,
                                     associated_data=associated_data,
                                     data=data)

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


def split_host_port(host_port: str) -> Tuple[str, str]: # port returned as string
    ipv6  = re.compile(r'\[(?P<host>[:0-9a-f]+)\](?P<port>:\d+)?$')
    other = re.compile(r'(?P<host>[^:]+)(?P<port>:\d+)?$')
    m = ipv6.match(host_port)
    if not m:
        m = other.match(host_port)
    if not m:
        raise ConnStringFormatError('Connection strings must be in <node_pubkey>@<host>:<port> format')
    host = m.group('host')
    if m.group('port'):
        port = m.group('port')[1:]
    else:
        port = '9735'
    try:
        int(port)
    except ValueError:
        raise ConnStringFormatError('Port number must be decimal')
    return host, port

def extract_nodeid(connect_contents: str) -> Tuple[bytes, Optional[str]]:
    """Takes a connection-string-like str, and returns a tuple (node_id, rest),
    where rest is typically a host (with maybe port). Examples:
    - extract_nodeid(pubkey@host:port) == (pubkey, host:port)
    - extract_nodeid(pubkey@host) == (pubkey, host)
    - extract_nodeid(pubkey) == (pubkey, None)
    Can raise ConnStringFormatError.
    """
    rest = None
    try:
        # connection string?
        nodeid_hex, rest = connect_contents.split("@", 1)
    except ValueError:
        # node id as hex?
        nodeid_hex = connect_contents
    if rest == '':
        raise ConnStringFormatError('At least a hostname must be supplied after the at symbol.')
    try:
        node_id = bytes.fromhex(nodeid_hex)
        if len(node_id) != 33:
            raise Exception()
    except Exception:
        raise ConnStringFormatError('Invalid node ID, must be 33 bytes and hexadecimal')
    return node_id, rest

class LNPeerAddr:
    # note: while not programmatically enforced, this class is meant to be *immutable*

    def __init__(self, host: str, port: int, pubkey: bytes):
        assert isinstance(host, str), repr(host)
        assert isinstance(port, int), repr(port)
        assert isinstance(pubkey, bytes), repr(pubkey)
        try:
            net_addr = NetAddress(host, port)  # this validates host and port
        except Exception as e:
            raise ValueError(f"cannot construct LNPeerAddr: invalid host or port (host={host}, port={port})") from e
        # note: not validating pubkey as it would be too expensive:
        # if not ECPubkey.is_pubkey_bytes(pubkey): raise ValueError()
        self.host = host
        self.port = port
        self.pubkey = pubkey
        self._net_addr = net_addr

    def __str__(self):
        return '{}@{}'.format(self.pubkey.hex(), self.net_addr_str())

    @classmethod
    def from_str(cls, s):
        node_id, rest = extract_nodeid(s)
        host, port = split_host_port(rest)
        return LNPeerAddr(host, int(port), node_id)

    def __repr__(self):
        return f'<LNPeerAddr host={self.host} port={self.port} pubkey={self.pubkey.hex()}>'

    def net_addr(self) -> NetAddress:
        return self._net_addr

    def net_addr_str(self) -> str:
        return str(self._net_addr)

    def __eq__(self, other):
        if not isinstance(other, LNPeerAddr):
            return False
        return (self.host == other.host
                and self.port == other.port
                and self.pubkey == other.pubkey)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.host, self.port, self.pubkey))

class LNTransportBase:
    reader: StreamReader
    writer: StreamWriter
    privkey: bytes
    peer_addr: Optional[LNPeerAddr] = None


class LNTransport(RSTransport, Logger):

    _privkey: bytes
    _remote_pubkey: bytes

    def __init__(self, session_factory, privkey, peer_addr=None):
        framer = QueueFramer()
        kind = SessionKind.SERVER if peer_addr is None else SessionKind.CLIENT
        self.peer_addr = peer_addr # todo: remove this, pass only pubkey
        self._remote_pubkey = peer_addr.pubkey if peer_addr else None

        Logger.__init__(self)
        RSTransport.__init__(self, session_factory, framer, kind)
        assert type(privkey) is bytes and len(privkey) == 32
        self._privkey = privkey
        self._data = bytearray()
        self._data_received = asyncio.Event()
        self.handshake_done = asyncio.Event()

    def is_listener(self):
        return self.kind == SessionKind.SERVER

    @log_exceptions
    async def read_data(self, len):
        await self._data_received.wait()
        chunk = self._data[0:len]
        self._data = self._data[len:]
        if not self._data:
            self._data_received.clear()
        return chunk

    async def write(self, message) -> None:
        self.send_bytes(message)

    def send_bytes(self, msg: bytes) -> None:
        l = len(msg).to_bytes(2, 'big')
        lc = aead_encrypt(self.sk, self.sn(), b'', l)
        c = aead_encrypt(self.sk, self.sn(), b'', msg)
        assert len(lc) == 18
        assert len(c) == len(msg) + 16
        self._asyncio_transport.write(lc+c)

    @log_exceptions
    async def decrypt_messages(self):
        if self.is_listener():
            await self.listener_handshake()
        else:
            await self.handshake()
        while True:
            rn_l, rk_l = self.rn()
            rn_m, rk_m = self.rn()
            while True:
                if len(self._data) >= 18:
                    lc = bytes(self._data[:18])
                    l = aead_decrypt(rk_l, rn_l, b'', lc)
                    length = int.from_bytes(l, 'big')
                    offset = 18 + length + 16
                    if len(self._data) >= offset:
                        c = bytes(self._data[18:offset])
                        del self._data[:offset]  # much faster than: buffer=buffer[offset:]
                        msg = aead_decrypt(rk_m, rn_m, b'', c)
                        self._framer.received_message(msg)
                        break
                await self._data_received.wait()
                self._data_received.clear()

    async def read_messages(self):
        while True:
            msg = await self.receive_message()
            yield msg

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
        self._sn = 0
        self._rn = 0
        self.r_ck = ck
        self.s_ck = ck

    async def listener_handshake(self, **kwargs):
        hs = HandshakeState(privkey_to_pubkey(self._privkey))
        act1 = b''
        while len(act1) < 50:
            buf = await self.read_data(50 - len(act1))
            if not buf:
                raise HandshakeFailed('responder disconnected')
            act1 += buf
        if len(act1) != 50:
            raise HandshakeFailed('responder: short act 1 read, length is ' + str(len(act1)))
        if bytes([act1[0]]) != HandshakeState.handshake_version:
            raise HandshakeFailed('responder: bad handshake version in act 1')
        c = act1[-16:]
        re = act1[1:34]
        h = hs.update(re)
        ss = get_ecdh(self._privkey, re)
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
        self._asyncio_transport.write(msg)
        # act 3
        act3 = b''
        while len(act3) < 66:
            buf = await self.read_data(66 - len(act3))
            if not buf:
                raise HandshakeFailed('responder disconnected')
            act3 += buf
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
        self._remote_pubkey = rs
        self.handshake_done.set()
        return rs

    def connection_made(self, transport):
        RSTransport.connection_made(self, transport)
        self._decrypt_messages_task = self.loop.create_task(self.decrypt_messages())

    def connection_lost(self, exc):
        RSTransport.connection_lost(self, exc)
        self._process_messages_task.cancel() # fixme: this should be done in parent class
        self._decrypt_messages_task.cancel()

    def data_received(self, chunk):
        self._data += chunk
        self._data_received.set()
        self.session.data_received(chunk)

    async def handshake(self):
        assert self._remote_pubkey is not None
        hs = HandshakeState(self._remote_pubkey)
        # Get a new ephemeral key
        epriv, epub = create_ephemeral_key()
        msg, _temp_k1 = act1_initiator_message(hs, epriv, epub)
        # act 1
        self._asyncio_transport.write(msg)
        rspns = await self.read_data(2**10)
        if len(rspns) != 50:
            raise HandshakeFailed(f"Lightning handshake act 1 response has bad length, "
                                  f"are you sure this is the right pubkey? {self._remote_pubkey.hex()}")
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
        my_pubkey = privkey_to_pubkey(self._privkey)
        c = aead_encrypt(temp_k2, 1, hs.h, my_pubkey)
        hs.update(c)
        ss = get_ecdh(self._privkey[:32], alice_epub)
        ck, temp_k3 = get_bolt8_hkdf(hs.ck, ss)
        hs.ck = ck
        t = aead_encrypt(temp_k3, 0, hs.h, b'')
        msg = hs.handshake_version + c + t
        self._asyncio_transport.write(msg)
        self.sk, self.rk = get_bolt8_hkdf(hs.ck, b'')
        self.init_counters(ck)
        self.handshake_done.set()

    @cached_property
    def _id_hash(self) -> str:
        id_int = id(self)
        id_bytes = id_int.to_bytes((id_int.bit_length() + 7) // 8, byteorder='big')
        return sha256(id_bytes).hex()

    def name(self) -> str:
        pubkey = self.remote_pubkey()
        if pubkey:
            pubkey_hex = pubkey.hex() if pubkey else pubkey
            return f"{pubkey_hex[:10]}-{self._id_hash[:8]}"
        else:
            return ''

    def remote_pubkey(self) -> Optional[bytes]:
        return self._remote_pubkey



class LNClient:

    def __init__(self, privkey, session_factory, peer_addr, proxy=None, loop=None):
        assert type(privkey) is bytes and len(privkey) == 32
        self.privkey = privkey
        self.peer_addr = peer_addr
        self.proxy = MySocksProxy.from_proxy_dict(proxy) if proxy else None
        self.loop = loop or asyncio.get_running_loop()
        self.session_factory = session_factory
        self.protocol_factory = partial(LNTransport, self.session_factory, self.privkey, peer_addr=self.peer_addr)

    @log_exceptions
    async def create_connection(self):
        connector = self.proxy or self.loop
        return await connector.create_connection(self.protocol_factory, self.peer_addr.host, self.peer_addr.port)

    async def __aenter__(self):
        _transport, protocol = await self.create_connection()
        self.session = protocol.session
        assert isinstance(self.session, SessionBase)
        await protocol.handshake_done.wait()
        return self.session

    async def __aexit__(self, exc_type, exc_value, traceback):                                                                                                                                                            await self.session.close()



async def create_bolt8_server(privkey, session_factory, host=None, port=None, *, loop=None, **kwargs):
    loop = loop or asyncio.get_event_loop()
    protocol_factory = partial(LNTransport, session_factory, privkey)
    return await loop.create_server(protocol_factory, host, port)
