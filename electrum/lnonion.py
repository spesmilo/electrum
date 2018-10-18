# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import hashlib
from typing import Sequence, List, Tuple, NamedTuple
from enum import IntEnum, IntFlag

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

from . import ecc
from .crypto import sha256, hmac_oneshot
from .util import bh2u, profiler, xor_bytes, bfh
from .lnutil import get_ecdh
from .lnrouter import RouteEdge


NUM_MAX_HOPS_IN_PATH = 20
HOPS_DATA_SIZE = 1300      # also sometimes called routingInfoSize in bolt-04
PER_HOP_FULL_SIZE = 65     # HOPS_DATA_SIZE / 20
NUM_STREAM_BYTES = HOPS_DATA_SIZE + PER_HOP_FULL_SIZE
PER_HOP_HMAC_SIZE = 32


class UnsupportedOnionPacketVersion(Exception): pass
class InvalidOnionMac(Exception): pass


class OnionPerHop:

    def __init__(self, short_channel_id: bytes, amt_to_forward: bytes, outgoing_cltv_value: bytes):
        self.short_channel_id = short_channel_id
        self.amt_to_forward = amt_to_forward
        self.outgoing_cltv_value = outgoing_cltv_value

    def to_bytes(self) -> bytes:
        ret = self.short_channel_id
        ret += self.amt_to_forward
        ret += self.outgoing_cltv_value
        ret += bytes(12)  # padding
        if len(ret) != 32:
            raise Exception('unexpected length {}'.format(len(ret)))
        return ret

    @classmethod
    def from_bytes(cls, b: bytes):
        if len(b) != 32:
            raise Exception('unexpected length {}'.format(len(b)))
        return OnionPerHop(
            short_channel_id=b[:8],
            amt_to_forward=b[8:16],
            outgoing_cltv_value=b[16:20]
        )


class OnionHopsDataSingle:  # called HopData in lnd

    def __init__(self, per_hop: OnionPerHop = None):
        self.realm = 0
        self.per_hop = per_hop
        self.hmac = None

    def to_bytes(self) -> bytes:
        ret = bytes([self.realm])
        ret += self.per_hop.to_bytes()
        ret += self.hmac if self.hmac is not None else bytes(PER_HOP_HMAC_SIZE)
        if len(ret) != PER_HOP_FULL_SIZE:
            raise Exception('unexpected length {}'.format(len(ret)))
        return ret

    @classmethod
    def from_bytes(cls, b: bytes):
        if len(b) != PER_HOP_FULL_SIZE:
            raise Exception('unexpected length {}'.format(len(b)))
        ret = OnionHopsDataSingle()
        ret.realm = b[0]
        if ret.realm != 0:
            raise Exception('only realm 0 is supported')
        ret.per_hop = OnionPerHop.from_bytes(b[1:33])
        ret.hmac = b[33:]
        return ret


class OnionPacket:

    def __init__(self, public_key: bytes, hops_data: bytes, hmac: bytes):
        self.version = 0
        self.public_key = public_key
        self.hops_data = hops_data  # also called RoutingInfo in bolt-04
        self.hmac = hmac

    def to_bytes(self) -> bytes:
        ret = bytes([self.version])
        ret += self.public_key
        ret += self.hops_data
        ret += self.hmac
        if len(ret) != 1366:
            raise Exception('unexpected length {}'.format(len(ret)))
        return ret

    @classmethod
    def from_bytes(cls, b: bytes):
        if len(b) != 1366:
            raise Exception('unexpected length {}'.format(len(b)))
        version = b[0]
        if version != 0:
            raise UnsupportedOnionPacketVersion('version {} is not supported'.format(version))
        return OnionPacket(
            public_key=b[1:34],
            hops_data=b[34:1334],
            hmac=b[1334:]
        )


def get_bolt04_onion_key(key_type: bytes, secret: bytes) -> bytes:
    if key_type not in (b'rho', b'mu', b'um', b'ammag'):
        raise Exception('invalid key_type {}'.format(key_type))
    key = hmac_oneshot(key_type, msg=secret, digest=hashlib.sha256)
    return key


def get_shared_secrets_along_route(payment_path_pubkeys: Sequence[bytes],
                                   session_key: bytes) -> Sequence[bytes]:
    num_hops = len(payment_path_pubkeys)
    hop_shared_secrets = num_hops * [b'']
    ephemeral_key = session_key
    # compute shared key for each hop
    for i in range(0, num_hops):
        hop_shared_secrets[i] = get_ecdh(ephemeral_key, payment_path_pubkeys[i])
        ephemeral_pubkey = ecc.ECPrivkey(ephemeral_key).get_public_key_bytes()
        blinding_factor = sha256(ephemeral_pubkey + hop_shared_secrets[i])
        blinding_factor_int = int.from_bytes(blinding_factor, byteorder="big")
        ephemeral_key_int = int.from_bytes(ephemeral_key, byteorder="big")
        ephemeral_key_int = ephemeral_key_int * blinding_factor_int % ecc.CURVE_ORDER
        ephemeral_key = ephemeral_key_int.to_bytes(32, byteorder="big")
    return hop_shared_secrets


def new_onion_packet(payment_path_pubkeys: Sequence[bytes], session_key: bytes,
                     hops_data: Sequence[OnionHopsDataSingle], associated_data: bytes) -> OnionPacket:
    num_hops = len(payment_path_pubkeys)
    hop_shared_secrets = get_shared_secrets_along_route(payment_path_pubkeys, session_key)

    filler = generate_filler(b'rho', num_hops, PER_HOP_FULL_SIZE, hop_shared_secrets)
    mix_header = bytes(HOPS_DATA_SIZE)
    next_hmac = bytes(PER_HOP_HMAC_SIZE)

    # compute routing info and MAC for each hop
    for i in range(num_hops-1, -1, -1):
        rho_key = get_bolt04_onion_key(b'rho', hop_shared_secrets[i])
        mu_key = get_bolt04_onion_key(b'mu', hop_shared_secrets[i])
        hops_data[i].hmac = next_hmac
        stream_bytes = generate_cipher_stream(rho_key, NUM_STREAM_BYTES)
        mix_header = mix_header[:-PER_HOP_FULL_SIZE]
        mix_header = hops_data[i].to_bytes() + mix_header
        mix_header = xor_bytes(mix_header, stream_bytes)
        if i == num_hops - 1 and len(filler) != 0:
            mix_header = mix_header[:-len(filler)] + filler
        packet = mix_header + associated_data
        next_hmac = hmac_oneshot(mu_key, msg=packet, digest=hashlib.sha256)

    return OnionPacket(
        public_key=ecc.ECPrivkey(session_key).get_public_key_bytes(),
        hops_data=mix_header,
        hmac=next_hmac)


def calc_hops_data_for_payment(route: List[RouteEdge], amount_msat: int, final_cltv: int) \
        -> Tuple[List[OnionHopsDataSingle], int, int]:
    """Returns the hops_data to be used for constructing an onion packet,
    and the amount_msat and cltv to be used on our immediate channel.
    """
    amt = amount_msat
    cltv = final_cltv
    hops_data = [OnionHopsDataSingle(OnionPerHop(b"\x00" * 8,
                                                 amt.to_bytes(8, "big"),
                                                 cltv.to_bytes(4, "big")))]
    for route_edge in reversed(route[1:]):
        hops_data += [OnionHopsDataSingle(OnionPerHop(route_edge.short_channel_id,
                                                      amt.to_bytes(8, "big"),
                                                      cltv.to_bytes(4, "big")))]
        amt += route_edge.fee_for_edge(amt)
        cltv += route_edge.cltv_expiry_delta
    hops_data.reverse()
    return hops_data, amt, cltv


def generate_filler(key_type: bytes, num_hops: int, hop_size: int,
                    shared_secrets: Sequence[bytes]) -> bytes:
    filler_size = (NUM_MAX_HOPS_IN_PATH + 1) * hop_size
    filler = bytearray(filler_size)

    for i in range(0, num_hops-1):  # -1, as last hop does not obfuscate
        filler = filler[hop_size:]
        filler += bytearray(hop_size)
        stream_key = get_bolt04_onion_key(key_type, shared_secrets[i])
        stream_bytes = generate_cipher_stream(stream_key, filler_size)
        filler = xor_bytes(filler, stream_bytes)

    return filler[(NUM_MAX_HOPS_IN_PATH-num_hops+2)*hop_size:]


def generate_cipher_stream(stream_key: bytes, num_bytes: int) -> bytes:
    algo = algorithms.ChaCha20(stream_key, nonce=bytes(16))
    cipher = Cipher(algo, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(bytes(num_bytes))


ProcessedOnionPacket = NamedTuple("ProcessedOnionPacket", [("are_we_final", bool),
                                                           ("hop_data", OnionHopsDataSingle),
                                                           ("next_packet", OnionPacket)])


# TODO replay protection
def process_onion_packet(onion_packet: OnionPacket, associated_data: bytes,
                         our_onion_private_key: bytes) -> ProcessedOnionPacket:
    shared_secret = get_ecdh(our_onion_private_key, onion_packet.public_key)

    # check message integrity
    mu_key = get_bolt04_onion_key(b'mu', shared_secret)
    calculated_mac = hmac_oneshot(mu_key, msg=onion_packet.hops_data+associated_data,
                                  digest=hashlib.sha256)
    if onion_packet.hmac != calculated_mac:
        raise InvalidOnionMac()

    # peel an onion layer off
    rho_key = get_bolt04_onion_key(b'rho', shared_secret)
    stream_bytes = generate_cipher_stream(rho_key, NUM_STREAM_BYTES)
    padded_header = onion_packet.hops_data + bytes(PER_HOP_FULL_SIZE)
    next_hops_data = xor_bytes(padded_header, stream_bytes)

    # calc next ephemeral key
    blinding_factor = sha256(onion_packet.public_key + shared_secret)
    blinding_factor_int = int.from_bytes(blinding_factor, byteorder="big")
    next_public_key_int = ecc.ECPubkey(onion_packet.public_key) * blinding_factor_int
    next_public_key = next_public_key_int.get_public_key_bytes()

    hop_data = OnionHopsDataSingle.from_bytes(next_hops_data[:PER_HOP_FULL_SIZE])
    next_onion_packet = OnionPacket(
        public_key=next_public_key,
        hops_data=next_hops_data[PER_HOP_FULL_SIZE:],
        hmac=hop_data.hmac
    )
    if hop_data.hmac == bytes(PER_HOP_HMAC_SIZE):
        # we are the destination / exit node
        are_we_final = True
    else:
        # we are an intermediate node; forwarding
        are_we_final = False
    return ProcessedOnionPacket(are_we_final, hop_data, next_onion_packet)


class FailedToDecodeOnionError(Exception): pass


class OnionRoutingFailureMessage:

    def __init__(self, code: int, data: bytes):
        self.code = code
        self.data = data

    def __repr__(self):
        return repr((self.code, self.data))

    def to_bytes(self) -> bytes:
        ret = self.code.to_bytes(2, byteorder="big")
        ret += self.data
        return ret


def construct_onion_error(reason: OnionRoutingFailureMessage,
                          onion_packet: OnionPacket,
                          our_onion_private_key: bytes) -> bytes:
    # create payload
    failure_msg = reason.to_bytes()
    failure_len = len(failure_msg)
    pad_len = 256 - failure_len
    assert pad_len >= 0
    error_packet =  failure_len.to_bytes(2, byteorder="big")
    error_packet += failure_msg
    error_packet += pad_len.to_bytes(2, byteorder="big")
    error_packet += bytes(pad_len)
    # add hmac
    shared_secret = get_ecdh(our_onion_private_key, onion_packet.public_key)
    um_key = get_bolt04_onion_key(b'um', shared_secret)
    hmac_ = hmac_oneshot(um_key, msg=error_packet, digest=hashlib.sha256)
    error_packet = hmac_ + error_packet
    # obfuscate
    ammag_key = get_bolt04_onion_key(b'ammag', shared_secret)
    stream_bytes = generate_cipher_stream(ammag_key, len(error_packet))
    error_packet = xor_bytes(error_packet, stream_bytes)
    return error_packet


def _decode_onion_error(error_packet: bytes, payment_path_pubkeys: Sequence[bytes],
                        session_key: bytes) -> (bytes, int):
    """Returns the decoded error bytes, and the index of the sender of the error."""
    num_hops = len(payment_path_pubkeys)
    hop_shared_secrets = get_shared_secrets_along_route(payment_path_pubkeys, session_key)
    for i in range(num_hops):
        ammag_key = get_bolt04_onion_key(b'ammag', hop_shared_secrets[i])
        um_key = get_bolt04_onion_key(b'um', hop_shared_secrets[i])
        stream_bytes = generate_cipher_stream(ammag_key, len(error_packet))
        error_packet = xor_bytes(error_packet, stream_bytes)
        hmac_computed = hmac_oneshot(um_key, msg=error_packet[32:], digest=hashlib.sha256)
        hmac_found = error_packet[:32]
        if hmac_computed == hmac_found:
            return error_packet, i
    raise FailedToDecodeOnionError()


def decode_onion_error(error_packet: bytes, payment_path_pubkeys: Sequence[bytes],
                       session_key: bytes) -> (OnionRoutingFailureMessage, int):
    """Returns the failure message, and the index of the sender of the error."""
    decrypted_error, sender_index = _decode_onion_error(error_packet, payment_path_pubkeys, session_key)
    failure_msg = get_failure_msg_from_onion_error(decrypted_error)
    return failure_msg, sender_index


def get_failure_msg_from_onion_error(decrypted_error_packet: bytes) -> OnionRoutingFailureMessage:
    # get failure_msg bytes from error packet
    failure_len = int.from_bytes(decrypted_error_packet[32:34], byteorder='big')
    failure_msg = decrypted_error_packet[34:34+failure_len]
    # create failure message object
    failure_code = int.from_bytes(failure_msg[:2], byteorder='big')
    failure_code = OnionFailureCode(failure_code)
    failure_data = failure_msg[2:]
    return OnionRoutingFailureMessage(failure_code, failure_data)


class OnionFailureCodeMetaFlag(IntFlag):
    BADONION = 0x8000
    PERM     = 0x4000
    NODE     = 0x2000
    UPDATE   = 0x1000

BADONION = OnionFailureCodeMetaFlag.BADONION
PERM     = OnionFailureCodeMetaFlag.PERM
NODE     = OnionFailureCodeMetaFlag.NODE
UPDATE   = OnionFailureCodeMetaFlag.UPDATE
class OnionFailureCode(IntEnum):
    INVALID_REALM =                           PERM | 1
    TEMPORARY_NODE_FAILURE =                  NODE | 2
    PERMANENT_NODE_FAILURE =                  PERM | NODE | 2
    REQUIRED_NODE_FEATURE_MISSING =           PERM | NODE | 3
    INVALID_ONION_VERSION =                   BADONION | PERM | 4
    INVALID_ONION_HMAC =                      BADONION | PERM | 5
    INVALID_ONION_KEY =                       BADONION | PERM | 6
    TEMPORARY_CHANNEL_FAILURE =               UPDATE | 7
    PERMANENT_CHANNEL_FAILURE =               PERM | 8
    REQUIRED_CHANNEL_FEATURE_MISSING =        PERM | 9
    UNKNOWN_NEXT_PEER =                       PERM | 10
    AMOUNT_BELOW_MINIMUM =                    UPDATE | 11
    FEE_INSUFFICIENT =                        UPDATE | 12
    INCORRECT_CLTV_EXPIRY =                   UPDATE | 13
    EXPIRY_TOO_SOON =                         UPDATE | 14
    UNKNOWN_PAYMENT_HASH =                    PERM | 15
    INCORRECT_PAYMENT_AMOUNT =                PERM | 16
    FINAL_EXPIRY_TOO_SOON =                   17
    FINAL_INCORRECT_CLTV_EXPIRY =             18
    FINAL_INCORRECT_HTLC_AMOUNT =             19
    CHANNEL_DISABLED =                        UPDATE | 20
    EXPIRY_TOO_FAR =                          21

    @classmethod
    def _missing_(cls, value: int) -> int:
        # note that for unknown error codes, we return an int,
        # not an instance of cls
        return value


# don't use these elsewhere, the names are ambiguous without context
del BADONION; del PERM; del NODE; del UPDATE
