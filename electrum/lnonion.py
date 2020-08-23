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

import io
import hashlib
from typing import Sequence, List, Tuple, NamedTuple, TYPE_CHECKING
from enum import IntEnum, IntFlag

from . import ecc
from .crypto import sha256, hmac_oneshot, chacha20_encrypt
from .util import bh2u, profiler, xor_bytes, bfh
from .lnutil import (get_ecdh, PaymentFailure, NUM_MAX_HOPS_IN_PAYMENT_PATH,
                     NUM_MAX_EDGES_IN_PAYMENT_PATH, ShortChannelID, OnionFailureCodeMetaFlag)
from .lnmsg import OnionWireSerializer, read_bigsize_int, write_bigsize_int

if TYPE_CHECKING:
    from .lnrouter import LNPaymentRoute


HOPS_DATA_SIZE = 1300      # also sometimes called routingInfoSize in bolt-04
LEGACY_PER_HOP_FULL_SIZE = 65
NUM_STREAM_BYTES = 2 * HOPS_DATA_SIZE
PER_HOP_HMAC_SIZE = 32


class UnsupportedOnionPacketVersion(Exception): pass
class InvalidOnionMac(Exception): pass
class InvalidOnionPubkey(Exception): pass


class LegacyHopDataPayload:

    def __init__(self, *, short_channel_id: bytes, amt_to_forward: int, outgoing_cltv_value: int):
        self.short_channel_id = ShortChannelID(short_channel_id)
        self.amt_to_forward = amt_to_forward
        self.outgoing_cltv_value = outgoing_cltv_value

    def to_bytes(self) -> bytes:
        ret = self.short_channel_id
        ret += int.to_bytes(self.amt_to_forward, length=8, byteorder="big", signed=False)
        ret += int.to_bytes(self.outgoing_cltv_value, length=4, byteorder="big", signed=False)
        ret += bytes(12)  # padding
        if len(ret) != 32:
            raise Exception('unexpected length {}'.format(len(ret)))
        return ret

    def to_tlv_dict(self) -> dict:
        d = {
            "amt_to_forward": {"amt_to_forward": self.amt_to_forward},
            "outgoing_cltv_value": {"outgoing_cltv_value": self.outgoing_cltv_value},
            "short_channel_id": {"short_channel_id": self.short_channel_id},
        }
        return d

    @classmethod
    def from_bytes(cls, b: bytes) -> 'LegacyHopDataPayload':
        if len(b) != 32:
            raise Exception('unexpected length {}'.format(len(b)))
        return LegacyHopDataPayload(
            short_channel_id=b[:8],
            amt_to_forward=int.from_bytes(b[8:16], byteorder="big", signed=False),
            outgoing_cltv_value=int.from_bytes(b[16:20], byteorder="big", signed=False),
        )

    @classmethod
    def from_tlv_dict(cls, d: dict) -> 'LegacyHopDataPayload':
        return LegacyHopDataPayload(
            short_channel_id=d["short_channel_id"]["short_channel_id"] if "short_channel_id" in d else b"\x00" * 8,
            amt_to_forward=d["amt_to_forward"]["amt_to_forward"],
            outgoing_cltv_value=d["outgoing_cltv_value"]["outgoing_cltv_value"],
        )


class OnionHopsDataSingle:  # called HopData in lnd

    def __init__(self, *, is_tlv_payload: bool, payload: dict = None):
        self.is_tlv_payload = is_tlv_payload
        if payload is None:
            payload = {}
        self.payload = payload
        self.hmac = None
        self._raw_bytes_payload = None  # used in unit tests

    def to_bytes(self) -> bytes:
        hmac_ = self.hmac if self.hmac is not None else bytes(PER_HOP_HMAC_SIZE)
        if self._raw_bytes_payload is not None:
            ret = write_bigsize_int(len(self._raw_bytes_payload))
            ret += self._raw_bytes_payload
            ret += hmac_
            return ret
        if not self.is_tlv_payload:
            ret = b"\x00"  # realm==0
            legacy_payload = LegacyHopDataPayload.from_tlv_dict(self.payload)
            ret += legacy_payload.to_bytes()
            ret += hmac_
            if len(ret) != LEGACY_PER_HOP_FULL_SIZE:
                raise Exception('unexpected length {}'.format(len(ret)))
            return ret
        else:  # tlv
            payload_fd = io.BytesIO()
            OnionWireSerializer.write_tlv_stream(fd=payload_fd,
                                                 tlv_stream_name="tlv_payload",
                                                 **self.payload)
            payload_bytes = payload_fd.getvalue()
            with io.BytesIO() as fd:
                fd.write(write_bigsize_int(len(payload_bytes)))
                fd.write(payload_bytes)
                fd.write(hmac_)
                return fd.getvalue()

    @classmethod
    def from_fd(cls, fd: io.BytesIO) -> 'OnionHopsDataSingle':
        first_byte = fd.read(1)
        if len(first_byte) == 0:
            raise Exception(f"unexpected EOF")
        fd.seek(-1, io.SEEK_CUR)  # undo read
        if first_byte == b'\x00':
            # legacy hop data format
            b = fd.read(LEGACY_PER_HOP_FULL_SIZE)
            if len(b) != LEGACY_PER_HOP_FULL_SIZE:
                raise Exception(f'unexpected length {len(b)}')
            ret = OnionHopsDataSingle(is_tlv_payload=False)
            legacy_payload = LegacyHopDataPayload.from_bytes(b[1:33])
            ret.payload = legacy_payload.to_tlv_dict()
            ret.hmac = b[33:]
            return ret
        elif first_byte == b'\x01':
            # reserved for future use
            raise Exception("unsupported hop payload: length==1")
        else:
            hop_payload_length = read_bigsize_int(fd)
            hop_payload = fd.read(hop_payload_length)
            if hop_payload_length != len(hop_payload):
                raise Exception(f"unexpected EOF")
            ret = OnionHopsDataSingle(is_tlv_payload=True)
            ret.payload = OnionWireSerializer.read_tlv_stream(fd=io.BytesIO(hop_payload),
                                                              tlv_stream_name="tlv_payload")
            ret.hmac = fd.read(PER_HOP_HMAC_SIZE)
            assert len(ret.hmac) == PER_HOP_HMAC_SIZE
            return ret

    def __repr__(self):
        return f"<OnionHopsDataSingle. is_tlv_payload={self.is_tlv_payload}. payload={self.payload}. hmac={self.hmac}>"


class OnionPacket:

    def __init__(self, public_key: bytes, hops_data: bytes, hmac: bytes):
        assert len(public_key) == 33
        assert len(hops_data) == HOPS_DATA_SIZE
        assert len(hmac) == PER_HOP_HMAC_SIZE
        self.version = 0
        self.public_key = public_key
        self.hops_data = hops_data  # also called RoutingInfo in bolt-04
        self.hmac = hmac
        if not ecc.ECPubkey.is_pubkey_bytes(public_key):
            raise InvalidOnionPubkey()

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
    if key_type not in (b'rho', b'mu', b'um', b'ammag', b'pad'):
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
    assert num_hops == len(hops_data)
    hop_shared_secrets = get_shared_secrets_along_route(payment_path_pubkeys, session_key)

    filler = _generate_filler(b'rho', hops_data, hop_shared_secrets)
    next_hmac = bytes(PER_HOP_HMAC_SIZE)

    # Our starting packet needs to be filled out with random bytes, we
    # generate some deterministically using the session private key.
    pad_key = get_bolt04_onion_key(b'pad', session_key)
    mix_header = generate_cipher_stream(pad_key, HOPS_DATA_SIZE)

    # compute routing info and MAC for each hop
    for i in range(num_hops-1, -1, -1):
        rho_key = get_bolt04_onion_key(b'rho', hop_shared_secrets[i])
        mu_key = get_bolt04_onion_key(b'mu', hop_shared_secrets[i])
        hops_data[i].hmac = next_hmac
        stream_bytes = generate_cipher_stream(rho_key, HOPS_DATA_SIZE)
        hop_data_bytes = hops_data[i].to_bytes()
        mix_header = mix_header[:-len(hop_data_bytes)]
        mix_header = hop_data_bytes + mix_header
        mix_header = xor_bytes(mix_header, stream_bytes)
        if i == num_hops - 1 and len(filler) != 0:
            mix_header = mix_header[:-len(filler)] + filler
        packet = mix_header + associated_data
        next_hmac = hmac_oneshot(mu_key, msg=packet, digest=hashlib.sha256)

    return OnionPacket(
        public_key=ecc.ECPrivkey(session_key).get_public_key_bytes(),
        hops_data=mix_header,
        hmac=next_hmac)


def calc_hops_data_for_payment(route: 'LNPaymentRoute', amount_msat: int,
                               final_cltv: int, *, payment_secret: bytes = None) \
        -> Tuple[List[OnionHopsDataSingle], int, int]:
    """Returns the hops_data to be used for constructing an onion packet,
    and the amount_msat and cltv to be used on our immediate channel.
    """
    if len(route) > NUM_MAX_EDGES_IN_PAYMENT_PATH:
        raise PaymentFailure(f"too long route ({len(route)} edges)")

    # payload that will be seen by the last hop:
    amt = amount_msat
    cltv = final_cltv
    hop_payload = {
        "amt_to_forward": {"amt_to_forward": amt},
        "outgoing_cltv_value": {"outgoing_cltv_value": cltv},
    }
    if payment_secret is not None:
        hop_payload["payment_data"] = {"payment_secret": payment_secret, "total_msat": amt}
    hops_data = [OnionHopsDataSingle(is_tlv_payload=route[-1].has_feature_varonion(),
                                     payload=hop_payload)]
    # payloads, backwards from last hop (but excluding the first edge):
    for edge_index in range(len(route) - 1, 0, -1):
        route_edge = route[edge_index]
        hop_payload = {
            "amt_to_forward": {"amt_to_forward": amt},
            "outgoing_cltv_value": {"outgoing_cltv_value": cltv},
            "short_channel_id": {"short_channel_id": route_edge.short_channel_id},
        }
        hops_data += [OnionHopsDataSingle(is_tlv_payload=route[edge_index-1].has_feature_varonion(),
                                          payload=hop_payload)]
        amt += route_edge.fee_for_edge(amt)
        cltv += route_edge.cltv_expiry_delta
    hops_data.reverse()
    return hops_data, amt, cltv


def _generate_filler(key_type: bytes, hops_data: Sequence[OnionHopsDataSingle],
                     shared_secrets: Sequence[bytes]) -> bytes:
    num_hops = len(hops_data)

    # generate filler that matches all but the last hop (no HMAC for last hop)
    filler_size = 0
    for hop_data in hops_data[:-1]:
        filler_size += len(hop_data.to_bytes())
    filler = bytearray(filler_size)

    for i in range(0, num_hops-1):  # -1, as last hop does not obfuscate
        # Sum up how many frames were used by prior hops.
        filler_start = HOPS_DATA_SIZE
        for hop_data in hops_data[:i]:
            filler_start -= len(hop_data.to_bytes())
        # The filler is the part dangling off of the end of the
        # routingInfo, so offset it from there, and use the current
        # hop's frame count as its size.
        filler_end = HOPS_DATA_SIZE + len(hops_data[i].to_bytes())

        stream_key = get_bolt04_onion_key(key_type, shared_secrets[i])
        stream_bytes = generate_cipher_stream(stream_key, NUM_STREAM_BYTES)
        filler = xor_bytes(filler, stream_bytes[filler_start:filler_end])
        filler += bytes(filler_size - len(filler))  # right pad with zeroes

    return filler


def generate_cipher_stream(stream_key: bytes, num_bytes: int) -> bytes:
    return chacha20_encrypt(key=stream_key,
                            nonce=bytes(8),
                            data=bytes(num_bytes))


class ProcessedOnionPacket(NamedTuple):
    are_we_final: bool
    hop_data: OnionHopsDataSingle
    next_packet: OnionPacket


# TODO replay protection
def process_onion_packet(onion_packet: OnionPacket, associated_data: bytes,
                         our_onion_private_key: bytes) -> ProcessedOnionPacket:
    if not ecc.ECPubkey.is_pubkey_bytes(onion_packet.public_key):
        raise InvalidOnionPubkey()
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
    padded_header = onion_packet.hops_data + bytes(HOPS_DATA_SIZE)
    next_hops_data = xor_bytes(padded_header, stream_bytes)
    next_hops_data_fd = io.BytesIO(next_hops_data)

    # calc next ephemeral key
    blinding_factor = sha256(onion_packet.public_key + shared_secret)
    blinding_factor_int = int.from_bytes(blinding_factor, byteorder="big")
    next_public_key_int = ecc.ECPubkey(onion_packet.public_key) * blinding_factor_int
    next_public_key = next_public_key_int.get_public_key_bytes()

    hop_data = OnionHopsDataSingle.from_fd(next_hops_data_fd)
    next_onion_packet = OnionPacket(
        public_key=next_public_key,
        hops_data=next_hops_data_fd.read(HOPS_DATA_SIZE),
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

    @classmethod
    def from_bytes(cls, failure_msg: bytes):
        failure_code = int.from_bytes(failure_msg[:2], byteorder='big')
        try:
            failure_code = OnionFailureCode(failure_code)
        except ValueError:
            pass  # uknown failure code
        failure_data = failure_msg[2:]
        return OnionRoutingFailureMessage(failure_code, failure_data)

    def code_name(self) -> str:
        if isinstance(self.code, OnionFailureCode):
            return str(self.code.name)
        return f"Unknown error ({self.code!r})"


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
                        session_key: bytes) -> Tuple[bytes, int]:
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
    return OnionRoutingFailureMessage.from_bytes(failure_msg)



# TODO maybe we should rm this and just use OnionWireSerializer and onion_wire.csv
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
    INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS =    PERM | 15
    _LEGACY_INCORRECT_PAYMENT_AMOUNT =        PERM | 16
    FINAL_EXPIRY_TOO_SOON =                   17
    FINAL_INCORRECT_CLTV_EXPIRY =             18
    FINAL_INCORRECT_HTLC_AMOUNT =             19
    CHANNEL_DISABLED =                        UPDATE | 20
    EXPIRY_TOO_FAR =                          21
    INVALID_ONION_PAYLOAD =                   PERM | 22


# don't use these elsewhere, the names are ambiguous without context
del BADONION; del PERM; del NODE; del UPDATE
