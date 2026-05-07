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
from functools import cached_property
from typing import (Sequence, List, Tuple, NamedTuple, TYPE_CHECKING, Dict, Any, Optional, Union,
                    Mapping, Iterator)
from enum import IntEnum
from dataclasses import dataclass, field, replace
from types import MappingProxyType

import electrum_ecc as ecc

from .crypto import sha256, hmac_oneshot, chacha20_encrypt, get_ecdh, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from .util import profiler, xor_bytes, bfh
from .lnutil import (PaymentFailure, NUM_MAX_HOPS_IN_PAYMENT_PATH, LnFeatureContexts,
                     NUM_MAX_EDGES_IN_PAYMENT_PATH, ShortChannelID, OnionFailureCodeMetaFlag, LnFeatures,
                     NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE, validate_features, IncompatibleOrInsaneFeatures)
from .lnmsg import OnionWireSerializer, read_bigsize_int, write_bigsize_int
from .logging import get_logger
from . import lnmsg
from . import util

if TYPE_CHECKING:
    from .lnrouter import LNPaymentRoute

_logger = get_logger(__name__)

HOPS_DATA_SIZE = 1300      # also sometimes called routingInfoSize in bolt-04
PER_HOP_HMAC_SIZE = 32
ONION_MESSAGE_LARGE_SIZE = 32768

class UnsupportedOnionPacketVersion(Exception): pass
class InvalidOnionMac(Exception): pass
class InvalidOnionPubkey(Exception): pass
class InvalidPayloadSize(Exception): pass
class InvalidBlindedOnion(Exception): pass


@dataclass(frozen=True, kw_only=True)
class OnionHopsDataSingle:
    payload: Mapping = field(default_factory=lambda: MappingProxyType({}))
    hmac: Optional[bytes] = None
    tlv_stream_name: str = 'payload'
    blind_fields: Mapping = field(default_factory=lambda: MappingProxyType({}))
    _raw_bytes_payload: Optional[bytes] = None

    def __post_init__(self):
        # make all fields immutable recursively
        object.__setattr__(self, 'payload', util.make_object_immutable(self.payload))
        object.__setattr__(self, 'blind_fields', util.make_object_immutable(self.blind_fields))
        assert isinstance(self.payload, MappingProxyType)
        assert isinstance(self.blind_fields, MappingProxyType)
        assert isinstance(self.tlv_stream_name, str)
        assert (isinstance(self.hmac, bytes) and len(self.hmac) == PER_HOP_HMAC_SIZE) or self.hmac is None

    def to_bytes(self) -> bytes:
        hmac_ = self.hmac if self.hmac is not None else bytes(PER_HOP_HMAC_SIZE)
        if self._raw_bytes_payload is not None:
            ret = self._raw_bytes_payload
            ret += hmac_
            return ret
        # adding TLV payload. note: legacy hop data format no longer supported.
        payload_fd = io.BytesIO()
        OnionWireSerializer.write_tlv_stream(fd=payload_fd,
                                             tlv_stream_name=self.tlv_stream_name,
                                             **self.payload)
        payload_bytes = payload_fd.getvalue()
        with io.BytesIO() as fd:
            fd.write(write_bigsize_int(len(payload_bytes)))
            fd.write(payload_bytes)
            fd.write(hmac_)
            return fd.getvalue()

    @classmethod
    def from_fd(cls, fd: io.BytesIO, *, tlv_stream_name: str = 'payload') -> 'OnionHopsDataSingle':
        first_byte = fd.read(1)
        if len(first_byte) == 0:
            raise Exception(f"unexpected EOF")
        fd.seek(-1, io.SEEK_CUR)  # undo read
        if first_byte == b'\x00':
            # legacy hop data format
            raise Exception("legacy hop data format no longer supported")
        elif first_byte == b'\x01':
            # reserved for future use
            raise Exception("unsupported hop payload: length==1")
        else:  # tlv format
            hop_payload_length = read_bigsize_int(fd)
            hop_payload = fd.read(hop_payload_length)
            if hop_payload_length != len(hop_payload):
                raise Exception(f"unexpected EOF")
            payload = OnionWireSerializer.read_tlv_stream(fd=io.BytesIO(hop_payload),
                                                          tlv_stream_name=tlv_stream_name)
            ret = OnionHopsDataSingle(
                tlv_stream_name=tlv_stream_name,
                payload=payload,
                hmac=fd.read(PER_HOP_HMAC_SIZE)
            )
            return ret

    def __repr__(self):
        return f"<OnionHopsDataSingle. {self.payload=}. {self.hmac=}>"


@dataclass(frozen=True, kw_only=True)
class OnionPacket:
    public_key: bytes
    hops_data: bytes  # also called RoutingInfo in bolt-04
    hmac: bytes
    version: int = 0
    # for debugging our own onions:
    _debug_hops_data: Optional[Sequence[OnionHopsDataSingle]] = None
    _debug_route: Optional['LNPaymentRoute'] = None

    def __post_init__(self):
        assert len(self.public_key) == 33
        assert len(self.hmac) == PER_HOP_HMAC_SIZE
        if not ecc.ECPubkey.is_pubkey_bytes(self.public_key):
            raise InvalidOnionPubkey()

    def to_bytes(self) -> bytes:
        ret = bytes([self.version])
        ret += self.public_key
        ret += self.hops_data
        ret += self.hmac
        return ret

    @classmethod
    def from_bytes(cls, b: bytes) -> 'OnionPacket':
        return OnionPacket(
            public_key=b[1:34],
            hops_data=b[34:-32],
            hmac=b[-32:],
            version=b[0],
        )

    @cached_property
    def onion_hash(self) -> bytes:
        return sha256(self.to_bytes())


@dataclass(frozen=True, kw_only=True)
class BlindedPathHop:
    blinded_node_id: bytes
    enclen: int
    encrypted_recipient_data: bytes

    def __post_init__(self):
        ecc.ECPubkey(b=self.blinded_node_id)


@dataclass(frozen=True, kw_only=True)
class BlindedPath:
    """
    https://github.com/lightning/bolts/blob/34455ffe28b308dd7ac7552234d565890af8605b/04-onion-routing.md?plain=1#L441
    """
    first_node_id: bytes
    first_path_key: bytes
    num_hops: bytes
    path: list[BlindedPathHop]

    @property
    def hop_count(self) -> int:
        return int.from_bytes(self.num_hops, byteorder='big', signed=False)

    def __post_init__(self):
        # if num_hops is 0 in any blinded_path in offer_paths: MUST NOT respond to the offer
        assert isinstance(self.num_hops, bytes), type(self.num_hops)
        assert isinstance(self.path, list), self.path
        if self.hop_count == 0:
            raise ValueError('invalid num_hops of 0')
        if not self.path:
            raise ValueError('empty path')
        if not len(self.path) == self.hop_count:
            raise ValueError(f'{len(self.path)=} != {self.hop_count=}')
        # ecc.ECPubkey(b=self.first_node_id)  # fails bolt 12 test vectors using dummy node ids
        ecc.ECPubkey(b=self.first_path_key)

    @classmethod
    def decode(cls, blinded_path: bytes) -> 'BlindedPath':
        with io.BytesIO(blinded_path) as blinded_path_fd:
            blinded_path = OnionWireSerializer.read_field(
                fd=blinded_path_fd,
                field_type='blinded_path',
                count=1)
        return cls.from_dict(blinded_path)

    @classmethod
    def from_dict(cls, d: dict) -> 'BlindedPath':
        if isinstance(d['path'], Mapping):  # single path
            d['path'] = [d['path']]
        return BlindedPath(
            first_node_id=d['first_node_id'],
            first_path_key=d['first_path_key'],
            num_hops=d['num_hops'],
            path=[BlindedPathHop(**p) for p in d['path']],
        )


@dataclass(frozen=True)
class BlindedPayInfo:
    fee_base_msat: int
    fee_proportional_millionths: int
    cltv_expiry_delta: int
    htlc_minimum_msat: int
    htlc_maximum_msat: int
    features: LnFeatures

    def __post_init__(self):
        if self.cltv_expiry_delta > NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE:
            raise ValueError(f"unreasonably long {self.cltv_expiry_delta=}")

    @property
    def requires_unknown_mandatory_features(self) -> bool:
        """
        MUST NOT use the corresponding invoice_paths.path if payinfo.features has any unknown even bits set.
        """
        try:
            validate_features(self.features, context=LnFeatureContexts.BLINDED_PAYINFO)
        except IncompatibleOrInsaneFeatures:
            return True
        return False

    @classmethod
    def from_dict(cls, d: dict) -> 'BlindedPayInfo':
        return BlindedPayInfo(
            fee_base_msat=int(d['fee_base_msat']),
            fee_proportional_millionths=int(d['fee_proportional_millionths']),
            cltv_expiry_delta=int(d['cltv_expiry_delta']),
            htlc_minimum_msat=int(d['htlc_minimum_msat']),
            htlc_maximum_msat=int(d['htlc_maximum_msat']),
            features=LnFeatures(int.from_bytes(d['features'], byteorder="big", signed=False))
        )

    def to_dict(self) -> dict:
        return {
            'fee_base_msat': self.fee_base_msat,
            'fee_proportional_millionths': self.fee_proportional_millionths,
            'cltv_expiry_delta': self.cltv_expiry_delta,
            'htlc_minimum_msat': self.htlc_minimum_msat,
            'htlc_maximum_msat': self.htlc_maximum_msat,
            'flen': len(self.features.to_tlv_bytes()),
            'features': self.features.to_tlv_bytes()
        }


class BlindedPathInfo(NamedTuple):
    path: BlindedPath
    payinfo: Optional[BlindedPayInfo]


def get_bolt04_onion_key(key_type: bytes, secret: bytes) -> bytes:
    if key_type not in (b'rho', b'mu', b'um', b'ammag', b'pad', b'blinded_node_id'):
        raise Exception('invalid key_type {}'.format(key_type))
    key = hmac_oneshot(key_type, msg=secret, digest=hashlib.sha256)
    return key


def get_shared_secrets_along_route(payment_path_pubkeys: Sequence[bytes],
                                   session_key: bytes) -> Tuple[Sequence[bytes], Sequence[bytes]]:
    num_hops = len(payment_path_pubkeys)
    hop_shared_secrets = num_hops * [b'']
    hop_blinded_node_ids = num_hops * [b'']
    ephemeral_key = session_key
    # compute shared key for each hop
    for i in range(0, num_hops):
        hop_shared_secrets[i] = get_ecdh(ephemeral_key, payment_path_pubkeys[i])
        hop_blinded_node_ids[i] = get_blinded_node_id(payment_path_pubkeys[i], hop_shared_secrets[i])
        ephemeral_pubkey = ecc.ECPrivkey(ephemeral_key).get_public_key_bytes()
        blinding_factor = sha256(ephemeral_pubkey + hop_shared_secrets[i])
        blinding_factor_int = int.from_bytes(blinding_factor, byteorder="big")
        ephemeral_key_int = int.from_bytes(ephemeral_key, byteorder="big")
        ephemeral_key_int = ephemeral_key_int * blinding_factor_int % ecc.CURVE_ORDER
        ephemeral_key = ephemeral_key_int.to_bytes(32, byteorder="big")
    return hop_shared_secrets, hop_blinded_node_ids


def get_blinded_node_id(node_id: bytes, shared_secret: bytes):
    # blinded node id
    # B(i) = HMAC256("blinded_node_id", ss(i)) * N(i)
    ss_bni_hmac = get_bolt04_onion_key(b'blinded_node_id', shared_secret)
    ss_bni_hmac_int = int.from_bytes(ss_bni_hmac, byteorder="big")
    blinded_node_id = ecc.ECPubkey(node_id) * ss_bni_hmac_int
    return blinded_node_id.get_public_key_bytes()


def blinding_privkey(privkey: bytes, shared_secret: bytes) -> bytes:
    b_hmac = get_bolt04_onion_key(b'blinded_node_id', shared_secret)
    b_hmac_int = int.from_bytes(b_hmac, byteorder="big")

    our_privkey_int = int.from_bytes(privkey, byteorder="big")
    our_privkey_int = our_privkey_int * b_hmac_int % ecc.CURVE_ORDER
    our_privkey = our_privkey_int.to_bytes(32, byteorder="big")
    return our_privkey


def next_blinding_from_shared_secret(pubkey: bytes, shared_secret: bytes) -> bytes:
    # E_i+1=SHA256(E_i||ss_i) * E_i
    blinding_factor = sha256(pubkey + shared_secret)
    blinding_factor_int = int.from_bytes(blinding_factor, byteorder="big")
    next_public_key_int = ecc.ECPubkey(pubkey) * blinding_factor_int
    return next_public_key_int.get_public_key_bytes()


def new_onion_packet(
    payment_path_pubkeys: Sequence[bytes],
    session_key: bytes,
    hops_data: List[OnionHopsDataSingle],
    *,
    associated_data: bytes = b'',
    trampoline: bool = False,
    onion_message: bool = False
) -> OnionPacket:
    num_hops = len(payment_path_pubkeys)
    assert num_hops == len(hops_data), f"{num_hops=}, {hops_data=}"
    hop_shared_secrets, _ = get_shared_secrets_along_route(payment_path_pubkeys, session_key)

    payload_size = 0
    for i in range(num_hops):
        # FIXME: serializing here and again below. cache bytes in OnionHopsDataSingle? _raw_bytes_payload?
        payload_size += len(hops_data[i].to_bytes())
    if trampoline:
        data_size = payload_size
    elif onion_message:
        if payload_size <= HOPS_DATA_SIZE:
            data_size = HOPS_DATA_SIZE
        else:
            data_size = ONION_MESSAGE_LARGE_SIZE
    else:
        data_size = HOPS_DATA_SIZE

    if payload_size > data_size:
        raise InvalidPayloadSize(f'payload too big for onion packet (max={data_size}, required={payload_size})')

    filler = _generate_filler(b'rho', hops_data, hop_shared_secrets, data_size)
    next_hmac = bytes(PER_HOP_HMAC_SIZE)

    # Our starting packet needs to be filled out with random bytes, we
    # generate some deterministically using the session private key.
    pad_key = get_bolt04_onion_key(b'pad', session_key)
    mix_header = generate_cipher_stream(pad_key, data_size)

    # compute routing info and MAC for each hop
    for i in range(num_hops-1, -1, -1):
        rho_key = get_bolt04_onion_key(b'rho', hop_shared_secrets[i])
        mu_key = get_bolt04_onion_key(b'mu', hop_shared_secrets[i])
        hops_data[i] = replace(hops_data[i], hmac=next_hmac)
        stream_bytes = generate_cipher_stream(rho_key, data_size)
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


def encrypt_onionmsg_data_tlv(*, shared_secret, **kwargs):
    rho_key = get_bolt04_onion_key(b'rho', shared_secret)
    with io.BytesIO() as encrypted_data_tlv_fd:
        OnionWireSerializer.write_tlv_stream(
            fd=encrypted_data_tlv_fd,
            tlv_stream_name='encrypted_data_tlv',
            **kwargs)
        encrypted_data_tlv_bytes = encrypted_data_tlv_fd.getvalue()
        encrypted_recipient_data = chacha20_poly1305_encrypt(
            key=rho_key, nonce=bytes(12),
            data=encrypted_data_tlv_bytes)
        return encrypted_recipient_data


def decrypt_onionmsg_data_tlv(*, shared_secret: bytes, encrypted_recipient_data: bytes) -> dict:
    rho_key = get_bolt04_onion_key(b'rho', shared_secret)
    recipient_data_bytes = chacha20_poly1305_decrypt(key=rho_key, nonce=bytes(12), data=encrypted_recipient_data)

    with io.BytesIO(recipient_data_bytes) as fd:
        recipient_data = OnionWireSerializer.read_tlv_stream(fd=fd, tlv_stream_name='encrypted_data_tlv')

    return recipient_data


def encrypt_hops_recipient_data(
        hops_data: List[OnionHopsDataSingle],
        hop_shared_secrets: Sequence[bytes]
) -> None:
    """Encrypt plaintext OnionHopsDataSingle.blind_fields into encrypted_recipient_data"""
    for i, (hop_data, hop_shared_secret) in enumerate(zip(hops_data, hop_shared_secrets)):
        assert 'encrypted_recipient_data' not in hop_data.payload, hop_data
        encrypted_recipient_data = encrypt_onionmsg_data_tlv(shared_secret=hop_shared_secret, **hop_data.blind_fields)
        new_hop_payload = {'encrypted_recipient_data': {'encrypted_recipient_data': encrypted_recipient_data}}
        new_hop_payload.update(hop_data.payload)  # keep other fields
        hops_data[i] = replace(hop_data, payload=new_hop_payload)


def calc_hops_data_for_payment(
        route: 'LNPaymentRoute',
        amount_msat: int,  # that final recipient receives
        *,
        final_cltv_abs: int,
        total_msat: int,
        payment_secret: bytes,
) -> Tuple[List[OnionHopsDataSingle], int, int]:
    """Returns the hops_data to be used for constructing an onion packet,
    and the amount_msat and cltv_abs to be used on our immediate channel.
    """
    if len(route) > NUM_MAX_EDGES_IN_PAYMENT_PATH:
        raise PaymentFailure(f"too long route ({len(route)} edges)")
    amt = amount_msat
    cltv_abs = final_cltv_abs
    # payload that will be seen by the last hop:
    # for multipart payments we need to tell the receiver about the total and
    # partial amounts
    hop_payload = {
        "amt_to_forward": {"amt_to_forward": amt},
        "outgoing_cltv_value": {"outgoing_cltv_value": cltv_abs},
        "payment_data": {
            "payment_secret": payment_secret,
            "total_msat": total_msat,
            "amount_msat": amt,
        }}
    hops_data = [OnionHopsDataSingle(payload=hop_payload)]
    # payloads, backwards from last hop (but excluding the first edge):
    for route_edge in reversed(route[1:]):
        hop_payload = {
            "amt_to_forward": {"amt_to_forward": amt},
            "outgoing_cltv_value": {"outgoing_cltv_value": cltv_abs},
            "short_channel_id": {"short_channel_id": route_edge.short_channel_id},
        }
        hops_data.append(
            OnionHopsDataSingle(payload=hop_payload))
        amt += route_edge.fee_for_edge(amt)
        cltv_abs += route_edge.cltv_delta
    hops_data.reverse()
    return hops_data, amt, cltv_abs


def calc_hops_data_for_blinded_payment(
        route_to_introduction_point: 'LNPaymentRoute',
        recipient_amount_msat: int,
        *,
        final_cltv_abs: int,
        total_msat: int,
        invoice_blinded_path_info: 'BlindedPathInfo',
) -> Tuple[List[OnionHopsDataSingle], List[bytes], int, int]:
    """
    Returns the hops_data to be used for constructing an onion packet,
    and the amount_msat and cltv_abs to be used on our immediate channel.
    https://github.com/lightning/bolts/blob/444805d12ab98c30006173bb190cd9d6fce9e405/04-onion-routing.md?plain=1#L264
    """
    from .lnrouter import fee_for_edge_msat
    invoice_blinded_path, invoice_payinfo = invoice_blinded_path_info.path, invoice_blinded_path_info.payinfo
    assert invoice_blinded_path and invoice_payinfo
    if len(route_to_introduction_point) > NUM_MAX_EDGES_IN_PAYMENT_PATH:
        raise PaymentFailure(f"too long route ({len(route_to_introduction_point)} edges)")

    hops_data = []
    amt = recipient_amount_msat
    inv_hops = invoice_blinded_path.path
    num_hops = len(inv_hops)
    if not invoice_payinfo.htlc_minimum_msat <= recipient_amount_msat <= invoice_payinfo.htlc_maximum_msat:
        raise Exception(f'{invoice_payinfo=} htlc limits cannot fit {recipient_amount_msat=}')

    _logger.debug('inv_hops: ' + repr(inv_hops))
    # assemble data for the hops on the given blinded path
    for i, inv_hop in enumerate(reversed(inv_hops)):
        # each hop gets their encrypted recipient data
        payload: dict = {
            'encrypted_recipient_data': {'encrypted_recipient_data': inv_hop.encrypted_recipient_data}
        }
        if i == 0:  # recipient
            payload.update({
                'amt_to_forward': {'amt_to_forward': recipient_amount_msat},
                'outgoing_cltv_value': {'outgoing_cltv_value': final_cltv_abs},
                'total_amount_msat': {'total_msat': total_msat},
            })
        if i == num_hops - 1:  # introduction point
            payload['current_path_key'] = {'path_key': invoice_blinded_path.first_path_key}
        _logger.debug(f'inv_hop[{num_hops - 1 - i}].payload: ' + repr(payload))
        hops_data.append(OnionHopsDataSingle(payload=payload))

    # add the fees + cltv for the (whole) blinded path, amt is then what the introduction point gets
    amt += fee_for_edge_msat(
        forwarded_amount_msat=recipient_amount_msat,
        fee_base_msat=invoice_payinfo.fee_base_msat,
        fee_proportional_millionths=invoice_payinfo.fee_proportional_millionths,
    )
    cltv_abs = final_cltv_abs + invoice_payinfo.cltv_expiry_delta
    _logger.debug(f'blinded payment introduction point {amt=} for {recipient_amount_msat=}, {cltv_abs=}')

    # payloads for the unblinded part of the path, backwards from pre-IP node (excluding the first edge)
    for i, route_edge in enumerate(reversed(route_to_introduction_point[1:])):
        hop_payload = {
            "amt_to_forward": {"amt_to_forward": amt},
            "outgoing_cltv_value": {"outgoing_cltv_value": cltv_abs},
            "short_channel_id": {"short_channel_id": route_edge.short_channel_id},
        }

        hops_data.append(OnionHopsDataSingle(payload=hop_payload))
        amt += route_edge.fee_for_edge(amt)
        cltv_abs += route_edge.cltv_delta

        _logger.debug(f'route_edge[{len(route_to_introduction_point) - 1 - i}].payload: ' + repr(hop_payload) + \
                     f'\nedge_in_amt: {amt}, edge_in_cltv: {cltv_abs}' + \
                     f'\n--> {route_edge.end_node.hex()}')

    hops_data.reverse()
    blinded_path_blinded_node_pubkeys = [x.blinded_node_id for x in inv_hops][1:]
    return hops_data, blinded_path_blinded_node_pubkeys, amt, cltv_abs


def _generate_filler(key_type: bytes, hops_data: Sequence[OnionHopsDataSingle],
                     shared_secrets: Sequence[bytes], data_size:int) -> bytes:
    num_hops = len(hops_data)

    # generate filler that matches all but the last hop (no HMAC for last hop)
    filler_size = 0
    for hop_data in hops_data[:-1]:
        filler_size += len(hop_data.to_bytes())
    filler = bytearray(filler_size)

    for i in range(0, num_hops-1):  # -1, as last hop does not obfuscate
        # Sum up how many frames were used by prior hops.
        filler_start = data_size
        for hop_data in hops_data[:i]:
            filler_start -= len(hop_data.to_bytes())
        # The filler is the part dangling off of the end of the
        # routingInfo, so offset it from there, and use the current
        # hop's frame count as its size.
        filler_end = data_size + len(hops_data[i].to_bytes())

        stream_key = get_bolt04_onion_key(key_type, shared_secrets[i])
        stream_bytes = generate_cipher_stream(stream_key, 2 * data_size)
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
    trampoline_onion_packet: Optional[OnionPacket]
    blinded_path_recipient_data: Optional[MappingProxyType] = None
    next_path_key: Optional[bytes] = None

    @property
    def amt_to_forward(self) -> Optional[int]:
        k1 = k2 = 'amt_to_forward'
        return self._get_from_payload(k1, k2, int)

    @property
    def outgoing_cltv_value(self) -> Optional[int]:
        k1 = k2 = 'outgoing_cltv_value'
        return self._get_from_payload(k1, k2, int)

    @property
    def next_chan_scid(self) -> Optional[ShortChannelID]:
        k1 = k2 = 'short_channel_id'
        if self.blinded_path_recipient_data is not None:
            return self.get_from_recipient_data(k1, k2, ShortChannelID)
        return self._get_from_payload(k1, k2, ShortChannelID)

    @property
    def next_node_id(self) -> Optional[bytes]:
        if self.blinded_path_recipient_data is not None:
            return self.get_from_recipient_data('next_node_id', 'node_id', bytes)
        return None

    @property
    def total_msat(self) -> Optional[int]:
        if self.blinded_path_recipient_data is not None:
            return self._get_from_payload('total_amount_msat', 'total_msat', int)
        return self._get_from_payload('payment_data', 'total_msat', int)

    @property
    def payment_secret(self) -> Optional[bytes]:
        if self.blinded_path_recipient_data is not None:
            return None
        return self._get_from_payload('payment_data', 'payment_secret', bytes)

    def _get_from_payload(self, k1: str, k2: str, res_type: type):
        return self._get_from(self.hop_data.payload, k1, k2, res_type)

    def get_from_recipient_data(self, k1: str, k2: str, res_type: type):
        assert self.blinded_path_recipient_data is not None
        return self._get_from(self.blinded_path_recipient_data, k1, k2, res_type)

    @staticmethod
    def _get_from(payload: Mapping, k1: str, k2: str, res_type: type):
        try:
            result = payload[k1][k2]
            return res_type(result)
        except Exception:
            return None


# TODO replay protection
def process_onion_packet(
        onion_packet: OnionPacket,
        our_onion_private_key: bytes,
        *,
        associated_data: bytes = b'',
        is_trampoline=False,
        current_path_key: Optional[bytes] = None,
        tlv_stream_name='payload') -> ProcessedOnionPacket:
    # TODO: check Onion features ( PERM|NODE|3 (required_node_feature_missing )
    if onion_packet.version != 0:
        raise UnsupportedOnionPacketVersion()
    if not ecc.ECPubkey.is_pubkey_bytes(onion_packet.public_key):
        raise InvalidOnionPubkey()
    is_onion_message = tlv_stream_name == 'onionmsg_tlv'
    recipient_data_shared_secret = None
    if current_path_key:
        recipient_data_shared_secret = get_ecdh(our_onion_private_key, current_path_key)
        # the onion is encrypted to our blinded node id
        our_onion_private_key = blinding_privkey(our_onion_private_key, recipient_data_shared_secret)
    shared_secret = get_ecdh(our_onion_private_key, onion_packet.public_key)
    # check message integrity
    mu_key = get_bolt04_onion_key(b'mu', shared_secret)
    calculated_mac = hmac_oneshot(
        mu_key, msg=onion_packet.hops_data+associated_data,
        digest=hashlib.sha256)
    if not util.constant_time_compare(onion_packet.hmac, calculated_mac):
        raise InvalidOnionMac()
    # peel an onion layer off
    rho_key = get_bolt04_onion_key(b'rho', shared_secret)
    data_size = len(onion_packet.hops_data) if is_trampoline else HOPS_DATA_SIZE
    if is_onion_message and len(onion_packet.hops_data) > HOPS_DATA_SIZE:
        data_size = ONION_MESSAGE_LARGE_SIZE
    stream_bytes = generate_cipher_stream(rho_key, 2 * data_size)
    padded_header = onion_packet.hops_data + bytes(data_size)
    next_hops_data = xor_bytes(padded_header, stream_bytes)
    next_hops_data_fd = io.BytesIO(next_hops_data)
    hop_data = OnionHopsDataSingle.from_fd(next_hops_data_fd, tlv_stream_name=tlv_stream_name)

    blinded_path_recipient_data = {}
    initial_path_key = hop_data.payload.get('current_path_key', {}).get('path_key')
    encrypted_recipient_data = hop_data.payload.get('encrypted_recipient_data', {}).get('encrypted_recipient_data')
    if encrypted_recipient_data is not None:
        # we are part of a blinded path
        if bool(initial_path_key) == bool(current_path_key):
            raise InvalidBlindedOnion("need exactly one path key")
        if not current_path_key:  # we are the introduction point
            current_path_key = initial_path_key
            recipient_data_shared_secret = get_ecdh(our_onion_private_key, current_path_key)
        assert recipient_data_shared_secret
        try:
            blinded_path_recipient_data = decrypt_onionmsg_data_tlv(
                shared_secret=recipient_data_shared_secret,
                encrypted_recipient_data=encrypted_recipient_data,
            )
        except Exception as e:
            raise InvalidBlindedOnion from e
    elif current_path_key or initial_path_key:
        raise InvalidBlindedOnion("got path key without encrypted_recipient_data")

    # trampoline
    trampoline_onion_packet = hop_data.payload.get('trampoline_onion_packet')
    if trampoline_onion_packet:
        if is_trampoline:
            raise Exception("found nested trampoline inside trampoline")
        trampoline_onion_packet = trampoline_onion_packet['trampoline_onion_packet']
        trampoline_onion_packet = OnionPacket.from_bytes(trampoline_onion_packet)
    # calc next ephemeral key
    next_public_key = next_blinding_from_shared_secret(onion_packet.public_key, shared_secret)
    next_onion_packet = OnionPacket(
        public_key=next_public_key,
        hops_data=next_hops_data_fd.read(data_size),
        hmac=hop_data.hmac)
    if hop_data.hmac == bytes(PER_HOP_HMAC_SIZE):
        # we are the destination / exit node
        are_we_final = True
    else:
        # we are an intermediate node; forwarding
        are_we_final = False

    next_path_key = blinded_path_recipient_data.get('next_path_key_override', {}).get('path_key')
    if not are_we_final and current_path_key and not next_path_key:
        assert recipient_data_shared_secret
        next_path_key = next_blinding_from_shared_secret(current_path_key, recipient_data_shared_secret)

    return ProcessedOnionPacket(
        are_we_final,
        hop_data,
        next_onion_packet,
        trampoline_onion_packet,
        util.make_object_immutable(blinded_path_recipient_data) if current_path_key else None,
        next_path_key,
    )


def compare_trampoline_onions(
    trampoline_onions: Iterator[Optional[ProcessedOnionPacket]],
    *,
    exclude_amt_to_fwd: bool = False,
) -> bool:
    """
    compare values of trampoline onions payloads and are_we_final.
    If we are receiver of a multi trampoline payment amt_to_fwd can differ between the trampoline
    parts of the payment, so it needs to be excluded from the comparison when comparing all trampoline
    onions of the whole payment (however it can be compared between the onions in a single trampoline part).
    """
    try:
        first_onion = next(trampoline_onions)
    except StopIteration:
        raise ValueError("nothing to compare")

    if first_onion is None:
        # we don't support mixed mpp sets of htlcs with trampoline onions and regular non-trampoline htlcs.
        # In theory this could happen if a sender e.g. uses trampoline as fallback to deliver
        # outstanding mpp parts if local pathfinding wasn't successful for the whole payment,
        # resulting in a mixed payment. However, it's not even clear if the spec allows for such a constellation.
        return all(onion is None for onion in trampoline_onions)
    assert isinstance(first_onion, ProcessedOnionPacket), f"{first_onion=}"

    are_we_final = first_onion.are_we_final
    payload = first_onion.hop_data.payload
    total_msat = first_onion.total_msat
    outgoing_cltv = first_onion.outgoing_cltv_value
    payment_secret = first_onion.payment_secret
    for onion in trampoline_onions:
        if onion is None:
            return False
        assert isinstance(onion, ProcessedOnionPacket), f"{onion=}"
        assert onion.trampoline_onion_packet is None, f"{onion=} cannot have trampoline_onion_packet"
        if onion.are_we_final != are_we_final:
            return False
        if not exclude_amt_to_fwd:
            if onion.hop_data.payload != payload:
                return False
        else:
            if onion.total_msat != total_msat:
                return False
            if onion.outgoing_cltv_value != outgoing_cltv:
                return False
            if onion.payment_secret != payment_secret:
                return False
    return True


class FailedToDecodeOnionError(Exception): pass


class OnionRoutingFailure(Exception):

    def __init__(self, code: Union[int, 'OnionFailureCode'], data: bytes):
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
        failure_code = OnionFailureCode.from_int(failure_code)  # convert to enum, if known code
        failure_data = failure_msg[2:]
        return OnionRoutingFailure(failure_code, failure_data)

    def code_name(self) -> str:
        if isinstance(self.code, OnionFailureCode):
            return str(self.code.name)
        return f"Unknown error ({self.code!r})"

    def decode_data(self) -> Optional[Dict[str, Any]]:
        try:
            message_type, payload = OnionWireSerializer.decode_msg(self.to_bytes())
        except lnmsg.FailedToParseMsg:
            payload = None
        return payload

    def to_wire_msg(self, onion_packet: OnionPacket, privkey: bytes, local_height: int) -> bytes:
        onion_error = construct_onion_error(self, onion_packet.public_key, privkey, local_height)
        error_bytes = obfuscate_onion_error(onion_error, onion_packet.public_key, privkey)
        return error_bytes


class OnionParsingError(OnionRoutingFailure):
    """
    Onion parsing error will cause a htlc to get failed with update_fail_malformed_htlc.
    Using INVALID_ONION_VERSION as there is no unspecific BADONION failure code defined in the spec
    for the case we just cannot parse the onion.
    """
    def __init__(self, data: bytes):
        OnionRoutingFailure.__init__(self, code=OnionFailureCode.INVALID_ONION_VERSION, data=data)


def construct_onion_error(
        error: OnionRoutingFailure,
        their_public_key: bytes,
        our_onion_private_key: bytes,
        local_height: int
) -> bytes:
    # add local height
    if error.code == OnionFailureCode.INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
        error.data += local_height.to_bytes(4, byteorder="big")
    # create payload
    failure_msg = error.to_bytes()
    failure_len = len(failure_msg)
    pad_len = 256 - failure_len
    assert pad_len >= 0
    error_packet =  failure_len.to_bytes(2, byteorder="big")
    error_packet += failure_msg
    error_packet += pad_len.to_bytes(2, byteorder="big")
    error_packet += bytes(pad_len)
    # add hmac
    shared_secret = get_ecdh(our_onion_private_key, their_public_key)
    um_key = get_bolt04_onion_key(b'um', shared_secret)
    hmac_ = hmac_oneshot(um_key, msg=error_packet, digest=hashlib.sha256)
    error_packet = hmac_ + error_packet
    return error_packet

def obfuscate_onion_error(error_packet, their_public_key, our_onion_private_key):
    shared_secret = get_ecdh(our_onion_private_key, their_public_key)
    ammag_key = get_bolt04_onion_key(b'ammag', shared_secret)
    stream_bytes = generate_cipher_stream(ammag_key, len(error_packet))
    error_packet = xor_bytes(error_packet, stream_bytes)
    return error_packet


def _decode_onion_error(error_packet: bytes, payment_path_pubkeys: Sequence[bytes],
                        session_key: bytes) -> Tuple[bytes, int]:
    """
    Returns the decoded error bytes, and the index of the sender of the error.
    https://github.com/lightning/bolts/blob/14272b1bd9361750cfdb3e5d35740889a6b510b5/04-onion-routing.md?plain=1#L1096
    """
    num_hops = len(payment_path_pubkeys)
    hop_shared_secrets, _ = get_shared_secrets_along_route(payment_path_pubkeys, session_key)
    result = None
    dummy_secret = bytes(32)
    # SHOULD continue decrypting, until the loop has been repeated 27 times
    for i in range(27):
        if i < num_hops:
            ammag_key = get_bolt04_onion_key(b'ammag', hop_shared_secrets[i])
            um_key = get_bolt04_onion_key(b'um', hop_shared_secrets[i])
        else:
            # SHOULD use constant `ammag` and `um` keys to obfuscate the route length.
            ammag_key = get_bolt04_onion_key(b'ammag', dummy_secret)
            um_key = get_bolt04_onion_key(b'um', dummy_secret)

        stream_bytes = generate_cipher_stream(ammag_key, len(error_packet))
        error_packet = xor_bytes(error_packet, stream_bytes)
        hmac_computed = hmac_oneshot(um_key, msg=error_packet[32:], digest=hashlib.sha256)
        hmac_found = error_packet[:32]
        if util.constant_time_compare(hmac_found, hmac_computed) and i < num_hops:
            result = error_packet, i

    if result is not None:
        return result
    raise FailedToDecodeOnionError()


def decode_onion_error(error_packet: bytes, payment_path_pubkeys: Sequence[bytes],
                       session_key: bytes) -> Tuple[OnionRoutingFailure, int]:
    """Returns the failure message, and the index of the sender of the error."""
    decrypted_error, sender_index = _decode_onion_error(error_packet, payment_path_pubkeys, session_key)
    failure_msg = get_failure_msg_from_onion_error(decrypted_error)
    return failure_msg, sender_index


def get_failure_msg_from_onion_error(decrypted_error_packet: bytes) -> OnionRoutingFailure:
    # get failure_msg bytes from error packet
    failure_len = int.from_bytes(decrypted_error_packet[32:34], byteorder='big')
    failure_msg = decrypted_error_packet[34:34+failure_len]
    # create failure message object
    return OnionRoutingFailure.from_bytes(failure_msg)



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
    MPP_TIMEOUT =                             23
    INVALID_ONION_BLINDING =                  BADONION | PERM | 24
    TRAMPOLINE_FEE_INSUFFICIENT =             NODE | 51
    TRAMPOLINE_EXPIRY_TOO_SOON =              NODE | 52

    @classmethod
    def from_int(cls, code: int) -> Union[int, 'OnionFailureCode']:
        try:
            code = OnionFailureCode(code)
        except ValueError:
            pass  # unknown failure code
        return code


# don't use these elsewhere, the names are ambiguous without context
del BADONION; del PERM; del NODE; del UPDATE
