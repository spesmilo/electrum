# Copyright (C) 2025 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

# There are three main formats we use to pass around ECDSA signatures:
# - "sig64":   A "compact" 64-byte serialized format.
# - "der_sig": The DER format used on-chain in Bitcoin.
#              This is a variable length (around 71-73 bytes) serialized format.
# - "r and s": A tuple of integers (r, s).
# This module contains helper functions to convert between these.

from typing import Tuple
from ctypes import (
    byref, c_size_t, create_string_buffer,
)

from .ecc_fast import _libsecp256k1


def ecdsa_sig64_from_der_sig(der_sig: bytes) -> bytes:
    r, s = get_r_and_s_from_ecdsa_der_sig(der_sig)
    return ecdsa_sig64_from_r_and_s(r, s)


def ecdsa_der_sig_from_ecdsa_sig64(sig64: bytes) -> bytes:
    r, s = get_r_and_s_from_ecdsa_sig64(sig64)
    return ecdsa_der_sig_from_r_and_s(r, s)


def ecdsa_der_sig_from_r_and_s(r: int, s: int) -> bytes:
    sig64 = (
        int.to_bytes(r, length=32, byteorder="big") +
        int.to_bytes(s, length=32, byteorder="big"))
    sig = create_string_buffer(64)
    ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_libsecp256k1.ctx, sig, sig64)
    if 1 != ret:
        raise Exception("Bad signature")
    ret = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)
    der_sig = create_string_buffer(80)  # this much space should be enough
    der_sig_size = c_size_t(len(der_sig))
    ret = _libsecp256k1.secp256k1_ecdsa_signature_serialize_der(_libsecp256k1.ctx, der_sig, byref(der_sig_size), sig)
    if 1 != ret:
        raise Exception("failed to serialize DER sig")
    der_sig_size = der_sig_size.value
    return bytes(der_sig)[:der_sig_size]


def get_r_and_s_from_ecdsa_der_sig(der_sig: bytes) -> Tuple[int, int]:
    assert isinstance(der_sig, bytes)
    sig = create_string_buffer(64)
    ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_der(_libsecp256k1.ctx, sig, der_sig, len(der_sig))
    if 1 != ret:
        raise Exception("Bad signature")
    ret = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)
    compact_signature = create_string_buffer(64)
    _libsecp256k1.secp256k1_ecdsa_signature_serialize_compact(_libsecp256k1.ctx, compact_signature, sig)
    r = int.from_bytes(compact_signature[:32], byteorder="big")
    s = int.from_bytes(compact_signature[32:], byteorder="big")
    return r, s


def get_r_and_s_from_ecdsa_sig64(sig64: bytes) -> Tuple[int, int]:
    if not (isinstance(sig64, bytes) and len(sig64) == 64):
        raise Exception("sig64 must be bytes, and 64 bytes exactly")
    sig = create_string_buffer(64)
    ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_libsecp256k1.ctx, sig, sig64)
    if 1 != ret:
        raise Exception("Bad signature")
    ret = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)
    compact_signature = create_string_buffer(64)
    _libsecp256k1.secp256k1_ecdsa_signature_serialize_compact(_libsecp256k1.ctx, compact_signature, sig)
    r = int.from_bytes(compact_signature[:32], byteorder="big")
    s = int.from_bytes(compact_signature[32:], byteorder="big")
    return r, s


def ecdsa_sig64_from_r_and_s(r: int, s: int) -> bytes:
    sig64 = (
        int.to_bytes(r, length=32, byteorder="big") +
        int.to_bytes(s, length=32, byteorder="big"))
    sig = create_string_buffer(64)
    ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_libsecp256k1.ctx, sig, sig64)
    if 1 != ret:
        raise Exception("Bad signature")
    ret = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)
    compact_signature = create_string_buffer(64)
    _libsecp256k1.secp256k1_ecdsa_signature_serialize_compact(_libsecp256k1.ctx, compact_signature, sig)
    return bytes(compact_signature)
