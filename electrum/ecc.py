# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018-2024 The Electrum developers
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

import base64
import hashlib
import functools
import secrets
from typing import Union, Tuple, Optional
from ctypes import (
    byref, c_char_p, c_size_t, create_string_buffer, cast,
)

from . import ecc_fast
from .ecc_fast import _libsecp256k1, SECP256K1_EC_UNCOMPRESSED, LibModuleMissing

def assert_bytes(x):
    assert isinstance(x, (bytes, bytearray))

# Some unit tests need to create ECDSA sigs without grinding the R value (and just use RFC6979).
# see https://github.com/bitcoin/bitcoin/pull/13666
ENABLE_ECDSA_R_VALUE_GRINDING = True


def string_to_number(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big', signed=False)


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


def _x_and_y_from_pubkey_bytes(pubkey: bytes) -> Tuple[int, int]:
    assert isinstance(pubkey, bytes), f'pubkey must be bytes, not {type(pubkey)}'
    pubkey_ptr = create_string_buffer(64)
    ret = _libsecp256k1.secp256k1_ec_pubkey_parse(
        _libsecp256k1.ctx, pubkey_ptr, pubkey, len(pubkey))
    if 1 != ret:
        raise InvalidECPointException(
            f'public key could not be parsed or is invalid: {pubkey.hex()!r}')

    pubkey_serialized = create_string_buffer(65)
    pubkey_size = c_size_t(65)
    _libsecp256k1.secp256k1_ec_pubkey_serialize(
        _libsecp256k1.ctx, pubkey_serialized, byref(pubkey_size), pubkey_ptr, SECP256K1_EC_UNCOMPRESSED)
    pubkey_serialized = bytes(pubkey_serialized)
    assert pubkey_serialized[0] == 0x04, pubkey_serialized
    x = int.from_bytes(pubkey_serialized[1:33], byteorder='big', signed=False)
    y = int.from_bytes(pubkey_serialized[33:65], byteorder='big', signed=False)
    return x, y


class InvalidECPointException(Exception):
    """e.g. not on curve, or infinity"""


@functools.total_ordering
class ECPubkey(object):

    def __init__(self, b: Optional[bytes]):
        if b is not None:
            assert isinstance(b, (bytes, bytearray)), f'pubkey must be bytes-like, not {type(b)}'
            if isinstance(b, bytearray):
                b = bytes(b)
            self._x, self._y = _x_and_y_from_pubkey_bytes(b)
        else:
            self._x, self._y = None, None

    @classmethod
    def from_ecdsa_sig64(cls, sig64: bytes, recid: int, msg32: bytes) -> 'ECPubkey':
        assert_bytes(sig64)
        if len(sig64) != 64:
            raise Exception(f'wrong encoding used for signature? len={len(sig64)} (should be 64)')
        if not (0 <= recid <= 3):
            raise ValueError('recid is {}, but should be 0 <= recid <= 3'.format(recid))
        assert isinstance(msg32, (bytes, bytearray)), type(msg32)
        assert len(msg32) == 32, len(msg32)
        sig65 = create_string_buffer(65)
        ret = _libsecp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact(
            _libsecp256k1.ctx, sig65, sig64, recid)
        if 1 != ret:
            raise Exception('failed to parse signature')
        pubkey = create_string_buffer(64)
        ret = _libsecp256k1.secp256k1_ecdsa_recover(_libsecp256k1.ctx, pubkey, sig65, msg32)
        if 1 != ret:
            raise InvalidECPointException('failed to recover public key')
        return ECPubkey._from_libsecp256k1_pubkey_ptr(pubkey)

    @classmethod
    def from_ecdsa_sig65(cls, sig65: bytes, msg32: bytes) -> Tuple['ECPubkey', bool, Optional[str]]:
        assert_bytes(sig65)
        if len(sig65) != 65:
            raise Exception(f'wrong encoding used for signature? len={len(sig65)} (should be 65)')
        nV = sig65[0]
        # as per BIP-0137:
        #     27-30: p2pkh (uncompressed)
        #     31-34: p2pkh (compressed)
        #     35-38: p2wpkh-p2sh
        #     39-42: p2wpkh
        # However, the signatures we create do not respect this, and we instead always use 27-34,
        # only distinguishing between compressed/uncompressed, so we treat those values as "any".
        if not (27 <= nV <= 42):
            raise Exception("Bad encoding")
        txin_type_guess = None
        compressed = True
        if nV >= 39:
            nV -= 12
            txin_type_guess = "p2wpkh"
        elif nV >= 35:
            nV -= 8
            txin_type_guess = "p2wpkh-p2sh"
        elif nV >= 31:
            nV -= 4
        else:
            compressed = False
        recid = nV - 27
        pubkey = cls.from_ecdsa_sig64(sig65[1:], recid, msg32)
        return pubkey, compressed, txin_type_guess

    @classmethod
    def from_x_and_y(cls, x: int, y: int) -> 'ECPubkey':
        _bytes = (b'\x04'
                  + int.to_bytes(x, length=32, byteorder='big', signed=False)
                  + int.to_bytes(y, length=32, byteorder='big', signed=False))
        return ECPubkey(_bytes)

    def get_public_key_bytes(self, compressed=True) -> bytes:
        if self.is_at_infinity(): raise Exception('point is at infinity')
        x = int.to_bytes(self.x(), length=32, byteorder='big', signed=False)
        y = int.to_bytes(self.y(), length=32, byteorder='big', signed=False)
        if compressed:
            header = b'\x03' if self.y() & 1 else b'\x02'
            return header + x
        else:
            header = b'\x04'
            return header + x + y

    def get_public_key_hex(self, compressed=True) -> str:
        return self.get_public_key_bytes(compressed).hex()

    def point(self) -> Tuple[Optional[int], Optional[int]]:
        x = self.x()
        y = self.y()
        assert (x is None) == (y is None), f"either both x and y, or neither should be None. {(x, y)=}"
        return x, y

    def x(self) -> Optional[int]:
        return self._x

    def y(self) -> Optional[int]:
        return self._y

    def _to_libsecp256k1_pubkey_ptr(self):
        """pointer to `secp256k1_pubkey` C struct"""
        pubkey_ptr = create_string_buffer(64)
        pk_bytes = self.get_public_key_bytes(compressed=False)
        ret = _libsecp256k1.secp256k1_ec_pubkey_parse(
            _libsecp256k1.ctx, pubkey_ptr, pk_bytes, len(pk_bytes))
        if 1 != ret:
            raise Exception(f'public key could not be parsed or is invalid: {pk_bytes.hex()!r}')
        return pubkey_ptr

    def _to_libsecp256k1_xonly_pubkey_ptr(self):
        """pointer to `secp256k1_xonly_pubkey` C struct"""
        if not ecc_fast.HAS_SCHNORR:
            raise LibModuleMissing(
                'libsecp256k1 library found but it was built '
                'without required modules (--enable-module-schnorrsig --enable-module-extrakeys)')
        pubkey_ptr = create_string_buffer(64)
        pk_bytes = self.get_public_key_bytes(compressed=True)[1:]
        ret = _libsecp256k1.secp256k1_xonly_pubkey_parse(
            _libsecp256k1.ctx, pubkey_ptr, pk_bytes)
        if 1 != ret:
            raise Exception(f'public key could not be parsed or is invalid: {pk_bytes.hex()!r}')
        return pubkey_ptr

    @classmethod
    def _from_libsecp256k1_pubkey_ptr(cls, pubkey) -> 'ECPubkey':
        pubkey_serialized = create_string_buffer(65)
        pubkey_size = c_size_t(65)
        _libsecp256k1.secp256k1_ec_pubkey_serialize(
            _libsecp256k1.ctx, pubkey_serialized, byref(pubkey_size), pubkey, SECP256K1_EC_UNCOMPRESSED)
        return ECPubkey(bytes(pubkey_serialized))

    def __repr__(self):
        if self.is_at_infinity():
            return f"<ECPubkey infinity>"
        return f"<ECPubkey {self.get_public_key_hex()}>"

    def __mul__(self, other: int):
        if not isinstance(other, int):
            raise TypeError('multiplication not defined for ECPubkey and {}'.format(type(other)))

        other %= CURVE_ORDER
        if self.is_at_infinity() or other == 0:
            return POINT_AT_INFINITY
        pubkey = self._to_libsecp256k1_pubkey_ptr()

        ret = _libsecp256k1.secp256k1_ec_pubkey_tweak_mul(_libsecp256k1.ctx, pubkey, other.to_bytes(32, byteorder="big"))
        if 1 != ret:
            return POINT_AT_INFINITY
        return ECPubkey._from_libsecp256k1_pubkey_ptr(pubkey)

    def __rmul__(self, other: int):
        return self * other

    def __add__(self, other):
        if not isinstance(other, ECPubkey):
            raise TypeError('addition not defined for ECPubkey and {}'.format(type(other)))
        if self.is_at_infinity(): return other
        if other.is_at_infinity(): return self

        pubkey1 = self._to_libsecp256k1_pubkey_ptr()
        pubkey2 = other._to_libsecp256k1_pubkey_ptr()
        pubkey_sum = create_string_buffer(64)

        pubkey1 = cast(pubkey1, c_char_p)
        pubkey2 = cast(pubkey2, c_char_p)
        array_of_pubkey_ptrs = (c_char_p * 2)(pubkey1, pubkey2)
        ret = _libsecp256k1.secp256k1_ec_pubkey_combine(_libsecp256k1.ctx, pubkey_sum, array_of_pubkey_ptrs, 2)
        if 1 != ret:
            return POINT_AT_INFINITY
        return ECPubkey._from_libsecp256k1_pubkey_ptr(pubkey_sum)

    def __eq__(self, other) -> bool:
        if not isinstance(other, ECPubkey):
            return False
        return self.point() == other.point()

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.point())

    def __lt__(self, other):
        if not isinstance(other, ECPubkey):
            raise TypeError('comparison not defined for ECPubkey and {}'.format(type(other)))
        p1 = ((self.x() or 0), (self.y() or 0))
        p2 = ((other.x() or 0), (other.y() or 0))
        return p1 < p2

    def ecdsa_verify_recoverable(self, sig65: bytes, msg32: bytes) -> bool:
        try:
            public_key, _compressed, _txin_type_guess = self.from_ecdsa_sig65(sig65, msg32)
        except Exception:
            return False
        # check public key
        if public_key != self:
            return False
        # check message
        return self.ecdsa_verify(sig65[1:], msg32)

    def ecdsa_verify(
        self,
        sig64: bytes,
        msg32: bytes,
        *,
        enforce_low_s: bool = True,  # policy/standardness rule
    ) -> bool:
        assert_bytes(sig64)
        if len(sig64) != 64:
            return False
        if not (isinstance(msg32, bytes) and len(msg32) == 32):
            return False

        sig = create_string_buffer(64)
        ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_libsecp256k1.ctx, sig, sig64)
        if 1 != ret:
            return False
        if not enforce_low_s:
            ret = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)

        pubkey = self._to_libsecp256k1_pubkey_ptr()
        if 1 != _libsecp256k1.secp256k1_ecdsa_verify(_libsecp256k1.ctx, sig, msg32, pubkey):
            return False
        return True

    def schnorr_verify(self, sig64: bytes, msg32: bytes) -> bool:
        assert isinstance(sig64, bytes), type(sig64)
        assert len(sig64) == 64, len(sig64)
        assert isinstance(msg32, bytes), type(msg32)
        assert len(msg32) == 32, len(msg32)
        if not ecc_fast.HAS_SCHNORR:
            raise LibModuleMissing(
                'libsecp256k1 library found but it was built '
                'without required modules (--enable-module-schnorrsig --enable-module-extrakeys)')
        msglen = 32
        pubkey = self._to_libsecp256k1_xonly_pubkey_ptr()
        if 1 != _libsecp256k1.secp256k1_schnorrsig_verify(_libsecp256k1.ctx, sig64, msg32, msglen, pubkey):
            return False
        return True

    @classmethod
    def order(cls) -> int:
        return CURVE_ORDER

    def is_at_infinity(self) -> bool:
        return self == POINT_AT_INFINITY

    @classmethod
    def is_pubkey_bytes(cls, b: bytes) -> bool:
        try:
            ECPubkey(b)
            return True
        except Exception:
            return False

    def has_even_y(self) -> bool:
        return self.y() % 2 == 0


GENERATOR = ECPubkey(bytes.fromhex('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
                                   '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'))
CURVE_ORDER = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
POINT_AT_INFINITY = ECPubkey(None)



def is_secret_within_curve_range(secret: Union[int, bytes]) -> bool:
    if isinstance(secret, bytes):
        secret = string_to_number(secret)
    return 0 < secret < CURVE_ORDER


class ECPrivkey(ECPubkey):

    def __init__(self, privkey_bytes: bytes):
        assert_bytes(privkey_bytes)
        if len(privkey_bytes) != 32:
            raise Exception('unexpected size for secret. should be 32 bytes, not {}'.format(len(privkey_bytes)))
        secret = string_to_number(privkey_bytes)
        if not is_secret_within_curve_range(secret):
            raise InvalidECPointException('Invalid secret scalar (not within curve order)')
        self.secret_scalar = secret

        pubkey = GENERATOR * secret
        super().__init__(pubkey.get_public_key_bytes(compressed=False))

    @classmethod
    def from_secret_scalar(cls, secret_scalar: int) -> 'ECPrivkey':
        secret_bytes = int.to_bytes(secret_scalar, length=32, byteorder='big', signed=False)
        return ECPrivkey(secret_bytes)

    @classmethod
    def from_arbitrary_size_secret(cls, privkey_bytes: bytes) -> 'ECPrivkey':
        """This method is only for legacy reasons. Do not introduce new code that uses it.
        Unlike the default constructor, this method does not require len(privkey_bytes) == 32,
        and the secret does not need to be within the curve order either.
        """
        return ECPrivkey(cls.normalize_secret_bytes(privkey_bytes))

    @classmethod
    def normalize_secret_bytes(cls, privkey_bytes: bytes) -> bytes:
        scalar = string_to_number(privkey_bytes) % CURVE_ORDER
        if scalar == 0:
            raise Exception('invalid EC private key scalar: zero')
        privkey_32bytes = int.to_bytes(scalar, length=32, byteorder='big', signed=False)
        return privkey_32bytes

    def __repr__(self):
        return f"<ECPrivkey {self.get_public_key_hex()}>"

    @classmethod
    def generate_random_key(cls) -> 'ECPrivkey':
        randint = secrets.randbelow(CURVE_ORDER - 1) + 1
        ephemeral_exponent = int.to_bytes(randint, length=32, byteorder='big', signed=False)
        return ECPrivkey(ephemeral_exponent)

    def get_secret_bytes(self) -> bytes:
        return int.to_bytes(self.secret_scalar, length=32, byteorder='big', signed=False)

    def ecdsa_sign(self, msg32: bytes, *, sigencode=None) -> bytes:
        if not (isinstance(msg32, bytes) and len(msg32) == 32):
            raise Exception("msg32 to be signed must be bytes, and 32 bytes exactly")
        if sigencode is None:
            sigencode = ecdsa_sig64_from_r_and_s

        privkey_bytes = self.secret_scalar.to_bytes(32, byteorder="big")
        nonce_function = None
        sig = create_string_buffer(64)
        def sign_with_extra_entropy(extra_entropy):
            ret = _libsecp256k1.secp256k1_ecdsa_sign(
                _libsecp256k1.ctx, sig, msg32, privkey_bytes,
                nonce_function, extra_entropy)
            if 1 != ret:
                raise Exception('the nonce generation function failed, or the private key was invalid')
            compact_signature = create_string_buffer(64)
            _libsecp256k1.secp256k1_ecdsa_signature_serialize_compact(_libsecp256k1.ctx, compact_signature, sig)
            r = int.from_bytes(compact_signature[:32], byteorder="big")
            s = int.from_bytes(compact_signature[32:], byteorder="big")
            return r, s

        r, s = sign_with_extra_entropy(extra_entropy=None)
        if ENABLE_ECDSA_R_VALUE_GRINDING:
            counter = 0
            while r >= 2**255:  # grind for low R value https://github.com/bitcoin/bitcoin/pull/13666
                counter += 1
                extra_entropy = counter.to_bytes(32, byteorder="little")
                r, s = sign_with_extra_entropy(extra_entropy=extra_entropy)

        sig64 = ecdsa_sig64_from_r_and_s(r, s)
        if not self.ecdsa_verify(sig64, msg32):
            raise Exception("sanity check failed: signature we just created does not verify!")

        sig = sigencode(r, s)
        return sig

    def schnorr_sign(self, msg32: bytes, *, aux_rand32: bytes = None) -> bytes:
        """Creates a BIP-340 schnorr signature for the given message (hash)
        and using the optional auxiliary random data.

        note: msg32 is supposed to be a 32 byte hash of the message to be signed.
              The BIP recommends using bip340_tagged_hash for hashing the message.
        """
        assert isinstance(msg32, bytes), type(msg32)
        assert len(msg32) == 32, len(msg32)
        if aux_rand32 is None:
            aux_rand32 = bytes(32)
        assert isinstance(aux_rand32, bytes), type(aux_rand32)
        assert len(aux_rand32) == 32, len(aux_rand32)
        if not ecc_fast.HAS_SCHNORR:
            raise LibModuleMissing(
                'libsecp256k1 library found but it was built '
                'without required modules (--enable-module-schnorrsig --enable-module-extrakeys)')
        # construct "keypair" obj
        privkey_bytes = self.secret_scalar.to_bytes(32, byteorder="big")
        keypair = create_string_buffer(96)
        ret = _libsecp256k1.secp256k1_keypair_create(_libsecp256k1.ctx, keypair, privkey_bytes)
        if 1 != ret:
            raise Exception('secret key was invalid')
        # sign msg and verify sig
        sig64 = create_string_buffer(64)
        ret = _libsecp256k1.secp256k1_schnorrsig_sign32(
            _libsecp256k1.ctx, sig64, msg32, keypair, aux_rand32)
        sig64 = bytes(sig64)
        if 1 != ret:
            raise Exception('signing failure')
        if not self.schnorr_verify(sig64, msg32):
            raise Exception("sanity check failed: signature we just created does not verify!")
        return sig64

    def ecdsa_sign_recoverable(self, msg32: bytes, *, is_compressed: bool) -> bytes:
        assert len(msg32) == 32, len(msg32)

        def bruteforce_recid(sig64: bytes):
            for recid in range(4):
                sig65 = construct_ecdsa_sig65(sig64, recid, is_compressed=is_compressed)
                if not self.ecdsa_verify_recoverable(sig65, msg32):
                    continue
                return sig65, recid
            else:
                raise Exception("error: cannot sign message. no recid fits..")

        sig64 = self.ecdsa_sign(msg32, sigencode=ecdsa_sig64_from_r_and_s)
        sig65, recid = bruteforce_recid(sig64)
        return sig65



def construct_ecdsa_sig65(sig64: bytes, recid: int, *, is_compressed: bool) -> bytes:
    comp = 4 if is_compressed else 0
    return bytes([27 + recid + comp]) + sig64


