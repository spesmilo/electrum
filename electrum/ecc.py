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

import base64
import hashlib
import functools
from typing import Union, Tuple, Optional
from ctypes import (
    byref, c_byte, c_int, c_uint, c_char_p, c_size_t, c_void_p, create_string_buffer,
    CFUNCTYPE, POINTER, cast
)

from .util import bfh, assert_bytes, to_bytes, InvalidPassword, profiler, randrange
from .crypto import (sha256d, aes_encrypt_with_iv, aes_decrypt_with_iv, hmac_oneshot)
from . import constants
from .logging import get_logger
from .ecc_fast import _libsecp256k1, SECP256K1_EC_UNCOMPRESSED

_logger = get_logger(__name__)


# Some unit tests need to create ECDSA sigs without grinding the R value (and just use RFC6979).
# see https://github.com/bitcoin/bitcoin/pull/13666
ENABLE_ECDSA_R_VALUE_GRINDING = True


def string_to_number(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big', signed=False)


def sig_string_from_der_sig(der_sig: bytes) -> bytes:
    r, s = get_r_and_s_from_der_sig(der_sig)
    return sig_string_from_r_and_s(r, s)


def der_sig_from_sig_string(sig_string: bytes) -> bytes:
    r, s = get_r_and_s_from_sig_string(sig_string)
    return der_sig_from_r_and_s(r, s)


def der_sig_from_r_and_s(r: int, s: int) -> bytes:
    sig_string = (int.to_bytes(r, length=32, byteorder="big") +
                  int.to_bytes(s, length=32, byteorder="big"))
    sig = create_string_buffer(64)
    ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_libsecp256k1.ctx, sig, sig_string)
    if not ret:
        raise Exception("Bad signature")
    ret = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)
    der_sig = create_string_buffer(80)  # this much space should be enough
    der_sig_size = c_size_t(len(der_sig))
    ret = _libsecp256k1.secp256k1_ecdsa_signature_serialize_der(_libsecp256k1.ctx, der_sig, byref(der_sig_size), sig)
    if not ret:
        raise Exception("failed to serialize DER sig")
    der_sig_size = der_sig_size.value
    return bytes(der_sig)[:der_sig_size]


def get_r_and_s_from_der_sig(der_sig: bytes) -> Tuple[int, int]:
    assert isinstance(der_sig, bytes)
    sig = create_string_buffer(64)
    ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_der(_libsecp256k1.ctx, sig, der_sig, len(der_sig))
    if not ret:
        raise Exception("Bad signature")
    ret = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)
    compact_signature = create_string_buffer(64)
    _libsecp256k1.secp256k1_ecdsa_signature_serialize_compact(_libsecp256k1.ctx, compact_signature, sig)
    r = int.from_bytes(compact_signature[:32], byteorder="big")
    s = int.from_bytes(compact_signature[32:], byteorder="big")
    return r, s


def get_r_and_s_from_sig_string(sig_string: bytes) -> Tuple[int, int]:
    if not (isinstance(sig_string, bytes) and len(sig_string) == 64):
        raise Exception("sig_string must be bytes, and 64 bytes exactly")
    sig = create_string_buffer(64)
    ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_libsecp256k1.ctx, sig, sig_string)
    if not ret:
        raise Exception("Bad signature")
    ret = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)
    compact_signature = create_string_buffer(64)
    _libsecp256k1.secp256k1_ecdsa_signature_serialize_compact(_libsecp256k1.ctx, compact_signature, sig)
    r = int.from_bytes(compact_signature[:32], byteorder="big")
    s = int.from_bytes(compact_signature[32:], byteorder="big")
    return r, s


def sig_string_from_r_and_s(r: int, s: int) -> bytes:
    sig_string = (int.to_bytes(r, length=32, byteorder="big") +
                  int.to_bytes(s, length=32, byteorder="big"))
    sig = create_string_buffer(64)
    ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_libsecp256k1.ctx, sig, sig_string)
    if not ret:
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
    if not ret:
        raise InvalidECPointException('public key could not be parsed or is invalid')

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
    def from_sig_string(cls, sig_string: bytes, recid: int, msg_hash: bytes) -> 'ECPubkey':
        assert_bytes(sig_string)
        if len(sig_string) != 64:
            raise Exception(f'wrong encoding used for signature? len={len(sig_string)} (should be 64)')
        if not (0 <= recid <= 3):
            raise ValueError('recid is {}, but should be 0 <= recid <= 3'.format(recid))
        sig65 = create_string_buffer(65)
        ret = _libsecp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact(
            _libsecp256k1.ctx, sig65, sig_string, recid)
        if not ret:
            raise Exception('failed to parse signature')
        pubkey = create_string_buffer(64)
        ret = _libsecp256k1.secp256k1_ecdsa_recover(_libsecp256k1.ctx, pubkey, sig65, msg_hash)
        if not ret:
            raise InvalidECPointException('failed to recover public key')
        return ECPubkey._from_libsecp256k1_pubkey_ptr(pubkey)

    @classmethod
    def from_signature65(cls, sig: bytes, msg_hash: bytes) -> Tuple['ECPubkey', bool, Optional[str]]:
        if len(sig) != 65:
            raise Exception(f'wrong encoding used for signature? len={len(sig)} (should be 65)')
        nV = sig[0]
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
        pubkey = cls.from_sig_string(sig[1:], recid, msg_hash)
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
        pubkey = create_string_buffer(64)
        public_pair_bytes = self.get_public_key_bytes(compressed=False)
        ret = _libsecp256k1.secp256k1_ec_pubkey_parse(
            _libsecp256k1.ctx, pubkey, public_pair_bytes, len(public_pair_bytes))
        if not ret:
            raise Exception('public key could not be parsed or is invalid')
        return pubkey

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
        if not ret:
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
        if not ret:
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

    def verify_message_for_address(self, sig65: bytes, message: bytes, algo=lambda x: sha256d(msg_magic(x))) -> bool:
        assert_bytes(message)
        h = algo(message)
        try:
            public_key, compressed, txin_type_guess = self.from_signature65(sig65, h)
        except Exception:
            return False
        # check public key
        if public_key != self:
            return False
        # check message
        return self.verify_message_hash(sig65[1:], h)

    def verify_message_hash(self, sig_string: bytes, msg_hash: bytes) -> bool:
        assert_bytes(sig_string)
        if len(sig_string) != 64:
            return False
        if not (isinstance(msg_hash, bytes) and len(msg_hash) == 32):
            return False

        sig = create_string_buffer(64)
        ret = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_libsecp256k1.ctx, sig, sig_string)
        if not ret:
            return False
        ret = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)

        pubkey = self._to_libsecp256k1_pubkey_ptr()
        if 1 != _libsecp256k1.secp256k1_ecdsa_verify(_libsecp256k1.ctx, sig, msg_hash, pubkey):
            return False
        return True

    def encrypt_message(self, message: bytes, magic: bytes = b'BIE1') -> bytes:
        """
        ECIES encryption/decryption methods; AES-128-CBC with PKCS7 is used as the cipher; hmac-sha256 is used as the mac
        """
        assert_bytes(message)

        ephemeral = ECPrivkey.generate_random_key()
        ecdh_key = (self * ephemeral.secret_scalar).get_public_key_bytes(compressed=True)
        key = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        ciphertext = aes_encrypt_with_iv(key_e, iv, message)
        ephemeral_pubkey = ephemeral.get_public_key_bytes(compressed=True)
        encrypted = magic + ephemeral_pubkey + ciphertext
        mac = hmac_oneshot(key_m, encrypted, hashlib.sha256)

        return base64.b64encode(encrypted + mac)

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


GENERATOR = ECPubkey(bytes.fromhex('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
                                   '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'))
CURVE_ORDER = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
POINT_AT_INFINITY = ECPubkey(None)


def msg_magic(message: bytes) -> bytes:
    from .bitcoin import var_int
    length = bfh(var_int(len(message)))
    return b"\x18Bitcoin Signed Message:\n" + length + message


def verify_signature(pubkey: bytes, sig: bytes, h: bytes) -> bool:
    return ECPubkey(pubkey).verify_message_hash(sig, h)


def verify_message_with_address(address: str, sig65: bytes, message: bytes, *, net=None) -> bool:
    from .bitcoin import pubkey_to_address
    assert_bytes(sig65, message)
    if net is None: net = constants.net
    h = sha256d(msg_magic(message))
    try:
        public_key, compressed, txin_type_guess = ECPubkey.from_signature65(sig65, h)
    except Exception as e:
        return False
    # check public key using the address
    pubkey_hex = public_key.get_public_key_hex(compressed)
    txin_types = (txin_type_guess,) if txin_type_guess else ('p2pkh', 'p2wpkh', 'p2wpkh-p2sh')
    for txin_type in txin_types:
        addr = pubkey_to_address(txin_type, pubkey_hex, net=net)
        if address == addr:
            break
    else:
        return False
    # check message
    return public_key.verify_message_hash(sig65[1:], h)


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
        randint = randrange(CURVE_ORDER)
        ephemeral_exponent = int.to_bytes(randint, length=32, byteorder='big', signed=False)
        return ECPrivkey(ephemeral_exponent)

    def get_secret_bytes(self) -> bytes:
        return int.to_bytes(self.secret_scalar, length=32, byteorder='big', signed=False)

    def sign(self, msg_hash: bytes, sigencode=None) -> bytes:
        if not (isinstance(msg_hash, bytes) and len(msg_hash) == 32):
            raise Exception("msg_hash to be signed must be bytes, and 32 bytes exactly")
        if sigencode is None:
            sigencode = sig_string_from_r_and_s

        privkey_bytes = self.secret_scalar.to_bytes(32, byteorder="big")
        nonce_function = None
        sig = create_string_buffer(64)
        def sign_with_extra_entropy(extra_entropy):
            ret = _libsecp256k1.secp256k1_ecdsa_sign(
                _libsecp256k1.ctx, sig, msg_hash, privkey_bytes,
                nonce_function, extra_entropy)
            if not ret:
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

        sig_string = sig_string_from_r_and_s(r, s)
        if not self.verify_message_hash(sig_string, msg_hash):
            raise Exception("sanity check failed: signature we just created does not verify!")

        sig = sigencode(r, s)
        return sig

    def sign_transaction(self, hashed_preimage: bytes) -> bytes:
        return self.sign(hashed_preimage, sigencode=der_sig_from_r_and_s)

    def sign_message(
            self,
            message: Union[bytes, str],
            is_compressed: bool,
            algo=lambda x: sha256d(msg_magic(x)),
    ) -> bytes:
        def bruteforce_recid(sig_string):
            for recid in range(4):
                sig65 = construct_sig65(sig_string, recid, is_compressed)
                if not self.verify_message_for_address(sig65, message, algo):
                    continue
                return sig65, recid
            else:
                raise Exception("error: cannot sign message. no recid fits..")

        message = to_bytes(message, 'utf8')
        msg_hash = algo(message)
        sig_string = self.sign(msg_hash, sigencode=sig_string_from_r_and_s)
        sig65, recid = bruteforce_recid(sig_string)
        return sig65

    def decrypt_message(self, encrypted: Union[str, bytes], magic: bytes=b'BIE1') -> bytes:
        encrypted = base64.b64decode(encrypted)  # type: bytes
        if len(encrypted) < 85:
            raise Exception('invalid ciphertext: length')
        magic_found = encrypted[:4]
        ephemeral_pubkey_bytes = encrypted[4:37]
        ciphertext = encrypted[37:-32]
        mac = encrypted[-32:]
        if magic_found != magic:
            raise Exception('invalid ciphertext: invalid magic bytes')
        try:
            ephemeral_pubkey = ECPubkey(ephemeral_pubkey_bytes)
        except InvalidECPointException as e:
            raise Exception('invalid ciphertext: invalid ephemeral pubkey') from e
        ecdh_key = (ephemeral_pubkey * self.secret_scalar).get_public_key_bytes(compressed=True)
        key = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        if mac != hmac_oneshot(key_m, encrypted[:-32], hashlib.sha256):
            raise InvalidPassword()
        return aes_decrypt_with_iv(key_e, iv, ciphertext)


def construct_sig65(sig_string: bytes, recid: int, is_compressed: bool) -> bytes:
    comp = 4 if is_compressed else 0
    return bytes([27 + recid + comp]) + sig_string
