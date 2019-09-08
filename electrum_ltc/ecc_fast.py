# taken (with minor modifications) from pycoin
# https://github.com/richardkiss/pycoin/blob/01b1787ed902df23f99a55deb00d8cd076a906fe/pycoin/ecdsa/native/secp256k1.py

import os
import sys
import traceback
import ctypes
from ctypes.util import find_library
from ctypes import (
    byref, c_byte, c_int, c_uint, c_char_p, c_size_t, c_void_p, create_string_buffer, CFUNCTYPE, POINTER
)

import ecdsa

from .logging import get_logger


_logger = get_logger(__name__)


SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1)
SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
# /** The higher bits contain the actual data. Do not use directly. */
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

# /** Flags to pass to secp256k1_context_create. */
SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT)

SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)


def load_library():
    if sys.platform == 'darwin':
        library_path = 'libsecp256k1.0.dylib'
    elif sys.platform in ('windows', 'win32'):
        library_path = 'libsecp256k1.dll'
    elif 'ANDROID_DATA' in os.environ:
        library_path = 'libsecp256k1.so'
    else:
        library_path = 'libsecp256k1.so.0'

    secp256k1 = ctypes.cdll.LoadLibrary(library_path)
    if not secp256k1:
        _logger.warning('libsecp256k1 library failed to load')
        return None

    try:
        secp256k1.secp256k1_context_create.argtypes = [c_uint]
        secp256k1.secp256k1_context_create.restype = c_void_p

        secp256k1.secp256k1_context_randomize.argtypes = [c_void_p, c_char_p]
        secp256k1.secp256k1_context_randomize.restype = c_int

        secp256k1.secp256k1_ec_pubkey_create.argtypes = [c_void_p, c_void_p, c_char_p]
        secp256k1.secp256k1_ec_pubkey_create.restype = c_int

        secp256k1.secp256k1_ecdsa_sign.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_void_p, c_void_p]
        secp256k1.secp256k1_ecdsa_sign.restype = c_int

        secp256k1.secp256k1_ecdsa_verify.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_verify.restype = c_int

        secp256k1.secp256k1_ec_pubkey_parse.argtypes = [c_void_p, c_char_p, c_char_p, c_size_t]
        secp256k1.secp256k1_ec_pubkey_parse.restype = c_int

        secp256k1.secp256k1_ec_pubkey_serialize.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p, c_uint]
        secp256k1.secp256k1_ec_pubkey_serialize.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_parse_compact.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_parse_compact.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_normalize.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_normalize.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_serialize_compact.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_serialize_compact.restype = c_int

        secp256k1.secp256k1_ec_pubkey_tweak_mul.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ec_pubkey_tweak_mul.restype = c_int

        secp256k1.ctx = secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        r = secp256k1.secp256k1_context_randomize(secp256k1.ctx, os.urandom(32))
        if r:
            return secp256k1
        else:
            _logger.warning('secp256k1_context_randomize failed')
            return None
    except (OSError, AttributeError):
        _logger.warning('libsecp256k1 library was found and loaded but there was an error when using it')
        return None


class _patched_functions:
    prepared_to_patch = False
    monkey_patching_active = False


def _prepare_monkey_patching_of_python_ecdsa_internals_with_libsecp256k1():
    if not _libsecp256k1:
        return

    # save original functions so that we can undo patching (needed for tests)
    _patched_functions.orig_sign   = staticmethod(ecdsa.ecdsa.Private_key.sign)
    _patched_functions.orig_verify = staticmethod(ecdsa.ecdsa.Public_key.verifies)
    _patched_functions.orig_mul    = staticmethod(ecdsa.ellipticcurve.Point.__mul__)

    curve_secp256k1 = ecdsa.ecdsa.curve_secp256k1
    curve_order = ecdsa.curves.SECP256k1.order
    point_at_infinity = ecdsa.ellipticcurve.INFINITY

    def mul(self: ecdsa.ellipticcurve.Point, other: int):
        if self.curve() != curve_secp256k1:
            # this operation is not on the secp256k1 curve; use original implementation
            return _patched_functions.orig_mul(self, other)
        other %= curve_order
        if self == point_at_infinity or other == 0:
            return point_at_infinity
        pubkey = create_string_buffer(64)
        public_pair_bytes = b'\4' + self.x().to_bytes(32, byteorder="big") + self.y().to_bytes(32, byteorder="big")
        r = _libsecp256k1.secp256k1_ec_pubkey_parse(
            _libsecp256k1.ctx, pubkey, public_pair_bytes, len(public_pair_bytes))
        if not r:
            return False
        r = _libsecp256k1.secp256k1_ec_pubkey_tweak_mul(_libsecp256k1.ctx, pubkey, other.to_bytes(32, byteorder="big"))
        if not r:
            return point_at_infinity

        pubkey_serialized = create_string_buffer(65)
        pubkey_size = c_size_t(65)
        _libsecp256k1.secp256k1_ec_pubkey_serialize(
            _libsecp256k1.ctx, pubkey_serialized, byref(pubkey_size), pubkey, SECP256K1_EC_UNCOMPRESSED)
        x = int.from_bytes(pubkey_serialized[1:33], byteorder="big")
        y = int.from_bytes(pubkey_serialized[33:], byteorder="big")
        return ecdsa.ellipticcurve.Point(curve_secp256k1, x, y, curve_order)

    def sign(self: ecdsa.ecdsa.Private_key, hash: int, random_k: int):
        # note: random_k is ignored
        if self.public_key.curve != curve_secp256k1:
            # this operation is not on the secp256k1 curve; use original implementation
            return _patched_functions.orig_sign(self, hash, random_k)
        secret_exponent = self.secret_multiplier
        nonce_function = None
        sig = create_string_buffer(64)
        sig_hash_bytes = hash.to_bytes(32, byteorder="big")
        _libsecp256k1.secp256k1_ecdsa_sign(
            _libsecp256k1.ctx, sig, sig_hash_bytes, secret_exponent.to_bytes(32, byteorder="big"), nonce_function, None)
        compact_signature = create_string_buffer(64)
        _libsecp256k1.secp256k1_ecdsa_signature_serialize_compact(_libsecp256k1.ctx, compact_signature, sig)
        r = int.from_bytes(compact_signature[:32], byteorder="big")
        s = int.from_bytes(compact_signature[32:], byteorder="big")
        return ecdsa.ecdsa.Signature(r, s)

    def verify(self: ecdsa.ecdsa.Public_key, hash: int, signature: ecdsa.ecdsa.Signature):
        if self.curve != curve_secp256k1:
            # this operation is not on the secp256k1 curve; use original implementation
            return _patched_functions.orig_verify(self, hash, signature)
        sig = create_string_buffer(64)
        input64 = signature.r.to_bytes(32, byteorder="big") + signature.s.to_bytes(32, byteorder="big")
        r = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_libsecp256k1.ctx, sig, input64)
        if not r:
            return False
        r = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_libsecp256k1.ctx, sig, sig)

        public_pair_bytes = b'\4' + self.point.x().to_bytes(32, byteorder="big") + self.point.y().to_bytes(32, byteorder="big")
        pubkey = create_string_buffer(64)
        r = _libsecp256k1.secp256k1_ec_pubkey_parse(
            _libsecp256k1.ctx, pubkey, public_pair_bytes, len(public_pair_bytes))
        if not r:
            return False

        return 1 == _libsecp256k1.secp256k1_ecdsa_verify(_libsecp256k1.ctx, sig, hash.to_bytes(32, byteorder="big"), pubkey)

    # save new functions so that we can (re-)do patching
    _patched_functions.fast_sign   = sign
    _patched_functions.fast_verify = verify
    _patched_functions.fast_mul    = mul

    _patched_functions.prepared_to_patch = True


def do_monkey_patching_of_python_ecdsa_internals_with_libsecp256k1():
    if not _libsecp256k1:
        # FIXME logging 'verbosity' is not yet initialised
        _logger.info('libsecp256k1 library not available, falling back to python-ecdsa. '
                     'This means signing operations will be slower.')
        return
    if not _patched_functions.prepared_to_patch:
        raise Exception("can't patch python-ecdsa without preparations")
    ecdsa.ecdsa.Private_key.sign      = _patched_functions.fast_sign
    ecdsa.ecdsa.Public_key.verifies   = _patched_functions.fast_verify
    ecdsa.ellipticcurve.Point.__mul__ = _patched_functions.fast_mul
    # ecdsa.ellipticcurve.Point.__add__ = ...  # TODO??

    _patched_functions.monkey_patching_active = True


def undo_monkey_patching_of_python_ecdsa_internals_with_libsecp256k1():
    if not _libsecp256k1:
        return
    if not _patched_functions.prepared_to_patch:
        raise Exception("can't patch python-ecdsa without preparations")
    ecdsa.ecdsa.Private_key.sign      = _patched_functions.orig_sign
    ecdsa.ecdsa.Public_key.verifies   = _patched_functions.orig_verify
    ecdsa.ellipticcurve.Point.__mul__ = _patched_functions.orig_mul

    _patched_functions.monkey_patching_active = False


def is_using_fast_ecc():
    return _patched_functions.monkey_patching_active


try:
    _libsecp256k1 = load_library()
except:
    _libsecp256k1 = None

_prepare_monkey_patching_of_python_ecdsa_internals_with_libsecp256k1()
