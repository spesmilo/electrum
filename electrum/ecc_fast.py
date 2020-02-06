# taken (with minor modifications) from pycoin
# https://github.com/richardkiss/pycoin/blob/01b1787ed902df23f99a55deb00d8cd076a906fe/pycoin/ecdsa/native/secp256k1.py

import os
import sys
import traceback
import ctypes
from ctypes import (
    byref, c_byte, c_int, c_uint, c_char_p, c_size_t, c_void_p, create_string_buffer,
    CFUNCTYPE, POINTER, cast
)

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

        secp256k1.secp256k1_ecdsa_signature_parse_der.argtypes = [c_void_p, c_char_p, c_char_p, c_size_t]
        secp256k1.secp256k1_ecdsa_signature_parse_der.restype = c_int

        secp256k1.secp256k1_ecdsa_signature_serialize_der.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p]
        secp256k1.secp256k1_ecdsa_signature_serialize_der.restype = c_int

        secp256k1.secp256k1_ec_pubkey_tweak_mul.argtypes = [c_void_p, c_char_p, c_char_p]
        secp256k1.secp256k1_ec_pubkey_tweak_mul.restype = c_int

        secp256k1.secp256k1_ec_pubkey_combine.argtypes = [c_void_p, c_char_p, c_void_p, c_size_t]
        secp256k1.secp256k1_ec_pubkey_combine.restype = c_int

        secp256k1.ctx = secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        ret = secp256k1.secp256k1_context_randomize(secp256k1.ctx, os.urandom(32))
        if ret:
            return secp256k1
        else:
            _logger.warning('secp256k1_context_randomize failed')
            return None
    except (OSError, AttributeError):
        _logger.warning('libsecp256k1 library was found and loaded but there was an error when using it')
        return None


def is_using_fast_ecc():
    return True  # TODO rm


try:
    _libsecp256k1 = load_library()
except BaseException as e:
    _logger.warning(f'failed to load libsecp256k1: {repr(e)}')
    _libsecp256k1 = None
