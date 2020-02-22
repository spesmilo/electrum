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


class LibModuleMissing(Exception): pass


def load_library():
    if sys.platform == 'darwin':
        library_paths = (os.path.join(os.path.dirname(__file__), 'libsecp256k1.0.dylib'),
                         'libsecp256k1.0.dylib')
    elif sys.platform in ('windows', 'win32'):
        library_paths = (os.path.join(os.path.dirname(__file__), 'libsecp256k1-0.dll'),
                         'libsecp256k1-0.dll')
    elif 'ANDROID_DATA' in os.environ:
        library_paths = ('libsecp256k1.so',)
    else:  # desktop Linux and similar
        library_paths = (os.path.join(os.path.dirname(__file__), 'libsecp256k1.so.0'),
                         'libsecp256k1.so.0')

    exceptions = []
    secp256k1 = None
    for libpath in library_paths:
        try:
            secp256k1 = ctypes.cdll.LoadLibrary(libpath)
        except BaseException as e:
            exceptions.append(e)
        else:
            break
    if not secp256k1:
        _logger.error(f'libsecp256k1 library failed to load. exceptions: {repr(exceptions)}')
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

        # --enable-module-recovery
        try:
            secp256k1.secp256k1_ecdsa_recover.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
            secp256k1.secp256k1_ecdsa_recover.restype = c_int

            secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.argtypes = [c_void_p, c_char_p, c_char_p, c_int]
            secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.restype = c_int
        except (OSError, AttributeError):
            raise LibModuleMissing('libsecp256k1 library found but it was built '
                                   'without required module (--enable-module-recovery)')

        secp256k1.ctx = secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        ret = secp256k1.secp256k1_context_randomize(secp256k1.ctx, os.urandom(32))
        if not ret:
            _logger.error('secp256k1_context_randomize failed')
            return None

        return secp256k1
    except (OSError, AttributeError) as e:
        _logger.error(f'libsecp256k1 library was found and loaded but there was an error when using it: {repr(e)}')
        return None


_libsecp256k1 = None
try:
    _libsecp256k1 = load_library()
except BaseException as e:
    _logger.error(f'failed to load libsecp256k1: {repr(e)}')


if _libsecp256k1 is None:
    # hard fail:
    sys.exit(f"Error: Failed to load libsecp256k1.")
