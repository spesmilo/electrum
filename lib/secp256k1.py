#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
'''
secp256k1 - Maintain a single global secp256k1 context. ecc_fast.py and
schnorr.py make use of this context to do fast ECDSA signing or Schnorr signing,
respectively.
'''
import os
import sys
import ctypes
from ctypes.util import find_library
from ctypes import (
    byref, c_byte, c_int, c_uint, c_char_p, c_size_t, c_void_p, create_string_buffer, CFUNCTYPE, POINTER
)

from .util import print_stderr

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


def _load_library():
    if sys.platform == 'darwin':
        library_paths = ('libsecp256k1.0.dylib',  # on Mac it's in the pyinstaller top level folder, which is in libpath
                         os.path.join(os.path.dirname(__file__), 'libsecp256k1.0.dylib'))  # fall back to "running from source" mode lib/ folder
    elif sys.platform in ('windows', 'win32'):
        library_paths = ('libsecp256k1-0.dll',  # on Windows it's in the pyinstaller top level folder, which is in the path
                         os.path.join(os.path.dirname(__file__), 'libsecp256k1-0.dll'))  # does running from source even make sense on Windows? Enquiring minds want to know.
    elif 'ANDROID_DATA' in os.environ:
        # We don't actually use coincurve's Python API, it's just a convenient way to load
        # libsecp256k1.
        import coincurve  # noqa: F401
        library_paths = 'libsecp256k1.so',
    elif sys.platform == 'ios':
        # On iOS, we link secp256k1 directly into the produced binary. We load
        # the current executable as a shared library (this works on darwin/iOS).
        # iOS build note: In Xcode you need to set "Symbols Hidden by Default"
        # to "No" for Debug & Release builds for this to work.
        library_paths =  (sys.executable,)
    else:
        library_paths = (os.path.join(os.path.dirname(__file__), 'libsecp256k1.so.0'),  # on linux we install it alongside the python scripts.
                         'libsecp256k1.so.0')  # fall back to system lib, if any

    secp256k1 = None
    for lp in library_paths:
        try:
            secp256k1 = ctypes.cdll.LoadLibrary(lp)
        except:
            continue
        if secp256k1:
            break
    if not secp256k1:
        print_stderr('[secp256k1] warning: libsecp256k1 library failed to load')
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

        secp256k1.secp256k1_ec_pubkey_combine.argtypes = [c_void_p, c_void_p, POINTER(c_void_p), c_size_t]
        secp256k1.secp256k1_ec_pubkey_combine.restype = c_int

        secp256k1.ctx = secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        r = secp256k1.secp256k1_context_randomize(secp256k1.ctx, os.urandom(32))
        if r:
            return secp256k1
        else:
            print_stderr('[secp256k1] warning: secp256k1_context_randomize failed')
            return None
    except (OSError, AttributeError):
        print_stderr('[secp256k1] warning: libsecp256k1 library was found and loaded but there was an error when using it')
        return None

try:
    secp256k1 = _load_library()
except:
    secp256k1 = None
