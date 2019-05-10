#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
'''
Schnorr sign/verify bindings for libsecp256k1. Requries secp256k1.py.

In the future this file perhaps can also contain bindings that use OpenSSL and
even Python-only Schnorr sign/verify as a fallback if secp256k1 is unavailable.
'''
import os
import sys
from ctypes import create_string_buffer, c_void_p, c_char_p, c_int, c_size_t

from . import secp256k1


class SecpMissing(RuntimeError):
    ''' Base class of the below two exception classes '''

class SecpMissingLibrary(SecpMissing):
    ''' Raised to indicate we are missing libsecp256k1 '''

class SecpMissingSchnorr(SecpMissing):
    ''' Raised to indicate we are missing the requisite Schnorr functions from
    libsecp256k1, even though we have libsecp256k1 '''

def _boilerplate_secp_check(which):
    if not secp256k1.secp256k1:
        raise SecpMissingLibrary('Missing library libsecp256k1, or the library could not be loaded')
    if which is None:
        raise SecpMissingSchnorr('libsecp256k1 found, but the Schnorr module is missing and/or not compiled-in')

def _setup_sign_function():
    if not secp256k1.secp256k1:
        return None
    try:
        # Try and find the symbol in the lib. If it's not there, it means we
        # were likely using Core's lib which lacks schnorr.
        secp256k1.secp256k1.secp256k1_schnorr_sign.argtypes = [ c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p ]
        secp256k1.secp256k1.secp256k1_schnorr_sign.restype = c_int
    except AttributeError:
        return None
    return secp256k1.secp256k1.secp256k1_schnorr_sign

def _setup_verify_function():
    if not secp256k1.secp256k1:
        return None
    try:
        # Try and find the symbol in the lib. If it's not there, it means we
        # were likely using Core's lib which lacks schnorr.
        secp256k1.secp256k1.secp256k1_schnorr_verify.argtypes = [ c_void_p, c_void_p, c_void_p, c_void_p ]
        secp256k1.secp256k1.secp256k1_schnorr_verify.restype = c_int
    except AttributeError:
        return None
    return secp256k1.secp256k1.secp256k1_schnorr_verify

_secp256k1_schnorr_sign = _setup_sign_function()
_secp256k1_schnorr_verify = _setup_verify_function()

def sign(privkey, message_hash):
    ''' May raise a SecpMissing subclass or ValueError on failure

    Will return either: the 64-byte signature as a bytes object, or an empty
    bytes object b'' on failure.  Failure can occur due to an invalid private
    key.

    `privkey` should be the 32 byte raw private key (as you would get from
    bitcoin.deserialize_privkey, etc).

    `message_hash` should be the 32 byte sha256d hash of the tx input (or
    message) you want to sign'''

    _boilerplate_secp_check(_secp256k1_schnorr_sign)

    if not isinstance(privkey, bytes) or len(privkey) != 32:
        raise ValueError('privkey must be a bytes object of length 32')
    if not isinstance(message_hash, bytes) or len(message_hash) != 32:
        raise ValueError('message_hash must be a bytes object of length 32')

    sig = create_string_buffer(64)
    res = _secp256k1_schnorr_sign(
        secp256k1.secp256k1.ctx, sig, message_hash, privkey, None, None
    )
    if not res:
        # 'privkey' was not a valid private key
        return b''
    return bytes(sig)

def verify(pubkey, signature, message_hash):
    ''' May raise a SecpMissing subclass or ValueError on failure

    Will return 1 if correct signature, 0 if incorrect

    `pubkey` should be the the raw public key bytes (as you would get from
    bitcoin.pubic_key_from_private_key, after hex decoding, etc).

    `signature` should be the 64 byte schnorr signature as would be returned
    from `sign` above.

    `message_hash` should be the 32 byte sha256d hash of the tx message to be
    verified'''

    _boilerplate_secp_check(_secp256k1_schnorr_verify)

    if not isinstance(pubkey, bytes) or len(pubkey) not in (33, 65):
        raise ValueError('pubkey must be a bytes object of either length 33 or 65')
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError('signature must be a bytes object of length 64')
    if not isinstance(message_hash, bytes) or len(message_hash) != 32:
        raise ValueError('message_hash must be a bytes object of length 32')
    pubkey_parsed = create_string_buffer(64)
    res = secp256k1.secp256k1.secp256k1_ec_pubkey_parse(
        secp256k1.secp256k1.ctx, pubkey_parsed, pubkey, c_size_t(len(pubkey))
    )
    if not res:
        raise ValueError('pubkey could not be parsed by the secp256k1 library')
    res = _secp256k1_schnorr_verify(
        secp256k1.secp256k1.ctx, signature, message_hash, pubkey_parsed
    )
    return int(res)

def is_available():
    ''' Returns True iff libsecp was found and it contains the requisite
    functions to perform Schnorr sign and verify, False otherwise. '''
    return bool(_secp256k1_schnorr_sign and _secp256k1_schnorr_verify)
