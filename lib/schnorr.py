#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
'''
Schnorr sign/verify uses Requries libsecp256k1 acceleration if available.

A Python-only Schnorr sign/verify is available as a fallback if secp256k1 is
unavailable. Note that this is much less secure as it contains side channel
vulnerabilities, and must not be used in an automated-signing environment.
'''
import os
import sys
import hmac, hashlib
from ctypes import create_string_buffer, c_void_p, c_char_p, c_int, c_size_t

from . import secp256k1

# for pure-python -- TODO refactor these out of bitcoin.py
import ecdsa
from ecdsa.numbertheory import jacobi
from .bitcoin import ser_to_point, point_to_ser

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

def has_fast_sign():
    """Does sign() do fast (& side-channel secure) schnorr signatures?"""
    return bool(_secp256k1_schnorr_sign)
def has_fast_verify():
    """Does verify() do fast schnorr verification?"""
    return bool(_secp256k1_schnorr_verify)


# only used for pure python:
def nonce_function_rfc6979(order, privkeybytes, msg32, algo16=b'', ndata=b''):
    """ pure python RFC6979 deterministic nonce generation, done in
    libsecp256k1 style -- see nonce_function_rfc6979() in secp256k1.c.
    """
    assert len(privkeybytes) == 32
    assert len(msg32) == 32
    assert len(algo16) in (0, 16)
    assert len(ndata) in (0, 32)
    assert order.bit_length() == 256

    V = b'\x01'*32
    K = b'\x00'*32
    blob = bytes(privkeybytes) + msg32 + ndata + algo16
    # initialize
    K = hmac.HMAC(K, V+b'\x00'+blob, 'sha256').digest()
    V = hmac.HMAC(K, V, 'sha256').digest()
    K = hmac.HMAC(K, V+b'\x01'+blob, 'sha256').digest()
    V = hmac.HMAC(K, V, 'sha256').digest()
    # loop forever until an in-range k is found
    while True:
        # see RFC6979 3.2.h.2 : we take a shortcut and don't build T in
        # multiple steps since the first step is always the right size for
        # our purpose.
        V = hmac.HMAC(K, V, 'sha256').digest()
        T = V
        assert len(T) == 32
        k = int.from_bytes(T, 'big')
        if k > 0 and k < order:
            break
        K = hmac.HMAC(K, V+b'\x00', 'sha256').digest()
        V = HMAC_K(V)
    return k


def sign(privkey, message_hash):
    '''Create a Schnorr signature.

    Returns a 64-long bytes object (the signature), or raise ValueError
    on failure. Failure can occur due to an invalid private key.

    `privkey` should be the 32 byte raw private key (as you would get from
    bitcoin.deserialize_privkey, etc).

    `message_hash` should be the 32 byte sha256d hash of the tx input (or
    message) you want to sign
    '''

    if not isinstance(privkey, bytes) or len(privkey) != 32:
        raise ValueError('privkey must be a bytes object of length 32')
    if not isinstance(message_hash, bytes) or len(message_hash) != 32:
        raise ValueError('message_hash must be a bytes object of length 32')

    if _secp256k1_schnorr_sign:
        sig = create_string_buffer(64)
        res = _secp256k1_schnorr_sign(
            secp256k1.secp256k1.ctx, sig, message_hash, privkey, None, None
        )
        if not res:
            # Looking at the libsecp256k1 code, we can see that this will
            # only occur if privkey is == 0 or >= order, i.e., if it has
            # no associated pubkey. But as it's not specified in API we'll
            # just leave it as a vague exception.
            raise ValueError('could not sign')
        return bytes(sig)
    else:
        # pure python fallback:
        G = ecdsa.SECP256k1.generator
        order = G.order()
        fieldsize = G.curve().p()

        secexp = int.from_bytes(privkey, 'big')
        if not 0 < secexp < order:
            raise ValueError('could not sign')
        pubpoint = secexp * G
        pubbytes = point_to_ser(pubpoint, comp=True)

        k = nonce_function_rfc6979(order, privkey, message_hash,
                                   algo16=b'Schnorr+SHA256\x20\x20')
        R = k * G
        if jacobi(R.y(), fieldsize) == -1:
            k = order - k
        rbytes = R.x().to_bytes(32,'big')

        ebytes = hashlib.sha256(rbytes + pubbytes + message_hash).digest()
        e = int.from_bytes(ebytes, 'big')

        s = (k + e*secexp) % order

        return rbytes + s.to_bytes(32, 'big')


def verify(pubkey, signature, message_hash):
    '''Verify a Schnorr signature, returning True if valid.

    May raise a ValueError or return False on failure.

    `pubkey` should be the the raw public key bytes (as you would get from
    bitcoin.pubic_key_from_private_key, after hex decoding, etc).

    `signature` should be the 64 byte schnorr signature as would be returned
    from `sign` above.

    `message_hash` should be the 32 byte sha256d hash of the tx message to be
    verified'''

    if not isinstance(pubkey, bytes) or len(pubkey) not in (33, 65):
        raise ValueError('pubkey must be a bytes object of either length 33 or 65')
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError('signature must be a bytes object of length 64')
    if not isinstance(message_hash, bytes) or len(message_hash) != 32:
        raise ValueError('message_hash must be a bytes object of length 32')
    if _secp256k1_schnorr_verify:
        pubkey_parsed = create_string_buffer(64)
        res = secp256k1.secp256k1.secp256k1_ec_pubkey_parse(
            secp256k1.secp256k1.ctx, pubkey_parsed, pubkey, c_size_t(len(pubkey))
        )
        if not res:
            raise ValueError('pubkey could not be parsed by the secp256k1 library')
        res = _secp256k1_schnorr_verify(
            secp256k1.secp256k1.ctx, signature, message_hash, pubkey_parsed
        )
        return bool(res)
    else:
        G = ecdsa.SECP256k1.generator
        order = G.order()
        fieldsize = G.curve().p()

        try:
            pubpoint = ser_to_point(pubkey)
        except:
            # off-curve points, failed decompression, bad format,
            # point at infinity:
            raise ValueError('pubkey could not be parsed')

        rbytes = signature[:32]
        ## these unnecessary since below we do bytes comparison and
        ## R.x() is always < fieldsize.
        # r = int.from_bytes(rbytes, 'big')
        # if r >= fieldsize:
        #    return False

        sbytes = signature[32:]
        s = int.from_bytes(sbytes, 'big')
        if s >= order:
            return False

        # compressed format, regardless of whether pubkey was compressed or not:
        pubbytes = point_to_ser(pubpoint, comp=True)

        ebytes = hashlib.sha256(rbytes + pubbytes + message_hash).digest()
        e = int.from_bytes(ebytes, 'big')

        R = s*G + (- e)*pubpoint

        if R == ecdsa.ellipticcurve.INFINITY:
            return False

        if jacobi(R.y(), fieldsize) != 1:
            return False

        return (R.x().to_bytes(32, 'big') == rbytes)


if __name__ == "__main__":
    # Test Schnorr implementation.
    # duplicate the deterministic sig test from Bitcoin ABC's
    # src/test/key_tests.cpp .
    private_key = bytes.fromhex(
        "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747")

    pubkey = bytes.fromhex(
        "030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744")

    def sha(b):
        return hashlib.sha256(b).digest()
    msg = b"Very deterministic message"
    msghash = sha(sha(msg))
    assert msghash == bytes.fromhex(
        "5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a")

    sig = sign(private_key, msghash)
    assert sig == bytes.fromhex(
        "2c56731ac2f7a7e7f11518fc7722a166b02438924ca9d8b4d1113"
        "47b81d0717571846de67ad3d913a8fdf9d8f3f73161a4c48ae81c"
        "b183b214765feb86e255ce")

    assert verify(pubkey, sig, msghash)
    print("ok")
