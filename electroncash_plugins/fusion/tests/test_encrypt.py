#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
# This file (c) 2019 Mark Lundeberg
# Part of the Electron Cash SPV Wallet
# License: MIT
import unittest

from .. import encrypt


def fastslowcase(testmethod):
    """ method -> class decorator to run with pycryptodomex's fast AES enabled/disabled """
    class _TestClass(unittest.TestCase):
        def test_slow(self):
            saved = encrypt.AES
            encrypt.AES = None
            try:
                testmethod(self)
            finally:
                encrypt.AES = saved
        def test_fast(self):
            if not encrypt.AES:
                self.skipTest("accelerated AES library not available")
            testmethod(self)

    _TestClass.__name__ = testmethod.__name__
    return _TestClass

@fastslowcase
def TestNormal(self):
    Apriv =  bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000005')
    Apub = bytes.fromhex('022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4')

    # short message
    msg12 = b'test message'
    assert len(msg12) == 12

    e12 = encrypt.encrypt(msg12, Apub)
    self.assertEqual(len(e12), 65)  # since it's only 12 bytes, it and length fit into one block
    e12 = encrypt.encrypt(msg12, Apub, pad_to_length = 16)
    self.assertEqual(len(e12), 65)
    d12, k = encrypt.decrypt(e12, Apriv)
    self.assertEqual(d12, msg12)
    d12 = encrypt.decrypt_with_symmkey(e12, k)
    self.assertEqual(d12, msg12)

    # tweak the nonce point's oddness bit
    e12_bad = bytearray(e12) ; e12_bad[0] ^= 1
    with self.assertRaises(encrypt.DecryptionFailed):
        encrypt.decrypt(e12_bad, Apriv)
    d12 = encrypt.decrypt_with_symmkey(e12_bad, k)  # works because it doesn't care about nonce point
    self.assertEqual(d12, msg12)

    # tweak the hmac
    e12_bad = bytearray(e12) ; e12_bad[-1] ^= 1
    with self.assertRaises(encrypt.DecryptionFailed):
        encrypt.decrypt(e12_bad, Apriv)
    with self.assertRaises(encrypt.DecryptionFailed):
        encrypt.decrypt_with_symmkey(e12_bad, k)

    # tweak the message
    e12_bad = bytearray(e12) ; e12_bad[35] ^= 1
    with self.assertRaises(encrypt.DecryptionFailed):
        encrypt.decrypt(e12_bad, Apriv)
    with self.assertRaises(encrypt.DecryptionFailed):
        encrypt.decrypt_with_symmkey(e12_bad, k)

    # drop a byte
    e12_bad = bytearray(e12) ; e12_bad.pop()
    with self.assertRaises(encrypt.DecryptionFailed):
        encrypt.decrypt(e12_bad, Apriv)
    with self.assertRaises(encrypt.DecryptionFailed):
        encrypt.decrypt_with_symmkey(e12_bad, k)

    msg13 = msg12 + b'!'
    e13 = encrypt.encrypt(msg13, Apub)
    self.assertEqual(len(e13), 81)  # need another block
    with self.assertRaises(ValueError):
        encrypt.encrypt(msg13, Apub, pad_to_length = 16)
    e13 = encrypt.encrypt(msg13, Apub, pad_to_length = 32)
    self.assertEqual(len(e13), 81)
    encrypt.decrypt(e13, Apriv)

    msgbig = b'a'*1234
    ebig = encrypt.encrypt(msgbig, Apub)
    self.assertEqual(len(ebig), 33 + (1234+4+10) + 16)
    dbig, k = encrypt.decrypt(ebig, Apriv)
    self.assertEqual(dbig, msgbig)


    self.assertEqual(len(encrypt.encrypt(b'', Apub)), 65)
    self.assertEqual(len(encrypt.encrypt(b'', Apub, pad_to_length = 1248)), 1297)
    with self.assertRaises(ValueError):
        encrypt.encrypt(b'', Apub, pad_to_length = 0)
