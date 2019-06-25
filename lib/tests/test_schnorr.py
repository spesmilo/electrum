#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
# This file (c) 2019 Mark Lundeberg & Calin Culianu
# Part of the Electron Cash SPV Wallet
# License: MIT
import unittest
from .. import schnorr

import hashlib

class TestSchnorr(unittest.TestCase):

    def do_it(self):
        ''' Test Schnorr implementation.
        Duplicate the deterministic sig test from Bitcoin ABC's
        src/test/key_tests.cpp '''
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

        sig = schnorr.sign(private_key, msghash)
        ref_sig = bytes.fromhex("2c56731ac2f7a7e7f11518fc7722a166b02438924ca9d8"
                                "b4d111347b81d0717571846de67ad3d913a8fdf9d8f3f7"
                                "3161a4c48ae81cb183b214765feb86e255ce")
        self.assertEqual(sig, ref_sig)

        self.assertTrue(schnorr.verify(pubkey, sig, msghash))

    def test_schnorr(self):
        saved = (schnorr._secp256k1_schnorr_sign, schnorr._secp256k1_schnorr_verify)
        slow = (None, None)
        schnorr._secp256k1_schnorr_sign, schnorr._secp256k1_schnorr_verify = slow # clear the ctypes function to force slow

        self.do_it()

        if slow != saved:
            # swap back, do it fast
            schnorr._secp256k1_schnorr_sign, schnorr._secp256k1_schnorr_verify = saved
            self.do_it()

