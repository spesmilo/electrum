#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2012 thomasv@gitorious
#
# This file is:
#     Copyright (C) 2018 Calin Culianu <calin.culianu@gmail.com>
#
# MIT LICENSE
#
'''
    Monkey Patches -- mostly to modify electroncash.* package to suit our needs.
    Don't hate me.  (This was needed to keep the iOS stuff self-contained.)
'''
from .uikit_bindings import *
from electroncash.util import (InvalidPassword, profiler)
import electroncash.bitcoin as ec_bitcoin
from electroncash_gui.ios_native.utils import NSLog
import sys, ssl

class MonkeyPatches:

    patched = False # don't write to this. Instead use patch() and unpatch()

    @classmethod
    def patch(cls):
        if cls.patched:
            print('*** WARNING: MonkeyPatches are already applied!')
            return

        cls._Patch_SSL.patch()
        cls._Patch_AES.patch()

        cls.patched = True
        NSLog("MonkeyPatches Applied")

    @classmethod
    def unpatch(cls):
        if not cls.patched:
            print('*** WARNING: MonkeyPatches was not active!')
            return

        cls._Patch_AES.unpatch()
        cls._Patch_SSL.unpatch()

        cls.patched = False
        NSLog("MonkeyPatches Disabled")

    #
    # Private.. Don't directly use the stuff below.
    #
    class _Patch_SSL:
        patched = False
        origs = tuple()

        @classmethod
        def patch(cls):
            if cls.patched:
                NSLog("*** SSL *** Already patched.")
                return False
            try:
                #
                # The below is very important to allow OpenSSL to do SSL connections on iOS without verifying certs.
                # If you take this out, blockchain_headers from http://bitcoincash.com will fail, and the
                # "downloading headers" thing will take ages.  So I left this in.
                # TODO: Figure out how to get bitcoincash.com to not fail with cert verification.
                #   - Calin May 24, 2018
                #
                if (getattr(ssl, '_create_unverified_context', None)):
                    if not cls.origs:
                        cls.origs = (ssl._create_default_https_context, ssl.create_default_context)
                    ssl._create_default_https_context = ssl._create_unverified_context
                    ssl.create_default_context = ssl._create_unverified_context
                    NSLog("*** SSL *** Allow Unverfied Context: ENABLED")
                else:
                    raise Exception("pyOpenSSL seems to be missing the '_create_unverified_context' function")
            except:
                NSLog("*** SSL *** Allow Unverified Context: FAILED (%s)"%(str(sys.exc_info()[1])))
                return False
            cls.patched = True
            return True

        @classmethod
        def unpatch(cls):
            if not cls.patched: return False
            if cls.origs:
                ssl._create_default_https_context, ssl.create_default_context = cls.origs
                cls.patched = False
                NSLog("*** SSL *** Allow Unverfied Context: Disabled")
            return not cls.patched

    class _Patch_AES:
        patched = False

        @classmethod
        def patch(cls):
            ec_bitcoin.aes_decrypt_with_iv = cls._aes_decrypt_with_iv
            ec_bitcoin.aes_encrypt_with_iv = cls._aes_encrypt_with_iv
            cls.patched = True
            NSLog("*** AES *** Use iOS CommonCrypto: ENABLED")
            return True

        @classmethod
        def unpatch(cls):
            ec_bitcoin.aes_decrypt_with_iv = cls._orig_aes_decrypt_with_iv
            ec_bitcoin.aes_encrypt_with_iv = cls._orig_aes_encrypt_with_iv
            cls.patched = False
            NSLog("*** AES *** Use iOS CommonCrypto: Disabled")
            return True

        _orig_aes_encrypt_with_iv = ec_bitcoin.aes_encrypt_with_iv
        _orig_aes_decrypt_with_iv = ec_bitcoin.aes_decrypt_with_iv

        @classmethod
        @profiler
        def _aes_encrypt_with_iv(cls, key, iv, data):
            ''' Use iOS native AES implementation if available '''
            nsdata = ns_from_py(data)
            e = nsdata.AES128EncryptWithKey_initializationVector_(ns_from_py(key), ns_from_py(iv) if iv else None)
            if e is None:
                print('*** WARNING: Could not encrypt data using platform-native AES, falling back to slow pyaes method!')
                return cls._orig_aes_encrypt_with_iv(key, iv, data)
            e = py_from_ns(e)
            return e


        @classmethod
        @profiler
        def _aes_decrypt_with_iv(cls, key, iv, data):
            ''' Use iOS native AES implementation if available '''
            nsdata = ns_from_py(data)
            pt = nsdata.AES128DecryptWithKey_initializationVector_keepPadding_(ns_from_py(key), ns_from_py(iv) if iv else None, True)
            if pt is None:
                print('*** WARNING: Could not decrypt data using platform-native AES, falling back to slow pyaes method!')
                return cls._orig_aes_decrypt_with_iv(key, iv, data)
            pt = py_from_ns(pt)
            try:
                return ec_bitcoin.strip_PKCS7_padding(pt)
            except ec_bitcoin.InvalidPadding:
                raise InvalidPassword()

        '''
        @classmethod
        def TEST(cls):
            b = ec_bitcoin
            oldenc, olddec = cls._orig_aes_encrypt_with_iv, cls._orig_aes_decrypt_with_iv
            #newenc, newdec = cls._aes_encrypt_with_iv, cls._aes_decrypt_with_iv
            # test
            data = b'this is a test of the emergency broadcast system.. this is only a test'
            key = b'1234567890123456'
            iv =  b'1023120345647381'
            cypher = py_from_ns(ns_from_py(data).AES128EncryptWithKey_initializationVector_(key,iv))
            data2 = py_from_ns(ns_from_py(cypher).AES128DecryptWithKey_initializationVector_keepPadding_(key,iv,True))
            print("data=",data,"data2=",data2,'cypher=',cypher)
            cypher = oldenc(key,iv,data)
            data2 = olddec(key,iv,cypher)
            print("data=",data,"data2=",data2,'cypher=',cypher)
        '''
