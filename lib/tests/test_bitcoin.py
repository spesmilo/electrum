import unittest
import sys
from ecdsa.util import number_to_string

from lib.bitcoin import (
    generator_secp256k1, point_to_ser, public_key_to_bc_address, EC_KEY,
    bip32_root, bip32_public_derivation, bip32_private_derivation, pw_encode,
    pw_decode)

try:
    import ecdsa
except ImportError:
    sys.exit("Error: python-ecdsa does not seem to be installed. Try 'sudo pip install ecdsa'")

class Test_bitcoin(unittest.TestCase):

    def test_crypto(self):
        for message in ["Chancellor on brink of second bailout for banks", chr(255)*512]:
            self.do_test_crypto(message)

    def do_test_crypto(self, message):
        G = generator_secp256k1
        _r  = G.order()
        pvk = ecdsa.util.randrange( pow(2,256) ) %_r

        Pub = pvk*G
        pubkey_c = point_to_ser(Pub,True)
        #pubkey_u = point_to_ser(Pub,False)
        addr_c = public_key_to_bc_address(pubkey_c)
        #addr_u = public_key_to_bc_address(pubkey_u)

        #print "Private key            ", '%064x'%pvk
        eck = EC_KEY(number_to_string(pvk,_r))

        #print "Compressed public key  ", pubkey_c.encode('hex')
        enc = EC_KEY.encrypt_message(message, pubkey_c)
        dec = eck.decrypt_message(enc)
        assert dec == message

        #print "Uncompressed public key", pubkey_u.encode('hex')
        #enc2 = EC_KEY.encrypt_message(message, pubkey_u)
        dec2 = eck.decrypt_message(enc)
        assert dec2 == message

        signature = eck.sign_message(message, True, addr_c)
        #print signature
        EC_KEY.verify_message(addr_c, signature, message)



    def test_bip32(self):
        # see https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        xpub, xprv = self.do_test_bip32("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000")
        assert xpub == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        assert xprv == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"

        xpub, xprv = self.do_test_bip32("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542","m/0/2147483647'/1/2147483646'/2")
        assert xpub == "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        assert xprv == "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"


    def do_test_bip32(self, seed, sequence):
        xprv, xpub = bip32_root(seed)
        assert sequence[0:2] == "m/"
        path = 'm'
        sequence = sequence[2:]
        for n in sequence.split('/'):
            child_path = path + '/' + n
            if n[-1] != "'":
                xpub2 = bip32_public_derivation(xpub, path, child_path)
            xprv, xpub = bip32_private_derivation(xprv, path, child_path)
            if n[-1] != "'":
                assert xpub == xpub2
            path = child_path

        return xpub, xprv


    def test_aes(self):
        s = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        self.do_test_aes(s, s)

    def do_test_aes(self, s, p):
        enc = pw_encode(s, p)
        dec = pw_decode(enc, p)
        assert dec == s
