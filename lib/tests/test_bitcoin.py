import unittest
import sys
from ecdsa.util import number_to_string

from lib.bitcoin import (
    generator_secp256k1, point_to_ser, public_key_to_bc_address, EC_KEY,
    bip32_root, bip32_public_derivation, bip32_private_derivation, pw_encode,
    pw_decode, Hash, public_key_from_private_key, address_from_private_key,
    is_valid, is_private_key, xpub_from_xprv, is_new_seed, is_old_seed,
    var_int, op_push)

try:
    import ecdsa
except ImportError:
    sys.exit("Error: python-ecdsa does not seem to be installed. Try 'sudo pip install ecdsa'")


class Test_bitcoin(unittest.TestCase):

    def test_crypto(self):
        for message in ["Chancellor on brink of second bailout for banks", chr(255)*512]:
            self._do_test_crypto(message)

    def _do_test_crypto(self, message):
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

        signature = eck.sign_message(message, True)
        #print signature
        EC_KEY.verify_message(eck, signature, message)

    def test_bip32(self):
        # see https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        xpub, xprv = self._do_test_bip32("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000", testnet=False)
        assert xpub == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        assert xprv == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"

        xpub, xprv = self._do_test_bip32("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542","m/0/2147483647'/1/2147483646'/2", testnet=False)
        assert xpub == "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        assert xprv == "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"

    def test_bip32_testnet(self):
        xpub, xprv = self._do_test_bip32("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000", testnet=True)
        assert xpub == "tpubDHNy3kAG39ThyiwwsgoKY4iRenXDRtce8qdCFJZXPMCJg5dsCUHayp84raLTpvyiNA9sXPob5rgqkKvkN8S7MMyXbnEhGJMW64Cf4vFAoaF"
        assert xprv == "tprv8kgvuL81tmn36Fv9z38j8f4K5m1HGZRjZY2QxnXDy5PuqbP6a5TzoKWCgTcGHBu66W3TgSbAu2yX6sPza5FkHmy564Sh6gmCPUNeUt4yj2x"

        xpub, xprv = self._do_test_bip32("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542","m/0/2147483647'/1/2147483646'/2", testnet=True)
        assert xpub == "tpubDG9qJLc8hq8PMG7y4sQEodLSocEkfj4mGrUC75b7G76mDoqybcUXvmvRsruvLeF14mhixobZwZP6LwqeFePKU83Sv8ZnxWdHBb6VzE6zbvC"
        assert xprv == "tprv8jTo9vZtZTSiTo6BBDjeQDgLEaipWPsrhYsQpZYoqqJNPKbCyDewkHJZhkoSHiWYCUf1Gm4TFzQxcG4D6s1J9Hsn4whDK7QYyHHokJeUuac"

    def _do_test_bip32(self, seed, sequence, testnet):
        xprv, xpub = bip32_root(seed.decode('hex'), testnet)
        assert sequence[0:2] == "m/"
        path = 'm'
        sequence = sequence[2:]
        for n in sequence.split('/'):
            child_path = path + '/' + n
            if n[-1] != "'":
                xpub2 = bip32_public_derivation(xpub, path, child_path, testnet)
            xprv, xpub = bip32_private_derivation(xprv, path, child_path, testnet)
            if n[-1] != "'":
                assert xpub == xpub2
            path = child_path

        return xpub, xprv

    def test_aes_homomorphic(self):
        """Make sure AES is homomorphic."""
        payload = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        password = u'secret'
        enc = pw_encode(payload, password)
        dec = pw_decode(enc, password)
        self.assertEqual(dec, payload)

    def test_aes_encode_without_password(self):
        """When not passed a password, pw_encode is noop on the payload."""
        payload = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        enc = pw_encode(payload, None)
        self.assertEqual(payload, enc)

    def test_aes_deencode_without_password(self):
        """When not passed a password, pw_decode is noop on the payload."""
        payload = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        enc = pw_decode(payload, None)
        self.assertEqual(payload, enc)

    def test_aes_decode_with_invalid_password(self):
        """pw_decode raises an Exception when supplied an invalid password."""
        payload = u"blah"
        password = u"uber secret"
        wrong_password = u"not the password"
        enc = pw_encode(payload, password)
        self.assertRaises(Exception, pw_decode, enc, wrong_password)

    def test_hash(self):
        """Make sure the Hash function does sha256 twice"""
        payload = u"test"
        expected = '\x95MZI\xfdp\xd9\xb8\xbc\xdb5\xd2R&x)\x95\x7f~\xf7\xfalt\xf8\x84\x19\xbd\xc5\xe8"\t\xf4'

        result = Hash(payload)
        self.assertEqual(expected, result)

    def test_xpub_from_xprv(self):
        """We can derive the xpub key from a xprv."""
        # Taken from test vectors in https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        xprv = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"

        result = xpub_from_xprv(xprv)
        self.assertEqual(result, xpub)

    def test_xpub_from_xprv_testnet(self):
        """We can derive the xpub key from a xprv using testnet headers."""
        xpub = "tpubDHNy3kAG39ThyiwwsgoKY4iRenXDRtce8qdCFJZXPMCJg5dsCUHayp84raLTpvyiNA9sXPob5rgqkKvkN8S7MMyXbnEhGJMW64Cf4vFAoaF"
        xprv = "tprv8kgvuL81tmn36Fv9z38j8f4K5m1HGZRjZY2QxnXDy5PuqbP6a5TzoKWCgTcGHBu66W3TgSbAu2yX6sPza5FkHmy564Sh6gmCPUNeUt4yj2x"
        result = xpub_from_xprv(xprv, testnet=True)
        self.assertEqual(result, xpub)

    def test_var_int(self):
        for i in range(0xfd):
            self.assertEqual(var_int(i), "{:02x}".format(i) )

        self.assertEqual(var_int(0xfd), "fdfd00")
        self.assertEqual(var_int(0xfe), "fdfe00")
        self.assertEqual(var_int(0xff), "fdff00")
        self.assertEqual(var_int(0x1234), "fd3412")
        self.assertEqual(var_int(0xffff), "fdffff")
        self.assertEqual(var_int(0x10000), "fe00000100")
        self.assertEqual(var_int(0x12345678), "fe78563412")
        self.assertEqual(var_int(0xffffffff), "feffffffff")
        self.assertEqual(var_int(0x100000000), "ff0000000001000000")
        self.assertEqual(var_int(0x0123456789abcdef), "ffefcdab8967452301")

    def test_op_push(self):
        self.assertEqual(op_push(0x00), '00')
        self.assertEqual(op_push(0x12), '12')
        self.assertEqual(op_push(0x4b), '4b')
        self.assertEqual(op_push(0x4c), '4c4c')
        self.assertEqual(op_push(0xfe), '4cfe')
        self.assertEqual(op_push(0xff), '4dff00')
        self.assertEqual(op_push(0x100), '4d0001')
        self.assertEqual(op_push(0x1234), '4d3412')
        self.assertEqual(op_push(0xfffe), '4dfeff')
        self.assertEqual(op_push(0xffff), '4effff0000')
        self.assertEqual(op_push(0x10000), '4e00000100')
        self.assertEqual(op_push(0x12345678), '4e78563412')


class Test_keyImport(unittest.TestCase):
    """ The keys used in this class are TEST keys from
        https://en.bitcoin.it/wiki/BIP_0032_TestVectors"""

    private_key = "L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW"
    public_key_hex = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    main_address = "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"

    def test_public_key_from_private_key(self):
        result = public_key_from_private_key(self.private_key)
        self.assertEqual(self.public_key_hex, result)

    def test_address_from_private_key(self):
        result = address_from_private_key(self.private_key)
        self.assertEqual(self.main_address, result)

    def test_is_valid_address(self):
        self.assertTrue(is_valid(self.main_address))
        self.assertFalse(is_valid("not an address"))

    def test_is_private_key(self):
        self.assertTrue(is_private_key(self.private_key))
        self.assertFalse(is_private_key(self.public_key_hex))


class Test_seeds(unittest.TestCase):
    """ Test old and new seeds. """
    
    def test_new_seed(self):
        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform able"
        self.assertTrue(is_new_seed(seed))

        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform"
        self.assertFalse(is_new_seed(seed))

    def test_old_seed(self):
        self.assertTrue(is_old_seed(" ".join(["like"] * 12)))
        self.assertFalse(is_old_seed(" ".join(["like"] * 18)))
        self.assertTrue(is_old_seed(" ".join(["like"] * 24)))
        self.assertFalse(is_old_seed("not a seed"))

        self.assertTrue(is_old_seed("0123456789ABCDEF" * 2))
        self.assertTrue(is_old_seed("0123456789ABCDEF" * 4))
