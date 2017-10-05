from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import base64
import six
import unittest
import sys
from ecdsa.util import number_to_string

from lib.bitcoin import (
    generator_secp256k1, point_to_ser, public_key_to_p2pkh, EC_KEY,
    bip32_root, bip32_public_derivation, bip32_private_derivation, pw_encode,
    pw_decode, Hash, public_key_from_private_key, address_from_private_key,
    is_address, is_private_key, xpub_from_xprv, is_new_seed, is_old_seed,
    var_int, op_push, address_to_script, regenerate_key,
    verify_message, deserialize_privkey)
from lib.util import bfh

try:
    import ecdsa
except ImportError:
    sys.exit("Error: python-ecdsa does not seem to be installed. Try 'sudo pip install ecdsa'")


class Test_bitcoin(unittest.TestCase):

    def test_crypto(self):
        for message in [b"Chancellor on brink of second bailout for banks", b'\xff'*512]:
            self._do_test_crypto(message)

    def _do_test_crypto(self, message):
        G = generator_secp256k1
        _r  = G.order()
        pvk = ecdsa.util.randrange( pow(2,256) ) %_r

        Pub = pvk*G
        pubkey_c = point_to_ser(Pub,True)
        #pubkey_u = point_to_ser(Pub,False)
        addr_c = public_key_to_p2pkh(pubkey_c)

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

    def test_msg_signing(self):
        msg1 = b'Chancellor on brink of second bailout for banks'
        msg2 = b'Electrum'

        def sign_message_with_wif_privkey(wif_privkey, msg):
            txin_type, privkey, compressed = deserialize_privkey(wif_privkey)
            key = regenerate_key(privkey)
            return key.sign_message(msg, compressed)

        sig1 = sign_message_with_wif_privkey(
            'T7J3unHmmx9S8e8Zdi9r98A7wTW386HkxvMbUKEMsAY9JRWfbSe6', msg1)
        sig2 = sign_message_with_wif_privkey(
            'T6oaa3RpobKE2jFtkUyBJHcvCBKQJsBoSoAqZnzUQ3oexiXW7rWq', msg2)

        sig1_b64 = base64.b64encode(sig1)
        sig2_b64 = base64.b64encode(sig2)

        self.assertEqual(sig1_b64, b'IHGAMaPxjrn3CD19S7J5KAq4xF6mdLznsSL8SrqhNwficUHlK5wSth6/JiZ/pEyo92nkUoA+kL9VJpjLnKJKTmM=')
        self.assertEqual(sig2_b64, b'IIYiI5SslM+9hBEedDjl03V51vuDgjbJ493Ygb3DfDzaHBp/AkCWeJ7EL8s6IHvTsb2CHF/y8MlVQJTs5fXCOvs=')

        self.assertTrue(verify_message('LPvBisC3rGmpGa3E3NeQk3PHQN4VS237y2', sig1, msg1))
        self.assertTrue(verify_message('LeqUvj52PSAtwcwUPKR11zRod4N3fEg2Lx', sig2, msg2))

    def test_bip32(self):
        # see https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        xpub, xprv = self._do_test_bip32("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000")
        assert xpub == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        assert xprv == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"

        xpub, xprv = self._do_test_bip32("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542","m/0/2147483647'/1/2147483646'/2")
        assert xpub == "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        assert xprv == "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"

    def _do_test_bip32(self, seed, sequence):
        xprv, xpub = bip32_root(bfh(seed), 'standard')
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
        expected = b'\x95MZI\xfdp\xd9\xb8\xbc\xdb5\xd2R&x)\x95\x7f~\xf7\xfalt\xf8\x84\x19\xbd\xc5\xe8"\t\xf4'

        result = Hash(payload)
        self.assertEqual(expected, result)

    def test_xpub_from_xprv(self):
        """We can derive the xpub key from a xprv."""
        # Taken from test vectors in https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        xprv = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"

        result = xpub_from_xprv(xprv)
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

    # TODO testnet addresses
    def test_address_to_script(self):
        # bech32 native segwit
        # test vectors from BIP-0173
        self.assertEqual(address_to_script('LTC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KGMN4N9'), '0014751e76e8199196d454941c45d1b3a323f1433bd6')
        self.assertEqual(address_to_script('ltc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k0tul4w'), '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6')
        self.assertEqual(address_to_script('LTC1SW50QZGYDF5'), '6002751e')
        self.assertEqual(address_to_script('ltc1zw508d6qejxtdg4y5r3zarvaryvdzur3w'), '5210751e76e8199196d454941c45d1b3a323')

        # base58 P2PKH
        self.assertEqual(address_to_script('LNuZh2Eeps3L114Lu4PVCxBR61UvqcAb8p'), '76a91428662c67561b95c79d2257d2a93d9d151c977e9188ac')
        self.assertEqual(address_to_script('LVTnwCztciF3bcZpSqvJStuMSXrnDt1pUU'), '76a914704f4b81cadb7bf7e68c08cd3657220f680f863c88ac')

        # base58 P2SH
        self.assertEqual(address_to_script('MBmyiC29MUQSfPC2gKtdrazbSWHvGqJCnU'), 'a9142a84cf00d47f699ee7bbc1dea5ec1bdecb4ac15487')
        self.assertEqual(address_to_script('MWBtJBTgiEWYQ7m17wFktku2dvSFZXqhWZ'), 'a914f47c8954e421031ad04ecd8e7752c9479206b9d387')


class Test_keyImport(unittest.TestCase):
    """ The keys used in this class are TEST keys from
        https://en.bitcoin.it/wiki/BIP_0032_TestVectors"""

    private_key = "TAD8rebzCEyYBZWCqjsKxeH9YjenLqX55MNgqGyeQkHdN5T7ejYH"
    public_key_hex = "0220d43256bdb32c7517bb0e3f086f54ec351d2299a5808b6a36c7ba434094c8ef"
    main_address = "LYUdH72gHL4gcW8pPwaJm4uCFbkCXABAZW"

    def test_public_key_from_private_key(self):
        txin_type, privkey, compressed = deserialize_privkey(self.private_key)
        result = public_key_from_private_key(privkey, compressed)
        self.assertEqual(self.public_key_hex, result)

    def test_address_from_private_key(self):
        result = address_from_private_key(self.private_key)
        self.assertEqual(self.main_address, result)

    def test_is_valid_address(self):
        self.assertTrue(is_address(self.main_address))
        self.assertFalse(is_address("not an address"))

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
