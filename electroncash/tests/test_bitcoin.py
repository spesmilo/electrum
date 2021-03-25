import base64
import unittest
import sys
from ecdsa.util import number_to_string

from ..address import Address
from ..bitcoin import (
    generator_secp256k1, point_to_ser, public_key_to_p2pkh, EC_KEY, bip32_root,
    bip32_public_derivation, bip32_private_derivation, pw_encode, pw_decode,
    Hash, public_key_from_private_key, address_from_private_key, is_private_key,
    xpub_from_xprv, var_int, op_push, regenerate_key, verify_message,
    deserialize_privkey, serialize_privkey, is_minikey, is_compressed, is_xpub,
    xpub_type, is_xprv, is_bip32_derivation, Bip38Key)
from ..networks import set_mainnet, set_testnet
from ..util import bfh

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
        self.assertEqual(message, dec)

        #print "Uncompressed public key", pubkey_u.encode('hex')
        #enc2 = EC_KEY.encrypt_message(message, pubkey_u)
        dec2 = eck.decrypt_message(enc)
        self.assertEqual(message, dec2)

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
            'L1TnU2zbNaAqMoVh65Cyvmcjzbrj41Gs9iTLcWbpJCMynXuap6UN', msg1)
        addr1 = '15hETetDmcXm1mM4sEf7U2KXC9hDHFMSzz'
        sig2 = sign_message_with_wif_privkey(
            '5Hxn5C4SQuiV6e62A1MtZmbSeQyrLFhu5uYks62pU5VBUygK2KD', msg2)
        addr2 = '1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6'

        sig1_b64 = base64.b64encode(sig1)
        sig2_b64 = base64.b64encode(sig2)

        # NOTE: you cannot rely on exact binary patterns of signatures
        # produced by libsecp versus python ecdsa, etc. This is because nonces
        # may differ.  We ran into this when switching from Bitcoin Core libsecp
        # to Bitcoin ABC libsecp.  Amaury Sechet confirmed this to be true.
        # Mark Lundeberg suggested we still do binary exact matches from a set,
        # though, just to notice when nonces of the underlying lib change.
        # So.. the below test is has been updated to use a set.
        #self.assertEqual(sig1_b64, b'H/9jMOnj4MFbH3d7t4yCQ9i7DgZU/VZ278w3+ySv2F4yIsdqjsc5ng3kmN8OZAThgyfCZOQxZCWza9V5XzlVY0Y=')
        #self.assertEqual(sig2_b64, b'G84dmJ8TKIDKMT9qBRhpX2sNmR0y5t+POcYnFFJCs66lJmAs3T8A6Sbpx7KA6yTQ9djQMabwQXRrDomOkIKGn18=')
        #
        # Hardcoded sigs were generated with an old version of Python ECDSA by Electrum team.
        # New sigs generated with Bitcoin-ABC libsecp variant.  Both verify against each other ok
        # They just have different byte patterns we can expect due to different nonces used (both are to spec).
        accept_b64_1 = {
            # Older core libsecp/python ecdsa nonce produces this deterministic signature
            b'H/9jMOnj4MFbH3d7t4yCQ9i7DgZU/VZ278w3+ySv2F4yIsdqjsc5ng3kmN8OZAThgyfCZOQxZCWza9V5XzlVY0Y=',
            # New Bitoin ABC libsecp nonce produces this deterministic signature
            b'IA+oq/uGz4kKA2bNgxPcM+T216abyUiBhofMg1J8fC5BLAbbIpF2toCHaO7/LQAxhQBtu5D6ROq1JjXiRwPAASg=',
        }
        accept_b64_2 = {
            # core/ecdsa
            b'G84dmJ8TKIDKMT9qBRhpX2sNmR0y5t+POcYnFFJCs66lJmAs3T8A6Sbpx7KA6yTQ9djQMabwQXRrDomOkIKGn18=',
            # libsecp bitcoin-abc
            b'HP+MT0B/Ga++0DEXDJE0oBb1DEsBMX0j+i2mbyEI4nwVMZkwc/pHgL2KlntotC+k8uU8y/M4YAdO4n7vfuUVL8A=',
        }

        # does it match with one of our hard-coded sigs in the set?
        self.assertTrue(sig1_b64 in accept_b64_1)
        self.assertTrue(sig2_b64 in accept_b64_2)
        # can it verify its own sigs?
        self.assertTrue(verify_message(addr1, sig1, msg1))
        self.assertTrue(verify_message(addr2, sig2, msg2))
        # Can we verify the hardcoded sigs (this checks that the underlying ECC
        # libs basically are ok with either nonce being used)
        for sig in accept_b64_1:
            self.assertTrue(verify_message(addr1, base64.b64decode(sig), msg1))
        for sig in accept_b64_2:
            self.assertTrue(verify_message(addr2, base64.b64decode(sig), msg2))

        self.assertRaises(Exception, verify_message, addr1, b'wrong', msg1)
        # test for bad sigs for a message
        self.assertFalse(verify_message(addr1, sig2, msg1))
        self.assertFalse(verify_message(addr2, sig1, msg2))

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

    def test_var_int(self):
        for i in range(0xfd):
            self.assertEqual(var_int(i), "{:02x}".format(i))

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


class Test_bitcoin_testnet(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        set_testnet()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        set_mainnet()


class Test_xprv_xpub(unittest.TestCase):

    xprv_xpub = (
        # Taken from test vectors in https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        {'xprv': 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
         'xpub': 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
         'xtype': 'standard'},
    )

    def _do_test_bip32(self, seed, sequence):
        xprv, xpub = bip32_root(bfh(seed), 'standard')
        self.assertEqual("m/", sequence[0:2])
        path = 'm'
        sequence = sequence[2:]
        for n in sequence.split('/'):
            child_path = path + '/' + n
            if n[-1] != "'":
                xpub2 = bip32_public_derivation(xpub, path, child_path)
            xprv, xpub = bip32_private_derivation(xprv, path, child_path)
            if n[-1] != "'":
                self.assertEqual(xpub, xpub2)
            path = child_path

        return xpub, xprv

    def test_bip32(self):
        # see https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        xpub, xprv = self._do_test_bip32("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000")
        self.assertEqual("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", xpub)
        self.assertEqual("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", xprv)

        xpub, xprv = self._do_test_bip32("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542","m/0/2147483647'/1/2147483646'/2")
        self.assertEqual("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt", xpub)
        self.assertEqual("xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", xprv)

    def test_xpub_from_xprv(self):
        """We can derive the xpub key from a xprv."""
        for xprv_details in self.xprv_xpub:
            result = xpub_from_xprv(xprv_details['xprv'])
            self.assertEqual(result, xprv_details['xpub'])

    def test_is_xpub(self):
        for xprv_details in self.xprv_xpub:
            xpub = xprv_details['xpub']
            self.assertTrue(is_xpub(xpub))
        self.assertFalse(is_xpub('xpub1nval1d'))
        self.assertFalse(is_xpub('xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52WRONGBADWRONG'))

    def test_xpub_type(self):
        for xprv_details in self.xprv_xpub:
            xpub = xprv_details['xpub']
            self.assertEqual(xprv_details['xtype'], xpub_type(xpub))

    def test_is_xprv(self):
        for xprv_details in self.xprv_xpub:
            xprv = xprv_details['xprv']
            self.assertTrue(is_xprv(xprv))
        self.assertFalse(is_xprv('xprv1nval1d'))
        self.assertFalse(is_xprv('xprv661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52WRONGBADWRONG'))

    def test_is_bip32_derivation(self):
        self.assertTrue(is_bip32_derivation("m/0'/1"))
        self.assertTrue(is_bip32_derivation("m/0'/0'"))
        self.assertTrue(is_bip32_derivation("m/44'/0'/0'/0/0"))
        self.assertTrue(is_bip32_derivation("m/49'/0'/0'/0/0"))
        self.assertFalse(is_bip32_derivation("mmmmmm"))
        self.assertFalse(is_bip32_derivation("n/"))
        self.assertFalse(is_bip32_derivation(""))
        self.assertFalse(is_bip32_derivation("m/q8462"))


class Test_keyImport(unittest.TestCase):

    priv_pub_addr = (
           {'priv': 'KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6',
            'pub': '02c6467b7e621144105ed3e4835b0b4ab7e35266a2ae1c4f8baa19e9ca93452997',
            'address': '17azqT8T16coRmWKYFj3UjzJuxiYrYFRBR',
            'minikey' : False,
            'txin_type': 'p2pkh',
            'compressed': True,
            'addr_encoding': 'base58',
            'scripthash': 'c9aecd1fef8d661a42c560bf75c8163e337099800b8face5ca3d1393a30508a7'},
           {'priv': '5Hxn5C4SQuiV6e62A1MtZmbSeQyrLFhu5uYks62pU5VBUygK2KD',
            'pub': '04e5fe91a20fac945845a5518450d23405ff3e3e1ce39827b47ee6d5db020a9075422d56a59195ada0035e4a52a238849f68e7a325ba5b2247013e0481c5c7cb3f',
            'address': '1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6',
            'minikey': False,
            'txin_type': 'p2pkh',
            'compressed': False,
            'addr_encoding': 'base58',
            'scripthash': 'f5914651408417e1166f725a5829ff9576d0dbf05237055bf13abd2af7f79473'},
           # from http://bitscan.com/articles/security/spotlight-on-mini-private-keys
           {'priv': 'SzavMBLoXU6kDrqtUVmffv',
            'pub': '04588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9f88ff2a00d7e752d44cbe16e1ebcf0890b76ec7c78886109dee76ccfc8445424',
            'address': '1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj',
            'minikey': True,
            'txin_type': 'p2pkh',
            'compressed': False,  # this is Casascius coins... issue #2748
            'addr_encoding': 'base58',
            'scripthash': '5b07ddfde826f5125ee823900749103cea37808038ecead5505a766a07c34445'},
    )

    def test_public_key_from_private_key(self):
        for priv_details in self.priv_pub_addr:
            txin_type, privkey, compressed = deserialize_privkey(priv_details['priv'])
            result = public_key_from_private_key(privkey, compressed)
            self.assertEqual(priv_details['pub'], result)
            self.assertEqual(priv_details['txin_type'], txin_type)
            self.assertEqual(priv_details['compressed'], compressed)

    def test_address_from_private_key(self):
        for priv_details in self.priv_pub_addr:
            addr2 = address_from_private_key(priv_details['priv'])
            self.assertEqual(priv_details['address'], addr2)

    def test_is_private_key(self):
        for priv_details in self.priv_pub_addr:
            self.assertTrue(is_private_key(priv_details['priv']))
            self.assertFalse(is_private_key(priv_details['pub']))
            self.assertFalse(is_private_key(priv_details['address']))
        self.assertFalse(is_private_key("not a privkey"))

    def test_serialize_privkey(self):
        for priv_details in self.priv_pub_addr:
            txin_type, privkey, compressed = deserialize_privkey(priv_details['priv'])
            priv2 = serialize_privkey(privkey, compressed, txin_type)
            if not priv_details['minikey']:
                self.assertEqual(priv_details['priv'], priv2)

    def test_address_to_scripthash(self):
        for priv_details in self.priv_pub_addr:
            addr = Address.from_string(priv_details['address'])
            sh = addr.to_scripthash_hex()
            self.assertEqual(priv_details['scripthash'], sh)

    def test_is_minikey(self):
        for priv_details in self.priv_pub_addr:
            minikey = priv_details['minikey']
            priv = priv_details['priv']
            self.assertEqual(minikey, is_minikey(priv))

    def test_is_compressed(self):
        for priv_details in self.priv_pub_addr:
            self.assertEqual(priv_details['compressed'],
                             is_compressed(priv_details['priv']))

class Test_Bip38(unittest.TestCase):
    ''' Test Bip38 encryption/decryption. Test cases taken from:

    https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki '''

    def test_decrypt(self):
        if not Bip38Key.isFast():
            self.skipTest("Bip38 lacks a fast scrypt function, skipping decrypt test")
            return

        # Test basic comprehension
        self.assertTrue(Bip38Key.isBip38('6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg'))
        self.assertFalse(Bip38Key.isBip38('5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'))

        # No EC Mult, Uncompressed key
        b38 = Bip38Key('6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg')
        self.assertEqual(b38.decrypt('TestingOneTwoThree')[0], '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR')

        b38 = Bip38Key('6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq')
        self.assertEqual(b38.decrypt('Satoshi')[0], '5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5')

        # No EC Mult, Compressed key
        b38 = Bip38Key('6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo')
        self.assertEqual(b38.decrypt('TestingOneTwoThree')[0], 'L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP')

        b38 = Bip38Key('6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7')
        self.assertEqual(b38.decrypt('Satoshi')[0], 'KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7')

        # EC Mult, No compression, No lot/sequence
        b38 = Bip38Key('6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX')
        self.assertEqual(b38.decrypt('TestingOneTwoThree')[0], '5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2')

        b38 = Bip38Key('6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd')
        self.assertEqual(b38.decrypt('Satoshi')[0], '5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH')

        # EC multiply, no compression, lot/sequence numbers
        b38 = Bip38Key('6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j')
        self.assertEqual(b38.decrypt('MOLON LABE')[0], '5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8')
        self.assertEqual(b38.lot, 263183)
        self.assertEqual(b38.sequence, 1)

        # EC multiply, no compression, lot/sequence numbers, unicode passphrase
        b38 = Bip38Key('6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH')
        self.assertEqual(b38.decrypt('ΜΟΛΩΝ ΛΑΒΕ')[0], '5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D')
        self.assertEqual(b38.lot, 806938)
        self.assertEqual(b38.sequence, 1)


        # Test raise on bad pass
        b38 = Bip38Key('6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo')
        self.assertRaises(Bip38Key.PasswordError, b38.decrypt, 'a bad password')

        # Test raise on not a Bip 38 key
        self.assertRaises(Bip38Key.DecodeError, Bip38Key, '5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D')
        # Test raise on garbled key
        self.assertRaises(Exception, Bip38Key, '6PYNKZ1EAgYgmQfmNVamxyzgmQfK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo')


    def test_encrypt(self):
        if not Bip38Key.isFast():
            self.skipTest("Bip38 lacks a fast scrypt function, skipping encrypt test")
            return
        # Test encrypt, uncompressed key
        b38 = Bip38Key.encrypt('5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5', 'a very password')
        self.assertFalse(b38.compressed)
        self.assertEqual(b38.typ, Bip38Key.Type.NonECMult)
        self.assertEqual(b38.decrypt('a very password')[0], '5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5')

        # Test encrypt, compressed key, unicode PW
        b38 = Bip38Key.encrypt('L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP', 'éåñ!!∆∆∆¡™£¢…æ÷≥')
        self.assertTrue(b38.compressed)
        self.assertEqual(b38.typ, Bip38Key.Type.NonECMult)
        self.assertEqual(b38.decrypt('éåñ!!∆∆∆¡™£¢…æ÷≥')[0], 'L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP')

        # Test encrypt garbage WIF
        self.assertRaises(Exception, Bip38Key.encrypt, '5HtasLLLLLsadjlaskjalqqj817qwiean', 'a very password')

        # Test EC Mult encrypt intermediate, passphrase: ΜΟΛΩΝ ΛΑΒΕ
        b38 = Bip38Key.ec_mult_from_intermediate_passphrase_string('passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK', True)
        self.assertTrue(b38.compressed)
        self.assertEqual(b38.typ, Bip38Key.Type.ECMult)
        self.assertEqual(b38.lot, 806938)
        self.assertEqual(b38.sequence, 1)
        self.assertTrue(bool(b38.decrypt('ΜΟΛΩΝ ΛΑΒΕ')))

        # Test EC Mult compressed end-to-end, passphrase: ΜΟΛΩΝ ΛΑΒΕ
        b38 = Bip38Key.createECMult('ΜΟΛΩΝ ΛΑΒΕ', (12345, 617), True)
        self.assertTrue(b38.compressed)
        self.assertEqual(b38.typ, Bip38Key.Type.ECMult)
        self.assertEqual(b38.lot, 12345)
        self.assertEqual(b38.sequence, 617)
        self.assertTrue(bool(b38.decrypt('ΜΟΛΩΝ ΛΑΒΕ')))


        # Test EC Mult uncompressed end-to-end, passphrase: ΜΟΛΩΝ ΛΑΒΕ
        b38 = Bip38Key.createECMult('ΜΟΛΩΝ ΛΑΒΕ', (456, 123), False)
        self.assertFalse(b38.compressed)
        self.assertEqual(b38.typ, Bip38Key.Type.ECMult)
        self.assertEqual(b38.lot, 456)
        self.assertEqual(b38.sequence, 123)
        self.assertTrue(bool(b38.decrypt('ΜΟΛΩΝ ΛΑΒΕ')))

        # Success!
