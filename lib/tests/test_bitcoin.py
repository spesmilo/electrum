import unittest
import sys
from ecdsa.util import number_to_string

from lib.bitcoin import (
    generator_secp256k1, point_to_ser, public_key_to_bc_address, EC_KEY,
    bip32_root, bip32_public_derivation, bip32_private_derivation, pw_encode,
    pw_decode, Hash, public_key_from_private_key, address_from_private_key,
    is_valid, is_private_key, xpub_from_xprv)

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

        signature = eck.sign_message(message, True, addr_c)
        #print signature
        EC_KEY.verify_message(addr_c, signature, message)

    def test_bip32(self):
        # see https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        xpub, xprv = self._do_test_bip32("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000", testnet=False)
        assert xpub == "Ltub2dSSz9YcDJpFxJ331ypEC1VHQTk8CHdiiVEsiqFVQwH7fAbxnFwEf1wfyQmhxqRjAU2YVwgGPnWBAEoFtAgKJrJeqKNrFTTJzbNbDMUZjYL"
        assert xprv == "Ltpv7CG7PN84yAHJLRLCmNKr7Rf4xu3w8354dy8r3rVCUkVX4oQtTLtoeQqQj3yd9Y9xeB5xkrcvtm6NdWyKqytn7q4pWzBZkH6BGmF86hsLPtJ"

        xpub, xprv = self._do_test_bip32("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542","m/0/2147483647'/1/2147483646'/2", testnet=False)
        assert xpub == "Ltub2cDKEjzUszUwKqD4DAR9Ta7JZHTfS85qrW5sacH5HhBaCtp5BQ8Bbyk2zhMAUYh1s5aPwMUFFVCRkri9mgdXRcNa9fhwwfj668GS8jig9Sj"
        assert xprv == "Ltpv7B2ydxZwdqwyhxWDxYvmNzH67imUMsXBmyyqudWnMWPycXczrV5kbNdmkMAoA4mQk9hWMB6DFiXp8udYNmeKyLyXVsS5xhjXraAHN6qF1PS"

    def test_bip32_testnet(self):
        xpub, xprv = self._do_test_bip32("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000", testnet=True)
        assert xpub == "ttub4iNCzaWah84FUoDUuprcpYoztSizaGtcp1EkHLF9hD5sQgjenThtvLgiK9XLPknGnUnCsgr4jCbXE5UScpRTk1yC5E9QwRiizwYEMTD5WmZ"
        assert xprv == "ttpv9HBsPo63SyXHrvWefDNEjxynSt2oW2KxjV8icMUrm2JGpKYaTYfTujaT4njFaTWWGBqd8bnjEBBihMeWaddvYzjMktx8SFMbH7QmEqDEKag"

        xpub, xprv = self._do_test_bip32("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542","m/0/2147483647'/1/2147483646'/2", testnet=True)
        assert xpub == "ttub4h95FAxTMoivrLPW71TY67S23GSXp7Ljx25k97GjZxzKxQwmBbtqsJV5LS6nuU3ZV6L4K6e3auHmphPLWLNfrn37PaUWddzW6US5Gsv5T8x"
        assert xprv == "ttpv9FxjePXv7fByETgfrPyA1XbobhkLjrn5sVyiU8WSdnCjN3kgrgrQrhNp65vRaz7xNATAivG1b8dACkJj7RPUQWe4jnCeefzwrvKvW92SgA6"

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
        xpub = "Ltub2dSSz9YcDJpFxJ331ypEC1VHQTk8CHdiiVEsiqFVQwH7fAbxnFwEf1wfyQmhxqRjAU2YVwgGPnWBAEoFtAgKJrJeqKNrFTTJzbNbDMUZjYL"
        xprv = "Ltpv7CG7PN84yAHJLRLCmNKr7Rf4xu3w8354dy8r3rVCUkVX4oQtTLtoeQqQj3yd9Y9xeB5xkrcvtm6NdWyKqytn7q4pWzBZkH6BGmF86hsLPtJ"

        result = xpub_from_xprv(xprv)
        self.assertEqual(result, xpub)

    def test_xpub_from_xprv_testnet(self):
        """We can derive the xpub key from a xprv using testnet headers."""
        xpub = "ttub4iNCzaWah84FUoDUuprcpYoztSizaGtcp1EkHLF9hD5sQgjenThtvLgiK9XLPknGnUnCsgr4jCbXE5UScpRTk1yC5E9QwRiizwYEMTD5WmZ"
        xprv = "ttpv9HBsPo63SyXHrvWefDNEjxynSt2oW2KxjV8icMUrm2JGpKYaTYfTujaT4njFaTWWGBqd8bnjEBBihMeWaddvYzjMktx8SFMbH7QmEqDEKag"
        result = xpub_from_xprv(xprv, testnet=True)
        self.assertEqual(result, xpub)


class Test_keyImport(unittest.TestCase):
    """ The keys used in this class are TEST keys from
        https://en.bitcoin.it/wiki/BIP_0032_TestVectors"""

    private_key = "TAD8rebzCEyYBZWCqjsKxeH9YjenLqX55MNgqGyeQkHdN5T7ejYH"
    public_key_hex = "0220d43256bdb32c7517bb0e3f086f54ec351d2299a5808b6a36c7ba434094c8ef"
    main_address = "LYUdH72gHL4gcW8pPwaJm4uCFbkCXABAZW"

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


