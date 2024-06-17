# Copyright (c) 2018-2023 The HWI developers
# Copyright (c) 2023 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# originally from https://github.com/bitcoin-core/HWI/blob/f5a9b29c00e483cc99a1b8f4f5ef75413a092869/test/test_descriptor.py

from binascii import unhexlify
import unittest

from electrum.descriptor import (
    parse_descriptor,
    MultisigDescriptor,
    SHDescriptor,
    TRDescriptor,
    PKHDescriptor,
    WPKHDescriptor,
    WSHDescriptor,
    PubkeyProvider,
)
from electrum import ecc
from electrum.util import bfh

from . import ElectrumTestCase, as_testnet


class TestDescriptor(ElectrumTestCase):

    @as_testnet
    def test_parse_descriptor_with_origin(self):
        d = "wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, "/0/0")
        self.assertEqual(desc.pubkeys[0].get_full_derivation_path(), "m/84h/1h/0h/0/0")
        self.assertEqual(desc.pubkeys[0].get_full_derivation_int_list(), [16777216, 2147483732, 2147483649, 2147483648, 0, 0])
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand()
        self.assertEqual(e.output_script, unhexlify("0014d95fc47eada9e4c3cf59a2cbf9e96517c3ba2efa"))
        self.assertEqual(e.redeem_script, None)
        self.assertEqual(e.witness_script, None)
        self.assertEqual(e.address(), "tb1qm90ugl4d48jv8n6e5t9ln6t9zlpm5th690vysp")

    @as_testnet
    def test_parse_multisig_descriptor_with_origin(self):
        d = "wsh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0))"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WSHDescriptor))
        self.assertTrue(isinstance(desc.subdescriptors[0], MultisigDescriptor))
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].deriv_path, "/0/0")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].get_full_derivation_path(), "m/48h/0h/0h/2h/0/0")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].get_full_derivation_int_list(), [16777216, 2147483696, 2147483648, 2147483648, 2147483650, 0, 0])

        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.fingerprint.hex(), "00000002")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].pubkey, "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].deriv_path, "/0/0")
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand()
        self.assertEqual(e.output_script, unhexlify("002084b64b2b8651df8fd3e9735f6269edbf9e03abf619ae0788be9f17bf18e83d59"))
        self.assertEqual(e.redeem_script, None)
        self.assertEqual(e.witness_script, unhexlify("522102c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c721033a4f18d2b498273ed7439c59f6d8a673d5b9c67a03163d530e12c941ca22be3352ae"))

        d = "sh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0))"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, SHDescriptor))
        self.assertTrue(isinstance(desc.subdescriptors[0], MultisigDescriptor))
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].deriv_path, "/0/0")

        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.fingerprint.hex(), "00000002")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].pubkey, "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].deriv_path, "/0/0")
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand()
        self.assertEqual(e.output_script, unhexlify("a91495ee6326805b1586bb821fc3c0eeab2c68441b4187"))
        self.assertEqual(e.redeem_script, unhexlify("522102c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c721033a4f18d2b498273ed7439c59f6d8a673d5b9c67a03163d530e12c941ca22be3352ae"))
        self.assertEqual(e.witness_script, None)

        d = "sh(wsh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0)))"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, SHDescriptor))
        self.assertTrue(isinstance(desc.subdescriptors[0], WSHDescriptor))
        self.assertTrue(isinstance(desc.subdescriptors[0].subdescriptors[0], MultisigDescriptor))
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[0].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[0].deriv_path, "/0/0")

        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[1].origin.fingerprint.hex(), "00000002")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[1].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[1].pubkey, "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty")
        self.assertEqual(desc.subdescriptors[0].subdescriptors[0].pubkeys[1].deriv_path, "/0/0")
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand()
        self.assertEqual(e.output_script, unhexlify("a914779ae0f6958e98b997cc177f9b554289905fbb5587"))
        self.assertEqual(e.redeem_script, unhexlify("002084b64b2b8651df8fd3e9735f6269edbf9e03abf619ae0788be9f17bf18e83d59"))
        self.assertEqual(e.witness_script, unhexlify("522102c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c721033a4f18d2b498273ed7439c59f6d8a673d5b9c67a03163d530e12c941ca22be3352ae"))

    @as_testnet
    def test_parse_descriptor_without_origin(self):
        d = "wpkh(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin, None)
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, "/0/0")
        self.assertEqual(desc.pubkeys[0].get_full_derivation_path(), "m/0/0")
        self.assertEqual(desc.pubkeys[0].get_full_derivation_int_list(), [0, 0])
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand()
        self.assertEqual(e.output_script, unhexlify("0014d95fc47eada9e4c3cf59a2cbf9e96517c3ba2efa"))
        self.assertEqual(e.redeem_script, None)
        self.assertEqual(e.witness_script, None)

    @as_testnet
    def test_parse_descriptor_with_origin_fingerprint_only(self):
        d = "wpkh([00000001]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(len(desc.pubkeys[0].origin.path), 0)
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, "/0/0")
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand()
        self.assertEqual(e.output_script, unhexlify("0014d95fc47eada9e4c3cf59a2cbf9e96517c3ba2efa"))
        self.assertEqual(e.redeem_script, None)
        self.assertEqual(e.witness_script, None)

    def test_parse_descriptor_with_key_at_end_with_origin(self):
        d = "wpkh([00000001/84h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h/0/0")
        self.assertEqual(desc.pubkeys[0].pubkey, "02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7")
        self.assertEqual(desc.pubkeys[0].deriv_path, None)
        self.assertEqual(desc.pubkeys[0].get_full_derivation_path(), "m/84h/1h/0h/0/0")
        self.assertEqual(desc.pubkeys[0].get_full_derivation_int_list(), [16777216, 2147483732, 2147483649, 2147483648, 0, 0])
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand()
        self.assertEqual(e.output_script, unhexlify("0014d95fc47eada9e4c3cf59a2cbf9e96517c3ba2efa"))
        self.assertEqual(e.redeem_script, None)
        self.assertEqual(e.witness_script, None)

        d = "pkh([00000001/84h/1h/0h/0/0]02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, PKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h/0/0")
        self.assertEqual(desc.pubkeys[0].pubkey, "02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7")
        self.assertEqual(desc.pubkeys[0].deriv_path, None)
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand()
        self.assertEqual(e.output_script, unhexlify("76a914d95fc47eada9e4c3cf59a2cbf9e96517c3ba2efa88ac"))
        self.assertEqual(e.redeem_script, None)
        self.assertEqual(e.witness_script, None)

    def test_parse_descriptor_with_key_at_end_without_origin(self):
        d = "wpkh(02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin, None)
        self.assertEqual(desc.pubkeys[0].pubkey, "02c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7")
        self.assertEqual(desc.pubkeys[0].deriv_path, None)
        self.assertEqual(desc.pubkeys[0].get_full_derivation_path(), "m")
        self.assertEqual(desc.pubkeys[0].get_full_derivation_int_list(), [])
        self.assertEqual(desc.to_string_no_checksum(), d)

    def test_parse_empty_descriptor(self):
        self.assertRaises(ValueError, parse_descriptor, "")

    @as_testnet
    def test_parse_descriptor_replace_h(self):
        d = "wpkh([00000001/84'/1'/0']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")

    @as_testnet
    def test_parse_descriptor_unknown_notation_for_hardened_derivation(self):
        with self.assertRaises(ValueError):
            desc = parse_descriptor("wpkh([00000001/84x/1x/0x]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)")
        with self.assertRaises(ValueError):
            desc = parse_descriptor("wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0x)")

    def test_checksums(self):
        with self.subTest(msg="Valid checksum"):
            self.assertIsNotNone(parse_descriptor("sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#5js07kwj"))
            self.assertIsNotNone(parse_descriptor("sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#hgmsckna"))
            self.assertIsNotNone(parse_descriptor("sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))"))
            self.assertIsNotNone(parse_descriptor("sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))"))
        with self.subTest(msg="Empty Checksum"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#")
        with self.subTest(msg="Too long Checksum"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#5js07kwjq")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#hgmscknaq")
        with self.subTest(msg="Too Short Checksum"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#5js07kw")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#hgmsckn")
        with self.subTest(msg="Error in Payload"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(3,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxf")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(3,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5")
        with self.subTest(msg="Error in Checksum"):
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#5js07kej")
            self.assertRaises(ValueError, parse_descriptor, "sh(multi(2,[00000000/111h/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09y5")

    @as_testnet
    def test_tr_descriptor(self):
        d = "tr([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, TRDescriptor))
        self.assertEqual(len(desc.pubkeys), 1)
        self.assertEqual(len(desc.subdescriptors), 0)
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, "/0/0")
        self.assertEqual(desc.get_max_tree_depth(), None)
        self.assertEqual(desc.to_string_no_checksum(), d)

        d = "tr([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,{pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B),{{pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B),pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)},pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)}})"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, TRDescriptor))
        self.assertEqual(len(desc.subdescriptors), 4)
        self.assertEqual(len(desc.desc_tree), 2)
        self.assertEqual(len(desc.pubkeys), 1)
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, "/0/0")
        self.assertEqual(desc.desc_tree[0].to_string_no_checksum(), "pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)")
        self.assertEqual(desc.desc_tree[1][0][0].to_string_no_checksum(), "pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)")
        self.assertEqual(desc.desc_tree[1][0][1].to_string_no_checksum(), "pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)")
        self.assertEqual(desc.desc_tree[1][1].to_string_no_checksum(), "pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)")
        self.assertEqual(desc.get_max_tree_depth(), 3)
        self.assertEqual(desc.to_string_no_checksum(), d)

    def test_tr_descriptor_bip386(self):
        # test vectors from https://github.com/bitcoin/bips/blob/e2f7481a132e1c5863f5ffcbff009964d7c2af20/bip-0386.mediawiki#test-vectors
        # TODO add missing tests
        self.assertEqual(
            "512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11",
            parse_descriptor("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)").expand().output_script.hex())
        self.assertEqual(
            "512017cf18db381d836d8923b1bdb246cfcd818da1a9f0e6e7907f187f0b2f937754",
            parse_descriptor("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))").expand().output_script.hex())

    @as_testnet
    def test_parse_descriptor_with_range(self):
        d = "wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*)"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, "/0/*")
        self.assertEqual(desc.to_string_no_checksum(), d)
        with self.assertRaises(ValueError):  # "pos" arg needed due to "*"
            e = desc.expand()
        e = desc.expand(pos=7)
        self.assertEqual(e.output_script, unhexlify("0014c5f80de08f6ae8dd720bf4e4948ba498c96256a1"))
        self.assertEqual(e.redeem_script, None)
        self.assertEqual(e.witness_script, None)

        with self.assertRaises(ValueError):  # wildcard only allowed in last position
            parse_descriptor("wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/*/0)")
        with self.assertRaises(ValueError):  # only one wildcard(*) is allowed
            parse_descriptor("wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/*/*)")

    @as_testnet
    def test_parse_multisig_descriptor_with_range(self):
        d = "wsh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/*))"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, WSHDescriptor))
        self.assertTrue(isinstance(desc.subdescriptors[0], MultisigDescriptor))
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.subdescriptors[0].pubkeys[0].deriv_path, "/0/*")

        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.fingerprint.hex(), "00000002")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].origin.get_derivation_path(), "m/48h/0h/0h/2h")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].pubkey, "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty")
        self.assertEqual(desc.subdescriptors[0].pubkeys[1].deriv_path, "/0/*")
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand(pos=7)
        self.assertEqual(e.output_script, unhexlify("0020453cdf90aef0997947bc0605481f81dd2978ecd2d04ac36fb57397a82341682d"))
        self.assertEqual(e.redeem_script, None)
        self.assertEqual(e.witness_script, unhexlify("5221034e703dfcd64f23ad5d6156ee3b9dd7566137626c663bb521bf710957599723342102c35627535d26de98ae749b7a7849df99cbe53af795005437ca647c8af9a006af52ae"))

    @as_testnet
    def test_multisig_descriptor_with_mixed_range(self):
        d = "sh(wsh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0)))"
        desc = parse_descriptor(d)
        e = desc.expand(pos=7)
        self.assertEqual(e.output_script, bfh("a914644ece12bab2f84ad6de96ec18de51e6168c028987"))
        self.assertEqual(e.redeem_script, bfh("0020824ce4ffab74a8d09c2f77ed447fb040ea5dfbed06f8e3b3327127a18634f6a7"))
        self.assertEqual(e.witness_script, bfh("5221034e703dfcd64f23ad5d6156ee3b9dd7566137626c663bb521bf7109575997233421033a4f18d2b498273ed7439c59f6d8a673d5b9c67a03163d530e12c941ca22be3352ae"))
        self.assertEqual(e.address(), "2N2Pbxw3HNJ9jrUw8LCSfXyDWx9TKGRT2an")

    @as_testnet
    def test_uncompressed_pubkey_in_segwit(self):
        pubkey = ecc.ECPubkey(bfh("02a0507c8bb3d96dfd7731bafb0ae30e6ed10bbadd6a9f9f88eaf0602b9cc99adc"))
        pubkey_comp_hex = pubkey.get_public_key_hex(compressed=True)
        pubkey_uncomp_hex = pubkey.get_public_key_hex(compressed=False)
        self.assertEqual(pubkey_comp_hex, "02a0507c8bb3d96dfd7731bafb0ae30e6ed10bbadd6a9f9f88eaf0602b9cc99adc")
        self.assertEqual(pubkey_uncomp_hex, "04a0507c8bb3d96dfd7731bafb0ae30e6ed10bbadd6a9f9f88eaf0602b9cc99adc3ccfc29410b8f23c15d88413a6b88c8cd44b016a7f1dd91a8d64c3107c6bce1a")
        # pkh
        desc = parse_descriptor(f"pkh({pubkey_comp_hex})")
        self.assertEqual(desc.expand().output_script, bfh("76a9140297bde2689a3c79ffe050583b62f86f2d9dae5488ac"))
        desc = parse_descriptor(f"pkh({pubkey_uncomp_hex})")
        self.assertEqual(desc.expand().output_script, bfh("76a914e1f4a76b122f0288b013404cd52a9d1de0ced3c488ac"))
        # wpkh
        desc = parse_descriptor(f"wpkh({pubkey_comp_hex})")
        self.assertEqual(desc.expand().output_script, bfh("00140297bde2689a3c79ffe050583b62f86f2d9dae54"))
        with self.assertRaises(ValueError):  # only compressed public keys can be used in segwit scripts
            desc = parse_descriptor(f"wpkh({pubkey_uncomp_hex})")
        # sh(wsh(multi()))
        desc = parse_descriptor(f"sh(wsh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*,{pubkey_comp_hex})))")
        self.assertEqual(desc.expand(pos=2).output_script, bfh("a9148f162cce29ad81e63ed45cd09aff83418316eab687"))
        with self.assertRaises(ValueError):  # only compressed public keys can be used in segwit scripts
            desc = parse_descriptor(f"sh(wsh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/*,{pubkey_uncomp_hex})))")

    @as_testnet
    def test_parse_descriptor_context(self):
        desc = parse_descriptor("sh(wsh(sortedmulti(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0)))")
        self.assertTrue(isinstance(desc, SHDescriptor))
        with self.assertRaises(ValueError):  # Can only have sh() at top level
            desc = parse_descriptor("wsh(sh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0)))")
        with self.assertRaises(ValueError):  # Can only have wsh() at top level or inside sh()
            desc = parse_descriptor("wsh(wsh(multi(2,[00000001/48h/0h/0h/2h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,[00000002/48h/0h/0h/2h]tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty/0/0)))")

        desc = parse_descriptor("wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)")
        self.assertTrue(isinstance(desc, WPKHDescriptor))
        with self.assertRaises(ValueError):  # Can only have wpkh() at top level or inside sh()
            desc = parse_descriptor("wsh(wpkh([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0))")

    def test_parse_descriptor_ypub_zpub_forbidden(self):
        desc = parse_descriptor("wpkh([535e473f/0h]xpub68W3CJPrQzHhTQcHM6tbCvNVB9ih4tbzsFBLwe7zZUj5uHuhxBUhvnXe1RQhbKCTiTj3D7kXni6yAD88i2xnjKHaJ5NqTtHawKnPFCDnmo4/0/*)")
        with self.assertRaises(ValueError):  # only standard xpub/xprv allowed
            desc = parse_descriptor("wpkh([535e473f/0h]ypub6TLJVy4mZfqBJhoQBTgDR1TzM7s91WbVnMhZj31swV6xxPiwCqeGYrBn2dNHbDrP86qqxbM6FNTX3VjhRjNoXYyBAR5G3o75D3r2djmhZwM/0/*)")
        with self.assertRaises(ValueError):  # only standard xpub/xprv allowed
            desc = parse_descriptor("wpkh([535e473f/0h]zpub6nAZodjgiMNf9zzX1pTqd6ZVX61ax8azhUDnWRumKVUr1VYATVoqAuqv3qKsb8WJXjxei4wei2p4vnMG9RnpKnen2kmgdhvZUmug2NnHNsr/0/*)")

    @as_testnet
    def test_sortedmulti_ranged_pubkey_order(self):
        xpub1 = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
        xpub2 = "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty"
        # if ranged, we sort lexicographically
        desc = parse_descriptor(f"sh(wsh(sortedmulti(2,[00000001/48h/0h/0h/2h]{xpub1}/0/*,[00000002/48h/0h/0h/2h]{xpub2}/0/*)))")
        self.assertEqual([xpub1, xpub2], [pk.pubkey for pk in desc.subdescriptors[0].subdescriptors[0].pubkeys])
        desc = parse_descriptor(f"sh(wsh(sortedmulti(2,[00000002/48h/0h/0h/2h]{xpub2}/0/*,[00000001/48h/0h/0h/2h]{xpub1}/0/*)))")
        self.assertEqual([xpub1, xpub2], [pk.pubkey for pk in desc.subdescriptors[0].subdescriptors[0].pubkeys])
        # if unsorted "multi", don't touch order
        desc = parse_descriptor(f"sh(wsh(multi(2,[00000002/48h/0h/0h/2h]{xpub2}/0/*,[00000001/48h/0h/0h/2h]{xpub1}/0/*)))")
        self.assertEqual([xpub2, xpub1], [pk.pubkey for pk in desc.subdescriptors[0].subdescriptors[0].pubkeys])

    @as_testnet
    def test_sortedmulti_unranged_pubkey_order(self):
        xpub1 = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
        xpub2 = "tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty"
        # if not ranged, we sort according to final derived pubkey order
        desc = parse_descriptor(f"sh(wsh(sortedmulti(2,[00000001/48h/0h/0h/2h]{xpub1}/0/0,[00000002/48h/0h/0h/2h]{xpub2}/0/0)))")
        self.assertEqual([xpub1, xpub2], [pk.pubkey for pk in desc.subdescriptors[0].subdescriptors[0].pubkeys])
        desc = parse_descriptor(f"sh(wsh(sortedmulti(2,[00000001/48h/0h/0h/2h]{xpub1}/0/1,[00000002/48h/0h/0h/2h]{xpub2}/0/1)))")
        self.assertEqual([xpub2, xpub1], [pk.pubkey for pk in desc.subdescriptors[0].subdescriptors[0].pubkeys])
        desc = parse_descriptor(f"sh(wsh(sortedmulti(2,[00000001/48h/0h/0h/2h]{xpub1}/0/4,[00000002/48h/0h/0h/2h]{xpub2}/0/4)))")
        self.assertEqual([xpub1, xpub2], [pk.pubkey for pk in desc.subdescriptors[0].subdescriptors[0].pubkeys])
        # if unsorted "multi", don't touch order
        desc = parse_descriptor(f"sh(wsh(multi(2,[00000001/48h/0h/0h/2h]{xpub1}/0/1,[00000002/48h/0h/0h/2h]{xpub2}/0/1)))")
        self.assertEqual([xpub1, xpub2], [pk.pubkey for pk in desc.subdescriptors[0].subdescriptors[0].pubkeys])

    def test_pubkey_provider_deriv_path(self):
        xpub = "xpub68W3CJPrQzHhTQcHM6tbCvNVB9ih4tbzsFBLwe7zZUj5uHuhxBUhvnXe1RQhbKCTiTj3D7kXni6yAD88i2xnjKHaJ5NqTtHawKnPFCDnmo4"
        # valid:
        pp = PubkeyProvider(origin=None, pubkey=xpub, deriv_path="/1/7")
        pp = PubkeyProvider(origin=None, pubkey=xpub, deriv_path="/1/*")
        # invalid:
        with self.assertRaises(ValueError):
            pp = PubkeyProvider(origin=None, pubkey=xpub, deriv_path="1")
        with self.assertRaises(ValueError):
            pp = PubkeyProvider(origin=None, pubkey=xpub, deriv_path="1/7")
        with self.assertRaises(ValueError):
            pp = PubkeyProvider(origin=None, pubkey=xpub, deriv_path="m/1/7")
        with self.assertRaises(ValueError):
            pp = PubkeyProvider(origin=None, pubkey=xpub, deriv_path="*/7")
        with self.assertRaises(ValueError):
            pp = PubkeyProvider(origin=None, pubkey=xpub, deriv_path="*/*")

        pubkey_hex = "02a0507c8bb3d96dfd7731bafb0ae30e6ed10bbadd6a9f9f88eaf0602b9cc99adc"
        # valid:
        pp = PubkeyProvider(origin=None, pubkey=pubkey_hex, deriv_path=None)
        # invalid:
        with self.assertRaises(ValueError):
            pp = PubkeyProvider(origin=None, pubkey=pubkey_hex, deriv_path="/1/7")
