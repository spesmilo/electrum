# Copyright (c) 2018-2023 The HWI developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# originally from https://github.com/bitcoin-core/HWI/blob/f5a9b29c00e483cc99a1b8f4f5ef75413a092869/test/test_descriptor.py

from binascii import unhexlify

from electrum.descriptor import (
    parse_descriptor,
    MultisigDescriptor,
    SHDescriptor,
    TRDescriptor,
    PKHDescriptor,
    WPKHDescriptor,
    WSHDescriptor,
)

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
        self.assertEqual(desc.to_string_no_checksum(), d)
        e = desc.expand()
        self.assertEqual(e.output_script, unhexlify("0014d95fc47eada9e4c3cf59a2cbf9e96517c3ba2efa"))
        self.assertEqual(e.redeem_script, None)
        self.assertEqual(e.witness_script, None)

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
        self.assertEqual(desc.to_string_no_checksum(), d)

    def test_parse_empty_descriptor(self):
        self.assertRaises(ValueError, parse_descriptor, "")

    @as_testnet
    def test_parse_descriptor_replace_h(self):
        d = "wpkh([00000001/84'/1'/0']tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0)"
        desc = parse_descriptor(d)
        self.assertIsNotNone(desc)
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")

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
        self.assertEqual(desc.to_string_no_checksum(), d)

        d = "tr([00000001/84h/1h/0h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/0,{pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B),{{pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B),pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)},pk(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B)}})"
        desc = parse_descriptor(d)
        self.assertTrue(isinstance(desc, TRDescriptor))
        self.assertEqual(len(desc.subdescriptors), 4)
        self.assertEqual(desc.pubkeys[0].origin.fingerprint.hex(), "00000001")
        self.assertEqual(desc.pubkeys[0].origin.get_derivation_path(), "m/84h/1h/0h")
        self.assertEqual(desc.pubkeys[0].pubkey, "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
        self.assertEqual(desc.pubkeys[0].deriv_path, "/0/0")
        self.assertEqual(desc.depths, [1, 3, 3, 2])
        self.assertEqual(desc.to_string_no_checksum(), d)
