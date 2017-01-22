from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import six
import unittest
from lib import transaction
from lib.bitcoin import TYPE_ADDRESS

import pprint
from lib.keystore import xpubkey_to_address

from lib.util import bh2u

from lib.util import bh2u

unsigned_blob = '01000000012a5c9a94fcde98f5581cd00162c60a13936ceb75389ea65bf38633b424eb4031000000005701ff4c53ff0488b21e03ef2afea18000000089689bff23e1e7fb2f161daa37270a97a3d8c2e537584b2d304ecb47b86d21fc021b010d3bd425f8cf2e04824bfdf1f1f5ff1d51fadd9a41f9e3fb8dd3403b1bfe00000000ffffffff0140420f00000000001976a914230ac37834073a42146f11ef8414ae929feaafc388ac00000000'
signed_blob = '01000000012a5c9a94fcde98f5581cd00162c60a13936ceb75389ea65bf38633b424eb4031000000006c493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6ffffffff0140420f00000000001976a914230ac37834073a42146f11ef8414ae929feaafc388ac00000000'
v2_blob = "0200000001191601a44a81e061502b7bfbc6eaa1cef6d1e6af5308ef96c9342f71dbf4b9b5000000006b483045022100a6d44d0a651790a477e75334adfb8aae94d6612d01187b2c02526e340a7fd6c8022028bdf7a64a54906b13b145cd5dab21a26bd4b85d6044e9b97bceab5be44c2a9201210253e8e0254b0c95776786e40984c1aa32a7d03efa6bdacdea5f421b774917d346feffffff026b20fa04000000001976a914024db2e87dd7cfd0e5f266c5f212e21a31d805a588aca0860100000000001976a91421919b94ae5cefcdf0271191459157cdb41c4cbf88aca6240700"

class TestBCDataStream(unittest.TestCase):

    def test_compact_size(self):
        s = transaction.BCDataStream()
        values = [0, 1, 252, 253, 2**16-1, 2**16, 2**32-1, 2**32, 2**64-1]
        for v in values:
            s.write_compact_size(v)

        with self.assertRaises(transaction.SerializationError):
            s.write_compact_size(-1)

        self.assertEquals(bh2u(s.input),
                          '0001fcfdfd00fdfffffe00000100feffffffffff0000000001000000ffffffffffffffffff')
        for v in values:
            self.assertEquals(s.read_compact_size(), v)

        with self.assertRaises(IndexError):
            s.read_compact_size()

    def test_string(self):
        s = transaction.BCDataStream()
        with self.assertRaises(transaction.SerializationError):
            s.read_string()

        msgs = ['Hello', ' ', 'World', '', '!']
        for msg in msgs:
            s.write_string(msg)
        for msg in msgs:
            self.assertEquals(s.read_string(), msg)

        with self.assertRaises(transaction.SerializationError):
            s.read_string()

    def test_bytes(self):
        s = transaction.BCDataStream()
        s.write(b'foobar')
        self.assertEquals(s.read_bytes(3), b'foo')
        self.assertEquals(s.read_bytes(2), b'ba')
        self.assertEquals(s.read_bytes(4), b'r')
        self.assertEquals(s.read_bytes(1), b'')

class TestTransaction(unittest.TestCase):

    def test_tx_unsigned(self):
        expected = {
            'inputs': [{
                'type': 'p2pkh',
                'address': '1446oU3z268EeFgfcwJv6X2VBXHfoYxfuD',
                'num_sig': 1,
                'prevout_hash': '3140eb24b43386f35ba69e3875eb6c93130ac66201d01c58f598defc949a5c2a',
                'prevout_n': 0,
                'pubkeys': ['02e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6'],
                'scriptSig': '01ff4c53ff0488b21e03ef2afea18000000089689bff23e1e7fb2f161daa37270a97a3d8c2e537584b2d304ecb47b86d21fc021b010d3bd425f8cf2e04824bfdf1f1f5ff1d51fadd9a41f9e3fb8dd3403b1bfe00000000',
                'sequence': 4294967295,
                'signatures': [None],
                'x_pubkeys': ['ff0488b21e03ef2afea18000000089689bff23e1e7fb2f161daa37270a97a3d8c2e537584b2d304ecb47b86d21fc021b010d3bd425f8cf2e04824bfdf1f1f5ff1d51fadd9a41f9e3fb8dd3403b1bfe00000000']}],
            'lockTime': 0,
            'outputs': [{
                'address': '14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs',
                'prevout_n': 0,
                'scriptPubKey': '76a914230ac37834073a42146f11ef8414ae929feaafc388ac',
                'type': TYPE_ADDRESS,
                'value': 1000000}],
                'version': 1
        }
        tx = transaction.Transaction(unsigned_blob)
        self.assertEquals(tx.deserialize(), expected)
        self.assertEquals(tx.deserialize(), None)

        self.assertEquals(tx.as_dict(), {'hex': unsigned_blob, 'complete': False, 'final': True})
        self.assertEquals(tx.get_outputs(), [('14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs', 1000000)])
        self.assertEquals(tx.get_output_addresses(), ['14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs'])

        self.assertTrue(tx.has_address('14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs'))
        self.assertTrue(tx.has_address('1446oU3z268EeFgfcwJv6X2VBXHfoYxfuD'))
        self.assertFalse(tx.has_address('1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))

        self.assertEquals(tx.serialize(), unsigned_blob)

        tx.update_signatures(signed_blob)
        self.assertEquals(tx.raw, signed_blob)

        tx.update(unsigned_blob)
        tx.raw = None
        blob = str(tx)
        self.assertEquals(transaction.deserialize(blob), expected)

    def test_tx_signed(self):
        expected = {
            'inputs': [{
                'type': 'p2pkh',
                'address': '1446oU3z268EeFgfcwJv6X2VBXHfoYxfuD',
                'num_sig': 1,
                'prevout_hash': '3140eb24b43386f35ba69e3875eb6c93130ac66201d01c58f598defc949a5c2a',
                'prevout_n': 0,
                'pubkeys': ['02e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6'],
                'scriptSig': '493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6',
                'sequence': 4294967295,
                'signatures': ['3046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d98501'],
                'x_pubkeys': ['02e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6']}],
            'lockTime': 0,
            'outputs': [{
                'address': '14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs',
                'prevout_n': 0,
                'scriptPubKey': '76a914230ac37834073a42146f11ef8414ae929feaafc388ac',
                'type': TYPE_ADDRESS,
                'value': 1000000}],
            'version': 1
        }
        tx = transaction.Transaction(signed_blob)
        self.assertEquals(tx.deserialize(), expected)
        self.assertEquals(tx.deserialize(), None)
        self.assertEquals(tx.as_dict(), {'hex': signed_blob, 'complete': True, 'final': True})

        self.assertEquals(tx.serialize(), signed_blob)

        tx.update_signatures(signed_blob)

    def test_errors(self):
        with self.assertRaises(TypeError):
            transaction.Transaction.pay_script(output_type=None, addr='')

        with self.assertRaises(BaseException):
            xpubkey_to_address('')

    def test_parse_xpub(self):
        res = xpubkey_to_address('fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200')
        self.assertEquals(res, ('04ee98d63800824486a1cf5b4376f2f574d86e0a3009a6448105703453f3368e8e1d8d090aaecdd626a45cc49876709a3bbb6dc96a4311b3cac03e225df5f63dfc', '19h943e4diLc68GXW7G75QNe2KWuMu7BaJ'))

        res = xpubkey_to_address('fd007d260305ef27224bbcf6cf5238d2b3638b5a78d5')
        self.assertEquals(res, ('fd007d260305ef27224bbcf6cf5238d2b3638b5a78d5', '1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))

    def test_version_field(self):
        tx = transaction.Transaction(v2_blob)
        self.assertEquals(tx.txid(), "b97f9180173ab141b61b9f944d841e60feec691d6daab4d4d932b24dd36606fe")


class NetworkMock(object):

    def __init__(self, unspent):
        self.unspent = unspent

    def synchronous_get(self, arg):
        return self.unspent
