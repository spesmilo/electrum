import unittest
from lib import transaction
from lib import bitcoin
from lib.bitcoin import TYPE_ADDRESS, set_testnet
from sample_tx import sample_tx_mainnet, sample_tx_testnet

import pprint
from lib.keystore import xpubkey_to_address

v2_blob = "0200000001191601a44a81e061502b7bfbc6eaa1cef6d1e6af5308ef96c9342f71dbf4b9b5000000006b483045022100a6d44d0a651790a477e75334adfb8aae94d6612d01187b2c02526e340a7fd6c8022028bdf7a64a54906b13b145cd5dab21a26bd4b85d6044e9b97bceab5be44c2a9201210253e8e0254b0c95776786e40984c1aa32a7d03efa6bdacdea5f421b774917d346feffffff026b20fa04000000001976a914024db2e87dd7cfd0e5f266c5f212e21a31d805a588aca0860100000000001976a91421919b94ae5cefcdf0271191459157cdb41c4cbf88aca6240700"


class TestBCDataStream(unittest.TestCase):
    def test_compact_size(self):
        s = transaction.BCDataStream()
        values = [0, 1, 252, 253, 2 ** 16 - 1, 2 ** 16, 2 ** 32 - 1, 2 ** 32, 2 ** 64 - 1]
        for v in values:
            s.write_compact_size(v)

        with self.assertRaises(transaction.SerializationError):
            s.write_compact_size(-1)

        self.assertEquals(s.input.encode('hex'),
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
        s.write('foobar')
        self.assertEquals(s.read_bytes(3), 'foo')
        self.assertEquals(s.read_bytes(2), 'ba')
        self.assertEquals(s.read_bytes(4), 'r')
        self.assertEquals(s.read_bytes(1), '')


class TransactionBase(unittest.TestCase):
    def do_deserialization(self, samples):
        for sample in samples:
            if 'raw' in sample and 'tx' in sample:
                tx = transaction.Transaction(sample['raw'])
                self.assertEquals(tx.deserialize(), sample['tx'])
            if 'raw_unsigned' in sample and 'tx_unsigned' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                self.assertEquals(tx.deserialize(), sample['tx_unsigned'])

    def do_serialization(self, samples):
        for sample in samples:
            if 'raw' in sample and 'tx' in sample:
                tx = transaction.Transaction(sample['raw'])
                tx.deserialize()
                del (tx.raw)
                self.assertEquals(tx.serialize(), sample['raw'])
            if 'raw_unsigned' in sample and 'tx_unsigned' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                tx.deserialize()
                del (tx.raw)
                self.assertEquals(tx.serialize(), sample['raw_unsigned'])

    def do_outputs(self, samples):
        for sample in samples:
            if 'raw' in sample and 'outputs' in sample:
                tx = transaction.Transaction(sample['raw'])
                self.assertEquals(tx.get_outputs(), sample['outputs'])
            if 'raw_unsigned' in sample and 'outputs' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                self.assertEquals(tx.get_outputs(), sample['outputs'])

    def do_outputaddresses(self, samples):
        for sample in samples:
            if 'raw' in sample and 'outputaddresses' in sample:
                tx = transaction.Transaction(sample['raw'])
                self.assertEquals(tx.get_output_addresses(), sample['outputaddresses'])
            if 'raw_unsigned' in sample and 'outputaddresses' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                self.assertEquals(tx.get_output_addresses(), sample['outputaddresses'])

    def do_has_address(self, samples):
        for sample in samples:
            if 'raw' in sample and 'outputaddresses' in sample:
                tx = transaction.Transaction(sample['raw'])
                for a in sample['outputaddresses']:
                    self.assertTrue(tx.has_address(a))
                self.assertFalse(tx.has_address('1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))
            if 'raw_unsigned' in sample and 'outputaddresses' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                for a in sample['outputaddresses']:
                    self.assertTrue(tx.has_address(a))
                self.assertFalse(tx.has_address('1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))

    def do_txid(self, samples):
        for sample in samples:
            if 'raw' in sample and 'txid' in sample:
                tx = transaction.Transaction(sample['raw'])
                self.assertEquals(tx.txid(), sample['txid'])

    def do_update_signatures(self, samples):
        for sample in samples:
            if 'raw' in sample and 'raw_unsigned' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                with self.assertRaises(transaction.InputValueMissing):
                    tx.update_signatures(sample['raw'])
                if 'inputvalues' in sample:
                    for i, val in enumerate(sample['inputvalues']):
                        tx._inputs[i]['value'] = val
                    tx.update_signatures(sample['raw'])
                    self.assertEquals(tx.raw, sample['raw'])
            elif 'raw' in sample:
                # nothing should happen
                tx = transaction.Transaction(sample['raw'])
                tx.update_signatures(sample['raw'])
                self.assertEquals(tx.raw, sample['raw'])

    def do_sign(self, samples):
        ''' test signing tx - need raw_unsigned, raw, keypairs in tx'''
        for sample in samples:
            if 'raw_unsigned' in sample and 'raw' in sample and 'keypairs' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                tx.deserialize()
                with self.assertRaises(transaction.InputValueMissing):
                    tx.sign(sample['keypairs'])
                if 'inputvalues' in sample:
                    for i, val in enumerate(sample['inputvalues']):
                        tx._inputs[i]['value'] = val
                    tx.sign(sample['keypairs'])
                    self.assertEquals(tx.serialize(),sample['raw'])


class TestTransactionsMainNet(TransactionBase):
    def test_deserialization(self):
        self.do_deserialization(sample_tx_mainnet)

    def test_has_addtrss(self):
        self.do_has_address(sample_tx_mainnet)

    def test_outputaddresses(self):
        self.do_outputaddresses(sample_tx_mainnet)

    def test_outputs(self):
        self.do_outputs(sample_tx_mainnet)

    def test_serialization(self):
        self.do_serialization(sample_tx_mainnet)

    def test_txid(self):
        self.do_txid(sample_tx_mainnet)

    def test_update_signatures(self):
        self.do_update_signatures(sample_tx_mainnet)

    def test_sign(self):
        self.do_sign(sample_tx_mainnet)

    def test_errors(self):
        with self.assertRaises(TypeError):
            transaction.Transaction.pay_script(output_type=None, addr='')

        with self.assertRaises(BaseException):
            xpubkey_to_address('')

    def test_parse_xpub(self):
        res = xpubkey_to_address(
            'fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200')
        self.assertEquals(res, (
        '04ee98d63800824486a1cf5b4376f2f574d86e0a3009a6448105703453f3368e8e1d8d090aaecdd626a45cc49876709a3bbb6dc96a4311b3cac03e225df5f63dfc',
        '19h943e4diLc68GXW7G75QNe2KWuMu7BaJ'))

        res = xpubkey_to_address('fd007d260305ef27224bbcf6cf5238d2b3638b5a78d5')
        self.assertEquals(res, ('fd007d260305ef27224bbcf6cf5238d2b3638b5a78d5', '1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))

    def test_version_field(self):
        tx = transaction.Transaction(v2_blob)
        self.assertEquals(tx.txid(), "b97f9180173ab141b61b9f944d841e60feec691d6daab4d4d932b24dd36606fe")


class TestTransactionsTestNet(TransactionBase):
    def setUp(self):
        set_testnet()

    def tearDown(self):
        # restore mainnet again
        bitcoin.TESTNET = False
        bitcoin.ADDRTYPE_P2PKH = 0
        bitcoin.ADDRTYPE_P2SH = 5
        bitcoin.ADDRTYPE_P2WPKH = 6
        bitcoin.XPRV_HEADER = 0x0488ade4
        bitcoin.XPUB_HEADER = 0x0488b21e
        bitcoin.HEADERS_URL = "http://bitcoincash.com/files/blockchain_headers"
        bitcoin.GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

    def test_deserialization(self):
        self.do_deserialization(sample_tx_testnet)

    def test_has_addtrss(self):
        self.do_has_address(sample_tx_testnet)

    def test_outputaddresses(self):
        self.do_outputaddresses(sample_tx_testnet)

    def test_outputs(self):
        self.do_outputs(sample_tx_testnet)

    def test_serialization(self):
        self.do_serialization(sample_tx_testnet)

    def test_txid(self):
        self.do_txid(sample_tx_testnet)

    def test_update_signatures(self):
        self.do_update_signatures(sample_tx_testnet)

    def test_sign(self):
        self.do_sign(sample_tx_testnet)


class NetworkMock(object):
    def __init__(self, unspent):
        self.unspent = unspent

    def synchronous_get(self, arg):
        return self.unspent

