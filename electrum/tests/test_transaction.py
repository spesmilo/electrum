import unittest

from electrum import transaction
from electrum.bitcoin import TYPE_ADDRESS, TYPE_SCRIPT
from electrum.keystore import xpubkey_to_address
from electrum.util import bh2u, bfh

from . import SequentialTestCase, TestCaseForTestnet
from .test_bitcoin import needs_test_with_all_ecc_implementations

unsigned_blob = '45505446ff00010000000001f8ddeb9a69819ed38bec0d121a241bbf2465f61263068881a28cc2b71c4b5525010000005701ff4c53ff0488b21e000000000000000000350138c626aac760ea9eedb47287f12c4d783910821c5602d5f8ed933a8f0d95025fb1f45ecb87f2089dc8b0257fc23cc5fd13ae9d4e14c08b0398002d68eae14c00000000feffffff0301a41dc2f5b4e17ec90d88808ff7a4e54e53acce037ff51c093d3f1f57fafd18670100005af3107a4000001976a9140210e63973f9feddf155e5e73ac8f7289549b5f788ac01a41dc2f5b4e17ec90d88808ff7a4e54e53acce037ff51c093d3f1f57fafd18670100016bcc41e8793c001976a9149e327995acc97229c07ce5e75789dab5eb3b689188ac01a41dc2f5b4e17ec90d88808ff7a4e54e53acce037ff51c093d3f1f57fafd18670100000000000086c4000003000000'
signed_blob = '010000000001f8ddeb9a69819ed38bec0d121a241bbf2465f61263068881a28cc2b71c4b5525010000006b483045022100c055b7b07847ee98bce64b22058356efca5b81f8a69f8c2b285669081c58361c02202d14691a6909888fc09e6fb2ab37949de87e0c7d1e72db10d6a2bfbec35fe61b0121031ec67b31750c9ca58b859200267625681d4c9849f8fb163207c4186a273e0b0afeffffff0301a41dc2f5b4e17ec90d88808ff7a4e54e53acce037ff51c093d3f1f57fafd18670100005af3107a4000001976a9140210e63973f9feddf155e5e73ac8f7289549b5f788ac01a41dc2f5b4e17ec90d88808ff7a4e54e53acce037ff51c093d3f1f57fafd18670100016bcc41e8793c001976a9149e327995acc97229c07ce5e75789dab5eb3b689188ac01a41dc2f5b4e17ec90d88808ff7a4e54e53acce037ff51c093d3f1f57fafd18670100000000000086c4000003000000'
signed_blob_signatures = ['3045022100c055b7b07847ee98bce64b22058356efca5b81f8a69f8c2b285669081c58361c02202d14691a6909888fc09e6fb2ab37949de87e0c7d1e72db10d6a2bfbec35fe61b01',]

v2_blob = "0200000000026d88e03db6f5537a1e8ab5e6f5629b9bd3d8cd202ebdd957b2082190b7aecf9e000000006a473044022008430c1563591de0313db6fcbb9bbc1314bc4782ae18cbc4b69fec65a5843a160220079efb70719c75e307f0ac2f7cce8ebd3bb3d4a79eccb7b1fe58df1a0e81f15b0121025980f0aa6b634c1a2c8ae2b01aa257669f436c740ca392a61120e69fc478774bfeffffff6d88e03db6f5537a1e8ab5e6f5629b9bd3d8cd202ebdd957b2082190b7aecf9e010000006a47304402203b7407baee09f20013856e682656fd3b6d7444eddaee40130eaa1d8dddf2dcce02202264c5de2f1422a89d22b3ade2dae0162ea0bc0489384bc94285aeca2c801dc90121021fe5af011813507148fd6b55e1aee4b5e316dada54c4cb448a0839e2a6d55428feffffff0401613d2c1a8ff549ce716a749f5e8e2b123ae1b4b7661bd3a2d731609dada0ff3b0100038d7e8ceefc00001976a914a017fc5aefbcf6cd57044b90c3d85cfbec95c72888ac01613d2c1a8ff549ce716a749f5e8e2b123ae1b4b7661bd3a2d731609dada0ff3b010000000017d78400001976a9140217928daaa582b55e07363cd88a998ab167812088ac0190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a524458001976a91450fc2d2d68e3224e8334ac469f0a2cf6928dd3ca88ac0190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d9724659010000000000002b98000000000000"
signed_segwit_blob = "0200000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff020190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d9724659010000000000060ab80001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000000000000000266a24aa21a9ed818007e5b371ffd2ddaf01a00a017ac309b1f0dd184fac749babd10505496e8e000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000"

class TestBCDataStream(SequentialTestCase):

    def test_compact_size(self):
        s = transaction.BCDataStream()
        values = [0, 1, 252, 253, 2**16-1, 2**16, 2**32-1, 2**32, 2**64-1]
        for v in values:
            s.write_compact_size(v)

        with self.assertRaises(transaction.SerializationError):
            s.write_compact_size(-1)

        self.assertEqual(bh2u(s.input),
                          '0001fcfdfd00fdfffffe00000100feffffffffff0000000001000000ffffffffffffffffff')
        for v in values:
            self.assertEqual(s.read_compact_size(), v)

        with self.assertRaises(transaction.SerializationError):
            s.read_compact_size()

    def test_string(self):
        s = transaction.BCDataStream()
        with self.assertRaises(transaction.SerializationError):
            s.read_string()

        msgs = ['Hello', ' ', 'World', '', '!']
        for msg in msgs:
            s.write_string(msg)
        for msg in msgs:
            self.assertEqual(s.read_string(), msg)

        with self.assertRaises(transaction.SerializationError):
            s.read_string()

    def test_bytes(self):
        s = transaction.BCDataStream()
        s.write(b'foobar')
        self.assertEqual(s.read_bytes(3), b'foo')
        self.assertEqual(s.read_bytes(2), b'ba')
        self.assertEqual(s.read_bytes(4), b'r')
        self.assertEqual(s.read_bytes(1), b'')

class TestTransaction(SequentialTestCase):
    @needs_test_with_all_ecc_implementations
    def test_tx_unsigned(self):
        self.maxDiff = None
        expected = {
            'inputs': [{
                'type': 'p2pkh',
                'address': 'GMZM3hwnGzgbk93mBR7bEL7B7eYg35gpHk',
                'issuance': None,
                'num_sig': 1,
                'prevout_hash': '25554b1cb7c28ca28188066312f66524bf1b241a120dec8bd39e81699aebddf8',
                'prevout_n': 1,
                'pubkeys': ['031ec67b31750c9ca58b859200267625681d4c9849f8fb163207c4186a273e0b0a'],
                'scriptSig': '01ff4c53ff0488b21e000000000000000000350138c626aac760ea9eedb47287f12c4d783910821c5602d5f8ed933a8f0d95025fb1f45ecb87f2089dc8b0257fc23cc5fd13ae9d4e14c08b0398002d68eae14c00000000',
                'sequence': 4294967294,
                'signatures': [None],
                'x_pubkeys': ['ff0488b21e000000000000000000350138c626aac760ea9eedb47287f12c4d783910821c5602d5f8ed933a8f0d95025fb1f45ecb87f2089dc8b0257fc23cc5fd13ae9d4e14c08b0398002d68eae14c00000000']}],
            'lockTime': 3,
            'outputs': [{
                'address': 'GJ2r1hJhT5h6WYTVD28BCUH7zVR9QcewCt',
                'asset': '6718fdfa571f3f3d091cf57f03ceac534ee5a4f78f80880dc97ee1b4f5c21da4',
                'asset_version': 1,
                'nonce': None,
                'nonce_version': 0,
                'prevout_n': 0,
                'scriptPubKey': '76a9140210e63973f9feddf155e5e73ac8f7289549b5f788ac',
                'range_proof': None,
                'surjection_proof': None,
                'type': TYPE_ADDRESS,
                'value': 100000000000000,
                'value_version': 1},
                {
                'address': 'GYGPeVm3KGjbiQY6kqE4ABVuXFrMLtrxhT',
                'asset': '6718fdfa571f3f3d091cf57f03ceac534ee5a4f78f80880dc97ee1b4f5c21da4',
                'asset_version': 1,
                'nonce': None,
                'nonce_version': 0,
                'prevout_n': 1,
                'scriptPubKey': '76a9149e327995acc97229c07ce5e75789dab5eb3b689188ac',
                'range_proof': None,
                'surjection_proof': None,
                'type': TYPE_ADDRESS,
                'value': 399999999965500,
                'value_version': 1},
                {
                'address': '',
                'asset': '6718fdfa571f3f3d091cf57f03ceac534ee5a4f78f80880dc97ee1b4f5c21da4',
                'asset_version': 1,
                'nonce': None,
                'nonce_version': 0,
                'prevout_n': 2,
                'scriptPubKey': '',
                'range_proof': None,
                'surjection_proof': None,
                'type': TYPE_SCRIPT,
                'value': 34500,
                'value_version': 1}],
            'partial': True,
            'segwit_ser': False,
            'version': 1,
        }
        tx = transaction.Transaction(unsigned_blob)
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)

        self.assertEqual(tx.as_dict(), {'hex': unsigned_blob, 'complete': False, 'final': True})
        self.assertEqual(tx.get_outputs(), [('GJ2r1hJhT5h6WYTVD28BCUH7zVR9QcewCt', 100000000000000, '6718fdfa571f3f3d091cf57f03ceac534ee5a4f78f80880dc97ee1b4f5c21da4'), ('GYGPeVm3KGjbiQY6kqE4ABVuXFrMLtrxhT', 399999999965500, '6718fdfa571f3f3d091cf57f03ceac534ee5a4f78f80880dc97ee1b4f5c21da4'), ('SCRIPT ', 34500, '6718fdfa571f3f3d091cf57f03ceac534ee5a4f78f80880dc97ee1b4f5c21da4')])
        self.assertEqual(tx.get_output_addresses(), ['GJ2r1hJhT5h6WYTVD28BCUH7zVR9QcewCt', 'GYGPeVm3KGjbiQY6kqE4ABVuXFrMLtrxhT', 'SCRIPT '])

        self.assertTrue(tx.has_address('GJ2r1hJhT5h6WYTVD28BCUH7zVR9QcewCt'))
        self.assertTrue(tx.has_address('GYGPeVm3KGjbiQY6kqE4ABVuXFrMLtrxhT'))
        self.assertFalse(tx.has_address('1FRUENS6LR8JdwEoptZwjRA1c64WDgcsab'))
        self.assertEqual(tx.serialize(), unsigned_blob)

        tx.update_signatures(signed_blob_signatures)
        self.assertEqual(tx.raw, signed_blob)

        tx.update(unsigned_blob)
        tx.raw = None
        blob = str(tx)
        self.assertEqual(transaction.deserialize(blob), expected)

    @needs_test_with_all_ecc_implementations
    def test_tx_signed(self):
        self.maxDiff=None
        expected = {
            'inputs': [{
                'type': 'unknown',
                'address': None,
                'issuance': None,
                'num_sig': 0,
                'prevout_hash': '25554b1cb7c28ca28188066312f66524bf1b241a120dec8bd39e81699aebddf8',
                'prevout_n': 1,
                'scriptSig': '483045022100c055b7b07847ee98bce64b22058356efca5b81f8a69f8c2b285669081c58361c02202d14691a6909888fc09e6fb2ab37949de87e0c7d1e72db10d6a2bfbec35fe61b0121031ec67b31750c9ca58b859200267625681d4c9849f8fb163207c4186a273e0b0a',
                'sequence': 4294967294}],
            'lockTime': 3,
            'outputs': [
                {
                'address': 'GJ2r1hJhT5h6WYTVD28BCUH7zVR9QcewCt',
                'asset': '6718fdfa571f3f3d091cf57f03ceac534ee5a4f78f80880dc97ee1b4f5c21da4',
                'asset_version': 1,
                'nonce': None,
                'nonce_version': 0,
                'prevout_n': 0,
                'scriptPubKey': '76a9140210e63973f9feddf155e5e73ac8f7289549b5f788ac',
                'range_proof': None,
                'surjection_proof': None,
                'type': TYPE_ADDRESS,
                'value': 100000000000000,
                'value_version': 1},
                {
                'address': 'GYGPeVm3KGjbiQY6kqE4ABVuXFrMLtrxhT',
                'asset': '6718fdfa571f3f3d091cf57f03ceac534ee5a4f78f80880dc97ee1b4f5c21da4',
                'asset_version': 1,
                'nonce': None,
                'nonce_version': 0,
                'prevout_n': 1,
                'scriptPubKey': '76a9149e327995acc97229c07ce5e75789dab5eb3b689188ac',
                'range_proof': None,
                'surjection_proof': None,
                'type': TYPE_ADDRESS,
                'value': 399999999965500,
                'value_version': 1},
                {
                'address': '',
                'asset': '6718fdfa571f3f3d091cf57f03ceac534ee5a4f78f80880dc97ee1b4f5c21da4',
                'asset_version': 1,
                'nonce': None,
                'nonce_version': 0,
                'prevout_n': 2,
                'scriptPubKey': '',
                'range_proof': None,
                'surjection_proof': None,
                'type': TYPE_SCRIPT,
                'value': 34500,
                'value_version': 1},
                ],
            'partial': False,
            'segwit_ser': False,
            'version': 1,
        }
        tx = transaction.Transaction(signed_blob)
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)
        self.assertEqual(tx.as_dict(), {'hex': signed_blob, 'complete': True, 'final': True})

        self.assertEqual(tx.serialize(), signed_blob)

        tx.update_signatures(signed_blob_signatures)

        self.assertEqual(tx.estimated_total_size(), 341)
        self.assertEqual(tx.estimated_base_size(), 341)
        self.assertEqual(tx.estimated_witness_size(), 0)
        self.assertEqual(tx.estimated_weight(), 1364)
        self.assertEqual(tx.estimated_size(), 341)

    def test_estimated_output_size(self):
        estimated_output_size = transaction.Transaction.estimated_output_size
        self.assertEqual(estimated_output_size('GMXXqwFmj4QZpffUes4JMhTYnxuVf8avcW'), 34)
        self.assertEqual(estimated_output_size('g6fKzJ2gixBd6kk6q3YceUna2DQFdbGTzZ'), 32)
        self.assertEqual(estimated_output_size('bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af'), 31)
        self.assertEqual(estimated_output_size('bc1qnvks7gfdu72de8qv6q6rhkkzu70fqz4wpjzuxjf6aydsx7wxfwcqnlxuv3'), 43)

    # TODO other tests for segwit tx
    def test_tx_signed_segwit(self):
        tx = transaction.Transaction(signed_segwit_blob)

        self.assertEqual(tx.estimated_total_size(), 223)
        self.assertEqual(tx.estimated_base_size(), 182)
        self.assertEqual(tx.estimated_witness_size(), 41)
        self.assertEqual(tx.estimated_weight(), 769)
        self.assertEqual(tx.estimated_size(), 193)

    def test_errors(self):
        with self.assertRaises(TypeError):
            transaction.Transaction.pay_script(output_type=None, addr='')

        with self.assertRaises(BaseException):
            xpubkey_to_address('')

    def test_parse_xpub(self):
        res = xpubkey_to_address('fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200')
        self.assertEqual(res, ('04ee98d63800824486a1cf5b4376f2f574d86e0a3009a6448105703453f3368e8e1d8d090aaecdd626a45cc49876709a3bbb6dc96a4311b3cac03e225df5f63dfc', 'GSY4UAy1cZwuAbZpS3vDWAiXwVJkMmTka6'))

    def test_version_field(self):
        tx = transaction.Transaction(v2_blob)
        self.assertEqual(tx.txid(), "7201a219a30af1303e4c17ab15a02e2d9c6fbfcd162403d5d171f293fa7901ce")

    def test_get_address_from_output_script(self):
        # the inverse of this test is in test_bitcoin: test_address_to_script
        addr_from_script = lambda script: transaction.get_address_from_output_script(bfh(script))
        ADDR = transaction.TYPE_ADDRESS

        # bech32 native segwit
        # test vectors from BIP-0173
        self.assertEqual((ADDR, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), addr_from_script('0014751e76e8199196d454941c45d1b3a323f1433bd6'))
        self.assertEqual((ADDR, 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx'), addr_from_script('5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'))
        self.assertEqual((ADDR, 'bc1sw50qa3jx3s'), addr_from_script('6002751e'))
        self.assertEqual((ADDR, 'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj'), addr_from_script('5210751e76e8199196d454941c45d1b3a323'))

        # base58 p2pkh
        self.assertEqual((ADDR, 'GMXXqwFmj4QZpffUes4JMhTYnxuVf8avcW'), addr_from_script('76a91428662c67561b95c79d2257d2a93d9d151c977e9188ac'))
        self.assertEqual((ADDR, 'GU5m6821WucHRHAxCeb7beBV9VHM2T4gFA'), addr_from_script('76a914704f4b81cadb7bf7e68c08cd3657220f680f863c88ac'))
        self.assertEqual((ADDR, 'GRk3uasenYYEjDT9QM5zi67z1cSwdunn7V'), addr_from_script('76a91456a4c36cd1fdb71a493fec9941b69b4a7cec90ea88ac'))

        # base58 p2sh
        self.assertEqual((ADDR, 'g6fKzJ2gixBd6kk6q3YceUna2DQFdbGTzZ'), addr_from_script('a9142a84cf00d47f699ee7bbc1dea5ec1bdecb4ac15487'))
        self.assertEqual((ADDR, 'gR5EaHUE5iHiqVK5Geujgeh1DdYay7aHKK'), addr_from_script('a914f47c8954e421031ad04ecd8e7752c9479206b9d387'))

#####

    def _run_naive_tests_on_tx(self, raw_tx, txid):
        tx = transaction.Transaction(raw_tx)
        self.assertEqual(txid, tx.txid())
        self.assertEqual(raw_tx, tx.serialize())
        self.assertTrue(tx.estimated_size() >= 0)

    def test_txid_ocean_1(self):
        raw_tx = '020000000003709afab77f27e44f86ba8fbe98eae07bf5a2c789aba842c1f5074571f3ca01e8000000006a473044022043909dcd53d1f29cbe85379d613aaed4365b8c2caefac19710835befa246ac9b022071f0b9535f40f2302ec3b078658779a6bb90d1bf1335c57c2665e1b614cdca6f012102877b934f94f2a3526f6f8d3463200ed18d0db3805ddfa9b95c49b8f3b4c5f9f5feffffff9929d283448860b9c8f878f72b9498740ce5eac04c6f889c928e919ddad9e334000000006a47304402207f7a3e18b7c1cd23faf84113f9e3529efbd905bb769bdae89bbb0ba48bebdde702204eefc801b4a66d0b53b8a1593f5b9b22263b6990938b35c11f222dd8065487c2012103cecc35686372cced9792776ab3894686252b6db17892d7821ac6dc889e578ed1feffffff9929d283448860b9c8f878f72b9498740ce5eac04c6f889c928e919ddad9e334010000006a47304402203bd5fbc2c4c24e3c8dacb2cb88b4d250453a437c91ff57533b8132b0993c26f202205440a629830ad74b6723ee09bb595ab52a52b4bab1f9a2280ce01833b2e4b91c01210218868f2c88bbc2b83897e16f49e7175c2acb77f8afe48f3a01b65d975f3a7cc1feffffff0401ed8c7bbf7a3d0bca6f342917b5ee3230e449d679371e1253c9098f7a49edad2a010000000017d78400001976a91459a23f87599b762aac26ff3bdcb35a4a6fb2431588ac0190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a51e198001976a914e99690c5b0e28056f91d50c0edf77cea3fd411a088ac01ed8c7bbf7a3d0bca6f342917b5ee3230e449d679371e1253c9098f7a49edad2a010000000029b92700001976a9140d90d12a0d6da5f948fc8cfc2e8224af5c8fa4d588ac0190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d9724659010000000000003728000002000000'
        txid = 'c4e6658adf0bb20ec82cc295723ff5a5b6531460b04048a6b023f496902a44a3'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_coinbase_segwit_ocean_2(self):
        raw_tx = '0200000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff020190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d9724659010000000000060ab80001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000000000000000266a24aa21a9ed818007e5b371ffd2ddaf01a00a017ac309b1f0dd184fac749babd10505496e8e000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000'
        txid = '55620ef3fddaa94eff3ea160f54e167b11a80d662d4ee26bf53c3fa28b647589'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_issuance_ocean_3(self):
        raw_tx = '020000000001ca983f7957320e7721424a10335ffdd7cb13b564eb5dca3b296b11e1d0e8ae0a1e00008000feffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100038d7ea4c6800000030190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a526ff0001976a914b6abccfdb3e6c6a7f2e60e691ecbf480d3349c3e88ac01613d2c1a8ff549ce716a749f5e8e2b123ae1b4b7661bd3a2d731609dada0ff3b0100038d7ea4c68000001976a914c2a33ae4acdef0a30fa15efbfbbc77989d3dd97988ac0190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d9724659010000000000001810000000000000'
        txid = '9ecfaeb7902108b257d9bd2e20cdd8d39b9b62f5e6b58a1e7a53f5b63de0886d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_initial_issuance_ocean_4(self):
        raw_tx = '0100000000013db482a0a84809ef146d2dfd133a6d7028116e0c3d502c0f9a5472b157b8eecd0000008000ffffffff000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0100002d79883d2000010000000000000000640190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a5288000001510190f6212d141349050aca026eeb6e53a037bfaf5e0383deae7b9a5139d972465901000000746a52880000015100000000'
        txid = '0aaee8d0e1116b293bca5deb64b513cbd7fd5f33104a4221770e3257793f98ca'
        self._run_naive_tests_on_tx(raw_tx, txid)

class TestTransactionTestnet(TestCaseForTestnet):

    def _run_naive_tests_on_tx(self, raw_tx, txid):
        tx = transaction.Transaction(raw_tx)
        self.assertEqual(txid, tx.txid())
        self.assertEqual(raw_tx, tx.serialize())
        self.assertTrue(tx.estimated_size() >= 0)

# partial txns using our partial format --->
    # NOTE: our partial format contains xpubs, and xpubs have version bytes,
    # and version bytes encode the network as well; so these are network-sensitive!
    '''
    def test_txid_partial_segwit_p2wpkh(self):
        raw_tx = '45505446ff000100000000010115a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff02f6fd1200000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600140f9de573bc679d040e763d13f0250bd03e625f6ffeffffffff9095ab000000000000000201ff53ff045f1cf6014af5fa07800000002fa3f450ba41799b9b62642979505817783a9b6c656dc11cd0bb4fa362096808026adc616c25a4d0a877d1741eb1db9cef65c15118bd7d5f31bf65f319edda81840100c8000f391400'
        txid = '63ff7e99d85d8e33f683e6ec84574bdf8f5111078a5fe900893e019f9a7f95c3'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_partial_segwit_p2wpkh_p2sh_simple(self):
        raw_tx = '45505446ff0001000000000101d0d23a6fbddb21cc664cb81cca96715baa4d6dbe5b7b9bcc6632f1005a7b0b840100000017160014a78a91261e71a681b6312cd184b14503a21f856afdffffff0134410f000000000017a914d6514ca17ecc31952c990daf96e307fbc58529cd87feffffffff40420f000000000000000201ff53ff044a5262033601222e800000001618aa51e49a961f63fd111f64cd4a7e792c1d7168be7a07703de505ebed2cf70286ebbe755767adaa5835f4d78dec1ee30849d69eacfe80b7ee6b1585279536c30000020011391400'
        txid = '2739f2e7fde9b8ec73fce4aee53722cc7683312d1321ded073284c51fadf44df'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_partial_segwit_p2wpkh_p2sh_mixed_outputs(self):
        raw_tx = '45505446ff00010000000001011dcac788f24b84d771b60c44e1f9b6b83429e50f06e1472d47241922164013b00100000017160014801d28ca6e2bde551112031b6cb75de34f10851ffdffffff0440420f00000000001600140f9de573bc679d040e763d13f0250bd03e625f6fc0c62d000000000017a9142899f6484e477233ce60072fc185ef4c1f2c654487809698000000000017a914d40f85ba3c8fa0f3615bcfa5d6603e36dfc613ef87712d19040000000017a914e38c0cffde769cb65e72cda1c234052ae8d2254187feffffffff6ad1ee040000000000000201ff53ff044a5262033601222e800000001618aa51e49a961f63fd111f64cd4a7e792c1d7168be7a07703de505ebed2cf70286ebbe755767adaa5835f4d78dec1ee30849d69eacfe80b7ee6b1585279536c301000c000f391400'
        txid = 'ba5c88e07a4025a39ad3b85247cbd4f556a70d6312b18e04513c7cec9d45d6ac'
        self._run_naive_tests_on_tx(raw_tx, txid)
    '''
# end partial txns <---


class NetworkMock(object):

    def __init__(self, unspent):
        self.unspent = unspent

    def synchronous_send(self, arg):
        return self.unspent
