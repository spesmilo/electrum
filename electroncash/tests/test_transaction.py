import unittest
from pprint import pprint

from .. import transaction
from ..address import Address, ScriptOutput, PublicKey
from ..bitcoin import TYPE_ADDRESS, TYPE_PUBKEY, TYPE_SCRIPT

from ..keystore import xpubkey_to_address

from ..util import bh2u

unsigned_blob = '010000000149f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed010000005701ff4c53ff0488b21e0000000000000000004f130d773e678a58366711837ec2e33ea601858262f8eaef246a7ebd19909c9a03c3b30e38ca7d797fee1223df1c9827b2a9f3379768f520910260220e0560014600002300feffffffd8e43201000000000118e43201000000001976a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac5fbd0700'
signed_blob = '010000000149f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed010000006a473044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f46885412103b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166feffffff0118e43201000000001976a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac5fbd0700'
v2_blob = "0200000001191601a44a81e061502b7bfbc6eaa1cef6d1e6af5308ef96c9342f71dbf4b9b5000000006b483045022100a6d44d0a651790a477e75334adfb8aae94d6612d01187b2c02526e340a7fd6c8022028bdf7a64a54906b13b145cd5dab21a26bd4b85d6044e9b97bceab5be44c2a9201210253e8e0254b0c95776786e40984c1aa32a7d03efa6bdacdea5f421b774917d346feffffff026b20fa04000000001976a914024db2e87dd7cfd0e5f266c5f212e21a31d805a588aca0860100000000001976a91421919b94ae5cefcdf0271191459157cdb41c4cbf88aca6240700"
nonmin_blob = '010000000142b88360bd83813139af3a251922b7f3d2ac88e45a2a703c28db8ee8580dc3a300000000654c41151dc44bece88c5933d737176499209a0b1688d5eb51eb6f1fd9fcf2fb32d138c94b96a4311673b75a31c054210b2058735ce6c12e529ddea4a6b91e4a3786d94121034a29987f30ad5d23d79ed5215e034c51f6825bdb2aa595c2bdeb37902960b3d1feffffff012e030000000000001976a914480d1be8ab76f8cdd85ce4077f51d35b0baaa25a88ac4b521400'

class TestBCDataStream(unittest.TestCase):

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

class TestTransaction(unittest.TestCase):

    def test_tx_unsigned(self):
        expected = {
            'inputs': [{'address': Address.from_string('13Vp8Y3hD5Cb6sERfpxePz5vGJizXbWciN'),
                        'num_sig': 1,
                        'prevout_hash': 'ed6a4d07e546b677abf6ba1257c2546128c694f23f4b9ebbd822fdfe435ef349',
                        'prevout_n': 1,
                        'pubkeys': ['03b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166'],
                        'sequence': 4294967294,
                        'signatures': [None],
                        'type': 'p2pkh',
                        'value': 20112600,
                        'x_pubkeys': ['ff0488b21e0000000000000000004f130d773e678a58366711837ec2e33ea601858262f8eaef246a7ebd19909c9a03c3b30e38ca7d797fee1223df1c9827b2a9f3379768f520910260220e0560014600002300']}],
            'lockTime': 507231,
            'outputs': [{'address': Address.from_string('1MYXdf4moacvaEKZ57ozerpJ3t9xSeN6LK'),
                         'prevout_n': 0,
                         'scriptPubKey': '76a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac',
                         'type': 0,
                         'value': 20112408}],
            'version': 1}
        tx = transaction.Transaction(unsigned_blob)
        calc = tx.deserialize()
        self.assertEqual(calc, expected)
        self.assertEqual(tx.deserialize(), None)

        self.assertEqual(tx.as_dict(), {'hex': unsigned_blob, 'complete': False, 'final': True})
        self.assertEqual(tx.get_outputs(), [(Address.from_string('1MYXdf4moacvaEKZ57ozerpJ3t9xSeN6LK'), 20112408)])
        self.assertEqual(tx.get_output_addresses(), [Address.from_string('1MYXdf4moacvaEKZ57ozerpJ3t9xSeN6LK')])

        self.assertTrue(tx.has_address(Address.from_string('1MYXdf4moacvaEKZ57ozerpJ3t9xSeN6LK')))
        self.assertTrue(tx.has_address(Address.from_string('13Vp8Y3hD5Cb6sERfpxePz5vGJizXbWciN')))
        self.assertFalse(tx.has_address(Address.from_string('1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH')))

        self.assertEqual(tx.serialize(), unsigned_blob)

        tx.update_signatures(['3044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f46885'])
        self.assertEqual(tx.raw, signed_blob)

        tx.update(unsigned_blob)
        tx.raw = None
        blob = str(tx)
        self.assertEqual(transaction.deserialize(blob), expected)

    def test_tx_signed(self):
        expected = {
            'inputs': [{'address': Address.from_string('13Vp8Y3hD5Cb6sERfpxePz5vGJizXbWciN'),
                        'num_sig': 1,
                        'prevout_hash': 'ed6a4d07e546b677abf6ba1257c2546128c694f23f4b9ebbd822fdfe435ef349',
                        'prevout_n': 1,
                        'pubkeys': ['03b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166'],
                        'scriptSig': '473044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f46885412103b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166',
                        'sequence': 4294967294,
                        'signatures': ['3044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f4688541'],
                        'type': 'p2pkh',
                        'x_pubkeys': ['03b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166']}],
            'lockTime': 507231,
            'outputs': [{'address': Address.from_string('1MYXdf4moacvaEKZ57ozerpJ3t9xSeN6LK'),
                         'prevout_n': 0,
                         'scriptPubKey': '76a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac',
                         'type': 0,
                         'value': 20112408}],
            'version': 1
        }
        tx = transaction.Transaction(signed_blob)
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)
        self.assertEqual(tx.as_dict(), {'hex': signed_blob, 'complete': True, 'final': True})

        self.assertEqual(tx.serialize(), signed_blob)

        tx.update_signatures([expected['inputs'][0]['signatures'][0][:-2]])

        self.assertEqual(tx.estimated_size(), 191)

    def test_tx_nonminimal_scriptSig(self):
        # The nonminimal push is the '4c41...' (PUSHDATA1 length=0x41 [...]) at
        # the start of the scriptSig. Minimal is '41...' (PUSH0x41 [...]).
        expected = {
            'inputs': [{'address': Address.from_pubkey('034a29987f30ad5d23d79ed5215e034c51f6825bdb2aa595c2bdeb37902960b3d1'),
                        'num_sig': 1,
                        'prevout_hash': 'a3c30d58e88edb283c702a5ae488acd2f3b72219253aaf39318183bd6083b842',
                        'prevout_n': 0,
                        'pubkeys': ['034a29987f30ad5d23d79ed5215e034c51f6825bdb2aa595c2bdeb37902960b3d1'],
                        'scriptSig': '4c41151dc44bece88c5933d737176499209a0b1688d5eb51eb6f1fd9fcf2fb32d138c94b96a4311673b75a31c054210b2058735ce6c12e529ddea4a6b91e4a3786d94121034a29987f30ad5d23d79ed5215e034c51f6825bdb2aa595c2bdeb37902960b3d1',
                        'sequence': 4294967294,
                        'signatures': ['151dc44bece88c5933d737176499209a0b1688d5eb51eb6f1fd9fcf2fb32d138c94b96a4311673b75a31c054210b2058735ce6c12e529ddea4a6b91e4a3786d941'],
                        'type': 'p2pkh',
                        'x_pubkeys': ['034a29987f30ad5d23d79ed5215e034c51f6825bdb2aa595c2bdeb37902960b3d1']}],
            'lockTime': 1331787,
            'outputs': [{'address': Address.from_pubkey('034a29987f30ad5d23d79ed5215e034c51f6825bdb2aa595c2bdeb37902960b3d1'),
                         'prevout_n': 0,
                         'scriptPubKey': '76a914480d1be8ab76f8cdd85ce4077f51d35b0baaa25a88ac',
                         'type': 0,
                         'value': 814}],
            'version': 1
        }
        tx = transaction.Transaction(nonmin_blob)
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)
        self.assertEqual(tx.as_dict(), {'hex': nonmin_blob, 'complete': True, 'final': True})

        self.assertEqual(tx.serialize(), nonmin_blob)

        # if original push is lost, will wrongly be e64808c1eb86e8cab68fcbd8b7f3b01f8cc8f39bd05722f1cf2d7cd9b35fb4e3
        self.assertEqual(tx.txid(), '66020177ae3273d874728667b6a24e0a1c0200079119f3d0c294da40f0e85d34')

        # cause it to lose the original push, and reserialize with minimal
        del tx.inputs()[0]['scriptSig']
        self.assertEqual(tx.txid(), 'e64808c1eb86e8cab68fcbd8b7f3b01f8cc8f39bd05722f1cf2d7cd9b35fb4e3')

    def test_errors(self):
        with self.assertRaises(TypeError):
            transaction.Transaction.pay_script(output_type=None, addr='')

        with self.assertRaises(BaseException):
            xpubkey_to_address('')

    def test_parse_xpub(self):
        res = xpubkey_to_address('fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200')
        self.assertEqual(res, ('04ee98d63800824486a1cf5b4376f2f574d86e0a3009a6448105703453f3368e8e1d8d090aaecdd626a45cc49876709a3bbb6dc96a4311b3cac03e225df5f63dfc', Address.from_string('19h943e4diLc68GXW7G75QNe2KWuMu7BaJ')))

    def test_version_field(self):
        tx = transaction.Transaction(v2_blob)
        self.assertEqual(tx.txid(), "b97f9180173ab141b61b9f944d841e60feec691d6daab4d4d932b24dd36606fe")

    def test_txid_coinbase_to_p2pk(self):
        tx = transaction.Transaction('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4103400d0302ef02062f503253482f522cfabe6d6dd90d39663d10f8fd25ec88338295d4c6ce1c90d4aeb368d8bdbadcc1da3b635801000000000000000474073e03ffffffff013c25cf2d01000000434104b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7bac00000000')
        self.assertEqual('dbaf14e1c476e76ea05a8b71921a46d6b06f0a950f17c5f9f1a03b8fae467f10', tx.txid())

    def test_txid_coinbase_to_p2pkh(self):
        tx = transaction.Transaction('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff25033ca0030400001256124d696e656420627920425443204775696c640800000d41000007daffffffff01c00d1298000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000')
        self.assertEqual('4328f9311c6defd9ae1bd7f4516b62acf64b361eb39dfcf09d9925c5fd5c61e8', tx.txid())

    def test_txid_p2pk_to_p2pkh(self):
        tx = transaction.Transaction('010000000118231a31d2df84f884ced6af11dc24306319577d4d7c340124a7e2dd9c314077000000004847304402200b6c45891aed48937241907bc3e3868ee4c792819821fcde33311e5a3da4789a02205021b59692b652a01f5f009bd481acac2f647a7d9c076d71d85869763337882e01fdffffff016c95052a010000001976a9149c4891e7791da9e622532c97f43863768264faaf88ac00000000')
        self.assertEqual('90ba90a5b115106d26663fce6c6215b8699c5d4b2672dd30756115f3337dddf9', tx.txid())

    def test_txid_p2pk_to_p2sh(self):
        tx = transaction.Transaction('0100000001e4643183d6497823576d17ac2439fb97eba24be8137f312e10fcc16483bb2d070000000048473044022032bbf0394dfe3b004075e3cbb3ea7071b9184547e27f8f73f967c4b3f6a21fa4022073edd5ae8b7b638f25872a7a308bb53a848baa9b9cc70af45fcf3c683d36a55301fdffffff011821814a0000000017a9143c640bc28a346749c09615b50211cb051faff00f8700000000')
        self.assertEqual('172bdf5a690b874385b98d7ab6f6af807356f03a26033c6a65ab79b4ac2085b5', tx.txid())

    def test_txid_p2pkh_to_p2pkh(self):
        tx = transaction.Transaction('0100000001f9dd7d33f315617530dd72264b5d9c69b815626cce3f66266d1015b1a590ba90000000006a4730440220699bfee3d280a499daf4af5593e8750b54fef0557f3c9f717bfa909493a84f60022057718eec7985b7796bb8630bf6ea2e9bf2892ac21bd6ab8f741a008537139ffe012103b4289890b40590447b57f773b5843bf0400e9cead08be225fac587b3c2a8e973fdffffff01ec24052a010000001976a914ce9ff3d15ed5f3a3d94b583b12796d063879b11588ac00000000')
        self.assertEqual('24737c68f53d4b519939119ed83b2a8d44d716d7f3ca98bcecc0fbb92c2085ce', tx.txid())

    def test_txid_p2pkh_to_p2sh(self):
        tx = transaction.Transaction('010000000195232c30f6611b9f2f82ec63f5b443b132219c425e1824584411f3d16a7a54bc000000006b4830450221009f39ac457dc8ff316e5cc03161c9eff6212d8694ccb88d801dbb32e85d8ed100022074230bb05e99b85a6a50d2b71e7bf04d80be3f1d014ea038f93943abd79421d101210317be0f7e5478e087453b9b5111bdad586038720f16ac9658fd16217ffd7e5785fdffffff0200e40b540200000017a914d81df3751b9e7dca920678cc19cac8d7ec9010b08718dfd63c2c0000001976a914303c42b63569ff5b390a2016ff44651cd84c7c8988acc7010000')
        self.assertEqual('155e4740fa59f374abb4e133b87247dccc3afc233cb97c2bf2b46bba3094aedc', tx.txid())

    def test_txid_p2sh_to_p2pkh(self):
        tx = transaction.Transaction('0100000001b98d550fa331da21038952d6931ffd3607c440ab2985b75477181b577de118b10b000000fdfd0000483045022100a26ea637a6d39aa27ea7a0065e9691d477e23ad5970b5937a9b06754140cf27102201b00ed050b5c468ee66f9ef1ff41dfb3bd64451469efaab1d4b56fbf92f9df48014730440220080421482a37cc9a98a8dc3bf9d6b828092ad1a1357e3be34d9c5bbdca59bb5f02206fa88a389c4bf31fa062977606801f3ea87e86636da2625776c8c228bcd59f8a014c69522102420e820f71d17989ed73c0ff2ec1c1926cf989ad6909610614ee90cf7db3ef8721036eae8acbae031fdcaf74a824f3894bf54881b42911bd3ad056ea59a33ffb3d312103752669b75eb4dc0cca209af77a59d2c761cbb47acc4cf4b316ded35080d92e8253aeffffffff0101ac3a00000000001976a914a6b6bcc85975bf6a01a0eabb2ac97d5a418223ad88ac00000000')
        self.assertEqual('0ea982e8e601863e604ef6d9acf9317ae59d3eac9cafee6dd946abadafd35af8', tx.txid())

    def test_txid_p2sh_to_p2sh(self):
        tx = transaction.Transaction('01000000018695eef2250b3a3b6ef45fe065e601610e69dd7a56de742092d40e6276e6c9ec00000000fdfd000047304402203199bf8e49f7203e8bcbfd754aa356c6ba61643a3490f8aef3888e0aaa7c048c02201e7180bfd670f4404e513359b4020fbc85d6625e3e265e0c357e8611f11b83e401483045022100e60f897db114679f9a310a032a22e9a7c2b8080affe2036c480ff87bf6f45ada02202dbd27af38dd97d418e24d89c3bb7a97e359dd927c1094d8c9e5cac57df704fb014c69522103adc563b9f5e506f485978f4e913c10da208eac6d96d49df4beae469e81a4dd982102c52bc9643a021464a31a3bfa99cfa46afaa4b3acda31e025da204b4ee44cc07a2103a1c8edcc3310b3d7937e9e4179e7bd9cdf31c276f985f4eb356f21b874225eb153aeffffffff02b8ce05000000000017a9145c9c158430b7b79c3ad7ef9bdf981601eda2412d87b82400000000000017a9146bf3ff89019ecc5971a39cdd4f1cabd3b647ad5d8700000000')
        self.assertEqual('2caab5a11fa1ec0f5bb014b8858d00fecf2c001e15d22ad04379ad7b36fef305', tx.txid())

    def test_parse_output_p2pkh(self):
        tx = transaction.Transaction('010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000001976a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac00000000')
        self.assertEqual(tx.outputs(), [(TYPE_ADDRESS, Address.from_P2PKH_hash(b'\xaa'*20), 0)])
        self.assertEqual('7a0e3fcbdaa9ecc6ccce1ad325b6b661e774a57f2e8519c679964e2dd32e200f', tx.txid())

    def test_parse_output_p2pkh_nonmin(self):
        tx = transaction.Transaction('010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000001a76a94c14aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac00000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(bytes.fromhex('76a94c14aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac')), 0)])
        self.assertEqual('69706667959fd2e6aa3385acdcd2c478e875344422e1f4c94eb06065268540d1', tx.txid())

    def test_parse_output_p2sh(self):
        tx = transaction.Transaction('0100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000017a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8700000000')
        self.assertEqual(tx.outputs(), [(TYPE_ADDRESS, Address.from_P2SH_hash(b'\xaa'*20), 0)])
        self.assertEqual('d33750908965d24a411d94371fdc64ebb06f13bf4d19e73372347e6b4eeca49f', tx.txid())

    def test_parse_output_p2sh_nonmin(self):
        tx = transaction.Transaction('0100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000018a94c14aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8700000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(bytes.fromhex('a94c14aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa87')), 0)])
        self.assertEqual('dd4b174d7094c63c9f530703702a8d76c7b3fe5fc278ba2837dbd75bc5b0b296', tx.txid())

    def test_parse_output_p2pk(self):
        tx = transaction.Transaction('010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000002321030000000000000000000000000000000000000000000000000000000000000000ac00000000')
        self.assertEqual(tx.outputs(), [(TYPE_PUBKEY, PublicKey.from_pubkey(b'\x03' + b'\x00'*32), 0)])
        self.assertEqual('78afa0576a4ee6e7db663a58202f11bab8e860dd4a2226f856a2490187046b3d', tx.txid())

    def test_parse_output_p2pk_badpubkey(self):
        tx = transaction.Transaction('010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000002321040000000000000000000000000000000000000000000000000000000000000000ac00000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(bytes.fromhex('21040000000000000000000000000000000000000000000000000000000000000000ac')), 0)])
        self.assertEqual('8e57f026081b6589570dc5e6e339b706d2ac75e6cbd1896275dee176b8d35ba6', tx.txid())

    def test_parse_output_p2pk_nonmin(self):
        tx = transaction.Transaction('01000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000244c21030000000000000000000000000000000000000000000000000000000000000000ac00000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(bytes.fromhex('4c21030000000000000000000000000000000000000000000000000000000000000000ac')), 0)])
        self.assertEqual('730d77384d7bfc965caa338b501e7b071092474320af6ea19052859c93bfaf98', tx.txid())

    def test_parse_output_p2pk_uncomp(self):
        tx = transaction.Transaction('0100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000043410400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac00000000')
        self.assertEqual(tx.outputs(), [(TYPE_PUBKEY, PublicKey.from_pubkey(b'\x04' + b'\x00'*64), 0)])
        self.assertEqual('053626542393dd957a14bb2bcbfdcf3564a5f438e923799e1b9714c4a8e70a7c', tx.txid())

    def test_parse_output_p2pk_uncomp_badpubkey(self):
        tx = transaction.Transaction('0100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000043410300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac00000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(b'\x41\x03' + b'\x00'*64 + b'\xac'), 0)])
        self.assertEqual('a15a9f86f5a47ef7efc28ae701f5b2a353aff76a21cb22ff08b77759533fb59b', tx.txid())

    def test_parse_output_p2pk_uncomp_nonmin(self):
        tx = transaction.Transaction('01000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000444c410400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac00000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(b'\x4c\x41\x04' + b'\x00'*64 + b'\xac'), 0)])
        self.assertEqual('bd8e0827c8bacd6bac10dd28d5fc6ad52f3fef3f91200c7c1d8698531c9325e9', tx.txid())

    def test_parse_output_baremultisig(self):
        # no special support for recognizing bare multisig outputs
        tx = transaction.Transaction('0100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000025512103000000000000000000000000000000000000000000000000000000000000000051ae00000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(b'\x51\x21\x03' + b'\x00'*32 + b'\x51\xae'), 0)])
        self.assertEqual('b1f66fde0aa3d5af03be3c69f599069aad217e939f36cacc2372ea4fece7d57b', tx.txid())

    def test_parse_output_baremultisig_nonmin(self):
        # even if bare multisig support is added, note that this case should still remain unrecognized
        tx = transaction.Transaction('0100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000026514c2103000000000000000000000000000000000000000000000000000000000000000051ae00000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(b'\x51\x4c\x21\x03' + b'\x00'*32 + b'\x51\xae'), 0)])
        self.assertEqual('eb0b69c86a05499cabc42b12d4706b18eab97ed6155fc966e488a433edf05932', tx.txid())

    def test_parse_output_truncated1(self):
        # truncated in middle of PUSHDATA2's first argument
        tx = transaction.Transaction('01000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000024d0100000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(b'\x4d\x01'), 0)])
        self.assertIn("Invalid script", tx.outputs()[0][1].to_ui_string())
        self.assertEqual('72d8af8edcc603c6c64390ac5eb913b97a80efe0f5ae7c00ad5397eb5786cd33', tx.txid())

    def test_parse_output_truncated1(self):
        # truncated in middle of PUSHDATA2's second argument
        tx = transaction.Transaction('01000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000044d0200ff00000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(b'\x4d\x02\x00\xff'), 0)])
        self.assertIn("Invalid script", tx.outputs()[0][1].to_ui_string())
        self.assertEqual('976667816c4955189973cc56ac839844da4ed32a8bd22a8c6217c2c04e69e9d7', tx.txid())

    def test_parse_output_empty(self):
        # nothing wrong with empty output script
        tx = transaction.Transaction('010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000')
        self.assertEqual(tx.outputs(), [(TYPE_SCRIPT, ScriptOutput(b''), 0)])
        self.assertEqual("", tx.outputs()[0][1].to_ui_string())
        self.assertEqual('50fa7bd4e5e2d3220fd2e84effec495b9845aba379d853408779d59a4b0b4f59', tx.txid())

class NetworkMock(object):

    def __init__(self, unspent):
        self.unspent = unspent

    def synchronous_get(self, arg):
        return self.unspent
