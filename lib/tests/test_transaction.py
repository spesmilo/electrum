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
signed_segwit_blob = "01000000000101b66d722484f2db63e827ebf41d02684fed0c6550e85015a6c9d41ef216a8a6f00000000000fdffffff0280c3c90100000000160014b65ce60857f7e7892b983851c2a8e3526d09e4ab64bac30400000000160014c478ebbc0ab2097706a98e10db7cf101839931c4024730440220789c7d47f876638c58d98733c30ae9821c8fa82b470285dcdf6db5994210bf9f02204163418bbc44af701212ad42d884cc613f3d3d831d2d0cc886f767cca6e0235e012103083a6dc250816d771faa60737bfe78b23ad619f6b458e0a1f1688e3a0605e79c00000000"

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
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)

        self.assertEqual(tx.as_dict(), {'hex': unsigned_blob, 'complete': False, 'final': True})
        self.assertEqual(tx.get_outputs(), [('14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs', 1000000)])
        self.assertEqual(tx.get_output_addresses(), ['14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs'])

        self.assertTrue(tx.has_address('14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs'))
        self.assertTrue(tx.has_address('1446oU3z268EeFgfcwJv6X2VBXHfoYxfuD'))
        self.assertFalse(tx.has_address('1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))

        self.assertEqual(tx.serialize(), unsigned_blob)

        tx.update_signatures(signed_blob)
        self.assertEqual(tx.raw, signed_blob)

        tx.update(unsigned_blob)
        tx.raw = None
        blob = str(tx)
        self.assertEqual(transaction.deserialize(blob), expected)

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
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)
        self.assertEqual(tx.as_dict(), {'hex': signed_blob, 'complete': True, 'final': True})

        self.assertEqual(tx.serialize(), signed_blob)

        tx.update_signatures(signed_blob)

        self.assertEqual(tx.estimated_total_size(), 193)
        self.assertEqual(tx.estimated_base_size(), 193)
        self.assertEqual(tx.estimated_witness_size(), 0)
        self.assertEqual(tx.estimated_weight(), 772)
        self.assertEqual(tx.estimated_size(), 193)

    # TODO other tests for segwit tx
    def test_tx_signed_segwit(self):
        tx = transaction.Transaction(signed_segwit_blob)

        self.assertEqual(tx.estimated_total_size(), 222)
        self.assertEqual(tx.estimated_base_size(), 113)
        self.assertEqual(tx.estimated_witness_size(), 109)
        self.assertEqual(tx.estimated_weight(), 561)
        self.assertEqual(tx.estimated_size(), 141)

    def test_errors(self):
        with self.assertRaises(TypeError):
            transaction.Transaction.pay_script(output_type=None, addr='')

        with self.assertRaises(BaseException):
            xpubkey_to_address('')

    def test_parse_xpub(self):
        res = xpubkey_to_address('fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200')
        self.assertEqual(res, ('04ee98d63800824486a1cf5b4376f2f574d86e0a3009a6448105703453f3368e8e1d8d090aaecdd626a45cc49876709a3bbb6dc96a4311b3cac03e225df5f63dfc', '19h943e4diLc68GXW7G75QNe2KWuMu7BaJ'))

    def test_version_field(self):
        tx = transaction.Transaction(v2_blob)
        self.assertEqual(tx.txid(), "b97f9180173ab141b61b9f944d841e60feec691d6daab4d4d932b24dd36606fe")

    def test_txid_coinbase_to_p2pk(self):
        tx = transaction.Transaction('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4103400d0302ef02062f503253482f522cfabe6d6dd90d39663d10f8fd25ec88338295d4c6ce1c90d4aeb368d8bdbadcc1da3b635801000000000000000474073e03ffffffff013c25cf2d01000000434104b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7bac00000000')
        self.assertEqual('dbaf14e1c476e76ea05a8b71921a46d6b06f0a950f17c5f9f1a03b8fae467f10', tx.txid())

    def test_txid_coinbase_to_p2pkh(self):
        tx = transaction.Transaction('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff25033ca0030400001256124d696e656420627920425443204775696c640800000d41000007daffffffff01c00d1298000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000')
        self.assertEqual('4328f9311c6defd9ae1bd7f4516b62acf64b361eb39dfcf09d9925c5fd5c61e8', tx.txid())

    def test_txid_segwit_coinbase_to_p2pk(self):
        tx = transaction.Transaction('020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502cd010101ffffffff0240be402500000000232103f4e686cdfc96f375e7c338c40c9b85f4011bb843a3e62e46a1de424ef87e9385ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000')
        self.assertEqual('fb5a57c24e640a6d8d831eb6e41505f3d54363c507da3733b098d820e3803301', tx.txid())

    def test_txid_segwit_coinbase_to_p2pkh(self):
        tx = transaction.Transaction('020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502c3010101ffffffff0240be4025000000001976a9141ea896d897483e0eb33dd6423f4a07970d0a0a2788ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000')
        self.assertEqual('ed3d100577477d799107eba97e76770b3efa253c7200e9abfb43da5d2b33513e', tx.txid())

    def test_txid_p2pk_to_p2pkh(self):
        tx = transaction.Transaction('010000000118231a31d2df84f884ced6af11dc24306319577d4d7c340124a7e2dd9c314077000000004847304402200b6c45891aed48937241907bc3e3868ee4c792819821fcde33311e5a3da4789a02205021b59692b652a01f5f009bd481acac2f647a7d9c076d71d85869763337882e01fdffffff016c95052a010000001976a9149c4891e7791da9e622532c97f43863768264faaf88ac00000000')
        self.assertEqual('90ba90a5b115106d26663fce6c6215b8699c5d4b2672dd30756115f3337dddf9', tx.txid())

    def test_txid_p2pk_to_p2sh(self):
        tx = transaction.Transaction('0100000001e4643183d6497823576d17ac2439fb97eba24be8137f312e10fcc16483bb2d070000000048473044022032bbf0394dfe3b004075e3cbb3ea7071b9184547e27f8f73f967c4b3f6a21fa4022073edd5ae8b7b638f25872a7a308bb53a848baa9b9cc70af45fcf3c683d36a55301fdffffff011821814a0000000017a9143c640bc28a346749c09615b50211cb051faff00f8700000000')
        self.assertEqual('172bdf5a690b874385b98d7ab6f6af807356f03a26033c6a65ab79b4ac2085b5', tx.txid())

    def test_txid_p2pk_to_p2wpkh(self):
        tx = transaction.Transaction('01000000015e5e2bf15f5793fdfd01e0ccd380033797ed2d4dba9498426ca84904176c26610000000049483045022100c77aff69f7ab4bb148f9bccffc5a87ee893c4f7f7f96c97ba98d2887a0f632b9022046367bdb683d58fa5b2e43cfc8a9c6d57724a27e03583942d8e7b9afbfeea5ab01fdffffff017289824a00000000160014460fc70f208bffa9abf3ae4abbd2f629d9cdcf5900000000')
        self.assertEqual('ca554b1014952f900aa8cf6e7ab02137a6fdcf933ad6a218de3891a2ef0c350d', tx.txid())

    def test_txid_p2pkh_to_p2pkh(self):
        tx = transaction.Transaction('0100000001f9dd7d33f315617530dd72264b5d9c69b815626cce3f66266d1015b1a590ba90000000006a4730440220699bfee3d280a499daf4af5593e8750b54fef0557f3c9f717bfa909493a84f60022057718eec7985b7796bb8630bf6ea2e9bf2892ac21bd6ab8f741a008537139ffe012103b4289890b40590447b57f773b5843bf0400e9cead08be225fac587b3c2a8e973fdffffff01ec24052a010000001976a914ce9ff3d15ed5f3a3d94b583b12796d063879b11588ac00000000')
        self.assertEqual('24737c68f53d4b519939119ed83b2a8d44d716d7f3ca98bcecc0fbb92c2085ce', tx.txid())

    def test_txid_p2pkh_to_p2sh(self):
        tx = transaction.Transaction('010000000195232c30f6611b9f2f82ec63f5b443b132219c425e1824584411f3d16a7a54bc000000006b4830450221009f39ac457dc8ff316e5cc03161c9eff6212d8694ccb88d801dbb32e85d8ed100022074230bb05e99b85a6a50d2b71e7bf04d80be3f1d014ea038f93943abd79421d101210317be0f7e5478e087453b9b5111bdad586038720f16ac9658fd16217ffd7e5785fdffffff0200e40b540200000017a914d81df3751b9e7dca920678cc19cac8d7ec9010b08718dfd63c2c0000001976a914303c42b63569ff5b390a2016ff44651cd84c7c8988acc7010000')
        self.assertEqual('155e4740fa59f374abb4e133b87247dccc3afc233cb97c2bf2b46bba3094aedc', tx.txid())

    def test_txid_p2pkh_to_p2wpkh(self):
        tx = transaction.Transaction('0100000001ce85202cb9fbc0ecbc98caf3d716d7448d2a3bd89e113999514b3df5687c7324000000006b483045022100adab7b6cb1179079c9dfc0021f4db0346730b7c16555fcc4363059dcdd95f653022028bcb816f4fb98615fb8f4b18af3ad3708e2d72f94a6466cc2736055860422cf012102a16a25148dd692462a691796db0a4a5531bcca970a04107bf184a2c9f7fd8b12fdffffff012eb6042a010000001600147d0170de18eecbe84648979d52b666dddee0b47400000000')
        self.assertEqual('ed29e100499e2a3a64a2b0cb3a68655b9acd690d29690fa541be530462bf3d3c', tx.txid())

    def test_txid_p2sh_to_p2pkh(self):
        tx = transaction.Transaction('01000000000101f9823f87af35d158e7dc81a67011f4e511e3f6cab07ac108e524b0ff8b950b39000000002322002041f0237866eb72e4a75cd6faf5ccd738703193907d883aa7b3a8169c636706a9fdffffff020065cd1d000000001976a9148150cd6cf729e7e262699875fec1f760b0aab3cc88acc46f9a3b0000000017a91433ccd0f95a7b9d8eef68be40bb59c64d6e14d87287040047304402205ca97126a5956c2deaa956a2006d79a348775d727074a04b71d9c18eb5e5525402207b9353497af15881100a2786adab56c8930c02d46cc1a8b55496c06e22d3459b01483045022100b4fa898057927c2d920ae79bca752dda58202ea8617d3e6ed96cbd5d1c0eb2fc02200824c0e742d1b4d643cec439444f5d8779c18d4f42c2c87cce24044a3babf2df0147522102db78786b3c214826bd27010e3c663b02d67144499611ee3f2461c633eb8f1247210377082028c124098b59a5a1e0ea7fd3ebca72d59c793aecfeedd004304bac15cd52aec9010000')
        self.assertEqual('17e1d498ba82503e3bfa81ac4897a57e33f3d36b41bcf4765ba604466c478986', tx.txid())

    def test_txid_p2sh_to_p2sh(self):
        tx = transaction.Transaction('01000000000101b58520acb479ab656a3c03263af0567380aff6b67a8db98543870b695adf2b170000000017160014cfd2b9f7ed9d4d4429ed6946dbb3315f75e85f14fdffffff020065cd1d0000000017a91485f5681bec38f9f07ae9790d7f27c2bb90b5b63c87106ab32c0000000017a914ff402e164dfce874435641ae9ac41fc6fb14c4e18702483045022100b3d1c89c7c92151ed1df78815924569446782776b6a2c170ca5d74c5dd1ad9b102201d7bab1974fd2aa66546dd15c1f1e276d787453cec31b55a2bd97b050abf20140121024a1742ece86df3dbce4717c228cf51e625030cef7f5e6dde33a4fffdd17569eac7010000')
        self.assertEqual('ead0e7abfb24ddbcd6b89d704d7a6091e43804a458baa930adf6f1cb5b6b42f7', tx.txid())

    def test_txid_p2sh_to_p2wpkh(self):
        tx = transaction.Transaction('010000000001018689476c4604a65b76f4bc416bd3f3337ea59748ac81fa3b3e5082ba98d4e1170100000023220020ae40340707f9726c0f453c3d47c96e7f3b7b4b85608eb3668b69bbef9c7ab374fdffffff0218b2cc1d0000000017a914f2fdd81e606ff2ab804d7bb46bf8838a711c277b870065cd1d0000000016001496ad8959c1f0382984ecc4da61c118b4c8751e5104004730440220387b9e7d402fbcada9ba55a27a8d0563eafa9904ebd2f8f7e3d86e4b45bc0ec202205f37fa0e2bf8cbd384f804562651d7c6f69adce5db4c1a5b9103250a47f73e6b01473044022074903f4dd4fd6b32289be909eb5109924740daa55e79be6dbd728687683f9afa02205d934d981ca12cbec450611ca81dc4127f8da5e07dd63d41049380502de3f15401475221025c3810b37147105106cef970f9b91d3735819dee4882d515c1187dbd0b8f0c792103e007c492323084f1c103beff255836408af89bb9ae7f2fcf60502c28ff4b0c9152aeca010000')
        self.assertEqual('6f294c84cbd0241650931b4c1be3dfb2f175d682c7a9538b30b173e1083deed3', tx.txid())

    def test_txid_p2wpkh_to_p2pkh(self):
        tx = transaction.Transaction('0100000000010197e6bf4a70bc118e3a8d9842ed80422e335679dfc29b5ba0f9123f6a5863b8470000000000fdffffff02402bca7f130000001600146f579c953d9e7e7719f2baa20bde22eb5f24119200e87648170000001976a9140cd8fa5fd81c3acf33f93efd179b388de8dd693388ac0247304402204ff33b3ea8fb270f62409bfc257457ca5eb1fec5e4d3a7c11aa487207e131d4d022032726b998e338e5245746716e5cd0b40d32b69d1535c3d841f049d98a5d819b1012102dc3ce3220363aff579eb2c45c973e8b186a829c987c3caea77c61975666e7d1bc8010000')
        self.assertEqual('c721ed35767a3a209b688e68e3bb136a72d2b631fe81c56be8bdbb948c343dbc', tx.txid())

    def test_txid_p2wpkh_to_p2sh(self):
        tx = transaction.Transaction('010000000001013c3dbf620453be41a50f69290d69cd9a5b65683acbb0a2643a2a9e4900e129ed0000000000fdffffff02002f68590000000017a914c7c4dcd0ddf70f15c6df13b4a4d56e9f13c49b2787a0429cd000000000160014e514e3ecf89731e7853e4f3a20983484c569d3910247304402205368cc548209303db5a8f2ebc282bd0f7af0d080ce0f7637758587f94d3971fb0220098cec5752554758bc5fa4de332b980d5e0054a807541581dc5e4de3ed29647501210233717cd73d95acfdf6bd72c4fb5df27cd6bd69ce947daa3f4a442183a97877efc8010000')
        self.assertEqual('390b958bffb024e508c17ab0caf6e311e5f41170a681dce758d135af873f82f9', tx.txid())

    def test_txid_p2wpkh_to_p2wpkh(self):
        tx = transaction.Transaction('010000000001010d350cefa29138de18a2d63a93cffda63721b07a6ecfa80a902f9514104b55ca0000000000fdffffff012a4a824a00000000160014b869999d342a5d42d6dc7af1efc28456da40297a024730440220475bb55814a52ea1036919e4408218c693b8bf93637b9f54c821b5baa3b846e102207276ed7a79493142c11fb01808a4142bbdd525ae7bdccdf8ecb7b8e3c856b4d90121024cdeaca7a53a7e23a1edbe9260794eaa83063534b5f111ee3c67d8b0cb88f0eec8010000')
        self.assertEqual('51087ece75c697cc872d2e643d646b0f3e1f2666fa1820b7bff4343d50dd680e', tx.txid())


class NetworkMock(object):

    def __init__(self, unspent):
        self.unspent = unspent

    def synchronous_get(self, arg):
        return self.unspent
