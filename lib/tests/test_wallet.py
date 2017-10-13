import shutil
import tempfile
import sys
import unittest
import os
import json

from io import StringIO
from lib.storage import WalletStorage, FINAL_SEED_VERSION
import lib.wallet as wallet
import lib.keystore as keystore
import lib.bitcoin as bitcoin, lib.transaction as transaction
from sample_tx import sample_tx_testnet


class FakeSynchronizer(object):

    def __init__(self):
        self.store = []

    def add(self, address):
        self.store.append(address)


class WalletTestCase(unittest.TestCase):

    def setUp(self):
        super(WalletTestCase, self).setUp()
        self.user_dir = tempfile.mkdtemp()

        self.wallet_path = os.path.join(self.user_dir, "somewallet")

        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

    def tearDown(self):
        super(WalletTestCase, self).tearDown()
        shutil.rmtree(self.user_dir)
        # Restore the "real" stdout
        sys.stdout = self._saved_stdout


class TestWalletStorage(WalletTestCase):

    def test_read_dictionary_from_file(self):

        some_dict = {"a":"b", "c":"d"}
        contents = json.dumps(some_dict)
        with open(self.wallet_path, "w") as f:
            contents = f.write(contents)

        storage = WalletStorage(self.wallet_path, manual_upgrades=True)
        self.assertEqual("b", storage.get("a"))
        self.assertEqual("d", storage.get("c"))

    def test_write_dictionary_to_file(self):

        storage = WalletStorage(self.wallet_path)

        some_dict = {
            u"a": u"b",
            u"c": u"d",
            u"seed_version": FINAL_SEED_VERSION}

        for key, value in some_dict.items():
            storage.put(key, value)
        storage.write()

        contents = ""
        with open(self.wallet_path, "r") as f:
            contents = f.read()
        self.assertEqual(some_dict, json.loads(contents))


class TestStandardWallet(unittest.TestCase):
    def setUp(self):
        bitcoin.set_testnet()
        self.user_dir = tempfile.mkdtemp()
        self.wallet_path = os.path.join(self.user_dir, "testwallet")
        self.storage = WalletStorage(self.wallet_path)
        k = keystore.from_seed('absent feel require game library trade march seven quantum recycle warfare tomorrow', '')
        self.storage.put('seed_type', 'standard')
        self.storage.put('keystore', k.dump())
        self.wallet = wallet.Standard_Wallet(self.storage)
        for i in range(2):
            self.wallet.create_new_address(False)       # normal addresses
            self.wallet.create_new_address(True)        # change addresses
        self.wallet.storage.write()

    def tearDown(self):
        del self.wallet
        del self.storage
        shutil.rmtree(self.user_dir)
        # restore back to mainnet
        bitcoin.TESTNET = False
        bitcoin.ADDRTYPE_P2PKH = 0
        bitcoin.ADDRTYPE_P2SH = 5
        bitcoin.ADDRTYPE_P2WPKH = 6
        bitcoin.XPRV_HEADER = 0x0488ade4
        bitcoin.XPUB_HEADER = 0x0488b21e
        bitcoin.HEADERS_URL = "http://bitcoincash.com/files/blockchain_headers"
        bitcoin.GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


    def test_addresses(self):
        self.assertTrue('mx6w8bqyDQHZUJP6vAUVgXAoL6U1QnDgEJ' in self.wallet.get_addresses())
        self.assertTrue('n1xnWFMLF9xkcUxL3ZwQKbGkRNBpGKdFjt' in self.wallet.get_addresses())
        self.assertFalse('invalid address' in self.wallet.get_addresses())
        self.assertTrue(len(self.wallet.get_addresses()) >= 2)

    def test_add_transaction(self):
        addedtx = self.add_all_txs()
        self.assertEqual(len(self.wallet.transactions),len(addedtx))
        # adding tx's does not automatically update the utxo's
        self.assertEqual(len(self.wallet.get_utxos()),0)

    # this fails, related to issue 169, being worked on
    def test_sign(self):
        for sample in sample_tx_testnet:
            if 'raw_unsigned' in sample:
                tx = transaction.Transaction(sample['raw_unsigned'])
                tx.deserialize()
                for i in tx.inputs():
                    self.assertTrue(i['address'] in self.wallet.get_addresses())
                self.assertFalse(tx.is_complete())
                # wallet has no tx history, so this should fail
                with self.assertRaises(transaction.InputValueMissing):
                    self.wallet.sign_transaction(tx, None)
                self.assertFalse(tx.is_complete())
                if 'input_txs' in sample:
                    for i in sample['input_txs']:       # add the txs for the inputs to the wallet
                        itx = transaction.Transaction(i)
                        self.wallet.add_transaction(itx.txid(),itx)
                    self.wallet.sign_transaction(tx, None)
                    self.assertTrue(tx.is_complete())


    def add_all_txs(self):
        addedtx = []
        for sample in sample_tx_testnet:
            if 'raw' in sample:
                tx = transaction.Transaction(sample['raw'])
                if tx.txid() not in addedtx:
                    self.wallet.add_transaction(tx.txid(),tx)
                    addedtx.append(tx.txid())
            if 'input_txs' in sample:
                for i in sample['input_txs']:
                    tx = transaction.Transaction(i)
                    if tx.txid() not in addedtx:
                        self.wallet.add_transaction(tx.txid(), tx)
                        addedtx.append(tx.txid())
        return addedtx


class TestMultiSigWallet(unittest.TestCase):
    def setUp(self):
        bitcoin.set_testnet()
        self.user_dir = tempfile.mkdtemp()
        self.wallet_path = os.path.join(self.user_dir, "multisig2")
        self.storage = WalletStorage(self.wallet_path)
        self.storage.put('wallet_type', "2of3")
        k = [keystore.from_seed('almost cross mistake border loud enable birth worth end helmet flash cliff', '')]
        k.append(keystore.from_keys('tpubD6NzVbkrYhZ4XikksiCN1DTVgBZUQcKeN5XkbeqhDZei5z15sb34cES57n7BS7zxuN5QSwRtFidx4VMYk9VBoX76CCsek6P2mzWkTj3UtiK'))
        k.append(keystore.from_keys('tpubD6NzVbkrYhZ4XgqM6axUN9ZhvBhCawMKRsT9Lqxs6fMjj5TAB9cE7vJATk1vuGrpBVaqVPKrSPXeDYJMbLWKN9svbKEW38WAWQq5nU3nqT1'))
        for i, one_k in enumerate(k):
            self.storage.put('x%d/' % (i + 1), one_k.dump())
        self.wallet = wallet.Multisig_Wallet(self.storage)
        for i in range(2):
            self.wallet.create_new_address(False)       # normal addresses
            self.wallet.create_new_address(True)        # change addresses
        self.wallet.storage.write()

    def tearDown(self):
        del self.wallet
        del self.storage
        shutil.rmtree(self.user_dir)
        # restore back to mainnet
        bitcoin.TESTNET = False
        bitcoin.ADDRTYPE_P2PKH = 0
        bitcoin.ADDRTYPE_P2SH = 5
        bitcoin.ADDRTYPE_P2WPKH = 6
        bitcoin.XPRV_HEADER = 0x0488ade4
        bitcoin.XPUB_HEADER = 0x0488b21e
        bitcoin.HEADERS_URL = "http://bitcoincash.com/files/blockchain_headers"
        bitcoin.GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

    def test_signfromcmdline(self):
        # tx has been signed by one in 2of3 multisig - check that it can be completed by second
        raw_onesign = '0100000001f5c9f455b2321add71f307a9ee7a757770ffa679b42da21e2e1c025f09b0a80f01000000fd1f010001ff01ff483045022100ea5a8a813f70a0ed6919f49ab7b24a45858a66a433694d098f42df53fa2b152702205b2161ba4010a667e24b8a7e1bc18172b04d4e964a5a61e7803e14e68f7aa5c4414ccf524c53ff043587cf000000000000000000877214e20b564ea196f5849d59ee5df75f19c9653e51cbb1b36b5016127d6d7603717353e251530938e2f58e69e4241220a83de34c6a34531dbc8a2d9fab4bf1ef010000004c53ff043587cf000000000000000000496e2dc110ea22d9eccc4cf544073593cbd4cd8bd9cdbb990cfa4be8a1bc3735037fe33cf2c12ca4669a262c753da553af507c45776029d1373b36d995a5d1e3df010000002103f0e6194aadb6eb52d11e1f677af21251cda80a24d409230df6f94c4b4030893853aefeffffff0280969800000000001976a914b6d22863dfffe257f72ed5ad6daaef8ba970139e88ac7099c4040000000017a9140192877a30ab29b73abda5549bbb0a8db01d08128700000000'
        tx_onesign = {
            'inputs': [{
                'redeemScript': '5221024e539282253ccc288f93966e94fecb637f9491718f1c573ced10aa052fea939a2103de64029a56a6a9fb78c8b8f030fc557db85a4f47d1278e556081cd7b2ca381f92103f0e6194aadb6eb52d11e1f677af21251cda80a24d409230df6f94c4b4030893853ae',
                'signatures': [None, None, '3045022100ea5a8a813f70a0ed6919f49ab7b24a45858a66a433694d098f42df53fa2b152702205b2161ba4010a667e24b8a7e1bc18172b04d4e964a5a61e7803e14e68f7aa5c441'],
                'prevout_hash': '0fa8b0095f021c2e1ea22db479a6ff7077757aeea907f371dd1a32b255f4c9f5',
                'scriptSig': '0001ff01ff483045022100ea5a8a813f70a0ed6919f49ab7b24a45858a66a433694d098f42df53fa2b152702205b2161ba4010a667e24b8a7e1bc18172b04d4e964a5a61e7803e14e68f7aa5c4414ccf524c53ff043587cf000000000000000000877214e20b564ea196f5849d59ee5df75f19c9653e51cbb1b36b5016127d6d7603717353e251530938e2f58e69e4241220a83de34c6a34531dbc8a2d9fab4bf1ef010000004c53ff043587cf000000000000000000496e2dc110ea22d9eccc4cf544073593cbd4cd8bd9cdbb990cfa4be8a1bc3735037fe33cf2c12ca4669a262c753da553af507c45776029d1373b36d995a5d1e3df010000002103f0e6194aadb6eb52d11e1f677af21251cda80a24d409230df6f94c4b4030893853ae',
                'sequence': 4294967294,
                'x_pubkeys': ['ff043587cf000000000000000000877214e20b564ea196f5849d59ee5df75f19c9653e51cbb1b36b5016127d6d7603717353e251530938e2f58e69e4241220a83de34c6a34531dbc8a2d9fab4bf1ef01000000',
                              'ff043587cf000000000000000000496e2dc110ea22d9eccc4cf544073593cbd4cd8bd9cdbb990cfa4be8a1bc3735037fe33cf2c12ca4669a262c753da553af507c45776029d1373b36d995a5d1e3df01000000',
                              '03f0e6194aadb6eb52d11e1f677af21251cda80a24d409230df6f94c4b40308938'],
                'address': '2N5JTUQ7VJ3XBYh7LmK8Uuhs72UmJGSYcdE',
                'num_sig': 2,
                'pubkeys': ['024e539282253ccc288f93966e94fecb637f9491718f1c573ced10aa052fea939a',
                            '03de64029a56a6a9fb78c8b8f030fc557db85a4f47d1278e556081cd7b2ca381f9',
                            '03f0e6194aadb6eb52d11e1f677af21251cda80a24d409230df6f94c4b40308938'],
                'type': 'p2sh',
                'prevout_n': 1
            }],
            'lockTime': 0,
            'version': 1,
            'outputs': [{
                'prevout_n': 0,
                'scriptPubKey': '76a914b6d22863dfffe257f72ed5ad6daaef8ba970139e88ac',
                'type': 0,
                'value': 10000000,
                'address': 'mxBd2z6kJG48EJpi7oVZ5SWoKWMeJuJHsV'
            }, {
                'prevout_n': 1,
                'scriptPubKey': 'a9140192877a30ab29b73abda5549bbb0a8db01d081287',
                'type': 0,
                'value': 79993200,
                'address': '2MsPYCWAYtRTPZWMQvX1ZGYgqoBuGgPF6wn'
            }]
        }
        tx = transaction.Transaction(raw_onesign)
        self.assertEqual(tx.deserialize(),tx_onesign)
        self.assertFalse(tx.is_complete())

        # wallet has no tx history, so this should fail
        with self.assertRaises(transaction.InputValueMissing):
            self.wallet.sign_transaction(tx, None)

        # the tx that is used as input
        raw_src = '01000000010144a6dd5efda1f7f54ed7ba5dcce314f44a071ceb330ac3143dc694aeadb43400000000fdfd000047304402201f2e4d4357688201206168bb99de54a433a13d49160a5b5957fea794be5f1e38022021b4c6d146b2bf7374a46c00e1c7331f36ff1ff47afa29e2b9da8132a309b654414830450221009912b21f3ce1bff9fe6aa03d7da020c9b15dab7c311adbfac038193c6705b35402207625260c4f8a106ccee09946baae2c89d588087bc8e49cc9af474904a5f42157414c6952210348d80fbd95e620b150ca0be9a6090b4c98bc29fb32354d8f0b6b783bab24986d21036410bdf162b5695fc4b79368150480f2d0708303db03fcc7d23707c70b6efe2c2103f7412915e5e7fc72d1cf2829533c1557c9bb169bbbe7d4f7520fc69edaf55de453aefeffffff0280969800000000001976a914b6d22863dfffe257f72ed5ad6daaef8ba970139e88ac383d5d050000000017a914843e0387ccbf569be834e12b119eab167b47835d8700000000'
        srctx = transaction.Transaction(raw_src)
        self.assertTrue('2N5JTUQ7VJ3XBYh7LmK8Uuhs72UmJGSYcdE' in srctx.get_output_addresses())
        self.wallet.add_transaction(srctx.txid(),srctx)

        # this fails, issue 169
        self.wallet.sign_transaction(tx, None)
        self.assertTrue(tx.is_complete())
