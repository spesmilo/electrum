import shutil
import tempfile
import sys
import unittest
import os
import json

from StringIO import StringIO
from lib.wallet import WalletStorage, NewWallet


class FakeConfig(object):
    """A stub config file to be used in tests"""
    def __init__(self, path):
        self.path = path
        self.store = {}

    def set(self, key, value):
        self.store[key] = value

    def get(self, key, default=None):
        return self.store.get(key, default)


class FakeSynchronizer(object):

    def __init__(self):
        self.store = []

    def add(self, address):
        self.store.append(address)

class FakeNetwork(object):
    def get_local_height():
        return 10000

class WalletTestCase(unittest.TestCase):

    def setUp(self):
        super(WalletTestCase, self).setUp()
        self.user_dir = tempfile.mkdtemp()

        self.fake_config = FakeConfig(self.user_dir)

        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

    def tearDown(self):
        super(WalletTestCase, self).tearDown()
        shutil.rmtree(self.user_dir)
        # Restore the "real" stdout
        sys.stdout = self._saved_stdout


class TestWalletStorage(WalletTestCase):

    def test_init_wallet_default_path(self):
        storage = WalletStorage(self.fake_config)
        expected = os.path.join(self.user_dir, "wallets", "default_wallet")
        self.assertEqual(expected, storage.path)

    def test_init_wallet_explicit_path(self):
        path = os.path.join(self.user_dir, "somewallet")
        self.fake_config.set("wallet_path", path)

        storage = WalletStorage(self.fake_config)
        self.assertEqual(path, storage.path)

    def test_read_dictionnary_from_file(self):
        path = os.path.join(self.user_dir, "somewallet")
        self.fake_config.set("wallet_path", path)

        some_dict = {"a":"b", "c":"d"}
        contents = repr(some_dict)
        with open(path, "w") as f:
            contents = f.write(contents)

        storage = WalletStorage(self.fake_config)
        self.assertEqual("b", storage.get("a"))
        self.assertEqual("d", storage.get("c"))

    def test_write_dictionnary_to_file(self):
        path = os.path.join(self.user_dir, "somewallet")
        self.fake_config.set("wallet_path", path)

        storage = WalletStorage(self.fake_config)

        some_dict = {"a":"b", "c":"d"}
        storage.data = some_dict

        storage.write()

        contents = ""
        with open(path, "r") as f:
            contents = f.read()
        self.assertEqual(some_dict, json.loads(contents))

class TestNewWallet(WalletTestCase):

    seed_text = "travel nowhere air position hill peace suffer parent beautiful rise blood power home crumble teach"
    password = "secret"

    first_account_name = "account1"

    import_private_key = "L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW"
    import_key_address = "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"

    def setUp(self):
        super(TestNewWallet, self).setUp()
        self.storage = WalletStorage(self.fake_config)
        self.wallet = NewWallet(self.storage)
        self.wallet.network = FakeNetwork()
        # This cannot be constructed by electrum at random, it should be safe
        # from eventual collisions.
        self.wallet.add_seed(self.seed_text, self.password)
        self.wallet.create_master_keys(self.password)
        self.wallet.create_main_account(self.password)

    def test_wallet_with_seed_is_not_watching_only(self):
        self.assertFalse(self.wallet.is_watching_only())

    def test_wallet_without_seed_is_watching_only(self):
        # We need a new storage , since the default storage was already seeded
        # in setUp()
        new_dir = tempfile.mkdtemp()
        config = FakeConfig(new_dir)
        storage = WalletStorage(config)
        wallet = NewWallet(storage)
        self.assertTrue(wallet.is_watching_only())
        shutil.rmtree(new_dir)  # Don't leave useless stuff in /tmp

    def test_new_wallet_is_deterministic(self):
        self.assertTrue(self.wallet.is_deterministic())

    def test_get_seed_returns_correct_seed(self):
        self.assertEqual(self.wallet.get_seed(self.password), self.seed_text)


    def test_key_import(self):
        # Wallets have no imported keys by default.
        self.assertFalse(self.wallet.has_imported_keys())

        # Importing a key works.
        self.wallet.import_key(self.import_private_key, "")
        self.assertIn(self.import_key_address, self.wallet.addresses())
        self.assertTrue(self.wallet.has_imported_keys())

        # Deleting the key works.
        self.wallet.delete_imported_key(self.import_key_address)
        self.assertFalse(self.wallet.has_imported_keys())
        self.assertNotIn(self.import_key_address, self.wallet.addresses())

    def test_update_password(self):
        new_password = "secret2"
        self.wallet.update_password(self.password, new_password)
        self.wallet.get_seed(new_password)

    def test_transaction_with_server_fee(self):
      outputs = [('address', '1MQaPKJTVZt7vKNtdXZBUiv4smtf5yZ9Ao', 90000)]
      self.wallet.server_fee = 10000
      self.wallet.server_fee_addr = '1MYwrbuXqHyyvk8pTRNTH7b92DHsv9BSmz'
      coins = [{'coinbase': '', 'height': 1, 'value': 100000}]
      self.wallet.add_input_info = lambda x: x #Skip this as we do not have an account for the address
      tx = self.wallet.make_unsigned_transaction(outputs, fixed_fee=0, coins=coins, change_addr=self.import_key_address)
      self.assertIn(('address', self.wallet.server_fee_addr, self.wallet.server_fee), tx.outputs)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestNewWallet)
    unittest.TextTestRunner(verbosity=2).run(suite)
