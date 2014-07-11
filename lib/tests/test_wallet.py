import shutil
import tempfile
import sys
import unittest
import os

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

    def test_init_wallet_default_wallet_path(self):
        path = os.path.join(self.user_dir, "somewallet")
        self.fake_config.set("default_wallet_path", path)

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
        self.assertEqual(repr(some_dict), contents)


class TestNewWallet(WalletTestCase):

    seed_text = "The seed will sprout and grow up tall."
    password = "secret"

    master_xpub = "xpub661MyMwAqRbcGEop5Rnp68oX1ikeFNVMtx1utwXZGRKMmeXVxwBM5UzkwU9nGB1EofZekLDRfi1w5F9P7Vac3PEuWdWHr2gHLW8vp5YyKJ1"
    master_xpriv = "xprv9s21ZrQH143K3kjLyQFoizrnTgv9qumWXj6K6Z7wi5nNtrCMRPs6XggH6Bbgz9CUgPJnZnV74yUdRSr8qWVELr9QQTgU5aNL33ViMyD9nhs"

    first_account_name = "account1"
    first_account_first_address = "Ld975YW8975uNNuhWQWNgiJDH3EMtGacza"
    first_account_second_address = "LP16W5shm7hfKStDe6dgHdg9Loty5FcukH"

    import_private_key = "TAroS5Knm8GZcnpPycBgzjwwDLWMyQjDrcuGPPoArgrbW7Ln22qp"
    import_key_address = "LPzGaoLUtXFkmNo3u1chDxGxDnSaBQTTxm"

    def setUp(self):
        super(TestNewWallet, self).setUp()
        self.storage = WalletStorage(self.fake_config)
        self.wallet = NewWallet(self.storage)
        # This cannot be constructed by electrum at random, it should be safe
        # from eventual collisions.
        self.wallet.add_seed(self.seed_text, self.password)

    def test_wallet_with_seed_is_not_watching_only(self):
        self.assertFalse(self.wallet.is_watching_only())

    def test_wallet_without_seed_is_watching_only(self):
        # We need a new storage , since the default storage was already seeded
        # in setUp()
        new_dir = tempfile.mkdtemp()
        config = FakeConfig(new_dir)
        wallet = NewWallet(config)
        self.assertTrue(wallet.is_watching_only())
        shutil.rmtree(new_dir)  # Don't leave useless stuff in /tmp

    def test_new_wallet_is_deterministic(self):
        self.assertTrue(self.wallet.is_deterministic())

    def test_get_seed_returns_correct_seed(self):
        self.assertEqual(self.wallet.get_seed(self.password), self.seed_text)
        self.assertEqual(0, len(self.wallet.addresses()))

    def test_add_account(self):
        self.wallet.create_account(self.first_account_name, self.password)
        self.assertEqual(1, len(self.wallet.addresses()))
        self.assertIn(self.first_account_first_address,
                         self.wallet.addresses())

    def test_add_account_add_address(self):
        self.wallet.create_account(self.first_account_name, self.password)
        self.wallet.synchronizer = FakeSynchronizer()

        self.wallet.create_new_address()
        self.assertEqual(2, len(self.wallet.addresses()))
        self.assertIn(self.first_account_first_address,
                         self.wallet.addresses())
        self.assertIn(self.first_account_second_address,
                      self.wallet.addresses())

    def test_key_import(self):
        # Wallets have no imported keys by default.
        self.wallet.create_account(self.first_account_name, self.password)
        self.assertFalse(self.wallet.has_imported_keys())

        # Importing a key works.
        self.wallet.import_key(self.import_private_key, "")
        self.assertEqual(2, len(self.wallet.addresses()))
        self.assertIn(self.import_key_address, self.wallet.addresses())

        self.assertTrue(self.wallet.has_imported_keys())

        # Deleting the key works.
        self.wallet.delete_imported_key(self.import_key_address)
        self.assertFalse(self.wallet.has_imported_keys())
        self.assertEqual(1, len(self.wallet.addresses()))
        self.assertNotIn(self.import_key_address, self.wallet.addresses())

    def test_update_password(self):
        new_password = "secret2"
        self.wallet.update_password(self.password, new_password)
        self.wallet.create_account(self.first_account_name, new_password)
        self.assertEqual(1, len(self.wallet.addresses()))
