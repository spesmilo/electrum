import shutil
import tempfile
import sys
import unittest
import os
import json

from StringIO import StringIO
from lib.wallet import WalletStorage, NewWallet


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

    def test_read_dictionnary_from_file(self):

        some_dict = {"a":"b", "c":"d"}
        contents = repr(some_dict)
        with open(self.wallet_path, "w") as f:
            contents = f.write(contents)

        storage = WalletStorage(self.wallet_path)
        self.assertEqual("b", storage.get("a"))
        self.assertEqual("d", storage.get("c"))

    def test_write_dictionnary_to_file(self):

        storage = WalletStorage(self.wallet_path)

        some_dict = {"a":"b", "c":"d"}

        for key, value in some_dict.items():
            storage.put(key, value, False)
        storage.write()

        contents = ""
        with open(self.wallet_path, "r") as f:
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
        self.storage = WalletStorage(self.wallet_path)
        self.wallet = NewWallet(self.storage)
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
        storage = WalletStorage(os.path.join(new_dir, "somewallet"))
        wallet = NewWallet(storage)
        self.assertTrue(wallet.is_watching_only())
        shutil.rmtree(new_dir)  # Don't leave useless stuff in /tmp

    def test_new_wallet_is_deterministic(self):
        self.assertTrue(self.wallet.is_deterministic())

    def test_get_seed_returns_correct_seed(self):
        self.assertEqual(self.wallet.get_seed(self.password), self.seed_text)

    def test_update_password(self):
        new_password = "secret2"
        self.wallet.update_password(self.password, new_password)
        self.wallet.get_seed(new_password)
