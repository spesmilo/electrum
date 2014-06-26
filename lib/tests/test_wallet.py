import shutil
import tempfile
import sys
import unittest
import os

from StringIO import StringIO
from lib.wallet import WalletStorage

class FakeConfig(object):
    """A stub config file to be used in tests"""
    def __init__(self, path):
        self.path = path
        self.store = {}

    def set(self, key, value):
        self.store[key] = value

    def get(self, key):
        return self.store.get(key, None)


class TestWalletStorage(unittest.TestCase):

    def setUp(self):
        super(TestWalletStorage, self).setUp()
        self.user_dir = tempfile.mkdtemp()

        self.fake_config = FakeConfig(self.user_dir)

        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

    def tearDown(self):
        super(TestWalletStorage, self).tearDown()
        shutil.rmtree(self.user_dir)
        # Restore the "real" stdout
        sys.stdout = self._saved_stdout

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

