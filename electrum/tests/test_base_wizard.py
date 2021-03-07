import os
import inspect
import json
import shutil
import tempfile

from electrum.base_wizard import BaseWizard
from electrum.keystore import BIP32_KeyStore
from electrum.simple_config import SimpleConfig
from electrum.storage import WalletStorage, StorageEncryptionVersion
from electrum.wallet_db import WalletDB, FINAL_SEED_VERSION

from . import TestCaseForTestnet


X1 = {
    'derivation': "m/45'/0",
    'pw_hash_version': 1,
    'root_fingerprint': '3f635a63',
    'type': 'bip32',
    'xprv': 'tprv8e9ce2psffApayzry2mGdWP2zkFGomo4xgNVj3dyohcaxwiR7vZ'
            'GtE5dzqCUTah7QoZb716n21QdHptT1d9DYNALyaio5gVyQTHQmy6Fyk9',
    'xpub': 'tpubDAqenSs7p2rVUT2ergRs2v39ZmmCy6yyXyyH1ZgHDyQyoRyBkKN'
            's4ihWAyr9b5uuJpuZvUYC9xDabdsoP9As2ZZZmSLEkLEkMDsaoEUaPNo'
}

X2 = {
    'derivation': "m/45'/0",
    'pw_hash_version': 1,
    'root_fingerprint': 'e54b06c8',
    'type': 'bip32',
    'xprv': 'tprv8eFGXNuTxVENvqBHHHGjQ61WaWqmjx9rp4vtZVNhskcBZUbdmD1'
            'Nws8sGqBttSJUxPLT9VEYNHcHUbXx6UkPCtiQjN5DqCWPmo3bvUW7W5Z',
    'xpub': 'tpubDAwJfnwi6rv3pJD5AvwKoVfd9YMhuHLmPNXfr1R1J2QaPxrQPbp'
            'y8MkjSweG9YkwiSi5YAjvuyoezMWH8k18oUyfiHSTUHdqZLQLTY5AtuD'
}


X1_VIEW_ONLY = {
    'derivation': None,
    'pw_hash_version': 1,
    'root_fingerprint': None,
    'type': 'bip32',
    'xprv': None,
    'xpub': 'tpubDAwJfnwi6rv3pJD5AvwKoVfd9YMhuHLmPNXfr1R1J2QaPxrQPbp'
            'y8MkjSweG9YkwiSi5YAjvuyoezMWH8k18oUyfiHSTUHdqZLQLTY5AtuD'
}


class SimpleWizard(BaseWizard):

    def continue_multisig_setup_dialog(self, m, n, keystores, run_next):
        self.last_method = inspect.currentframe().f_code.co_name
        self.last_args = (m, n, keystores, run_next)


class BaseWizardTestCase(TestCaseForTestnet):

    def setUp(self):
        super(BaseWizardTestCase, self).setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.wallet_path = os.path.join(self.electrum_path, "somewallet")
        self.wizard = SimpleWizard(self.config, None)

    def test_continue_multisig_setup(self):
        wiz = self.wizard
        storage = WalletStorage(self.wallet_path)
        d = {'wallet_type': 'standard', "seed_version": FINAL_SEED_VERSION}
        d['wallet_type'] = '2of3'
        d['x1/'] = X1
        db = WalletDB(json.dumps(d), manual_upgrades=True)
        assert db.check_unfinished_multisig()
        db.write(storage)
        storage = WalletStorage(self.wallet_path)
        wiz.continue_multisig_setup(storage)
        assert wiz.unfinished_multisig
        assert wiz.unfinished_enc_version == StorageEncryptionVersion.PLAINTEXT
        assert not wiz.unfinished_check_password
        assert wiz.last_method == 'continue_multisig_setup_dialog'
        last_args = wiz.last_args
        assert last_args[0:2] == (2, 3)  # m, n
        assert last_args[2] == wiz.keystores  # keystores
        assert len(last_args[2]) == 1
        k1 = last_args[2][0]
        assert type(k1) == BIP32_KeyStore
        assert k1.get_root_fingerprint() == '3f635a63'
        assert last_args[3] == wiz.choose_keystore  # run_next

        d['x2/'] = X2
        db = WalletDB(json.dumps(d), manual_upgrades=True)
        assert db.check_unfinished_multisig()
        db.write(storage)
        storage = WalletStorage(self.wallet_path)
        wiz.continue_multisig_setup(storage)
        assert wiz.unfinished_multisig
        assert wiz.unfinished_enc_version == StorageEncryptionVersion.PLAINTEXT
        assert not wiz.unfinished_check_password
        assert wiz.last_method == 'continue_multisig_setup_dialog'
        last_args = wiz.last_args
        assert last_args[0:2] == (2, 3)  # m, n
        assert last_args[2] == wiz.keystores  # keystores
        assert len(last_args[2]) == 2
        k1, k2 = last_args[2]
        assert type(k1) == BIP32_KeyStore
        assert k1.get_root_fingerprint() == '3f635a63'
        assert type(k2) == BIP32_KeyStore
        assert k2.get_root_fingerprint() == 'e54b06c8'
        assert last_args[3] == wiz.choose_keystore  # run_next

    def test_check_need_confirm_password(self):
        wiz = self.wizard
        storage = WalletStorage(self.wallet_path)
        d = {'wallet_type': 'standard', "seed_version": FINAL_SEED_VERSION}
        d['wallet_type'] = '2of3'
        d['x1/'] = X1_VIEW_ONLY
        d['x2/'] = X2
        db = WalletDB(json.dumps(d), manual_upgrades=True)
        db.write(storage)
        storage = WalletStorage(self.wallet_path)
        wiz.continue_multisig_setup(storage)

        wiz.unfinished_check_password = storage.check_password
        assert wiz.check_need_confirm_password()
        wiz.unfinished_check_password = None
        assert not wiz.check_need_confirm_password()
        wiz.keystores[1].update_password(None, 'test')
        assert wiz.check_need_confirm_password()
