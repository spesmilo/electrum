import shutil
import tempfile
import sys
import os
import json
from decimal import Decimal
import time

from io import StringIO
from electrum_ltc.storage import WalletStorage
from electrum_ltc.wallet_db import FINAL_SEED_VERSION
from electrum_ltc.wallet import (Abstract_Wallet, Standard_Wallet, create_new_wallet,
                                 restore_wallet_from_text, Imported_Wallet, Wallet)
from electrum_ltc.exchange_rate import ExchangeBase, FxThread
from electrum_ltc.util import TxMinedInfo, InvalidPassword
from electrum_ltc.bitcoin import COIN
from electrum_ltc.wallet_db import WalletDB
from electrum_ltc.simple_config import SimpleConfig

from . import ElectrumTestCase


class FakeSynchronizer(object):

    def __init__(self):
        self.store = []

    def add(self, address):
        self.store.append(address)


class WalletTestCase(ElectrumTestCase):

    def setUp(self):
        super(WalletTestCase, self).setUp()
        self.user_dir = tempfile.mkdtemp()
        self.config = SimpleConfig({'electrum_path': self.user_dir})

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

        storage = WalletStorage(self.wallet_path)
        db = WalletDB(storage.read(), manual_upgrades=True)
        self.assertEqual("b", db.get("a"))
        self.assertEqual("d", db.get("c"))

    def test_write_dictionary_to_file(self):

        storage = WalletStorage(self.wallet_path)
        db = WalletDB('', manual_upgrades=True)

        some_dict = {
            u"a": u"b",
            u"c": u"d",
            u"seed_version": FINAL_SEED_VERSION}

        for key, value in some_dict.items():
            db.put(key, value)
        db.write(storage)

        with open(self.wallet_path, "r") as f:
            contents = f.read()
        d = json.loads(contents)
        for key, value in some_dict.items():
            self.assertEqual(d[key], value)

class FakeExchange(ExchangeBase):
    def __init__(self, rate):
        super().__init__(lambda self: None, lambda self: None)
        self.quotes = {'TEST': rate}

class FakeFxThread:
    def __init__(self, exchange):
        self.exchange = exchange
        self.ccy = 'TEST'

    remove_thousands_separator = staticmethod(FxThread.remove_thousands_separator)
    timestamp_rate = FxThread.timestamp_rate
    ccy_amount_str = FxThread.ccy_amount_str
    history_rate = FxThread.history_rate

class FakeWallet:
    def __init__(self, fiat_value):
        super().__init__()
        self.fiat_value = fiat_value
        self.db = WalletDB("{}", manual_upgrades=True)
        self.db.transactions = self.db.verified_tx = {'abc':'Tx'}

    def get_tx_height(self, txid):
        # because we use a current timestamp, and history is empty,
        # FxThread.history_rate will use spot prices
        return TxMinedInfo(height=10, conf=10, timestamp=int(time.time()), header_hash='def')

    default_fiat_value = Abstract_Wallet.default_fiat_value
    price_at_timestamp = Abstract_Wallet.price_at_timestamp
    class storage:
        put = lambda self, x: None

txid = 'abc'
ccy = 'TEST'

class TestFiat(ElectrumTestCase):
    def setUp(self):
        super().setUp()
        self.value_sat = COIN
        self.fiat_value = {}
        self.wallet = FakeWallet(fiat_value=self.fiat_value)
        self.fx = FakeFxThread(FakeExchange(Decimal('1000.001')))
        default_fiat = Abstract_Wallet.default_fiat_value(self.wallet, txid, self.fx, self.value_sat)
        self.assertEqual(Decimal('1000.001'), default_fiat)
        self.assertEqual('1,000.00', self.fx.ccy_amount_str(default_fiat, commas=True))

    def test_save_fiat_and_reset(self):
        self.assertEqual(False, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '1000.01', self.fx, self.value_sat))
        saved = self.fiat_value[ccy][txid]
        self.assertEqual('1,000.01', self.fx.ccy_amount_str(Decimal(saved), commas=True))
        self.assertEqual(True,       Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '', self.fx, self.value_sat))
        self.assertNotIn(txid, self.fiat_value[ccy])
        # even though we are not setting it to the exact fiat value according to the exchange rate, precision is truncated away
        self.assertEqual(True, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '1,000.002', self.fx, self.value_sat))

    def test_too_high_precision_value_resets_with_no_saved_value(self):
        self.assertEqual(True, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '1,000.001', self.fx, self.value_sat))

    def test_empty_resets(self):
        self.assertEqual(True, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '', self.fx, self.value_sat))
        self.assertNotIn(ccy, self.fiat_value)

    def test_save_garbage(self):
        self.assertEqual(False, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, 'garbage', self.fx, self.value_sat))
        self.assertNotIn(ccy, self.fiat_value)


class TestCreateRestoreWallet(WalletTestCase):

    def test_create_new_wallet(self):
        passphrase = 'mypassphrase'
        password = 'mypassword'
        encrypt_file = True
        d = create_new_wallet(path=self.wallet_path,
                              passphrase=passphrase,
                              password=password,
                              encrypt_file=encrypt_file,
                              gap_limit=1,
                              config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet

        # lightning initialization
        self.assertTrue(wallet.db.get('lightning_privkey2').startswith('xprv'))

        wallet.check_password(password)
        self.assertEqual(passphrase, wallet.keystore.get_passphrase(password))
        self.assertEqual(d['seed'], wallet.keystore.get_seed(password))
        self.assertEqual(encrypt_file, wallet.storage.is_encrypted())

    def test_restore_wallet_from_text_mnemonic(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        passphrase = 'mypassphrase'
        password = 'mypassword'
        encrypt_file = True
        d = restore_wallet_from_text(text,
                                     path=self.wallet_path,
                                     passphrase=passphrase,
                                     password=password,
                                     encrypt_file=encrypt_file,
                                     gap_limit=1,
                                     config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(passphrase, wallet.keystore.get_passphrase(password))
        self.assertEqual(text, wallet.keystore.get_seed(password))
        self.assertEqual(encrypt_file, wallet.storage.is_encrypted())
        self.assertEqual('ltc1q2ccr34wzep58d4239tl3x3734ttle92arvely7', wallet.get_receiving_addresses()[0])

    def test_restore_wallet_from_text_xpub(self):
        text = 'zpub6nydoME6CFdJtMpzHW5BNoPz6i6XbeT9qfz72wsRqGdgGEYeivso6xjfw8cGcCyHwF7BNW4LDuHF35XrZsovBLWMF4qXSjmhTXYiHbWqGLt'
        d = restore_wallet_from_text(text, path=self.wallet_path, gap_limit=1, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(text, wallet.keystore.get_master_public_key())
        self.assertEqual('ltc1q2ccr34wzep58d4239tl3x3734ttle92arvely7', wallet.get_receiving_addresses()[0])

    def test_restore_wallet_from_text_xkey_that_is_also_a_valid_electrum_seed_by_chance(self):
        text = 'yprvAJBpuoF4FKpK92ofzQ7ge6VJMtorow3maAGPvPGj38ggr2xd1xCrC9ojUVEf9jhW5L9SPu6fU2U3o64cLrRQ83zaQGNa6YP3ajZS6hHNPXj'
        d = restore_wallet_from_text(text, path=self.wallet_path, gap_limit=1, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(text, wallet.keystore.get_master_private_key(password=None))
        self.assertEqual('MVnD1Yo1HNNGNY4ZvaXv4kdxzKtzPzA8FT', wallet.get_receiving_addresses()[0])

    def test_restore_wallet_from_text_xprv(self):
        text = 'zprvAZzHPqhCMt51fskXBUYB1fTFYgG3CBjJUT4WEZTpGw6hPSDWBPZYZARC5sE9xAcX8NeWvvucFws8vZxEa65RosKAhy7r5MsmKTxr3hmNmea'
        d = restore_wallet_from_text(text, path=self.wallet_path, gap_limit=1, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(text, wallet.keystore.get_master_private_key(password=None))
        self.assertEqual('ltc1q2ccr34wzep58d4239tl3x3734ttle92arvely7', wallet.get_receiving_addresses()[0])

    def test_restore_wallet_from_text_addresses(self):
        text = 'ltc1q2ccr34wzep58d4239tl3x3734ttle92arvely7 ltc1qnp78h78vp92pwdwq5xvh8eprlga5q8gu7xl7hg'
        d = restore_wallet_from_text(text, path=self.wallet_path, config=self.config)
        wallet = d['wallet']  # type: Imported_Wallet
        self.assertEqual('ltc1q2ccr34wzep58d4239tl3x3734ttle92arvely7', wallet.get_receiving_addresses()[0])
        self.assertEqual(2, len(wallet.get_receiving_addresses()))
        # also test addr deletion
        wallet.delete_address('ltc1qnp78h78vp92pwdwq5xvh8eprlga5q8gu7xl7hg')
        self.assertEqual(1, len(wallet.get_receiving_addresses()))

    def test_restore_wallet_from_text_privkeys(self):
        text = 'p2wpkh:TAa25Tq4PdzhDKBoVaFaCdV3yxvLrRikQviNkuFQLeYopsVvNTV3 p2wpkh:T7tYQXfHmkSmS3A2eLCrPNHG21JrEFj9NZWbS6f71Z7SLEgRqD97'
        d = restore_wallet_from_text(text, path=self.wallet_path, config=self.config)
        wallet = d['wallet']  # type: Imported_Wallet
        addr0 = wallet.get_receiving_addresses()[0]
        self.assertEqual('ltc1q2ccr34wzep58d4239tl3x3734ttle92arvely7', addr0)
        self.assertEqual('p2wpkh:TAa25Tq4PdzhDKBoVaFaCdV3yxvLrRikQviNkuFQLeYopsVvNTV3',
                         wallet.export_private_key(addr0, password=None))
        self.assertEqual(2, len(wallet.get_receiving_addresses()))
        # also test addr deletion
        wallet.delete_address('ltc1qnp78h78vp92pwdwq5xvh8eprlga5q8gu7xl7hg')
        self.assertEqual(1, len(wallet.get_receiving_addresses()))


class TestWalletPassword(WalletTestCase):

    def test_update_password_of_imported_wallet(self):
        wallet_str = '{"addr_history":{"LMK1a5LKLkLFCEKukwwTrGxPboNvZjDbcY":[],"LPRvUteVjy7MwDYro7o6XJ8SzhaYBJQhoM":[],"LZBc9EVXNXW1aGdrxodATNp9kYeCxufeWb":[]},"addresses":{"change":[],"receiving":["LMK1a5LKLkLFCEKukwwTrGxPboNvZjDbcY","LZBc9EVXNXW1aGdrxodATNp9kYeCxufeWb","LPRvUteVjy7MwDYro7o6XJ8SzhaYBJQhoM"]},"keystore":{"keypairs":{"0344b1588589958b0bcab03435061539e9bcf54677c104904044e4f8901f4ebdf5":"T8hVerMmMsVnq7mkXpEw4krEhXJ5BZNVv7mb4C7LoV8Ni8iywME1","0389508c13999d08ffae0f434a085f4185922d64765c0bff2f66e36ad7f745cc5f":"T96yXyhXKvujT4sMAPihoJJ2sXNTwDircc7WnT2qqXTdBs433uZ5","04575f52b82f159fa649d2a4c353eb7435f30206f0a6cb9674fbd659f45082c37d559ffd19bea9c0d3b7dcc07a7b79f4cffb76026d5d4dff35341efe99056e22d2":"6vHESf1YF8tPdqpGyEiNvibJPRZzKsB4ijYsywkUaz3SfUAnidY"},"type":"imported"},"pruned_txo":{},"seed_version":13,"stored_height":-1,"transactions":{},"tx_fees":{},"txi":{},"txo":{},"use_encryption":false,"verified_tx3":{},"wallet_type":"standard","winpos-qt":[100,100,840,405]}'
        db = WalletDB(wallet_str, manual_upgrades=False)
        storage = WalletStorage(self.wallet_path)
        wallet = Wallet(db, storage, config=self.config)

        wallet.check_password(None)

        wallet.update_password(None, "1234")

        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")

    def test_update_password_of_standard_wallet(self):
        wallet_str = '''{"addr_history":{"LLT9wyJ9BLXsA7riHYi75ZFfxDZxS32oAG":[],"LLwNKFZDfjbB8jkWnzqPF2r3XsBxHu3mHF":[],"LMWQH2yLhZ7VnHx9RF6CpvZPd8ySV5Lanh":[],"LMyDQiayPVgAxmtmfU1B9Mh98GwozAPdCj":[],"LNgcK42YMxmW9FADVuhx4Bm3sWCPTPydxX":[],"LNuiTArKDn23okCnUaHLdUQMfVrvjvjMnU":[],"LPUEAWEFxY956wMN7H8E8ctRpFiM528kSn":[],"LS2GG9wz7M29h2S2Vp9TCVGr1ppHuMvQeL":[],"LSvKsf3Q55rUdtzBmoEjEqDEt2j5NEo9CF":[],"LT16eUG1pRZFXWKDZLCXWrcdvEa9vWyQz8":[],"LTo6Pmy4jeTRr1dsodhym6SvXADh7b69Av":[],"LUCzzEYAvFv65DpGn7BWA4EyBXnQ5evfQJ":[],"LUGUhzEAVatT2jTH9ktAYmF7jMvbPaECbC":[],"LKRixTwrG2FkQYPoRxHxLw6ujam1EHbQAf":[],"LY8mxubJfda3rZL5udixMexVzEXUsqGaNP":[],"LYHvweg8uAa6ACDiTKpC3V6749vk1g26k1":[],"LagAhx4KgpAdpysLSWV8jBS3WPz5YsDTXU":[],"Lajnx2mXFZgtJguqH3C6cS29jck4ago9vq":[],"Lavj6A9GKjrtdVL1KwHeqyCPYAkhyZoFVE":[],"LcJQigi9nbtkUxu6GSjBv2HnETs8jtLNPR":[],"LcjviD3pPN7HiHAn1dYbBwU6NLBwJJrSXZ":[],"LddFDqGsV8XDm9yUf2J37EDNZXtth3N4UF":[],"Le2upsurQXvsBXxP95pt4cJzNKUC6NQTuK":[],"Le4SVbqTuFnyVQe2jkDd2sDpNF79ngHorT":[],"LgE4ERkNimLfKxjMydnoSM23rNqtG5pPYc":[],"Lhz5ZQ1pYxTtuD6V2un762Kd4HByp4QwXB":[]},"addresses":{"change":["Lavj6A9GKjrtdVL1KwHeqyCPYAkhyZoFVE","LagAhx4KgpAdpysLSWV8jBS3WPz5YsDTXU","LPUEAWEFxY956wMN7H8E8ctRpFiM528kSn","LUGUhzEAVatT2jTH9ktAYmF7jMvbPaECbC","LUCzzEYAvFv65DpGn7BWA4EyBXnQ5evfQJ","LcjviD3pPN7HiHAn1dYbBwU6NLBwJJrSXZ"],"receiving":["LNuiTArKDn23okCnUaHLdUQMfVrvjvjMnU","LMWQH2yLhZ7VnHx9RF6CpvZPd8ySV5Lanh","LTo6Pmy4jeTRr1dsodhym6SvXADh7b69Av","LcJQigi9nbtkUxu6GSjBv2HnETs8jtLNPR","Lhz5ZQ1pYxTtuD6V2un762Kd4HByp4QwXB","LMyDQiayPVgAxmtmfU1B9Mh98GwozAPdCj","LddFDqGsV8XDm9yUf2J37EDNZXtth3N4UF","LLT9wyJ9BLXsA7riHYi75ZFfxDZxS32oAG","LLwNKFZDfjbB8jkWnzqPF2r3XsBxHu3mHF","LNgcK42YMxmW9FADVuhx4Bm3sWCPTPydxX","Le4SVbqTuFnyVQe2jkDd2sDpNF79ngHorT","LS2GG9wz7M29h2S2Vp9TCVGr1ppHuMvQeL","LYHvweg8uAa6ACDiTKpC3V6749vk1g26k1","LSvKsf3Q55rUdtzBmoEjEqDEt2j5NEo9CF","Le2upsurQXvsBXxP95pt4cJzNKUC6NQTuK","LT16eUG1pRZFXWKDZLCXWrcdvEa9vWyQz8","LKRixTwrG2FkQYPoRxHxLw6ujam1EHbQAf","LY8mxubJfda3rZL5udixMexVzEXUsqGaNP","Lajnx2mXFZgtJguqH3C6cS29jck4ago9vq","LgE4ERkNimLfKxjMydnoSM23rNqtG5pPYc"]},"keystore":{"seed":"cereal wise two govern top pet frog nut rule sketch bundle logic","type":"bip32","xprv":"xprv9s21ZrQH143K29XjRjUs6MnDB9wXjXbJP2kG1fnRk8zjdDYWqVkQYUqaDtgZp5zPSrH5PZQJs8sU25HrUgT1WdgsPU8GbifKurtMYg37d4v","xpub":"xpub661MyMwAqRbcEdcCXm1sTViwjBn28zK9kFfrp4C3JUXiW1sfP34f6HA45B9yr7EH5XGzWuTfMTdqpt9XPrVQVUdgiYb5NW9m8ij1FSZgGBF"},"pruned_txo":{},"seed_type":"standard","seed_version":13,"stored_height":-1,"transactions":{},"tx_fees":{},"txi":{},"txo":{},"use_encryption":false,"verified_tx3":{},"wallet_type":"standard","winpos-qt":[619,310,840,405]}'''
        db = WalletDB(wallet_str, manual_upgrades=False)
        storage = WalletStorage(self.wallet_path)
        wallet = Wallet(db, storage, config=self.config)

        wallet.check_password(None)

        wallet.update_password(None, "1234")
        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")

    def test_update_password_with_app_restarts(self):
        wallet_str = '{"addr_history":{"LMK1a5LKLkLFCEKukwwTrGxPboNvZjDbcY":[],"LPRvUteVjy7MwDYro7o6XJ8SzhaYBJQhoM":[],"LZBc9EVXNXW1aGdrxodATNp9kYeCxufeWb":[]},"addresses":{"change":[],"receiving":["LMK1a5LKLkLFCEKukwwTrGxPboNvZjDbcY","LZBc9EVXNXW1aGdrxodATNp9kYeCxufeWb","LPRvUteVjy7MwDYro7o6XJ8SzhaYBJQhoM"]},"keystore":{"keypairs":{"0344b1588589958b0bcab03435061539e9bcf54677c104904044e4f8901f4ebdf5":"T8hVerMmMsVnq7mkXpEw4krEhXJ5BZNVv7mb4C7LoV8Ni8iywME1","0389508c13999d08ffae0f434a085f4185922d64765c0bff2f66e36ad7f745cc5f":"T96yXyhXKvujT4sMAPihoJJ2sXNTwDircc7WnT2qqXTdBs433uZ5","04575f52b82f159fa649d2a4c353eb7435f30206f0a6cb9674fbd659f45082c37d559ffd19bea9c0d3b7dcc07a7b79f4cffb76026d5d4dff35341efe99056e22d2":"6vHESf1YF8tPdqpGyEiNvibJPRZzKsB4ijYsywkUaz3SfUAnidY"},"type":"imported"},"pruned_txo":{},"seed_version":13,"stored_height":-1,"transactions":{},"tx_fees":{},"txi":{},"txo":{},"use_encryption":false,"verified_tx3":{},"wallet_type":"standard","winpos-qt":[100,100,840,405]}'
        db = WalletDB(wallet_str, manual_upgrades=False)
        storage = WalletStorage(self.wallet_path)
        wallet = Wallet(db, storage, config=self.config)
        wallet.stop()

        storage = WalletStorage(self.wallet_path)
        # if storage.is_encrypted():
        #     storage.decrypt(password)
        db = WalletDB(storage.read(), manual_upgrades=False)
        wallet = Wallet(db, storage, config=self.config)

        wallet.check_password(None)

        wallet.update_password(None, "1234")
        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")
