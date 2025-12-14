import shutil
import tempfile
import sys
import os
import json
from decimal import Decimal
import time
from io import StringIO
import asyncio

from electrum.storage import WalletStorage
from electrum.wallet_db import FINAL_SEED_VERSION
from electrum.wallet import (Abstract_Wallet, Standard_Wallet, create_new_wallet,
                             Imported_Wallet, Wallet)
from electrum.exchange_rate import ExchangeBase, FxThread
from electrum.util import TxMinedInfo, InvalidPassword
from electrum.bitcoin import COIN
from electrum.wallet_db import WalletDB
from electrum.json_db import JsonDB
from electrum.simple_config import SimpleConfig
from electrum import util
from electrum.daemon import Daemon
from electrum.invoices import PR_UNPAID, PR_PAID, PR_UNCONFIRMED
from electrum.transaction import tx_from_any
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED

from . import ElectrumTestCase
from . import restore_wallet_from_text__for_unittest


class FakeSynchronizer(object):

    def __init__(self, db):
        self.db = db
        self.store = []

    def add(self, address):
        self.store.append(address)


class WalletTestCase(ElectrumTestCase):

    def setUp(self):
        super(WalletTestCase, self).setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

        self.wallet_path = os.path.join(self.electrum_path, "somewallet")

        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

    def tearDown(self):
        super(WalletTestCase, self).tearDown()
        # Restore the "real" stdout
        sys.stdout = self._saved_stdout


class TestWalletStorage(WalletTestCase):

    def test_read_dictionary_from_file(self):

        some_dict = {"a":"b", "c":"d"}
        contents = json.dumps(some_dict)
        with open(self.wallet_path, "w") as f:
            contents = f.write(contents)

        storage = WalletStorage(self.wallet_path)
        db = JsonDB(storage.read(), storage=storage)
        self.assertEqual("b", db.get([''], "a"))
        self.assertEqual("d", db.get([''], "c"))

    def test_write_dictionary_to_file(self):

        storage = WalletStorage(self.wallet_path)
        db = JsonDB('', storage=storage)

        some_dict = {
            u"a": u"b",
            u"c": u"d",
            u"seed_version": FINAL_SEED_VERSION}

        for key, value in some_dict.items():
            db.put([''], key, value)
        db.write()

        with open(self.wallet_path, "r") as f:
            contents = f.read()
        d = json.loads(contents)
        for key, value in some_dict.items():
            self.assertEqual(d[key], value)

    async def test_storage_imported_add_privkeys_persistence_test(self):
        text = ' '.join([
            'p2wpkh:L4jkdiXszG26SUYvwwJhzGwg37H2nLhrbip7u6crmgNeJysv5FHL',
            'p2wpkh:L24GxnN7NNUAfCXA6hFzB1jt59fYAAiFZMcLaJ2ZSawGpM3uqhb1'
        ])
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet_path, config=self.config)
        wallet = d['wallet']  # type: Imported_Wallet
        self.assertEqual(2, len(wallet.get_receiving_addresses()))
        await wallet.stop()

        # open the wallet anew again, and add a privkey. This should add the new data as a json_patch
        del wallet
        wallet = Daemon._load_wallet(self.wallet_path, password=None, config=self.config)

        wallet.import_private_keys(['p2wpkh:KzuqaaLp9zYjVuj8vQtCwFdiZFreW3NJNBachgVS8S9XMgj5y78b'], password=None)
        self.assertEqual(3, len(wallet.get_receiving_addresses()))
        self.assertEqual(3, len(wallet.keystore.keypairs))
        await wallet.stop()

        # open the wallet anew again, and verify if the privkey was stored
        del wallet
        wallet = Daemon._load_wallet(self.wallet_path, password=None, config=self.config)
        self.assertEqual(3, len(wallet.get_receiving_addresses()))
        self.assertEqual(3, len(wallet.keystore.keypairs))
        self.assertTrue('03bf450797034dc95693096e575e3b3db14e5f074679b349b727f90fc7804ce7ab' in wallet.keystore.keypairs)
        self.assertTrue('030dac677b9484e23db6f9255eddf433f4f12c02f9b35e0100f2f103ffbccf540f' in wallet.keystore.keypairs)
        self.assertTrue('02f11d5f222a728fd08226cb5a1e85a74d58fc257bd3764bf1234346f91defed72' in wallet.keystore.keypairs)

    async def test_storage_prevouts_by_scripthash_persistence(self):
        text = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet_path, config=self.config)
        wallet1 = d['wallet']  # type: Standard_Wallet
        # create payreq
        addr = wallet1.get_unused_address()
        self.assertEqual("1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf", addr)
        pr_key = wallet1.create_request(amount_sat=10000, message="msg", address=addr, exp_delay=86400)
        pr = wallet1.get_request(pr_key)
        self.assertIsNotNone(pr)
        self.assertEqual(PR_UNPAID, wallet1.get_invoice_status(pr))
        await wallet1.stop()

        # open the wallet anew again, and get paid onchain
        del wallet1
        wallet1 = Daemon._load_wallet(self.wallet_path, password=None, config=self.config)
        tx = tx_from_any("02000000000101a97a9ae7fb1a9220fdd170a974987ac24631dcff89b60fa4907c78c3639994db0000000000fdffffff0210270000000000001976a914ea7804a2c266063572cc009a63dc25dcc0e9d9b588ac20491e0000000000160014b8e4fdc91593b67de2bf214694ef47e38dc2ee8e02473044022005326882904906cfa9c1de75333ace1019596f2ab25d21118220d037dfc0e48b02207d0b3f075cfe5e1e0247ff3cdd7155dc05e7459daf1bfa0ea02e9112b9151ec90121026cc6a74c2b0e38661d341ffae48fe7dde5196ca4afe95d28b496673fa4cf646700000000")
        wallet1.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))
        await wallet1.stop()

        # open the wallet anew again, and verify payreq is still paid
        del wallet1
        wallet1 = Daemon._load_wallet(self.wallet_path, password=None, config=self.config)
        self.assertEqual(PR_UNCONFIRMED, wallet1.get_invoice_status(pr))


class FakeExchange(ExchangeBase):
    def __init__(self, rate):
        super().__init__(lambda self: None, lambda self: None)
        self._quotes = {'TEST': rate}
        self._quotes_timestamp = float("inf")  # spot price from the far future never becomes stale :P

class FakeFxThread:
    def __init__(self, exchange):
        self.exchange = exchange
        self.ccy = 'TEST'

    remove_thousands_separator = staticmethod(FxThread.remove_thousands_separator)
    timestamp_rate = FxThread.timestamp_rate
    ccy_amount_str = FxThread.ccy_amount_str
    history_rate = FxThread.history_rate

class FakeADB:
    def get_tx_height(self, txid):
        # because we use a current timestamp, and history is empty,
        # FxThread.history_rate will use spot prices
        return TxMinedInfo(_height=10, conf=10, timestamp=int(time.time()), header_hash='def')

class FakeWallet:
    def __init__(self, fiat_value):
        super().__init__()
        self.fiat_value = fiat_value
        json_db = JsonDB('', storage=None)
        self.db = WalletDB(json_db.get_stored_dict())
        self.adb = FakeADB()
        self.db.transactions = self.db.verified_tx = {'abc':'Tx'}

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
        self.assertEqual('1 000.00', self.fx.ccy_amount_str(default_fiat, add_thousands_sep=True))

    def test_save_fiat_and_reset(self):
        self.assertEqual(False, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '1000.01', self.fx, self.value_sat))
        saved = self.fiat_value[ccy][txid]
        self.assertEqual('1 000.01', self.fx.ccy_amount_str(Decimal(saved), add_thousands_sep=True))
        self.assertEqual(True,       Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '', self.fx, self.value_sat))
        self.assertNotIn(txid, self.fiat_value[ccy])
        # even though we are not setting it to the exact fiat value according to the exchange rate, precision is truncated away
        self.assertEqual(True, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '1 000.002', self.fx, self.value_sat))

    def test_too_high_precision_value_resets_with_no_saved_value(self):
        self.assertEqual(True, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '1 000.001', self.fx, self.value_sat))

    def test_empty_resets(self):
        self.assertEqual(True, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, '', self.fx, self.value_sat))
        self.assertNotIn(ccy, self.fiat_value)

    def test_save_garbage(self):
        self.assertEqual(False, Abstract_Wallet.set_fiat_value(self.wallet, txid, ccy, 'garbage', self.fx, self.value_sat))
        self.assertNotIn(ccy, self.fiat_value)


class TestCreateRestoreWallet(WalletTestCase):

    async def test_create_new_wallet(self):
        passphrase = 'mypassphrase'
        password = 'mypassword'
        encrypt_file = True
        d = create_new_wallet(path=self.wallet_path,
                              passphrase=passphrase,
                              password=password,
                              encrypt_file=encrypt_file,
                              gap_limit=1,
                              gap_limit_for_change=1,
                              config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet

        # lightning initialization
        self.assertTrue(wallet.db.get('lightning_xprv').startswith('zprv'))

        wallet.check_password(password)
        self.assertEqual(passphrase, wallet.keystore.get_passphrase(password))
        self.assertEqual(d['seed'], wallet.keystore.get_seed(password))
        self.assertEqual(encrypt_file, wallet.storage.is_encrypted())

    async def test_restore_wallet_from_text_mnemonic(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        passphrase = 'mypassphrase'
        password = 'mypassword'
        encrypt_file = True
        d = restore_wallet_from_text__for_unittest(
            text,
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
        self.assertEqual('bc1q2ccr34wzep58d4239tl3x3734ttle92a8srmuw', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_no_storage(self):
        text = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
        d = restore_wallet_from_text__for_unittest(
            text,
            path=None,
            gap_limit=1,
            config=self.config,
        )
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(None, wallet.storage)
        self.assertEqual(text, wallet.keystore.get_seed(None))
        self.assertEqual('bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_xpub(self):
        text = 'zpub6nydoME6CFdJtMpzHW5BNoPz6i6XbeT9qfz72wsRqGdgGEYeivso6xjfw8cGcCyHwF7BNW4LDuHF35XrZsovBLWMF4qXSjmhTXYiHbWqGLt'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet_path, gap_limit=1, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(text, wallet.keystore.get_master_public_key())
        self.assertEqual('bc1q2ccr34wzep58d4239tl3x3734ttle92a8srmuw', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_xkey_that_is_also_a_valid_electrum_seed_by_chance(self):
        text = 'yprvAJBpuoF4FKpK92ofzQ7ge6VJMtorow3maAGPvPGj38ggr2xd1xCrC9ojUVEf9jhW5L9SPu6fU2U3o64cLrRQ83zaQGNa6YP3ajZS6hHNPXj'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet_path, gap_limit=1, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(text, wallet.keystore.get_master_private_key(password=None))
        self.assertEqual('3Pa4hfP3LFWqa2nfphYaF7PZfdJYNusAnp', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_xprv(self):
        text = 'zprvAZzHPqhCMt51fskXBUYB1fTFYgG3CBjJUT4WEZTpGw6hPSDWBPZYZARC5sE9xAcX8NeWvvucFws8vZxEa65RosKAhy7r5MsmKTxr3hmNmea'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet_path, gap_limit=1, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet
        self.assertEqual(text, wallet.keystore.get_master_private_key(password=None))
        self.assertEqual('bc1q2ccr34wzep58d4239tl3x3734ttle92a8srmuw', wallet.get_receiving_addresses()[0])

    async def test_restore_wallet_from_text_addresses(self):
        text = 'bc1q2ccr34wzep58d4239tl3x3734ttle92a8srmuw bc1qnp78h78vp92pwdwq5xvh8eprlga5q8gu66960c'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet_path, config=self.config)
        wallet = d['wallet']  # type: Imported_Wallet
        self.assertEqual('bc1q2ccr34wzep58d4239tl3x3734ttle92a8srmuw', wallet.get_receiving_addresses()[0])
        self.assertEqual(2, len(wallet.get_receiving_addresses()))
        # also test addr deletion
        wallet.delete_address('bc1qnp78h78vp92pwdwq5xvh8eprlga5q8gu66960c')
        self.assertEqual(1, len(wallet.get_receiving_addresses()))

    async def test_restore_wallet_from_text_privkeys(self):
        text = 'p2wpkh:L4jkdiXszG26SUYvwwJhzGwg37H2nLhrbip7u6crmgNeJysv5FHL p2wpkh:L24GxnN7NNUAfCXA6hFzB1jt59fYAAiFZMcLaJ2ZSawGpM3uqhb1'
        d = restore_wallet_from_text__for_unittest(text, path=self.wallet_path, config=self.config)
        wallet = d['wallet']  # type: Imported_Wallet
        addr0 = wallet.get_receiving_addresses()[0]
        self.assertEqual('bc1q2ccr34wzep58d4239tl3x3734ttle92a8srmuw', addr0)
        self.assertEqual('p2wpkh:L4jkdiXszG26SUYvwwJhzGwg37H2nLhrbip7u6crmgNeJysv5FHL',
                         wallet.export_private_key(addr0, password=None))
        self.assertEqual(2, len(wallet.get_receiving_addresses()))
        # also test addr deletion
        wallet.delete_address('bc1qnp78h78vp92pwdwq5xvh8eprlga5q8gu66960c')
        self.assertEqual(1, len(wallet.get_receiving_addresses()))


class TestWalletPassword(WalletTestCase):

    async def test_update_password_of_imported_wallet(self):
        wallet_str = '{"addr_history":{"1364Js2VG66BwRdkaoxAaFtdPb1eQgn8Dr":[],"15CyDgLffJsJgQrhcyooFH4gnVDG82pUrA":[],"1Exet2BhHsFxKTwhnfdsBMkPYLGvobxuW6":[]},"addresses":{"change":[],"receiving":["1364Js2VG66BwRdkaoxAaFtdPb1eQgn8Dr","1Exet2BhHsFxKTwhnfdsBMkPYLGvobxuW6","15CyDgLffJsJgQrhcyooFH4gnVDG82pUrA"]},"keystore":{"keypairs":{"0344b1588589958b0bcab03435061539e9bcf54677c104904044e4f8901f4ebdf5":"L2sED74axVXC4H8szBJ4rQJrkfem7UMc6usLCPUoEWxDCFGUaGUM","0389508c13999d08ffae0f434a085f4185922d64765c0bff2f66e36ad7f745cc5f":"L3Gi6EQLvYw8gEEUckmqawkevfj9s8hxoQDFveQJGZHTfyWnbk1U","04575f52b82f159fa649d2a4c353eb7435f30206f0a6cb9674fbd659f45082c37d559ffd19bea9c0d3b7dcc07a7b79f4cffb76026d5d4dff35341efe99056e22d2":"5JyVyXU1LiRXATvRTQvR9Kp8Rx1X84j2x49iGkjSsXipydtByUq"},"type":"imported"},"pruned_txo":{},"seed_version":13,"stored_height":-1,"transactions":{},"tx_fees":{},"txi":{},"txo":{},"use_encryption":false,"verified_tx3":{},"wallet_type":"standard","winpos-qt":[100,100,840,405]}'
        storage = WalletStorage(self.wallet_path)
        json_db = JsonDB(wallet_str, storage=storage)
        db = WalletDB(json_db.get_stored_dict())
        wallet = Wallet(db, config=self.config)

        wallet.check_password(None)

        wallet.update_password(None, "1234")

        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")

    async def test_update_password_of_standard_wallet(self):
        wallet_str = '''{"addr_history":{"12ECgkzK6gHouKAZ7QiooYBuk1CgJLJxes":[],"12iR43FPb5M7sw4Mcrr5y1nHKepg9EtZP1":[],"13HT1pfWctsSXVFzF76uYuVdQvcAQ2MAgB":[],"13kG9WH9JqS7hyCcVL1ssLdNv4aXocQY9c":[],"14Tf3qiiHJXStSU4KmienAhHfHq7FHpBpz":[],"14gmBxYV97mzYwWdJSJ3MTLbTHVegaKrcA":[],"15FGuHvRssu1r8fCw98vrbpfc3M4xs5FAV":[],"17oJzweA2gn6SDjsKgA9vUD5ocT1sSnr2Z":[],"18hNcSjZzRcRP6J2bfFRxp9UfpMoC4hGTv":[],"18n9PFxBjmKCGhd4PCDEEqYsi2CsnEfn2B":[],"19a98ZfEezDNbCwidVigV5PAJwrR2kw4Jz":[],"19z3j2ELqbg2pR87byCCt3BCyKR7rc3q8G":[],"1A3XSmvLQvePmvm7yctsGkBMX9ZKKXLrVq":[],"1CmhFe2BN1h9jheFpJf4v39XNPj8F9U6d":[],"1DuphhHUayKzbkdvjVjf5dtjn2ACkz4zEs":[],"1E4ygSNJpWL2uPXZHBptmU2LqwZTqb1Ado":[],"1GTDSjkVc9vaaBBBGNVqTANHJBcoT5VW9z":[],"1GWqgpThAuSq3tDg6uCoLQxPXQNnU8jZ52":[],"1GhmpwqSF5cqNgdr9oJMZx8dKxPRo4pYPP":[],"1J5TTUQKhwehEACw6Jjte1E22FVrbeDmpv":[],"1JWySzjzJhsETUUcqVZHuvQLA7pfFfmesb":[],"1KQHxcy3QUHAWMHKUtJjqD9cMKXcY2RTwZ":[],"1KoxZfc2KsgovjGDxwqanbFEA76uxgYH4G":[],"1KqVEPXdpbYvEbwsZcEKkrA4A2jsgj9hYN":[],"1N16yDSYe76c5A3CoVoWAKxHeAUc8Jhf9J":[],"1Pm8JBhzUJDqeQQKrmnop1Frr4phe1jbTt":[]},"addresses":{"change":["1GhmpwqSF5cqNgdr9oJMZx8dKxPRo4pYPP","1GTDSjkVc9vaaBBBGNVqTANHJBcoT5VW9z","15FGuHvRssu1r8fCw98vrbpfc3M4xs5FAV","1A3XSmvLQvePmvm7yctsGkBMX9ZKKXLrVq","19z3j2ELqbg2pR87byCCt3BCyKR7rc3q8G","1JWySzjzJhsETUUcqVZHuvQLA7pfFfmesb"],"receiving":["14gmBxYV97mzYwWdJSJ3MTLbTHVegaKrcA","13HT1pfWctsSXVFzF76uYuVdQvcAQ2MAgB","19a98ZfEezDNbCwidVigV5PAJwrR2kw4Jz","1J5TTUQKhwehEACw6Jjte1E22FVrbeDmpv","1Pm8JBhzUJDqeQQKrmnop1Frr4phe1jbTt","13kG9WH9JqS7hyCcVL1ssLdNv4aXocQY9c","1KQHxcy3QUHAWMHKUtJjqD9cMKXcY2RTwZ","12ECgkzK6gHouKAZ7QiooYBuk1CgJLJxes","12iR43FPb5M7sw4Mcrr5y1nHKepg9EtZP1","14Tf3qiiHJXStSU4KmienAhHfHq7FHpBpz","1KqVEPXdpbYvEbwsZcEKkrA4A2jsgj9hYN","17oJzweA2gn6SDjsKgA9vUD5ocT1sSnr2Z","1E4ygSNJpWL2uPXZHBptmU2LqwZTqb1Ado","18hNcSjZzRcRP6J2bfFRxp9UfpMoC4hGTv","1KoxZfc2KsgovjGDxwqanbFEA76uxgYH4G","18n9PFxBjmKCGhd4PCDEEqYsi2CsnEfn2B","1CmhFe2BN1h9jheFpJf4v39XNPj8F9U6d","1DuphhHUayKzbkdvjVjf5dtjn2ACkz4zEs","1GWqgpThAuSq3tDg6uCoLQxPXQNnU8jZ52","1N16yDSYe76c5A3CoVoWAKxHeAUc8Jhf9J"]},"keystore":{"seed":"cereal wise two govern top pet frog nut rule sketch bundle logic","type":"bip32","xprv":"xprv9s21ZrQH143K29XjRjUs6MnDB9wXjXbJP2kG1fnRk8zjdDYWqVkQYUqaDtgZp5zPSrH5PZQJs8sU25HrUgT1WdgsPU8GbifKurtMYg37d4v","xpub":"xpub661MyMwAqRbcEdcCXm1sTViwjBn28zK9kFfrp4C3JUXiW1sfP34f6HA45B9yr7EH5XGzWuTfMTdqpt9XPrVQVUdgiYb5NW9m8ij1FSZgGBF"},"pruned_txo":{},"seed_type":"standard","seed_version":13,"stored_height":-1,"transactions":{},"tx_fees":{},"txi":{},"txo":{},"use_encryption":false,"verified_tx3":{},"wallet_type":"standard","winpos-qt":[619,310,840,405]}'''
        storage = WalletStorage(self.wallet_path)
        json_db = JsonDB(wallet_str, storage=storage)
        db = WalletDB(json_db.get_stored_dict())
        wallet = Wallet(db, config=self.config)

        wallet.check_password(None)

        wallet.update_password(None, "1234")
        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")

    async def test_update_password_of_standard_wallet_oldseed(self):
        d = restore_wallet_from_text__for_unittest(
            "powerful random nobody notice nothing important anyway look away hidden message over", path=self.wallet_path, config=self.config)
        wallet = d['wallet']  # type: Standard_Wallet

        wallet.check_password(None)

        wallet.update_password(None, "1234")
        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")

    async def test_update_password_with_app_restarts(self):
        wallet_str = '{"addr_history":{"1364Js2VG66BwRdkaoxAaFtdPb1eQgn8Dr":[],"15CyDgLffJsJgQrhcyooFH4gnVDG82pUrA":[],"1Exet2BhHsFxKTwhnfdsBMkPYLGvobxuW6":[]},"addresses":{"change":[],"receiving":["1364Js2VG66BwRdkaoxAaFtdPb1eQgn8Dr","1Exet2BhHsFxKTwhnfdsBMkPYLGvobxuW6","15CyDgLffJsJgQrhcyooFH4gnVDG82pUrA"]},"keystore":{"keypairs":{"0344b1588589958b0bcab03435061539e9bcf54677c104904044e4f8901f4ebdf5":"L2sED74axVXC4H8szBJ4rQJrkfem7UMc6usLCPUoEWxDCFGUaGUM","0389508c13999d08ffae0f434a085f4185922d64765c0bff2f66e36ad7f745cc5f":"L3Gi6EQLvYw8gEEUckmqawkevfj9s8hxoQDFveQJGZHTfyWnbk1U","04575f52b82f159fa649d2a4c353eb7435f30206f0a6cb9674fbd659f45082c37d559ffd19bea9c0d3b7dcc07a7b79f4cffb76026d5d4dff35341efe99056e22d2":"5JyVyXU1LiRXATvRTQvR9Kp8Rx1X84j2x49iGkjSsXipydtByUq"},"type":"imported"},"pruned_txo":{},"seed_version":13,"stored_height":-1,"transactions":{},"tx_fees":{},"txi":{},"txo":{},"use_encryption":false,"verified_tx3":{},"wallet_type":"standard","winpos-qt":[100,100,840,405]}'
        storage = WalletStorage(self.wallet_path)
        json_db = JsonDB(wallet_str, storage=storage)
        db = WalletDB(json_db.get_stored_dict())
        wallet = Wallet(db, config=self.config)
        await wallet.stop()

        storage = WalletStorage(self.wallet_path)
        # if storage.is_encrypted():
        #     storage.decrypt(password)
        json_db = JsonDB(wallet_str, storage=storage)
        db = WalletDB(json_db.get_stored_dict())
        wallet = Wallet(db, config=self.config)

        wallet.check_password(None)

        wallet.update_password(None, "1234")
        with self.assertRaises(InvalidPassword):
            wallet.check_password(None)
        with self.assertRaises(InvalidPassword):
            wallet.check_password("wrong password")
        wallet.check_password("1234")
