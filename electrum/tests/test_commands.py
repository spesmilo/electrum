import unittest
from unittest import mock
from decimal import Decimal

from electrum.commands import Commands, eval_bool
from electrum import storage, wallet
from electrum.wallet import restore_wallet_from_text
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.simple_config import SimpleConfig
from electrum.transaction import Transaction, TxOutput, tx_from_any

from . import ElectrumTestCase
from .test_wallet_vertical import WalletIntegrityHelper


class TestCommands(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def test_setconfig_non_auth_number(self):
        self.assertEqual(7777, Commands._setconfig_normalize_value('rpcport', "7777"))
        self.assertEqual(7777, Commands._setconfig_normalize_value('rpcport', '7777'))
        self.assertAlmostEqual(Decimal(2.3), Commands._setconfig_normalize_value('somekey', '2.3'))

    def test_setconfig_non_auth_number_as_string(self):
        self.assertEqual("7777", Commands._setconfig_normalize_value('somekey', "'7777'"))

    def test_setconfig_non_auth_boolean(self):
        self.assertEqual(True, Commands._setconfig_normalize_value('show_console_tab', "true"))
        self.assertEqual(True, Commands._setconfig_normalize_value('show_console_tab', "True"))

    def test_setconfig_non_auth_list(self):
        self.assertEqual(['file:///var/www/', 'https://electrum.org'],
            Commands._setconfig_normalize_value('url_rewrite', "['file:///var/www/','https://electrum.org']"))
        self.assertEqual(['file:///var/www/', 'https://electrum.org'],
            Commands._setconfig_normalize_value('url_rewrite', '["file:///var/www/","https://electrum.org"]'))

    def test_setconfig_auth(self):
        self.assertEqual("7777", Commands._setconfig_normalize_value('rpcuser', "7777"))
        self.assertEqual("7777", Commands._setconfig_normalize_value('rpcuser', '7777'))
        self.assertEqual("7777", Commands._setconfig_normalize_value('rpcpassword', '7777'))
        self.assertEqual("2asd", Commands._setconfig_normalize_value('rpcpassword', '2asd'))
        self.assertEqual("['file:///var/www/','https://electrum.org']",
            Commands._setconfig_normalize_value('rpcpassword', "['file:///var/www/','https://electrum.org']"))

    def test_eval_bool(self):
        self.assertFalse(eval_bool("False"))
        self.assertFalse(eval_bool("false"))
        self.assertFalse(eval_bool("0"))
        self.assertTrue(eval_bool("True"))
        self.assertTrue(eval_bool("true"))
        self.assertTrue(eval_bool("1"))

    async def test_convert_xkey(self):
        cmds = Commands(config=self.config)
        xpubs = {
            ("xpub6CCWFbvCbqF92kGwm9nV7t7RvVoQUKaq5USMdyVP6jvv1NgN52KAX6NNYCeE8Ca7JQC4K5tZcnQrubQcjJ6iixfPs4pwAQJAQgTt6hBjg11", "standard"),
            ("ypub6X2mZGb7kWnct3U4bWa7KyCw6TwrQwaKzaxaRNPGUkJo4UVbKgUj9A2WZQbp87E2i3Js4ZV85SmQnt2BSzWjXCLzjQXMkK7egQXXVHT4eKn", "p2wpkh-p2sh"),
            ("zpub6qs2rwG2uCL6jLfBRsMjY4JSGS6JMZZpuhUoCmH9rkgg7aJpaLeHmDgeacZQ81sx7gRfp35gY77xgAdkAgvkKS2bbkDnLDw8x8bAsuKBrvP", "p2wpkh"),
        }
        for xkey1, xtype1 in xpubs:
            for xkey2, xtype2 in xpubs:
                self.assertEqual(xkey2, await cmds.convert_xkey(xkey1, xtype2))

        xprvs = {
            ("xprv9yD9r6PJmTgqpGCUf8FUkkAhNTxv4rryiFWkqb5mYQPw8aMDXUzuyJ3tgv5vUqYkdK1E6Q5jKxPss4HkMBYV4q8AfG8t7rxgyS4xQX4ndAm", "standard"),
            ("yprvAJ3R9m4Dv9EKfZPbVV36xqGCYS7N1UrUdN2ycyyevQmpBgASn9AUbMi2i83WUkCg2x82qsgHnckRkLuK4sxVs4omXbqJhmnBFA8bo8ssinK", "p2wpkh-p2sh"),
            ("zprvAcsgTRj94pmoWraiKqpjAvMhiQFox6qyYUZCQNsYJR9hEmyg2oL3DRNAjL16UerbSbEqbMGrFH6yddWsnaNWfJVNPwXjHgbfWtCFBgDxFkX", "p2wpkh"),
        }
        for xkey1, xtype1 in xprvs:
            for xkey2, xtype2 in xprvs:
                self.assertEqual(xkey2, await cmds.convert_xkey(xkey1, xtype2))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_encrypt_decrypt(self, mock_save_db):
        wallet = restore_wallet_from_text('p2wpkh:L4rYY5QpfN6wJEF4SEKDpcGhTPnCe9zcGs6hiSnhpprZqVywFifN',
                                          path='if_this_exists_mocking_failed_648151893',
                                          config=self.config)['wallet']
        cmds = Commands(config=self.config)
        cleartext = "asdasd this is the message"
        pubkey = "021f110909ded653828a254515b58498a6bafc96799fb0851554463ed44ca7d9da"
        ciphertext = await cmds.encrypt(pubkey, cleartext)
        self.assertEqual(cleartext, await cmds.decrypt(pubkey, ciphertext, wallet=wallet))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_export_private_key_imported(self, mock_save_db):
        wallet = restore_wallet_from_text('p2wpkh:L4rYY5QpfN6wJEF4SEKDpcGhTPnCe9zcGs6hiSnhpprZqVywFifN p2wpkh:L4jkdiXszG26SUYvwwJhzGwg37H2nLhrbip7u6crmgNeJysv5FHL',
                                          path='if_this_exists_mocking_failed_648151893',
                                          config=self.config)['wallet']
        cmds = Commands(config=self.config)
        # single address tests
        with self.assertRaises(Exception):
            await cmds.getprivatekeys("asdasd", wallet=wallet)  # invalid addr, though might raise "not in wallet"
        with self.assertRaises(Exception):
            await cmds.getprivatekeys("bc1qgfam82qk7uwh5j2xxmcd8cmklpe0zackyj6r23", wallet=wallet)  # not in wallet
        self.assertEqual("p2wpkh:L4jkdiXszG26SUYvwwJhzGwg37H2nLhrbip7u6crmgNeJysv5FHL",
                         await cmds.getprivatekeys("bc1q2ccr34wzep58d4239tl3x3734ttle92a8srmuw", wallet=wallet))
        # list of addresses tests
        with self.assertRaises(Exception):
            await cmds.getprivatekeys(['bc1q2ccr34wzep58d4239tl3x3734ttle92a8srmuw', 'asd'], wallet=wallet)
        self.assertEqual(['p2wpkh:L4jkdiXszG26SUYvwwJhzGwg37H2nLhrbip7u6crmgNeJysv5FHL', 'p2wpkh:L4rYY5QpfN6wJEF4SEKDpcGhTPnCe9zcGs6hiSnhpprZqVywFifN'],
                         await cmds.getprivatekeys(['bc1q2ccr34wzep58d4239tl3x3734ttle92a8srmuw', 'bc1q9pzjpjq4nqx5ycnywekcmycqz0wjp2nq604y2n'], wallet=wallet))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_export_private_key_deterministic(self, mock_save_db):
        wallet = restore_wallet_from_text('bitter grass shiver impose acquire brush forget axis eager alone wine silver',
                                          gap_limit=2,
                                          path='if_this_exists_mocking_failed_648151893',
                                          config=self.config)['wallet']
        cmds = Commands(config=self.config)
        # single address tests
        with self.assertRaises(Exception):
            await cmds.getprivatekeys("asdasd", wallet=wallet)  # invalid addr, though might raise "not in wallet"
        with self.assertRaises(Exception):
            await cmds.getprivatekeys("bc1qgfam82qk7uwh5j2xxmcd8cmklpe0zackyj6r23", wallet=wallet)  # not in wallet
        self.assertEqual("p2wpkh:L15oxP24NMNAXxq5r2aom24pHPtt3Fet8ZutgL155Bad93GSubM2",
                         await cmds.getprivatekeys("bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af", wallet=wallet))
        # list of addresses tests
        with self.assertRaises(Exception):
            await cmds.getprivatekeys(['bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af', 'asd'], wallet=wallet)
        self.assertEqual(['p2wpkh:L15oxP24NMNAXxq5r2aom24pHPtt3Fet8ZutgL155Bad93GSubM2', 'p2wpkh:L4rYY5QpfN6wJEF4SEKDpcGhTPnCe9zcGs6hiSnhpprZqVywFifN'],
                         await cmds.getprivatekeys(['bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af', 'bc1q9pzjpjq4nqx5ycnywekcmycqz0wjp2nq604y2n'], wallet=wallet))


class TestCommandsTestnet(ElectrumTestCase):
    TESTNET = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    async def test_convert_xkey(self):
        cmds = Commands(config=self.config)
        xpubs = {
            ("tpubD8p5qNfjczgTGbh9qgNxsbFgyhv8GgfVkmp3L88qtRm5ibUYiDVCrn6WYfnGey5XVVw6Bc5QNQUZW5B4jFQsHjmaenvkFUgWtKtgj5AdPm9", "standard"),
            ("upub59wfQ8qJTg6ZSuvwtR313Qdp8gP8TSBwTof5dPQ3QVsYp1N9t29Rr9TGF1pj8kAXUg3mKbmrTKasA2qmBJKb1bGUzB6ApDZpVC7LoHhyvBo", "p2wpkh-p2sh"),
            ("vpub5UmvhoWDcMe3JD84impdFVjKJeXaQ4BSNvBJQnHvnWFRs7BP8gJzUD7QGDnK8epStKAa55NQuywR3KTKtzjbopx5rWnbQ8PJkvAzBtgaGBc", "p2wpkh"),
        }
        for xkey1, xtype1 in xpubs:
            for xkey2, xtype2 in xpubs:
                self.assertEqual(xkey2, await cmds.convert_xkey(xkey1, xtype2))

        xprvs = {
            ("tprv8c83gxdVUcznP8fMx2iNUBbaQgQC7MUbBUDG3c6YU9xgt7Dn5pfcgHUeNZTAvuYmNgVHjyTzYzGWwJr7GvKCm2FkPaaJipyipbfJeB3tdPW", "standard"),
            ("uprv8vxJzdJQdJYGERrUnPVzgGh5aeYe3yU66ajUpzzRrALZwD31LUqBJM8nPmQkvpCgnKc6VT4Z1ed4pbTfzcjDZFwMFvGjJjoD6Kix2pCwVe7", "p2wpkh-p2sh"),
            ("vprv9FnaJHyKmz5k5j3bckHctMnakch5zbTb1hFhcPtKEAiSzJrEb8zjvQnvQyNLvircBxiuEvf7UJycht5EiK9EMVcx8Fy9techN3nbRQRFhEv", "p2wpkh"),
        }
        for xkey1, xtype1 in xprvs:
            for xkey2, xtype2 in xprvs:
                self.assertEqual(xkey2, await cmds.convert_xkey(xkey1, xtype2))

    async def test_serialize(self):
        cmds = Commands(config=self.config)
        jsontx = {
            "inputs": [
                {
                    "prevout_hash": "9d221a69ca3997cbeaf5624d723e7dc5f829b1023078c177d37bdae95f37c539",
                    "prevout_n": 1,
                    "value_sats": 1000000,
                    "privkey": "p2wpkh:cVDXzzQg6RoCTfiKpe8MBvmm5d5cJc6JLuFApsFDKwWa6F5TVHpD"
                }
            ],
            "outputs": [
                {
                    "address": "tb1q4s8z6g5jqzllkgt8a4har94wl8tg0k9m8kv5zd",
                    "value_sats": 990000
                }
            ]
        }
        self.assertEqual("0200000000010139c5375fe9da7bd377c1783002b129f8c57d3e724d62f5eacb9739ca691a229d0100000000feffffff01301b0f0000000000160014ac0e2d229200bffb2167ed6fd196aef9d687d8bb0247304402206367fb2ddd723985f5f51e0f2435084c0a66f5c26f4403a75d3dd417b71a20450220545dc3637bcb49beedbbdf5063e05cad63be91af4f839886451c30ecd6edf1d20121021f110909ded653828a254515b58498a6bafc96799fb0851554463ed44ca7d9da00000000",
                         await cmds.serialize(jsontx))

    async def test_serialize_custom_nsequence(self):
        cmds = Commands(config=self.config)
        jsontx = {
            "inputs": [
                {
                    "prevout_hash": "9d221a69ca3997cbeaf5624d723e7dc5f829b1023078c177d37bdae95f37c539",
                    "prevout_n": 1,
                    "value_sats": 1000000,
                    "privkey": "p2wpkh:cVDXzzQg6RoCTfiKpe8MBvmm5d5cJc6JLuFApsFDKwWa6F5TVHpD",
                    "nsequence": 0xfffffffd
                }
            ],
            "outputs": [
                {
                    "address": "tb1q4s8z6g5jqzllkgt8a4har94wl8tg0k9m8kv5zd",
                    "value_sats": 990000
                }
            ]
        }
        self.assertEqual("0200000000010139c5375fe9da7bd377c1783002b129f8c57d3e724d62f5eacb9739ca691a229d0100000000fdffffff01301b0f0000000000160014ac0e2d229200bffb2167ed6fd196aef9d687d8bb0247304402201c551df0458528d19ba1dd79b134dcf0055f7b029dfc3d0d024e6253d069d13e02206d03cfc85a6fc648acb6fc6be630e4567d1dd00ddbcdee551ee0711414e2f33f0121021f110909ded653828a254515b58498a6bafc96799fb0851554463ed44ca7d9da00000000",
                         await cmds.serialize(jsontx))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_getprivatekeyforpath(self, mock_save_db):
        wallet = restore_wallet_from_text('north rent dawn bunker hamster invest wagon market romance pig either squeeze',
                                          gap_limit=2,
                                          path='if_this_exists_mocking_failed_648151893',
                                          config=self.config)['wallet']
        cmds = Commands(config=self.config)
        self.assertEqual("p2wpkh:cUzm7zPpWgLYeURgff4EsoMjhskCpsviBH4Y3aZcrBX8UJSRPjC2",
                         await cmds.getprivatekeyforpath([0, 10000], wallet=wallet))
        self.assertEqual("p2wpkh:cUzm7zPpWgLYeURgff4EsoMjhskCpsviBH4Y3aZcrBX8UJSRPjC2",
                         await cmds.getprivatekeyforpath("m/0/10000", wallet=wallet))
        self.assertEqual("p2wpkh:cQAj4WGf1socCPCJNMjXYCJ8Bs5JUAk5pbDr4ris44QdgAXcV24S",
                         await cmds.getprivatekeyforpath("m/5h/100000/88h/7", wallet=wallet))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_payto(self, mock_save_db):
        wallet = restore_wallet_from_text('disagree rug lemon bean unaware square alone beach tennis exhibit fix mimic',
                                          gap_limit=2,
                                          path='if_this_exists_mocking_failed_648151893',
                                          config=self.config)['wallet']
        # bootstrap wallet
        funding_tx = Transaction('0200000000010165806607dd458280cb57bf64a16cf4be85d053145227b98c28932e953076b8e20000000000fdffffff02ac150700000000001600147e3ddfe6232e448a8390f3073c7a3b2044fd17eb102908000000000016001427fbe3707bc57e5bb63d6f15733ec88626d8188a02473044022049ce9efbab88808720aa563e2d9bc40226389ab459c4390ea3e89465665d593502206c1c7c30a2f640af1e463e5107ee4cfc0ee22664cfae3f2606a95303b54cdef80121026269e54d06f7070c1f967eb2874ba60de550dfc327a945c98eb773672d9411fd77181e00')
        funding_txid = funding_tx.txid()
        self.assertEqual('ede61d39e501d65ccf34e6300da439419c43393f793bb9a8a4b06b2d0d80a8a0', funding_txid)
        wallet.adb.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        cmds = Commands(config=self.config)
        tx_str = await cmds.payto(
            destination="tb1qsyzgpwa0vg2940u5t6l97etuvedr5dejpf9tdy",
            amount="0.00123456",
            feerate=50,
            locktime=1972344,
            wallet=wallet)

        tx = tx_from_any(tx_str)
        self.assertEqual(2, len(tx.outputs()))
        txout = TxOutput.from_address_and_value("tb1qsyzgpwa0vg2940u5t6l97etuvedr5dejpf9tdy", 123456)
        self.assertTrue(txout in tx.outputs())
        self.assertEqual("02000000000101a0a8800d2d6bb0a4a8b93b793f39439c4139a40d30e634cf5cd601e5391de6ed0100000000fdffffff0240e2010000000000160014810480bbaf62145abf945ebe5f657c665a3a3732462b060000000000160014a5103285eb519f826520a9f7d3227e1eaa7ec5f802473044022057a6f4b1ec63336c7d0ba233e785ec9f2e2d9c2d67617a50e069f4498ee6a3b7022032fb331e0bef06f46e9cb77bfe94413142653c4912516835e941fa7f170c1a53012103001b55f19541faaf7e6d57dd1bdb9fdc37725fc500e12f2418cc11e0aed4154978181e00",
                         tx_str)

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_paytomany_multiple_max_spends(self, mock_save_db):
        wallet = restore_wallet_from_text('kit virtual quantum festival fortune inform ladder saddle filter soldier start ghost',
                                          gap_limit=2,
                                          path='if_this_exists_mocking_failed_648151893',
                                          config=self.config)['wallet']
        # bootstrap wallet
        funding_tx = Transaction('02000000000101f59876b1c65bbe3e182ccc7ea7224fe397bb9b70aadcbbf4f4074c75c8a074840000000000fdffffff021f351f00000000001600144eec851dd980cc36af1f629a32325f511604d6af56732d000000000016001439267bc7f3e3fabeae3bc3f73880de22d8b01ba50247304402207eac5f639806a00878488d58ca651d690292145bca5511531845ae21fab309d102207162708bd344840cc1bacff1092e426eb8484f83f5c068ba4ca579813de324540121020e0798c267ff06ee8b838cd465f3cfa6c843a122a04917364ce000c29ca205cae5f31f00')
        funding_txid = funding_tx.txid()
        self.assertEqual('e8e977bd9c857d84ec1b8f154ae2ee5dfa49fffb7688942a586196c1ad15de15', funding_txid)
        wallet.adb.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        cmds = Commands(config=self.config)
        tx_str = await cmds.paytomany(
            outputs=[["tb1qk3g0t9pw5wctkzz7gh6k3ljfuukn729s67y54e", 0.002],
                     ["tb1qr7evucrllljtryam6y2k3ntmlptq208pghql2h", "2!"],
                     ["tb1qs3msqp0n0qade2haanjw2dkaa5lm77vwvce00h", 0.003],
                     ["tb1qar4ye43tdfj6y5n3yndp9adhs2wuz2v0wgqn5l", "3!"]],
            fee="0.00005000",
            locktime=2094054,
            wallet=wallet)

        tx = tx_from_any(tx_str)
        self.assertEqual(4, len(tx.outputs()))
        self.assertEqual("0200000000010115de15adc19661582a948876fbff49fa5deee24a158f1bec847d859cbd77e9e80100000000fdffffff04400d030000000000160014b450f5942ea3b0bb085e45f568fe49e72d3f28b0e09304000000000016001484770005f3783adcaafdece4e536dded3fbf798e12190f00000000001600141fb2ce607fffe4b193bbd11568cd7bf856053ce19ca5160000000000160014e8ea4cd62b6a65a2527124da12f5b7829dc1298f02473044022079570c62352d7c462ee50851d27f829f7ea5757d258b6b38a6b377a4910ba597022056653f1b15a9693ba790e89ebac60e33b7a1d8357e05cd3d7ecc1ae00e9ab4a8012102eed460ead0cbaa71ad52b70899acf4ea12682ab237207b045c5cf9c6d11c2bcfe6f31f00",
                         tx_str)

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_signtransaction_without_wallet(self, mock_save_db):
        cmds = Commands(config=self.config)
        unsigned_tx = "70736274ff0100a0020000000221d3645ba44f33fff6fe2666dc080279bc34b531c66888729712a80b204a32a10100000000fdffffffdd7f90d51acf98dc45ad7489316a983868c75e16bf14ffeb9eae01603a7b4da40100000000fdffffff02e8030000000000001976a9149a9ec2b35a7660c80dae38dd806fdf9b0fde68fd88ac74c11000000000001976a914f0dc093f7fb1b76cfd06610d5359d6595676cc2b88aca79b1d00000100e102000000018ba8cf9f0ff0b44c389e4a1cd25c0770636d95ccef161e313542647d435a5fd0000000006a4730440220373b3989905177f2e36d7e3d02b967d03092747fe7bbd3ba7b2c24623a88538c02207be79ee1d981060c2be6783f4946ce1bda1f64671b349ef14a4a6fecc047a71e0121030de43c5ed4c6272d20ce3becf3fb7afd5c3ccfb5d58ddfdf3047981e0b005e0dfdffffff02c0010700000000001976a9141cd3eb65bce2cae9f54544b65e46b3ad1f0b187288ac40420f00000000001976a914f0dc093f7fb1b76cfd06610d5359d6595676cc2b88ac979b1d00000100e102000000014e39236158716e91b0b2170ebe9d6b359d139e9ebfff163f2bafd0bec9890d04000000006a473044022070340deb95ca25ef86c4c7a9539b5c8f7b8351941635450311f914cd9c2f45ea02203fa7576e032ab5ae4763c78f5c2124573213c956286fd766582d9462515dc6540121033f6737e40a3a6087bc58bc5b82b427f9ed26d710b8fe2f70bfdd3d62abebcf74fdffffff02e8030000000000001976a91490350959750b3b38e451df16bd5957b7649bf5d288acac840100000000001976a914f0dc093f7fb1b76cfd06610d5359d6595676cc2b88ac979b1d00000000"
        privkey = "cVtE728tULSA4gut4QWxo218q6PRsXHQAv84SXix83cuvScvGd1H"
        self.assertEqual("020000000221d3645ba44f33fff6fe2666dc080279bc34b531c66888729712a80b204a32a1010000006a47304402205b30e188e30c846f98dacc714c16b7cd3a58a3fa24973d289683c9d32813e24c0220153855a29e96fb083084417ba3e3873ccaeb08435dad93773ab60716f94a36160121033f6737e40a3a6087bc58bc5b82b427f9ed26d710b8fe2f70bfdd3d62abebcf74fdffffffdd7f90d51acf98dc45ad7489316a983868c75e16bf14ffeb9eae01603a7b4da4010000006a473044022010daa3dadf53bdcb071c6eff6b8787e3f675ed61feb4fef72d0bf9d99c0162f802200e73abd880b6f2ee5fe8c0abab731f1dddeb0f60df5e050a79c365bd718da1c80121033f6737e40a3a6087bc58bc5b82b427f9ed26d710b8fe2f70bfdd3d62abebcf74fdffffff02e8030000000000001976a9149a9ec2b35a7660c80dae38dd806fdf9b0fde68fd88ac74c11000000000001976a914f0dc093f7fb1b76cfd06610d5359d6595676cc2b88aca79b1d00",
                         await cmds.signtransaction_with_privkey(tx=unsigned_tx, privkey=privkey))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_signtransaction_with_wallet(self, mock_save_db):
        wallet = restore_wallet_from_text('bitter grass shiver impose acquire brush forget axis eager alone wine silver',
                                          gap_limit=2,
                                          path='if_this_exists_mocking_failed_648151893',
                                          config=self.config)['wallet']

        # bootstrap wallet1
        funding_tx = Transaction('01000000014576dacce264c24d81887642b726f5d64aa7825b21b350c7b75a57f337da6845010000006b483045022100a3f8b6155c71a98ad9986edd6161b20d24fad99b6463c23b463856c0ee54826d02200f606017fd987696ebbe5200daedde922eee264325a184d5bbda965ba5160821012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609ffffffff0240420f00000000001600148a28bddb7f61864bdcf58b2ad13d5aeb3abc3c42a2ddb90e000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000')
        funding_txid = funding_tx.txid()
        funding_output_value = 1000000
        self.assertEqual('add2535aedcbb5ba79cc2260868bb9e57f328738ca192937f2c92e0e94c19203', funding_txid)
        wallet.adb.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        cmds = Commands(config=self.config)

        unsigned_tx = "cHNidP8BAHECAAAAAQOSwZQOLsnyNykZyjiHMn/luYuGYCLMebq1y+1aU9KtAAAAAAD+////AigjAAAAAAAAFgAUaQtZqBQGAvsjzCkE7OnMTa82EFIwGw8AAAAAABYAFKwOLSKSAL/7IWftb9GWrvnWh9i7AAAAAAABAN8BAAAAAUV22sziZMJNgYh2Qrcm9dZKp4JbIbNQx7daV/M32mhFAQAAAGtIMEUCIQCj+LYVXHGpitmYbt1hYbINJPrZm2RjwjtGOFbA7lSCbQIgD2BgF/2YdpbrvlIA2u3eki7uJkMloYTVu9qWW6UWCCEBIQLlxHPAUdrjEEPDNSZtDvicHaqy802IXMdwayZ/MmnGCf////8CQEIPAAAAAAAWABSKKL3bf2GGS9z1iyrRPVrrOrw8QqLduQ4AAAAAGXapFMOElQNCy2+N9VF1tIWGg4sDEw+tiKwAAAAAIgYDD67ptKJbfbggI8qYkZJxLN1MtT09kzhZHHkJ5YGuHAwQsuNafQAAAIAAAAAAAAAAAAAiAgKFhOeJ459BORsvJ4UsoYq+wGpUEcIb41D+1h7scSDeUxCy41p9AAAAgAEAAAAAAAAAAAA="

        self.assertEqual("020000000001010392c1940e2ec9f2372919ca3887327fe5b98b866022cc79bab5cbed5a53d2ad0000000000feffffff022823000000000000160014690b59a8140602fb23cc2904ece9cc4daf361052301b0f0000000000160014ac0e2d229200bffb2167ed6fd196aef9d687d8bb02473044022027e1e37172e52b2d84106663cff5bcf6e447dcb41f6483f99584cfb4de2785f4022005c72f6324ad130c78fca43fe5fc565526d1723f2c9dc3efea78f66d7ae9d4360121030faee9b4a25b7db82023ca989192712cdd4cb53d3d9338591c7909e581ae1c0c00000000",
                         await cmds.signtransaction(tx=unsigned_tx, wallet=wallet))

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_bumpfee(self, mock_save_db):
        wallet = restore_wallet_from_text('right nominee cheese afford exotic pilot mask illness rug fringe degree pottery',
                                          gap_limit=2,
                                          path='if_this_exists_mocking_failed_648151893',
                                          config=self.config)['wallet']

        funding_tx = Transaction("02000000000102789e8aa8caa79d87241ff9df0e3fd757a07c85a30195d76e8efced1d57c56b670000000000fdffffff7ee2b6abd52b332f797718ae582f8d3b979b83b1799e0a3bfb2c90c6e070c29e0100000000fdffffff020820000000000000160014c0eb720c93a61615d2d66542d381be8943ca553950c3000000000000160014d7dbd0196a2cbd76420f14a19377096cf6cddb75024730440220485b491ad8d3ce3b4da034a851882da84a06ec9800edff0d3fd6aa42eeba3b440220359ea85d32a05932ac417125e133fa54e54e7e9cd20ebc54b883576b8603fd65012103860f1fbf8a482b9d35d7d4d04be8fb33d856a514117cd8b73e372d36895feec60247304402206c2ca56cc030853fa59b4b3cb293f69a3378ead0f10cb76f640f8c2888773461022079b7055d0f6af6952a48e5b97218015b0723462d667765c142b41bd35e3d9c0a01210359e303f57647094a668d69e8ff0bd46c356d00aa7da6dc533c438e71c057f0793e721f00")
        funding_txid = funding_tx.txid()
        wallet.adb.receive_tx_callback(funding_txid, funding_tx, TX_HEIGHT_UNCONFIRMED)

        cmds = Commands(config=self.config)
        tx = "02000000000101b9723dfc69af058ef6613539a000d2cd098a2c8a74e802b6d8739db708ba8c9a0100000000fdffffff02a00f00000000000016001429e1fd187f0cac845946ae1b11dc136c536bfc0fe8b2000000000000160014100611bcb3aee7aad176936cf4ed56ade03027aa02473044022063c05e2347f16251922830ccc757231247b3c2970c225f988e9204844a1ab7b802204652d2c4816707e3d3bea2609b83b079001a435bad2a99cc2e730f276d07070c012102ee3f00141178006c78b0b458aab21588388335078c655459afe544211f15aee050721f00"
        self.assertEqual("02000000000101b9723dfc69af058ef6613539a000d2cd098a2c8a74e802b6d8739db708ba8c9a0100000000fdffffff02a00f00000000000016001429e1fd187f0cac845946ae1b11dc136c536bfc0f84b2000000000000160014100611bcb3aee7aad176936cf4ed56ade03027aa0247304402203aa63539b673a3bd70a76482b17f35f8843974fab28f84143a00450789010bc40220779c2ce2d0217f973f1f6c9f718e19fc7ebd14dd8821a962f002437cda3082ec012102ee3f00141178006c78b0b458aab21588388335078c655459afe544211f15aee000000000",
                         await cmds.bumpfee(tx=tx, new_fee_rate='1.6', wallet=wallet))

        self.assertEqual("02000000000101b9723dfc69af058ef6613539a000d2cd098a2c8a74e802b6d8739db708ba8c9a0100000000fdffffff02a00f00000000000016001429e1fd187f0cac845946ae1b11dc136c536bfc0f84b2000000000000160014100611bcb3aee7aad176936cf4ed56ade03027aa0247304402203aa63539b673a3bd70a76482b17f35f8843974fab28f84143a00450789010bc40220779c2ce2d0217f973f1f6c9f718e19fc7ebd14dd8821a962f002437cda3082ec012102ee3f00141178006c78b0b458aab21588388335078c655459afe544211f15aee000000000",
                         await cmds.bumpfee(tx=tx, new_fee_rate='1.6', from_coins="9a8cba08b79d73d8b602e8748a2c8a09cdd200a0393561f68e05af69fc3d72b9:1", wallet=wallet))
