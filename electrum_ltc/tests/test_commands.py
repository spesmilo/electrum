import unittest
from unittest import mock
from decimal import Decimal

from electrum_ltc.commands import Commands, eval_bool
from electrum_ltc import storage
from electrum_ltc.wallet import restore_wallet_from_text

from . import TestCaseForTestnet


class TestCommands(unittest.TestCase):

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

    def test_convert_xkey(self):
        cmds = Commands(config=None, wallet=None, network=None)
        xpubs = {
            ("xpub6CCWFbvCbqF92kGwm9nV7t7RvVoQUKaq5USMdyVP6jvv1NgN52KAX6NNYCeE8Ca7JQC4K5tZcnQrubQcjJ6iixfPs4pwAQJAQgTt6hBjg11", "standard"),
            ("ypub6X2mZGb7kWnct3U4bWa7KyCw6TwrQwaKzaxaRNPGUkJo4UVbKgUj9A2WZQbp87E2i3Js4ZV85SmQnt2BSzWjXCLzjQXMkK7egQXXVHT4eKn", "p2wpkh-p2sh"),
            ("zpub6qs2rwG2uCL6jLfBRsMjY4JSGS6JMZZpuhUoCmH9rkgg7aJpaLeHmDgeacZQ81sx7gRfp35gY77xgAdkAgvkKS2bbkDnLDw8x8bAsuKBrvP", "p2wpkh"),
        }
        for xkey1, xtype1 in xpubs:
            for xkey2, xtype2 in xpubs:
                self.assertEqual(xkey2, cmds.convert_xkey(xkey1, xtype2))

        xprvs = {
            ("xprv9yD9r6PJmTgqpGCUf8FUkkAhNTxv4rryiFWkqb5mYQPw8aMDXUzuyJ3tgv5vUqYkdK1E6Q5jKxPss4HkMBYV4q8AfG8t7rxgyS4xQX4ndAm", "standard"),
            ("yprvAJ3R9m4Dv9EKfZPbVV36xqGCYS7N1UrUdN2ycyyevQmpBgASn9AUbMi2i83WUkCg2x82qsgHnckRkLuK4sxVs4omXbqJhmnBFA8bo8ssinK", "p2wpkh-p2sh"),
            ("zprvAcsgTRj94pmoWraiKqpjAvMhiQFox6qyYUZCQNsYJR9hEmyg2oL3DRNAjL16UerbSbEqbMGrFH6yddWsnaNWfJVNPwXjHgbfWtCFBgDxFkX", "p2wpkh"),
        }
        for xkey1, xtype1 in xprvs:
            for xkey2, xtype2 in xprvs:
                self.assertEqual(xkey2, cmds.convert_xkey(xkey1, xtype2))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_encrypt_decrypt(self, mock_write):
        wallet = restore_wallet_from_text('p2wpkh:TAgoypi14k5Y54svysG62xp5QFRWiF1W64zxaFRFPo2jMPSMoa5D',
                                          path='if_this_exists_mocking_failed_648151893')['wallet']
        cmds = Commands(config=None, wallet=wallet, network=None)
        cleartext = "asdasd this is the message"
        pubkey = "021f110909ded653828a254515b58498a6bafc96799fb0851554463ed44ca7d9da"
        ciphertext = cmds.encrypt(pubkey, cleartext)
        self.assertEqual(cleartext, cmds.decrypt(pubkey, ciphertext))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_export_private_key_imported(self, mock_write):
        wallet = restore_wallet_from_text('p2wpkh:TAgoypi14k5Y54svysG62xp5QFRWiF1W64zxaFRFPo2jMPSMoa5D p2wpkh:TAa25Tq4PdzhDKBoVaFaCdV3yxvLrRikQviNkuFQLeYopsVvNTV3',
                                          path='if_this_exists_mocking_failed_648151893')['wallet']
        cmds = Commands(config=None, wallet=wallet, network=None)
        # single address tests
        with self.assertRaises(Exception):
            cmds.getprivatekeys("asdasd")  # invalid addr, though might raise "not in wallet"
        with self.assertRaises(Exception):
            cmds.getprivatekeys("ltc1qgfam82qk7uwh5j2xxmcd8cmklpe0zackqwq8jp")  # not in wallet
        self.assertEqual("p2wpkh:TAa25Tq4PdzhDKBoVaFaCdV3yxvLrRikQviNkuFQLeYopsVvNTV3",
                         cmds.getprivatekeys("ltc1q2ccr34wzep58d4239tl3x3734ttle92arvely7"))
        # list of addresses tests
        with self.assertRaises(Exception):
            cmds.getprivatekeys(['ltc1q2ccr34wzep58d4239tl3x3734ttle92arvely7', 'asd'])
        self.assertEqual(['p2wpkh:TAa25Tq4PdzhDKBoVaFaCdV3yxvLrRikQviNkuFQLeYopsVvNTV3', 'p2wpkh:TAgoypi14k5Y54svysG62xp5QFRWiF1W64zxaFRFPo2jMPSMoa5D'],
                         cmds.getprivatekeys(['ltc1q2ccr34wzep58d4239tl3x3734ttle92arvely7', 'ltc1q9pzjpjq4nqx5ycnywekcmycqz0wjp2nq7n0qjr']))

    @mock.patch.object(storage.WalletStorage, '_write')
    def test_export_private_key_deterministic(self, mock_write):
        wallet = restore_wallet_from_text('bitter grass shiver impose acquire brush forget axis eager alone wine silver',
                                          gap_limit=2,
                                          path='if_this_exists_mocking_failed_648151893')['wallet']
        cmds = Commands(config=None, wallet=wallet, network=None)
        # single address tests
        with self.assertRaises(Exception):
            cmds.getprivatekeys("asdasd")  # invalid addr, though might raise "not in wallet"
        with self.assertRaises(Exception):
            cmds.getprivatekeys("ltc1qgfam82qk7uwh5j2xxmcd8cmklpe0zackqwq8jp")  # not in wallet
        self.assertEqual("p2wpkh:T6v5Q8KEmjLmJoTxPfXfyNcCEFYC7Lfmwmp9Y8dce9knevo9ZkPk",
                         cmds.getprivatekeys("ltc1q3g5tmkmlvxryhh843v4dz026avatc0zz8xd49e"))
        # list of addresses tests
        with self.assertRaises(Exception):
            cmds.getprivatekeys(['ltc1q3g5tmkmlvxryhh843v4dz026avatc0zz8xd49e', 'asd'])
        self.assertEqual(['p2wpkh:T6v5Q8KEmjLmJoTxPfXfyNcCEFYC7Lfmwmp9Y8dce9knevo9ZkPk', 'p2wpkh:TAgoypi14k5Y54svysG62xp5QFRWiF1W64zxaFRFPo2jMPSMoa5D'],
                         cmds.getprivatekeys(['ltc1q3g5tmkmlvxryhh843v4dz026avatc0zz8xd49e', 'ltc1q9pzjpjq4nqx5ycnywekcmycqz0wjp2nq7n0qjr']))


class TestCommandsTestnet(TestCaseForTestnet):

    def test_convert_xkey(self):
        cmds = Commands(config=None, wallet=None, network=None)
        xpubs = {
            ("tpubD8p5qNfjczgTGbh9qgNxsbFgyhv8GgfVkmp3L88qtRm5ibUYiDVCrn6WYfnGey5XVVw6Bc5QNQUZW5B4jFQsHjmaenvkFUgWtKtgj5AdPm9", "standard"),
            ("upub59wfQ8qJTg6ZSuvwtR313Qdp8gP8TSBwTof5dPQ3QVsYp1N9t29Rr9TGF1pj8kAXUg3mKbmrTKasA2qmBJKb1bGUzB6ApDZpVC7LoHhyvBo", "p2wpkh-p2sh"),
            ("vpub5UmvhoWDcMe3JD84impdFVjKJeXaQ4BSNvBJQnHvnWFRs7BP8gJzUD7QGDnK8epStKAa55NQuywR3KTKtzjbopx5rWnbQ8PJkvAzBtgaGBc", "p2wpkh"),
        }
        for xkey1, xtype1 in xpubs:
            for xkey2, xtype2 in xpubs:
                self.assertEqual(xkey2, cmds.convert_xkey(xkey1, xtype2))

        xprvs = {
            ("tprv8c83gxdVUcznP8fMx2iNUBbaQgQC7MUbBUDG3c6YU9xgt7Dn5pfcgHUeNZTAvuYmNgVHjyTzYzGWwJr7GvKCm2FkPaaJipyipbfJeB3tdPW", "standard"),
            ("uprv8vxJzdJQdJYGERrUnPVzgGh5aeYe3yU66ajUpzzRrALZwD31LUqBJM8nPmQkvpCgnKc6VT4Z1ed4pbTfzcjDZFwMFvGjJjoD6Kix2pCwVe7", "p2wpkh-p2sh"),
            ("vprv9FnaJHyKmz5k5j3bckHctMnakch5zbTb1hFhcPtKEAiSzJrEb8zjvQnvQyNLvircBxiuEvf7UJycht5EiK9EMVcx8Fy9techN3nbRQRFhEv", "p2wpkh"),
        }
        for xkey1, xtype1 in xprvs:
            for xkey2, xtype2 in xprvs:
                self.assertEqual(xkey2, cmds.convert_xkey(xkey1, xtype2))
