import unittest
from lib.bip38 import bip38_decrypt

class TestBip38(unittest.TestCase):

    def test_no_ec_mult_no_comp_1(self):
        passphrase = 'TestingOneTwoThree'
        encrypted = '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg'
        decrypted = '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'
        self.assertEqual(bip38_decrypt(encrypted, passphrase), decrypted)

    def test_bad_password(self):
        passphrase = 'TestingOneTwo'
        encrypted = '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg'
        self.assertRaises(Exception, bip38_decrypt, encrypted, passphrase)

    def test_no_ec_mult_no_comp_2(self):
        passphrase = 'Satoshi'
        encrypted = '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq'
        decrypted = '5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5'
        self.assertEqual(bip38_decrypt(encrypted, passphrase), decrypted)

    def test_no_ec_mult_with_comp_1(self):
        passphrase = 'TestingOneTwoThree'
        encrypted = '6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo'
        decrypted = 'L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP'
        self.assertEqual(bip38_decrypt(encrypted, passphrase), decrypted)

    def test_no_ec_mult_with_comp_2(self):
        passphrase = 'Satoshi'
        encrypted = '6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7'
        decrypted = 'KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7'
        self.assertEqual(bip38_decrypt(encrypted, passphrase), decrypted)

    def test_ec_mult_not_yet_implemented(self):
        passphrase = 'TestingOneTwoThree'
        encrypted = '6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX'
        decrypted = '5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2'
        self.assertRaises(Exception, bip38_decrypt, encrypted, passphrase)

    def test_no_ec_unicode(self):
        passphrase = u'\u03D2\u0301\u0000\U00010400\U0001F4A9'
        encrypted = '6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn'
        decrypted = '5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4'
        self.assertEqual(bip38_decrypt(encrypted, passphrase), decrypted)

