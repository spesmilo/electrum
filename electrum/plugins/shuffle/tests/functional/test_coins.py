import unittest

import sys, os
sys.path.append(os.path.realpath(os.path.dirname(__file__)+"/../../../../"))
# print(sys.path)

import imp
imp.load_module('electroncash', *imp.find_module('lib'))
imp.load_module('electroncash_plugins', *imp.find_module('plugins'))

from electroncash_plugins.shuffle.coin import Coin, address_from_public_key
from electroncash_plugins.shuffle.tests.test import testNetwork, random_sk, make_fake_public_key, make_fake_address, fake_hash
from electroncash_plugins.shuffle.messages import Messages
from electrum.bitcoin import Hash
from electrum.address import Address


class TestCoin(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestCoin, self).__init__(*args, **kwargs)
        self.network = testNetwork()
        self.ec_keys = [random_sk() for _ in range(10)]
        self.public_keys = [make_fake_public_key(secret_key=sk) for sk in self.ec_keys]
        self.addresses = [address_from_public_key(public_key) for public_key in self.public_keys]
        for address in self.addresses:
            for value in [10000, 1000, 500, 100]:
                self.network.add_coin(address, value, tx_hash = fake_hash(address, value))
        self.coin = Coin(self.network)

    def test_001_sufficient_funds(self):
        pubkey_1, pubkey_2, pubkey_3 = self.public_keys[0:3]
        address_1, address_2, address_3 = self.addresses[0:3]
        address_x = "111111111111111111111111111"
        inputs = {
            pubkey_1:[
                fake_hash(address_1, 1000) + ":0",
                fake_hash(address_1, 100)  + ":0"
                ],
            pubkey_2:[
                fake_hash(address_2, 1000) + ":0"]
            }
        self.assertTrue(self.coin.check_inputs_for_sufficient_funds(inputs, 2022))
        self.assertFalse(self.coin.check_inputs_for_sufficient_funds(inputs, 20022))
        bad_hash_input = {Hash("pubkey_1").hex():["a1h4"]}
        self.assertIsNone(self.coin.check_inputs_for_sufficient_funds(bad_hash_input, 2222))
        bad_address_input = {Hash("pubkey_111").hex():["a111h1"]}
        self.assertIsNone(self.coin.check_inputs_for_sufficient_funds(bad_address_input, 2222))


    def test_002_get_coins(self):
        pubkey_1, pubkey_2, pubkey_3 = self.public_keys[0:3]
        address_1, address_2, address_3 = self.addresses[0:3]
        inputs = {
            pubkey_1:[
                fake_hash(address_1, 1000)+":0",
                fake_hash(address_1, 100)+":0"
                ],
            pubkey_2:[fake_hash(address_2, 1000)+":0"]
            }
        coins = self.coin.get_coins(inputs)
        self.assertEquals(coins[pubkey_1][0]["value"], 1000)
        self.assertEquals(coins[pubkey_1][0]["tx_hash"], fake_hash(address_1, 1000))
        self.assertEquals(coins[pubkey_1][1]["value"], 100)
        self.assertEquals(coins[pubkey_1][1]["tx_hash"], fake_hash(address_1, 100))
        self.assertEquals(coins[pubkey_2][0]["value"], 1000)
        self.assertEquals(coins[pubkey_2][0]["tx_hash"], fake_hash(address_2, 1000))
        bad_input = {
            pubkey_1:[fake_hash(address_2, 2222)]
        }
        coins = self.coin.get_coins(bad_input)
        self.assertIsNone(coins)

    def test_003_make_unsigned_transaction(self):
        fee = 100
        amount = 1000
        pubkey_1, pubkey_2, pubkey_3, pubkey_4 = self.public_keys[0:4]
        address_1, address_2, address_3, address_4 = self.addresses[0:4]
        inputs = {
            "player_1_vk":
            {
                pubkey_1:[
                    fake_hash(address_1, 500) + ":0",
                    fake_hash(address_1, 100) + ":0",
                ],
                pubkey_2:[
                    fake_hash(address_2, 500) + ":0",
                ]
            },
            "player_2_vk":
            {
                pubkey_3:[
                    fake_hash(address_3, 1000) + ":0" ,
                    fake_hash(address_3, 100) + ":0",
                ]
            },
            "player_3_vk":
            {
                pubkey_4:[
                    fake_hash(address_4, 10000)+ ":0",
                ]
            }
        }
        outputs = [make_fake_address() for _ in range(3)]
        changes = { player:make_fake_address() for player in ["player_1_vk", "player_2_vk", "player_3_vk"]}
        transaction = self.coin.make_unsigned_transaction(amount, fee, inputs, outputs, changes)

        flat_inputs = [
            {"public_key": pubkey_1, "address": address_1, "tx_hash": inputs["player_1_vk"][pubkey_1][0].split(":")[0], "value": 500, "tx_pos":0},
            {"public_key": pubkey_1, "address": address_1, "tx_hash": inputs["player_1_vk"][pubkey_1][1].split(":")[0], "value": 100, "tx_pos":0},
            {"public_key": pubkey_2, "address": address_2, "tx_hash": inputs["player_1_vk"][pubkey_2][0].split(":")[0], "value": 500, "tx_pos":0},
            {"public_key": pubkey_3, "address": address_3, "tx_hash": inputs["player_2_vk"][pubkey_3][0].split(":")[0], "value": 1000, "tx_pos":0},
            {"public_key": pubkey_3, "address": address_3, "tx_hash": inputs["player_2_vk"][pubkey_3][1].split(":")[0], "value": 100, "tx_pos":0},
            {"public_key": pubkey_4, "address": address_4, "tx_hash": inputs["player_3_vk"][pubkey_4][0].split(":")[0], "value": 10000, "tx_pos":0},
        ]
        flat_inputs.sort(key=lambda x:x["tx_hash"])
        for i, input in enumerate(transaction.inputs()):
            self.assertEquals(input['value'], flat_inputs[i]['value'])
            self.assertEquals(input['tx_hash'], flat_inputs[i]['tx_hash'])
            self.assertEquals(input['pubkeys'][0], flat_inputs[i]['public_key'])
            self.assertEquals(input['address'].to_string(Address.FMT_LEGACY), flat_inputs[i]['address'].to_string(Address.FMT_LEGACY))
        amounts = {"player_1_vk":1100, "player_2_vk":1100, "player_3_vk":10000 }
        flat_changes = [(changes[player], amounts[player]) for player in sorted(changes)]
        flat_outputs = [
            (0, Address.from_string(outputs[0]), amount),
            (0, Address.from_string(outputs[1]), amount),
            (0, Address.from_string(outputs[2]), amount),
            (0, Address.from_string(flat_changes[2][0]), flat_changes[2][1] - amount - fee)
        ]
        print(transaction.outputs())
        self.assertEquals(transaction.outputs(), flat_outputs)


    def test_004_all_about_signatures(self):
        fee = 50
        amount = 1000
        sk_1, sk_2, sk_3, sk_4 = self.ec_keys[0:4]
        pubkey_1, pubkey_2, pubkey_3, pubkey_4 = self.public_keys[0:4]
        address_1, address_2, address_3, address_4 = self.addresses[0:4]
        inputs_vk_1 = {
            pubkey_1:[
                fake_hash(address_1, 500)+":0",
                fake_hash(address_1, 100)+":0",
            ],
            pubkey_2:[
                fake_hash(address_2, 500)+":0",
            ]
        }
        inputs_vk_2 = {
            pubkey_3:[
                fake_hash(address_3, 1000)+":0",
                fake_hash(address_3, 100)+":0",
            ]
        }
        inputs_vk_3 = {
            pubkey_4:[
                fake_hash(address_4, 10000)+":0",
            ]
        }
        inputs = {
            "player_1_vk": inputs_vk_1,
            "player_2_vk": inputs_vk_2,
            "player_3_vk": inputs_vk_3
        }
        outputs = [make_fake_address() for _ in range(3)]
        changes = { player:make_fake_address() for player in ["player_1_vk", "player_2_vk", "player_3_vk"]}
        transaction = self.coin.make_unsigned_transaction(amount, fee, inputs, outputs, changes)
        secret_keys_vk_1 = {pubkey_1:sk_1, pubkey_2: sk_2}
        secret_keys_vk_2 = {pubkey_3:sk_3}
        secret_keys_vk_3 = {pubkey_4:sk_4}
        signatures = {}
        signatures.update(self.coin.get_transaction_signature(transaction, inputs_vk_1, secret_keys_vk_1))
        signatures.update(self.coin.get_transaction_signature(transaction, inputs_vk_2, secret_keys_vk_2))
        signatures.update(self.coin.get_transaction_signature(transaction, inputs_vk_3, secret_keys_vk_3))
        for player in inputs:
            for pubkey in inputs[player]:
                for tx_hash in inputs[player][pubkey]:
                    signature = signatures[tx_hash]
                    self.assertTrue(self.coin.verify_tx_signature(signature , transaction, pubkey, tx_hash))
        self.coin.add_transaction_signatures(transaction, signatures)


    def test_005_verigy_signatures(self):
        message = b"some_message_for_test"
        sk_1 = random_sk()
        pubkey_1 = sk_1.get_public_key(True)
        signature_1 = sk_1.sign_message(message, True)
        self.assertTrue(self.coin.verify_signature(signature_1, message, pubkey_1))

        sk_2 = random_sk()
        pubkey_2 = sk_2.get_public_key(False)
        signature_2 = sk_2.sign_message(message, False)
        self.assertTrue(self.coin.verify_signature(signature_2, message, pubkey_2))
        self.assertFalse(self.coin.verify_signature(signature_2, message, pubkey_1))
