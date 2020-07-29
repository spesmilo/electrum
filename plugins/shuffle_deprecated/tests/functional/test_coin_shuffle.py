import unittest

import imp
imp.load_module('electroncash', *imp.find_module('lib'))
imp.load_module('electroncash_plugins', *imp.find_module('plugins'))

from electroncash_plugins.shuffle_deprecated.coin import Coin, address_from_public_key
from electroncash_plugins.shuffle_deprecated.crypto import Crypto
from electroncash_plugins.shuffle_deprecated.messages import Messages
from electroncash_plugins.shuffle_deprecated.round import Round
from electroncash_plugins.shuffle_deprecated.tests.test import testNetwork, random_sk, make_fake_public_key, make_fake_address, fake_hash
from electroncash_plugins.shuffle_deprecated.comms import Channel, ChannelWithPrint
# from electroncash_plugins.shuffle_deprecated.phase import Phase


class TestRound(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestRound, self).__init__(*args, **kwargs)
        self.network = testNetwork()
        self.ec_keys = [random_sk() for _ in range(10)]
        self.public_keys = [make_fake_public_key(secret_key=sk) for sk in self.ec_keys]
        self.addresses = [address_from_public_key(public_key) for public_key in self.public_keys]
        for address in self.addresses:
            for value in [10000, 1000, 500, 100]:
                self.network.add_coin(address, value, tx_hash = fake_hash(address, value))
        self.coin = Coin(self.network)

    def setUp(self):
        self.number_of_players = 5
        self.crypto = Crypto()
        self.messages = Messages()
        self.outchan = Channel()
        self.inchan = Channel()
        self.logchan = Channel()
        self.session = b"session"
        # self.phase = Phase('Announcement')
        self.phase = 'Announcement'
        self.amount = 1000
        self.fee = 50
        self.secret_keys = [random_sk() for _ in range(self.number_of_players)]
        self.verification_keys = [make_fake_public_key(secret_key=sk) for sk in self.secret_keys]
        self.players = {index + 1:vk for index, vk in enumerate(self.verification_keys)}
        self.inputs = {
            self.verification_keys[0]:{
                self.public_keys[0]:[
                    fake_hash(self.addresses[0], 500) + ":0",
                    fake_hash(self.addresses[0], 100) + ":0"
                ],
                self.public_keys[1]:[
                    fake_hash(self.addresses[1], 500) + ":0"
                ]
            },
            self.verification_keys[1]:{
                self.public_keys[2]:[
                    fake_hash(self.addresses[2], 1000) + ":0",
                    fake_hash(self.addresses[2], 100) + ":0"
                ],
            },
            self.verification_keys[2]:{
                self.public_keys[3]:[
                    fake_hash(self.addresses[3], 1000) + ":0"
                ],
                self.public_keys[4]:[
                    fake_hash(self.addresses[4], 100) + ":0"
                ],
            },
            self.verification_keys[3]:{
                self.public_keys[5]:[
                    fake_hash(self.addresses[5], 10000) + ":0"
                ],
            },
            self.verification_keys[4]:{
                self.public_keys[6]:[
                    fake_hash(self.addresses[6], 1000) + ":0"
                ],
                self.public_keys[7]:[
                    fake_hash(self.addresses[7], 500) + ":0"
                ]
            }
        }
        self.sks = {
            self.public_keys[0]:self.ec_keys[0],
            self.public_keys[1]:self.ec_keys[1],
            }
        self.all_sks =  {
            self.verification_keys[0]:{
                self.public_keys[0]:self.ec_keys[0],
                self.public_keys[1]:self.ec_keys[1]
            },
            self.verification_keys[1]:{
                self.public_keys[2]:self.ec_keys[2],
            },
            self.verification_keys[2]:{
                self.public_keys[3]:self.ec_keys[3],
                self.public_keys[4]:self.ec_keys[4],
            },
            self.verification_keys[3]:{
                self.public_keys[5]:self.ec_keys[5],
            },
            self.verification_keys[4]:{
                self.public_keys[6]:self.ec_keys[6],
                self.public_keys[7]:self.ec_keys[7]
            }
        }
        self.sk = self.secret_keys[0]
        self.verification_key = self.verification_keys[0]
        self.new_addresses = [make_fake_address() for _ in range(self.number_of_players)]
        self.changes = {vk:make_fake_address() for vk in self.verification_keys}
        self.addr_new = self.new_addresses[0]
        self.change = make_fake_address()
        self.round = Round(self.coin, self.crypto, self.messages,
                           self.inchan, self.outchan, self.logchan,
                           self.session, self.phase, self.amount, self.fee,
                           self.sk, self.sks, self.inputs, self.verification_key, self.players, self.addr_new, self.change)

    def test_001_test_init(self):
        self.assertEquals(self.round.number_of_players, self.number_of_players)
        self.assertEquals(self.round.me, 1)

    def test_002_blame_insufficient_funds(self):
        self.assertTrue(self.round.blame_insufficient_funds())
        self.assertEquals(self.logchan.get(), "Player 1 finds sufficient funds")
        self.round.inputs[self.round.players[1]][self.public_keys[1]][0] = fake_hash(self.addresses[1], 100)+":0"
        self.assertFalse(self.round.blame_insufficient_funds())
        self.assertEquals(self.logchan.get(), "Blame: insufficient funds of player 1")
        self.assertIsNotNone(self.outchan.get(timeout=0))

    def test_0021_blame_insufficient_funds_network_fail(self):
        self.round.coin.network = None
        self.assertIsNone(self.round.blame_insufficient_funds())
        self.assertEquals(self.logchan.get(), "Error: blockchain network fault!")

    def test_003_process_equivocation_check(self):
        # SetUp
        self.round.new_addresses = self.new_addresses
        self.round.changes = self.changes
        self.round.encryption_keys = {player:"encryption_key" for player in self.round.players.values()}
        computed_hash = self.crypto.hash(str(self.round.new_addresses) +
                                         str([self.round.encryption_keys[self.round.players[i]]
                                              for i in sorted(self.round.players)]))
        # Wrong phase ignored
        self.round.phase = 'Announcement'
        self.round.process_equivocation_check()
        self.assertTrue(self.outchan.empty())
        self.assertTrue(self.logchan.empty())
        # Set Proper phase
        # Check if incomplete inbox ignored
        self.round.phase = 'EquivocationCheck'
        self.round.inbox[self.messages.phases[self.round.phase]] = {
            self.round.players[1]: "something"
        }
        self.round.process_equivocation_check()
        self.assertTrue(self.outchan.empty())
        self.assertTrue(self.logchan.empty())
        # check processing with inbox completed
        # making the fake messages with equal hashes and fulfill inbox with it
        self.messages.clear_packets()
        self.messages.add_hash(computed_hash)
        message = self.messages.packets.SerializeToString()
        self.round.inbox[self.messages.phases[self.round.phase]] = {
            player:message for player in self.round.players.values()
        }
        self.round.process_equivocation_check()
        self.assertEquals(self.round.phase, "VerificationAndSubmission")
        self.assertTrue(self.logchan.get(timeout=0), "Player 1 reaches phase 5")
        self.assertTrue(self.logchan.get(timeout=0), "Player 1 send transaction signatures")
        self.assertTrue(self.logchan.empty())
        self.assertIsNotNone(self.round.transaction)
        self.messages.packets.ParseFromString(self.outchan.get(timeout=0))
        self.assertTrue(self.outchan.empty())
        signatures = self.messages.get_signatures()
        for pubkey in self.round.inputs[self.round.vk]:
            for hash in self.round.inputs[self.round.vk][pubkey]:
                self.assertIn(hash, signatures)
        # Checking the blame behaviour
        self.round.phase = 'EquivocationCheck'
        self.messages.clear_packets()
        self.messages.add_hash(computed_hash+b"fail")
        message = self.messages.packets.SerializeToString()
        self.round.inbox[self.messages.phases[self.round.phase]][self.round.vk] = message
        self.round.process_equivocation_check()
        self.assertEquals(self.round.phase, "Blame")
        self.assertEquals(self.logchan.get(timeout=0), "Player 1 found bad hash from 1")
        self.assertEquals(self.logchan.get(timeout=0), "Blame: wrong hash computed by player 1")
        self.assertTrue(self.logchan.empty())
        self.messages.packets.ParseFromString(self.outchan.get(timeout=0))
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("EQUIVOCATIONFAILURE")) # This should be replaced with allias for the reason instread of 2.

    def test_004_process_verification_and_submission(self):
        self.round.phase = 'VerificationAndSubmission'
        # Check if nothing is happend with incomplete inbox
        self.round.inbox[self.messages.phases[self.round.phase]] = {
            self.round.players[1]: "something"
        }
        self.round.process_verification_and_submission()
        self.assertTrue(self.outchan.empty())
        self.assertTrue(self.logchan.empty())
        # Check normal case
        transaction = self.coin.make_unsigned_transaction(self.amount, self.fee, self.inputs, self.new_addresses, self.changes)
        self.round.transaction = transaction
        signatures = { player:self.coin.get_transaction_signature(transaction, self.inputs[player], self.all_sks[player])
                       for player in self.round.players.values()}
        transaction = self.coin.make_unsigned_transaction(self.amount, self.fee, self.inputs, self.new_addresses, self.changes)
        for player in signatures:
            self.messages.clear_packets()
            self.messages.add_signatures(signatures[player])
            self.round.inbox[self.messages.phases[self.round.phase]][player] = self.messages.packets.SerializeToString()
        self.round.process_verification_and_submission()
        self.assertIsNotNone(self.round.tx)
        self.assertTrue(self.round.done)
        self.assertEquals(self.logchan.get(timeout=0),"Player 1 got transaction signatures")
        self.assertEquals(self.logchan.get(timeout=0),"Player 1 done")
        self.assertEquals(self.logchan.get(timeout=0),"Player 1 complete protocol")
        self.assertTrue(self.logchan.empty())
        self.assertTrue(self.outchan.empty())
        # Abnormal case
        self.round.done = False
        self.round.tx = None
        transaction = self.coin.make_unsigned_transaction(self.amount, self.fee, self.inputs, self.new_addresses, self.changes)
        signatures = { player:self.coin.get_transaction_signature(transaction, self.inputs[player], self.all_sks[player])
                       for player in self.round.players.values()}
        signatures[self.round.vk][self.inputs[self.round.vk][self.public_keys[0]][0]] = signatures[self.round.vk][self.inputs[self.round.vk][self.public_keys[0]][1]]
        for player in signatures:
            self.messages.clear_packets()
            self.messages.add_signatures(signatures[player])
            self.round.inbox[self.messages.phases[self.round.phase]][player] = self.messages.packets.SerializeToString()
        self.round.transaction = self.coin.make_unsigned_transaction(self.amount, self.fee, self.inputs, self.new_addresses, self.changes)
        self.round.process_verification_and_submission()
        self.assertEquals(self.logchan.get(timeout=0),"Player 1 got transaction signatures")
        self.assertEquals(self.logchan.get(timeout=0),"Blame: wrong transaction signature from player 1")
        self.assertTrue(self.logchan.empty())
        self.messages.packets.ParseFromString(self.outchan.get(timeout = 0))
        self.assertEquals(self.messages.get_blame_reason(), self.messages.blame_reason("Invalid Signature"))
