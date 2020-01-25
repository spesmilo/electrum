import unittest
from test import TestProtocolCase

# import imp
# imp.load_module('electroncash', *imp.find_module('lib'))
# imp.load_module('electroncash_gui', *imp.find_module('gui'))
# imp.load_module('electroncash_plugins', *imp.find_module('plugins'))

from electroncash.bitcoin import public_key_to_p2pkh

class TestProtocol(TestProtocolCase):

    def test_001_same_keys_appears(self):
        protocolThreads = self.make_clients_threads()
        protocolThreads[0].vk = protocolThreads[1].vk
        self.start_protocols(protocolThreads)
        done = False
        while not done:
            for p in protocolThreads:
                if p.done.is_set():
                    done = True
                    break
        self.stop_protocols(protocolThreads)
        last_messages = [self.get_last_logger_message(pThread) for pThread in protocolThreads]
        self.assertIn('Error: The same keys appears!', last_messages)

    def test_002_insufficient_funds(self):
        from electroncash_plugins.shuffle_deprecated.coin import Coin
        coin = Coin(self.network)
        protocolThreads = self.make_clients_threads(with_print = True)
        coins_1 = coin.get_coins(protocolThreads[0].inputs)
        for pubkey in coins_1:
            bad_addr = public_key_to_p2pkh(bytes.fromhex(pubkey))
            for coin in coins_1[pubkey]:
                coin['value'] = 0
            self.network.coins[bad_addr] = coins_1[pubkey]
        self.start_protocols(protocolThreads)
        done = False
        while not done:
            completes = [self.is_protocol_complete(p) for p in protocolThreads[1:]]
            done = all(completes)
        self.stop_protocols(protocolThreads)
        tx = protocolThreads[1].protocol.tx.raw
        for pThread in protocolThreads[2:]:
            self.assertEqual(tx, pThread.protocol.tx.raw)
        print(protocolThreads[-1].protocol.tx.raw)
        print(protocolThreads[-1].protocol.change_addresses)
