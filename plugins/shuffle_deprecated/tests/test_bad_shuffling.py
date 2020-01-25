from test import TestProtocolCase, bad_client_same_ciphertext, bad_client_changig_the_output
from electroncash.bitcoin import public_key_to_p2pkh
import random
import time

class TestProtocol(TestProtocolCase):

    def test_001_duplicated_ciphertexts(self):
        protocolThreads = self.make_clients_threads(with_print = True, number_of_clients = self.number_of_players - 1)
        bad_thread = self.make_bad_client(bad_client_same_ciphertext, with_print = True)
        bad_client_position = random.randint(1, len(protocolThreads)-2)# Nor first not last
        for pThread in protocolThreads[:bad_client_position]:
            pThread.start()
        time.sleep(1)
        bad_thread.start()
        time.sleep(1)
        for pThread in protocolThreads[bad_client_position:]:
            pThread.start()
        protocolThreads.append(bad_thread)
        done = False
        while not done:
            completes = [self.is_protocol_complete(p) for p in protocolThreads[:-1]]
            done = all(completes)
        self.stop_protocols(protocolThreads)
        tx = protocolThreads[0].protocol.tx.raw
        for pThread in protocolThreads[:-1]:
            self.assertEqual(tx, pThread.protocol.tx.raw)

    def test_002_missing_output(self):
        protocolThreads = self.make_clients_threads(with_print = True, number_of_clients = self.number_of_players - 1)
        bad_thread = self.make_bad_client(bad_client_changig_the_output, with_print = True)
        bad_client_position = random.randint(1, len(protocolThreads)-2)# Nor first not last
        for pThread in protocolThreads[:bad_client_position]:
            pThread.start()
        time.sleep(1)
        bad_thread.start()
        time.sleep(1)
        for pThread in protocolThreads[bad_client_position:]:
            pThread.start()
        protocolThreads.append(bad_thread)

        done = False
        while not done:
            completes = [self.is_protocol_complete(p) for p in protocolThreads[:-1]]
            done = all(completes)
        self.stop_protocols(protocolThreads)
        tx = protocolThreads[0].protocol.tx.raw
        for pThread in protocolThreads[:-1]:
            self.assertEqual(tx, pThread.protocol.tx.raw)
