import unittest
from time import sleep
from test import TestProtocolCase
from electrum.network import Network, SimpleConfig

class TestNetworkFault(unittest.TestCase):

    def setUp(self):
        self.config = SimpleConfig()
        self.network = Network(self.config)
        self.network.start()

    def tearDown(self):
        self.network.stop()

    def test_000_no_connection(self):
        address = "1HdGRAJjzsPZrVrJfkFRMjM3jCib7viZgD"
        self.network.stop()
        try:
            res = self.network.synchronous_get(('blockchain.address.listunspent', [address]), timeout=5)
            self.assertFalse(True)
            print(res)
        except BaseException as e:
            print("Error: {}".format(e))
            self.assertFalse(False)


    def test_001_erorr_message(self):
        address = "realy fake address"
        try:
            res = self.network.synchronous_get(('blockchain.address.listunspent', [address]), timeout=5)
            self.assertFalse(True)
            print(res)
        except BaseException as e:
            print("Error: {}".format(e))
            self.assertFalse(False)

class TestProtocolOnFault(TestProtocolCase):

    def is_protocol_done(self, pThread):
        if pThread.protocol:
            return pThread.protocol.done
        else:
            pThread.done.is_set()

    def test_001_sufficient_funds_fault(self):
        protocolThreads = self.make_clients_threads()
        protocolThreads[0].network = None # OMAGAD OMAGAD
        for pThread in protocolThreads:
            pThread.start()
        done = False
        error_raised = False
        while not done:
            # read protocol messages
            for pThread in protocolThreads:
                try:
                    message = pThread.logger.get_nowait()
                    print(message)
                    if message.startswith("Error"):
                        error_raised = True
                except:
                    pass
            done = any([self.is_protocol_done(pThread) == True for pThread in protocolThreads])
        for pThread in protocolThreads:
            pThread.join()
        # read all items in log channels
        for pThread in protocolThreads:
            while not pThread.logger.empty():
                try:
                    message = pThread.logger.get_nowait()
                    print(message)
                    if message.startswith("Error"):
                        error_raised = True
                except:
                    pass
        self.assertTrue(error_raised)

    def test_002_make_transaction_fault(self):
        protocolThreads = self.make_clients_threads()
        for pThread in protocolThreads:
            pThread.start()
        done = False
        error_raised = False
        while not done:
            # read protocol messages
            for pThread in protocolThreads:
                try:
                    message = pThread.logger.get_nowait()
                    print(message)
                    if message.startswith("Error"):
                        error_raised = True
                    if pThread.network != None and "encrypt " in message:
                        pThread.protocol.coin.network = None
                except:
                    pass
            done = any([self.is_protocol_done(pThread) == True for pThread in protocolThreads])
        for pThread in protocolThreads:
            pThread.join()
        # read all items in log channels
        for pThread in protocolThreads:
            while not pThread.logger.empty():
                try:
                    message = pThread.logger.get_nowait()
                    print(message)
                    if message.startswith("Error"):
                        error_raised = True
                except:
                    pass
        self.assertTrue(error_raised)

    def test_003_broadcast_transaction_fault(self):
        protocolThreads = self.make_clients_threads()
        for pThread in protocolThreads:
            pThread.start()
        done = False
        error_raised = False
        while not done:
            # read protocol messages
            for pThread in protocolThreads:
                try:
                    message = pThread.logger.get_nowait()
                    print(message)
                    if message.startswith("Error"):
                        error_raised = True
                    if pThread.network != None and "got transaction signatures" in message:
                        pThread.protocol.coin.network = None
                except:
                    pass
            done = any([self.is_protocol_done(pThread) == True for pThread in protocolThreads])
        for pThread in protocolThreads:
            pThread.join()
        # read all items in log channels
        for pThread in protocolThreads:
            while not pThread.logger.empty():
                try:
                    message = pThread.logger.get_nowait()
                    print(message)
                    if message.startswith("Error"):
                        error_raised = True
                except:
                    pass
        self.assertTrue(error_raised)
