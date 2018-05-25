import unittest
import threading

from lib import constants


# some unit tests are modifying globals; sorry.
class SequentialTestCase(unittest.TestCase):

    test_lock = threading.Lock()

    def setUp(self):
        super().setUp()
        self.test_lock.acquire()

    def tearDown(self):
        super().tearDown()
        self.test_lock.release()


class TestCaseForTestnet(SequentialTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.set_testnet()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()
