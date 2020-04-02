import unittest
import threading
import tempfile
import shutil

from electrumsys import constants


# Set this locally to make the test suite run faster.
# If set, unit tests that would normally test functions with multiple implementations,
# will only be run once, using the fastest implementation.
# e.g. libsecp256k1 vs python-ecdsa. pycryptodomex vs pyaes.
FAST_TESTS = False


# some unit tests are modifying globals...
class SequentialTestCase(unittest.TestCase):

    test_lock = threading.Lock()

    def setUp(self):
        super().setUp()
        self.test_lock.acquire()

    def tearDown(self):
        super().tearDown()
        self.test_lock.release()


class ElectrumSysTestCase(SequentialTestCase):
    """Base class for our unit tests."""

    def setUp(self):
        super().setUpClass()
        self.electrumsys_path = tempfile.mkdtemp()

    def tearDown(self):
        super().tearDownClass()
        shutil.rmtree(self.electrumsys_path)


class TestCaseForTestnet(ElectrumSysTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.set_testnet()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()
