import unittest
import threading
import tempfile
import shutil

import electrum
import electrum.logging
from electrum import constants
from electrum import util


# Set this locally to make the test suite run faster.
# If set, unit tests that would normally test functions with multiple implementations,
# will only be run once, using the fastest implementation.
# e.g. libsecp256k1 vs python-ecdsa. pycryptodomex vs pyaes.
FAST_TESTS = False


electrum.logging._configure_stderr_logging()


# some unit tests are modifying globals...
class SequentialTestCase(unittest.TestCase):

    test_lock = threading.Lock()

    def setUp(self):
        super().setUp()
        self.test_lock.acquire()

    def tearDown(self):
        super().tearDown()
        self.test_lock.release()


class ElectrumTestCase(SequentialTestCase):
    """Base class for our unit tests."""

    # maxDiff = None

    def setUp(self):
        super().setUp()
        self.asyncio_loop, self._stop_loop, self._loop_thread = util.create_and_start_event_loop()
        self.electrum_path = tempfile.mkdtemp()

    def tearDown(self):
        self.asyncio_loop.call_soon_threadsafe(self._stop_loop.set_result, 1)
        self._loop_thread.join(timeout=1)
        super().tearDown()
        shutil.rmtree(self.electrum_path)


class TestCaseForTestnet(ElectrumTestCase):
    """Class that runs member tests in testnet mode"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.set_testnet()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()


def as_testnet(func):
    """Function decorator to run a single unit test in testnet mode.

    NOTE: this is inherently sequential; tests running in parallel would break things
    """
    def run_test(*args, **kwargs):
        old_net = constants.net
        try:
            constants.set_testnet()
            func(*args, **kwargs)
        finally:
            constants.net = old_net
    return run_test

