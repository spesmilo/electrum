import asyncio
import os
import unittest
import threading
import tempfile
import shutil
import functools
import inspect

import electrum
import electrum.logging
from electrum import constants
from electrum import util
from electrum.logging import Logger
from electrum.wallet import restore_wallet_from_text


# Set this locally to make the test suite run faster.
# If set, unit tests that would normally test functions with multiple implementations,
# will only be run once, using the fastest implementation.
# e.g. libsecp256k1 vs python-ecdsa. pycryptodomex vs pyaes.
FAST_TESTS = False


electrum.logging._configure_stderr_logging(verbosity="*")

electrum.util.AS_LIB_USER_I_WANT_TO_MANAGE_MY_OWN_ASYNCIO_LOOP = True


class ElectrumTestCase(unittest.IsolatedAsyncioTestCase, Logger):
    """Base class for our unit tests."""

    TESTNET = False
    REGTEST = False
    TEST_ANCHOR_CHANNELS = False
    # maxDiff = None  # for debugging

    # some unit tests are modifying globals... so we run sequentially:
    _test_lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        Logger.__init__(self)
        unittest.IsolatedAsyncioTestCase.__init__(self, *args, **kwargs)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        assert not (cls.REGTEST and cls.TESTNET), "regtest and testnet are mutually exclusive"
        if cls.REGTEST:
            constants.BitcoinRegtest.set_as_network()
        elif cls.TESTNET:
            constants.BitcoinTestnet.set_as_network()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        if cls.TESTNET or cls.REGTEST:
            constants.BitcoinMainnet.set_as_network()

    def setUp(self):
        have_lock = self._test_lock.acquire(timeout=0.1)
        if not have_lock:
            # This can happen when trying to run the tests in parallel,
            # or if a prior test raised  during `setUp` or `asyncSetUp` and never released the lock.
            raise Exception("timed out waiting for test_lock")
        super().setUp()
        self.electrum_path = tempfile.mkdtemp(prefix="electrum-unittest-base-")
        assert util._asyncio_event_loop is None, "global event loop already set?!"

    async def asyncSetUp(self):
        await super().asyncSetUp()
        loop = util.get_asyncio_loop()
        # IsolatedAsyncioTestCase creates event loops with debug=True, which makes the tests take ~4x time
        if not (os.environ.get("PYTHONASYNCIODEBUG") or os.environ.get("PYTHONDEVMODE")):
            loop.set_debug(False)
        util._asyncio_event_loop = loop

    def tearDown(self):
        util.callback_mgr.clear_all_callbacks()
        shutil.rmtree(self.electrum_path)
        super().tearDown()
        util._asyncio_event_loop = None  # cleared here, at the ~last possible moment. asyncTearDown is too early.
        self._test_lock.release()


def as_testnet(func):
    """Function decorator to run a single unit test in testnet mode.

    NOTE: this is inherently sequential; tests running in parallel would break things
    """
    old_net = constants.net
    if inspect.iscoroutinefunction(func):
        async def run_test(*args, **kwargs):
            try:
                constants.BitcoinTestnet.set_as_network()
                return await func(*args, **kwargs)
            finally:
                constants.net = old_net
    else:
        def run_test(*args, **kwargs):
            try:
                constants.BitcoinTestnet.set_as_network()
                return func(*args, **kwargs)
            finally:
                constants.net = old_net
    return run_test


@functools.wraps(restore_wallet_from_text)
def restore_wallet_from_text__for_unittest(*args, gap_limit=2, gap_limit_for_change=1, **kwargs):
    """much lower default gap limits (to save compute time)"""
    return restore_wallet_from_text(
        *args,
        gap_limit=gap_limit,
        gap_limit_for_change=gap_limit_for_change,
        **kwargs,
    )
