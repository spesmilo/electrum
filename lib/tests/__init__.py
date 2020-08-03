import unittest
import threading
import tempfile
import shutil


# some unit tests are modifying globals...
class SequentialTestCase(unittest.TestCase):

    test_lock = threading.Lock()

    def setUp(self):
        super().setUp()
        self.test_lock.acquire()

    def tearDown(self):
        super().tearDown()
        self.test_lock.release()


class ElectronCashTestCase(SequentialTestCase):
    """Base class for our unit tests."""

    def setUp(self):
        super().setUpClass()
        self.electrum_path = tempfile.mkdtemp()

    def tearDown(self):
        super().tearDownClass()
        shutil.rmtree(self.electrum_path)
