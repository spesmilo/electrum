import asyncio
import tempfile
import unittest

from electrum import constants
from electrum.simple_config import SimpleConfig
from electrum import blockchain
from electrum.interface import Interface
from electrum.crypto import sha256
from electrum.util import bh2u


class MockTaskGroup:
    async def spawn(self, x): return

class MockNetwork:
    main_taskgroup = MockTaskGroup()
    asyncio_loop = asyncio.get_event_loop()

class MockInterface(Interface):
    def __init__(self, config):
        self.config = config
        network = MockNetwork()
        network.config = config
        super().__init__(network, 'mock-server:50000:t', None)
        self.q = asyncio.Queue()
        self.blockchain = blockchain.Blockchain(config=self.config, forkpoint=0,
                                                parent=None, forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        self.tip = 12
        self.blockchain._size = self.tip + 1
    async def get_block_header(self, height, assert_mode):
        assert self.q.qsize() > 0, (height, assert_mode)
        item = await self.q.get()
        print("step with height", height, item)
        assert item['block_height'] == height, (item['block_height'], height)
        assert assert_mode in item['mock'], (assert_mode, item)
        return item

class TestNetwork(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.set_regtest()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()

    def setUp(self):
        self.config = SimpleConfig({'electrum_path': tempfile.mkdtemp(prefix="test_network")})
        self.interface = MockInterface(self.config)

    def test_fork_noconflict(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 6
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1,'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1,'check':lambda x: True, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        ifa = self.interface
        self.assertEqual(('fork', 8), asyncio.get_event_loop().run_until_complete(ifa.sync_until(8, next_height=7)))
        self.assertEqual(self.interface.q.qsize(), 0)

    def test_fork_conflict(self):
        blockchain.blockchains = {7: {'check': lambda bad_header: False}}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 6
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1,'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1,'check':lambda x: True, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        ifa = self.interface
        self.assertEqual(('fork', 8), asyncio.get_event_loop().run_until_complete(ifa.sync_until(8, next_height=7)))
        self.assertEqual(self.interface.q.qsize(), 0)

    def test_can_connect_during_backward(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 2
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 3, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = self.interface
        self.assertEqual(('catchup', 5), asyncio.get_event_loop().run_until_complete(ifa.sync_until(8, next_height=4)))
        self.assertEqual(self.interface.q.qsize(), 0)

    def mock_fork(self, bad_header):
        forkpoint = bad_header['block_height']
        b = blockchain.Blockchain(config=self.config, forkpoint=forkpoint, parent=None,
                                  forkpoint_hash=bh2u(sha256(str(forkpoint))), prev_hash=bh2u(sha256(str(forkpoint-1))))
        return b

    def test_chain_false_during_binary(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        mock_connect = lambda height: height == 3
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: True,  'connect': mock_connect}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1, 'check': lambda x: False, 'fork': self.mock_fork, 'connect': mock_connect}})
        self.interface.q.put_nowait({'block_height': 3, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = self.interface
        self.assertEqual(('catchup', 7), asyncio.get_event_loop().run_until_complete(ifa.sync_until(8, next_height=6)))
        self.assertEqual(self.interface.q.qsize(), 0)


if __name__=="__main__":
    constants.set_regtest()
    unittest.main()
