import asyncio
import tempfile
import unittest

from electrum.constants import set_regtest
from electrum.simple_config import SimpleConfig
from electrum import blockchain
from electrum.interface import Interface

class MockInterface(Interface):
    def __init__(self, config):
        self.config = config
        super().__init__(None, 'mock-server:50000:t', self.config.electrum_path(), None)
        class FakeNetwork:
            max_checkpoint = lambda: 0
        self.network = FakeNetwork
        self.q = asyncio.Queue()
        self.blockchain = blockchain.Blockchain(self.config, 2002, None)
        self.tip = 12
    async def get_block_header(self, height, assert_mode):
        assert self.q.qsize() > 0, (height, assert_mode)
        item = await self.q.get()
        print("step with height", height, item)
        assert item['block_height'] == height, (item['block_height'], height)
        assert assert_mode in item['mock'], (assert_mode, item)
        return item

class TestNetwork(unittest.TestCase):
    def setUp(self):
        self.config = SimpleConfig({'electrum_path': tempfile.mkdtemp(prefix="test_network")})
        self.interface = MockInterface(self.config)

    def test_new_fork(self):
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
        self.assertEqual(('fork', 8), asyncio.get_event_loop().run_until_complete(ifa.sync_until(8, next_height=8)))
        self.assertEqual(self.interface.q.qsize(), 0)

    def test_new_can_connect_during_backward(self):
        blockchain.blockchains = {}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 2
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        self.interface.q.put_nowait({'block_height': 3, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = self.interface
        self.assertEqual(('catchup', 5), asyncio.get_event_loop().run_until_complete(ifa.sync_until(8, next_height=5)))
        self.assertEqual(self.interface.q.qsize(), 0)

    def mock_fork(self, bad_header):
        return blockchain.Blockchain(self.config, bad_header['block_height'], None)

    def test_new_chain_false_during_binary(self):
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
        self.assertEqual(('catchup', 7), asyncio.get_event_loop().run_until_complete(ifa.sync_until(8, next_height=7)))
        self.assertEqual(self.interface.q.qsize(), 0)

    def test_new_join(self):
        blockchain.blockchains = {7: {'check': lambda bad_header: True}}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': lambda height: height == 6}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: True,  'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: True}})
        ifa = self.interface
        self.assertEqual(('join', 7), asyncio.get_event_loop().run_until_complete(ifa.sync_until(8, next_height=7)))
        self.assertEqual(self.interface.q.qsize(), 0)

    def test_new_reorg(self):
        times = 0
        def check(header):
            nonlocal times
            self.assertEqual(header['block_height'], 7)
            times += 1
            return times != 1
        blockchain.blockchains = {7: {'check': check, 'parent': {'check': lambda x: True}}}
        self.interface.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': lambda height: height == 6}})
        self.interface.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: 1,  'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 4, 'mock': {'binary':1, 'check': lambda x: 1, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 5, 'mock': {'binary':1, 'check': lambda x: 1, 'connect': lambda x: False}})
        self.interface.q.put_nowait({'block_height': 6, 'mock': {'binary':1, 'check': lambda x: 1, 'connect': lambda x: True}})
        self.interface.q.put_nowait({'block_height': 7, 'mock': {'binary':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = self.interface
        self.assertEqual(('join', 8), asyncio.get_event_loop().run_until_complete(ifa.sync_until(8, next_height=8)))
        self.assertEqual(self.interface.q.qsize(), 0)
        self.assertEqual(times, 2)

if __name__=="__main__":
    set_regtest()
    unittest.main()
