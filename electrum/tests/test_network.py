import asyncio
import tempfile
import unittest

from electrum.constants import set_regtest
from electrum.simple_config import SimpleConfig
from electrum import blockchain
from electrum.interface import BlockHeaderInterface

class MockConnection:
    def __init__(self):
        self.q = asyncio.Queue()
        self.server = 'mock-server'
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

    def blockchain_iface_pair(self, forkpoint=2002):
        b = blockchain.Blockchain(self.config, forkpoint, None)
        class FakeNetwork:
            max_checkpoint = lambda: 0
        class FakeIface:
            blockchain = b
            network = FakeNetwork
            tip = 12
        return FakeIface

    def test_new_fork(self):
        blockchain.blockchains = {}
        conn = MockConnection()
        conn.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(block_header_iface):
            return block_header_iface.height == 6
        conn.q.put_nowait({'block_height': 7, 'mock': {'backward':1,'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        conn.q.put_nowait({'block_height': 2, 'mock': {'backward':1,'check':lambda x: True, 'connect': lambda x: False}})
        conn.q.put_nowait({'block_height': 4, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        conn.q.put_nowait({'block_height': 5, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        conn.q.put_nowait({'block_height': 6, 'mock': {'binary':1,'check':lambda x: True, 'connect': lambda x: True}})
        ifa = BlockHeaderInterface(conn, 8, self.blockchain_iface_pair())
        self.assertEqual('fork', asyncio.get_event_loop().run_until_complete(ifa.sync_until(next_height=8)))
        self.assertEqual(conn.q.qsize(), 0)

    def test_new_can_connect_during_backward(self):
        blockchain.blockchains = {}
        conn = MockConnection()
        conn.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(block_header_iface):
            return block_header_iface.height == 2
        conn.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        conn.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        conn.q.put_nowait({'block_height': 3, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        conn.q.put_nowait({'block_height': 4, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = BlockHeaderInterface(conn, 8, self.blockchain_iface_pair())
        self.assertEqual('catchup', asyncio.get_event_loop().run_until_complete(ifa.sync_until(next_height=5)))
        self.assertEqual(conn.q.qsize(), 0)

    def mock_fork(self, bad_header):
        return blockchain.Blockchain(self.config, bad_header['block_height'], None)

    def test_new_chain_false_during_binary(self):
        blockchain.blockchains = {}
        conn = MockConnection()
        conn.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        mock_connect = lambda bhi: bhi.height == 3
        conn.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': mock_connect}})
        conn.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: True,  'connect': mock_connect}})
        conn.q.put_nowait({'block_height': 4, 'mock': {'binary':1, 'check': lambda x: False, 'fork': self.mock_fork, 'connect': mock_connect}})
        conn.q.put_nowait({'block_height': 3, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: True}})
        conn.q.put_nowait({'block_height': 5, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        conn.q.put_nowait({'block_height': 6, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = BlockHeaderInterface(conn, 8, self.blockchain_iface_pair(1000))
        self.assertEqual('catchup', asyncio.get_event_loop().run_until_complete(ifa.sync_until(next_height=7)))
        self.assertEqual(conn.q.qsize(), 0)

    def test_new_join(self):
        blockchain.blockchains = {7: {'check': lambda bad_header: True}}
        conn = MockConnection()
        conn.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        conn.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': lambda x: x.height == 6}})
        conn.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: True,  'connect': lambda x: False}})
        conn.q.put_nowait({'block_height': 4, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: False}})
        conn.q.put_nowait({'block_height': 5, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: False}})
        conn.q.put_nowait({'block_height': 6, 'mock': {'binary':1, 'check': lambda x: True, 'connect': lambda x: True}})
        ifa = BlockHeaderInterface(conn, 8, self.blockchain_iface_pair())
        self.assertEqual('join', asyncio.get_event_loop().run_until_complete(ifa.sync_until(next_height=7)))
        self.assertEqual(conn.q.qsize(), 0)

    def test_new_reorg(self):
        times = 0
        def check(header):
            nonlocal times
            self.assertEqual(header['block_height'], 7)
            times += 1
            return times != 1
        blockchain.blockchains = {7: {'check': check, 'parent': {'check': lambda x: True}}}
        conn = MockConnection()
        conn.q.put_nowait({'block_height': 8, 'mock': {'catchup':1, 'check': lambda x: False, 'connect': lambda x: False}})
        conn.q.put_nowait({'block_height': 7, 'mock': {'backward':1, 'check': lambda x: False, 'connect': lambda x: x.height == 6}})
        conn.q.put_nowait({'block_height': 2, 'mock': {'backward':1, 'check': lambda x: 1,  'connect': lambda x: False}})
        conn.q.put_nowait({'block_height': 4, 'mock': {'binary':1, 'check': lambda x: 1, 'connect': lambda x: False}})
        conn.q.put_nowait({'block_height': 5, 'mock': {'binary':1, 'check': lambda x: 1, 'connect': lambda x: False}})
        conn.q.put_nowait({'block_height': 6, 'mock': {'binary':1, 'check': lambda x: 1, 'connect': lambda x: True}})
        conn.q.put_nowait({'block_height': 7, 'mock': {'binary':1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa = BlockHeaderInterface(conn, 8, self.blockchain_iface_pair())
        self.assertEqual('join', asyncio.get_event_loop().run_until_complete(ifa.sync_until(next_height=8)))
        self.assertEqual(conn.q.qsize(), 0)
        self.assertEqual(times, 2)

if __name__=="__main__":
    set_regtest()
    unittest.main()
