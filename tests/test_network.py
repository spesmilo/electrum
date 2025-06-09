import asyncio
import tempfile
import unittest

from electrum import constants
from electrum.simple_config import SimpleConfig
from electrum import blockchain
from electrum.interface import Interface, ServerAddr, ChainResolutionMode
from electrum.crypto import sha256
from electrum.util import OldTaskGroup
from electrum import util

from . import ElectrumTestCase


CRM = ChainResolutionMode


class MockNetwork:

    def __init__(self, config: SimpleConfig):
        self.config = config
        self.asyncio_loop = util.get_asyncio_loop()
        self.taskgroup = OldTaskGroup()
        self.proxy = None

class MockInterface(Interface):
    def __init__(self, config: SimpleConfig):
        self.config = config
        network = MockNetwork(config)
        super().__init__(network=network, server=ServerAddr.from_str('mock-server:50000:t'))
        self.q = asyncio.Queue()
        self.blockchain = blockchain.Blockchain(config=self.config, forkpoint=0,
                                                parent=None, forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        self.set_tip(0)

    async def get_block_header(self, height: int, *, mode: ChainResolutionMode) -> dict:
        assert self.q.qsize() > 0, (height, mode)
        item = await self.q.get()
        self.logger.debug(f"step with {height=}. {item=}")
        assert item['block_height'] == height, (item['block_height'], height)
        assert mode in item['mock'], (mode, item)
        return item

    async def run(self):
        return

    async def _maybe_warm_headers_cache(self, *args, **kwargs):
        return

    def set_tip(self, tip: int):
        self.tip = tip
        self.blockchain._size = self.tip + 1


class TestNetwork(ElectrumTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.BitcoinRegtest.set_as_network()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.BitcoinMainnet.set_as_network()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.interface = MockInterface(self.config)

    # finds forkpoint during binary, new fork
    async def test_fork(self):
        """client starts on main chain, has no knowledge of any fork.
        server is on other side of chain split, the last common block is height 6.
        """
        ifa = self.interface
        ifa.set_tip(12)  # FIXME how could the server tip be this high? for local chain, it's ok though.
        blockchain.blockchains = {}
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 6
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1,'check': lambda x: False, 'connect': mock_connect, 'fork': self.mock_fork}})
        ifa.q.put_nowait({'block_height': 2, 'mock': {CRM.BACKWARD:1,'check':lambda x: True, 'connect': lambda x: False}})
        ifa.q.put_nowait({'block_height': 4, 'mock': {CRM.BINARY:1,'check':lambda x: True, 'connect': lambda x: True}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.BINARY:1,'check':lambda x: True, 'connect': lambda x: True}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.BINARY:1,'check':lambda x: True, 'connect': lambda x: True}})
        res = await ifa.sync_until(8, next_height=7)
        self.assertEqual((CRM.FORK, 8), res)
        self.assertEqual(ifa.q.qsize(), 0)

    # finds forkpoint during backwards, existing fork
    async def test_can_connect_during_backward(self):
        """client starts on main chain. client already knows about another fork, which has local height 1.
        server is on that fork but has more blocks.
        client happens to ask for header at height 2 during backward search (which directly builds on top the existing fork).
        """
        ifa = self.interface
        ifa.set_tip(12)  # FIXME how could the server tip be this high? for local chain, it's ok though.
        blockchain.blockchains = {}
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'check': lambda x: False, 'connect': lambda x: False}})
        def mock_connect(height):
            return height == 2
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'check': lambda x: False, 'connect': mock_connect}})
        ifa.q.put_nowait({'block_height': 2, 'mock': {CRM.BACKWARD:1, 'check': lambda x: False, 'connect': mock_connect}})
        ifa.q.put_nowait({'block_height': 3, 'mock': {CRM.CATCHUP:1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa.q.put_nowait({'block_height': 4, 'mock': {CRM.CATCHUP:1, 'check': lambda x: False, 'connect': lambda x: True}})
        res = await ifa.sync_until(8, next_height=4)
        self.assertEqual((CRM.CATCHUP, 5), res)
        self.assertEqual(ifa.q.qsize(), 0)

    def mock_fork(self, bad_header):
        forkpoint = bad_header['block_height']
        self.interface.logger.debug(f"mock_fork() called with {forkpoint=}")
        b = blockchain.Blockchain(config=self.config, forkpoint=forkpoint, parent=None,
                                  forkpoint_hash=sha256(str(forkpoint)).hex(), prev_hash=sha256(str(forkpoint-1)).hex())
        return b

    # finds forkpoint during binary, new fork
    async def test_chain_false_during_binary(self):
        """client starts on main chain, has no knowledge of any fork.
        server is on other side of chain split, the last common block is height 3.
        """
        ifa = self.interface
        ifa.set_tip(12)  # FIXME how could the server tip be this high? for local chain, it's ok though.
        blockchain.blockchains = {}
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'check': lambda x: False, 'connect': lambda x: False}})
        mock_connect = lambda height: height == 3
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'check': lambda x: False, 'connect': mock_connect}})
        ifa.q.put_nowait({'block_height': 2, 'mock': {CRM.BACKWARD:1, 'check': lambda x: True,  'connect': mock_connect}})
        ifa.q.put_nowait({'block_height': 4, 'mock': {CRM.BINARY:1, 'check': lambda x: False, 'fork': self.mock_fork, 'connect': mock_connect}})
        ifa.q.put_nowait({'block_height': 3, 'mock': {CRM.BINARY:1, 'check': lambda x: True, 'connect': lambda x: True}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.CATCHUP:1, 'check': lambda x: False, 'connect': lambda x: True}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.CATCHUP:1, 'check': lambda x: False, 'connect': lambda x: True}})
        res = await ifa.sync_until(8, next_height=6)
        self.assertEqual((CRM.CATCHUP, 7), res)
        self.assertEqual(ifa.q.qsize(), 0)


if __name__ == "__main__":
    constants.BitcoinRegtest.set_as_network()
    unittest.main()
