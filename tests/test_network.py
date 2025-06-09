import asyncio
import tempfile
import unittest
from typing import List

from electrum import constants
from electrum.simple_config import SimpleConfig
from electrum import blockchain
from electrum.interface import Interface, ServerAddr, ChainResolutionMode
from electrum.crypto import sha256
from electrum.util import OldTaskGroup
from electrum import util

from . import ElectrumTestCase


CRM = ChainResolutionMode


class MockBlockchain:

    def __init__(self, headers: List[str]):
        self._headers = headers
        self.forkpoint = len(headers)

    def height(self) -> int:
        return len(self._headers) - 1

    def save_header(self, header: dict) -> None:
        assert header['block_height'] == self.height()+1, f"new {header['block_height']=}, cur {self.height()=}"
        self._headers.append(header['mock']['id'])

    def check_header(self, header: dict) -> bool:
        return header['mock']['id'] in self._headers

    def can_connect(self, header: dict, *, check_height: bool = True) -> bool:
        height = header['block_height']
        if check_height and self.height() != height - 1:
            return False
        if self.check_header(header):
            return True
        return header['mock']['prev_id'] in self._headers

    def fork(parent, header: dict) -> 'MockBlockchain':
        if not parent.can_connect(header, check_height=False):
            raise Exception("forking header does not connect to parent chain")
        forkpoint = header.get('block_height')
        self = MockBlockchain(parent._headers[:forkpoint])
        self.save_header(header)
        chain_id = header['mock']['id']
        with blockchain.blockchains_lock:
            blockchain.blockchains[chain_id] = self
        return self


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

    async def get_block_header(self, height: int, *, mode: ChainResolutionMode) -> dict:
        assert self.q.qsize() > 0, (height, mode)
        item = await self.q.get()
        self.logger.debug(f"step with {height=}. {mode=}. will get {item=}")
        assert item['block_height'] == height, (item['block_height'], height)
        assert mode in item['mock'], (mode, item)
        return item

    async def run(self):
        return

    async def _maybe_warm_headers_cache(self, *args, **kwargs):
        return


class TestHeaderChainResolution(ElectrumTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        constants.BitcoinRegtest.set_as_network()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.BitcoinMainnet.set_as_network()

    def tearDown(self):
        blockchain.blockchains = {}
        super().tearDown()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.interface = MockInterface(self.config)

    async def test_catchup_one_block_behind(self):
        """Single chain, but client is behind. The client's height is 5, server is on block 6.
        - first missing block found during *catchup* phase
        """
        ifa = self.interface
        ifa.tip = 6
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a"])
        blockchain.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.CATCHUP:1, 'id': '06a', 'prev_id': '05a'}})
        res = await ifa.sync_until(ifa.tip)
        self.assertEqual((CRM.CATCHUP, 7), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(blockchain.blockchains), 1)

    async def test_catchup_already_up_to_date(self):
        """Single chain, local chain tip already matches server tip."""
        ifa = self.interface
        ifa.tip = 5
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a"])
        blockchain.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.CATCHUP:1, 'id': '05a', 'prev_id': '04a'}})
        res = await ifa.sync_until(ifa.tip)
        self.assertEqual((CRM.CATCHUP, 6), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(blockchain.blockchains), 1)

    async def test_catchup_client_ahead_of_lagging_server(self):
        """Single chain, server is lagging."""
        ifa = self.interface
        ifa.tip = 3
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a"])
        blockchain.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 3, 'mock': {CRM.CATCHUP:1, 'id': '03a', 'prev_id': '02a'}})
        res = await ifa.sync_until(ifa.tip)
        self.assertEqual((CRM.CATCHUP, 4), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(blockchain.blockchains), 1)

    async def test_catchup_fast_forward(self):
        """Single chain, but client is behind. The client's height is 5, server is already on block 12.
        - first missing block found during *backward* phase
        """
        ifa = self.interface
        ifa.tip = 12
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a"])
        blockchain.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 12, 'mock': {CRM.CATCHUP:1, 'id': '12a', 'prev_id': '11a'}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.BACKWARD:1, 'id': '06a', 'prev_id': '05a'}})
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.CATCHUP: 1, 'id': '07a', 'prev_id': '06a'}})
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP: 1, 'id': '08a', 'prev_id': '07a'}})
        ifa.q.put_nowait({'block_height': 9, 'mock': {CRM.CATCHUP: 1, 'id': '09a', 'prev_id': '08a'}})
        res = await ifa.sync_until(ifa.tip, next_height=9)
        self.assertEqual((CRM.CATCHUP, 10), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(blockchain.blockchains), 1)

    async def test_fork(self):
        """client starts on main chain, has no knowledge of any fork.
        server is on other side of chain split, the last common block is height 6.
        - first missing block found during *binary* phase
        - is *new* fork
        """
        ifa = self.interface
        ifa.tip = 8
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a"])
        blockchain.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'id': '08b', 'prev_id': '07b'}})
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'id': '07b', 'prev_id': '06a'}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.BACKWARD:1, 'id': '05a', 'prev_id': '04a'}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.BINARY:1, 'id': '06a', 'prev_id': '05a'}})
        res = await ifa.sync_until(ifa.tip, next_height=7)
        self.assertEqual((CRM.FORK, 8), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(blockchain.blockchains), 2)

    async def test_can_connect_during_backward(self):
        """client starts on main chain. client already knows about another fork, which has local height 4.
        server is on that fork but has more blocks.
        - first missing block found during *backward* phase
        - is *existing* fork
        """
        ifa = self.interface
        ifa.tip = 8
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a"])
        blockchain.blockchains = {
            "00a": ifa.blockchain,
            "03b": MockBlockchain(["00a", "01a", "02a", "03b", "04b"]),
        }
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'id': '08b', 'prev_id': '07b'}})
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'id': '07b', 'prev_id': '06b'}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.BACKWARD:1, 'id': '05b', 'prev_id': '04b'}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.CATCHUP:1, 'id': '06b', 'prev_id': '05b'}})
        res = await ifa.sync_until(ifa.tip, next_height=6)
        self.assertEqual((CRM.CATCHUP, 7), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(blockchain.blockchains), 2)

    async def test_chain_false_during_binary(self):
        """client starts on main chain, has no knowledge of any fork.
        server is on other side of chain split, the last common block is height 3.
        - first missing block found during *binary* phase
        - is *new* fork
        """
        ifa = self.interface
        ifa.tip = 8
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a"])
        blockchain.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'id': '08b', 'prev_id': '07b'}})
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'id': '07b', 'prev_id': '06b'}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.BACKWARD:1, 'id': '05b', 'prev_id': '04b'}})
        ifa.q.put_nowait({'block_height': 1, 'mock': {CRM.BACKWARD:1, 'id': '01a', 'prev_id': '00a'}})
        ifa.q.put_nowait({'block_height': 3, 'mock': {CRM.BINARY:1, 'id': '03a', 'prev_id': '02a'}})
        ifa.q.put_nowait({'block_height': 4, 'mock': {CRM.BINARY:1, 'id': '04b', 'prev_id': '03a'}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.CATCHUP:1, 'id': '05b', 'prev_id': '04b'}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.CATCHUP:1, 'id': '06b', 'prev_id': '05b'}})
        res = await ifa.sync_until(ifa.tip, next_height=6)
        self.assertEqual((CRM.CATCHUP, 7), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(blockchain.blockchains), 2)

    async def test_chain_true_during_binary(self):
        """client starts on main chain. client already knows about another fork, which has local height 10.
        server is on that fork but has more blocks.
        - first missing block found during *binary* phase
        - is *existing* fork
        """
        ifa = self.interface
        ifa.tip = 20
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a", "13a", "14a"])
        blockchain.blockchains = {
            "00a": ifa.blockchain,
            "07b": MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07b", "08b", "09b", "10b"]),
        }
        ifa.q.put_nowait({'block_height': 20, 'mock': {CRM.CATCHUP:1, 'id': '20b', 'prev_id': '19b'}})
        ifa.q.put_nowait({'block_height': 15, 'mock': {CRM.BACKWARD:1, 'id': '15b', 'prev_id': '14b'}})
        ifa.q.put_nowait({'block_height': 13, 'mock': {CRM.BACKWARD:1, 'id': '13b', 'prev_id': '12b'}})
        ifa.q.put_nowait({'block_height': 9, 'mock': {CRM.BACKWARD:1, 'id': '09b', 'prev_id': '08b'}})
        ifa.q.put_nowait({'block_height': 11, 'mock': {CRM.BINARY:1, 'id': '11b', 'prev_id': '10b'}})
        ifa.q.put_nowait({'block_height': 10, 'mock': {CRM.BINARY:1, 'id': '10b', 'prev_id': '09b'}})
        ifa.q.put_nowait({'block_height': 11, 'mock': {CRM.CATCHUP:1, 'id': '11b', 'prev_id': '10b'}})
        ifa.q.put_nowait({'block_height': 12, 'mock': {CRM.CATCHUP:1, 'id': '12b', 'prev_id': '11b'}})
        ifa.q.put_nowait({'block_height': 13, 'mock': {CRM.CATCHUP:1, 'id': '13b', 'prev_id': '12b'}})
        res = await ifa.sync_until(ifa.tip, next_height=13)
        self.assertEqual((CRM.CATCHUP, 14), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(blockchain.blockchains), 2)


if __name__ == "__main__":
    constants.BitcoinRegtest.set_as_network()
    unittest.main()
