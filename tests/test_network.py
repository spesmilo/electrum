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
        self.logger.debug(f"step with {height=}. {item=}")
        assert item['block_height'] == height, (item['block_height'], height)
        assert mode in item['mock'], (mode, item)
        return item

    async def run(self):
        return

    async def _maybe_warm_headers_cache(self, *args, **kwargs):
        return


class TestNetwork(ElectrumTestCase):

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

    # finds forkpoint during binary, new fork
    async def test_fork(self):
        """client starts on main chain, has no knowledge of any fork.
        server is on other side of chain split, the last common block is height 6.
        """
        ifa = self.interface
        ifa.tip = 12  # FIXME how could the server tip be this high?
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a"])
        blockchain.blockchains = {"00a": ifa.blockchain}
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'id': '08b', 'prev_id': '07b'}})
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'id': '07b', 'prev_id': '06a'}})
        ifa.q.put_nowait({'block_height': 2, 'mock': {CRM.BACKWARD:1, 'id': '02a', 'prev_id': '01a'}})
        ifa.q.put_nowait({'block_height': 4, 'mock': {CRM.BINARY:1, 'id': '04a', 'prev_id': '03a'}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.BINARY:1, 'id': '05a', 'prev_id': '04a'}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.BINARY:1, 'id': '06a', 'prev_id': '05a'}})
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
        ifa.tip = 12  # FIXME how could the server tip be this high?
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a"])
        blockchain.blockchains = {
            "00a": ifa.blockchain,
            "01b": MockBlockchain(["00a", "01b"]),
        }
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'id': '08b', 'prev_id': '07b'}})
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'id': '07b', 'prev_id': '06b'}})
        ifa.q.put_nowait({'block_height': 2, 'mock': {CRM.BACKWARD:1, 'id': '02b', 'prev_id': '01b'}})
        ifa.q.put_nowait({'block_height': 3, 'mock': {CRM.CATCHUP:1, 'id': '03b', 'prev_id': '02b'}})
        ifa.q.put_nowait({'block_height': 4, 'mock': {CRM.CATCHUP:1, 'id': '04b', 'prev_id': '03b'}})
        res = await ifa.sync_until(8, next_height=4)
        self.assertEqual((CRM.CATCHUP, 5), res)
        self.assertEqual(ifa.q.qsize(), 0)

    # finds forkpoint during binary, new fork
    async def test_chain_false_during_binary(self):
        """client starts on main chain, has no knowledge of any fork.
        server is on other side of chain split, the last common block is height 3.
        """
        ifa = self.interface
        ifa.tip = 12  # FIXME how could the server tip be this high?
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a"])
        blockchain.blockchains = {"00a": ifa.blockchain}
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'id': '08b', 'prev_id': '07b'}})
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'id': '07b', 'prev_id': '06b'}})
        ifa.q.put_nowait({'block_height': 2, 'mock': {CRM.BACKWARD:1, 'id': '02a', 'prev_id': '01a'}})
        ifa.q.put_nowait({'block_height': 4, 'mock': {CRM.BINARY:1, 'id': '04b', 'prev_id': '03a'}})
        ifa.q.put_nowait({'block_height': 3, 'mock': {CRM.BINARY:1, 'id': '03a', 'prev_id': '02a'}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.CATCHUP:1, 'id': '05b', 'prev_id': '04b'}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.CATCHUP:1, 'id': '06b', 'prev_id': '05b'}})
        res = await ifa.sync_until(8, next_height=6)
        self.assertEqual((CRM.CATCHUP, 7), res)
        self.assertEqual(ifa.q.qsize(), 0)


if __name__ == "__main__":
    constants.BitcoinRegtest.set_as_network()
    unittest.main()
