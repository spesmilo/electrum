import asyncio
import tempfile
import threading
import unittest
from types import SimpleNamespace
from typing import List

from electrum import constants
from electrum.simple_config import SimpleConfig
from electrum.blockchain import BlockchainManager
from electrum.interface import Interface, ServerAddr, ChainResolutionMode
from electrum.network import Network
from electrum.crypto import sha256
from electrum.logging import Logger
from electrum.util import OldTaskGroup
from electrum import util

from . import ElectrumTestCase
from . import test_blockchain


CRM = ChainResolutionMode


class MockBlockchain:

    def __init__(self, headers: List[str], bc_mgr: 'BlockchainManager', *, forkpoint: int = 0):
        self._headers = headers
        self.forkpoint = forkpoint
        self.bc_mgr = bc_mgr

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
        self = MockBlockchain(parent._headers[:forkpoint], parent.bc_mgr, forkpoint=forkpoint)
        self.save_header(header)
        chain_id = header['mock']['id']
        with self.bc_mgr.blockchains_lock:
            self.bc_mgr.blockchains[chain_id] = self
        return self


class MockNetwork(Logger):

    def __init__(self, config: SimpleConfig):
        Logger.__init__(self)
        self.config = config
        self.bc_mgr = BlockchainManager.from_config(config)
        self.asyncio_loop = util.get_asyncio_loop()
        self.taskgroup = OldTaskGroup()
        self.proxy = None
        self.bhi_lock = asyncio.Lock()
        # for switch_lagging_interface
        self.auto_connect = True
        self.interface = None
        self.interfaces = {}
        self.interfaces_lock = threading.Lock()
        self.default_server = None
        self._blockchain = self.bc_mgr.get_best_chain()

    blockchain = Network.blockchain
    get_server_height = Network.get_server_height
    get_local_height = Network.get_local_height
    _server_is_lagging = Network._server_is_lagging
    switch_lagging_interface = Network.switch_lagging_interface

    async def switch_to_interface(self, server: ServerAddr):
        self.default_server = server
        self.interface = self.interfaces[server]


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
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a"], ifa.bc_mgr)
        ifa.bc_mgr.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.CATCHUP:1, 'id': '06a', 'prev_id': '05a'}})
        res = await ifa.sync_until(ifa.tip)
        self.assertEqual((CRM.CATCHUP, 7), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(ifa.bc_mgr.blockchains), 1)

    async def test_catchup_already_up_to_date(self):
        """Single chain, local chain tip already matches server tip."""
        ifa = self.interface
        ifa.tip = 5
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a"], ifa.bc_mgr)
        ifa.bc_mgr.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.CATCHUP:1, 'id': '05a', 'prev_id': '04a'}})
        res = await ifa.sync_until(ifa.tip)
        self.assertEqual((CRM.CATCHUP, 6), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(ifa.bc_mgr.blockchains), 1)

    async def test_catchup_client_ahead_of_lagging_server(self):
        """Single chain, server is lagging."""
        ifa = self.interface
        ifa.tip = 3
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a"], ifa.bc_mgr)
        ifa.bc_mgr.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 3, 'mock': {CRM.CATCHUP:1, 'id': '03a', 'prev_id': '02a'}})
        res = await ifa.sync_until(ifa.tip)
        self.assertEqual((CRM.CATCHUP, 4), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(ifa.bc_mgr.blockchains), 1)

    async def test_catchup_fast_forward(self):
        """Single chain, but client is behind. The client's height is 5, server is already on block 12.
        - first missing block found during *backward* phase
        """
        ifa = self.interface
        ifa.tip = 12
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a"], ifa.bc_mgr)
        ifa.bc_mgr.blockchains = {
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
        self.assertEqual(len(ifa.bc_mgr.blockchains), 1)

    async def test_fork(self):
        """client starts on main chain, has no knowledge of any fork.
        server is on other side of chain split, the last common block is height 6.
        - first missing block found during *binary* phase
        - is *new* fork
        """
        ifa = self.interface
        ifa.tip = 8
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a"], ifa.bc_mgr)
        ifa.bc_mgr.blockchains = {
            "00a": ifa.blockchain,
        }
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'id': '08b', 'prev_id': '07b'}})
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'id': '07b', 'prev_id': '06a'}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.BACKWARD:1, 'id': '05a', 'prev_id': '04a'}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.BINARY:1, 'id': '06a', 'prev_id': '05a'}})
        res = await ifa.sync_until(ifa.tip, next_height=7)
        self.assertEqual((CRM.FORK, 8), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(ifa.bc_mgr.blockchains), 2)

    async def test_can_connect_during_backward(self):
        """client starts on main chain. client already knows about another fork, which has local height 4.
        server is on that fork but has more blocks.
        - first missing block found during *backward* phase
        - is *existing* fork
        """
        ifa = self.interface
        ifa.tip = 8
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a"], ifa.bc_mgr)
        ifa.bc_mgr.blockchains = {
            "00a": ifa.blockchain,
            "03b": MockBlockchain(["00a", "01a", "02a", "03b", "04b"], ifa.bc_mgr, forkpoint=3),
        }
        ifa.q.put_nowait({'block_height': 8, 'mock': {CRM.CATCHUP:1, 'id': '08b', 'prev_id': '07b'}})
        ifa.q.put_nowait({'block_height': 7, 'mock': {CRM.BACKWARD:1, 'id': '07b', 'prev_id': '06b'}})
        ifa.q.put_nowait({'block_height': 5, 'mock': {CRM.BACKWARD:1, 'id': '05b', 'prev_id': '04b'}})
        ifa.q.put_nowait({'block_height': 6, 'mock': {CRM.CATCHUP:1, 'id': '06b', 'prev_id': '05b'}})
        res = await ifa.sync_until(ifa.tip, next_height=6)
        self.assertEqual((CRM.CATCHUP, 7), res)
        self.assertEqual(ifa.q.qsize(), 0)
        self.assertEqual(len(ifa.bc_mgr.blockchains), 2)

    async def test_chain_false_during_binary(self):
        """client starts on main chain, has no knowledge of any fork.
        server is on other side of chain split, the last common block is height 3.
        - first missing block found during *binary* phase
        - is *new* fork
        """
        ifa = self.interface
        ifa.tip = 8
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a"], ifa.bc_mgr)
        ifa.bc_mgr.blockchains = {
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
        self.assertEqual(len(ifa.bc_mgr.blockchains), 2)

    async def test_chain_true_during_binary(self):
        """client starts on main chain. client already knows about another fork, which has local height 10.
        server is on that fork but has more blocks.
        - first missing block found during *binary* phase
        - is *existing* fork
        """
        ifa = self.interface
        ifa.tip = 20
        ifa.blockchain = MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07a", "08a", "09a", "10a", "11a", "12a", "13a", "14a"], ifa.bc_mgr)
        ifa.bc_mgr.blockchains = {
            "00a": ifa.blockchain,
            "07b": MockBlockchain(["00a", "01a", "02a", "03a", "04a", "05a", "06a", "07b", "08b", "09b", "10b"], ifa.bc_mgr, forkpoint=7),
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
        self.assertEqual(len(ifa.bc_mgr.blockchains), 2)

    async def test_switch_away_from_server_stuck_below_reorg(self):
        """The main server is stuck below the forkpoint of a reorg (#11112).
        The reorg turns the chain object of the main interface into the losing branch,
        whose tip no server is on. We should still switch to a server at the tip of the best chain.
        """
        headers = test_blockchain.TestBlockchain.HEADERS
        network = self.interface.network
        chain = network.bc_mgr.get_best_chain()
        for name in "ABCDEFOPQ":
            chain.save_header(headers[name])
        stuck_iface = SimpleNamespace(
            server=ServerAddr.from_str('stuck-server:50000:t'), tip=5, tip_header=headers['F'], blockchain=chain)
        network.interface = stuck_iface
        network.default_server = stuck_iface.server
        # reorg: the fork G..J becomes the best chain, chain is left with O..Q
        fork = chain.fork(headers['G'])
        for name in "HIJ":
            fork.save_header(headers[name])
        self.assertEqual(fork, network.bc_mgr.get_best_chain())
        self.assertEqual((6, 8), (chain.forkpoint, chain.height()))
        good_iface = SimpleNamespace(
            server=ServerAddr.from_str('good-server:50000:t'), tip=9, tip_header=headers['J'], blockchain=fork)
        network.interfaces = {iface.server: iface for iface in (stuck_iface, good_iface)}

        await network.switch_lagging_interface()
        self.assertEqual(fork, stuck_iface.blockchain)
        self.assertEqual(good_iface, network.interface)


if __name__ == "__main__":
    constants.BitcoinRegtest.set_as_network()
    unittest.main()
