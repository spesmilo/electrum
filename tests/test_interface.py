import asyncio
from functools import partial

import aiorpcx
from aiorpcx import RPCError

from electrum.interface import ServerAddr, Interface, PaddedRSTransport
from electrum import util, blockchain
from electrum.util import OldTaskGroup, bfh
from electrum.simple_config import SimpleConfig
from electrum.transaction import Transaction
from electrum.wallet import Abstract_Wallet
from electrum.blockchain import Blockchain

from . import ElectrumTestCase
from . import restore_wallet_from_text__for_unittest
from .toyserver import ToyServer, ToyServerSession


class TestServerAddr(ElectrumTestCase):

    def test_from_str(self):
        self.assertEqual(ServerAddr(host="104.198.149.61", port=80, protocol="t"),
                         ServerAddr.from_str("104.198.149.61:80:t"))
        self.assertEqual(ServerAddr(host="ecdsa.net", port=110, protocol="s"),
                         ServerAddr.from_str("ecdsa.net:110:s"))
        self.assertEqual(ServerAddr(host="2400:6180:0:d1::86b:e001", port=50002, protocol="s"),
                         ServerAddr.from_str("[2400:6180:0:d1::86b:e001]:50002:s"))
        self.assertEqual(ServerAddr(host="localhost", port=8080, protocol="s"),
                         ServerAddr.from_str("localhost:8080:s"))

    def test_from_str_with_inference(self):
        self.assertEqual(None, ServerAddr.from_str_with_inference("104.198.149.61"))
        self.assertEqual(None, ServerAddr.from_str_with_inference("ecdsa.net"))
        self.assertEqual(None, ServerAddr.from_str_with_inference("2400:6180:0:d1::86b:e001"))
        self.assertEqual(None, ServerAddr.from_str_with_inference("[2400:6180:0:d1::86b:e001]"))

        self.assertEqual(ServerAddr(host="104.198.149.61", port=80, protocol="s"),
                         ServerAddr.from_str_with_inference("104.198.149.61:80"))
        self.assertEqual(ServerAddr(host="ecdsa.net", port=110, protocol="s"),
                         ServerAddr.from_str_with_inference("ecdsa.net:110"))
        self.assertEqual(ServerAddr(host="2400:6180:0:d1::86b:e001", port=50002, protocol="s"),
                         ServerAddr.from_str_with_inference("[2400:6180:0:d1::86b:e001]:50002"))

        self.assertEqual(ServerAddr(host="104.198.149.61", port=80, protocol="t"),
                         ServerAddr.from_str_with_inference("104.198.149.61:80:t"))
        self.assertEqual(ServerAddr(host="ecdsa.net", port=110, protocol="s"),
                         ServerAddr.from_str_with_inference("ecdsa.net:110:s"))
        self.assertEqual(ServerAddr(host="2400:6180:0:d1::86b:e001", port=50002, protocol="s"),
                         ServerAddr.from_str_with_inference("[2400:6180:0:d1::86b:e001]:50002:s"))

    def test_to_friendly_name(self):
        self.assertEqual("104.198.149.61:80:t",
                         ServerAddr(host="104.198.149.61", port=80, protocol="t").to_friendly_name())
        self.assertEqual("ecdsa.net:110",
                         ServerAddr(host="ecdsa.net", port=110, protocol="s").to_friendly_name())
        self.assertEqual("ecdsa.net:50001:t",
                         ServerAddr(host="ecdsa.net", port=50001, protocol="t").to_friendly_name())
        self.assertEqual("[2400:6180:0:d1::86b:e001]:50002",
                         ServerAddr(host="2400:6180:0:d1::86b:e001", port=50002, protocol="s").to_friendly_name())
        self.assertEqual("[2400:6180:0:d1::86b:e001]:50001:t",
                         ServerAddr(host="2400:6180:0:d1::86b:e001", port=50001, protocol="t").to_friendly_name())


class MockNetwork:

    def __init__(self, *, config: SimpleConfig):
        self.config = config
        self.asyncio_loop = util.get_asyncio_loop()
        self.taskgroup = OldTaskGroup()
        blockchain.read_blockchains(self.config)
        blockchain.init_headers_file_for_best_chain()
        self.proxy = None
        self.debug = True
        self.bhi_lock = asyncio.Lock()
        self.interface = None  # type: Interface | None

    async def connection_down(self, interface: Interface):
        pass
    def get_network_timeout_seconds(self, request_type) -> int:
        return 10
    def check_interface_against_healthy_spread_of_connected_servers(self, iface_to_check: Interface) -> bool:
        return True
    def update_fee_estimates(self, *, fee_est: dict[int, int] = None):
        pass
    async def switch_unwanted_fork_interface(self):
        pass
    async def switch_lagging_interface(self):
        pass
    def blockchain(self) -> Blockchain:
        return self.interface.blockchain
    def get_local_height(self) -> int:
        return self.blockchain().height()


class TestInterface(ElectrumTestCase):
    REGTEST = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.NETWORK_SKIPMERKLECHECK = True
        self._orig_WAIT_FOR_BUFFER_GROWTH_SECONDS = PaddedRSTransport.WAIT_FOR_BUFFER_GROWTH_SECONDS
        PaddedRSTransport.WAIT_FOR_BUFFER_GROWTH_SECONDS = 0

    def tearDown(self):
        PaddedRSTransport.WAIT_FOR_BUFFER_GROWTH_SECONDS = self._orig_WAIT_FOR_BUFFER_GROWTH_SECONDS
        super().tearDown()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self._toyserver = ToyServer()
        session_factory = partial(ToyServerSession, toyserver=self._toyserver)
        self._server: asyncio.base_events.Server = await aiorpcx.serve_rs(session_factory, "127.0.0.1")
        server_socket_addr = self._server.sockets[0].getsockname()
        self._server_port = server_socket_addr[1]
        self.network = MockNetwork(config=self.config)

    async def asyncTearDown(self):
        if self.network.interface:
            await self.network.interface.close()
        self._server.close()
        await self._server.wait_closed()
        await super().asyncTearDown()

    async def _start_iface_and_wait_for_sync(self):
        interface = Interface(network=self.network, server=ServerAddr(host="127.0.0.1", port=self._server_port, protocol="t"))
        interface.client_name = lambda: "alice"
        self.network.interface = interface
        async with util.async_timeout(5):
            await interface.ready
            await interface._blockchain_updated.wait()
        return interface

    def _get_server_session(self) -> ToyServerSession:
        return self._toyserver.get_session_by_name("alice")

    async def test_client_syncs_headers_to_tip(self):
        interface = await self._start_iface_and_wait_for_sync()
        self.assertEqual(self._toyserver.cur_height, interface.tip)
        self.assertFalse(interface.got_disconnected.is_set())

    async def test_transaction_get(self):
        interface = await self._start_iface_and_wait_for_sync()
        # inject a tx into the server:
        self._toyserver._add_tx(Transaction("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a010000001600140297bde2689a3c79ffe050583b62f86f2d9dae540000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"))
        # try requesting tx unknown to server:
        with self.assertRaises(RPCError) as ctx:
            await interface.get_transaction("deadbeef"*8)
        self.assertTrue("unknown txid" in ctx.exception.message)
        # try requesting known tx:
        rawtx = await interface.get_transaction("bdae818ad3c1f261317738ae9284159bf54874356f186dbc7afd631dc1527fcb")
        self.assertEqual(rawtx, self._toyserver.txs["bdae818ad3c1f261317738ae9284159bf54874356f186dbc7afd631dc1527fcb"].hex())
        self.assertEqual(self._get_server_session()._method_counts["blockchain.transaction.get"], 2)

    async def test_transaction_broadcast(self):
        interface = await self._start_iface_and_wait_for_sync()
        rawtx1 = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025200ffffffff0200f2052a010000001600140297bde2689a3c79ffe050583b62f86f2d9dae540000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"
        tx = Transaction(rawtx1)
        # broadcast
        await interface.broadcast_transaction(tx)
        self.assertEqual(bfh(rawtx1), self._toyserver.txs.get(tx.txid()))
        # now request tx.
        # as we just broadcast this same tx, this will hit the client iface cache, and won't call the server.
        self.assertEqual(self._get_server_session()._method_counts["blockchain.transaction.get"], 0)
        rawtx2 = await interface.get_transaction(tx.txid())
        self.assertEqual(rawtx1, rawtx2)
        self.assertEqual(self._get_server_session()._method_counts["blockchain.transaction.get"], 0)

    async def test_dont_request_gethistory_if_status_change_results_from_mempool_txs_simply_getting_mined(self):
        """After a new block is mined, we recv "blockchain.scripthash.subscribe" notifs.
        We opportunistically guess the scripthash status changed purely because touching mempool txs just got mined.
        If the guess is correct, we won't call the "blockchain.scripthash.get_history" RPC.
        """
        interface = await self._start_iface_and_wait_for_sync()
        w1 = restore_wallet_from_text__for_unittest("9dk", path=None, config=self.config)['wallet']  # type: Abstract_Wallet
        w1.start_network(self.network)
        await w1.up_to_date_changed_event.wait()
        self.assertEqual(self._get_server_session()._method_counts["blockchain.scripthash.get_history"], 0)
        # fund w1 (in mempool)
        funding_tx = "01000000000101e855888b77b1688d08985b863bfe85b354049b4eba923db9b5cf37089975d5d10000000000fdffffff0280969800000000001600140297bde2689a3c79ffe050583b62f86f2d9dae5460abe9000000000016001472df47551b6e7e0c8428814d2e572bc5ac773dda024730440220383efa2f0f5b87f8ce5d6b6eaf48cba03bf522b23fbb23b2ac54ff9d9a8f6a8802206f67d1f909f3c7a22ac0308ac4c19853ffca3a9317e1d7e0c88cc3a86853aaac0121035061949222555a0df490978fe6e7ebbaa96332ecb5c266918fd800c0eef736e7358d1400"
        funding_txid = await self._get_server_session()._handle_transaction_broadcast(funding_tx)
        await w1.up_to_date_changed_event.wait()
        while not w1.is_up_to_date():
            await w1.up_to_date_changed_event.wait()
        self.assertEqual(self._get_server_session()._method_counts["blockchain.scripthash.get_history"], 1)
        self.assertEqual(
            w1.adb.get_address_history("bcrt1qq2tmmcngng78nllq2pvrkchcdukemtj5jnxz44"),
            {funding_txid: 0})
        # mine funding tx
        await self._toyserver.mine_block(txs=[Transaction(funding_tx)])
        await w1.up_to_date_changed_event.wait()
        while not w1.is_up_to_date():
            await w1.up_to_date_changed_event.wait()
        # see if we managed to guess new history, and hence did not need to call get_history RPC
        self.assertEqual(self._get_server_session()._method_counts["blockchain.scripthash.get_history"], 1)
        self.assertEqual(
            w1.adb.get_address_history("bcrt1qq2tmmcngng78nllq2pvrkchcdukemtj5jnxz44"),
            {funding_txid: 7})

