import asyncio
import collections

import aiorpcx
from aiorpcx import RPCError

import electrum
from electrum.interface import ServerAddr, Interface, PaddedRSTransport
from electrum import util, blockchain
from electrum.util import OldTaskGroup, bfh
from electrum.logging import Logger
from electrum.simple_config import SimpleConfig
from electrum.transaction import Transaction
from electrum import constants

from . import ElectrumTestCase


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


# regtest chain:
BLOCK_HEADERS = {
    0: bfh("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000"),
    1: bfh("0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f186c8dfd970a4545f79916bc1d75c9d00432f57c89209bf3bb115b7612848f509c25f45bffff7f2000000000"),
    2: bfh("00000020686bdfc6a3db73d5d93e8c9663a720a26ecb1ef20eb05af11b36cdbc57c19f7ebf2cbf153013a1c54abaf70e95198fcef2f3059cc6b4d0f7e876808e7d24d11cc825f45bffff7f2000000000"),
    3: bfh("00000020122baa14f3ef54985ae546d1611559e3f487bd2a0f46e8dbb52fbacc9e237972e71019d7feecd9b8596eca9a67032c5f4641b23b5d731dc393e37de7f9c2f299e725f45bffff7f2000000000"),
    4: bfh("00000020f8016f7ef3a17d557afe05d4ea7ab6bde1b2247b7643896c1b63d43a1598b747a3586da94c71753f27c075f57f44faf913c31177a0957bbda42e7699e3a2141aed25f45bffff7f2001000000"),
    5: bfh("000000201d589c6643c1d121d73b0573e5ee58ab575b8fdf16d507e7e915c5fbfbbfd05e7aee1d692d1615c3bdf52c291032144ce9e3b258a473c17c745047f3431ff8e2ee25f45bffff7f2000000000"),
    6: bfh("00000020b833ed46eea01d4c980f59feee44a66aa1162748b6801029565d1466790c405c3a141ce635cbb1cd2b3a4fcdd0a3380517845ba41736c82a79cab535d31128066526f45bffff7f2001000000"),
    7: bfh("00000020abe8e119d1877c9dc0dc502d1a253fb9a67967c57732d2f71ee0280e8381ff0a9690c2fe7c1a4450c74dc908fe94dd96c3b0637d51475e9e06a78e944a0c7fe28126f45bffff7f2000000000"),
    8: bfh("000000202ce41d94eb70e1518bc1f72523f84a903f9705d967481e324876e1f8cf4d3452148be228a4c3f2061bafe7efdfc4a8d5a94759464b9b5c619994d45dfcaf49e1a126f45bffff7f2000000000"),
    9: bfh("00000020552755b6c59f3d51e361d16281842a4e166007799665b5daed86a063dd89857415681cb2d00ff889193f6a68a93f5096aeb2d84ca0af6185a462555822552221a626f45bffff7f2000000000"),
    10: bfh("00000020a13a491cbefc93cd1bb1938f19957e22a134faf14c7dee951c45533e2c750f239dc087fc977b06c24a69c682d1afd1020e6dc1f087571ccec66310a786e1548fab26f45bffff7f2000000000"),
    11: bfh("00000020dbf3a9b55dfefbaf8b6e43a89cf833fa2e208bbc0c1c5d76c0d71b9e4a65337803b243756c25053253aeda309604363460a3911015929e68705bd89dff6fe064b026f45bffff7f2002000000"),
    12: bfh("000000203d0932b3b0c78eccb39a595a28ae4a7c966388648d7783fd1305ec8d40d4fe5fd67cb902a7d807cee7676cb543feec3e053aa824d5dfb528d5b94f9760313d9db726f45bffff7f2001000000"),
}

_active_server_sessions = set()
def _get_active_server_session() -> 'ServerSession':
    assert 1 == len(_active_server_sessions), len(_active_server_sessions)
    return list(_active_server_sessions)[0]

class ServerSession(aiorpcx.RPCSession, Logger):

    def __init__(self, *args, **kwargs):
        aiorpcx.RPCSession.__init__(self, *args, **kwargs)
        Logger.__init__(self)
        self.logger.debug(f'connection from {self.remote_address()}')
        self.cur_height = 6  # type: int  # chain tip
        self.txs = {
            "bdae818ad3c1f261317738ae9284159bf54874356f186dbc7afd631dc1527fcb": bfh("020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a010000001600140297bde2689a3c79ffe050583b62f86f2d9dae540000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"),
        }  # type: dict[str, bytes]
        self._method_counts = collections.defaultdict(int)  # type: dict[str, int]
        _active_server_sessions.add(self)

    async def connection_lost(self):
        await super().connection_lost()
        self.logger.debug(f'{self.remote_address()} disconnected')
        _active_server_sessions.discard(self)

    async def handle_request(self, request):
        handlers = {
            'server.version': self._handle_server_version,
            'server.features': self._handle_server_features,
            'blockchain.estimatefee': self._handle_estimatefee,
            'blockchain.headers.subscribe': self._handle_headers_subscribe,
            'blockchain.block.header': self._handle_block_header,
            'blockchain.block.headers': self._handle_block_headers,
            'blockchain.transaction.get': self._handle_transaction_get,
            'blockchain.transaction.broadcast': self._handle_transaction_broadcast,
            'server.ping': self._handle_ping,
        }
        handler = handlers.get(request.method)
        self._method_counts[request.method] += 1
        coro = aiorpcx.handler_invocation(handler, request)()
        return await coro

    async def _handle_server_version(self, client_name='', protocol_version=None):
        return ['best_server_impl/0.1', '1.4']

    async def _handle_server_features(self) -> dict:
        return {
            'genesis_hash': constants.net.GENESIS,
            'hosts': {"14.3.140.101": {"tcp_port": 51001, "ssl_port": 51002}},
            'protocol_max': '1.7.0',
            'protocol_min': '1.4.3',
            'pruning': None,
            'server_version': 'ElectrumX 1.19.0',
            'hash_function': 'sha256',
        }

    async def _handle_estimatefee(self, number, mode=None):
        return 1000

    async def _handle_headers_subscribe(self):
        return {'hex': BLOCK_HEADERS[self.cur_height].hex(), 'height': self.cur_height}

    async def _handle_block_header(self, height):
        return BLOCK_HEADERS[height].hex()

    async def _handle_block_headers(self, start_height, count):
        assert start_height <= self.cur_height, (start_height, self.cur_height)
        last_height = min(start_height+count-1, self.cur_height)  # [start_height, last_height]
        count = last_height - start_height + 1
        headers = b"".join(BLOCK_HEADERS[idx] for idx in range(start_height, last_height+1))
        return {'hex': headers.hex(), 'count': count, 'max': 2016}

    async def _handle_ping(self):
        return None

    async def _handle_transaction_get(self, tx_hash: str, verbose=False):
        assert not verbose
        rawtx = self.txs.get(tx_hash)
        if rawtx is None:
            DAEMON_ERROR = 2
            raise RPCError(DAEMON_ERROR, f'daemon error: unknown txid={tx_hash}')
        return rawtx.hex()

    async def _handle_transaction_broadcast(self, raw_tx: str):
        tx = Transaction(raw_tx)
        self.txs[tx.txid()] = bfh(raw_tx)
        return tx.txid()


class TestInterface(ElectrumTestCase):
    REGTEST = True

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self._orig_WAIT_FOR_BUFFER_GROWTH_SECONDS = PaddedRSTransport.WAIT_FOR_BUFFER_GROWTH_SECONDS
        PaddedRSTransport.WAIT_FOR_BUFFER_GROWTH_SECONDS = 0

    def tearDown(self):
        PaddedRSTransport.WAIT_FOR_BUFFER_GROWTH_SECONDS = self._orig_WAIT_FOR_BUFFER_GROWTH_SECONDS
        super().tearDown()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self._server: asyncio.base_events.Server = await aiorpcx.serve_rs(ServerSession, "127.0.0.1")
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
        self.network.interface = interface
        await util.wait_for2(interface.ready, 5)
        await interface._blockchain_updated.wait()
        return interface

    async def test_client_syncs_headers_to_tip(self):
        interface = await self._start_iface_and_wait_for_sync()
        self.assertEqual(_get_active_server_session().cur_height, interface.tip)
        self.assertFalse(interface.got_disconnected.is_set())

    async def test_transaction_get(self):
        interface = await self._start_iface_and_wait_for_sync()
        # try requesting tx unknown to server:
        with self.assertRaises(RPCError) as ctx:
            await interface.get_transaction("deadbeef"*8)
        self.assertTrue("unknown txid" in ctx.exception.message)
        # try requesting known tx:
        rawtx = await interface.get_transaction("bdae818ad3c1f261317738ae9284159bf54874356f186dbc7afd631dc1527fcb")
        self.assertEqual(rawtx, _get_active_server_session().txs["bdae818ad3c1f261317738ae9284159bf54874356f186dbc7afd631dc1527fcb"].hex())
        self.assertEqual(_get_active_server_session()._method_counts["blockchain.transaction.get"], 2)

    async def test_transaction_broadcast(self):
        interface = await self._start_iface_and_wait_for_sync()
        rawtx1 = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025200ffffffff0200f2052a010000001600140297bde2689a3c79ffe050583b62f86f2d9dae540000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"
        tx = Transaction(rawtx1)
        # broadcast
        await interface.broadcast_transaction(tx)
        self.assertEqual(bfh(rawtx1), _get_active_server_session().txs.get(tx.txid()))
        # now request tx.
        # as we just broadcast this same tx, this will hit the client iface cache, and won't call the server.
        self.assertEqual(_get_active_server_session()._method_counts["blockchain.transaction.get"], 0)
        rawtx2 = await interface.get_transaction(tx.txid())
        self.assertEqual(rawtx1, rawtx2)
        self.assertEqual(_get_active_server_session()._method_counts["blockchain.transaction.get"], 0)
