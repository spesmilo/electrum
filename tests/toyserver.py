# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import collections
from dataclasses import dataclass
from functools import partial
from typing import Optional, Sequence, Iterable, List, Set

import aiorpcx
from aiorpcx import RPCError

from electrum import blockchain
from electrum.util import bfh
from electrum.logging import Logger
from electrum.transaction import Transaction, TxOutput, TxInput, TxOutpoint, PartialTxOutput
from electrum import constants
from electrum.bitcoin import script_to_scripthash, COIN, COINBASE_MATURITY
from electrum.simple_config import SimpleConfig
from electrum.synchronizer import history_status
from electrum.wallet import Abstract_Wallet
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.fee_policy import FixedFeePolicy

from . import restore_wallet_from_text__for_unittest


DAEMON_ERROR = 2

REGTEST_GENESIS_HEADER = bfh("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000")


@dataclass(kw_only=True, slots=True, frozen=True)
class FakeBlock:
    header: bytes
    txids: Sequence[str] = ()


class ToyServer:
    """Electrum Server backend"""

    asyncio_server: asyncio.base_events.Server
    server_port: int

    def __init__(self):
        self.sessions = set()  # type: Set[ToyServerSession]
        self._blocks = [FakeBlock(header=REGTEST_GENESIS_HEADER)]  # type: list[FakeBlock]

        # indexes:
        self.sh_to_funding_txids = collections.defaultdict(set)  # type: dict[str, set[str]]
        self.sh_to_spending_txids = collections.defaultdict(set)  # type: dict[str, set[str]]
        self.txs = {}  # type: dict[str, bytes]
        self._cache_blockheight_from_txid = {}  # type: dict[str, int]
        self.txo_to_spender_txid = {}  # type: dict[TxOutpoint, str | None]  # also contains UTXOs

        self._faucet_w = None  # type: Optional[Abstract_Wallet]

    async def start(self):
        session_factory = partial(ToyServerSession, toyserver=self)
        self.asyncio_server = await aiorpcx.serve_rs(session_factory, "127.0.0.1")
        server_socket_addr = self.asyncio_server.sockets[0].getsockname()
        self.server_port = server_socket_addr[1]

    async def stop(self):
        self.asyncio_server.close()
        await self.asyncio_server.wait_closed()

    def block_height_from_txid(self, txid: str) -> Optional[int]:
        # check cache first
        if height := self._cache_blockheight_from_txid.get(txid) is not None:
            if len(self._blocks) > height and txid in self._blocks[height].txids:
                # valid cache hit
                return height
            else:  # stale cache
                self._cache_blockheight_from_txid.pop(txid)
        # linear search
        for height, block in enumerate(self._blocks):
            if txid in block.txids:
                self._cache_blockheight_from_txid[txid] = height
                return height
        return None

    def get_session_by_name(self, client_name: str) -> 'ToyServerSession':
        found_sessions = [
            session for session in self.sessions
            if session.client_name == client_name]
        if len(found_sessions) > 1:
            raise Exception("multiple sessions reusing client_name")
        elif len(found_sessions) == 0:
            raise Exception("no session with given client_name")
        else:
            assert len(found_sessions) == 1
            return found_sessions[0]

    @property
    def cur_height(self) -> int:
        """chain tip"""
        return len(self._blocks) - 1

    def get_block_header(self, height: int) -> bytes:
        return self._blocks[height].header

    def calc_sh_history(self, sh: str) -> Sequence[tuple[str, int]]:
        txids = self.sh_to_funding_txids[sh] | self.sh_to_spending_txids[sh]
        hist = []
        for txid in txids:
            bh = self.block_height_from_txid(txid) or 0
            hist.append((txid, bh))
        hist.sort(key=lambda x: x[1])  # FIXME put mempool txs last
        return hist

    def _get_funded_and_spent_scripthashes(self, tx: Transaction) -> tuple[set[str], set[str]]:
        """Returns scripthashes touched by tx."""
        txid = tx.txid()
        assert txid
        funded_sh = set()
        for txout in tx.outputs():
            sh = script_to_scripthash(txout.scriptpubkey)
            funded_sh.add(sh)
        spent_sh = set()
        for txin in tx.inputs():
            if txin.is_coinbase_input():
                continue
            parent_tx_raw = self.txs[txin.prevout.txid.hex()]  # parent must not be missing!
            parent_tx = Transaction(parent_tx_raw)
            ptxout = parent_tx.outputs()[txin.prevout.out_idx]
            sh = script_to_scripthash(ptxout.scriptpubkey)
            spent_sh.add(sh)
        return funded_sh, spent_sh

    def _add_tx(self, tx: Transaction) -> set[str]:
        txid = tx.txid()
        assert txid
        self.txs[txid] = bfh(str(tx))
        # fund UTXOs
        for txout_idx, txout in enumerate(tx.outputs()):
            outpoint = TxOutpoint(txid=bfh(txid), out_idx=txout_idx)
            self.txo_to_spender_txid[outpoint] = None
        # spend UTXOs
        for txin in tx.inputs():
            if txin.is_coinbase_input():
                continue
            double_spender_txid = self.txo_to_spender_txid.get(txin.prevout, ...)
            if double_spender_txid is ...:
                raise RPCError(DAEMON_ERROR, f"cannot spend non-existent UTXO: {txin.prevout}")
            elif double_spender_txid is None:  # UTXO exists and is unspent
                self.txo_to_spender_txid[txin.prevout] = txid
            elif double_spender_txid == txid:  # already marked?
                pass                           # (duplicate calls, e.g. when added to mempool, and when mined)
            else:  # conflict
                raise RPCError(DAEMON_ERROR, f"cannot double-spend UTXO: {txin.prevout}. conflict: {txid} vs {double_spender_txid}")
        # update touched scripthashes
        funded_sh, spent_sh = self._get_funded_and_spent_scripthashes(tx)
        for sh in funded_sh:
            self.sh_to_funding_txids[sh].add(txid)
        for sh in spent_sh:
            self.sh_to_spending_txids[sh].add(txid)
        return funded_sh | spent_sh

    async def mempool_add_tx(self, tx: Transaction) -> None:
        touched_sh = self._add_tx(tx)
        # notify clients
        for session in self.sessions:
            await session.server_send_notifications(touched_sh=touched_sh)

    async def mine_block(
        self,
        *,
        txs: Iterable[Transaction] = None,
        coinbase_outputs: Iterable[TxOutput] = None,  # hmhm maturity?
    ) -> tuple[FakeBlock, Transaction]:
        if txs is None:
            txs = []
        coinbase_tx = Transaction(None)
        coinbase_tx._inputs = [TxInput(prevout=TxOutpoint(txid=bytes(32), out_idx=0xffffffff))]
        coinbase_tx._outputs = list(coinbase_outputs or []) + [TxOutput(scriptpubkey=bfh("6a04deadbeef"), value=0)]
        txs = [coinbase_tx] + txs
        assert not any(tx.txid() is None for tx in txs)
        # new header
        prev_header = self._blocks[-1].header
        prev_blockhash = blockchain.hash_raw_header(prev_header)
        new_header = blockchain.serialize_header({
            'version': 99999,  # don't care
            'prev_block_hash': prev_blockhash,
            'merkle_root': 'deadbeef' * 8,  # don't care
            'timestamp': 1_500_000_000,  # don't care
            'bits': 0x1d00ffff,  # don't care
            'nonce': 1,  # don't care
        })
        new_block = FakeBlock(header=new_header, txids=tuple(tx.txid() for tx in txs))
        self._blocks.append(new_block)
        # process txs
        touched_sh = set()
        for tx in txs:
            touched_sh |= self._add_tx(tx)
        # notify clients
        for session in self.sessions:
            await session.server_send_notifications(touched_sh=touched_sh, height_changed=True)
        return new_block, coinbase_tx

    async def set_up_faucet(self, *, config: SimpleConfig):
        assert self._faucet_w is None
        self._faucet_w = restore_wallet_from_text__for_unittest(
            "9dk", passphrase="faucet", path=None, config=config)['wallet']  # type: Abstract_Wallet
        self._faucet_w.adb.get_local_height = lambda *args: self.cur_height
        faucet_cb_txo = TxOutput.from_address_and_value(self._faucet_w.get_receiving_address(), 50 * COIN)
        block, cb_tx = await self.mine_block(coinbase_outputs=[faucet_cb_txo])
        faucet_tx_height = self.cur_height
        for _ in range(COINBASE_MATURITY):  # need to mine some blocks for maturity
            await self.mine_block()
        self._faucet_w.adb.receive_tx_callback(cb_tx, tx_height=faucet_tx_height)
        # note: balance is unverified due to lack of SPV, gets treated as "unconfirmed":
        assert self._faucet_w.get_balance() == (0, 50 * COIN, 0), self._faucet_w.get_balance()

    async def ask_faucet(self, outputs: Sequence[TxOutput]) -> Transaction:
        assert self._faucet_w, "faucet must be set up first using set_up_faucet()"
        outputs = [PartialTxOutput.from_txout(txout) for txout in outputs]
        tx = self._faucet_w.make_unsigned_transaction(outputs=outputs, fee_policy=FixedFeePolicy(0))
        self._faucet_w.sign_transaction(tx, password=None)
        self._faucet_w.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        await self.mempool_add_tx(tx)
        return tx


class ToyServerSession(aiorpcx.RPCSession, Logger):
    """Server-side representation of a single electrum-protocol session."""

    def __init__(self, *args, toyserver: ToyServer, **kwargs):
        aiorpcx.RPCSession.__init__(self, *args, **kwargs)
        Logger.__init__(self)
        self.svr = toyserver
        self.logger.debug(f'connection from {self.remote_address()}')
        self.subbed_headers = False
        self.notified_height = None  # type: Optional[int]
        self.subbed_scripthashes = set()  # type: set[str]
        self._method_counts = collections.defaultdict(int)  # type: dict[str, int]
        self.client_name = None
        self.svr.sessions.add(self)

    async def connection_lost(self):
        await super().connection_lost()
        self.logger.debug(f'{self.remote_address()} disconnected')
        self.svr.sessions.discard(self)

    async def handle_request(self, request):
        handlers = {
            'server.version': self._handle_server_version,
            'server.features': self._handle_server_features,
            'blockchain.estimatefee': self._handle_estimatefee,
            'blockchain.headers.subscribe': self._handle_headers_subscribe,
            'blockchain.block.header': self._handle_block_header,
            'blockchain.block.headers': self._handle_block_headers,
            'blockchain.scripthash.subscribe': self._handle_scripthash_subscribe,
            'blockchain.scripthash.get_history': self._handle_scripthash_get_history,
            'blockchain.transaction.get': self._handle_transaction_get,
            'blockchain.transaction.broadcast': self._handle_transaction_broadcast,
            'blockchain.transaction.get_merkle': self._handle_transaction_get_merkle,
            'mempool.get_info': self._handle_mempool_get_info,
            'server.ping': self._handle_ping,
        }
        handler = handlers.get(request.method)
        self._method_counts[request.method] += 1
        coro = aiorpcx.handler_invocation(handler, request)()
        return await coro

    async def _handle_server_version(self, client_name='', protocol_version=None, *args, **kwargs):
        self.client_name = client_name
        return ['toyserver/0.1', '1.6']

    async def _handle_server_features(self) -> dict:
        return {
            'genesis_hash': constants.net.GENESIS,
            'hosts': {"14.3.140.101": {"tcp_port": 51001, "ssl_port": 51002}},
            'protocol_max': '1.6',
            'protocol_min': '1.6',
            'pruning': None,
            'server_version': 'ElectrumX 1.19.0',
            'hash_function': 'sha256',
        }

    async def _handle_estimatefee(self, number, mode=None):
        return 0.00001000

    async def _handle_mempool_get_info(self):
        return {
            "mempoolminfee": 0.00001000,
            "minrelaytxfee": 0.00001000,
            "incrementalrelayfee": 0.00001000,
        }

    def _get_headersub_result(self):
        height = self.svr.cur_height
        return {'hex': self.svr.get_block_header(height).hex(), 'height': height}

    async def _handle_headers_subscribe(self):
        self.subbed_headers = True
        return self._get_headersub_result()

    async def _handle_block_header(self, height):
        return self.svr.get_block_header(height).hex()

    async def _handle_block_headers(self, start_height, count):
        cur_height = self.svr.cur_height
        assert start_height <= cur_height, (start_height, cur_height)
        last_height = min(start_height+count-1, cur_height)  # [start_height, last_height]
        count = last_height - start_height + 1
        headers = list(self.svr.get_block_header(idx).hex() for idx in range(start_height, last_height + 1))
        return {'headers': headers, 'count': count, 'max': 2016}

    async def _handle_ping(self):
        return None

    async def _handle_transaction_get(self, tx_hash: str, verbose=False):
        assert not verbose
        rawtx = self.svr.txs.get(tx_hash)
        if rawtx is None:
            raise RPCError(DAEMON_ERROR, f'daemon error: unknown txid={tx_hash}')
        return rawtx.hex()

    async def _handle_transaction_get_merkle(self, tx_hash: str, height: int) -> dict:
        # Fake stuff. Client will ignore it due to config.NETWORK_SKIPMERKLECHECK
        return {
            "merkle":
            [
                "713d6c7e6ce7bbea708d61162231eaa8ecb31c4c5dd84f81c20409a90069cb24",
                "03dbaec78d4a52fbaf3c7aa5d3fccd9d8654f323940716ddf5ee2e4bda458fde",
                "e670224b23f156c27993ac3071940c0ff865b812e21e0a162fe7a005d6e57851",
                "369a1619a67c3108a8850118602e3669455c70cdcdb89248b64cc6325575b885",
                "4756688678644dcb27d62931f04013254a62aeee5dec139d1aac9f7b1f318112",
                "7b97e73abc043836fd890555bfce54757d387943a6860e5450525e8e9ab46be5",
                "61505055e8b639b7c64fd58bce6fc5c2378b92e025a02583303f69930091b1c3",
                "27a654ff1895385ac14a574a0415d3bbba9ec23a8774f22ec20d53dd0b5386ff",
                "5312ed87933075e60a9511857d23d460a085f3b6e9e5e565ad2443d223cfccdc",
                "94f60b14a9f106440a197054936e6fb92abbd69d6059b38fdf79b33fc864fca0",
                "2d64851151550e8c4d337f335ee28874401d55b358a66f1bafab2c3e9f48773d"
            ],
            "block_height": height,
            "pos": 710,
        }

    async def _handle_transaction_broadcast(self, raw_tx: str) -> str:
        tx = Transaction(raw_tx)
        txid = tx.txid()
        await self.svr.mempool_add_tx(tx)  # TODO don't await, just queue up? this sends notifs before response, lol
        return txid

    async def _handle_scripthash_subscribe(self, sh: str) -> Optional[str]:
        self.subbed_scripthashes.add(sh)
        hist = self.svr.calc_sh_history(sh)
        return history_status(hist)

    async def _handle_scripthash_get_history(self, sh: str) -> Sequence[dict]:
        hist_tuples = self.svr.calc_sh_history(sh)
        hist_dicts = [{"height": height, "tx_hash": txid} for (txid, height) in hist_tuples]
        for hist_dict in hist_dicts:  # add "fee" key for mempool txs
            if hist_dict["height"] in (0, -1,):
                hist_dict["fee"] = 0
        return hist_dicts

    async def server_send_notifications(self, *, touched_sh: Iterable[str], height_changed: bool = False) -> None:
        if height_changed and self.subbed_headers and self.notified_height != self.svr.cur_height:
            self.notified_height = self.svr.cur_height
            args = (self._get_headersub_result(),)
            await self.send_notification('blockchain.headers.subscribe', args)
        touched_sh = set(sh for sh in touched_sh if sh in self.subbed_scripthashes)
        for sh in touched_sh:
            hist = self.svr.calc_sh_history(sh)
            args = (sh, history_status(hist))
            await self.send_notification("blockchain.scripthash.subscribe", args)

