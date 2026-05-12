# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import collections
from dataclasses import dataclass
from functools import partial
from typing import Optional, Sequence, Iterable, List, Set, Callable, TypeVar

import aiorpcx
from aiorpcx import RPCError

from electrum import blockchain
from electrum.util import bfh, OrderedSet
from electrum.logging import Logger
from electrum.transaction import Transaction, TxOutput, TxInput, TxOutpoint, PartialTxOutput
from electrum import constants
from electrum.bitcoin import script_to_scripthash, COIN, COINBASE_MATURITY
from electrum.simple_config import SimpleConfig
from electrum.synchronizer import history_status
from electrum.wallet import Abstract_Wallet
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.fee_policy import FixedFeePolicy

from .. import restore_wallet_from_text__for_unittest


DAEMON_ERROR = 2

REGTEST_GENESIS_HEADER = bfh("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000")

T = TypeVar("T")

def topologically_sort_subgraph(
    start_nodes: Iterable[T],
    *,
    get_direct_children: Callable[[T], Iterable[T]],
) -> Sequence[T]:
    # based on pseudo-code in https://en.wikipedia.org/wiki/Topological_sorting#Depth-first_search
    res = OrderedSet()  # "permanent mark"
    seen = set()        # "temporary mark"

    def recurse(node: str):
        if node in res:
            return
        if node in seen:
            raise Exception("cycle detected")
        seen.add(node)
        direct_children = get_direct_children(node)
        for child in direct_children:
            recurse(child)
        res.add(node)

    for start_node in start_nodes:
        if start_node not in res:
            recurse(start_node)
    return list(res)[::-1]



@dataclass(kw_only=True, slots=True, frozen=True)
class FakeBlock:
    header: bytes
    txids: Sequence[str] = None  # FIXME needs OrderedSet with index-based lookup? >.<

    def __post_init__(self):
        if self.txids is None:
            object.__setattr__(self, 'txids', tuple())


class TxConflicts(Exception): pass
class TxConflictsMempool(TxConflicts): pass
class TxConflictsBlockchain(TxConflicts): pass


class ToyServer(Logger):
    """Electrum Server backend"""

    asyncio_server: asyncio.base_events.Server
    server_port: int
    min_relay_feerate = 2000  # in satoshi per kvbyte

    def __init__(self):
        Logger.__init__(self)
        self.sessions = set()  # type: Set[ToyServerSession]
        self._blocks = [FakeBlock(header=REGTEST_GENESIS_HEADER)]  # type: list[FakeBlock]

        # indexes:
        self.sh_to_funding_txids = collections.defaultdict(set)  # type: dict[str, set[str]]
        self.sh_to_spending_txids = collections.defaultdict(set)  # type: dict[str, set[str]]
        self.txs = {}  # type: dict[str, bytes]  # txid->raw_tx
        self._cache_blockheight_and_pos_from_txid = {}  # type: dict[str, tuple[int, int]]
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

    def block_height_and_pos_from_txid(self, txid: str) -> Optional[tuple[int, int]]:  # FIXME slow
        # check cache first
        if (bh_and_pos := self._cache_blockheight_and_pos_from_txid.get(txid)) is not None:
            height, pos = bh_and_pos
            if (len(self._blocks) > height
                and len(self._blocks[height].txids) > pos
                and txid == self._blocks[height].txids[pos]
            ):
                # valid cache hit
                return height, pos
            else:  # stale cache
                self._cache_blockheight_and_pos_from_txid.pop(txid)
        # linear search
        for height, block in enumerate(self._blocks):
            for pos, txid2 in enumerate(block.txids):
                if txid == txid2:
                    self._cache_blockheight_and_pos_from_txid[txid] = height, pos
                    return height, pos
        return None

    def block_height_from_txid(self, txid: str) -> Optional[int]:
        bh_and_pos = self.block_height_and_pos_from_txid(txid)
        if bh_and_pos is None:
            return None
        bh, pos = bh_and_pos
        return bh

    def get_mempool_txids(self) -> set[str]:  # FIXME slow
        mempool = set()
        for txid in self.txs:
            if self.block_height_from_txid(txid) is None:
                mempool.add(txid)
        return mempool

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

    def _has_unconfirmed_inputs(self, txid: str) -> bool:
        tx = Transaction(self.txs[txid])
        return any(self.block_height_from_txid(txin.prevout.txid.hex()) is None for txin in tx.inputs())

    def calc_sh_history(self, sh: str) -> Sequence[tuple[str, int]]:
        txids = self.sh_to_funding_txids[sh] | self.sh_to_spending_txids[sh]
        hist1 = []
        for txid in txids:
            bh_and_pos = self.block_height_and_pos_from_txid(txid)
            if bh_and_pos is None:
                bh_and_pos = (0, 0) if not self._has_unconfirmed_inputs(txid) else (-1, 0)
            hist1.append((txid, bh_and_pos))

        def sort_key(x):
            txid, (bh, pos) = x
            if bh <= 0:
                bh = 10**9 - bh
            return bh, pos, txid

        hist1.sort(key=sort_key)
        hist2 = [(txid, bh) for (txid, (bh, pos)) in hist1]
        return hist2

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
        if txid in self.txs:  # already added
            funded_sh, spent_sh = self._get_funded_and_spent_scripthashes(tx)
            return funded_sh | spent_sh
        # we forbid conflicting txs. for mempool replacement, the caller must already have rm-ed the conflicts.
        conflict_txids = self._get_transitive_conflict_txids(tx)
        assert not conflict_txids, "tx conflict"
        self.logger.debug(f"_add_tx: {txid}")
        # update txid->tx map
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
                raise Exception(f"cannot spend non-existent UTXO: {txin.prevout}")
            elif double_spender_txid is None:  # UTXO exists and is unspent
                self.txo_to_spender_txid[txin.prevout] = txid
            elif double_spender_txid == txid:
                raise Exception("TXO already marked as spent by same txid?")
            else:
                raise Exception(f"cannot double-spend UTXO: {txin.prevout}. conflict: {txid} vs {double_spender_txid}")
        # update touched scripthashes
        funded_sh, spent_sh = self._get_funded_and_spent_scripthashes(tx)
        for sh in funded_sh:
            self.sh_to_funding_txids[sh].add(txid)
        for sh in spent_sh:
            self.sh_to_spending_txids[sh].add(txid)
        return funded_sh | spent_sh

    def _remove_tx_that_has_no_children(self, tx: Transaction) -> set[str]:
        txid = tx.txid()
        assert txid
        self.logger.debug(f"_remove_tx_that_has_no_children: {txid}")
        assert self.block_height_from_txid(txid) is None, "tx already mined"
        self.txs.pop(txid)
        # un-fund UTXOs
        for txout_idx, txout in enumerate(tx.outputs()):
            outpoint = TxOutpoint(txid=bfh(txid), out_idx=txout_idx)
            assert self.txo_to_spender_txid[outpoint] is None, "output already spent"
            self.txo_to_spender_txid.pop(outpoint)
        # un-spend UTXOs
        for txin in tx.inputs():
            if txin.is_coinbase_input():
                continue
            assert self.txo_to_spender_txid[txin.prevout] == txid
            self.txo_to_spender_txid[txin.prevout] = None
        # update touched scripthashes
        funded_sh, spent_sh = self._get_funded_and_spent_scripthashes(tx)
        for sh in funded_sh:
            self.sh_to_funding_txids[sh].discard(txid)
        for sh in spent_sh:
            self.sh_to_spending_txids[sh].discard(txid)
        return funded_sh | spent_sh

    def _remove_tx_and_all_children(self, tx: Transaction) -> set[str]:
        txid = tx.txid()
        assert txid
        assert txid in self.txs, "unknown tx"
        children = self._get_transitive_children_txids(txid)
        touched_sh = set()
        for txid in children:
            tx = Transaction(self.txs[txid])
            touched_sh |= self._remove_tx_that_has_no_children(tx)
        return touched_sh

    def _get_direct_children_txids(self, txid: str) -> Sequence[str]:
        res = []
        tx = Transaction(self.txs[txid])
        for txout_idx, txout in enumerate(tx.outputs()):
            outpoint = TxOutpoint(txid=bfh(txid), out_idx=txout_idx)
            if spender_txid := self.txo_to_spender_txid[outpoint]:
                res.append(spender_txid)
        return res

    def _get_transitive_children_txids(self, txid: str) -> Sequence[str]:
        """Returns all (grand-)children, including orig tx.
        Topologically sorted, children first.
        """
        return topologically_sort_subgraph([txid], get_direct_children=self._get_direct_children_txids)[::-1]

    def _get_direct_conflict_txids(self, tx: Transaction, *, include_self: bool = True) -> Sequence[str]:
        txid = tx.txid()
        assert txid
        res = []
        for txin in tx.inputs():
            if txin.is_coinbase_input():
                continue
            if double_spender_txid := self.txo_to_spender_txid.get(txin.prevout, None):
                if double_spender_txid != txid or include_self:
                    res.append(double_spender_txid)
        return res

    def _get_transitive_conflict_txids(self, tx: Transaction, *, include_self: bool = True) -> Iterable[str]:
        res = set()
        for direct_conflict in self._get_direct_conflict_txids(tx, include_self=include_self):
            res |= set(self._get_transitive_children_txids(direct_conflict))
        return res

    def _txs_from_txids(self, txids: Iterable[str]) -> Iterable[Transaction]:
        return [Transaction(self.txs[txid]) for txid in txids]

    def _get_fee_sat_paid_by_tx(self, tx: Transaction) -> int:
        input_sum = 0
        for txin in tx.inputs():
            parent_tx_raw = self.txs[txin.prevout.txid.hex()]  # parent must not be missing!
            parent_tx = Transaction(parent_tx_raw)
            ptxout = parent_tx.outputs()[txin.prevout.out_idx]
            input_sum += ptxout.value
        return input_sum - tx.output_value()

    async def mempool_add_tx(self, newtx: Transaction) -> None:
        touched_sh = set()
        conflict_txids = self._get_transitive_conflict_txids(newtx, include_self=False)
        conflict_txs = self._txs_from_txids(conflict_txids)
        if conflict_txids:
            if any(self.block_height_from_txid(txid) is not None for txid in conflict_txids):
                raise TxConflictsBlockchain()
            conflict_wu = sum(tx.estimated_weight() for tx in conflict_txs)
            conflict_fee = sum(self._get_fee_sat_paid_by_tx(tx) for tx in conflict_txs)
            conflict_sat_per_kvbyte = 4000 * conflict_fee // conflict_wu
            repl_fee = self._get_fee_sat_paid_by_tx(newtx)
            repl_sat_per_kvbyte = 4000 * repl_fee // newtx.estimated_weight()
            # our mempool replacement policy is simple but still similar to bitcoin core:
            if not (
                repl_fee > conflict_fee
                and repl_sat_per_kvbyte >= conflict_sat_per_kvbyte + self.min_relay_feerate
            ):
                raise TxConflictsMempool(f"mempool conflict. {len(conflict_txs)=}. {repl_fee=}, {conflict_fee=}. {repl_sat_per_kvbyte=}, {conflict_sat_per_kvbyte=}")
            # rm conflicts
            for tx in conflict_txs:
                if tx.txid() in self.txs:  # might already be removed in an earlier loop iter
                    touched_sh = self._remove_tx_and_all_children(tx)
        # no more conflicts. add new tx.
        touched_sh |= self._add_tx(newtx)
        # notify clients
        for session in self.sessions:
            await session.server_send_notifications(touched_sh=touched_sh)

    async def mempool_rm_tx(self, tx: Transaction) -> None:
        txid = tx.txid()
        assert txid
        assert txid in self.txs, "unknown tx"
        assert self.block_height_from_txid(txid) is None, "tx already mined"
        touched_sh = self._remove_tx_and_all_children(tx)
        # notify clients
        for session in self.sessions:
            await session.server_send_notifications(touched_sh=touched_sh)

    async def mine_block(
        self,
        *,
        coinbase_outputs: Iterable[TxOutput] = None,
        include_mempool: bool = True,  # whether to mine (all) txs in the mempool
        extra_txs: Iterable[Transaction] = None,  # additional txs to mine. can overlap with mempool
    ) -> tuple[FakeBlock, Transaction]:
        if extra_txs is None:
            extra_txs = []
        coinbase_tx = Transaction(None)
        coinbase_tx._inputs = [TxInput(prevout=TxOutpoint(txid=bytes(32), out_idx=0xffffffff))]
        coinbase_tx._outputs = list(coinbase_outputs or []) + [TxOutput(scriptpubkey=bfh("6a04deadbeef"), value=0)]
        coinbase_tx._locktime = self.cur_height  # to prevent duplicate txids (our fake coinbase txs are low-entropy)
        txs = OrderedSet()  # type: OrderedSet[Transaction]
        txs.add(coinbase_tx)
        txs |= OrderedSet(extra_txs)
        if include_mempool:
            for mempool_txid in self.get_mempool_txids():
                mempool_tx = Transaction(self.txs[mempool_txid])
                txs.add(mempool_tx)
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

    async def unmine_block(self) -> None:
        if self.cur_height == 0:
            raise Exception("cannot unmine genesis")
        # Simply pop the block from the chain.
        block = self._blocks.pop()
        # process txs
        # note: all txs in that block are now automatically considered to be in-mempool.
        #       no need to call _remove_tx -- that would also rm them from the mempool.
        touched_sh = set()
        for txid in block.txids:
            tx = Transaction(self.txs[txid])
            funded_sh, spent_sh = self._get_funded_and_spent_scripthashes(tx)
            touched_sh |= funded_sh | spent_sh
        # notify clients
        for session in self.sessions:
            await session.server_send_notifications(touched_sh=touched_sh, height_changed=True)

    async def set_up_faucet(self, *, config: SimpleConfig):
        assert self._faucet_w is None
        # FIXME we should give the faucet multiple UTXOs so that later it won't have to chain unconfirmed txs
        #       but this is broken atm: the faucet does not have a network so can't know which coins are mined.
        #       faucet_w considers all its UTXOs to be unconfirmed.
        num_starting_utxos = 2
        self._faucet_w = restore_wallet_from_text__for_unittest(
            "9dk", passphrase="faucet", path=None, config=config, gap_limit=num_starting_utxos)['wallet']  # type: Abstract_Wallet
        self._faucet_w.adb.get_local_height = lambda *args: self.cur_height
        for faucet_addr in self._faucet_w.get_receiving_addresses():
            block, cb_tx = await self.mine_block(coinbase_outputs=[TxOutput.from_address_and_value(faucet_addr, 50 * COIN)])
            self._faucet_w.adb.receive_tx_callback(cb_tx, tx_height=self.cur_height)
        for _ in range(COINBASE_MATURITY):  # need to mine some blocks for maturity
            await self.mine_block()
        # note: balance is unverified due to lack of SPV, gets treated as "unconfirmed":
        assert self._faucet_w.get_balance() == (0, 50 * COIN * num_starting_utxos, 0), self._faucet_w.get_balance()

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
            "mempoolminfee": self.svr.min_relay_feerate / COIN,
            "minrelaytxfee": self.svr.min_relay_feerate / COIN,
            "incrementalrelayfee": self.svr.min_relay_feerate / COIN,
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
        try:
            await self.svr.mempool_add_tx(tx)  # TODO don't await, just queue up? this sends notifs before response, lol
        except TxConflicts as e:
            raise RPCError(DAEMON_ERROR, str(e)) from e
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

