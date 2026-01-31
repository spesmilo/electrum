import electrum_ecc as ecc

from electrum import bitcoin
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.bitcoin import COIN, construct_script, opcodes
from electrum.fee_policy import FixedFeePolicy
from electrum.simple_config import SimpleConfig
from electrum.transaction import PartialTxInput, PartialTxOutput, TxOutput, Transaction
from electrum.wallet import Abstract_Wallet

from .. import ElectrumTestCase
from .. import restore_wallet_from_text__for_unittest
from .toyserver import ToyServer, topologically_sort_subgraph, TxConflicts, TxConflictsBlockchain


class TestToyServer(ElectrumTestCase):
    REGTEST = True

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.toyserver = ToyServer()
        await self.toyserver.start()
        assert self.toyserver.cur_height == 0
        for _ in range(10):  # mine some blocks
            await self.toyserver.mine_block()
        await self.toyserver.set_up_faucet(config=self.config)
        assert len(self.toyserver.get_mempool_txids()) == 0

    async def asyncTearDown(self):
        await self.toyserver.stop()
        await super().asyncTearDown()

    async def test_topological_sort(self):
        graph = {
            "A": ["B", "C"],
            "B": ["X"],
            "C": ["D1"],
            "D1": ["D2"],
            "D2": ["D3"],
            "D3": ["D4"],
            "D4": ["X"],
            "X": ["Y"],
            "Y": [],
        }
        get_direct_children = lambda x: graph[x]
        # note: there are multiple valid orderings, not just the one we assert
        self.assertEqual(
            ["A", "C", "D1", "D2", "D3", "D4", "B", "X", "Y"],
            topologically_sort_subgraph(["A"], get_direct_children=get_direct_children))
        self.assertEqual(
            ["A", "C", "D1", "D2", "D3", "D4", "B", "X", "Y"],
            topologically_sort_subgraph(list(graph), get_direct_children=get_direct_children))

        graph = {
            "B": ["X"],
            "C": ["D1"],
            "D1": ["D2"],
            "D2": ["D3"],
            "D3": ["D4"],
            "D4": ["X"],
            "X": ["Y"],
            "Y": [],
        }
        self.assertEqual(
            ["C", "D1", "D2", "D3", "D4", "B", "X", "Y"],
            topologically_sort_subgraph(["B", "C"], get_direct_children=get_direct_children))


    async def test_basic_mempool_and_mining_txs(self):
        server_height = self.toyserver.cur_height
        self.assertEqual(self.toyserver.get_mempool_txids(), set())
        secret_key = 0
        for cycle in range(2):
            mempool_txids = set()
            # populate mempool
            for _ in range(5):
                secret_key += 1
                spk = construct_script([secret_key * ecc.GENERATOR.get_public_key_bytes(compressed=True), opcodes.OP_CHECKSIG])
                txout = TxOutput(scriptpubkey=spk, value=1 * COIN)
                tx = await self.toyserver.ask_faucet([txout])
                mempool_txids.add(tx.txid())
                self.assertEqual(mempool_txids, self.toyserver.get_mempool_txids())
                self.assertEqual(None, self.toyserver.block_height_from_txid(tx.txid()))
            # mine a block
            await self.toyserver.mine_block()
            server_height += 1
            self.assertEqual(server_height, self.toyserver.cur_height)
            self.assertEqual(set(), self.toyserver.get_mempool_txids())
            for txid in mempool_txids:  # old mempool
                self.assertEqual(server_height, self.toyserver.block_height_from_txid(txid))

    async def test_mempool_replacement(self):
        self.assertEqual(self.toyserver.get_mempool_txids(), set())

        w = restore_wallet_from_text__for_unittest("9dk", path=None, config=self.config, gap_limit=4)['wallet']  # type: Abstract_Wallet
        # fund w
        w_addr0 = w.get_receiving_addresses()[0]
        funding_tx = await self.toyserver.ask_faucet([TxOutput.from_address_and_value(w_addr0, 20 * COIN)])
        w.adb.add_transaction(funding_tx)
        self.assertEqual(self.toyserver.get_mempool_txids(), {funding_tx.txid()})
        # wallet sends all to itself on fresh address: tx1
        w_addr1 = w.get_receiving_addresses()[1]
        tx1 = w.make_unsigned_transaction(
            outputs=[PartialTxOutput.from_address_and_value(w_addr1, "!")], fee_policy=FixedFeePolicy(5000))
        w.sign_transaction(tx1, password=None)
        w.adb.add_transaction(tx1)
        self.assertEqual(self.toyserver._get_transitive_conflict_txids(tx1), set())
        await self.toyserver.mempool_add_tx(tx1)
        self.assertEqual(self.toyserver.get_mempool_txids(), {funding_tx.txid(), tx1.txid()})
        self.assertEqual(self.toyserver._get_transitive_conflict_txids(tx1, include_self=False), set())
        self.assertEqual(self.toyserver._get_transitive_conflict_txids(tx1, include_self=True), {tx1.txid()})
        # wallet sends all to itself on fresh address: tx2
        w_addr2 = w.get_receiving_addresses()[2]
        tx2 = w.make_unsigned_transaction(
            outputs=[PartialTxOutput.from_address_and_value(w_addr2, "!")], fee_policy=FixedFeePolicy(5000))
        w.sign_transaction(tx2, password=None)
        w.adb.add_transaction(tx2)
        self.assertEqual(self.toyserver._get_transitive_conflict_txids(tx2), set())
        await self.toyserver.mempool_add_tx(tx2)
        self.assertEqual(self.toyserver.get_mempool_txids(), {funding_tx.txid(), tx1.txid(), tx2.txid()})

        self.assertEqual(len(w.adb.get_history(w.get_addresses())), 3)

        # -- wallet wants to double-spend tx1 (also invalidating tx2)
        # first, wallet tries tx1b, but uses too low fee
        w.adb.remove_transaction(tx1.txid())
        self.assertEqual(len(w.adb.get_history(w.get_addresses())), 1)
        w_addr3 = w.get_receiving_addresses()[3]
        tx1b = w.make_unsigned_transaction(
            outputs=[PartialTxOutput.from_address_and_value(w_addr3, "!")], fee_policy=FixedFeePolicy(5000))
        w.sign_transaction(tx1b, password=None)
        w.adb.add_transaction(tx1b)
        self.assertEqual(len(w.adb.get_history(w.get_addresses())), 2)
        self.assertEqual(self.toyserver._get_transitive_conflict_txids(tx1b), {tx1.txid(), tx2.txid()})
        with self.assertRaises(TxConflicts):
            await self.toyserver.mempool_add_tx(tx1b)
        self.assertEqual(self.toyserver.get_mempool_txids(), {funding_tx.txid(), tx1.txid(), tx2.txid()})

        # second, wallet tries tx1c, which pays high enough fees for replacement
        w.adb.remove_transaction(tx1b.txid())
        tx1c = w.make_unsigned_transaction(
            outputs=[PartialTxOutput.from_address_and_value(w_addr3, "!")], fee_policy=FixedFeePolicy(10_001))
        w.sign_transaction(tx1c, password=None)
        w.adb.add_transaction(tx1c)
        self.assertEqual(self.toyserver._get_transitive_conflict_txids(tx1c), {tx1.txid(), tx2.txid()})
        await self.toyserver.mempool_add_tx(tx1c)
        self.assertEqual(self.toyserver.get_mempool_txids(), {funding_tx.txid(), tx1c.txid()})

        # mine a block
        await self.toyserver.mine_block()
        self.assertEqual(self.toyserver.get_mempool_txids(), set())
        self.assertEqual(self.toyserver.cur_height, self.toyserver.block_height_from_txid(funding_tx.txid()))
        self.assertEqual(self.toyserver.cur_height, self.toyserver.block_height_from_txid(tx1c.txid()))

        # -- wallet wants to double-spend tx1c - but it is already mined!
        w.adb.remove_transaction(tx1c.txid())
        tx1d = w.make_unsigned_transaction(
            outputs=[PartialTxOutput.from_address_and_value(w_addr3, "!")], fee_policy=FixedFeePolicy(25_000))
        w.sign_transaction(tx1d, password=None)
        w.adb.add_transaction(tx1d)
        self.assertEqual(len(w.adb.get_history(w.get_addresses())), 2)
        self.assertEqual(self.toyserver._get_transitive_conflict_txids(tx1d), {tx1c.txid()})
        with self.assertRaises(TxConflictsBlockchain):
            await self.toyserver.mempool_add_tx(tx1d)
        self.assertEqual(self.toyserver.get_mempool_txids(), set())

    async def test_sort_order_of_scripthash_get_history(self):
        """txs touching a sh, as returned by 'blockchain.scripthash.get_history', must be in a canonical order"""
        # create a "gateway" wallet with many UTXOs, so later it can send without chaining unconfirmed txs
        w_gateway = restore_wallet_from_text__for_unittest(
            "9dk", passphrase="gateway", gap_limit=10, path=None, config=self.config)['wallet']  # type: Abstract_Wallet
        for gateway_addr in w_gateway.get_receiving_addresses():
            tx = await self.toyserver.ask_faucet([TxOutput.from_address_and_value(gateway_addr, 2 * COIN)])
            w_gateway.adb.add_transaction(tx)
        await self.toyserver.mine_block()
        coins_gateway = w_gateway.get_spendable_coins(w_gateway.get_addresses())
        coins_gateway_ctr = -1

        # create target wallet
        w = restore_wallet_from_text__for_unittest("9dk", path=None, config=self.config)['wallet']  # type: Abstract_Wallet
        w_addr0 = w.get_receiving_addresses()[0]
        w_addr1 = w.get_receiving_addresses()[1]

        async def send_1btc_from_gateway_to_target(addr) -> 'Transaction':
            nonlocal coins_gateway_ctr
            coins_gateway_ctr += 1
            tx = w_gateway.make_unsigned_transaction(
                coins=[coins_gateway[coins_gateway_ctr]],
                outputs=[PartialTxOutput.from_address_and_value(addr, 1 * COIN)], fee_policy=FixedFeePolicy(5000))
            w_gateway.sign_transaction(tx, password=None)
            await self.toyserver.mempool_add_tx(tx)
            return tx

        # fund address multiple times in a block
        tx1 = await send_1btc_from_gateway_to_target(w_addr0)
        w.adb.add_transaction(tx1)
        tx2 = await send_1btc_from_gateway_to_target(w_addr0)
        w.adb.add_transaction(tx2)
        tx3 = await send_1btc_from_gateway_to_target(w_addr0)
        w.adb.add_transaction(tx3)

        await self.toyserver.mine_block()

        # fund address once in a new block
        tx4 = await send_1btc_from_gateway_to_target(w_addr0)
        w.adb.add_transaction(tx4)

        await self.toyserver.mine_block()

        # fund address multiple times with mempool txs
        tx5 = await send_1btc_from_gateway_to_target(w_addr0)
        w.adb.add_transaction(tx5)
        tx6 = await send_1btc_from_gateway_to_target(w_addr0)
        w.adb.add_transaction(tx6)
        tx7 = await send_1btc_from_gateway_to_target(w_addr0)
        w.adb.add_transaction(tx7)

        # fund address twice with unconfirmed parent txs
        coins_tx5_out = [c for c in w.get_spendable_coins(domain=[w_addr0]) if c.prevout.txid.hex() == tx5.txid()]
        assert len(coins_tx5_out) == 1
        tx8 = w.make_unsigned_transaction(
            coins=coins_tx5_out,
            outputs=[PartialTxOutput.from_address_and_value(w_addr1, 100_000)], fee_policy=FixedFeePolicy(5000))
        w.sign_transaction(tx8, password=None)
        w.adb.add_transaction(tx8)
        await self.toyserver.mempool_add_tx(tx8)

        coins_tx6_out = [c for c in w.get_spendable_coins(domain=[w_addr0]) if c.prevout.txid.hex() == tx6.txid()]
        assert len(coins_tx6_out) == 1
        tx9 = w.make_unsigned_transaction(
            coins=coins_tx6_out,
            outputs=[PartialTxOutput.from_address_and_value(w_addr1, 100_000)], fee_policy=FixedFeePolicy(5000))
        w.sign_transaction(tx9, password=None)
        w.adb.add_transaction(tx9)
        await self.toyserver.mempool_add_tx(tx9)

        self.assertEqual(len(self.toyserver.get_mempool_txids()), 5)
        # finally, validate "blockchain.scripthash.get_history" sort order
        sh_history = self.toyserver.calc_sh_history(bitcoin.address_to_scripthash(w_addr0))
        self.assertEqual(len(sh_history), 9)
        tx123_A, tx123_B, tx123_C = sorted([tx1.txid(), tx2.txid(), tx3.txid()], key=lambda x: self.toyserver.block_height_and_pos_from_txid(x))
        tx567_A, tx567_B, tx567_C = sorted([tx5.txid(), tx6.txid(), tx7.txid()])
        tx89_A, tx89_B = sorted([tx8.txid(), tx9.txid()])
        self.assertEqual(sh_history, [
            (tx123_A, self.toyserver.cur_height - 1),
            (tx123_B, self.toyserver.cur_height - 1),
            (tx123_C, self.toyserver.cur_height - 1),
            (tx4.txid(), self.toyserver.cur_height),
            (tx567_A, 0),
            (tx567_B, 0),
            (tx567_C, 0),
            (tx89_A, -1),
            (tx89_B, -1),
        ])
