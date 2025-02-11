import unittest
import logging
from unittest import mock
import asyncio

from electrum import storage, bitcoin, keystore, wallet
from electrum import Transaction
from electrum import SimpleConfig
from electrum import util
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_LOCAL
from electrum.transaction import Transaction, PartialTxInput, PartialTxOutput, TxOutpoint
from electrum.logging import console_stderr_handler, Logger
from electrum.submarine_swaps import SwapManager, SwapData
from electrum.lnsweep import SweepInfo

from . import ElectrumTestCase
from .test_wallet_vertical import WalletIntegrityHelper

class MockNetwork(Logger):

    def __init__(self, config):
        self.config = config
        self.asyncio_loop = util.get_asyncio_loop()
        self.interface = None
        self.relay_fee = 1000
        self.wallets = []
        self._tx_event = asyncio.Event()

    def get_local_height(self):
        return 42

    def blockchain(self):
        class BlockchainMock:
            def is_tip_stale(self):
                return True
        return BlockchainMock()

    async def try_broadcasting(self, tx, name):
        for w in self.wallets:
            w.adb.receive_tx_callback(tx, TX_HEIGHT_UNCONFIRMED)

        self._tx_event.set()
        self._tx_event.clear()
        return tx.txid()

WALLET_SEED = 'fold object utility erase deputy output stadium feed stereo usage modify bean'
FUNDING_TX = Transaction('010000000001010f40064d66d766144e17bb3276d96042fd5aee2196bcce7e415f839e55a83de800000000171600147b6d7c7763b9185b95f367cf28e4dc6d09441e73fdffffff02404b4c00000000001976a9141df43441a3a3ee563e560d3ddc7e07cc9f9c3cdb88ac009871000000000017a9143873281796131b1996d2f94ab265327ee5e9d6e28702473044022029c124e5a1e2c6fa12e45ccdbdddb45fec53f33b982389455b110fdb3fe4173102203b3b7656bca07e4eae3554900aa66200f46fec0af10e83daaa51d9e4e62a26f4012103c8f0460c245c954ef563df3b1743ea23b965f98b120497ac53bd6b8e8e9e0f9bbe391400')

class TestTxBatcher(ElectrumTestCase):

    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.FEE_EST_DYNAMIC = False
        self.config.FEE_EST_STATIC_FEERATE = 5000

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.network = MockNetwork(self.config)

    def create_standard_wallet_from_seed(self, seed_words, *, config=None, gap_limit=2):
        if config is None:
            config = self.config
        ks = keystore.from_seed(seed_words, passphrase='', for_multisig=False)
        return WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=gap_limit, config=config)

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_batch_payments(self, mock_save_db):
        OUTGOING_ADDRESS = 'tb1q7rl9cxr85962ztnsze089zs8ycv52hk43f3m9n'
        # create wallet
        wallet = self.create_standard_wallet_from_seed(WALLET_SEED)
        wallet.start_network(self.network)
        wallet.txengine.SLEEP_INTERVAL = 0.01
        self.network.wallets.append(wallet)
        # fund wallet
        await self.network.try_broadcasting(FUNDING_TX, 'funding')
        assert wallet.adb.get_transaction(FUNDING_TX.txid()) is not None
        self.logger.info(f'wallet balance {wallet.get_balance()}')
        # payment 1
        output1 = PartialTxOutput.from_address_and_value(OUTGOING_ADDRESS, 100000)
        wallet.txengine.add_batch_payment(output1)
        # payment 2
        output2 = PartialTxOutput.from_address_and_value(OUTGOING_ADDRESS, 200000)
        wallet.txengine.add_batch_payment(output2)
        await self.network._tx_event.wait()
        tx = wallet.txengine.batch_tx
        txid = tx.txid()
        assert wallet.adb.get_transaction(txid) is not None
        assert len(tx.outputs()) == 3
        assert output1 in tx.outputs()
        assert output2 in tx.outputs()
        self.logger.info(f'{tx.outputs()}')

    async def test_rbf_batching__cannot_batch_as_would_need_to_use_ismine_outputs_of_basetx(self):
        """Wallet history contains unconf tx1 that spends all its coins to two ismine outputs,
        one 'recv' address (20k sats) and one 'change' (80k sats).
        The user tries to create tx2, that pays an invoice for 90k sats.
        Even if batch_rbf==True, no batching should be done. Instead, the outputs of tx1 should be used.
        """
        wallet = self.create_standard_wallet_from_seed(
            'cause carbon luggage air humble mistake melt paper supreme sense gravity void',
            config=self.config)
        wallet.start_network(self.network)
        wallet.txengine.SLEEP_INTERVAL = 0.01
        wallet.txengine.RETRY_DELAY = 0.60
        self.network.wallets.append(wallet)

        # bootstrap wallet (incoming funding_tx0)
        funding_tx = Transaction('020000000001021798e10f8b7220c57ea0d605316a52453ca9b3eed99996b5b7bdf4699548bb520000000000fdffffff277d82678d238ca45dd3490ac9fbb49272f0980b093b9197ff70ec8eb082cfb00100000000fdffffff028c360100000000001600147a9bfd90821be827275023849dd91ee80d494957a08601000000000016001476efaaa243327bf3a2c0f5380cb3914099448cec024730440220354b2a74f5ac039cca3618f7ff98229d243b89ac40550c8b027894f2c5cb88ff022064cb5ab1539b4c5367c2e01a8362e0aa12c2732bc8d08c3fce6eab9e56b7fe19012103e0a1499cb3d8047492c60466722c435dfbcffae8da9b83e758fbd203d12728f502473044022073cef8b0cfb093aed5b8eaacbb58c2fa6a69405a8e266cd65e76b726c9151d7602204d5820b23ab96acc57c272aac96d94740a20a6b89c016aa5aed7c06d1e6b9100012102f09e50a265c6a0dcf7c87153ea73d7b12a0fbe9d7d0bbec5db626b2402c1e85c02fa2400')
        funding_txid = funding_tx.txid()
        await self.network.try_broadcasting(funding_tx, 'funding')
        assert wallet.adb.get_transaction(funding_tx.txid()) is not None
        self.logger.info(f'wallet balance1 {wallet.get_balance()}')

        # to_self_payment tx1
        output1 = PartialTxOutput.from_address_and_value("tb1qyfnv3y866ufedugxxxfksyratv4pz3h78g9dad", 20_000)
        wallet.txengine.add_batch_payment(output1)
        await self.network._tx_event.wait()
        toself_tx = wallet.txengine.batch_tx
        assert len(toself_tx.outputs()) == 2
        assert output1 in toself_tx.outputs()

        # outgoing payment tx2
        output2 = PartialTxOutput.from_address_and_value("tb1qkfn0fude7z789uys2u7sf80kd4805zpvs3na0h", 90_000)
        wallet.txengine.add_batch_payment(output2)
        await self.network._tx_event.wait()
        tx2 = wallet.txengine.batch_tx
        assert len(tx2.outputs()) == 2
        assert output2 in tx2.outputs()


    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sweep_from_submarine_swap(self, mock_save_db):
        swap_funding_tx = "01000000000101500e9d67647481864edfb020b5c45e1c40d90f06b0130f9faed1a5149c6d26450000000000ffffffff0226080300000000002200205059c44bf57534303ab8f090f06b7bde58f5d2522440247a1ff6b41bdca9348df312c20100000000160014021d4f3b17921d790e1c022367a5bb078ce4deb402483045022100d41331089a2031396a1db8e4dec6dda9cacefe1288644b92f8e08a23325aa19b02204159230691601f7d726e4e6e0b7124d3377620f400d699a01095f0b0a09ee26a012102d60315c72c0cefd41c6d07883c20b88be3fc37aac7912f0052722a95de0de71600000000"
        swap_claim_tx = "02000000000101f9db8580febd5c0f85b6f1576c83f7739109e3a2d772743e3217e9537fea7e890000000000fdffffff010c050300000000001976a914aab9af3fbee0ab4e5c00d53e92f66d4bcb44f1bd88ac0347304402205151db039df4e0ce0f38927d24117eacde5418943440ed11d1fa7cb4c5051fc1022053e4f8b1b010fe7dcc02c32a171706feee832ee3d93c567770a7ab84d857658f0120f1939b5723155713855d7ebea6e174f77d41d669269e7f138856c3de190e7a366a8201208763a914d7a62ef0270960fe23f0f351b28caadab62c21838821030bfd61153816df786036ea293edce851d3a4b9f4a1c66bdc1a17f00ffef3d6b167750334ef24b1752102fc8128f17f9e666ea281c702171ab16c1dd2a4337b71f08970f5aa10c608a93268ac00000000"
        # create wallet
        wallet = self.create_standard_wallet_from_seed(WALLET_SEED)
        wallet.start_network(self.network)
        wallet.txengine.SLEEP_INTERVAL = 0.01
        self.network.wallets.append(wallet)
        # add swap data
        swap_data = SwapData(
            is_reverse=True,
            locktime=2420532,
            onchain_amount=198694,
            lightning_amount=200000,
            redeem_script=bytes.fromhex('8201208763a914d7a62ef0270960fe23f0f351b28caadab62c21838821030bfd61153816df786036ea293edce851d3a4b9f4a1c66bdc1a17f00ffef3d6b167750334ef24b1752102fc8128f17f9e666ea281c702171ab16c1dd2a4337b71f08970f5aa10c608a93268ac'),
            preimage=bytes.fromhex('f1939b5723155713855d7ebea6e174f77d41d669269e7f138856c3de190e7a36'),
            prepay_hash=None,
            privkey=bytes.fromhex('58fd0018a9a2737d1d6b81d380df96bf0c858473a9592015508a270a7c9b1d8d'),
            lockup_address='tb1q2pvugjl4w56rqw4c7zg0q6mmmev0t5jjy3qzg7sl766phh9fxjxsrtl77t',
            receive_address='tb1ql0adrj58g88xgz375yct63rclhv29hv03u0mel',
            funding_txid='897eea7f53e917323e7472d7a2e3099173f7836c57f1b6850f5cbdfe8085dbf9',
            spending_txid=None,
            is_redeemed=False,
        )
        wallet.adb.db.transactions[swap_data.funding_txid] = swap_funding_tx
        txin = PartialTxInput(
            prevout=TxOutpoint(txid=bytes.fromhex(swap_data.funding_txid), out_idx=0),
        )
        txin._trusted_value_sats = swap_data.onchain_amount
        txin, locktime = SwapManager.create_claim_txin(txin=txin, swap=swap_data, config=wallet.config)
        sweep_info = SweepInfo(
            txin=txin,
            csv_delay=0,
            cltv_abs=locktime,
            txout=None,
            name='swap claim',
        )
        wallet.txengine.add_sweep_info(sweep_info)
        await self.network._tx_event.wait()
        tx = wallet.txengine.batch_tx
        txid = tx.txid()
        self.assertEqual(swap_claim_tx, str(tx))

