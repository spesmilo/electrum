import unittest
import logging
from unittest import mock
import asyncio

from electrum import storage, bitcoin, keystore, wallet
from electrum import SimpleConfig
from electrum import util
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_LOCAL
from electrum.transaction import Transaction, PartialTxInput, PartialTxOutput, TxOutpoint
from electrum.logging import console_stderr_handler, Logger
from electrum.submarine_swaps import SwapManager, SwapData
from electrum.lnsweep import SweepInfo
from electrum.fee_policy import FeeTimeEstimates

from . import ElectrumTestCase
from .test_wallet_vertical import WalletIntegrityHelper, read_test_vector

WALLET_DATA = read_test_vector('cause_carbon_wallet.json')

class MockNetwork(Logger):

    def __init__(self, config):
        Logger.__init__(self)
        self.config = config
        self.fee_estimates = FeeTimeEstimates()
        self.asyncio_loop = util.get_asyncio_loop()
        self.interface = None
        self.relay_fee = 1000
        self.wallets = []
        self._tx_queue = asyncio.Queue()

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

        self._tx_queue.put_nowait(tx)
        return tx.txid()

    async def next_tx(self):
        tx = await util.wait_for2(self._tx_queue.get(), timeout=10)
        return tx

    def is_connected(self):
        return True


SWAP_FUNDING_TX = "01000000000101500e9d67647481864edfb020b5c45e1c40d90f06b0130f9faed1a5149c6d26450000000000ffffffff0226080300000000002200205059c44bf57534303ab8f090f06b7bde58f5d2522440247a1ff6b41bdca9348df312c20100000000160014021d4f3b17921d790e1c022367a5bb078ce4deb402483045022100d41331089a2031396a1db8e4dec6dda9cacefe1288644b92f8e08a23325aa19b02204159230691601f7d726e4e6e0b7124d3377620f400d699a01095f0b0a09ee26a012102d60315c72c0cefd41c6d07883c20b88be3fc37aac7912f0052722a95de0de71600000000"
SWAP_CLAIM_TX = "02000000000101f9db8580febd5c0f85b6f1576c83f7739109e3a2d772743e3217e9537fea7e890000000000fdffffff017005030000000000160014b113a47f3718da3fd161339a6681c150fef2cfe30347304402206736066ce15d34eed20951a9d974a100a72dc034f9c878769ddf27f9a584dcb1022042b14d627b8e8465a3a129bb43c0bd8369f49bbcf473879b9a477263655f1f930120f1939b5723155713855d7ebea6e174f77d41d669269e7f138856c3de190e7a366a8201208763a914d7a62ef0270960fe23f0f351b28caadab62c21838821030bfd61153816df786036ea293edce851d3a4b9f4a1c66bdc1a17f00ffef3d6b167750334ef24b1752102fc8128f17f9e666ea281c702171ab16c1dd2a4337b71f08970f5aa10c608a93268ac00000000"


class TestTxBatcher(ElectrumTestCase):

    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        console_stderr_handler.setLevel(logging.DEBUG)

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.fee_policy_descriptor = 'feerate:5000'

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.network = MockNetwork(self.config)

    def create_standard_wallet_from_seed(self, seed_words, *, config=None, gap_limit=2):
        if config is None:
            config = self.config
        ks = keystore.from_seed(seed_words, passphrase='', for_multisig=False)
        return WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=gap_limit, config=config)

    def _create_wallet(self):
        wallet = self.create_standard_wallet_from_seed(WALLET_DATA["seed"])
        wallet.start_network(self.network)
        wallet.txbatcher.SLEEP_INTERVAL = 0.01
        self.network.wallets.append(wallet)
        return wallet

    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_batch_payments(self, mock_save_db):
        # output 1:     tx1(o1) ---------------
        #                                      \
        # output 2:     tx1'(o1,o2)             ----> tx2(tx1|o2)
        #
        # tx1 is broadcast, and replaced by tx1'
        # tx1 gets mined
        # txbatcher creates a new transaction tx2, child of tx1
        #
        OUTGOING_ADDRESS = 'tb1q7rl9cxr85962ztnsze089zs8ycv52hk43f3m9n'
        wallet = self._create_wallet()
        # fund wallet
        funding_tx = Transaction(WALLET_DATA["funding_tx"])
        await self.network.try_broadcasting(funding_tx, 'funding')
        await self.network.next_tx()
        assert wallet.adb.get_transaction(funding_tx.txid()) is not None
        self.logger.info(f'wallet balance {wallet.get_balance()}')
        # payment 1 -> tx1(output1)
        output1 = PartialTxOutput.from_address_and_value(OUTGOING_ADDRESS, 10_000)
        wallet.txbatcher.add_payment_output('default', output1, self.fee_policy_descriptor)
        tx1 = await self.network.next_tx()
        assert output1 in tx1.outputs()
        # payment 2 -> tx2(output1, output2)
        output2 = PartialTxOutput.from_address_and_value(OUTGOING_ADDRESS, 20_000)
        wallet.txbatcher.add_payment_output('default', output2, self.fee_policy_descriptor)
        tx1_prime = await self.network.next_tx()
        assert wallet.adb.get_transaction(tx1_prime.txid()) is not None
        assert len(tx1_prime.outputs()) == 3
        assert output1 in tx1_prime.outputs()
        assert output2 in tx1_prime.outputs()
        # tx1 gets confirmed, tx2 gets removed
        wallet.adb.receive_tx_callback(tx1, 1)
        tx_mined_status = wallet.adb.get_tx_height(tx1.txid())
        wallet.adb.add_verified_tx(tx1.txid(), tx_mined_status._replace(conf=1))
        assert wallet.adb.get_transaction(tx1.txid()) is not None
        assert wallet.adb.get_transaction(tx1_prime.txid()) is None
        # txbatcher creates tx2
        tx2 = await self.network.next_tx()
        assert output1 in tx1.outputs()
        assert output2 in tx2.outputs()
        # check that tx2 is child of tx1
        assert len(tx2.inputs()) == 1
        assert tx2.inputs()[0].prevout.txid.hex() == tx1.txid()


    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_rbf_batching__cannot_batch_as_would_need_to_use_ismine_outputs_of_basetx(self, mock_save_db):
        """Wallet history contains unconf tx1 that spends all its coins to two ismine outputs,
        one 'recv' address (20k sats) and one 'change' (80k sats).
        The user tries to create tx2, that pays an invoice for 90k sats.
        The tx batcher fails  to batch, and should create a child transaction
        """
        wallet = self._create_wallet()
        # fund wallet
        funding_tx = Transaction(WALLET_DATA['funding_tx'])
        await self.network.try_broadcasting(funding_tx, 'funding')
        await self.network.next_tx()
        assert wallet.adb.get_transaction(funding_tx.txid()) is not None
        self.logger.info(f'wallet balance1 {wallet.get_balance()}')

        # to_self_payment tx1
        output1 = PartialTxOutput.from_address_and_value("tb1qyfnv3y866ufedugxxxfksyratv4pz3h78g9dad", 20_000)
        wallet.txbatcher.add_payment_output('default', output1, self.fee_policy_descriptor)
        toself_tx = await self.network.next_tx()
        assert len(toself_tx.outputs()) == 2
        assert output1 in toself_tx.outputs()

        # outgoing payment tx2
        output2 = PartialTxOutput.from_address_and_value("tb1qkfn0fude7z789uys2u7sf80kd4805zpvs3na0h", 90_000)
        wallet.txbatcher.add_payment_output('default', output2, self.fee_policy_descriptor)
        tx2 = await self.network.next_tx()
        assert len(tx2.outputs()) == 2
        assert output2 in tx2.outputs()


    @mock.patch.object(wallet.Abstract_Wallet, 'save_db')
    async def test_sweep_from_submarine_swap(self, mock_save_db):
        self.maxDiff = None
        # create wallet
        wallet = self._create_wallet()
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
        wallet.adb.db.transactions[swap_data.funding_txid] = Transaction(SWAP_FUNDING_TX)
        txin = PartialTxInput(
            prevout=TxOutpoint(txid=bytes.fromhex(swap_data.funding_txid), out_idx=0),
        )
        txin._trusted_value_sats = swap_data.onchain_amount
        txin, locktime = SwapManager.create_claim_txin(txin=txin, swap=swap_data)
        sweep_info = SweepInfo(
            txin=txin,
            cltv_abs=locktime,
            txout=None,
            name='swap claim',
            can_be_batched=True,
        )
        wallet.txbatcher.add_sweep_input('swaps', sweep_info, self.fee_policy_descriptor)
        tx = await self.network.next_tx()
        txid = tx.txid()
        self.assertEqual(SWAP_CLAIM_TX, str(tx))
        # add a new payment, reusing the same input
        # this tests that txin.make_witness() can be called more than once
        output1 = PartialTxOutput.from_address_and_value("tb1qyfnv3y866ufedugxxxfksyratv4pz3h78g9dad", 20_000)
        wallet.txbatcher.add_payment_output('swaps', output1, self.fee_policy_descriptor)
        new_tx = await self.network.next_tx()
        # check that we batched with previous tx
        assert new_tx.inputs()[0].prevout == tx.inputs()[0].prevout == txin.prevout
        assert output1 in new_tx.outputs()
