import unittest
import logging
from unittest import mock
import asyncio

from electrum import storage, bitcoin, keystore, wallet
from electrum import Transaction
from electrum import SimpleConfig
from electrum import util
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED, TX_HEIGHT_UNCONF_PARENT, TX_HEIGHT_LOCAL
from electrum.transaction import Transaction, PartialTxOutput
from electrum.logging import console_stderr_handler, Logger


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
OUTGOING_ADDRESS = 'tb1q7rl9cxr85962ztnsze089zs8ycv52hk43f3m9n'

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
        # create wallet
        wallet = self.create_standard_wallet_from_seed(WALLET_SEED)
        wallet.start_network(self.network)
        wallet.txengine.INTERVAL = 0.01
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
