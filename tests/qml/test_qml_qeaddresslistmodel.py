import gc
from unittest.mock import patch, MagicMock

from electrum import SimpleConfig
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.fee_policy import FixedFeePolicy
from electrum.gui.qml.qeaddresslistmodel import QEAddressCoinListModel
from electrum.gui.qml.qeconfig import QEConfig
from electrum.transaction import PartialTxOutput

from .. import ElectrumTestCase, restore_wallet_from_text__for_unittest
from .qt_util import create_qcoreapplication, delete_qobject, receive_incoming_tx


class TestQEAddressCoinListModelLabels(ElectrumTestCase):
    TESTNET = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # free the QObjects (and the wallets they hold) before other tests check for lingering wallets
        cls.addClassCleanup(gc.collect)
        create_qcoreapplication(cls)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        config = SimpleConfig({'electrum_path': self.electrum_path})
        self.wallet = restore_wallet_from_text__for_unittest(
            'bitter grass shiver impose acquire brush forget axis eager alone wine silver',
            path=None, config=config, gap_limit=4)['wallet']
        self.addr_a, self.addr_b, self.addr_c, self.addr_d = self.wallet.get_receiving_addresses()[:4]
        # incoming tx X pays A (X:0) and B (X:1)
        self.txid_x = receive_incoming_tx(self.wallet, '11', [(self.addr_a, 30_000), (self.addr_b, 20_000)])
        # incoming tx Y pays D (Y:0), which tx S spends to C (S:0)
        self.txid_y = receive_incoming_tx(self.wallet, '12', [(self.addr_d, 40_000)])
        coins = [c for c in self.wallet.get_utxos() if c.prevout.to_str() == f'{self.txid_y}:0']
        tx = self.wallet.make_unsigned_transaction(
            coins=coins, outputs=[PartialTxOutput.from_address_and_value(self.addr_c, '!')],
            fee_policy=FixedFeePolicy(1000))
        self.wallet.sign_transaction(tx, password=None)
        self.wallet.adb.receive_tx_callback(tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        self.txid_s = tx.txid()

        with patch.object(QEConfig, 'instance', MagicMock()):
            self.model = QEAddressCoinListModel(self.wallet)
        self.addCleanup(delete_qobject, self.model)

    def _label(self, *, outpoint: str = None, address: str = None) -> str:
        for row, item in enumerate(self.model._items):
            if (outpoint and item.get('outpoint') == outpoint) \
                    or (address and not item.get('outpoint') and item['address'] == address):
                return self.model.data(self.model.index(row, 0), self.model._ROLE_RMAP['label'])
        raise Exception(f'no row for {outpoint=} {address=}')

    async def test_address_label_updates_coins_of_txs_paying_it(self):
        self.wallet.set_label(self.addr_a, 'rent')
        self.assertEqual('rent', self._label(address=self.addr_a))
        self.assertEqual('rent', self._label(outpoint=f'{self.txid_x}:0'))
        # the coin at B has the label of tx X too, which includes the label of A
        self.assertEqual('rent', self._label(outpoint=f'{self.txid_x}:1'))

        self.wallet.set_label(self.addr_b, 'food')
        self.assertEqual('rent, food', self._label(outpoint=f'{self.txid_x}:0'))
        self.assertEqual('rent, food', self._label(outpoint=f'{self.txid_x}:1'))

        self.wallet.set_label(self.addr_a, None)
        self.assertEqual('', self._label(address=self.addr_a))
        self.assertEqual('food', self._label(outpoint=f'{self.txid_x}:0'))
        self.assertEqual('food', self._label(outpoint=f'{self.txid_x}:1'))

    async def test_outpoint_label_updates_coins_of_same_tx(self):
        self.wallet.set_label(f'{self.txid_x}:0', 'rent')
        self.assertEqual('rent', self._label(outpoint=f'{self.txid_x}:0'))
        self.assertEqual('rent', self._label(outpoint=f'{self.txid_x}:1'))

    async def test_spent_outpoint_label_updates_coins_of_spending_tx(self):
        self.assertEqual('', self._label(outpoint=f'{self.txid_s}:0'))
        self.wallet.set_label(f'{self.txid_y}:0', 'rent')
        self.assertEqual('sweep rent', self._label(outpoint=f'{self.txid_s}:0'))

    async def test_txid_label_updates_its_coins(self):
        self.wallet.set_label(self.txid_x, 'salary')
        self.assertEqual('salary', self._label(outpoint=f'{self.txid_x}:0'))
        self.assertEqual('salary', self._label(outpoint=f'{self.txid_x}:1'))
        self.assertEqual('', self._label(outpoint=f'{self.txid_s}:0'))

    async def test_label_updates_rows_moved_by_deleting_an_address(self):
        # removes the rows of A and of its coin X:0, the rows after them move up
        self.model.deleteAddress(self.addr_a)
        self.wallet.set_label(self.addr_b, 'food')
        self.assertEqual('food', self._label(address=self.addr_b))
        self.assertEqual('food', self._label(outpoint=f'{self.txid_x}:1'))
