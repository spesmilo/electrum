import gc
import time
from datetime import datetime
from unittest.mock import patch

from PyQt6.QtCore import Qt

from electrum import SimpleConfig
from electrum.gui.qml.qetransactionlistmodel import QETransactionListModel
from electrum.util import LightningHistoryItem

from .. import ElectrumTestCase, restore_wallet_from_text__for_unittest
from .qt_util import create_qcoreapplication, delete_qobject, receive_incoming_tx


class TestQETransactionListModel(ElectrumTestCase):

    def test_get_section_by_timestamp(self):
        f = QETransactionListModel.get_section_by_timestamp

        mock_today = datetime(2023, 6, 15, 0, 0, 0, 0)  # thursday
        with patch('electrum.gui.qml.qetransactionlistmodel.datetime') as mock_dt, \
                patch('electrum.gui.qml.qetransactionlistmodel.QLocale') as mock_locale:
            mock_dt.today.return_value = mock_today
            mock_dt.fromtimestamp = datetime.fromtimestamp
            mock_first_day_of_week = mock_locale.system.return_value.firstDayOfWeek
            mock_first_day_of_week.return_value = Qt.DayOfWeek.Monday

            today_ts = datetime(2023, 6, 15, 10, 30, 0).timestamp()
            self.assertEqual(f(today_ts), 'today')

            today_edge_ts = datetime(2023, 6, 15, 0, 0, 0).timestamp()
            self.assertEqual(f(today_edge_ts), 'today')

            yesterday_ts = datetime(2023, 6, 14, 15, 0, 0).timestamp()
            self.assertEqual(f(yesterday_ts), 'yesterday')

            yesterday_edge_ts = datetime(2023, 6, 13, 23, 59, 59).timestamp()
            self.assertEqual(f(yesterday_edge_ts), 'thisweek')

            thisweek_boundary_ts = datetime(2023, 6, 12, 0, 0, 0).timestamp()
            self.assertEqual(f(thisweek_boundary_ts), 'thisweek')

            lastweek_ts = datetime(2023, 6, 11, 23, 59, 59).timestamp()
            self.assertEqual(f(lastweek_ts), 'lastweek')

            lastweek_boundary_ts = datetime(2023, 6, 5, 0, 0, 0).timestamp()
            self.assertEqual(f(lastweek_boundary_ts), 'lastweek')

            thismonth_ts = datetime(2023, 6, 4, 23, 59, 59).timestamp()
            self.assertEqual(f(thismonth_ts), 'thismonth')

            thismonth_boundary_ts = datetime(2023, 6, 1, 0, 0, 0).timestamp()
            self.assertEqual(f(thismonth_boundary_ts), 'thismonth')

            lastmonth_ts = datetime(2023, 5, 31, 23, 59, 59).timestamp()
            self.assertEqual(f(lastmonth_ts), 'lastmonth')

            lastmonth_boundary_ts = datetime(2023, 5, 1, 0, 0, 0).timestamp()
            self.assertEqual(f(lastmonth_boundary_ts), 'lastmonth')

            older_ts = datetime(2023, 4, 30, 23, 59, 59).timestamp()
            self.assertEqual(f(older_ts), 'older')

            much_older_ts = datetime(2022, 1, 1, 0, 0, 0).timestamp()
            self.assertEqual(f(much_older_ts), 'older')

            # the week boundaries follow the locale's first day of the week
            sunday_ts = datetime(2023, 6, 11, 12, 0, 0).timestamp()
            prev_sunday_ts = datetime(2023, 6, 4, 12, 0, 0).timestamp()
            prev_saturday_ts = datetime(2023, 6, 3, 12, 0, 0).timestamp()
            self.assertEqual(f(sunday_ts), 'lastweek')
            self.assertEqual(f(prev_sunday_ts), 'thismonth')
            mock_first_day_of_week.return_value = Qt.DayOfWeek.Sunday
            self.assertEqual(f(sunday_ts), 'thisweek')
            self.assertEqual(f(prev_sunday_ts), 'lastweek')
            self.assertEqual(f(prev_saturday_ts), 'thismonth')
            mock_first_day_of_week.return_value = Qt.DayOfWeek.Saturday
            self.assertEqual(f(sunday_ts), 'thisweek')
            self.assertEqual(f(prev_saturday_ts), 'lastweek')

            # the more specific section wins where weeks and months overlap
            mock_first_day_of_week.return_value = Qt.DayOfWeek.Monday
            mock_dt.today.return_value = datetime(2023, 5, 2, 0, 0, 0, 0)  # tuesday
            self.assertEqual(f(datetime(2023, 5, 1, 12, 0, 0).timestamp()), 'yesterday')
            self.assertEqual(f(datetime(2023, 4, 30, 12, 0, 0).timestamp()), 'lastweek')
            self.assertEqual(f(datetime(2023, 4, 23, 12, 0, 0).timestamp()), 'lastmonth')

    def test_format_date_by_section(self):
        f = QETransactionListModel.format_date_by_section

        test_date = datetime(2023, 6, 15, 14, 30, 45)

        result = f('today', test_date)
        self.assertEqual(result, '14:30')

        result = f('yesterday', test_date)
        self.assertEqual(result, '14:30')

        result = f('thisweek', test_date)
        self.assertEqual(result, 'Thu, 14:30')

        result = f('lastweek', test_date)
        self.assertEqual(result, 'Thu 15, 14:30')

        result = f('thismonth', test_date)
        self.assertEqual(result, 'Thu 15, 14:30')

        result = f('lastmonth', test_date)
        self.assertEqual(result, 'Thu 15, 14:30')

        result = f('older', test_date)
        self.assertEqual(result, '2023-06-15 14:30')

        result = f('unknown_section', test_date)
        self.assertEqual(result, '2023-06-15 14:30')


class TestQETransactionListModelLabels(ElectrumTestCase):
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
        self.addr_a, self.addr_b = self.wallet.get_receiving_addresses()[:2]
        self.txid_x = receive_incoming_tx(self.wallet, '11', [(self.addr_a, 30_000)])
        # claim tx of a reverse swap, pays B
        self.txid_claim = receive_incoming_tx(self.wallet, '13', [(self.addr_b, 60_000)])

        # group the claim tx with the lightning payment of the swap, as SwapManager does it
        lnworker = self.wallet.lnworker
        payment_hash = 'ab' * 32
        swap_groups = {self.txid_claim: {
            'group_id': self.txid_claim,
            'label': 'Claim transaction',
            'group_label': 'Reverse swap 0.0006 tBTC',
        }}
        lightning_history = {payment_hash: LightningHistoryItem(
            type='payment', payment_hash=payment_hash, preimage=None, amount_msat=-61_000_000, fee_msat=0,
            group_id=self.txid_claim, timestamp=int(time.time()), label='', direction=None)}
        for patcher in (
                patch.object(lnworker.swap_manager, 'get_groups_for_onchain_history', return_value=swap_groups),
                patch.object(lnworker, 'get_lightning_history', return_value=lightning_history)):
            patcher.start()
            self.addCleanup(patcher.stop)

        self.model = QETransactionListModel(self.wallet)
        self.addCleanup(delete_qobject, self.model)
        self.assertEqual(2, len(self._row(self.txid_claim)['children']))
        self.assertEqual('Reverse swap 0.0006 tBTC', self._row(self.txid_claim)['label'])

    def _row(self, key: str) -> dict:
        for item in self.model.tx_history:
            if item['key'] == key:
                return item
        raise Exception(f'no row for {key=}')

    async def test_address_label_updates_tx_label_derived_from_it(self):
        self.wallet.set_label(self.addr_a, 'rent')
        self.assertEqual('rent', self._row(self.txid_x)['label'])

    async def test_address_label_keeps_group_label(self):
        # the claim tx pays to B, so its label may derive from the label of B
        self.wallet.set_label(self.addr_b, 'savings')
        self.assertEqual('Reverse swap 0.0006 tBTC', self._row(self.txid_claim)['label'])

    async def test_tx_label_keeps_group_label(self):
        self.wallet.set_label(self.txid_claim, 'my claim')
        self.assertEqual('Reverse swap 0.0006 tBTC', self._row(self.txid_claim)['label'])
        self.wallet.set_label(self.txid_claim, None)
        self.assertEqual('Reverse swap 0.0006 tBTC', self._row(self.txid_claim)['label'])
