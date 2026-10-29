from datetime import datetime
from unittest.mock import patch

from PyQt6.QtCore import Qt

from electrum import SimpleConfig
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.fee_policy import FixedFeePolicy
from electrum.gui.qml.qetransactionlistmodel import QETransactionListModel
from electrum.transaction import PartialTxOutput, Transaction
from electrum.util import TxMinedInfo

from .. import ElectrumTestCase, restore_wallet_from_text__for_unittest


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

    async def test_tx_verified_before_we_have_the_signed_tx(self):
        # see #10098
        config = SimpleConfig({'electrum_path': self.electrum_path})
        wallet = restore_wallet_from_text__for_unittest(
            'bitter grass shiver impose acquire brush forget axis eager alone wine silver', path=None, config=config)['wallet']
        # one dummy input, one output of 100000 sat to the first receiving address
        funding_tx = Transaction('020000000111111111111111111111111111111111111111111111111111111111111111110000000000fdffffff01a0860100000000001600148a28bddb7f61864bdcf58b2ad13d5aeb3abc3c4200000000')
        wallet.adb.receive_tx_callback(funding_tx, tx_height=TX_HEIGHT_UNCONFIRMED)
        # an unsigned tx saved as local, e.g. by the txbatcher
        tx = wallet.make_unsigned_transaction(
            outputs=[PartialTxOutput.from_address_and_value(wallet.get_receiving_addresses()[1], 50_000)],
            fee_policy=FixedFeePolicy(1000))
        wallet.adb.add_transaction(tx)
        model = QETransactionListModel(wallet)
        model.unregister_callbacks()  # we deliver the 'verified' event ourselves, below
        # the signed tx got mined, and SPV finishes before we download it
        wallet.adb.add_verified_tx(tx.txid(), TxMinedInfo(_height=100, conf=1, timestamp=1700000000, txpos=1, header_hash='00' * 32))
        model.on_tx_verified(tx.txid(), wallet.adb.get_tx_height(tx.txid()))
        self.assertEqual('local', model.tx_history[model._tx_positions[tx.txid()]]['section'])
