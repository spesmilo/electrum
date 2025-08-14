from datetime import datetime
from unittest.mock import patch

from electrum.gui.qml.qetransactionlistmodel import QETransactionListModel

from . import ElectrumTestCase


class TestQETransactionListModel(ElectrumTestCase):

    def test_get_section_by_timestamp(self):
        f = QETransactionListModel.get_section_by_timestamp

        mock_today = datetime(2023, 6, 15, 0, 0, 0, 0)
        with patch('electrum.gui.qml.qetransactionlistmodel.datetime') as mock_dt:
            mock_dt.today.return_value = mock_today
            mock_dt.fromtimestamp = datetime.fromtimestamp

            today_ts = datetime(2023, 6, 15, 10, 30, 0).timestamp()
            self.assertEqual(f(today_ts), 'today')

            today_edge_ts = datetime(2023, 6, 15, 0, 0, 1).timestamp()
            self.assertEqual(f(today_edge_ts), 'today')

            yesterday_ts = datetime(2023, 6, 14, 15, 0, 0).timestamp()
            self.assertEqual(f(yesterday_ts), 'yesterday')

            yesterday_edge_ts = datetime(2023, 6, 13, 23, 59, 59).timestamp()
            self.assertEqual(f(yesterday_edge_ts), 'lastweek')

            lastweek_ts = datetime(2023, 6, 12, 12, 0, 0).timestamp()
            self.assertEqual(f(lastweek_ts), 'lastweek')

            lastweek_boundary_ts = datetime(2023, 6, 8, 12, 0, 0).timestamp()
            self.assertEqual(f(lastweek_boundary_ts), 'lastweek')

            lastmonth_ts = datetime(2023, 6, 5, 9, 0, 0).timestamp()
            self.assertEqual(f(lastmonth_ts), 'lastmonth')

            lastmonth_boundary_ts = datetime(2023, 5, 15, 8, 0, 0).timestamp()
            self.assertEqual(f(lastmonth_boundary_ts), 'lastmonth')

            older_ts = datetime(2023, 5, 14, 10, 0, 0).timestamp()
            self.assertEqual(f(older_ts), 'older')

            much_older_ts = datetime(2022, 1, 1, 0, 0, 0).timestamp()
            self.assertEqual(f(much_older_ts), 'older')

    def test_format_date_by_section(self):
        f = QETransactionListModel.format_date_by_section

        test_date = datetime(2023, 6, 15, 14, 30, 45)

        result = f('today', test_date)
        self.assertEqual(result, '14:30')

        result = f('yesterday', test_date)
        self.assertEqual(result, '14:30')

        result = f('lastweek', test_date)
        self.assertEqual(result, 'Thu, 14:30')

        result = f('lastmonth', test_date)
        self.assertEqual(result, 'Thu 15, 14:30')

        result = f('older', test_date)
        self.assertEqual(result, '2023-06-15 14:30')

        result = f('unknown_section', test_date)
        self.assertEqual(result, '2023-06-15 14:30')

