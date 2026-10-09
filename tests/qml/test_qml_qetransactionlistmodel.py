from datetime import datetime
from unittest.mock import patch

from PyQt6.QtCore import Qt

from electrum.gui.qml.qetransactionlistmodel import QETransactionListModel

from .. import ElectrumTestCase


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

