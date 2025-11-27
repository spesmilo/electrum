from typing import TYPE_CHECKING
from electrum import SimpleConfig
from electrum.gui.qml.qeconfig import QEConfig
from tests.qt_util import QETestCase, qt_test

if TYPE_CHECKING:
    from PyQt6.QtCore import QRegularExpression


class TestConfig(QETestCase):
    @classmethod
    def setUpClass(cls):
        QEConfig(SimpleConfig())

    def setUp(self):
        super().setUp()
        self.q: QEConfig = QEConfig.instance
        # raise Exception()  # NOTE: exceptions in setUp() will block the test

    @qt_test
    def test_satstounits(self):
        self.q.config.BTC_AMOUNTS_DECIMAL_POINT = 5
        self.assertEqual(self.q.satsToUnits(100_000), 1.0)
        self.assertEqual(self.q.satsToUnits(1), 0.00001)
        self.assertEqual(self.q.satsToUnits(0.001), 0.00000001)

    @qt_test
    def test_unitstosats(self):
        qa = self.q.unitsToSats('')
        self.assertTrue(qa.isEmpty)
        qa = self.q.unitsToSats('0')
        self.assertTrue(qa.isEmpty)
        qa = self.q.unitsToSats('0.000')
        self.assertTrue(qa.isEmpty)

        self.q.config.BTC_AMOUNTS_DECIMAL_POINT = 5

        qa = self.q.unitsToSats('1')
        self.assertFalse(qa.isEmpty)
        self.assertEqual(qa.satsInt, 100_000)
        self.assertEqual(qa.msatsInt, 100_000_000)

        qa = self.q.unitsToSats('1.001')
        self.assertFalse(qa.isEmpty)
        self.assertEqual(qa.satsInt, 100_100)
        self.assertEqual(qa.msatsInt, 100_100_000)

        qa = self.q.unitsToSats('1.000001')
        self.assertFalse(qa.isEmpty)
        self.assertEqual(qa.satsInt, 100_000)
        self.assertEqual(qa.msatsInt, 100_000_100)

        self.q.config.BTC_AMOUNTS_DECIMAL_POINT = 0

        qa = self.q.unitsToSats('1.001')
        self.assertFalse(qa.isEmpty)
        self.assertEqual(qa.satsInt, 1)
        self.assertEqual(qa.msatsInt, 1001)

        qa = self.q.unitsToSats('1.0001')  # outside msat precision
        self.assertFalse(qa.isEmpty)
        self.assertEqual(qa.satsInt, 1)
        self.assertEqual(qa.msatsInt, 1000)

        self.q.config.BTC_AMOUNTS_DECIMAL_POINT = 8

        qa = self.q.unitsToSats('0.00000001001')
        self.assertFalse(qa.isEmpty)
        self.assertEqual(qa.satsInt, 1)
        self.assertEqual(qa.msatsInt, 1001)

    @qt_test
    def test_btc_amount_regexes(self):
        self.q.config.BTC_AMOUNTS_DECIMAL_POINT = 8

        a: 'QRegularExpression' = self.q.btcAmountRegex
        b: 'QRegularExpression' = self.q.btcAmountRegexMsat

        self.assertTrue(a.isValid())
        self.assertTrue(b.isValid())

        self.assertTrue(a.match('1').hasMatch())
        self.assertTrue(a.match('1.').hasMatch())
        self.assertTrue(a.match('1.00000000').hasMatch())
        self.assertFalse(a.match('1.000000000').hasMatch())
        self.assertTrue(a.match('21000000').hasMatch())
        self.assertFalse(a.match('121000000').hasMatch())

        self.assertTrue(b.match('1').hasMatch())
        self.assertTrue(b.match('1.').hasMatch())
        self.assertTrue(b.match('1.00000000').hasMatch())
        self.assertTrue(b.match('1.00000000000').hasMatch())
        self.assertFalse(b.match('1.000000000000').hasMatch())
        self.assertTrue(b.match('21000000').hasMatch())
        self.assertFalse(b.match('121000000').hasMatch())

        self.q.config.BTC_AMOUNTS_DECIMAL_POINT = 5

        a: 'QRegularExpression' = self.q.btcAmountRegex
        b: 'QRegularExpression' = self.q.btcAmountRegexMsat

        self.assertTrue(a.isValid())
        self.assertTrue(b.isValid())

        self.assertTrue(a.match('1').hasMatch())
        self.assertTrue(a.match('1.').hasMatch())
        self.assertTrue(a.match('1.00000').hasMatch())
        self.assertFalse(a.match('1.000000').hasMatch())
        self.assertTrue(a.match('21000000000').hasMatch())
        self.assertFalse(a.match('121000000000').hasMatch())

        self.assertTrue(b.match('1').hasMatch())
        self.assertTrue(b.match('1.').hasMatch())
        self.assertTrue(b.match('1.0000000').hasMatch())
        self.assertTrue(b.match('1.00000000').hasMatch())
        self.assertFalse(b.match('1.000000000000').hasMatch())
        self.assertTrue(b.match('21000000000').hasMatch())
        self.assertFalse(b.match('121000000000').hasMatch())

        self.q.config.BTC_AMOUNTS_DECIMAL_POINT = 0

        a: 'QRegularExpression' = self.q.btcAmountRegex
        b: 'QRegularExpression' = self.q.btcAmountRegexMsat

        self.assertTrue(a.isValid())
        self.assertTrue(b.isValid())

        self.assertTrue(a.match('1').hasMatch())
        self.assertFalse(a.match('1.').hasMatch())
        self.assertTrue(a.match('2100000000000000').hasMatch())
        self.assertFalse(a.match('12100000000000000').hasMatch())

        self.assertTrue(b.match('1').hasMatch())
        self.assertTrue(b.match('1.').hasMatch())
        self.assertTrue(b.match('1.000').hasMatch())
        self.assertFalse(b.match('1.0000').hasMatch())
        self.assertTrue(b.match('2100000000000000').hasMatch())
        self.assertFalse(b.match('12100000000000000').hasMatch())
