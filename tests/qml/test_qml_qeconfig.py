import os
import shutil
import tempfile
from typing import TYPE_CHECKING

from electrum import SimpleConfig
from electrum.gui.qml.qeconfig import QEConfig

from .qt_util import QETestCase, qt_test

if TYPE_CHECKING:
    from PyQt6.QtCore import QRegularExpression


class TestConfig(QETestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._unittest_base_path = tempfile.mkdtemp(prefix="electrum-unittest-base-")
        electrum_path = os.path.join(cls._unittest_base_path, "electrum")
        config = SimpleConfig({'electrum_path': electrum_path})
        QEConfig(config)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._unittest_base_path)
        super().tearDownClass()

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

    @qt_test
    def test_gossip_background_sync_settings(self):
        # a QEConfig of our own: signals need a live QObject, and the shared one died with the app of an earlier test
        electrum_path = tempfile.mkdtemp(prefix="electrum-unittest-gossip-", dir=self._unittest_base_path)
        QEConfig.instance = None
        try:
            q = QEConfig(SimpleConfig({'electrum_path': electrum_path}))
        finally:
            QEConfig.instance = self.q
        changes = []
        q.gossipBackgroundSyncChanged.connect(lambda: changes.append(1))
        self.assertTrue(q.gossipBackgroundSync)
        self.assertEqual(120, q.gossipBackgroundSyncInterval)
        self.assertTrue(q.gossipBackgroundSyncUnmeteredOnly)
        self.assertFalse(q.gossipBackgroundSyncChargingOnly)
        q.gossipBackgroundSync = False
        q.gossipBackgroundSyncInterval = 240
        q.gossipBackgroundSyncUnmeteredOnly = False
        q.gossipBackgroundSyncChargingOnly = True
        self.assertEqual(4, len(changes))  # each one changes the schedule of the job
        config = q.config
        self.assertFalse(config.LIGHTNING_GOSSIP_BACKGROUND_SYNC)
        self.assertEqual(240, config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_INTERVAL)
        self.assertFalse(config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_UNMETERED_ONLY)
        self.assertTrue(config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_CHARGING_ONLY)
        # whether we asked the user about the battery optimizations is remembered, and is not a setting of the job
        asked = []
        q.gossipBackgroundSyncBatteryAskedChanged.connect(lambda: asked.append(1))
        self.assertFalse(q.gossipBackgroundSyncBatteryAsked)
        q.gossipBackgroundSyncBatteryAsked = True
        self.assertTrue(config.LIGHTNING_GOSSIP_BACKGROUND_SYNC_BATTERY_ASKED)
        self.assertEqual([1], asked)
        self.assertEqual(4, len(changes))
