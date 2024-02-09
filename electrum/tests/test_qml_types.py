import shutil
import tempfile

from electrum import SimpleConfig
from electrum.gui.qml.qetypes import QEAmount
from electrum.tests.test_qt_base import QETestCase, QEventReceiver, qt_test


class WalletMock:
    def __init__(self, electrum_path):
        self.config = SimpleConfig({
            'electrum_path': electrum_path,
            'decimal_point': 5
        })
        self.contacts = None


class QETestTypes(QETestCase):

    def setUp(self):
        super().setUp()
        self.electrum_path = tempfile.mkdtemp()
        self.wallet = WalletMock(self.electrum_path)

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.electrum_path)

    @qt_test
    def test_qeamount(self):
        a = QEAmount()
        self.assertTrue(a.isEmpty)
        a_er = QEventReceiver(a.valueChanged)
        a.satsInt = 1
        self.assertTrue(bool(a_er.received))
        self.assertFalse(a.isEmpty)

        a_er.clear()
        a.clear()
        self.assertTrue(a.isEmpty)
        self.assertTrue(bool(a_er.received))

        a_er.clear()
        a.isMax = True
        self.assertTrue(a.isMax)
        self.assertFalse(a.isEmpty)
        self.assertTrue(bool(a_er.received))

    @qt_test
    def test_qeamount_copy(self):
        a = QEAmount()
        b = QEAmount()
        b.satsInt = 1
        c = QEAmount()
        c.msatsInt = 1
        d = QEAmount()
        d.isMax = True

        t = QEAmount()
        t_er = QEventReceiver(t.valueChanged)

        t.copyFrom(a)
        self.assertTrue(t.isEmpty)
        self.assertEqual(0, len(t_er.received))

        t.clear()
        t_er.clear()
        t.copyFrom(b)
        self.assertFalse(t.isEmpty)
        self.assertEqual(t.satsInt, 1)
        self.assertEqual(1, len(t_er.received))

        t.clear()
        t_er.clear()
        t.copyFrom(c)
        self.assertFalse(t.isEmpty)
        self.assertEqual(t.msatsInt, 1)
        self.assertEqual(1, len(t_er.received))

        t.clear()
        t_er.clear()
        t.copyFrom(d)
        self.assertFalse(t.isEmpty)
        self.assertTrue(t.isMax)
        self.assertEqual(1, len(t_er.received))
