import shutil
import tempfile

from electrum import SimpleConfig
from electrum.gui.qml.qetypes import QEAmount
from electrum.invoices import Invoice, LN_EXPIRY_NEVER
from tests.qt_util import QETestCase, QEventReceiver, qt_test
from electrum.transaction import PartialTxOutput


class WalletMock:
    def __init__(self, electrum_path):
        self.config = SimpleConfig({
            'electrum_path': electrum_path,
            'decimal_point': 5
        })
        self.contacts = None


class TestTypes(QETestCase):

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
        self.assertEqual('1', a.satsStr)

        a_er.clear()
        a.clear()
        self.assertTrue(a.isEmpty)
        self.assertTrue(bool(a_er.received))
        self.assertEqual('0', a.satsStr)

        a.clear()
        a_er.clear()
        a.isMax = True
        self.assertTrue(a.isMax)
        self.assertFalse(a.isEmpty)
        self.assertTrue(bool(a_er.received))
        self.assertEqual('0', a.satsStr)

        a.clear()
        a_er.clear()
        a.msatsInt = 1
        self.assertTrue(bool(a_er.received))
        self.assertFalse(a.isEmpty)
        self.assertEqual('1', a.msatsStr)

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

    @qt_test
    def test_qeamount_frominvoice(self):
        amount_sat = 10_000
        outputs = [PartialTxOutput.from_address_and_value('bc1qj3zx2zc4rpv3npzmznxhdxzn0wm7pzqp8p2293', amount_sat)]
        invoice = Invoice(
            amount_msat=amount_sat * 1000,
            message="mymsg",
            time=1692716965,
            exp=LN_EXPIRY_NEVER,
            outputs=outputs,
            bip70=None,
            height=0,
            lightning_invoice=None,
        )
        a = QEAmount(from_invoice=invoice)
        self.assertEqual(10_000, a.satsInt)
        self.assertEqual(10_000_000, a.msatsInt)
        self.assertFalse(a.isMax)

        outputs = [PartialTxOutput.from_address_and_value('bc1qj3zx2zc4rpv3npzmznxhdxzn0wm7pzqp8p2293', '!')]
        invoice = Invoice(
            amount_msat='!',
            message="mymsg",
            time=1692716965,
            exp=LN_EXPIRY_NEVER,
            outputs=outputs,
            bip70=None,
            height=0,
            lightning_invoice=None,
        )
        a = QEAmount(from_invoice=invoice)
        self.assertTrue(a.isMax)
        self.assertEqual(0, a.satsInt)
        self.assertEqual(0, a.msatsInt)

        bolt11 = 'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj'
        invoice = Invoice.from_bech32(bolt11)
        a = QEAmount(from_invoice=invoice)
        self.assertEqual(2_000_000, a.satsInt)
        self.assertEqual(2_000_000_000, a.msatsInt)
        self.assertFalse(a.isMax)
