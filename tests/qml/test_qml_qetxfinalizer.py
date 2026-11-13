import gc
import time
from collections import Counter
from decimal import Decimal

from electrum import constants, keystore
from electrum.bolt11 import BOLT11Addr, encode_bolt11_invoice
from electrum.invoices import Invoice
from electrum.simple_config import SimpleConfig
from electrum.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum.transaction import PartialTxOutput, Transaction

from electrum.gui.qml.qewallet import QEWallet
from electrum.gui.qml.qeinvoice import QEInvoice
from electrum.gui.qml.qetxfinalizer import QETxFinalizer
from electrum.gui.qml.qetypes import QEAmount

from .. import ElectrumTestCase
from ..test_bolt11 import PRIVKEY, RHASH, PAYMENT_SECRET
from ..test_wallet_vertical import WalletIntegrityHelper


class TestQmlMultiOutputInvoice(ElectrumTestCase):
    """Tests the pay path used by the QML gui with multi-output (paytomany) invoices,
    driving the same python objects the QML flow uses:
    WalletMainView.payOnchain() -> ConfirmTxDialog -> QETxFinalizer.make_tx()
    """
    TESTNET = True

    # p2wpkh wallet with a single 1_000_000 sat utxo (same fixture as TestWalletSending)
    SEED_FUNDED = 'bitter grass shiver impose acquire brush forget axis eager alone wine silver'
    SEED_RECIPIENT = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    FUNDING_TX = '01000000014576dacce264c24d81887642b726f5d64aa7825b21b350c7b75a57f337da6845010000006b483045022100a3f8b6155c71a98ad9986edd6161b20d24fad99b6463c23b463856c0ee54826d02200f606017fd987696ebbe5200daedde922eee264325a184d5bbda965ba5160821012102e5c473c051dae31043c335266d0ef89c1daab2f34d885cc7706b267f3269c609ffffffff0240420f00000000001600148a28bddb7f61864bdcf58b2ad13d5aeb3abc3c42a2ddb90e000000001976a914c384950342cb6f8df55175b48586838b03130fad88ac00000000'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # collect the QObject wrappers when the class is done: once a later test
        # creates a QCoreApplication, lingering ones become uncollectable and
        # keep their wallets alive (breaking the gc checks in test_daemon.py)
        cls.addClassCleanup(gc.collect)

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.FEE_POLICY = 'fixed:5000'

    def _create_funded_wallet(self):
        ks = keystore.from_seed(self.SEED_FUNDED, passphrase='', for_multisig=False)
        wallet = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=2, config=self.config)
        wallet.adb.receive_tx_callback(Transaction(self.FUNDING_TX), tx_height=TX_HEIGHT_UNCONFIRMED)
        return wallet

    def _recipient_addresses(self, n):
        ks = keystore.from_seed(self.SEED_RECIPIENT, passphrase='', for_multisig=False)
        w2 = WalletIntegrityHelper.create_standard_wallet(ks, gap_limit=max(n, 2), config=self.config)
        return w2.get_receiving_addresses()[:n]

    def _qeinvoice_for_saved_invoice(self, wallet, invoice):
        wallet.save_invoice(invoice)
        qew = QEWallet(wallet)
        self.addCleanup(qew.unregister_callbacks)
        qei = QEInvoice()
        self.addCleanup(qei.unregister_callbacks)
        qei.wallet = qew
        qei.key = invoice.get_id()
        return qew, qei

    def _finalizer_for_saved_invoice(self, wallet, invoice):
        """Wire up QEWallet/QEInvoice/QETxFinalizer the way WalletMainView.payOnchain()
        and ConfirmTxDialog wire them for a saved invoice."""
        qew, qei = self._qeinvoice_for_saved_invoice(wallet, invoice)
        fin = QETxFinalizer()
        fin.wallet = qew
        fin.address = qei.address
        fin.invoice = qei
        return qei, fin

    def _assert_tx_pays_outputs(self, tx, outputs):
        """every given output must appear in the tx (compared as multisets,
        so duplicate addresses are not collapsed)"""
        tx_outputs = Counter((o.address, o.value) for o in tx.outputs())
        expected = Counter((o.address, o.value) for o in outputs)
        self.assertEqual(Counter(), expected - tx_outputs,
                         f'invoice outputs not paid correctly: {tx.outputs()}')

    async def test_make_tx_pays_all_outputs_of_multi_output_invoice(self):
        wallet = self._create_funded_wallet()
        addrs = self._recipient_addresses(3)
        values = [100_000, 150_000, 200_000]
        outputs = [PartialTxOutput.from_address_and_value(a, v) for a, v in zip(addrs, values)]
        invoice = wallet.create_invoice(outputs=outputs, message='batch', URI=None)
        qei, fin = self._finalizer_for_saved_invoice(wallet, invoice)

        tx = fin.make_tx(sum(values))

        self._assert_tx_pays_outputs(tx, outputs)

    async def test_make_tx_pays_duplicate_address_outputs_separately(self):
        # paytomany invoices can pay the same address on multiple lines; the tx
        # must contain each output (make_unsigned_transaction does not merge
        # duplicate outputs by default)
        wallet = self._create_funded_wallet()
        addr = self._recipient_addresses(1)[0]
        outputs = [
            PartialTxOutput.from_address_and_value(addr, 100_000),
            PartialTxOutput.from_address_and_value(addr, 150_000),
        ]
        invoice = wallet.create_invoice(outputs=outputs, message='dup', URI=None)
        qei, fin = self._finalizer_for_saved_invoice(wallet, invoice)

        tx = fin.make_tx(250_000)

        self._assert_tx_pays_outputs(tx, outputs)

    async def test_make_tx_lightning_invoice_paid_via_fallback_uses_address_and_amount(self):
        # a lightning invoice paid onchain via its fallback address must keep the
        # (address, amount) path; the amount comes from the finalizer (it can
        # legitimately differ from the invoice amount), not from get_outputs()
        wallet = self._create_funded_wallet()
        fallback = self._recipient_addresses(1)[0]
        lnaddr = BOLT11Addr(
            date=int(time.time()),
            paymenthash=RHASH, payment_secret=PAYMENT_SECRET,
            amount=Decimal('0.003'),
            net=constants.BitcoinTestnet,
            tags=[('f', fallback), ('d', 'ln fallback'), ('9', 0x28200)])
        invoice = Invoice.from_bech32(encode_bolt11_invoice(lnaddr, PRIVKEY))
        qei, fin = self._finalizer_for_saved_invoice(wallet, invoice)

        tx = fin.make_tx(200_000)

        paid = {o.address: o.value for o in tx.outputs()}
        self.assertEqual(200_000, paid.get(fallback))

    async def test_update_rebuilds_tx_when_invoice_set_after_wallet(self):
        # in ConfirmTxDialog the finalizer's wallet binding triggers the first
        # update() before the invoice property lands, so setting the invoice
        # must rebuild the tx, or the collapsed single-output tx gets signed
        wallet = self._create_funded_wallet()
        addrs = self._recipient_addresses(3)
        values = [100_000, 150_000, 200_000]
        outputs = [PartialTxOutput.from_address_and_value(a, v) for a, v in zip(addrs, values)]
        invoice = wallet.create_invoice(outputs=outputs, message='batch', URI=None)
        qew, qei = self._qeinvoice_for_saved_invoice(wallet, invoice)

        fin = QETxFinalizer()
        fin.address = qei.address
        fin.amount = QEAmount(amount_sat=sum(values))
        fin.wallet = qew  # triggers update() while invoice is not set yet
        fin.invoice = qei

        self.assertTrue(fin.valid)
        self._assert_tx_pays_outputs(fin._tx, outputs)

    async def test_make_tx_pays_all_outputs_of_multiline_max_invoice(self):
        wallet = self._create_funded_wallet()
        addrs = self._recipient_addresses(2)
        outputs = [
            PartialTxOutput.from_address_and_value(addrs[0], 100_000),
            PartialTxOutput.from_address_and_value(addrs[1], '!'),
        ]
        invoice = wallet.create_invoice(outputs=outputs, message='batch max', URI=None)
        qei, fin = self._finalizer_for_saved_invoice(wallet, invoice)

        tx = fin.make_tx('!')

        paid = {o.address: o.value for o in tx.outputs()}
        self.assertEqual(2, len(tx.outputs()), f'expected no change output: {paid}')
        self.assertEqual(100_000, paid.get(addrs[0]))
        self.assertEqual(1_000_000 - 100_000 - 5000, paid.get(addrs[1]))

    async def test_make_tx_zero_amount_invoice_still_uses_override_amount(self):
        # zero-amount invoices carry value=0 outputs; the amount the user entered
        # arrives via the amount override, so the address+amount path must be kept
        wallet = self._create_funded_wallet()
        addr = self._recipient_addresses(1)[0]
        outputs = [PartialTxOutput.from_address_and_value(addr, 0)]
        invoice = wallet.create_invoice(outputs=outputs, message='no amount', URI=None)
        qei, fin = self._finalizer_for_saved_invoice(wallet, invoice)

        tx = fin.make_tx(300_000)

        paid = {o.address: o.value for o in tx.outputs()}
        self.assertEqual(300_000, paid.get(addr))

    async def test_amountless_multi_output_invoice_cannot_be_paid(self):
        # the desktop multiline parser accepts zero-value lines, so a saved
        # multi-output invoice can have an unspecified amount. An amount entered
        # by the user must not make it payable: the pay path spends to the
        # invoice outputs as-is, which would silently discard the entered amount
        wallet = self._create_funded_wallet()
        addrs = self._recipient_addresses(2)
        outputs = [PartialTxOutput.from_address_and_value(a, 0) for a in addrs]
        invoice = wallet.create_invoice(outputs=outputs, message='no amounts', URI=None)
        qew, qei = self._qeinvoice_for_saved_invoice(wallet, invoice)

        qei.amountOverride = QEAmount(amount_sat=300_000)  # as if entered by the user

        self.assertFalse(qei.canPay)

    async def test_amount_override_cleared_when_multi_output_invoice_loaded(self):
        # the QEInvoice instance is shared between subsequently viewed invoices;
        # an amount override left over from a previously viewed zero-amount
        # invoice must not be applied to a multi-output invoice
        wallet = self._create_funded_wallet()
        addrs = self._recipient_addresses(2)
        outputs = [PartialTxOutput.from_address_and_value(a, v) for a, v in zip(addrs, [100_000, 150_000])]
        invoice = wallet.create_invoice(outputs=outputs, message='batch', URI=None)
        wallet.save_invoice(invoice)
        qew = QEWallet(wallet)
        self.addCleanup(qew.unregister_callbacks)
        qei = QEInvoice()
        self.addCleanup(qei.unregister_callbacks)
        qei.wallet = qew
        qei.amountOverride = QEAmount(amount_sat=123_000)  # stale, from a previously viewed invoice

        qei.key = invoice.get_id()

        self.assertTrue(qei.amountOverride.isEmpty)

    async def test_qeinvoice_exposes_outputs_for_display(self):
        wallet = self._create_funded_wallet()
        addrs = self._recipient_addresses(3)
        values = [100_000, '!', '2!']
        outputs = [PartialTxOutput.from_address_and_value(a, v) for a, v in zip(addrs, values)]
        invoice = wallet.create_invoice(outputs=outputs, message='batch', URI=None)
        qew, qei = self._qeinvoice_for_saved_invoice(wallet, invoice)

        outs = qei.outputs
        self.assertEqual(3, len(outs))
        self.assertEqual(addrs, [o['address'] for o in outs])
        self.assertEqual(values, [o['value'] for o in outs])
        self.assertEqual([False, True, True], [o['is_max'] for o in outs])
