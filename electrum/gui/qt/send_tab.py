# Copyright (C) 2022 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
from decimal import Decimal
from typing import Optional, TYPE_CHECKING, Sequence, List
from urllib.parse import urlparse

from PyQt5.QtCore import pyqtSignal, QPoint
from PyQt5.QtWidgets import (QLabel, QVBoxLayout, QGridLayout,
                             QHBoxLayout, QCompleter, QWidget, QToolTip, QPushButton)

from electrum import util, paymentrequest
from electrum import lnutil
from electrum.plugin import run_hook
from electrum.i18n import _
from electrum.util import (get_asyncio_loop, FailedToParsePaymentIdentifier,
                           InvalidBitcoinURI, maybe_extract_lightning_payment_identifier, NotEnoughFunds,
                           NoDynamicFeeEstimates, InvoiceError, parse_max_spend)
from electrum.invoices import PR_PAID, Invoice, PR_BROADCASTING, PR_BROADCAST
from electrum.transaction import Transaction, PartialTxInput, PartialTransaction, PartialTxOutput
from electrum.network import TxBroadcastError, BestEffortRequestFailed
from electrum.logging import Logger
from electrum.lnaddr import lndecode, LnInvoiceException
from electrum.lnurl import decode_lnurl, request_lnurl, callback_lnurl, LNURLError, LNURL6Data

from .amountedit import AmountEdit, BTCAmountEdit, SizedFreezableLineEdit
from .util import WaitingDialog, HelpLabel, MessageBoxMixin, EnterButton, char_width_in_lineedit
from .util import get_iconname_camera, get_iconname_qrcode, read_QIcon
from .confirm_tx_dialog import ConfirmTxDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class SendTab(QWidget, MessageBoxMixin, Logger):

    payment_request_ok_signal = pyqtSignal()
    payment_request_error_signal = pyqtSignal()
    lnurl6_round1_signal = pyqtSignal(object, object)
    lnurl6_round2_signal = pyqtSignal(object)
    clear_send_tab_signal = pyqtSignal()
    show_error_signal = pyqtSignal(str)

    payment_request: Optional[paymentrequest.PaymentRequest]
    _lnurl_data: Optional[LNURL6Data] = None

    def __init__(self, window: 'ElectrumWindow'):
        QWidget.__init__(self, window)
        Logger.__init__(self)

        self.window = window
        self.wallet = window.wallet
        self.fx = window.fx
        self.config = window.config
        self.network = window.network

        self.format_amount_and_units = window.format_amount_and_units
        self.format_amount = window.format_amount
        self.base_unit = window.base_unit

        self.payto_URI = None
        self.payment_request = None  # type: Optional[paymentrequest.PaymentRequest]
        self.pending_invoice = None

        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self.send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        from .paytoedit import PayToEdit
        self.amount_e = BTCAmountEdit(self.window.get_decimal_point)
        self.payto_e = PayToEdit(self)
        msg = (_("Recipient of the funds.") + "\n\n"
               + _("You may enter a Bitcoin address, a label from your list of contacts "
                   "(a list of completions will be proposed), "
                   "or an alias (email-like address that forwards to a Bitcoin address)") + ". "
               + _("Lightning invoices are also supported.") + "\n\n"
               + _("You can also pay to many outputs in a single transaction, "
                   "specifying one output per line.") + "\n" + _("Format: address, amount") + "\n"
               + _("To set the amount to 'max', use the '!' special character.") + "\n"
               + _("Integers weights can also be used in conjunction with '!', "
                   "e.g. set one amount to '2!' and another to '3!' to split your coins 40-60."))
        payto_label = HelpLabel(_('Pay to'), msg)
        grid.addWidget(payto_label, 1, 0)
        grid.addWidget(self.payto_e.line_edit, 1, 1, 1, 4)
        grid.addWidget(self.payto_e.text_edit, 1, 1, 1, 4)

        #completer = QCompleter()
        #completer.setCaseSensitivity(False)
        #self.payto_e.set_completer(completer)
        #completer.setModel(self.window.completions)

        msg = _('Description of the transaction (not mandatory).') + '\n\n' \
              + _(
            'The description is not sent to the recipient of the funds. It is stored in your wallet file, and displayed in the \'History\' tab.')
        description_label = HelpLabel(_('Description'), msg)
        grid.addWidget(description_label, 2, 0)
        self.message_e = SizedFreezableLineEdit(width=600)
        grid.addWidget(self.message_e, 2, 1, 1, 4)

        msg = (_('The amount to be received by the recipient.') + ' '
               + _('Fees are paid by the sender.') + '\n\n'
               + _('The amount will be displayed in red if you do not have enough funds in your wallet.') + ' '
               + _('Note that if you have frozen some of your addresses, the available funds will be lower than your total balance.') + '\n\n'
               + _('Keyboard shortcut: type "!" to send all your coins.'))
        amount_label = HelpLabel(_('Amount'), msg)
        grid.addWidget(amount_label, 3, 0)
        grid.addWidget(self.amount_e, 3, 1)

        self.fiat_send_e = AmountEdit(self.fx.get_currency if self.fx else '')
        if not self.fx or not self.fx.is_enabled():
            self.fiat_send_e.setVisible(False)
        grid.addWidget(self.fiat_send_e, 3, 2)
        self.amount_e.frozen.connect(
            lambda: self.fiat_send_e.setFrozen(self.amount_e.isReadOnly()))

        self.window.connect_fields(self.amount_e, self.fiat_send_e)

        self.max_button = EnterButton(_("Max"), self.spend_max)
        btn_width = 10 * char_width_in_lineedit()
        self.max_button.setFixedWidth(btn_width)
        self.max_button.setCheckable(True)
        grid.addWidget(self.max_button, 3, 3)

        self.save_button = EnterButton(_("Save"), self.do_save_invoice)
        self.send_button = EnterButton(_("Pay") + "...", self.do_pay_or_get_invoice)
        self.clear_button = EnterButton(_("Clear"), self.do_clear)
        self.paste_button = QPushButton()
        self.paste_button.clicked.connect(lambda: self.payto_e._on_input_btn(self.window.app.clipboard().text()))
        self.paste_button.setIcon(read_QIcon('copy.png'))
        self.paste_button.setToolTip(_('Paste invoice from clipboard'))
        self.paste_button.setMaximumWidth(35)
        grid.addWidget(self.paste_button, 1, 5)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        #buttons.addWidget(self.paste_button)
        buttons.addWidget(self.clear_button)
        buttons.addWidget(self.save_button)
        buttons.addWidget(self.send_button)
        grid.addLayout(buttons, 6, 1, 1, 4)

        self.amount_e.shortcut.connect(self.spend_max)

        def reset_max(text):
            self.max_button.setChecked(False)
            enable = not bool(text) and not self.amount_e.isReadOnly()
            # self.max_button.setEnabled(enable)

        self.amount_e.textEdited.connect(reset_max)
        self.fiat_send_e.textEdited.connect(reset_max)

        self.set_onchain(False)

        self.invoices_label = QLabel(_('Invoices'))
        from .invoice_list import InvoiceList
        self.invoice_list = InvoiceList(self)
        self.toolbar, menu = self.invoice_list.create_toolbar_with_menu('')


        menu.addAction(read_QIcon(get_iconname_camera()),    _("Read QR code with camera"), self.payto_e.on_qr_from_camera_input_btn)
        menu.addAction(read_QIcon("picture_in_picture.png"), _("Read QR code from screen"), self.payto_e.on_qr_from_screenshot_input_btn)
        menu.addAction(read_QIcon("file.png"), _("Read invoice from file"), self.payto_e.on_input_file)
        self.paytomany_menu = menu.addToggle(_("&Pay to many"), self.toggle_paytomany)
        menu.addSeparator()
        menu.addAction(_("Import invoices"), self.window.import_invoices)
        menu.addAction(_("Export invoices"), self.window.export_invoices)

        vbox0 = QVBoxLayout()
        vbox0.addLayout(grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)
        hbox.addStretch(1)

        vbox = QVBoxLayout(self)
        vbox.addLayout(self.toolbar)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addWidget(self.invoices_label)
        vbox.addWidget(self.invoice_list)
        vbox.setStretchFactor(self.invoice_list, 1000)
        self.searchable_list = self.invoice_list
        self.invoice_list.update()  # after parented and put into a layout, can update without flickering
        run_hook('create_send_tab', grid)

        self.payment_request_ok_signal.connect(self.payment_request_ok)
        self.payment_request_error_signal.connect(self.payment_request_error)
        self.lnurl6_round1_signal.connect(self.on_lnurl6_round1)
        self.lnurl6_round2_signal.connect(self.on_lnurl6_round2)
        self.clear_send_tab_signal.connect(self.do_clear)
        self.show_error_signal.connect(self.show_error)

    def spend_max(self):
        if run_hook('abort_send', self):
            return
        outputs = self.payto_e.get_outputs(True)
        if not outputs:
            return
        make_tx = lambda fee_est, *, confirmed_only=False: self.wallet.make_unsigned_transaction(
            coins=self.window.get_coins(),
            outputs=outputs,
            fee=fee_est,
            is_sweep=False)
        try:
            try:
                tx = make_tx(None)
            except (NotEnoughFunds, NoDynamicFeeEstimates) as e:
                # Check if we had enough funds excluding fees,
                # if so, still provide opportunity to set lower fees.
                tx = make_tx(0)
        except NotEnoughFunds as e:
            self.max_button.setChecked(False)
            text = self.get_text_not_enough_funds_mentioning_frozen()
            self.show_error(text)
            return

        self.max_button.setChecked(True)
        amount = tx.output_value()
        __, x_fee_amount = run_hook('get_tx_extra_fee', self.wallet, tx) or (None, 0)
        amount_after_all_fees = amount - x_fee_amount
        self.amount_e.setAmount(amount_after_all_fees)
        # show tooltip explaining max amount
        mining_fee = tx.get_fee()
        mining_fee_str = self.format_amount_and_units(mining_fee)
        msg = _("Mining fee: {} (can be adjusted on next screen)").format(mining_fee_str)
        if x_fee_amount:
            twofactor_fee_str = self.format_amount_and_units(x_fee_amount)
            msg += "\n" + _("2fa fee: {} (for the next batch of transactions)").format(twofactor_fee_str)
        frozen_bal = self.get_frozen_balance_str()
        if frozen_bal:
            msg += "\n" + _("Some coins are frozen: {} (can be unfrozen in the Addresses or in the Coins tab)").format(frozen_bal)
        QToolTip.showText(self.max_button.mapToGlobal(QPoint(0, 0)), msg)

    def pay_onchain_dialog(
            self,
            outputs: List[PartialTxOutput], *,
            nonlocal_only=False,
            external_keypairs=None) -> None:
        # trustedcoin requires this
        if run_hook('abort_send', self):
            return
        is_sweep = bool(external_keypairs)
        # we call get_coins inside make_tx, so that inputs can be changed dynamically
        make_tx = lambda fee_est, *, confirmed_only=False: self.wallet.make_unsigned_transaction(
            coins=self.window.get_coins(nonlocal_only=nonlocal_only, confirmed_only=confirmed_only),
            outputs=outputs,
            fee=fee_est,
            is_sweep=is_sweep)
        output_values = [x.value for x in outputs]
        is_max = any(parse_max_spend(outval) for outval in output_values)
        output_value = '!' if is_max else sum(output_values)
        conf_dlg = ConfirmTxDialog(window=self.window, make_tx=make_tx, output_value=output_value)
        if conf_dlg.not_enough_funds:
            confirmed_only = self.config.get('confirmed_only', False)
            if not conf_dlg.can_pay_assuming_zero_fees(confirmed_only=False):
                text = self.get_text_not_enough_funds_mentioning_frozen()
                self.show_message(text)
                return
        tx = conf_dlg.run()
        if tx is None:
            # user cancelled
            return
        is_preview = conf_dlg.is_preview
        if is_preview:
            self.window.show_transaction(tx)
            return
        self.save_pending_invoice()
        def sign_done(success):
            if success:
                self.window.broadcast_or_show(tx)
            else:
                raise
        self.window.sign_tx(
            tx,
            callback=sign_done,
            external_keypairs=external_keypairs)

    def get_text_not_enough_funds_mentioning_frozen(self) -> str:
        text = _("Not enough funds")
        frozen_str = self.get_frozen_balance_str()
        if frozen_str:
            text += " ({} {})".format(
                frozen_str, _("are frozen")
            )
        return text

    def get_frozen_balance_str(self) -> Optional[str]:
        frozen_bal = sum(self.wallet.get_frozen_balance())
        if not frozen_bal:
            return None
        return self.format_amount_and_units(frozen_bal)

    def do_clear(self):
        self._lnurl_data = None
        self.max_button.setChecked(False)
        self.payment_request = None
        self.payto_URI = None
        self.payto_e.do_clear()
        self.set_onchain(False)
        for e in [self.message_e, self.amount_e]:
            e.setText('')
            e.setFrozen(False)
        for e in [self.send_button, self.save_button, self.clear_button, self.amount_e, self.fiat_send_e]:
            e.setEnabled(True)
        self.window.update_status()
        run_hook('do_clear', self)

    def set_onchain(self, b):
        self._is_onchain = b
        self.max_button.setEnabled(b)

    def lock_amount(self, b: bool) -> None:
        self.amount_e.setFrozen(b)
        self.max_button.setEnabled(not b)

    def prepare_for_send_tab_network_lookup(self):
        self.window.show_send_tab()
        self.payto_e.disable_checks = True
        for e in [self.payto_e, self.message_e]:
            e.setFrozen(True)
        self.lock_amount(True)
        for btn in [self.save_button, self.send_button, self.clear_button]:
            btn.setEnabled(False)
        self.payto_e.setTextNoCheck(_("please wait..."))

    def payment_request_ok(self):
        pr = self.payment_request
        if not pr:
            return
        invoice = Invoice.from_bip70_payreq(pr, height=0)
        if self.wallet.get_invoice_status(invoice) == PR_PAID:
            self.show_message("invoice already paid")
            self.do_clear()
            self.payment_request = None
            return
        self.payto_e.disable_checks = True
        if not pr.has_expired():
            self.payto_e.setGreen()
        else:
            self.payto_e.setExpired()
        self.payto_e.setTextNoCheck(pr.get_requestor())
        self.amount_e.setAmount(pr.get_amount())
        self.message_e.setText(pr.get_memo())
        self.set_onchain(True)
        self.max_button.setEnabled(False)
        # note: allow saving bip70 reqs, as we save them anyway when paying them
        for btn in [self.send_button, self.clear_button, self.save_button]:
            btn.setEnabled(True)
        # signal to set fee
        self.amount_e.textEdited.emit("")

    def payment_request_error(self):
        pr = self.payment_request
        if not pr:
            return
        self.show_message(pr.error)
        self.payment_request = None
        self.do_clear()

    def on_pr(self, request: 'paymentrequest.PaymentRequest'):
        self.payment_request = request
        if self.payment_request.verify(self.window.contacts):
            self.payment_request_ok_signal.emit()
        else:
            self.payment_request_error_signal.emit()

    def set_lnurl6(self, lnurl: str, *, can_use_network: bool = True):
        try:
            url = decode_lnurl(lnurl)
        except LnInvoiceException as e:
            self.show_error(_("Error parsing Lightning invoice") + f":\n{e}")
            return
        if not can_use_network:
            return

        async def f():
            try:
                lnurl_data = await request_lnurl(url)
            except LNURLError as e:
                self.show_error_signal.emit(f"LNURL request encountered error: {e}")
                self.clear_send_tab_signal.emit()
                return
            self.lnurl6_round1_signal.emit(lnurl_data, url)

        asyncio.run_coroutine_threadsafe(f(), get_asyncio_loop())  # TODO should be cancellable
        self.prepare_for_send_tab_network_lookup()

    def on_lnurl6_round1(self, lnurl_data: LNURL6Data, url: str):
        self._lnurl_data = lnurl_data
        domain = urlparse(url).netloc
        self.payto_e.setTextNoCheck(f"invoice from lnurl")
        self.message_e.setText(f"lnurl: {domain}: {lnurl_data.metadata_plaintext}")
        self.amount_e.setAmount(lnurl_data.min_sendable_sat)
        self.amount_e.setFrozen(False)
        for btn in [self.send_button, self.clear_button]:
            btn.setEnabled(True)
        self.set_onchain(False)

    def set_bolt11(self, invoice: str):
        """Parse ln invoice, and prepare the send tab for it."""
        try:
            lnaddr = lndecode(invoice)
        except LnInvoiceException as e:
            self.show_error(_("Error parsing Lightning invoice") + f":\n{e}")
            return
        except lnutil.IncompatibleOrInsaneFeatures as e:
            self.show_error(_("Invoice requires unknown or incompatible Lightning feature") + f":\n{e!r}")
            return

        pubkey = lnaddr.pubkey.serialize().hex()
        for k,v in lnaddr.tags:
            if k == 'd':
                description = v
                break
        else:
             description = ''
        self.payto_e.setFrozen(True)
        self.payto_e.setTextNoCheck(pubkey)
        self.payto_e.lightning_invoice = invoice
        if not self.message_e.text():
            self.message_e.setText(description)
        if lnaddr.get_amount_sat() is not None:
            self.amount_e.setAmount(lnaddr.get_amount_sat())
        self.set_onchain(False)

    def set_bip21(self, text: str, *, can_use_network: bool = True):
        on_bip70_pr = self.on_pr if can_use_network else None
        try:
            out = util.parse_URI(text, on_bip70_pr)
        except InvalidBitcoinURI as e:
            self.show_error(_("Error parsing URI") + f":\n{e}")
            return
        self.payto_URI = out
        r = out.get('r')
        sig = out.get('sig')
        name = out.get('name')
        if (r or (name and sig)) and can_use_network:
            self.prepare_for_send_tab_network_lookup()
            return
        address = out.get('address')
        amount = out.get('amount')
        label = out.get('label')
        message = out.get('message')
        lightning = out.get('lightning')
        if lightning and (self.wallet.has_lightning() or not address):
            self.handle_payment_identifier(lightning, can_use_network=can_use_network)
            return
        # use label as description (not BIP21 compliant)
        if label and not message:
            message = label
        if address:
            self.payto_e.setText(address)
        if message:
            self.message_e.setText(message)
        if amount:
            self.amount_e.setAmount(amount)

    def handle_payment_identifier(self, text: str, *, can_use_network: bool = True):
        """Takes
        Lightning identifiers:
        * lightning-URI (containing bolt11 or lnurl)
        * bolt11 invoice
        * lnurl
        Bitcoin identifiers:
        * bitcoin-URI
        and sets the sending screen.
        """
        text = text.strip()
        if not text:
            return
        if invoice_or_lnurl := maybe_extract_lightning_payment_identifier(text):
            if invoice_or_lnurl.startswith('lnurl'):
                self.set_lnurl6(invoice_or_lnurl, can_use_network=can_use_network)
            else:
                self.set_bolt11(invoice_or_lnurl)
        elif text.lower().startswith(util.BITCOIN_BIP21_URI_SCHEME + ':'):
            self.set_bip21(text, can_use_network=can_use_network)
        else:
            truncated_text = f"{text[:100]}..." if len(text) > 100 else text
            raise FailedToParsePaymentIdentifier(f"Could not handle payment identifier:\n{truncated_text}")
        # update fiat amount
        self.amount_e.textEdited.emit("")
        self.window.show_send_tab()

    def read_invoice(self) -> Optional[Invoice]:
        if self.check_payto_line_and_show_errors():
            return
        try:
            if not self._is_onchain:
                invoice_str = self.payto_e.lightning_invoice
                if not invoice_str:
                    return
                invoice = Invoice.from_bech32(invoice_str)
                if invoice.amount_msat is None:
                    amount_sat = self.get_amount()
                    if amount_sat:
                        invoice.amount_msat = int(amount_sat * 1000)
                if not self.wallet.has_lightning() and not invoice.can_be_paid_onchain():
                    self.show_error(_('Lightning is disabled'))
                    return
                return invoice
            else:
                outputs = self.read_outputs()
                if self.check_onchain_outputs_and_show_errors(outputs):
                    return
                message = self.message_e.text()
                return self.wallet.create_invoice(
                    outputs=outputs,
                    message=message,
                    pr=self.payment_request,
                    URI=self.payto_URI)
        except InvoiceError as e:
            self.show_error(_('Error creating payment') + ':\n' + str(e))

    def do_save_invoice(self):
        self.pending_invoice = self.read_invoice()
        if not self.pending_invoice:
            return
        self.save_pending_invoice()

    def save_pending_invoice(self):
        if not self.pending_invoice:
            return
        self.do_clear()
        self.wallet.save_invoice(self.pending_invoice)
        self.invoice_list.update()
        self.pending_invoice = None

    def get_amount(self) -> int:
        # must not be None
        return self.amount_e.get_amount() or 0

    def _lnurl_get_invoice(self) -> None:
        assert self._lnurl_data
        amount = self.get_amount()
        if not (self._lnurl_data.min_sendable_sat <= amount <= self._lnurl_data.max_sendable_sat):
            self.show_error(f'Amount must be between {self._lnurl_data.min_sendable_sat} and {self._lnurl_data.max_sendable_sat} sat.')
            return

        async def f():
            try:
                invoice_data = await callback_lnurl(
                    self._lnurl_data.callback_url,
                    params={'amount': self.get_amount() * 1000},
                )
            except LNURLError as e:
                self.show_error_signal.emit(f"LNURL request encountered error: {e}")
                self.clear_send_tab_signal.emit()
                return
            invoice = invoice_data.get('pr')
            self.lnurl6_round2_signal.emit(invoice)

        asyncio.run_coroutine_threadsafe(f(), get_asyncio_loop())  # TODO should be cancellable
        self.prepare_for_send_tab_network_lookup()

    def on_lnurl6_round2(self, bolt11_invoice: str):
        self._lnurl_data = None
        invoice = Invoice.from_bech32(bolt11_invoice)
        assert invoice.get_amount_sat() == self.get_amount(), (invoice.get_amount_sat(), self.get_amount())
        self.do_clear()
        self.payto_e.setText(bolt11_invoice)
        self.pending_invoice = invoice
        self.do_pay_invoice(invoice)

    def do_pay_or_get_invoice(self):
        if self._lnurl_data:
            self._lnurl_get_invoice()
            return
        self.pending_invoice = self.read_invoice()
        if not self.pending_invoice:
            return
        self.do_pay_invoice(self.pending_invoice)

    def pay_multiple_invoices(self, invoices):
        outputs = []
        for invoice in invoices:
            outputs += invoice.outputs
        self.pay_onchain_dialog(outputs)

    def do_edit_invoice(self, invoice: 'Invoice'):
        assert not bool(invoice.get_amount_sat())
        text = invoice.lightning_invoice if invoice.is_lightning() else invoice.get_address()
        self.payto_e._on_input_btn(text)
        self.amount_e.setFocus()
        # disable save button, because it would create a new invoice
        self.save_button.setEnabled(False)

    def do_pay_invoice(self, invoice: 'Invoice'):
        if not bool(invoice.get_amount_sat()):
            self.show_error(_('No amount'))
            return
        if invoice.is_lightning():
            self.pay_lightning_invoice(invoice)
        else:
            self.pay_onchain_dialog(invoice.outputs)

    def read_outputs(self) -> List[PartialTxOutput]:
        if self.payment_request:
            outputs = self.payment_request.get_outputs()
        else:
            outputs = self.payto_e.get_outputs(self.max_button.isChecked())
        return outputs

    def check_onchain_outputs_and_show_errors(self, outputs: List[PartialTxOutput]) -> bool:
        """Returns whether there are errors with outputs.
        Also shows error dialog to user if so.
        """
        if not outputs:
            self.show_error(_('No outputs'))
            return True

        for o in outputs:
            if o.scriptpubkey is None:
                self.show_error(_('Bitcoin Address is None'))
                return True
            if o.value is None:
                self.show_error(_('Invalid Amount'))
                return True

        return False  # no errors

    def check_payto_line_and_show_errors(self) -> bool:
        """Returns whether there are errors.
        Also shows error dialog to user if so.
        """
        pr = self.payment_request
        if pr:
            if pr.has_expired():
                self.show_error(_('Payment request has expired'))
                return True

        if not pr:
            errors = self.payto_e.get_errors()
            if errors:
                if len(errors) == 1 and not errors[0].is_multiline:
                    err = errors[0]
                    self.show_warning(_("Failed to parse 'Pay to' line") + ":\n" +
                                      f"{err.line_content[:40]}...\n\n"
                                      f"{err.exc!r}")
                else:
                    self.show_warning(_("Invalid Lines found:") + "\n\n" +
                                      '\n'.join([_("Line #") +
                                                 f"{err.idx+1}: {err.line_content[:40]}... ({err.exc!r})"
                                                 for err in errors]))
                return True

            if self.payto_e.is_alias and self.payto_e.validated is False:
                alias = self.payto_e.toPlainText()
                msg = _('WARNING: the alias "{}" could not be validated via an additional '
                        'security check, DNSSEC, and thus may not be correct.').format(alias) + '\n'
                msg += _('Do you wish to continue?')
                if not self.question(msg):
                    return True

        return False  # no errors

    def pay_lightning_invoice(self, invoice: Invoice):
        amount_sat = invoice.get_amount_sat()
        if amount_sat is None:
            raise Exception("missing amount for LN invoice")
        # note: lnworker might be None if LN is disabled,
        #       in which case we should still offer the user to pay onchain.
        lnworker = self.wallet.lnworker
        if lnworker is None or not lnworker.can_pay_invoice(invoice):
            coins = self.window.get_coins(nonlocal_only=True)
            can_pay_onchain = invoice.can_be_paid_onchain() and self.wallet.can_pay_onchain(invoice.get_outputs(), coins=coins)
            can_pay_with_new_channel = False
            can_pay_with_swap = False
            can_rebalance = False
            if lnworker:
                can_pay_with_new_channel = lnworker.suggest_funding_amount(amount_sat, coins=coins)
                can_pay_with_swap = lnworker.suggest_swap_to_send(amount_sat, coins=coins)
                rebalance_suggestion = lnworker.suggest_rebalance_to_send(amount_sat)
                can_rebalance = bool(rebalance_suggestion) and self.window.num_tasks() == 0
            choices = {}
            if can_rebalance:
                msg = ''.join([
                    _('Rebalance existing channels'), '\n',
                    _('Move funds between your channels in order to increase your sending capacity.')
                ])
                choices[0] = msg
            if can_pay_with_new_channel:
                msg = ''.join([
                    _('Open a new channel'), '\n',
                    _('You will be able to pay once the channel is open.')
                ])
                choices[1] = msg
            if can_pay_with_swap:
                msg = ''.join([
                    _('Swap onchain funds for lightning funds'), '\n',
                    _('You will be able to pay once the swap is confirmed.')
                ])
                choices[2] = msg
            if can_pay_onchain:
                msg = ''.join([
                    _('Pay onchain'), '\n',
                    _('Funds will be sent to the invoice fallback address.')
                ])
                choices[3] = msg
            msg = _('You cannot pay that invoice using Lightning.')
            if lnworker and lnworker.channels:
                num_sats_can_send = int(lnworker.num_sats_can_send())
                msg += '\n' + _('Your channels can send {}.').format(self.format_amount(num_sats_can_send) + ' ' + self.base_unit())
            if not choices:
                self.window.show_error(msg)
                return
            r = self.window.query_choice(msg, choices)
            if r is not None:
                self.save_pending_invoice()
                if r == 0:
                    chan1, chan2, delta = rebalance_suggestion
                    self.window.rebalance_dialog(chan1, chan2, amount_sat=delta)
                elif r == 1:
                    amount_sat, min_amount_sat = can_pay_with_new_channel
                    self.window.new_channel_dialog(amount_sat=amount_sat, min_amount_sat=min_amount_sat)
                elif r == 2:
                    chan, swap_recv_amount_sat = can_pay_with_swap
                    self.window.run_swap_dialog(is_reverse=False, recv_amount_sat=swap_recv_amount_sat, channels=[chan])
                elif r == 3:
                    self.pay_onchain_dialog(invoice.get_outputs(), nonlocal_only=True)
            return

        assert lnworker is not None
        # FIXME this is currently lying to user as we truncate to satoshis
        amount_msat = invoice.get_amount_msat()
        msg = _("Pay lightning invoice?") + '\n\n' + _("This will send {}?").format(self.format_amount_and_units(Decimal(amount_msat)/1000))
        if not self.question(msg):
            return
        self.save_pending_invoice()
        coro = lnworker.pay_invoice(invoice.lightning_invoice, amount_msat=amount_msat)
        self.window.run_coroutine_from_thread(coro, _('Sending payment'))

    def broadcast_transaction(self, tx: Transaction):

        def broadcast_thread():
            # non-GUI thread
            pr = self.payment_request
            if pr and pr.has_expired():
                self.payment_request = None
                return False, _("Invoice has expired")
            try:
                self.network.run_from_another_thread(self.network.broadcast_transaction(tx))
            except TxBroadcastError as e:
                return False, e.get_message_for_gui()
            except BestEffortRequestFailed as e:
                return False, repr(e)
            # success
            txid = tx.txid()
            if pr:
                self.payment_request = None
                refund_address = self.wallet.get_receiving_address()
                coro = pr.send_payment_and_receive_paymentack(tx.serialize(), refund_address)
                fut = asyncio.run_coroutine_threadsafe(coro, self.network.asyncio_loop)
                ack_status, ack_msg = fut.result(timeout=20)
                self.logger.info(f"Payment ACK: {ack_status}. Ack message: {ack_msg}")
            return True, txid

        # Capture current TL window; override might be removed on return
        parent = self.window.top_level_window(lambda win: isinstance(win, MessageBoxMixin))

        self.wallet.set_broadcasting(tx, PR_BROADCASTING)

        def broadcast_done(result):
            # GUI thread
            if result:
                success, msg = result
                if success:
                    parent.show_message(_('Payment sent.') + '\n' + msg)
                    self.invoice_list.update()
                    self.wallet.set_broadcasting(tx, PR_BROADCAST)
                else:
                    msg = msg or ''
                    parent.show_error(msg)
                    self.wallet.set_broadcasting(tx, None)

        WaitingDialog(self, _('Broadcasting transaction...'),
                      broadcast_thread, broadcast_done, self.window.on_error)

    def toggle_paytomany(self):
        self.payto_e.toggle_paytomany()
        if self.payto_e.is_paytomany():
            message = '\n'.join([
                _('Enter a list of outputs in the \'Pay to\' field.'),
                _('One output per line.'),
                _('Format: address, amount'),
                _('You may load a CSV file using the file icon.')
            ])
            self.window.show_tooltip_after_delay(message)

    def payto_contacts(self, labels):
        paytos = [self.window.get_contact_payto(label) for label in labels]
        self.window.show_send_tab()
        if len(paytos) == 1:
            self.payto_e.setText(paytos[0])
            self.amount_e.setFocus()
        else:
            text = "\n".join([payto + ", 0" for payto in paytos])
            self.payto_e.setText(text)
            self.payto_e.setFocus()


