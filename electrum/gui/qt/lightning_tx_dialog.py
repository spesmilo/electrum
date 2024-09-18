#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2020 The Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from typing import TYPE_CHECKING
from decimal import Decimal
import datetime

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QVBoxLayout, QLabel, QGridLayout

from electrum.i18n import _
from electrum.lnworker import PaymentDirection
from electrum.invoices import Invoice

from .util import WindowModalDialog, ShowQRLineEdit, ColorScheme, Buttons, CloseButton, font_height, ButtonsLineEdit
from .qrtextedit import ShowQRTextEdit

if TYPE_CHECKING:
    from .main_window import ElectrumWindow



class LightningTxDialog(WindowModalDialog):

    def __init__(self, parent: 'ElectrumWindow', tx_item: dict):
        WindowModalDialog.__init__(self, parent, _("Lightning Payment"))
        self.main_window = parent
        self.config = parent.config
        self.is_sent = tx_item['direction'] == PaymentDirection.SENT
        self.label = tx_item['label']
        self.timestamp = tx_item['timestamp']
        self.amount = Decimal(tx_item['amount_msat']) / 1000
        self.payment_hash = tx_item['payment_hash']
        self.preimage = tx_item['preimage']
        self.invoice = ""
        invoice = self.main_window.wallet.get_invoice(self.payment_hash)  # only check outgoing invoices
        if invoice:
            assert invoice.is_lightning(), f"{self.invoice!r}"
            self.invoice = invoice.lightning_invoice
        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        amount_str = self.main_window.format_amount_and_units(self.amount, timestamp=self.timestamp)
        vbox.addWidget(QLabel(_("Amount") + f": {amount_str}"))
        if self.is_sent:
            fee_msat = tx_item['fee_msat']
            fee_sat = Decimal(fee_msat) / 1000 if fee_msat is not None else None
            fee_str = self.main_window.format_amount_and_units(fee_sat, timestamp=self.timestamp)
            vbox.addWidget(QLabel(_("Fee") + f": {fee_str}"))
        time_str = datetime.datetime.fromtimestamp(self.timestamp).isoformat(' ')[:-3]
        vbox.addWidget(QLabel(_("Date") + ": " + time_str))
        self.tx_desc_label = QLabel(_("Description:"))
        vbox.addWidget(self.tx_desc_label)
        self.tx_desc = ButtonsLineEdit(self.label)
        def on_edited():
            text = self.tx_desc.text()
            if self.main_window.wallet.set_label(self.payment_hash, text):
                self.main_window.history_list.update()
                self.main_window.utxo_list.update()
                self.main_window.labels_changed_signal.emit()
        self.tx_desc.editingFinished.connect(on_edited)
        self.tx_desc.addCopyButton()
        vbox.addWidget(self.tx_desc)
        vbox.addWidget(QLabel(_("Payment hash") + ":"))
        self.hash_e = ShowQRLineEdit(self.payment_hash, self.config, title=_("Payment hash"))
        vbox.addWidget(self.hash_e)
        vbox.addWidget(QLabel(_("Preimage") + ":"))
        self.preimage_e = ShowQRLineEdit(self.preimage, self.config, title=_("Preimage"))
        vbox.addWidget(self.preimage_e)
        if self.invoice:
            vbox.addWidget(QLabel(_("Lightning Invoice") + ":"))
            self.invoice_e = ShowQRTextEdit(self.invoice, config=self.config)
            self.invoice_e.setMaximumHeight(max(150, 10 * font_height()))
            self.invoice_e.addCopyButton()
            vbox.addWidget(self.invoice_e)
        self.close_button = CloseButton(self)
        vbox.addLayout(Buttons(self.close_button))
        self.close_button.setFocus()
