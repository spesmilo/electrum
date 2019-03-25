#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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

from electrum.i18n import _

from PyQt5.QtWidgets import QVBoxLayout, QLabel

from .util import WindowModalDialog, ButtonsLineEdit, ColorScheme, Buttons, CloseButton
from .history_list import HistoryList, HistoryModel
from .qrtextedit import ShowQRTextEdit

class AddressHistoryModel(HistoryModel):
    def __init__(self, parent, address):
        super().__init__(parent)
        self.address = address

    def get_domain(self):
        return [self.address]

class AddressDialog(WindowModalDialog):

    def __init__(self, parent, address):
        WindowModalDialog.__init__(self, parent, _("Address"))
        self.address = address
        self.parent = parent
        self.config = parent.config
        self.wallet = parent.wallet
        self.app = parent.app
        self.saved = True

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Address:")))
        self.addr_e = ButtonsLineEdit(self.address)
        self.addr_e.addCopyButton(self.app)
        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.addr_e.addButton(icon, self.show_qr, _("Show QR Code"))
        self.addr_e.setReadOnly(True)
        vbox.addWidget(self.addr_e)

        try:
            pubkeys = self.wallet.get_public_keys(address)
        except BaseException as e:
            pubkeys = None
        if pubkeys:
            vbox.addWidget(QLabel(_("Public keys") + ':'))
            for pubkey in pubkeys:
                pubkey_e = ButtonsLineEdit(pubkey)
                pubkey_e.addCopyButton(self.app)
                pubkey_e.setReadOnly(True)
                vbox.addWidget(pubkey_e)

        try:
            redeem_script = self.wallet.pubkeys_to_redeem_script(pubkeys)
        except BaseException as e:
            redeem_script = None
        if redeem_script:
            vbox.addWidget(QLabel(_("Redeem Script") + ':'))
            redeem_e = ShowQRTextEdit(text=redeem_script)
            redeem_e.addCopyButton(self.app)
            vbox.addWidget(redeem_e)

        vbox.addWidget(QLabel(_("History")))
        addr_hist_model = AddressHistoryModel(self.parent, self.address)
        self.hw = HistoryList(self.parent, addr_hist_model)
        addr_hist_model.set_view(self.hw)
        vbox.addWidget(self.hw)

        vbox.addLayout(Buttons(CloseButton(self)))
        self.format_amount = self.parent.format_amount
        addr_hist_model.refresh('address dialog constructor')

    def show_qr(self):
        text = self.address
        try:
            self.parent.show_qrcode(text, 'Address', parent=self)
        except Exception as e:
            self.show_message(str(e))
