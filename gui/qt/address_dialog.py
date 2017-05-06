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

import PyQt4
from PyQt4.QtGui import *
from PyQt4.QtCore import *

from util import *
from history_list import HistoryList

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
        self.addr_e.addButton(":icons/qrcode.png", self.show_qr, _("Show QR Code"))
        self.addr_e.setReadOnly(True)
        vbox.addWidget(self.addr_e)

        vbox.addWidget(QLabel(_("History")))
        self.hw = HistoryList(self.parent)
        self.hw.get_domain = self.get_domain
        vbox.addWidget(self.hw)

        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.format_amount = self.parent.format_amount
        self.hw.update()

    def get_domain(self):
        return [self.address]

    def show_qr(self):
        text = self.address
        try:
            self.parent.show_qrcode(text, 'Address')
        except Exception as e:
            self.show_message(str(e))
