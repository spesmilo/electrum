#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys, time, datetime, re, threading
from electrum_grs.i18n import _, set_language
from electrum_grs.util import print_error, print_msg
import os.path, json, ast, traceback
import shutil
import StringIO


try:
    import PyQt4
except Exception:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore


from util import *
from history_widget import HistoryWidget

class AddressDialog(QDialog):

    def __init__(self, address, parent):
        self.address = address
        self.parent = parent
        self.config = parent.config
        self.wallet = parent.wallet
        self.app = parent.app
        self.saved = True

        QDialog.__init__(self)
        self.setMinimumWidth(700)
        self.setWindowTitle(_("Address"))
        self.setModal(1)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Address:")))
        self.addr_e = ButtonsLineEdit(self.address)
        self.addr_e.addCopyButton(self.app)
        self.addr_e.addButton(":icons/qrcode.png", self.show_qr, _("Show QR Code"))
        self.addr_e.setReadOnly(True)
        vbox.addWidget(self.addr_e)

        vbox.addWidget(QLabel(_("History")))
        self.hw = HistoryWidget(self.parent)
        vbox.addWidget(self.hw)

        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.format_amount = self.parent.format_amount

        h = self.wallet.get_history([self.address])
        self.hw.update(h)



    def show_qr(self):
        text = self.address
        try:
            self.parent.show_qrcode(text, 'Address')
        except Exception as e:
            self.show_message(str(e))



