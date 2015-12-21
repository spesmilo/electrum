#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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

import re
import platform
from decimal import Decimal
from urllib import quote

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui

from electrum_grs_gui.qt.qrcodewidget import QRCodeWidget
from electrum_grs.i18n import _

if platform.system() == 'Windows':
    MONOSPACE_FONT = 'Lucida Console'
elif platform.system() == 'Darwin':
    MONOSPACE_FONT = 'Monaco'
else:
    MONOSPACE_FONT = 'monospace'

column_index = 4

class QR_Window(QWidget):

    def __init__(self, win):
        QWidget.__init__(self)
        self.win = win
        self.setWindowTitle('Electrum-GRS - '+_('Payment Request'))
        self.setMinimumSize(800, 250)
        self.address = ''
        self.label = ''
        self.amount = 0
        self.setFocusPolicy(QtCore.Qt.NoFocus)

        main_box = QHBoxLayout()

        self.qrw = QRCodeWidget()
        main_box.addWidget(self.qrw, 1)

        vbox = QVBoxLayout()
        main_box.addLayout(vbox)

        self.address_label = QLabel("")
        #self.address_label.setFont(QFont(MONOSPACE_FONT))
        vbox.addWidget(self.address_label)

        self.label_label = QLabel("")
        vbox.addWidget(self.label_label)

        self.amount_label = QLabel("")
        vbox.addWidget(self.amount_label)

        vbox.addStretch(1)
        self.setLayout(main_box)


    def set_content(self, address, amount, message, url):
        address_text = "<span style='font-size: 18pt'>%s</span>" % address if address else ""
        self.address_label.setText(address_text)
        if amount:
            amount = self.win.format_amount(amount)
            amount_text = "<span style='font-size: 21pt'>%s</span> <span style='font-size: 16pt'>%s</span> " % (amount, self.win.base_unit())
        else:
            amount_text = ''
        self.amount_label.setText(amount_text)
        label_text = "<span style='font-size: 21pt'>%s</span>" % message if message else ""
        self.label_label.setText(label_text)
        self.qrw.setData(url)
