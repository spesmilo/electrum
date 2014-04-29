#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 ecdsa@github
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

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
from electrum_ltc.i18n import _
from electrum_ltc import mnemonic
from qrcodewidget import QRCodeWidget
from util import close_button

class SeedDialog(QDialog):
    def __init__(self, parent, seed, imported_keys):
        QDialog.__init__(self, parent)
        self.setModal(1)
        self.setWindowTitle('Electrum' + ' - ' + _('Seed'))
        vbox = show_seed_box(seed)
        if imported_keys:
            vbox.addWidget(QLabel("<b>"+_("WARNING")+":</b> " + _("Your wallet contains imported keys. These keys cannot be recovered from seed.") + "</b><p>"))
        vbox.addLayout(close_button(self))
        self.setLayout(vbox)


def icon_filename(sid):
    if sid == 'cold':
        return ":icons/cold_seed.png" 
    elif sid == 'hot':
        return ":icons/hot_seed.png" 
    else:
        return ":icons/seed.png" 
    



def show_seed_box(seed, sid=None):

    save_msg = _("Please save these %d words on paper (order is important).")%len(seed.split()) + " " 
    qr_msg = _("Your seed is also displayed as QR code, in case you want to transfer it to a mobile phone.") + "<p>"
    warning_msg = "<b>"+_("WARNING")+":</b> " + _("Never disclose your seed. Never type it on a website.") + "</b><p>"

    if sid is None:
        msg =  _("Your wallet generation seed is")
        msg2 = save_msg + " " \
               + _("This seed will allow you to recover your wallet in case of computer failure.") + "<br/>" \
               + warning_msg
        
    elif sid == 'cold':
        msg =  _("Your cold storage seed is")
        msg2 = save_msg + " " \
               + _("This seed will be permanently deleted from your wallet file. Make sure you have saved it before you press 'next'") + " " \
            
    elif sid == 'hot':
        msg =  _("Your hot seed is")
        msg2 = save_msg + " " \
               + _("If you ever need to recover your wallet from seed, you will need both this seed and your cold seed.") + " " \

    label1 = QLabel(msg+ ":")
    seed_text = QTextEdit(seed)
    seed_text.setReadOnly(True)
    seed_text.setMaximumHeight(130)

    label2 = QLabel(msg2)
    label2.setWordWrap(True)

    logo = QLabel()

    logo.setPixmap(QPixmap(icon_filename(sid)).scaledToWidth(56))
    logo.setMaximumWidth(60)

    grid = QGridLayout()
    grid.addWidget(logo, 0, 0)
    grid.addWidget(label1, 0, 1)
    grid.addWidget(seed_text, 1, 0, 1, 2)
    #qrw = QRCodeWidget(seed)
    #grid.addWidget(qrw, 0, 2, 2, 1)
    vbox = QVBoxLayout()
    vbox.addLayout(grid)
    vbox.addWidget(label2)
    vbox.addStretch(1)
    
    return vbox


def enter_seed_box(msg, sid=None):

    vbox = QVBoxLayout()
    logo = QLabel()
    logo.setPixmap(QPixmap(icon_filename(sid)).scaledToWidth(56))
    logo.setMaximumWidth(60)

    label = QLabel(msg)
    label.setWordWrap(True)

    seed_e = QTextEdit()
    seed_e.setMaximumHeight(100)
    seed_e.setTabChangesFocus(True)

    vbox.addWidget(label)

    grid = QGridLayout()
    grid.addWidget(logo, 0, 0)
    grid.addWidget(seed_e, 0, 1)

    vbox.addLayout(grid)
    return vbox, seed_e
