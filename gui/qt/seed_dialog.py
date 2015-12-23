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
from electrum.i18n import _

from util import *
from qrtextedit import ShowQRTextEdit, ScanQRTextEdit

class SeedDialog(WindowModalDialog):
    def __init__(self, parent, seed, imported_keys):
        WindowModalDialog.__init__(self, parent, ('Electrum - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = show_seed_box_msg(seed)
        if imported_keys:
            vbox.addWidget(QLabel("<b>"+_("WARNING")+":</b> " + _("Your wallet contains imported keys. These keys cannot be recovered from seed.") + "</b><p>"))
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)


def icon_filename(sid):
    if sid == 'cold':
        return ":icons/cold_seed.png"
    elif sid == 'hot':
        return ":icons/hot_seed.png"
    else:
        return ":icons/seed.png"


def show_seed_box_msg(seedphrase, sid=None):
    msg =  _("Your wallet generation seed is") + ":"
    vbox = show_seed_box(msg, seedphrase, sid)
    msg = ''.join([
        "<p>",
        _("Please save these %d words on paper (order is important).")%len(seedphrase.split()) + " ",
        _("This seed will allow you to recover your wallet in case of computer failure.") + "<br/>",
        "</p>",
        "<b>" + _("WARNING") + ":</b> ",
        "<ul>",
        "<li>" + _("Never disclose your seed.") + "</li>",
        "<li>" + _("Never type it on a website.") + "</li>",
        "<li>" + _("Do not send your seed to a printer.") + "</li>",
        "</ul>"
    ])
    label2 = QLabel(msg)
    label2.setWordWrap(True)
    vbox.addWidget(label2)
    vbox.addStretch(1)
    return vbox

def show_seed_box(msg, seed, sid):
    vbox, seed_e = enter_seed_box(msg, None, sid=sid, text=seed)
    return vbox

def enter_seed_box(msg, window, sid=None, text=None):
    vbox = QVBoxLayout()
    logo = QLabel()
    logo.setPixmap(QPixmap(icon_filename(sid)).scaledToWidth(56))
    logo.setMaximumWidth(60)
    label = QLabel(msg)
    label.setWordWrap(True)
    if not text:
        seed_e = ScanQRTextEdit()
        seed_e.setTabChangesFocus(True)
    else:
        seed_e = ShowQRTextEdit(text=text)
    seed_e.setMaximumHeight(130)
    vbox.addWidget(label)
    grid = QGridLayout()
    grid.addWidget(logo, 0, 0)
    grid.addWidget(seed_e, 0, 1)
    vbox.addLayout(grid)
    return vbox, seed_e
