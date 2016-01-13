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
from electrum_ltc.i18n import _

from util import *
from qrtextedit import ShowQRTextEdit, ScanQRTextEdit

def icon_filename(sid):
    if sid == 'cold':
        return ":icons/cold_seed.png"
    elif sid == 'hot':
        return ":icons/hot_seed.png"
    else:
        return ":icons/seed.png"

class SeedDialog(WindowModalDialog):
    def __init__(self, parent, seed, imported_keys):
        WindowModalDialog.__init__(self, parent, ('Electrum - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        vbox.addLayout(SeedWarningLayout(seed).layout())
        if imported_keys:
            warning = ("<b>" + _("WARNING") + ":</b> " +
                       _("Your wallet contains imported keys. These keys "
                         "cannot be recovered from your seed.") + "</b><p>")
            vbox.addWidget(WWLabel(warning))
        vbox.addLayout(Buttons(CloseButton(self)))


class SeedLayoutBase(object):
    def _seed_layout(self, seed=None, title=None, sid=None):
        logo = QLabel()
        logo.setPixmap(QPixmap(icon_filename(sid)).scaledToWidth(56))
        logo.setMaximumWidth(60)
        if seed:
            self.seed_e = ShowQRTextEdit()
            self.seed_e.setText(seed)
        else:
            self.seed_e = ScanQRTextEdit()
            self.seed_e.setTabChangesFocus(True)
        self.seed_e.setMaximumHeight(75)
        hbox = QHBoxLayout()
        hbox.addWidget(logo)
        hbox.addWidget(self.seed_e)
        if not title:
            return hbox
        vbox = QVBoxLayout()
        vbox.addWidget(WWLabel(title))
        vbox.addLayout(hbox)
        return vbox

    def layout(self):
        return self.layout_

    def seed_edit(self):
        return self.seed_e


class SeedInputLayout(SeedLayoutBase):
    def __init__(self, title=None, sid=None):
        self.layout_ = self._seed_layout(title=title, sid=sid)


class SeedDisplayLayout(SeedLayoutBase):
    def __init__(self, seed, title=None, sid=None):
        self.layout_ = self._seed_layout(seed=seed, title=title, sid=sid)


class SeedWarningLayout(SeedLayoutBase):
    def __init__(self, seed, title=None):
        if title is None:
            title =  _("Your wallet generation seed is:")
        msg = ''.join([
            "<p>",
            _("Please save these %d words on paper (order is important). "),
            _("This seed will allow you to recover your wallet in case "
              "of computer failure."),
            "</p>",
            "<b>" + _("WARNING") + ":</b> ",
            "<ul>",
            "<li>" + _("Never disclose your seed.") + "</li>",
            "<li>" + _("Never type it on a website.") + "</li>",
            "<li>" + _("Do not send your seed to a printer.") + "</li>",
            "</ul>"
        ]) % len(seed.split())
        vbox = QVBoxLayout()
        vbox.addLayout(self._seed_layout(seed=seed, title=title))
        vbox.addWidget(WWLabel(msg))
        self.layout_ = vbox
