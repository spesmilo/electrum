#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 ecdsa@github
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

from PyQt4.QtGui import *
from PyQt4.QtCore import *
from electrum.i18n import _

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
