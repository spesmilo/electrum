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



class SeedDisplayLayout(SeedLayoutBase):
    def __init__(self, seed, title=None, sid=None):
        self.layout_ = self._seed_layout(seed=seed, title=title, sid=sid)



def seed_warning_msg(seed):
    return ''.join([
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


class CreateSeedLayout(SeedLayoutBase):

    def __init__(self, seed):
        title =  _("Your wallet generation seed is:")
        tooltip = '\n'.join([
            _('You may extend your seed with a passphrase.'),
            _('Note tha this is NOT your encryption password.'),
            _('If you do not know what it is, leave it empty.'),
        ])
        vbox = QVBoxLayout()
        vbox.addLayout(self._seed_layout(seed=seed, title=title))
        self.passphrase_e = QLineEdit()
        self.passphrase_e.setToolTip(tooltip)
        hbox = QHBoxLayout()
        hbox.addStretch()
        label = QLabel(_('Passphrase') + ':')
        label.setToolTip(tooltip)
        hbox.addWidget(label)
        hbox.addWidget(self.passphrase_e)
        vbox.addLayout(hbox)
        msg = seed_warning_msg(seed)
        vbox.addWidget(WWLabel(msg))
        self.layout_ = vbox

    def passphrase(self):
        return unicode(self.passphrase_e.text()).strip()


class TextInputLayout(SeedLayoutBase):

    def __init__(self, parent, title, is_valid):
        self.is_valid = is_valid
        self.parent = parent
        self.layout_ = self._seed_layout(title=title)
        self.seed_e.textChanged.connect(self.on_edit)

    def get_text(self):
        return clean_text(self.seed_edit())

    def on_edit(self):
        self.parent.next_button.setEnabled(self.is_valid(self.get_text()))


class SeedInputLayout(SeedLayoutBase):

    def __init__(self, parent, title, is_seed, is_passphrase):
        vbox = QVBoxLayout()
        vbox.addLayout(self._seed_layout(title=title))
        self.passphrase_e = QLineEdit()
        hbox = QHBoxLayout()
        hbox.addStretch()
        hbox.addWidget(QLabel(_('Passphrase') + ':'))
        hbox.addWidget(self.passphrase_e)
        vbox.addLayout(hbox)
        self.layout_ = vbox
        self.parent = parent
        self.is_seed = is_seed
        self.is_passphrase = is_passphrase
        self.seed_e.textChanged.connect(self.on_edit)
        self.passphrase_e.textChanged.connect(self.on_edit)

    def get_passphrase(self):
        return unicode(self.passphrase_e.text()).strip()

    def get_seed(self):
        return clean_text(self.seed_edit())

    def on_edit(self):
        self.parent.next_button.setEnabled(self.is_seed(self.get_seed()) and self.is_passphrase(self.get_passphrase()))



class ShowSeedLayout(SeedLayoutBase):

    def __init__(self, seed, passphrase):
        title =  _("Your wallet generation seed is:")
        vbox = QVBoxLayout()
        vbox.addLayout(self._seed_layout(seed=seed, title=title))
        if passphrase:
            hbox = QHBoxLayout()
            passphrase_e = QLineEdit()
            passphrase_e.setText(passphrase)
            passphrase_e.setReadOnly(True)
            hbox.addWidget(QLabel('Your seed passphrase is'))
            hbox.addWidget(passphrase_e)
            vbox.addLayout(hbox)
        msg = seed_warning_msg(seed)
        vbox.addWidget(WWLabel(msg))
        self.layout_ = vbox


class SeedDialog(WindowModalDialog):
    def __init__(self, parent, seed, passphrase):
        WindowModalDialog.__init__(self, parent, ('Electrum - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        vbox.addLayout(ShowSeedLayout(seed, passphrase).layout())
        vbox.addLayout(Buttons(CloseButton(self)))
