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

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from electrum_ltc.i18n import _

from .util import *
from .qrtextedit import ShowQRTextEdit, ScanQRTextEdit


def seed_warning_msg(seed):
    return ''.join([
        "<p>",
        _("Please save these {0} words on paper (order is important). "),
        _("This seed will allow you to recover your wallet in case "
          "of computer failure."),
        "</p>",
        "<b>" + _("WARNING") + ":</b>",
        "<ul>",
        "<li>" + _("Never disclose your seed.") + "</li>",
        "<li>" + _("Never type it on a website.") + "</li>",
        "<li>" + _("Do not store it electronically.") + "</li>",
        "</ul>"
    ]).format(len(seed.split()))


class SeedLayout(QVBoxLayout):
    #options
    is_bip39 = False
    is_ext = False

    def seed_options(self):
        dialog = QDialog()
        vbox = QVBoxLayout(dialog)
        if 'ext' in self.options:
            cb_ext = QCheckBox(_('Extend this seed with custom words'))
            cb_ext.setChecked(self.is_ext)
            vbox.addWidget(cb_ext)
        if 'bip39' in self.options:
            def f(b):
                self.is_seed = (lambda x: bool(x)) if b else self.saved_is_seed
                self.is_bip39 = b
                self.on_edit()
                if b:
                    msg = ' '.join([
                        '<b>' + _('Warning') + ':</b>  ',
                        _('BIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                        _('However, we do not generate BIP39 seeds, because they do not meet our safety standard.'),
                        _('BIP39 seeds do not include a version number, which compromises compatibility with future software.'),
                        _('We do not guarantee that BIP39 imports will always be supported in Electrum.'),
                    ])
                else:
                    msg = ''
                self.seed_warning.setText(msg)
            cb_bip39 = QCheckBox(_('BIP39 seed'))
            cb_bip39.toggled.connect(f)
            cb_bip39.setChecked(self.is_bip39)
            vbox.addWidget(cb_bip39)
        vbox.addLayout(Buttons(OkButton(dialog)))
        if not dialog.exec_():
            return None
        self.is_ext = cb_ext.isChecked() if 'ext' in self.options else False
        self.is_bip39 = cb_bip39.isChecked() if 'bip39' in self.options else False

    def __init__(self, seed=None, title=None, icon=True, msg=None, options=None, is_seed=None, passphrase=None, parent=None):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.options = options
        if title:
            self.addWidget(WWLabel(title))
        if seed:
            self.seed_e = ShowQRTextEdit()
            self.seed_e.setText(seed)
        else:
            self.seed_e = ScanQRTextEdit()
            self.seed_e.setTabChangesFocus(True)
            self.is_seed = is_seed
            self.saved_is_seed = self.is_seed
            self.seed_e.textChanged.connect(self.on_edit)
        self.seed_e.setMaximumHeight(75)
        hbox = QHBoxLayout()
        if icon:
            logo = QLabel()
            logo.setPixmap(QPixmap(":icons/seed.png").scaledToWidth(64))
            logo.setMaximumWidth(60)
            hbox.addWidget(logo)
        hbox.addWidget(self.seed_e)
        self.addLayout(hbox)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        self.seed_type_label = QLabel('')
        hbox.addWidget(self.seed_type_label)
        if options:
            opt_button = EnterButton(_('Options'), self.seed_options)
            hbox.addWidget(opt_button)
            self.addLayout(hbox)
        if passphrase:
            hbox = QHBoxLayout()
            passphrase_e = QLineEdit()
            passphrase_e.setText(passphrase)
            passphrase_e.setReadOnly(True)
            hbox.addWidget(QLabel(_("Your seed extension is") + ':'))
            hbox.addWidget(passphrase_e)
            self.addLayout(hbox)
        self.addStretch(1)
        self.seed_warning = WWLabel('')
        if msg:
            self.seed_warning.setText(seed_warning_msg(seed))
        self.addWidget(self.seed_warning)

    def get_seed(self):
        text = self.seed_e.text()
        return ' '.join(text.split())

    def on_edit(self):
        from electrum_ltc.bitcoin import seed_type
        s = self.get_seed()
        b = self.is_seed(s)
        if not self.is_bip39:
            t = seed_type(s)
            label = _('Seed Type') + ': ' + t if t else ''
        else:
            from electrum_ltc.keystore import bip39_is_checksum_valid
            is_checksum, is_wordlist = bip39_is_checksum_valid(s)
            status = ('checksum: ' + ('ok' if is_checksum else 'failed')) if is_wordlist else 'unknown wordlist'
            label = 'BIP39' + ' (%s)'%status
        self.seed_type_label.setText(label)
        self.parent.next_button.setEnabled(b)


class KeysLayout(QVBoxLayout):
    def __init__(self, parent=None, title=None, is_valid=None):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.is_valid = is_valid
        self.text_e = ScanQRTextEdit()
        self.text_e.textChanged.connect(self.on_edit)
        self.addWidget(WWLabel(title))
        self.addWidget(self.text_e)

    def get_text(self):
        return self.text_e.text()

    def on_edit(self):
        b = self.is_valid(self.get_text())
        self.parent.next_button.setEnabled(b)


class SeedDialog(WindowModalDialog):

    def __init__(self, parent, seed, passphrase):
        WindowModalDialog.__init__(self, parent, ('Electrum-LTC - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        title =  _("Your wallet generation seed is:")
        slayout = SeedLayout(title=title, seed=seed, msg=True, passphrase=passphrase)
        vbox.addLayout(slayout)
        vbox.addLayout(Buttons(CloseButton(self)))
