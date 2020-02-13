#!/usr/bin/env python3
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
from electroncash.i18n import _
from electroncash import mnemonic

from .util import *
from .qrtextedit import ShowQRTextEdit, ScanQRTextEdit


def seed_warning_msg(seed, has_der=False, has_ext=False):
    extra = ''
    if has_der:
        if has_ext:
            extra = (' ' + _('Additionally, save the seed extension and derivation path as well.') + ' ')
        else:
            extra = (' ' + _('Additionally, save the derivation path as well.') + ' ')
    elif has_ext:
        extra = (' ' + _('Additionally, save the seed extension as well.') + ' ')
    return ''.join([
        "<p>",
        _("Please save these %d words on paper (order is important). "),
        extra,
        _("This seed will allow you to recover your wallet in case "
          "of computer failure."),
        "</p>",
        "<b>" + _("WARNING") + ":</b>",
        "<ul>",
        "<li>" + _("Never disclose your seed.") + "</li>",
        "<li>" + _("Never type it on a website.") + "</li>",
        "<li>" + _("Do not store it electronically.") + "</li>",
        "</ul>"
    ]) % len(seed.split())


class SeedLayout(QVBoxLayout):
    #options
    is_bip39 = False
    is_ext = False

    def seed_options(self):
        dialog = QDialog()
        vbox = QVBoxLayout(dialog)
        if 'ext' in self.options:
            cb_ext = QCheckBox(_('Extend this seed with custom words') + " " + _("(aka 'passphrase')"))
            cb_ext.setChecked(self.is_ext)
            vbox.addWidget(cb_ext)
        if 'bip39' in self.options:
            def f(b):
                self.is_seed = (lambda x: bool(x)) if b else self.saved_is_seed
                self.is_bip39 = b
                self.on_edit()
            cb_bip39 = QCheckBox(_('Force BIP39 interpretation of this seed'))
            cb_bip39.toggled.connect(f)
            cb_bip39.setChecked(self.is_bip39)
            vbox.addWidget(cb_bip39)
        vbox.addLayout(Buttons(OkButton(dialog)))
        if not dialog.exec_():
            return None
        self.is_ext = cb_ext.isChecked() if 'ext' in self.options else False
        self.is_bip39 = cb_bip39.isChecked() if 'bip39' in self.options else False

    def __init__(self, seed=None, title=None, icon=True, msg=None, options=None, is_seed=None, passphrase=None, parent=None, editable=True,
                 derivation=None, seed_type=None):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.options = options or ()
        if title:
            self.addWidget(WWLabel(title))
        self.seed_e = ButtonsTextEdit()
        self.editable = bool(editable)
        self.seed_e.setReadOnly(not self.editable)
        if seed:
            self.seed_e.setText(seed)
        else:
            self.seed_e.setTabChangesFocus(True)
            self.is_seed = is_seed
            self.saved_is_seed = self.is_seed
            self.seed_e.textChanged.connect(self.on_edit)
        self.seed_e.setMaximumHeight(75)
        hbox = QHBoxLayout()
        if icon:
            logo = QLabel()
            logo.setPixmap(QIcon(":icons/seed.png").pixmap(64))
            logo.setMaximumWidth(60)
            hbox.addWidget(logo)
        hbox.addWidget(self.seed_e)
        self.addLayout(hbox)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        self.seed_type_label = QLabel('')
        hbox.addWidget(self.seed_type_label)
        if self.options:
            opt_button = EnterButton(_('Options'), self.seed_options)
            hbox.addWidget(opt_button)
            self.addLayout(hbox)
        grid_maybe = QGridLayout()  # may not be used if none of the below if expressions evaluates to true, that's ok.
        grid_maybe.setColumnStretch(1, 1)  # we want the right-hand column to take up as much space as it needs.
        grid_row = 0
        if seed_type:
            seed_type_text = mnemonic.format_seed_type_name_for_ui(seed_type)
            grid_maybe.addWidget(QLabel(_("Seed format") + ':'), grid_row, 0)
            grid_maybe.addWidget(QLabel(f'<b>{seed_type_text}</b>'), grid_row, 1, Qt.AlignLeft)
            grid_row += 1
        if passphrase:
            passphrase_e = QLineEdit()
            passphrase_e.setText(passphrase)
            passphrase_e.setReadOnly(True)
            grid_maybe.addWidget(QLabel(_("Your seed extension is") + ':'), grid_row, 0)
            grid_maybe.addWidget(passphrase_e, grid_row, 1)
            grid_row += 1
        if derivation:
            der_e = QLineEdit()
            der_e.setText(str(derivation))
            der_e.setReadOnly(True)
            grid_maybe.addWidget(QLabel(_("Wallet derivation path") + ':'), grid_row, 0)
            grid_maybe.addWidget(der_e, grid_row, 1)
            grid_row += 1
        if grid_row > 0:  # only if above actually added widgets
            self.addLayout(grid_maybe)
        self.addStretch(1)
        self.seed_warning = WWLabel('')
        self.has_warning_message = bool(msg)
        if self.has_warning_message:
            self.seed_warning.setText(seed_warning_msg(seed, bool(derivation), bool(passphrase)))
        self.addWidget(self.seed_warning)

    def get_seed(self):
        text = self.seed_e.text()
        return ' '.join(text.split())

    _mnem = None
    def on_edit(self):
        may_clear_warning = not self.has_warning_message and self.editable
        if not self._mnem:
            # cache the lang wordlist so it doesn't need to get loaded each time.
            # This speeds up seed_type_name and Mnemonic.is_checksum_valid
            self._mnem = mnemonic.Mnemonic('en')
        s = self.get_seed()
        b = self.is_seed(s)
        if not self.is_bip39:
            t = mnemonic.format_seed_type_name_for_ui(mnemonic.seed_type_name(s))
            label = _('Seed Type') + ': ' + t if t else ''
            if t and may_clear_warning and 'bip39' in self.options:
                match_set = mnemonic.autodetect_seed_type(s)
                if len(match_set) > 1 and mnemonic.SeedType.BIP39 in match_set:
                    may_clear_warning = False
                    self.seed_warning.setText(
                        _('This seed is ambiguous and may also be interpreted as a <b>BIP39</b> seed.')
                        + '<br/><br/>'
                        + _('If you wish this seed to be interpreted as a BIP39 seed, '
                            'then use the Options button to force BIP39 interpretation of this seed.')
                    )
        else:
            is_checksum, is_wordlist = self._mnem.is_checksum_valid(s)
            status = ('checksum: ' + ('ok' if is_checksum else 'failed')) if is_wordlist else 'unknown wordlist'
            label = 'BIP39' + ' (%s)'%status
        self.seed_type_label.setText(label)
        self.parent.next_button.setEnabled(b)
        if may_clear_warning:
            self.seed_warning.setText('')


class KeysLayout(QVBoxLayout):
    def __init__(self, parent=None, title=None, is_valid=None, allow_multi=False):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.is_valid = is_valid
        self.text_e = ScanQRTextEdit(allow_multi=allow_multi)
        self.text_e.textChanged.connect(self.on_edit)
        self.addWidget(WWLabel(title))
        self.addWidget(self.text_e)

    def get_text(self):
        return self.text_e.text()

    def on_edit(self):
        b = self.is_valid(self.get_text())
        self.parent.next_button.setEnabled(b)


class SeedDialog(WindowModalDialog):

    def __init__(self, parent, seed, passphrase, derivation=None, seed_type=None):
        WindowModalDialog.__init__(self, parent, ('Electron Cash - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        title =  _("Your wallet generation seed is:")
        slayout = SeedLayout(title=title, seed=seed, msg=True, passphrase=passphrase, editable=False, derivation=derivation, seed_type=seed_type)
        vbox.addLayout(slayout)
        vbox.addLayout(Buttons(CloseButton(self)))
