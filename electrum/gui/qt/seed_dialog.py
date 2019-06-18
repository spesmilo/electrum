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

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QPalette
from PyQt5.QtWidgets import (QVBoxLayout, QCheckBox, QHBoxLayout, QLineEdit,
                             QLabel, QCompleter, QDialog, QStyledItemDelegate)

from electrum.i18n import _
from electrum.mnemonic import Mnemonic, seed_type
import electrum.old_mnemonic

from .util import (Buttons, OkButton, WWLabel, ButtonsTextEdit, icon_path,
                   EnterButton, CloseButton, WindowModalDialog, ColorScheme)
from .qrtextedit import ShowQRTextEdit, ScanQRTextEdit
from .completion_text_edit import CompletionTextEdit


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

    def __init__(self, seed=None, title=None, icon=True, msg=None, options=None,
                 is_seed=None, passphrase=None, parent=None, for_seed_words=True):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.options = options
        if title:
            self.addWidget(WWLabel(title))
        if seed:  # "read only", we already have the text
            if for_seed_words:
                self.seed_e = ButtonsTextEdit()
            else:  # e.g. xpub
                self.seed_e = ShowQRTextEdit()
            self.seed_e.setReadOnly(True)
            self.seed_e.setText(seed)
        else:  # we expect user to enter text
            assert for_seed_words
            self.seed_e = CompletionTextEdit()
            self.seed_e.setTabChangesFocus(False)  # so that tab auto-completes
            self.is_seed = is_seed
            self.saved_is_seed = self.is_seed
            self.seed_e.textChanged.connect(self.on_edit)
            self.initialize_completer()

        self.seed_e.setMaximumHeight(75)
        hbox = QHBoxLayout()
        if icon:
            logo = QLabel()
            logo.setPixmap(QPixmap(icon_path("seed.png"))
                           .scaledToWidth(64, mode=Qt.SmoothTransformation))
            logo.setMaximumWidth(60)
            hbox.addWidget(logo)
        hbox.addWidget(self.seed_e)
        self.addLayout(hbox)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        self.seed_type_label = QLabel('')
        hbox.addWidget(self.seed_type_label)

        # options
        self.is_bip39 = False
        self.is_ext = False
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

    def initialize_completer(self):
        bip39_english_list = Mnemonic('en').wordlist
        old_list = electrum.old_mnemonic.words
        only_old_list = set(old_list) - set(bip39_english_list)
        self.wordlist = bip39_english_list + list(only_old_list)  # concat both lists
        self.wordlist.sort()

        class CompleterDelegate(QStyledItemDelegate):
            def initStyleOption(self, option, index):
                super().initStyleOption(option, index)
                # Some people complained that due to merging the two word lists,
                # it is difficult to restore from a metal backup, as they planned
                # to rely on the "4 letter prefixes are unique in bip39 word list" property.
                # So we color words that are only in old list.
                if option.text in only_old_list:
                    # yellow bg looks ~ok on both light/dark theme, regardless if (un)selected
                    option.backgroundBrush = ColorScheme.YELLOW.as_color(background=True)

        self.completer = QCompleter(self.wordlist)
        delegate = CompleterDelegate(self.seed_e)
        self.completer.popup().setItemDelegate(delegate)
        self.seed_e.set_completer(self.completer)

    def get_seed(self):
        text = self.seed_e.text()
        return ' '.join(text.split())

    def on_edit(self):
        s = self.get_seed()
        b = self.is_seed(s)
        if not self.is_bip39:
            t = seed_type(s)
            label = _('Seed Type') + ': ' + t if t else ''
        else:
            from electrum.keystore import bip39_is_checksum_valid
            is_checksum, is_wordlist = bip39_is_checksum_valid(s)
            status = ('checksum: ' + ('ok' if is_checksum else 'failed')) if is_wordlist else 'unknown wordlist'
            label = 'BIP39' + ' (%s)'%status
        self.seed_type_label.setText(label)
        self.parent.next_button.setEnabled(b)

        # disable suggestions if user already typed an unknown word
        for word in self.get_seed().split(" ")[:-1]:
            if word not in self.wordlist:
                self.seed_e.disable_suggestions()
                return
        self.seed_e.enable_suggestions()

class KeysLayout(QVBoxLayout):
    def __init__(self, parent=None, header_layout=None, is_valid=None, allow_multi=False):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.is_valid = is_valid
        self.text_e = ScanQRTextEdit(allow_multi=allow_multi)
        self.text_e.textChanged.connect(self.on_edit)
        if isinstance(header_layout, str):
            self.addWidget(WWLabel(header_layout))
        else:
            self.addLayout(header_layout)
        self.addWidget(self.text_e)

    def get_text(self):
        return self.text_e.text()

    def on_edit(self):
        valid = False
        try:
            valid = self.is_valid(self.get_text())
        except Exception as e:
            self.parent.next_button.setToolTip(f'{_("Error")}: {str(e)}')
        else:
            self.parent.next_button.setToolTip('')
        self.parent.next_button.setEnabled(valid)


class SeedDialog(WindowModalDialog):

    def __init__(self, parent, seed, passphrase):
        WindowModalDialog.__init__(self, parent, ('Electrum - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        title =  _("Your wallet generation seed is:")
        slayout = SeedLayout(title=title, seed=seed, msg=True, passphrase=passphrase)
        vbox.addLayout(slayout)
        vbox.addLayout(Buttons(CloseButton(self)))
