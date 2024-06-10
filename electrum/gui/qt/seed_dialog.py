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

from typing import TYPE_CHECKING

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (QVBoxLayout, QCheckBox, QHBoxLayout, QLineEdit,
                             QLabel, QCompleter, QDialog, QStyledItemDelegate,
                             QScrollArea, QWidget, QPushButton)

from electrum.i18n import _
from electrum.mnemonic import Mnemonic, calc_seed_type, is_any_2fa_seed_type
from electrum import old_mnemonic
from electrum import slip39

from .util import (Buttons, OkButton, WWLabel, ButtonsTextEdit, icon_path,
                   EnterButton, CloseButton, WindowModalDialog, ColorScheme,
                   ChoicesLayout, font_height)
from .qrtextedit import ShowQRTextEdit, ScanQRTextEdit
from .completion_text_edit import CompletionTextEdit

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig


MSG_PASSPHRASE_WARN_ISSUE4566 = _("Warning") + ": "\
                              + _("You have multiple consecutive whitespaces or leading/trailing "
                                  "whitespaces in your passphrase.") + " " \
                              + _("This is discouraged.") + " " \
                              + _("Due to a bug, old versions of Electrum will NOT be creating the "
                                  "same wallet as newer versions or other software.")


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

    updated = pyqtSignal()

    def seed_options(self):
        dialog = QDialog()
        dialog.setWindowTitle(_("Seed Options"))
        vbox = QVBoxLayout(dialog)

        seed_types = [
            (value, title) for value, title in (
                ('electrum', _('Electrum')),
                ('bip39', _('BIP39 seed')),
                ('slip39', _('SLIP39 seed')),
            )
            if value in self.options or value == 'electrum'
        ]
        seed_type_values = [t[0] for t in seed_types]

        if 'ext' in self.options:
            cb_ext = QCheckBox(_('Extend this seed with custom words'))
            cb_ext.setChecked(self.is_ext)
            vbox.addWidget(cb_ext)
        if len(seed_types) >= 2:
            def f(choices_layout):
                self.seed_type = seed_type_values[choices_layout.selected_index()]
                self.is_seed = (lambda x: bool(x)) if self.seed_type != 'electrum' else self.saved_is_seed
                self.slip39_current_mnemonic_invalid = None
                self.seed_status.setText('')
                self.on_edit()
                if self.seed_type == 'bip39':
                    msg = ' '.join([
                        '<b>' + _('Warning') + ':</b>  ',
                        _('BIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                        _('However, we do not generate BIP39 seeds, because they do not meet our safety standard.'),
                        _('BIP39 seeds do not include a version number, which compromises compatibility with future software.'),
                        _('We do not guarantee that BIP39 imports will always be supported in Electrum.'),
                    ])
                elif self.seed_type == 'slip39':
                    msg = ' '.join([
                        '<b>' + _('Warning') + ':</b>  ',
                        _('SLIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                        _('However, we do not generate SLIP39 seeds.'),
                    ])
                else:
                    msg = ''
                self.update_share_buttons()
                self.initialize_completer()
                self.seed_warning.setText(msg)

            checked_index = seed_type_values.index(self.seed_type)
            titles = [t[1] for t in seed_types]
            clayout = ChoicesLayout(_('Seed type'), titles, on_clicked=f, checked_index=checked_index)
            vbox.addLayout(clayout.layout())

        vbox.addLayout(Buttons(OkButton(dialog)))
        if not dialog.exec_():
            return None
        self.is_ext = cb_ext.isChecked() if 'ext' in self.options else False
        self.seed_type = seed_type_values[clayout.selected_index()] if len(seed_types) >= 2 else 'electrum'
        self.updated.emit()

    def __init__(
            self,
            seed=None,
            title=None,
            icon=True,
            msg=None,
            options=None,
            is_seed=None,
            passphrase=None,
            parent=None,
            for_seed_words=True,
            *,
            config: 'SimpleConfig',
    ):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.options = options
        self.config = config
        self.seed_type = 'electrum'
        if title:
            self.addWidget(WWLabel(title))
        if seed:  # "read only", we already have the text
            if for_seed_words:
                self.seed_e = ButtonsTextEdit()
            else:  # e.g. xpub
                self.seed_e = ShowQRTextEdit(config=self.config)
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

        self.seed_e.setMaximumHeight(max(75, 5 * font_height()))
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

        # slip39 shares
        self.slip39_mnemonic_index = 0
        self.slip39_mnemonics = [""]
        self.slip39_seed = None
        self.slip39_current_mnemonic_invalid = None
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        self.prev_share_btn = QPushButton(_("Previous share"))
        self.prev_share_btn.clicked.connect(self.on_prev_share)
        hbox.addWidget(self.prev_share_btn)
        self.next_share_btn = QPushButton(_("Next share"))
        self.next_share_btn.clicked.connect(self.on_next_share)
        hbox.addWidget(self.next_share_btn)
        self.update_share_buttons()
        self.addLayout(hbox)

        self.addStretch(1)
        self.seed_status = WWLabel('')
        self.addWidget(self.seed_status)
        self.seed_warning = WWLabel('')
        if msg:
            self.seed_warning.setText(seed_warning_msg(seed))
        self.addWidget(self.seed_warning)

    def initialize_completer(self):
        if self.seed_type != 'slip39':
            bip39_english_list = Mnemonic('en').wordlist
            old_list = old_mnemonic.wordlist
            only_old_list = set(old_list) - set(bip39_english_list)
            self.wordlist = list(bip39_english_list) + list(only_old_list)  # concat both lists
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

            delegate = CompleterDelegate(self.seed_e)
        else:
            self.wordlist = list(slip39.get_wordlist())
            delegate = None

        self.completer = QCompleter(self.wordlist)
        if delegate:
            self.completer.popup().setItemDelegate(delegate)
        self.seed_e.set_completer(self.completer)

    def get_seed_words(self):
        return self.seed_e.text().split()

    def get_seed(self):
        if self.seed_type != 'slip39':
            return ' '.join(self.get_seed_words())
        else:
            return self.slip39_seed

    def on_edit(self):
        s = ' '.join(self.get_seed_words())
        b = self.is_seed(s)
        if self.seed_type == 'bip39':
            from electrum.keystore import bip39_is_checksum_valid
            is_checksum, is_wordlist = bip39_is_checksum_valid(s)
            label = ''
            if bool(s):
                label = ('' if is_checksum else _('BIP39 checksum failed')) if is_wordlist else _('Unknown BIP39 wordlist')
        elif self.seed_type == 'slip39':
            self.slip39_mnemonics[self.slip39_mnemonic_index] = s
            try:
                slip39.decode_mnemonic(s)
            except slip39.Slip39Error as e:
                share_status = str(e)
                current_mnemonic_invalid = True
            else:
                share_status = _('Valid.')
                current_mnemonic_invalid = False

            label = _('SLIP39 share') + ' #%d: %s' % (self.slip39_mnemonic_index + 1, share_status)

            # No need to process mnemonics if the current mnemonic remains invalid after editing.
            if not (self.slip39_current_mnemonic_invalid and current_mnemonic_invalid):
                self.slip39_seed, seed_status = slip39.process_mnemonics(self.slip39_mnemonics)
                self.seed_status.setText(seed_status)
            self.slip39_current_mnemonic_invalid = current_mnemonic_invalid

            b = self.slip39_seed is not None
            self.update_share_buttons()
        else:
            t = calc_seed_type(s)
            label = _('Seed Type') + ': ' + t if t else ''
            if t and not b:  # electrum seed, but does not conform to dialog rules
                # FIXME we should just accept any electrum seed and "redirect" the wizard automatically.
                #       i.e. if user selected wallet_type=="standard" but entered a 2fa seed, accept and redirect
                #            if user selected wallet_type=="2fa" but entered a std electrum seed, accept and redirect
                wiztype_fullname = _('Wallet with two-factor authentication') if is_any_2fa_seed_type(t) else _("Standard wallet")
                msg = ' '.join([
                    '<b>' + _('Warning') + ':</b>  ',
                    _("Looks like you have entered a valid seed of type '{}' but this dialog does not support such seeds.").format(t),
                    _("If unsure, try restoring as '{}'.").format(wiztype_fullname),
                ])
                self.seed_warning.setText(msg)
            else:
                self.seed_warning.setText("")

        self.seed_type_label.setText(label)
        self.parent.next_button.setEnabled(b)

        # disable suggestions if user already typed an unknown word
        for word in self.get_seed_words()[:-1]:
            if word not in self.wordlist:
                self.seed_e.disable_suggestions()
                return
        self.seed_e.enable_suggestions()

    def update_share_buttons(self):
        if self.seed_type != 'slip39':
            self.prev_share_btn.hide()
            self.next_share_btn.hide()
            return

        finished = self.slip39_seed is not None
        self.prev_share_btn.show()
        self.next_share_btn.show()
        self.prev_share_btn.setEnabled(self.slip39_mnemonic_index != 0)
        self.next_share_btn.setEnabled(
            # already pressed "prev" and undoing that:
            self.slip39_mnemonic_index < len(self.slip39_mnemonics) - 1
            # finished entering latest share and starting new one:
            or (bool(self.seed_e.text().strip()) and not self.slip39_current_mnemonic_invalid and not finished)
        )

    def on_prev_share(self):
        if not self.slip39_mnemonics[self.slip39_mnemonic_index]:
            del self.slip39_mnemonics[self.slip39_mnemonic_index]

        self.slip39_mnemonic_index -= 1
        self.seed_e.setText(self.slip39_mnemonics[self.slip39_mnemonic_index])
        self.slip39_current_mnemonic_invalid = None

    def on_next_share(self):
        if not self.slip39_mnemonics[self.slip39_mnemonic_index]:
            del self.slip39_mnemonics[self.slip39_mnemonic_index]
        else:
            self.slip39_mnemonic_index += 1

        if len(self.slip39_mnemonics) <= self.slip39_mnemonic_index:
            self.slip39_mnemonics.append("")
            self.seed_e.setFocus()
        self.seed_e.setText(self.slip39_mnemonics[self.slip39_mnemonic_index])
        self.slip39_current_mnemonic_invalid = None


class KeysLayout(QVBoxLayout):
    def __init__(
            self,
            parent=None,
            header_layout=None,
            is_valid=None,
            allow_multi=False,
            *,
            config: 'SimpleConfig',
    ):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.is_valid = is_valid
        self.text_e = ScanQRTextEdit(allow_multi=allow_multi, config=config)
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

    def __init__(self, parent, seed, passphrase, *, config: 'SimpleConfig'):
        WindowModalDialog.__init__(self, parent, ('Electrum - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        title =  _("Your wallet generation seed is:")
        slayout = SeedLayout(
            title=title,
            seed=seed,
            msg=True,
            passphrase=passphrase,
            config=config,
        )
        vbox.addLayout(slayout)
        vbox.addLayout(Buttons(CloseButton(self)))
