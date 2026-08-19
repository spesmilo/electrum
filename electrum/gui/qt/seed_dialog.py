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

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (QVBoxLayout, QCheckBox, QHBoxLayout, QLineEdit,
                             QLabel, QCompleter, QDialog, QStyledItemDelegate,
                             QWidget, QPushButton)

from electrum.i18n import _
from electrum.mnemonic import Mnemonic, calc_seed_type, is_any_2fa_seed_type, can_seed_have_passphrase
from electrum import old_mnemonic
from electrum import slip39
from electrum.util import ChoiceItem

from .util import (
    Buttons, OkButton, WWLabel, ButtonsTextEdit, icon_path, EnterButton,
    CloseButton, WindowModalDialog, ColorScheme, font_height, ChoiceWidget,
)
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


class SeedWidget(QWidget):

    updated = pyqtSignal()
    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(
            self,
            seed=None,
            title=None,
            icon=True,
            msg=None,
            options=None,
            is_seed=None,  # only used for electrum seeds
            passphrase=None,
            parent=None,
            for_seed_words=True,
            *,
            config: 'SimpleConfig',
    ):
        QWidget.__init__(self, parent)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        self.options = options
        self.config = config
        self.msg = msg

        if options:
            self.seed_types = [
                ChoiceItem(key=stype, label=label) for stype, label in (
                    ('electrum', 'Electrum'),
                    ('bip39', _('BIP39 seed')),
                    ('slip39', _('SLIP39 seed')),
                )
                if stype in self.options
            ]
            assert len(self.seed_types)
            self.seed_type = self.seed_types[0].key
        else:
            self.seed_type = 'electrum'

        self.is_seed = is_seed

        if title:
            vbox.addWidget(WWLabel(title))
        if seed:  # "read only", we already have the text
            if for_seed_words:
                self.seed_e = ButtonsTextEdit()
            else:  # e.g. xpub
                self.seed_e = ShowQRTextEdit(config=self.config)
                self.seed_e.addCopyButton()
            self.seed_e.setReadOnly(True)
            self.seed_e.setText(seed)
        else:  # we expect user to enter text
            assert for_seed_words
            self.seed_e = CompletionTextEdit()
            self.seed_e.setTabChangesFocus(False)  # so that tab auto-completes
            self.seed_e.textChanged.connect(self.on_edit)
            self.initialize_completer()

        self.seed_e.setMaximumHeight(max(75, 5 * font_height()))
        hbox = QHBoxLayout()
        if icon:
            logo = QLabel()
            logo.setPixmap(QPixmap(icon_path("seed.png"))
                           .scaledToWidth(64, mode=Qt.TransformationMode.SmoothTransformation))
            logo.setMaximumWidth(60)
            hbox.addWidget(logo)
        hbox.addWidget(self.seed_e)
        vbox.addLayout(hbox)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        self.seed_type_label = QLabel('')
        hbox.addWidget(self.seed_type_label)

        # options
        self.is_ext = False
        self.cb_ext = None
        self.ext_reason_label = None
        self.ext_box = None
        self.ext_edit = None
        self.ext_help = None
        self.ext_issue4566 = None
        if options:
            # Options is only for BIP39/SLIP39; extra-word lives on this page
            if 'bip39' in options or 'slip39' in options:
                opt_button = EnterButton(_('Options'), self.seed_options)
                hbox.addWidget(opt_button)
            vbox.addLayout(hbox)
            if 'ext' in options:
                self.cb_ext = QCheckBox(_('Extend this seed with custom words'))
                self.cb_ext.setEnabled(False)
                self.cb_ext.toggled.connect(self._on_ext_toggled)
                vbox.addWidget(self.cb_ext)
                self.ext_reason_label = WWLabel('')
                vbox.addWidget(self.ext_reason_label)
                self.ext_box = QWidget()
                ext_vbox = QVBoxLayout(self.ext_box)
                ext_vbox.setContentsMargins(0, 0, 0, 0)
                self.ext_help = WWLabel('')
                self.ext_edit = QLineEdit()
                self.ext_edit.textChanged.connect(self._on_ext_text)
                ext_warn = WWLabel('\n'.join([
                    _('Note that this is NOT your encryption password.'),
                    _('If you do not know what this is, leave this field empty.'),
                ]))
                self.ext_issue4566 = WWLabel(MSG_PASSPHRASE_WARN_ISSUE4566)
                self.ext_issue4566.setVisible(False)
                ext_vbox.addWidget(self.ext_help)
                ext_vbox.addWidget(self.ext_edit)
                ext_vbox.addWidget(ext_warn)
                ext_vbox.addWidget(self.ext_issue4566)
                self.ext_box.setVisible(False)
                vbox.addWidget(self.ext_box)
                self._update_ext_controls()
        if passphrase:
            hbox = QHBoxLayout()
            passphrase_e = QLineEdit()
            passphrase_e.setText(passphrase)
            passphrase_e.setReadOnly(True)
            hbox.addWidget(QLabel(_("Your seed extension is") + ':'))
            hbox.addWidget(passphrase_e)
            vbox.addLayout(hbox)

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
        vbox.addLayout(hbox)

        vbox.addStretch(1)
        self.seed_status = WWLabel('')
        vbox.addWidget(self.seed_status)
        self.seed_warning = WWLabel('')
        if msg:
            self.seed_warning.setText(seed_warning_msg(seed))
        else:
            self.update_seed_warning()

        vbox.addWidget(self.seed_warning)

    def seed_options(self):
        dialog = QDialog()
        dialog.setWindowTitle(_("Seed Options"))
        vbox = QVBoxLayout(dialog)

        def _sync_variant_enabled():
            if self._electrum_version_detected():
                seed_type_choice.set_item_enabled('bip39', False)
                seed_type_choice.set_item_enabled('slip39', False)
            else:
                seed_type_choice.set_item_enabled('bip39', True)
                seed_type_choice.set_item_enabled('slip39', True)

        def on_selected(idx):
            self.seed_type = seed_type_choice.selected_key
            self.slip39_current_mnemonic_invalid = None
            self.seed_status.setText('')
            self.update_seed_warning()
            self.on_edit()
            self.update_share_buttons()
            self.initialize_completer()
            _sync_variant_enabled()

        if len(self.seed_types) > 1:
            seed_type_choice = ChoiceWidget(message=_('Seed type'), choices=self.seed_types, default_key=self.seed_type)
            seed_type_choice.itemSelected.connect(on_selected)
            vbox.addWidget(seed_type_choice)
            _sync_variant_enabled()

        vbox.addLayout(Buttons(OkButton(dialog)))

        if not dialog.exec():
            return None

        if len(self.seed_types) > 1:
            self.seed_type = seed_type_choice.selected_key

        self.update_seed_warning()
        self.updated.emit()

    def update_seed_warning(self):
        if self.msg:
            return

        if self.seed_type == 'bip39':
            message = ' '.join([
                '<b>' + _('Warning') + ':</b>  ',
                _('BIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                _('However, we do not generate BIP39 seeds, because they do not meet our safety standard.'),
                _('BIP39 seeds do not include a version number, which compromises compatibility with future software.'),
                _('We do not guarantee that BIP39 imports will always be supported in Electrum.'),
            ])
        elif self.seed_type == 'slip39':
            message = ' '.join([
                '<b>' + _('Warning') + ':</b>  ',
                _('SLIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                _('However, we do not generate SLIP39 seeds.'),
            ])
        else:
            message = ''

        self.seed_warning.setText(message)

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
        if self.seed_type == 'bip39':
            from electrum.keystore import bip39_is_checksum_valid
            is_checksum, is_wordlist = bip39_is_checksum_valid(s)
            label = ''
            valid = bool(s)
            if valid:
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

            valid = self.slip39_seed is not None
            self.update_share_buttons()
        else:
            valid = self.is_seed(s)
            t = calc_seed_type(s)
            label = _('Seed Type') + ': ' + t if t else ''
            if t and not valid:  # electrum seed, but does not conform to dialog rules
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
        self._update_ext_controls()
        self.validChanged.emit(valid)

        # disable suggestions if user already typed an unknown word
        for word in self.get_seed_words()[:-1]:
            if word not in self.wordlist:
                self.seed_e.disable_suggestions()
                return
        self.seed_e.enable_suggestions()

    def _on_ext_toggled(self, checked):
        self.is_ext = checked
        if self.ext_box:
            self.ext_box.setVisible(bool(checked) and self.cb_ext.isEnabled())
        self.updated.emit()

    def _on_ext_text(self, text: str):
        if self.ext_issue4566 and self.seed_type == 'bip39':
            self.ext_issue4566.setVisible(text != ' '.join(text.split()))
        elif self.ext_issue4566:
            self.ext_issue4566.setVisible(False)
        self.updated.emit()

    def get_seed_extra_words(self) -> str:
        if not self.is_ext or not self.ext_edit:
            return ''
        return self.ext_edit.text()

    def _electrum_version_detected(self) -> bool:
        if self.seed_type != 'electrum':
            return False
        stype = calc_seed_type(self.get_seed())
        return bool(stype) and stype != 'old'

    def _set_ext_checked(self, checked: bool):
        if self.cb_ext is None:
            self.is_ext = checked
            return
        self.cb_ext.blockSignals(True)
        self.cb_ext.setChecked(checked)
        self.cb_ext.blockSignals(False)
        self.is_ext = checked

    def _sync_ext_box(self):
        if self.ext_box:
            self.ext_box.setVisible(bool(self.is_ext) and self.cb_ext.isEnabled())

    def _update_ext_controls(self):
        if self.cb_ext is None:
            return
        seed_text = self.seed_e.text().strip()
        if self.seed_type == 'bip39':
            self.cb_ext.setText(_('Use a BIP39 passphrase'))
            if self.ext_help:
                self.ext_help.setText('\n'.join([
                    _('Enter an optional BIP39 passphrase.'),
                    _('Each passphrase derives a different wallet.'),
                    _('This is sometimes incorrectly called the "25th word".'),
                ]))
            if self.ext_edit:
                self.ext_edit.setPlaceholderText(_('Enter your BIP39 passphrase'))
        else:
            self.cb_ext.setText(_('Extend this seed with custom words'))
            if self.ext_help:
                self.ext_help.setText('\n'.join([
                    _('You may extend your seed with custom words.'),
                    _('Your seed extension must be saved together with your seed.'),
                ]))
            if self.ext_edit:
                self.ext_edit.setPlaceholderText(_('Enter your custom word(s)'))
        if self.seed_type in ('bip39', 'slip39'):
            self.ext_reason_label.setText('')
            if not seed_text:
                self._set_ext_checked(False)
                self.cb_ext.setEnabled(False)
            else:
                self.cb_ext.setEnabled(True)
            self._sync_ext_box()
            return
        stype = calc_seed_type(self.get_seed())
        if not stype:
            self._set_ext_checked(False)
            self.cb_ext.setEnabled(False)
            self.ext_reason_label.setText('')
            self._sync_ext_box()
            return
        if not can_seed_have_passphrase(self.get_seed()):
            self._set_ext_checked(False)
            self.cb_ext.setEnabled(False)
            if stype == 'old':
                self.ext_reason_label.setText(_('Old Electrum seeds have no extra word.'))
            else:
                self.ext_reason_label.setText(_('This seed cannot be extended with an extra word.'))
            self._sync_ext_box()
            return
        self.cb_ext.setEnabled(True)
        self.ext_reason_label.setText('')
        self._sync_ext_box()

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


class KeysWidget(QWidget):

    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(
            self,
            parent=None,
            header_layout=None,
            is_valid=None,
            allow_multi=False,
            *,
            config: 'SimpleConfig',
    ):
        QWidget.__init__(self, parent)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        self.is_valid = is_valid
        self.text_e = ScanQRTextEdit(allow_multi=allow_multi, config=config)
        self.text_e.textChanged.connect(self.on_edit)
        if isinstance(header_layout, str):
            vbox.addWidget(WWLabel(header_layout))
        else:
            vbox.addLayout(header_layout)
        vbox.addWidget(self.text_e)

    def get_text(self):
        return self.text_e.text()

    def on_edit(self):
        try:
            valid = self.is_valid(self.get_text())
        except Exception as e:
            valid = False
        self.validChanged.emit(valid)


class SeedDialog(WindowModalDialog):

    def __init__(self, parent, seed, passphrase, *, config: 'SimpleConfig'):
        WindowModalDialog.__init__(self, parent, ('Electrum - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        title = _("Your wallet generation seed is:")
        seed_widget = SeedWidget(title=title, seed=seed, msg=True, passphrase=passphrase, config=config)
        vbox.addWidget(seed_widget)
        vbox.addLayout(Buttons(CloseButton(self)))
