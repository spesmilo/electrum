# Copyright (C) 2018 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import os
import sys
import threading
import traceback
from typing import Tuple, List, Callable, NamedTuple, Optional

from PyQt5.QtCore import QRect, QEventLoop, Qt, pyqtSignal
from PyQt5.QtGui import QPalette, QPen, QPainter, QPixmap
from PyQt5.QtWidgets import (QWidget, QDialog, QLabel, QHBoxLayout, QMessageBox,
                             QVBoxLayout, QLineEdit, QFileDialog, QPushButton,
                             QGridLayout, QSlider, QScrollArea)

from electrum.wallet import Wallet, Abstract_Wallet
from electrum.storage import WalletStorage
from electrum.util import UserCancelled, InvalidPassword, WalletFileException
from electrum.base_wizard import BaseWizard, HWD_SETUP_DECRYPT_WALLET, GoBack
from electrum.i18n import _

from .seed_dialog import SeedLayout, KeysLayout
from .network_dialog import NetworkChoiceLayout
from .util import (MessageBoxMixin, Buttons, icon_path, ChoicesLayout, WWLabel,
                   InfoButton, char_width_in_lineedit)
from .password_dialog import PasswordLayout, PasswordLayoutForHW, PW_NEW
from electrum.plugin import run_hook

MSG_ENTER_PASSWORD = _("Choose a password to encrypt your wallet keys.") + '\n'\
                     + _("Leave this field empty if you want to disable encryption.")
MSG_HW_STORAGE_ENCRYPTION = _("Set wallet file encryption.") + '\n'\
                          + _("Your wallet file does not contain secrets, mostly just metadata. ") \
                          + _("It also contains your master public key that allows watching your addresses.") + '\n\n'\
                          + _("Note: If you enable this setting, you will need your hardware device to open your wallet.")
WIF_HELP_TEXT = (_('WIF keys are typed in Electrum, based on script type.') + '\n\n' +
                 _('A few examples') + ':\n' +
                 'p2pkh:KxZcY47uGp9a...       \t-> 1DckmggQM...\n' +
                 'p2wpkh-p2sh:KxZcY47uGp9a... \t-> 3NhNeZQXF...\n' +
                 'p2wpkh:KxZcY47uGp9a...      \t-> bc1q3fjfk...')
# note: full key is KxZcY47uGp9aVQAb6VVvuBs8SwHKgkSR2DbZUzjDzXf2N2GPhG9n
MSG_PASSPHRASE_WARN_ISSUE4566 = _("Warning") + ": "\
                              + _("You have multiple consecutive whitespaces or leading/trailing "
                                  "whitespaces in your passphrase.") + " " \
                              + _("This is discouraged.") + " " \
                              + _("Due to a bug, old versions of Electrum will NOT be creating the "
                                  "same wallet as newer versions or other software.")


class CosignWidget(QWidget):
    size = 120

    def __init__(self, m, n):
        QWidget.__init__(self)
        self.R = QRect(0, 0, self.size, self.size)
        self.setGeometry(self.R)
        self.setMinimumHeight(self.size)
        self.setMaximumHeight(self.size)
        self.m = m
        self.n = n

    def set_n(self, n):
        self.n = n
        self.update()

    def set_m(self, m):
        self.m = m
        self.update()

    def paintEvent(self, event):
        bgcolor = self.palette().color(QPalette.Background)
        pen = QPen(bgcolor, 7, Qt.SolidLine)
        qp = QPainter()
        qp.begin(self)
        qp.setPen(pen)
        qp.setRenderHint(QPainter.Antialiasing)
        qp.setBrush(Qt.gray)
        for i in range(self.n):
            alpha = int(16* 360 * i/self.n)
            alpha2 = int(16* 360 * 1/self.n)
            qp.setBrush(Qt.green if i<self.m else Qt.gray)
            qp.drawPie(self.R, alpha, alpha2)
        qp.end()



def wizard_dialog(func):
    def func_wrapper(*args, **kwargs):
        run_next = kwargs['run_next']
        wizard = args[0]  # type: InstallWizard
        wizard.back_button.setText(_('Back') if wizard.can_go_back() else _('Cancel'))
        try:
            out = func(*args, **kwargs)
            if type(out) is not tuple:
                out = (out,)
            run_next(*out)
        except GoBack:
            if wizard.can_go_back():
                wizard.go_back()
                return
            else:
                wizard.close()
                raise
    return func_wrapper


class WalletAlreadyOpenInMemory(Exception):
    def __init__(self, wallet: Abstract_Wallet):
        super().__init__()
        self.wallet = wallet


# WindowModalDialog must come first as it overrides show_error
class InstallWizard(QDialog, MessageBoxMixin, BaseWizard):

    accept_signal = pyqtSignal()

    def __init__(self, config, app, plugins):
        QDialog.__init__(self, None)
        BaseWizard.__init__(self, config, plugins)
        self.setWindowTitle('Electrum  -  ' + _('Install Wizard'))
        self.app = app
        self.config = config
        self.setMinimumSize(600, 400)
        self.accept_signal.connect(self.accept)
        self.title = QLabel()
        self.main_widget = QWidget()
        self.back_button = QPushButton(_("Back"), self)
        self.back_button.setText(_('Back') if self.can_go_back() else _('Cancel'))
        self.next_button = QPushButton(_("Next"), self)
        self.next_button.setDefault(True)
        self.logo = QLabel()
        self.please_wait = QLabel(_("Please wait..."))
        self.please_wait.setAlignment(Qt.AlignCenter)
        self.icon_filename = None
        self.loop = QEventLoop()
        self.rejected.connect(lambda: self.loop.exit(0))
        self.back_button.clicked.connect(lambda: self.loop.exit(1))
        self.next_button.clicked.connect(lambda: self.loop.exit(2))
        outer_vbox = QVBoxLayout(self)
        inner_vbox = QVBoxLayout()
        inner_vbox.addWidget(self.title)
        inner_vbox.addWidget(self.main_widget)
        inner_vbox.addStretch(1)
        inner_vbox.addWidget(self.please_wait)
        inner_vbox.addStretch(1)
        scroll_widget = QWidget()
        scroll_widget.setLayout(inner_vbox)
        scroll = QScrollArea()
        scroll.setWidget(scroll_widget)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidgetResizable(True)
        icon_vbox = QVBoxLayout()
        icon_vbox.addWidget(self.logo)
        icon_vbox.addStretch(1)
        hbox = QHBoxLayout()
        hbox.addLayout(icon_vbox)
        hbox.addSpacing(5)
        hbox.addWidget(scroll)
        hbox.setStretchFactor(scroll, 1)
        outer_vbox.addLayout(hbox)
        outer_vbox.addLayout(Buttons(self.back_button, self.next_button))
        self.set_icon('electrum.png')
        self.show()
        self.raise_()
        self.refresh_gui()  # Need for QT on MacOSX.  Lame.

    def select_storage(self, path, get_wallet_from_daemon) -> Tuple[str, Optional[WalletStorage]]:

        vbox = QVBoxLayout()
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(_('Wallet') + ':'))
        self.name_e = QLineEdit()
        hbox.addWidget(self.name_e)
        button = QPushButton(_('Choose...'))
        hbox.addWidget(button)
        vbox.addLayout(hbox)

        self.msg_label = QLabel('')
        vbox.addWidget(self.msg_label)
        hbox2 = QHBoxLayout()
        self.pw_e = QLineEdit('', self)
        self.pw_e.setFixedWidth(17 * char_width_in_lineedit())
        self.pw_e.setEchoMode(2)
        self.pw_label = QLabel(_('Password') + ':')
        hbox2.addWidget(self.pw_label)
        hbox2.addWidget(self.pw_e)
        hbox2.addStretch()
        vbox.addLayout(hbox2)
        self.set_layout(vbox, title=_('Electrum wallet'))

        self.temp_storage = WalletStorage(path, manual_upgrades=True)
        wallet_folder = os.path.dirname(self.temp_storage.path)

        def on_choose():
            path, __ = QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder)
            if path:
                self.name_e.setText(path)

        def on_filename(filename):
            path = os.path.join(wallet_folder, filename)
            wallet_from_memory = get_wallet_from_daemon(path)
            try:
                if wallet_from_memory:
                    self.temp_storage = wallet_from_memory.storage
                else:
                    self.temp_storage = WalletStorage(path, manual_upgrades=True)
                self.next_button.setEnabled(True)
            except BaseException:
                self.logger.exception('')
                self.temp_storage = None
                self.next_button.setEnabled(False)
            user_needs_to_enter_password = False
            if self.temp_storage:
                if not self.temp_storage.file_exists():
                    msg =_("This file does not exist.") + '\n' \
                          + _("Press 'Next' to create this wallet, or choose another file.")
                elif not wallet_from_memory:
                    if self.temp_storage.is_encrypted_with_user_pw():
                        msg = _("This file is encrypted with a password.") + '\n' \
                              + _('Enter your password or choose another file.')
                        user_needs_to_enter_password = True
                    elif self.temp_storage.is_encrypted_with_hw_device():
                        msg = _("This file is encrypted using a hardware device.") + '\n' \
                              + _("Press 'Next' to choose device to decrypt.")
                    else:
                        msg = _("Press 'Next' to open this wallet.")
                else:
                    msg = _("This file is already open in memory.") + "\n" \
                        + _("Press 'Next' to create/focus window.")
            else:
                msg = _('Cannot read file')
            self.msg_label.setText(msg)
            if user_needs_to_enter_password:
                self.pw_label.show()
                self.pw_e.show()
                self.pw_e.setFocus()
            else:
                self.pw_label.hide()
                self.pw_e.hide()

        button.clicked.connect(on_choose)
        self.name_e.textChanged.connect(on_filename)
        n = os.path.basename(self.temp_storage.path)
        self.name_e.setText(n)

        while True:
            if self.loop.exec_() != 2:  # 2 = next
                raise UserCancelled
            if self.temp_storage.file_exists() and not self.temp_storage.is_encrypted():
                break
            if not self.temp_storage.file_exists():
                break
            wallet_from_memory = get_wallet_from_daemon(self.temp_storage.path)
            if wallet_from_memory:
                raise WalletAlreadyOpenInMemory(wallet_from_memory)
            if self.temp_storage.file_exists() and self.temp_storage.is_encrypted():
                if self.temp_storage.is_encrypted_with_user_pw():
                    password = self.pw_e.text()
                    try:
                        self.temp_storage.decrypt(password)
                        break
                    except InvalidPassword as e:
                        self.show_message(title=_('Error'), msg=str(e))
                        continue
                    except BaseException as e:
                        self.logger.exception('')
                        self.show_message(title=_('Error'), msg=str(e))
                        raise UserCancelled()
                elif self.temp_storage.is_encrypted_with_hw_device():
                    try:
                        self.run('choose_hw_device', HWD_SETUP_DECRYPT_WALLET, storage=self.temp_storage)
                    except InvalidPassword as e:
                        self.show_message(title=_('Error'),
                                          msg=_('Failed to decrypt using this hardware device.') + '\n' +
                                              _('If you use a passphrase, make sure it is correct.'))
                        self.reset_stack()
                        return self.select_storage(path, get_wallet_from_daemon)
                    except BaseException as e:
                        self.logger.exception('')
                        self.show_message(title=_('Error'), msg=str(e))
                        raise UserCancelled()
                    if self.temp_storage.is_past_initial_decryption():
                        break
                    else:
                        raise UserCancelled()
                else:
                    raise Exception('Unexpected encryption version')

        return self.temp_storage.path, (self.temp_storage if self.temp_storage.file_exists() else None)  #

    def run_upgrades(self, storage):
        path = storage.path
        if storage.requires_split():
            self.hide()
            msg = _("The wallet '{}' contains multiple accounts, which are no longer supported since Electrum 2.7.\n\n"
                    "Do you want to split your wallet into multiple files?").format(path)
            if not self.question(msg):
                return
            file_list = '\n'.join(storage.split_accounts())
            msg = _('Your accounts have been moved to') + ':\n' + file_list + '\n\n'+ _('Do you want to delete the old file') + ':\n' + path
            if self.question(msg):
                os.remove(path)
                self.show_warning(_('The file was removed'))
            # raise now, to avoid having the old storage opened
            raise UserCancelled()

        action = storage.get_action()
        if action and storage.requires_upgrade():
            raise WalletFileException('Incomplete wallet files cannot be upgraded.')
        if action:
            self.hide()
            msg = _("The file '{}' contains an incompletely created wallet.\n"
                    "Do you want to complete its creation now?").format(path)
            if not self.question(msg):
                if self.question(_("Do you want to delete '{}'?").format(path)):
                    os.remove(path)
                    self.show_warning(_('The file was removed'))
                return
            self.show()
            self.data = storage.db.data # FIXME
            self.run(action)
            for k, v in self.data.items():
                storage.put(k, v)
            storage.write()
            return

        if storage.requires_upgrade():
            self.upgrade_storage(storage)

    def finished(self):
        """Called in hardware client wrapper, in order to close popups."""
        return

    def on_error(self, exc_info):
        if not isinstance(exc_info[1], UserCancelled):
            self.logger.error("on_error", exc_info=exc_info)
            self.show_error(str(exc_info[1]))

    def set_icon(self, filename):
        prior_filename, self.icon_filename = self.icon_filename, filename
        self.logo.setPixmap(QPixmap(icon_path(filename))
                            .scaledToWidth(60, mode=Qt.SmoothTransformation))
        return prior_filename

    def set_layout(self, layout, title=None, next_enabled=True):
        self.title.setText("<b>%s</b>"%title if title else "")
        self.title.setVisible(bool(title))
        # Get rid of any prior layout by assigning it to a temporary widget
        prior_layout = self.main_widget.layout()
        if prior_layout:
            QWidget().setLayout(prior_layout)
        self.main_widget.setLayout(layout)
        self.back_button.setEnabled(True)
        self.next_button.setEnabled(next_enabled)
        if next_enabled:
            self.next_button.setFocus()
        self.main_widget.setVisible(True)
        self.please_wait.setVisible(False)

    def exec_layout(self, layout, title=None, raise_on_cancel=True,
                        next_enabled=True):
        self.set_layout(layout, title, next_enabled)
        result = self.loop.exec_()
        if not result and raise_on_cancel:
            raise UserCancelled
        if result == 1:
            raise GoBack from None
        self.title.setVisible(False)
        self.back_button.setEnabled(False)
        self.next_button.setEnabled(False)
        self.main_widget.setVisible(False)
        self.please_wait.setVisible(True)
        self.refresh_gui()
        return result

    def refresh_gui(self):
        # For some reason, to refresh the GUI this needs to be called twice
        self.app.processEvents()
        self.app.processEvents()

    def remove_from_recently_open(self, filename):
        self.config.remove_from_recently_open(filename)

    def text_input(self, title, message, is_valid, allow_multi=False):
        slayout = KeysLayout(parent=self, header_layout=message, is_valid=is_valid,
                             allow_multi=allow_multi)
        self.exec_layout(slayout, title, next_enabled=False)
        return slayout.get_text()

    def seed_input(self, title, message, is_seed, options):
        slayout = SeedLayout(title=message, is_seed=is_seed, options=options, parent=self)
        self.exec_layout(slayout, title, next_enabled=False)
        return slayout.get_seed(), slayout.is_bip39, slayout.is_ext

    @wizard_dialog
    def add_xpub_dialog(self, title, message, is_valid, run_next, allow_multi=False, show_wif_help=False):
        header_layout = QHBoxLayout()
        label = WWLabel(message)
        label.setMinimumWidth(400)
        header_layout.addWidget(label)
        if show_wif_help:
            header_layout.addWidget(InfoButton(WIF_HELP_TEXT), alignment=Qt.AlignRight)
        return self.text_input(title, header_layout, is_valid, allow_multi)

    @wizard_dialog
    def add_cosigner_dialog(self, run_next, index, is_valid):
        title = _("Add Cosigner") + " %d"%index
        message = ' '.join([
            _('Please enter the master public key (xpub) of your cosigner.'),
            _('Enter their master private key (xprv) if you want to be able to sign for them.')
        ])
        return self.text_input(title, message, is_valid)

    @wizard_dialog
    def restore_seed_dialog(self, run_next, test):
        options = []
        if self.opt_ext:
            options.append('ext')
        if self.opt_bip39:
            options.append('bip39')
        title = _('Enter Seed')
        message = _('Please enter your seed phrase in order to restore your wallet.')
        return self.seed_input(title, message, test, options)

    @wizard_dialog
    def confirm_seed_dialog(self, run_next, test):
        self.app.clipboard().clear()
        title = _('Confirm Seed')
        message = ' '.join([
            _('Your seed is important!'),
            _('If you lose your seed, your money will be permanently lost.'),
            _('To make sure that you have properly saved your seed, please retype it here.')
        ])
        seed, is_bip39, is_ext = self.seed_input(title, message, test, None)
        return seed

    @wizard_dialog
    def show_seed_dialog(self, run_next, seed_text):
        title =  _("Your wallet generation seed is:")
        slayout = SeedLayout(seed=seed_text, title=title, msg=True, options=['ext'])
        self.exec_layout(slayout)
        return slayout.is_ext

    def pw_layout(self, msg, kind, force_disable_encrypt_cb):
        playout = PasswordLayout(msg=msg, kind=kind, OK_button=self.next_button,
                                 force_disable_encrypt_cb=force_disable_encrypt_cb)
        playout.encrypt_cb.setChecked(True)
        self.exec_layout(playout.layout())
        return playout.new_password(), playout.encrypt_cb.isChecked()

    @wizard_dialog
    def request_password(self, run_next, force_disable_encrypt_cb=False):
        """Request the user enter a new password and confirm it.  Return
        the password or None for no password."""
        return self.pw_layout(MSG_ENTER_PASSWORD, PW_NEW, force_disable_encrypt_cb)

    @wizard_dialog
    def request_storage_encryption(self, run_next):
        playout = PasswordLayoutForHW(MSG_HW_STORAGE_ENCRYPTION)
        playout.encrypt_cb.setChecked(True)
        self.exec_layout(playout.layout())
        return playout.encrypt_cb.isChecked()

    @wizard_dialog
    def confirm_dialog(self, title, message, run_next):
        self.confirm(message, title)

    def confirm(self, message, title):
        label = WWLabel(message)
        vbox = QVBoxLayout()
        vbox.addWidget(label)
        self.exec_layout(vbox, title)

    @wizard_dialog
    def action_dialog(self, action, run_next):
        self.run(action)

    def terminate(self, **kwargs):
        self.accept_signal.emit()

    def waiting_dialog(self, task, msg, on_finished=None):
        label = WWLabel(msg)
        vbox = QVBoxLayout()
        vbox.addSpacing(100)
        label.setMinimumWidth(300)
        label.setAlignment(Qt.AlignCenter)
        vbox.addWidget(label)
        self.set_layout(vbox, next_enabled=False)
        self.back_button.setEnabled(False)

        t = threading.Thread(target=task)
        t.start()
        while True:
            t.join(1.0/60)
            if t.is_alive():
                self.refresh_gui()
            else:
                break
        if on_finished:
            on_finished()

    @wizard_dialog
    def choice_dialog(self, title, message, choices, run_next):
        c_values = [x[0] for x in choices]
        c_titles = [x[1] for x in choices]
        clayout = ChoicesLayout(message, c_titles)
        vbox = QVBoxLayout()
        vbox.addLayout(clayout.layout())
        self.exec_layout(vbox, title)
        action = c_values[clayout.selected_index()]
        return action

    def query_choice(self, msg, choices):
        """called by hardware wallets"""
        clayout = ChoicesLayout(msg, choices)
        vbox = QVBoxLayout()
        vbox.addLayout(clayout.layout())
        self.exec_layout(vbox, '')
        return clayout.selected_index()

    @wizard_dialog
    def choice_and_line_dialog(self, title: str, message1: str, choices: List[Tuple[str, str, str]],
                               message2: str, test_text: Callable[[str], int],
                               run_next, default_choice_idx: int=0) -> Tuple[str, str]:
        vbox = QVBoxLayout()

        c_values = [x[0] for x in choices]
        c_titles = [x[1] for x in choices]
        c_default_text = [x[2] for x in choices]
        def on_choice_click(clayout):
            idx = clayout.selected_index()
            line.setText(c_default_text[idx])
        clayout = ChoicesLayout(message1, c_titles, on_choice_click,
                                checked_index=default_choice_idx)
        vbox.addLayout(clayout.layout())

        vbox.addSpacing(50)
        vbox.addWidget(WWLabel(message2))

        line = QLineEdit()
        def on_text_change(text):
            self.next_button.setEnabled(test_text(text))
        line.textEdited.connect(on_text_change)
        on_choice_click(clayout)  # set default text for "line"
        vbox.addWidget(line)

        self.exec_layout(vbox, title)
        choice = c_values[clayout.selected_index()]
        return str(line.text()), choice

    @wizard_dialog
    def line_dialog(self, run_next, title, message, default, test, warning='',
                    presets=(), warn_issue4566=False):
        vbox = QVBoxLayout()
        vbox.addWidget(WWLabel(message))
        line = QLineEdit()
        line.setText(default)
        def f(text):
            self.next_button.setEnabled(test(text))
            if warn_issue4566:
                text_whitespace_normalised = ' '.join(text.split())
                warn_issue4566_label.setVisible(text != text_whitespace_normalised)
        line.textEdited.connect(f)
        vbox.addWidget(line)
        vbox.addWidget(WWLabel(warning))

        warn_issue4566_label = WWLabel(MSG_PASSPHRASE_WARN_ISSUE4566)
        warn_issue4566_label.setVisible(False)
        vbox.addWidget(warn_issue4566_label)

        for preset in presets:
            button = QPushButton(preset[0])
            button.clicked.connect(lambda __, text=preset[1]: line.setText(text))
            button.setMinimumWidth(150)
            hbox = QHBoxLayout()
            hbox.addWidget(button, alignment=Qt.AlignCenter)
            vbox.addLayout(hbox)

        self.exec_layout(vbox, title, next_enabled=test(default))
        return line.text()

    @wizard_dialog
    def show_xpub_dialog(self, xpub, run_next):
        msg = ' '.join([
            _("Here is your master public key."),
            _("Please share it with your cosigners.")
        ])
        vbox = QVBoxLayout()
        layout = SeedLayout(xpub, title=msg, icon=False, for_seed_words=False)
        vbox.addLayout(layout.layout())
        self.exec_layout(vbox, _('Master Public Key'))
        return None

    def init_network(self, network):
        message = _("Electrum communicates with remote servers to get "
                  "information about your transactions and addresses. The "
                  "servers all fulfill the same purpose only differing in "
                  "hardware. In most cases you simply want to let Electrum "
                  "pick one at random.  However if you prefer feel free to "
                  "select a server manually.")
        choices = [_("Auto connect"), _("Select server manually")]
        title = _("How do you want to connect to a server? ")
        clayout = ChoicesLayout(message, choices)
        self.back_button.setText(_('Cancel'))
        self.exec_layout(clayout.layout(), title)
        r = clayout.selected_index()
        if r == 1:
            nlayout = NetworkChoiceLayout(network, self.config, wizard=True)
            if self.exec_layout(nlayout.layout()):
                nlayout.accept()
        else:
            network.auto_connect = True
            self.config.set_key('auto_connect', True, True)

    @wizard_dialog
    def multisig_dialog(self, run_next):
        cw = CosignWidget(2, 2)
        m_edit = QSlider(Qt.Horizontal, self)
        n_edit = QSlider(Qt.Horizontal, self)
        n_edit.setMinimum(2)
        n_edit.setMaximum(15)
        m_edit.setMinimum(1)
        m_edit.setMaximum(2)
        n_edit.setValue(2)
        m_edit.setValue(2)
        n_label = QLabel()
        m_label = QLabel()
        grid = QGridLayout()
        grid.addWidget(n_label, 0, 0)
        grid.addWidget(n_edit, 0, 1)
        grid.addWidget(m_label, 1, 0)
        grid.addWidget(m_edit, 1, 1)
        def on_m(m):
            m_label.setText(_('Require {0} signatures').format(m))
            cw.set_m(m)
        def on_n(n):
            n_label.setText(_('From {0} cosigners').format(n))
            cw.set_n(n)
            m_edit.setMaximum(n)
        n_edit.valueChanged.connect(on_n)
        m_edit.valueChanged.connect(on_m)
        on_n(2)
        on_m(2)
        vbox = QVBoxLayout()
        vbox.addWidget(cw)
        vbox.addWidget(WWLabel(_("Choose the number of signatures needed to unlock funds in your wallet:")))
        vbox.addLayout(grid)
        self.exec_layout(vbox, _("Multi-Signature Wallet"))
        m = int(m_edit.value())
        n = int(n_edit.value())
        return (m, n)
