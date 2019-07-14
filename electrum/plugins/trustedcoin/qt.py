#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
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

from functools import partial
import threading
import sys
import os

from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import (QTextEdit, QVBoxLayout, QLabel, QGridLayout, QHBoxLayout,
                             QRadioButton, QCheckBox, QLineEdit)

from electrum.gui.qt.util import (read_QIcon, WindowModalDialog, WaitingDialog, OkButton,
                                  CancelButton, Buttons, icon_path, WWLabel, CloseButton)
from electrum.gui.qt.qrcodewidget import QRCodeWidget
from electrum.gui.qt.amountedit import AmountEdit
from electrum.gui.qt.main_window import StatusBarButton
from electrum.gui.qt.installwizard import InstallWizard
from electrum.i18n import _
from electrum.plugin import hook
from electrum.util import is_valid_email
from electrum.logging import Logger
from electrum.base_wizard import GoBack

from .trustedcoin import TrustedCoinPlugin, server


class TOS(QTextEdit):
    tos_signal = pyqtSignal()
    error_signal = pyqtSignal(object)


class HandlerTwoFactor(QObject, Logger):

    def __init__(self, plugin, window):
        QObject.__init__(self)
        self.plugin = plugin
        self.window = window
        Logger.__init__(self)

    def prompt_user_for_otp(self, wallet, tx, on_success, on_failure):
        if not isinstance(wallet, self.plugin.wallet_class):
            return
        if wallet.can_sign_without_server():
            return
        if not wallet.keystores['x3/'].get_tx_derivations(tx):
            self.logger.info("twofactor: xpub3 not needed")
            return
        window = self.window.top_level_window()
        auth_code = self.plugin.auth_dialog(window)
        WaitingDialog(parent=window,
                      message=_('Waiting for TrustedCoin server to sign transaction...'),
                      task=lambda: wallet.on_otp(tx, auth_code),
                      on_success=lambda *args: on_success(tx),
                      on_error=on_failure)


class Plugin(TrustedCoinPlugin):

    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)

    @hook
    def on_new_window(self, window):
        wallet = window.wallet
        if not isinstance(wallet, self.wallet_class):
            return
        wallet.handler_2fa = HandlerTwoFactor(self, window)
        if wallet.can_sign_without_server():
            msg = ' '.join([
                _('This wallet was restored from seed, and it contains two master private keys.'),
                _('Therefore, two-factor authentication is disabled.')
            ])
            action = lambda: window.show_message(msg)
        else:
            action = partial(self.settings_dialog, window)
        button = StatusBarButton(read_QIcon("trustedcoin-status.png"),
                                 _("TrustedCoin"), action)
        window.statusBar().addPermanentWidget(button)
        self.start_request_thread(window.wallet)

    def auth_dialog(self, window):
        d = WindowModalDialog(window, _("Authorization"))
        vbox = QVBoxLayout(d)
        pw = AmountEdit(None, is_int = True)
        msg = _('Please enter your Google Authenticator code')
        vbox.addWidget(QLabel(msg))
        grid = QGridLayout()
        grid.setSpacing(8)
        grid.addWidget(QLabel(_('Code')), 1, 0)
        grid.addWidget(pw, 1, 1)
        vbox.addLayout(grid)
        msg = _('If you have lost your second factor, you need to restore your wallet from seed in order to request a new code.')
        label = QLabel(msg)
        label.setWordWrap(1)
        vbox.addWidget(label)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec_():
            return
        return pw.get_amount()

    def prompt_user_for_otp(self, wallet, tx, on_success, on_failure):
        wallet.handler_2fa.prompt_user_for_otp(wallet, tx, on_success, on_failure)

    def waiting_dialog_for_billing_info(self, window, *, on_finished=None):
        def task():
            return self.request_billing_info(window.wallet, suppress_connection_error=False)
        def on_error(exc_info):
            e = exc_info[1]
            window.show_error("{header}\n{exc}\n\n{tor}"
                              .format(header=_('Error getting TrustedCoin account info.'),
                                      exc=str(e),
                                      tor=_('If you keep experiencing network problems, try using a Tor proxy.')))
        return WaitingDialog(parent=window,
                             message=_('Requesting account info from TrustedCoin server...'),
                             task=task,
                             on_success=on_finished,
                             on_error=on_error)

    @hook
    def abort_send(self, window):
        wallet = window.wallet
        if not isinstance(wallet, self.wallet_class):
            return
        if wallet.can_sign_without_server():
            return
        if wallet.billing_info is None:
            self.waiting_dialog_for_billing_info(window)
            return True
        return False

    def settings_dialog(self, window):
        self.waiting_dialog_for_billing_info(window,
                                             on_finished=partial(self.show_settings_dialog, window))

    def show_settings_dialog(self, window, success):
        if not success:
            window.show_message(_('Server not reachable.'))
            return

        wallet = window.wallet
        d = WindowModalDialog(window, _("TrustedCoin Information"))
        d.setMinimumSize(500, 200)
        vbox = QVBoxLayout(d)
        hbox = QHBoxLayout()

        logo = QLabel()
        logo.setPixmap(QPixmap(icon_path("trustedcoin-status.png")))
        msg = _('This wallet is protected by TrustedCoin\'s two-factor authentication.') + '<br/>'\
              + _("For more information, visit") + " <a href=\"https://api.trustedcoin.com/#/electrum-help\">https://api.trustedcoin.com/#/electrum-help</a>"
        label = QLabel(msg)
        label.setOpenExternalLinks(1)

        hbox.addStretch(10)
        hbox.addWidget(logo)
        hbox.addStretch(10)
        hbox.addWidget(label)
        hbox.addStretch(10)

        vbox.addLayout(hbox)
        vbox.addStretch(10)

        msg = _('TrustedCoin charges a small fee to co-sign transactions. The fee depends on how many prepaid transactions you buy. An extra output is added to your transaction every time you run out of prepaid transactions.') + '<br/>'
        label = QLabel(msg)
        label.setWordWrap(1)
        vbox.addWidget(label)

        vbox.addStretch(10)
        grid = QGridLayout()
        vbox.addLayout(grid)

        price_per_tx = wallet.price_per_tx
        n_prepay = wallet.num_prepay(self.config)
        i = 0
        for k, v in sorted(price_per_tx.items()):
            if k == 1:
                continue
            grid.addWidget(QLabel("Pay every %d transactions:"%k), i, 0)
            grid.addWidget(QLabel(window.format_amount(v/k) + ' ' + window.base_unit() + "/tx"), i, 1)
            b = QRadioButton()
            b.setChecked(k == n_prepay)
            b.clicked.connect(lambda b, k=k: self.config.set_key('trustedcoin_prepay', k, True))
            grid.addWidget(b, i, 2)
            i += 1

        n = wallet.billing_info.get('tx_remaining', 0)
        grid.addWidget(QLabel(_("Your wallet has {} prepaid transactions.").format(n)), i, 0)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec_()

    def go_online_dialog(self, wizard: InstallWizard):
        msg = [
            _("Your wallet file is: {}.").format(os.path.abspath(wizard.path)),
            _("You need to be online in order to complete the creation of "
              "your wallet.  If you generated your seed on an offline "
              'computer, click on "{}" to close this window, move your '
              "wallet file to an online computer, and reopen it with "
              "Electrum.").format(_('Cancel')),
            _('If you are online, click on "{}" to continue.').format(_('Next'))
        ]
        msg = '\n\n'.join(msg)
        wizard.reset_stack()
        try:
            wizard.confirm_dialog(title='', message=msg, run_next = lambda x: wizard.run('accept_terms_of_use'))
        except GoBack:
            # user clicked 'Cancel' and decided to move wallet file manually
            wizard.create_storage(wizard.path)
            raise

    def accept_terms_of_use(self, window):
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_("Terms of Service")))

        tos_e = TOS()
        tos_e.setReadOnly(True)
        vbox.addWidget(tos_e)
        tos_received = False

        vbox.addWidget(QLabel(_("Please enter your e-mail address")))
        email_e = QLineEdit()
        vbox.addWidget(email_e)

        next_button = window.next_button
        prior_button_text = next_button.text()
        next_button.setText(_('Accept'))

        def request_TOS():
            try:
                tos = server.get_terms_of_service()
            except Exception as e:
                self.logger.exception('Could not retrieve Terms of Service')
                tos_e.error_signal.emit(_('Could not retrieve Terms of Service:')
                                        + '\n' + str(e))
                return
            self.TOS = tos
            tos_e.tos_signal.emit()

        def on_result():
            tos_e.setText(self.TOS)
            nonlocal tos_received
            tos_received = True
            set_enabled()

        def on_error(msg):
            window.show_error(str(msg))
            window.terminate()

        def set_enabled():
            next_button.setEnabled(tos_received and is_valid_email(email_e.text()))

        tos_e.tos_signal.connect(on_result)
        tos_e.error_signal.connect(on_error)
        t = threading.Thread(target=request_TOS)
        t.setDaemon(True)
        t.start()
        email_e.textChanged.connect(set_enabled)
        email_e.setFocus(True)
        window.exec_layout(vbox, next_enabled=False)
        next_button.setText(prior_button_text)
        email = str(email_e.text())
        self.create_remote_key(email, window)

    def request_otp_dialog(self, window, short_id, otp_secret, xpub3):
        vbox = QVBoxLayout()
        if otp_secret is not None:
            uri = "otpauth://totp/%s?secret=%s"%('trustedcoin.com', otp_secret)
            l = QLabel("Please scan the following QR code in Google Authenticator. You may as well use the following key: %s"%otp_secret)
            l.setWordWrap(True)
            vbox.addWidget(l)
            qrw = QRCodeWidget(uri)
            vbox.addWidget(qrw, 1)
            msg = _('Then, enter your Google Authenticator code:')
        else:
            label = QLabel(
                "This wallet is already registered with TrustedCoin. "
                "To finalize wallet creation, please enter your Google Authenticator Code. "
            )
            label.setWordWrap(1)
            vbox.addWidget(label)
            msg = _('Google Authenticator code:')
        hbox = QHBoxLayout()
        hbox.addWidget(WWLabel(msg))
        pw = AmountEdit(None, is_int = True)
        pw.setFocus(True)
        pw.setMaximumWidth(50)
        hbox.addWidget(pw)
        vbox.addLayout(hbox)
        cb_lost = QCheckBox(_("I have lost my Google Authenticator account"))
        cb_lost.setToolTip(_("Check this box to request a new secret. You will need to retype your seed."))
        vbox.addWidget(cb_lost)
        cb_lost.setVisible(otp_secret is None)
        def set_enabled():
            b = True if cb_lost.isChecked() else len(pw.text()) == 6
            window.next_button.setEnabled(b)
        pw.textChanged.connect(set_enabled)
        cb_lost.toggled.connect(set_enabled)
        window.exec_layout(vbox, next_enabled=False, raise_on_cancel=False)
        self.check_otp(window, short_id, otp_secret, xpub3, pw.get_amount(), cb_lost.isChecked())
