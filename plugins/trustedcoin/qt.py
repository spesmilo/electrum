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
from threading import Thread
import re
from decimal import Decimal

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from electrum_gui.qt.util import *
from electrum_gui.qt.qrcodewidget import QRCodeWidget
from electrum_gui.qt.amountedit import AmountEdit
from electrum_gui.qt.main_window import StatusBarButton
from electrum.i18n import _
from electrum.plugins import hook
from trustedcoin import TrustedCoinPlugin, server


class Plugin(TrustedCoinPlugin):

    @hook
    def on_new_window(self, window):
        wallet = window.wallet
        if not isinstance(wallet, self.wallet_class):
            return
        if wallet.can_sign_without_server():
            msg = ' '.join([
                _('This wallet is was restored from seed, and it contains two master private keys.'),
                _('Therefore, two-factor authentication is disabled.')
            ])
            action = lambda: window.show_message(msg)
        else:
            action = partial(self.settings_dialog, window)
        button = StatusBarButton(QIcon(":icons/trustedcoin-status.png"),
                                 _("TrustedCoin"), action)
        window.statusBar().addPermanentWidget(button)
        t = Thread(target=self.request_billing_info, args=(wallet,))
        t.setDaemon(True)
        t.start()

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
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec_():
            return
        return pw.get_amount()

    @hook
    def sign_tx(self, window, tx):
        wallet = window.wallet
        if not isinstance(wallet, self.wallet_class):
            return
        if not wallet.can_sign_without_server():
            self.print_error("twofactor:sign_tx")
            auth_code = None
            if wallet.keystores['x3/'].get_tx_derivations(tx):
                auth_code = self.auth_dialog(window)
            else:
                self.print_error("twofactor: xpub3 not needed")
            window.wallet.auth_code = auth_code

    def waiting_dialog(self, window, on_finished=None):
        task = partial(self.request_billing_info, window.wallet)
        return WaitingDialog(window, 'Getting billing information...', task,
                             on_finished)

    @hook
    def abort_send(self, window):
        wallet = window.wallet
        if not isinstance(wallet, self.wallet_class):
            return
        if not wallet.can_sign_without_server():
            if wallet.billing_info is None:
                # request billing info before forming the transaction
                waiting_dialog(self, window).wait()
                if wallet.billing_info is None:
                    window.show_message('Could not contact server')
                    return True
        return False


    def settings_dialog(self, window):
        self.waiting_dialog(window, partial(self.show_settings_dialog, window))

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
        logo.setPixmap(QPixmap(":icons/trustedcoin-status.png"))
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

        msg = _('TrustedCoin charges a fee per co-signed transaction. You may pay on each transaction (an extra output will be added to your transaction), or you may purchase prepaid transaction using this dialog.') + '<br/>'
        label = QLabel(msg)
        label.setWordWrap(1)
        vbox.addWidget(label)

        vbox.addStretch(10)
        grid = QGridLayout()
        vbox.addLayout(grid)

        price_per_tx = wallet.price_per_tx
        v = price_per_tx.get(1)
        grid.addWidget(QLabel(_("Price per transaction (not prepaid):")), 0, 0)
        grid.addWidget(QLabel(window.format_amount(v) + ' ' + window.base_unit()), 0, 1)

        i = 1

        if 10 not in price_per_tx:
            price_per_tx[10] = 10 * price_per_tx.get(1)

        for k, v in sorted(price_per_tx.items()):
            if k == 1:
                continue
            grid.addWidget(QLabel("Price for %d prepaid transactions:"%k), i, 0)
            grid.addWidget(QLabel("%d x "%k + window.format_amount(v/k) + ' ' + window.base_unit()), i, 1)
            b = QPushButton(_("Buy"))
            b.clicked.connect(lambda b, k=k, v=v: self.on_buy(window, k, v, d))
            grid.addWidget(b, i, 2)
            i += 1

        n = wallet.billing_info.get('tx_remaining', 0)
        grid.addWidget(QLabel(_("Your wallet has %d prepaid transactions.")%n), i, 0)

        # tranfer button
        #def on_transfer():
        #    server.transfer_credit(self.user_id, recipient, otp, signature_callback)
        #    pass
        #b = QPushButton(_("Transfer"))
        #b.clicked.connect(on_transfer)
        #grid.addWidget(b, 1, 2)

        #grid.addWidget(QLabel(_("Next Billing Address:")), i, 0)
        #grid.addWidget(QLabel(self.billing_info['billing_address']), i, 1)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec_()

    def on_buy(self, window, k, v, d):
        d.close()
        if window.pluginsdialog:
            window.pluginsdialog.close()
        wallet = window.wallet
        uri = "bitcoin:" + wallet.billing_info['billing_address'] + "?message=TrustedCoin %d Prepaid Transactions&amount="%k + str(Decimal(v)/100000000)
        wallet.is_billing = True
        window.pay_to_URI(uri)
        window.payto_e.setFrozen(True)
        window.message_e.setFrozen(True)
        window.amount_e.setFrozen(True)

    def accept_terms_of_use(self, window):
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_("Terms of Service")))

        tos_e = QTextEdit()
        tos_e.setReadOnly(True)
        vbox.addWidget(tos_e)

        vbox.addWidget(QLabel(_("Please enter your e-mail address")))
        email_e = QLineEdit()
        vbox.addWidget(email_e)

        next_button = window.next_button
        prior_button_text = next_button.text()
        next_button.setText(_('Accept'))

        def request_TOS():
            tos = server.get_terms_of_service()
            self.TOS = tos
            window.emit(SIGNAL('twofactor:TOS'))

        def on_result():
            tos_e.setText(self.TOS)

        def set_enabled():
            next_button.setEnabled(re.match(regexp,email_e.text()) is not None)

        window.connect(window, SIGNAL('twofactor:TOS'), on_result)
        t = Thread(target=request_TOS)
        t.setDaemon(True)
        t.start()

        regexp = r"[^@]+@[^@]+\.[^@]+"
        email_e.textChanged.connect(set_enabled)
        email_e.setFocus(True)

        window.set_main_layout(vbox, next_enabled=False)
        next_button.setText(prior_button_text)
        return str(email_e.text())

    def request_otp_dialog(self, window, _id, otp_secret):
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
                "This wallet is already registered with Trustedcoin. "
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

        window.set_main_layout(vbox, next_enabled=False,
                               raise_on_cancel=False)
        return pw.get_amount(), cb_lost.isChecked()


