#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from functools import partial
from threading import Thread

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from electrum_gui.qt.util import *
from electrum_gui.qt.qrcodewidget import QRCodeWidget
from electrum_gui.qt.amountedit import AmountEdit
from electrum_gui.qt.main_window import StatusBarButton
from electrum.i18n import _
from electrum.plugins import hook

from trustedcoin import TrustedCoinPlugin, Wallet_2fa

def need_server(wallet, tx):
    from electrum.account import BIP32_Account
    # Detect if the server is needed
    long_id, short_id = wallet.get_user_id()
    xpub3 = wallet.master_public_keys['x3/']
    for x in tx.inputs_to_sign():
        if x[0:2] == 'ff':
            xpub, sequence = BIP32_Account.parse_xpubkey(x)
            if xpub == xpub3:
                return True
    return False

class Plugin(TrustedCoinPlugin):

    @hook
    def on_new_window(self, window):
        wallet = window.wallet
        if wallet.storage.get('wallet_type') == '2fa':
            button = StatusBarButton(QIcon(":icons/trustedcoin.png"),
                                     _("TrustedCoin"),
                                     partial(self.settings_dialog, window))
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
        self.print_error("twofactor:sign_tx")
        wallet = window.wallet
        if type(wallet) is Wallet_2fa and not wallet.can_sign_without_server():
            auth_code = None
            if need_server(wallet, tx):
                auth_code = self.auth_dialog(window)
            else:
                self.print_error("twofactor: xpub3 not needed")
            window.wallet.auth_code = auth_code

    @hook
    def abort_send(self, window):
        wallet = window.wallet
        if type(wallet) is Wallet_2fa and not wallet.can_sign_without_server():
            if wallet.billing_info is None:
                # request billing info before forming the transaction
                task = partial(self.request_billing_info, wallet)
                waiting_dialog = WaitingDialog(window, 'please wait...', task)
                waiting_dialog.start()
                waiting_dialog.wait()
                if wallet.billing_info is None:
                    window.show_message('Could not contact server')
                    return True
        return False


    def settings_dialog(self, window):
        task = partial(self.request_billing_info, window.wallet)
        self.waiting_dialog = WaitingDialog(window, 'please wait...', task, partial(self.show_settings_dialog, window))
        self.waiting_dialog.start()

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
        logo.setPixmap(QPixmap(":icons/trustedcoin.png"))
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
        window.set_layout(vbox)
        vbox.addWidget(QLabel(_("Terms of Service")))

        tos_e = QTextEdit()
        tos_e.setReadOnly(True)
        vbox.addWidget(tos_e)

        vbox.addWidget(QLabel(_("Please enter your e-mail address")))
        email_e = QLineEdit()
        vbox.addWidget(email_e)
        vbox.addStretch()
        accept_button = OkButton(window, _('Accept'))
        accept_button.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(window), accept_button))

        def request_TOS():
            tos = server.get_terms_of_service()
            self.TOS = tos
            window.emit(SIGNAL('twofactor:TOS'))

        def on_result():
            tos_e.setText(self.TOS)

        window.connect(window, SIGNAL('twofactor:TOS'), on_result)
        t = Thread(target=request_TOS)
        t.setDaemon(True)
        t.start()

        regexp = r"[^@]+@[^@]+\.[^@]+"
        email_e.textChanged.connect(lambda: accept_button.setEnabled(re.match(regexp,email_e.text()) is not None))
        email_e.setFocus(True)

        if not window.exec_():
            return

        email = str(email_e.text())
        return email


    def setup_google_auth(self, window, _id, otp_secret):
        vbox = QVBoxLayout()
        window.set_layout(vbox)
        if otp_secret is not None:
            uri = "otpauth://totp/%s?secret=%s"%('trustedcoin.com', otp_secret)
            vbox.addWidget(QLabel("Please scan this QR code in Google Authenticator."))
            qrw = QRCodeWidget(uri)
            vbox.addWidget(qrw, 1)
            msg = _('Then, enter your Google Authenticator code:')
        else:
            label = QLabel("This wallet is already registered, but it was never authenticated. To finalize your registration, please enter your Google Authenticator Code. If you do not have this code, delete the wallet file and start a new registration")
            label.setWordWrap(1)
            vbox.addWidget(label)
            msg = _('Google Authenticator code:')

        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(msg))
        pw = AmountEdit(None, is_int = True)
        pw.setFocus(True)
        hbox.addWidget(pw)
        hbox.addStretch(1)
        vbox.addLayout(hbox)

        b = OkButton(window, _('Next'))
        b.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(window), b))
        pw.textChanged.connect(lambda: b.setEnabled(len(pw.text())==6))

        while True:
            if not window.exec_():
                return False
            otp = pw.get_amount()
            try:
                server.auth(_id, otp)
                return True
            except:
                QMessageBox.information(window, _('Message'), _('Incorrect password'), _('OK'))
                pw.setText('')
