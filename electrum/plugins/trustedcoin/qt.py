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
import os
from typing import TYPE_CHECKING

from PyQt6.QtGui import QPixmap, QMovie, QColor
from PyQt6.QtCore import QObject, pyqtSignal, QSize, Qt
from PyQt6.QtWidgets import (QTextEdit, QVBoxLayout, QLabel, QGridLayout, QHBoxLayout,
                             QRadioButton, QCheckBox, QLineEdit, QPushButton, QWidget)

from electrum.i18n import _
from electrum.plugin import hook
from electrum.util import is_valid_email
from electrum.logging import Logger, get_logger
from electrum import keystore

from electrum.gui.qt.util import (read_QIcon, WindowModalDialog, WaitingDialog, OkButton,
                                  CancelButton, Buttons, icon_path, WWLabel, CloseButton, ColorScheme,
                                  ChoiceWidget)
from electrum.gui.qt.qrcodewidget import QRCodeWidget
from electrum.gui.qt.amountedit import AmountEdit
from electrum.gui.qt.main_window import StatusBarButton
from electrum.gui.qt.wizard.wallet import WCCreateSeed, WCConfirmSeed, WCHaveSeed, WCEnterExt, WCConfirmExt
from electrum.gui.qt.wizard.wizard import WizardComponent

from .common_qt import TrustedcoinPluginQObject
from .trustedcoin import TrustedCoinPlugin, server, DISCLAIMER

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard


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
        if not wallet.keystores['x3'].can_sign(tx, ignore_watching_only=True):
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
    def load_wallet(self, wallet: 'Abstract_Wallet', window: 'ElectrumWindow'):
        if not isinstance(wallet, self.wallet_class):
            return
        wallet.handler_2fa = HandlerTwoFactor(self, window)
        if wallet.can_sign_without_server():
            msg = ' '.join([
                _('This wallet was restored from seed, and it contains two master private keys.'),
                _('Therefore, two-factor authentication is disabled.')
            ])
            action = lambda: window.show_message(msg)
            icon = read_QIcon("trustedcoin-status-disabled.png")
        else:
            action = partial(self.settings_dialog, window)
            icon = read_QIcon("trustedcoin-status.png")
        sb = window.statusBar()
        button = StatusBarButton(icon, _("TrustedCoin"), action, sb.height())
        sb.addPermanentWidget(button)
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
        if not d.exec():
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
                                      exc=repr(e),
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
        n_prepay = wallet.num_prepay()
        i = 0
        for k, v in sorted(price_per_tx.items()):
            if k == 1:
                continue
            grid.addWidget(QLabel("Pay every %d transactions:"%k), i, 0)
            grid.addWidget(QLabel(window.format_amount(v/k) + ' ' + window.base_unit() + "/tx"), i, 1)
            b = QRadioButton()
            b.setChecked(k == n_prepay)
            def on_click(b, k):
                self.config.PLUGIN_TRUSTEDCOIN_NUM_PREPAY = k
            b.clicked.connect(partial(on_click, k=k))
            grid.addWidget(b, i, 2)
            i += 1

        n = wallet.billing_info.get('tx_remaining', 0)
        grid.addWidget(QLabel(_("Your wallet has {} prepaid transactions.").format(n)), i, 0)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec()

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        wizard.trustedcoin_qhelper = TrustedcoinPluginQObject(self, wizard, None)
        self.extend_wizard(wizard)
        if wizard.start_viewstate and wizard.start_viewstate.view.startswith('trustedcoin_'):
            wizard.start_viewstate.params.update({'icon': icon_path('trustedcoin-wizard.png')})

    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'trustedcoin_start': {
                'gui': WCDisclaimer,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
            },
            'trustedcoin_choose_seed': {
                'gui': WCChooseSeed,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
            },
            'trustedcoin_create_seed': {
                'gui': WCCreateSeed,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
            },
            'trustedcoin_confirm_seed': {
                'gui': WCConfirmSeed,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
            },
            'trustedcoin_have_seed': {
                'gui': WCHaveSeed,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
            },
            'trustedcoin_keep_disable': {
                'gui': WCKeepDisable,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
            },
            'trustedcoin_tos': {
                'gui': WCTerms,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
            },
            'trustedcoin_show_confirm_otp': {
                'gui': WCShowConfirmOTP,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
            }
        }
        wizard.navmap_merge(views)

        # modify default flow, insert seed extension entry/confirm as separate views
        ext = {
            'trustedcoin_create_seed': {
                'next': lambda d: 'trustedcoin_create_ext' if wizard.wants_ext(d) else 'trustedcoin_confirm_seed'
            },
            'trustedcoin_create_ext': {
                'gui': WCEnterExt,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
                'next': 'trustedcoin_confirm_seed',
            },
            'trustedcoin_confirm_seed': {
                'next': lambda d: 'trustedcoin_confirm_ext' if wizard.wants_ext(d) else 'trustedcoin_tos'
            },
            'trustedcoin_confirm_ext': {
                'gui': WCConfirmExt,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
                'next': 'trustedcoin_tos',
            },
            'trustedcoin_have_seed': {
                'next': lambda d: 'trustedcoin_have_ext' if wizard.wants_ext(d) else 'trustedcoin_keep_disable'
            },
            'trustedcoin_have_ext': {
                'gui': WCEnterExt,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
                'next': 'trustedcoin_keep_disable',
            },
        }
        wizard.navmap_merge(ext)

        # insert page offering choice to go online or continue on another system
        ext_online = {
            'trustedcoin_continue_online': {
                'gui': WCContinueOnline,
                'params': {'icon': icon_path('trustedcoin-wizard.png')},
                'next': lambda d: 'trustedcoin_tos' if d['trustedcoin_go_online'] else 'wallet_password',
                'accept': self.on_continue_online,
                'last': lambda d: not d['trustedcoin_go_online'] and wizard.is_single_password()
            },
            'trustedcoin_confirm_seed': {
                'next': lambda d: 'trustedcoin_confirm_ext' if wizard.wants_ext(d) else 'trustedcoin_continue_online'
            },
            'trustedcoin_confirm_ext': {
                'next': 'trustedcoin_continue_online',
            },
            'trustedcoin_keep_disable': {
                'next': lambda d: 'trustedcoin_continue_online' if d['trustedcoin_keepordisable'] != 'disable'
                else 'wallet_password',
            }
        }
        wizard.navmap_merge(ext_online)

    def on_continue_online(self, wizard_data):
        if not wizard_data['trustedcoin_go_online']:
            self.logger.debug('Staying offline, create keystores here')
            xprv1, xpub1, xprv2, xpub2, xpub3, short_id = self.create_keys(wizard_data)
            k1 = keystore.from_xprv(xprv1)
            k2 = keystore.from_xpub(xpub2)

            wizard_data['x1'] = k1.dump()
            wizard_data['x2'] = k2.dump()


class WCDisclaimer(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Disclaimer'))

        self.layout().addWidget(WWLabel('\n\n'.join(DISCLAIMER)))
        self.layout().addStretch(1)

        self._valid = True

    def apply(self):
        pass


class WCChooseSeed(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Create or restore'))
        message = _('Do you want to create a new seed, or restore a wallet using an existing seed?')
        choices = [
            ('createseed',  _('Create a new seed')),
            ('haveseed',    _('I already have a seed')),
        ]

        self.choice_w = ChoiceWidget(message=message, choices=choices)
        self.layout().addWidget(self.choice_w)
        self.layout().addStretch(1)

        self._valid = True

    def apply(self):
        self.wizard_data['keystore_type'] = self.choice_w.selected_key


class WCTerms(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Terms and conditions'))
        self._has_tos = False

    def on_ready(self):
        self.tos_e = TOS()
        self.tos_e.setReadOnly(True)
        self.layout().addWidget(self.tos_e)

        self.fetch_terms_and_conditions()

    def fetch_terms_and_conditions(self):
        self.wizard.trustedcoin_qhelper.busyChanged.connect(self.on_busy_changed)
        self.wizard.trustedcoin_qhelper.termsAndConditionsRetrieved.connect(self.on_terms_retrieved)
        self.wizard.trustedcoin_qhelper.termsAndConditionsError.connect(self.on_terms_error)
        self.wizard.trustedcoin_qhelper.fetchTermsAndConditions()

    def on_busy_changed(self):
        self.busy = self.wizard.trustedcoin_qhelper.busy

    def on_terms_retrieved(self, tos: str) -> None:
        self._has_tos = True
        self.tos_e.setText(tos)
        self.validate()

    def on_terms_error(self, error: str) -> None:
        self.error = error

    def validate(self):
        self.valid = self._has_tos

    def apply(self):
        pass


class WCShowConfirmOTP(WizardComponent):
    _logger = get_logger(__name__)

    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Authenticator secret'))
        self._otp_verified = False
        self._is_online_continuation = False

        self.new_otp = QWidget()
        new_otp_layout = QVBoxLayout()
        scanlabel = WWLabel(_('Enter or scan into authenticator app. Then authenticate below'))
        new_otp_layout.addWidget(scanlabel)
        self.qr = QRCodeWidget('')
        new_otp_layout.addWidget(self.qr)
        self.secretlabel = WWLabel()
        new_otp_layout.addWidget(self.secretlabel)
        self.new_otp.setLayout(new_otp_layout)

        self.exist_otp = QWidget()
        exist_otp_layout = QVBoxLayout()
        knownlabel = WWLabel(_('This wallet is already registered with TrustedCoin.'))
        exist_otp_layout.addWidget(knownlabel)
        self.knownsecretlabel = WWLabel(_('If you still have your OTP secret, then authenticate below to finalize wallet creation'))
        exist_otp_layout.addWidget(self.knownsecretlabel)
        self.exist_otp.setLayout(exist_otp_layout)

        self.authlabelnew = WWLabel(_('Then, enter your Google Authenticator code:'))
        self.authlabelexist = WWLabel(_('Google Authenticator code:'))

        self.spinner = QMovie(icon_path('spinner.gif'))
        self.spinner.setScaledSize(QSize(24, 24))
        self.spinner.setBackgroundColor(QColor('black'))
        self.spinner_l = QLabel()
        self.spinner_l.setMargin(5)
        self.spinner_l.setVisible(False)
        self.spinner_l.setMovie(self.spinner)

        self.otp_status_l = QLabel()
        self.otp_status_l.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.otp_status_l.setVisible(False)

        self.resetlabel = WWLabel(_('If you have lost your OTP secret, click the button below to request a new secret from the server.'))
        self.button = QPushButton('Request OTP secret')
        self.button.clicked.connect(self.on_request_otp)

        hbox = QHBoxLayout()
        hbox.addWidget(self.authlabelnew)
        hbox.addWidget(self.authlabelexist)
        hbox.addStretch(1)
        hbox.addWidget(self.spinner_l)
        self.otp_e = AmountEdit(None, is_int=True)
        self.otp_e.setFocus()
        self.otp_e.setMaximumWidth(150)
        self.otp_e.textEdited.connect(self.on_otp_edited)
        hbox.addWidget(self.otp_e)

        self.layout().addWidget(self.new_otp)
        self.layout().addWidget(self.exist_otp)
        self.layout().addLayout(hbox)
        self.layout().addWidget(self.otp_status_l)
        self.layout().addWidget(self.resetlabel)
        self.layout().addWidget(self.button)
        self.layout().addStretch(1)

    def on_ready(self):
        self.wizard.trustedcoin_qhelper.busyChanged.connect(self.on_busy_changed)
        self.wizard.trustedcoin_qhelper.remoteKeyError.connect(self.on_remote_key_error)
        self.wizard.trustedcoin_qhelper.otpSuccess.connect(self.on_otp_success)
        self.wizard.trustedcoin_qhelper.otpError.connect(self.on_otp_error)
        self.wizard.trustedcoin_qhelper.remoteKeyError.connect(self.on_remote_key_error)

        self._is_online_continuation = 'seed' not in self.wizard_data
        if self._is_online_continuation:
            self.knownsecretlabel.setText(_('Authenticate below to finalize wallet creation'))

        self.wizard.trustedcoin_qhelper.createKeystore()

    def update(self):
        is_new = bool(self.wizard.trustedcoin_qhelper.remoteKeyState != 'wallet_known')
        self.new_otp.setVisible(is_new)
        self.exist_otp.setVisible(not is_new)
        self.authlabelnew.setVisible(is_new)
        self.authlabelexist.setVisible(not is_new)
        self.authlabelexist.setEnabled(not self._otp_verified)
        self.otp_e.setEnabled(not self._otp_verified)
        self.resetlabel.setVisible(not is_new and not self._otp_verified and not self._is_online_continuation)
        self.button.setVisible(not is_new and not self._otp_verified and not self._is_online_continuation)

        if self.wizard.trustedcoin_qhelper.otpSecret:
            self.secretlabel.setText(self.wizard.trustedcoin_qhelper.otpSecret)
            uri = 'otpauth://totp/Electrum 2FA %s?secret=%s&digits=6' % (
                os.path.basename(self.wizard_data['wallet_name']), self.wizard.trustedcoin_qhelper.otpSecret)
            self.qr.setData(uri)

    def on_busy_changed(self):
        if not self.wizard.trustedcoin_qhelper._verifyingOtp:
            self.busy = self.wizard.trustedcoin_qhelper.busy
            if not self.busy:
                self.update()

    def on_remote_key_error(self, text):
        self._logger.error(text)
        self.error = text

    def on_request_otp(self):
        self.otp_status_l.setVisible(False)
        self.wizard.trustedcoin_qhelper.resetOtpSecret()
        self.update()

    def on_otp_success(self):
        self._otp_verified = True
        self.otp_status_l.setText('Valid!')
        self.otp_status_l.setVisible(True)
        self.otp_status_l.setStyleSheet(ColorScheme.GREEN.as_stylesheet(False))
        self.setEnabled(True)
        self.spinner_l.setVisible(False)
        self.spinner.stop()

        self.valid = True

    def on_otp_error(self, message):
        self.otp_status_l.setText(message)
        self.otp_status_l.setVisible(True)
        self.otp_status_l.setStyleSheet(ColorScheme.RED.as_stylesheet(False))
        self.setEnabled(True)
        self.spinner_l.setVisible(False)
        self.spinner.stop()

    def on_otp_edited(self):
        self.otp_status_l.setVisible(False)
        text = self.otp_e.text()
        if len(text) > 0:
            try:
                otp_int = int(text)
            except ValueError:
                return
        if len(text) == 6:
            # verify otp
            self.wizard.trustedcoin_qhelper.checkOtp(self.wizard.trustedcoin_qhelper.shortId, otp_int)
            self.setEnabled(False)
            self.spinner_l.setVisible(True)
            self.spinner.start()
            self.otp_e.setText('')

    def apply(self):
        pass


class WCKeepDisable(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Restore 2FA wallet'))
        message = ' '.join([
            'You are going to restore a wallet protected with two-factor authentication.',
            'Do you want to keep using two-factor authentication with this wallet,',
            'or do you want to disable it, and have two master private keys in your wallet?'
        ])
        choices = [
            ('keep',    _('Keep')),
            ('disable', _('Disable')),
        ]

        self.choice_w = ChoiceWidget(message=message, choices=choices)
        self.layout().addWidget(self.choice_w)
        self.layout().addStretch(1)

        self._valid = True

    def apply(self):
        self.wizard_data['trustedcoin_keepordisable'] = self.choice_w.selected_key


class WCContinueOnline(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Continue Online'))

    def on_ready(self):
        path = os.path.join(os.path.dirname(self.wizard._daemon.config.get_wallet_path()), self.wizard_data['wallet_name'])
        msg = [
            _("Your wallet file is: {}.").format(path),
            _("You need to be online in order to complete the creation of "
              "your wallet. If you want to continue online, keep the checkbox "
              "checked and press Next."),
            _("If you want this system to stay offline "
              "and continue the completion of the wallet on an online system, "
              "uncheck the checkbox and press Finish.")
        ]

        self.layout().addWidget(WWLabel('\n\n'.join(msg)))
        self.layout().addStretch(1)

        self.cb_online = QCheckBox(_('Go online to complete wallet creation'))
        self.cb_online.setChecked(True)
        self.cb_online.stateChanged.connect(self.on_updated)
        # self.cb_online.setToolTip(_("Check this box to request a new secret. You will need to retype your seed."))
        self.layout().addWidget(self.cb_online)
        self.layout().setAlignment(self.cb_online, Qt.AlignmentFlag.AlignHCenter)
        self.layout().addStretch(1)

        self._valid = True

    def apply(self):
        self.wizard_data['trustedcoin_go_online'] = self.cb_online.isChecked()
