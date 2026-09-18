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
from typing import TYPE_CHECKING

import qrcode

from PyQt6.QtWidgets import QDialog

from electrum.i18n import _
from electrum.plugin import hook
from electrum.util import ChoiceItem
from electrum.wizard import WizardViewState

from electrum.gui.common_qt.util import QtEventListener, qt_event_listener
from electrum.gui.qt.util import (internal_plugin_icon_path, WWLabel, ColorScheme, ChoiceWidget,
                                  read_QIcon_from_bytes)
from electrum.gui.qt.qrcodewidget import QRCodeWidget, QRDialog
from electrum.gui.qt.main_window import StatusBarButton
from electrum.gui.qt.wizard.wallet import (WCHaveSeed, WCEnterExt, WalletWizardComponent, QEKeystoreWizard)

from .trustedcoin import TrustedCoinPlugin, DISCLAIMER, make_cosigner_qr_data, make_psbt_qr_data

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet
    from electrum.transaction import PartialTransaction
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard


class Plugin(TrustedCoinPlugin):

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet', window: 'ElectrumWindow'):
        if not isinstance(wallet, self.wallet_class):
            return
        if wallet.can_sign_without_cosigner():
            msg = ' '.join([
                _('This wallet was restored from seed, and it contains two master private keys.'),
                _('Therefore, two-factor authentication is disabled.')
            ])
            action = lambda: window.show_message(msg)
            icon = read_QIcon_from_bytes(self.read_file("trustedcoin-status-disabled.png"))
        else:
            action = partial(self.settings_dialog, window)
            icon = read_QIcon_from_bytes(self.read_file("trustedcoin-status.png"))
        sb = window.statusBar()
        button = StatusBarButton(icon, _("Two-factor authentication"), action, sb.height())
        sb.addPermanentWidget(button)

    @hook
    def show_incomplete_tx(self, window: 'ElectrumWindow', tx: 'PartialTransaction') -> bool:
        # after signing with the first key, show the transaction to the mobile cosigner
        if not isinstance(window.wallet, self.wallet_class):
            return False
        help_text = ' '.join([
            _('Scan this QR code with the Electrum app on your phone, in order to sign and broadcast the transaction.'),
            _('If your phone is not set up as cosigner yet, click on the two-factor authentication icon in the status bar.'),
        ])
        try:
            dialog = PsbtQRDialog(tx, wallet=window.wallet, parent=window, config=self.config, help_text=help_text)
        except qrcode.exceptions.DataOverflowError:
            window.show_error('\n'.join([
                _('This transaction is too large to fit in a QR code.'),
                _('Try to spend fewer coins at once.'),
            ]))
            return True
        dialog.exec()
        return True

    def settings_dialog(self, window: 'ElectrumWindow'):
        msg = '\n\n'.join([
            _('This wallet is protected by two-factor authentication.'),
            ' '.join([
                _('The TrustedCoin service has been discontinued: transactions are now co-signed by the Electrum app on your phone.'),
                _('After you sign a transaction, scan the QR code displayed by Electrum with your phone, in order to broadcast it.'),
            ]),
            _('Do you want to set up your phone as cosigner of this wallet? You will need your 2FA seed.'),
        ])
        if window.question(msg, title=_('Two-factor authentication')):
            self.setup_cosigner(window)

    def setup_cosigner(self, window: 'ElectrumWindow'):
        # for existing wallets: the second master private key is not in the wallet file
        wallet = window.wallet
        params = {'icon': self.icon_path('trustedcoin-wizard.png')}
        data = {
            'wallet_type': '2fa',
            'keystore_type': 'haveseed',
            'trustedcoin_wallet_xpubs': [wallet.keystores[k].get_master_public_key() for k in ['x1', 'x2']],
        }
        wizard = QEKeystoreWizard(
            config=self.config, app=window.gui_object.app, plugins=window.gui_object.plugins,
            start_viewstate=WizardViewState('trustedcoin_have_seed', data, params))
        wizard.window_title = _('Set up mobile cosigner')
        wizard.navmap_merge({
            'trustedcoin_have_seed': {
                'gui': WCHaveSeed,
                'params': params,
                'next': lambda d: 'trustedcoin_have_ext' if wizard.wants_ext(d) else 'trustedcoin_show_cosigner_qr',
            },
            'trustedcoin_have_ext': {
                'gui': WCEnterExt,
                'params': params,
                'next': 'trustedcoin_show_cosigner_qr',
            },
            'trustedcoin_show_cosigner_qr': {
                'gui': WCShowCosignerQR,
                'params': params,
                'last': True,
            },
        })
        if wizard.exec() == QDialog.DialogCode.Accepted:
            window.show_message(_('Your phone is now set up as cosigner of this wallet.'))

    def icon_path(self, name):
        return internal_plugin_icon_path(self.name, name)

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        params = {'icon': self.icon_path('trustedcoin-wizard.png')}
        views = {
            'trustedcoin_start': {
                'gui': WCDisclaimer,
                'params': params,
            },
            'trustedcoin_have_seed': {
                'gui': WCHaveSeed,
                'params': params,
            },
            'trustedcoin_have_ext': {
                'gui': WCEnterExt,
                'params': params,
            },
            'trustedcoin_keep_disable': {
                'gui': WCKeepDisable,
                'params': params,
            },
            'trustedcoin_show_cosigner_qr': {
                'gui': WCShowCosignerQR,
                'params': params,
            },
        }
        wizard.navmap_merge(views)


class PsbtQRDialog(QRDialog, QtEventListener):
    """Shows a transaction to the mobile cosigner, until the wallet sees it."""

    def __init__(self, tx: 'PartialTransaction', *, wallet: 'Abstract_Wallet', parent, config, help_text: str):
        QRDialog.__init__(self, data=make_psbt_qr_data(tx), parent=parent,
                          title=_('Partially signed transaction'), help_text=help_text, config=config)
        self.wallet = wallet
        self.prevouts = {txin.prevout.to_str() for txin in tx.inputs()}
        self.finished.connect(lambda: self.unregister_callbacks())
        self.register_callbacks()

    @qt_event_listener
    def on_event_adb_added_tx(self, adb, tx_hash, tx):
        if adb != self.wallet.adb:
            return
        # the cosigner broadcast the transaction, so there is no point in showing it anymore
        if any(txin.prevout.to_str() in self.prevouts for txin in tx.inputs()):
            self.accept()


class WCDisclaimer(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Disclaimer'))

        self.layout().addWidget(WWLabel('\n\n'.join(DISCLAIMER)))
        self.layout().addStretch(1)

        self._valid = True

    def apply(self):
        # the desktop wizard can only restore 2fa wallets from seed
        self.wizard_data['keystore_type'] = 'haveseed'


class WCKeepDisable(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Restore 2FA wallet'))
        message = ' '.join([
            _('You are going to restore a wallet protected with two-factor authentication.'),
            _('Do you want to keep using two-factor authentication with this wallet, with the Electrum app on your phone as cosigner,'),
            _('or do you want to disable it, and have two master private keys in your wallet?'),
        ])
        choices = [
            ChoiceItem(key='keep', label=_('Keep, with Electrum on my phone as cosigner')),
            ChoiceItem(key='disable', label=_('Disable')),
        ]
        self.choice_w = ChoiceWidget(message=message, choices=choices)
        self.layout().addWidget(self.choice_w)
        self.layout().addStretch(1)

        self._valid = True

    def apply(self):
        self.wizard_data['trustedcoin_keepordisable'] = self.choice_w.selected_key


class WCShowCosignerQR(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Mobile cosigner'))

        self.layout().addWidget(WWLabel(' '.join([
            _('On your phone, open Electrum and scan this QR code.'),
            _("If there is no wallet on your phone yet, use the 'Scan QR code' button of its wizard."),
        ])))
        self.qr = QRCodeWidget('')
        self.layout().addWidget(self.qr)
        warning_l = WWLabel(_('This QR code contains a private key of your wallet. Do not show it to anyone else.'))
        warning_l.setStyleSheet(ColorScheme.RED.as_stylesheet())
        self.layout().addWidget(warning_l)
        self.layout().addStretch(1)

        self._valid = True

    def on_ready(self):
        plugin = self.wizard.plugins.get_plugin('trustedcoin')
        xprv1, xpub1, xprv2, xpub2, xpub3 = plugin.create_keys(self.wizard_data)
        wallet_xpubs = self.wizard_data.get('trustedcoin_wallet_xpubs')
        if wallet_xpubs is not None and wallet_xpubs != [xpub1, xpub2]:
            self.error = _('This seed does not match this wallet.')
            self.valid = False
            return
        self.qr.setData(make_cosigner_qr_data(xprv2, xpub1, xpub3))

        # set higher minHeight so the qr code is shown without scrolling
        prev_height = self.wizard.height()
        prev_min_height = self.wizard.minimumHeight()
        def restore_prev_height():
            self.wizard.setMinimumHeight(prev_min_height)
            self.wizard.resize(self.wizard.width(), prev_height)
            self.wizard.next_button.clicked.disconnect(restore_prev_height)
            self.wizard.back_button.clicked.disconnect(restore_prev_height)
        self.wizard.setMinimumHeight(600)
        self.wizard.next_button.clicked.connect(restore_prev_height)
        self.wizard.back_button.clicked.connect(restore_prev_height)

    def apply(self):
        pass
