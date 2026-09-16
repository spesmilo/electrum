import threading
from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal, pyqtProperty, pyqtSlot, QModelIndex

from electrum.i18n import _
from electrum.network import Network, TxBroadcastError, BestEffortRequestFailed
from electrum.plugin import hook
from electrum.util import InvalidPassword

from electrum.gui.common_qt.plugins import PluginQObject
from electrum.gui.qml.qedaemon import QEDaemon

from .trustedcoin import (TrustedCoinPlugin, MOBILE_DISCLAIMER, add_cosigner, claims_wallet_key,
                          find_cosigner_for_tx, is_wallet_output, parse_cosigner_qr_data,
                          parse_psbt_qr_data, sign_tx)

if TYPE_CHECKING:
    from electrum.transaction import PartialTransaction
    from electrum.gui.qml import ElectrumQmlApplication
    from electrum.gui.qml.qewizard import QENewWalletWizard


class TrustedcoinPluginQObject(PluginQObject):
    cosignerAdded = pyqtSignal()
    setupFailed = pyqtSignal([str], arguments=['message'])
    signFailed = pyqtSignal([str], arguments=['message'])
    signSuccess = pyqtSignal([str], arguments=['txid'])

    @pyqtProperty(str)
    def loader(self):
        return 'main.qml'

    @pyqtProperty(str, constant=True)
    def disclaimer(self):
        return '\n\n'.join(MOBILE_DISCLAIMER)

    @pyqtSlot(str, result=bool)
    def isCosignerSetupQr(self, data: str) -> bool:
        try:
            parse_cosigner_qr_data(data)
        except ValueError:
            return False
        return True

    @pyqtSlot(str, result=bool)
    def isCosignerPsbt(self, data: str) -> bool:
        try:
            parse_psbt_qr_data(data)
        except ValueError:
            return False
        return True

    @pyqtSlot(result=bool)
    def canUseAppPassword(self) -> bool:
        """Whether the password of this device is known, and can encrypt the cosigner key."""
        qedaemon = QEDaemon.instance
        return bool(qedaemon.singlePasswordEnabled and qedaemon.singlePassword)

    @pyqtSlot(result=bool)
    def hasWallets(self) -> bool:
        return bool(QEDaemon.instance.availableWallets.rowCount(QModelIndex()))

    @pyqtSlot(str, str)
    def setupCosigner(self, data: str, password: str):
        """Stores the keys of the 2fa wallet displayed by the desktop wizard."""
        qedaemon = QEDaemon.instance
        try:
            xprv2, xpub1, xpub3 = parse_cosigner_qr_data(data)
        except ValueError as e:
            self.plugin.logger.info(f'invalid cosigner QR code: {e}')
            self.setupFailed.emit(_('This is not a 2FA cosigner QR code.'))
            return
        if self.canUseAppPassword():
            password = qedaemon.singlePassword
        elif self.hasWallets():
            self.setupFailed.emit(' '.join([
                _('Electrum needs the password of this device in order to encrypt the cosigner key.'),
                _('Please open one of your wallets first. If your wallets use different passwords, '
                  'change them so that they all use the same password.'),
            ]))
            return
        elif password:
            # there is no wallet on this device yet: this password becomes the password of the app
            qedaemon.setSinglePassword(password)
        else:
            self.setupFailed.emit(_('A password is required.'))
            return
        add_cosigner(self.plugin.config, xprv2=xprv2, xpub1=xpub1, xpub3=xpub3, password=password)
        self.cosignerAdded.emit()

    @pyqtSlot(str, str, result='QVariantMap')
    def loadPsbt(self, data: str, password: str) -> dict:
        """Describes the transaction to be cosigned, for the confirmation dialog."""
        config = self.plugin.config
        try:
            tx = parse_psbt_qr_data(data)
        except ValueError as e:
            self.plugin.logger.info(f'invalid transaction QR code: {e}')
            return {'error': _('This is not a 2FA transaction QR code.')}
        try:
            keys = find_cosigner_for_tx(config, tx, password or QEDaemon.instance.singlePassword)
        except InvalidPassword:
            return {'error': _('Invalid password')}
        if keys is None:
            return {'error': _('This transaction belongs to no wallet that this device cosigns for.')}
        outputs = []
        amount = 0
        warning = ''
        for txout in tx.outputs():
            is_change = is_wallet_output(keys, txout)
            if not is_change:
                amount += txout.value
                if claims_wallet_key(keys, txout):
                    warning = _('An output of this transaction falsely claims to belong to your wallet.')
            outputs.append({
                'address': txout.get_ui_address_str(),
                'value': config.format_amount_and_units(txout.value),
                'is_change': is_change,
            })
        fee = tx.get_fee()
        return {
            'outputs': outputs,
            'amount': config.format_amount_and_units(amount),
            'fee': config.format_amount_and_units(fee) if fee is not None else _('unknown'),
            'warning': warning,
        }

    @pyqtSlot(str, str)
    def signAndBroadcast(self, data: str, password: str):
        def sign_task():
            try:
                tx = parse_psbt_qr_data(data)
                keys = find_cosigner_for_tx(
                    self.plugin.config, tx, password or QEDaemon.instance.singlePassword)
                sign_tx(tx, keys)
            except InvalidPassword:
                self.signFailed.emit(_('Invalid password'))
                return
            except Exception as e:
                self.plugin.logger.exception('could not sign transaction')
                self.signFailed.emit(repr(e))
                return
            if not tx.is_complete():
                self.signFailed.emit(_('Could not sign transaction'))
                return
            self.plugin.broadcast(tx, on_success=self.signSuccess.emit, on_failure=self.signFailed.emit)

        threading.Thread(target=sign_task, daemon=True).start()


class Plugin(TrustedCoinPlugin):
    def __init__(self, *args):
        super().__init__(*args)
        self.so = None  # type: TrustedcoinPluginQObject

    @hook
    def init_qml(self, app: 'ElectrumQmlApplication'):
        self.logger.debug(f'init_qml hook called, gui={str(type(app))}')
        # important: TrustedcoinPluginQObject needs to be parented, as keeping a ref
        # in the plugin is not enough to avoid gc
        self.so = TrustedcoinPluginQObject(self, app)
        self.extend_wizard(QEDaemon.instance.newWalletWizard)

    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'trustedcoin_start': {
                'gui': '../../../../plugins/trustedcoin/qml/Disclaimer',
            },
            # on mobile, restoring from seed disables two-factor authentication
            'trustedcoin_have_seed': {
                'gui': 'WCHaveSeed',
                'next': lambda d: 'trustedcoin_have_ext' if wizard.wants_ext(d) else 'wallet_password',
                'accept': lambda d: None if wizard.wants_ext(d) else self.recovery_disable(d),
                'last': lambda d: wizard.is_single_password() and not wizard.wants_ext(d),
            },
            'trustedcoin_have_ext': {
                'gui': 'WCEnterExt',
                'next': 'wallet_password',
                'accept': self.recovery_disable,
                'last': lambda d: wizard.is_single_password(),
            },
        }
        wizard.navmap_merge(views)

    def broadcast(self, tx: 'PartialTransaction', *, on_success, on_failure):
        network = Network.get_instance()
        if not network:
            on_failure(_('You are offline.'))
            return
        try:
            Network.run_from_another_thread(network.broadcast_transaction(tx))
        except TxBroadcastError as e:
            on_failure(e.get_message_for_gui())
        except BestEffortRequestFailed as e:
            on_failure(repr(e))
        else:
            on_success(tx.txid())
