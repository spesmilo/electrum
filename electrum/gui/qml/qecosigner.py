import threading
from typing import Optional, TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal, pyqtSlot, QModelIndex, QObject

from electrum.cosigner import (Cosigner, add_cosigner, check_cosigners_password, find_cosigner_for_tx,
                               find_cosigner_id_for_tx, get_cosigner_ids)
from electrum.i18n import _
from electrum.logging import get_logger
from electrum.network import Network, NetworkException, TxBroadcastError, BestEffortRequestFailed
from electrum.transaction import PartialTransaction, tx_from_any
from electrum.util import InvalidPassword

from .auth import AuthMixin, auth_protect
from .qedaemon import QEDaemon

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig


class QECosigner(AuthMixin, QObject):
    """Signs for the wallets of the 'keystores' file, which this device does not have."""

    _logger = get_logger(__name__)

    cosignerAdded = pyqtSignal()
    setupFailed = pyqtSignal([str], arguments=['message'])
    psbtLoaded = pyqtSignal(['QVariantMap'], arguments=['summary'])
    signFailed = pyqtSignal([str], arguments=['message'])
    signSuccess = pyqtSignal([str], arguments=['txid'])

    def __init__(self, config: 'SimpleConfig', parent=None):
        super().__init__(parent)
        self._config = config

    @pyqtSlot(str, result=bool)
    def isCosignerQr(self, data: str) -> bool:
        """Whether that QR code holds a key for this device to sign with."""
        try:
            Cosigner.from_qr_data(data)
        except ValueError:
            return False
        return True

    @pyqtSlot(str, result=bool)
    def canCosign(self, data: str) -> bool:
        """Whether that QR code holds a transaction this device signs for. The keys are
        indexed by the fingerprint they use in transactions, so this needs no password."""
        tx = self._parse_tx(data)
        return tx is not None and find_cosigner_id_for_tx(self._config, tx) is not None

    @pyqtSlot(result=bool)
    def canUseAppPassword(self) -> bool:
        """Whether the password of this device is known, and can encrypt the key."""
        qedaemon = QEDaemon.instance
        return bool(qedaemon.singlePasswordEnabled and qedaemon.singlePassword)

    @pyqtSlot(result=bool)
    def hasWallets(self) -> bool:
        return bool(QEDaemon.instance.availableWallets.rowCount(QModelIndex()))

    @pyqtSlot(result=bool)
    def hasCosigners(self) -> bool:
        """Whether this device already holds keys, which use the password of the app."""
        return bool(get_cosigner_ids(self._config))

    @pyqtSlot(str, result=bool)
    def verifyPassword(self, password: str) -> bool:
        """Whether that password is the one of this device. The gui authenticates against
        us when no wallet is open, as the keys of a cosigner can be here without any wallet.
        """
        if single_password := QEDaemon.instance.singlePassword:
            return password == single_password
        try:
            check_cosigners_password(self._config, password)
        except InvalidPassword:
            return False
        return True

    @pyqtSlot(str, str)
    def setupCosigner(self, data: str, password: str):
        """Stores the key displayed by the QR code of the other device."""
        qedaemon = QEDaemon.instance
        try:
            cosigner = Cosigner.from_qr_data(data)
        except ValueError as e:
            self._logger.info(f'invalid cosigner QR code: {e}')
            self.setupFailed.emit(_('This is not a cosigner QR code.'))
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
        elif not password:
            self.setupFailed.emit(_('A password is required.'))
            return
        else:
            # there is no wallet on this device. If it already holds keys, they use the
            # password of the app, and the user has to type that one: a second password
            # would leave the daemon unable to re-encrypt them all when it changes.
            try:
                check_cosigners_password(self._config, password)
            except InvalidPassword:
                self.setupFailed.emit(_('Invalid password'))
                return
        self._add_cosigner(cosigner, password)

    @auth_protect(method='wallet', message=_('Set up this device as cosigner?'))
    def _add_cosigner(self, cosigner: Cosigner, password: str) -> None:
        if not self.hasWallets():
            # there is no wallet on this device yet: this password becomes the password of the app
            QEDaemon.instance.setSinglePassword(password)
        add_cosigner(self._config, cosigner, password)
        self.cosignerAdded.emit()

    def _add_info_to_tx(self, tx: PartialTransaction, cosigner: Cosigner) -> None:
        """Completes the transaction with what the QR code could not carry, and checks
        what it claims. Raises if it cannot be verified."""
        if tx.is_missing_info_from_network():
            # QR codes do not contain the previous transactions
            Network.run_from_another_thread(tx.add_info_from_network(
                Network.get_instance(), ignore_network_issues=False, timeout=10))
        cosigner.add_wallet_info_to_tx(tx)

    @pyqtSlot(str, str)
    def loadPsbt(self, data: str, password: str):
        """Describes the transaction to be signed, for the confirmation dialog. The
        previous transactions are fetched from the network, so this does not run on the
        gui thread: the summary comes back with psbtLoaded, a failure with signFailed.
        """
        def load_task():
            try:
                summary = self._load_psbt(data, password)
            except Exception as e:
                # the gui waits for one of our signals before it lets the user go on
                self._logger.exception('could not read transaction')
                summary = {'error': repr(e)}
            if error := summary.get('error'):
                self.signFailed.emit(error)
            else:
                self.psbtLoaded.emit(summary)

        threading.Thread(target=load_task, daemon=True).start()

    def _load_psbt(self, data: str, password: str) -> dict:
        config = self._config
        tx = self._parse_tx(data)
        if tx is None:
            return {'error': _('This is not a transaction QR code.')}
        try:
            cosigner = find_cosigner_for_tx(config, tx, password or QEDaemon.instance.singlePassword)
        except InvalidPassword:
            return {'error': _('Invalid password')}
        if cosigner is None:
            return {'error': _('This transaction belongs to no wallet that this device signs for.')}
        try:
            self._add_info_to_tx(tx, cosigner)
        except NetworkException as e:
            self._logger.info(f'could not fetch previous transactions: {e}')
            return {'error': _('Could not fetch the previous transactions from the network.')}
        except Exception as e:
            self._logger.info(f'could not verify transaction: {e}')
            return {'error': _('This transaction could not be verified.')}
        outputs = []
        amount = 0
        claims_our_key = False
        high_index = False
        for txout in tx.outputs():
            is_change = cosigner.is_wallet_output(txout)
            if is_change:
                high_index = high_index or cosigner.is_high_derivation_index(txout)
            else:
                amount += txout.value
                claims_our_key = claims_our_key or cosigner.claims_our_key(txout)
            outputs.append({
                'address': txout.get_ui_address_str(),
                'value': config.format_amount_and_units(txout.value),
                'is_change': is_change,
            })
        warnings = []
        if claims_our_key:
            warnings.append(_('An output of this transaction falsely claims to belong to your wallet.'))
        if high_index:
            warnings.append(_('The change of this transaction is sent to an address that your wallet may never find.'))
        return {
            'outputs': outputs,
            'amount': config.format_amount_and_units(amount),
            'fee': config.format_amount_and_units(tx.get_fee()),
            'warning': '\n'.join(warnings),
        }

    @pyqtSlot(str, str)
    def signAndBroadcast(self, data: str, password: str):
        self._sign_and_broadcast(data, password)

    @auth_protect(method='wallet', message=_('Sign and broadcast this transaction?'))
    def _sign_and_broadcast(self, data: str, password: str) -> None:
        def sign_task():
            try:
                tx = self._parse_tx(data)
                cosigner = find_cosigner_for_tx(
                    self._config, tx, password or QEDaemon.instance.singlePassword)
                self._add_info_to_tx(tx, cosigner)
                cosigner.sign_transaction(tx)
            except InvalidPassword:
                self.signFailed.emit(_('Invalid password'))
                return
            except NetworkException as e:
                self._logger.info(f'could not fetch previous transactions: {e}')
                self.signFailed.emit(_('Could not fetch the previous transactions from the network.'))
                return
            except Exception as e:
                self._logger.exception('could not sign transaction')
                self.signFailed.emit(repr(e))
                return
            if not tx.is_complete():
                self.signFailed.emit(_('Could not sign transaction'))
                return
            self._broadcast(tx)

        threading.Thread(target=sign_task, daemon=True).start()

    def _parse_tx(self, data: str) -> Optional[PartialTransaction]:
        try:
            tx = tx_from_any(data)
        except Exception:
            return None
        return tx if isinstance(tx, PartialTransaction) else None

    def _broadcast(self, tx: PartialTransaction) -> None:
        network = Network.get_instance()
        if not network:
            self.signFailed.emit(_('You are offline.'))
            return
        try:
            Network.run_from_another_thread(network.broadcast_transaction(tx))
        except TxBroadcastError as e:
            self.signFailed.emit(e.get_message_for_gui())
        except BestEffortRequestFailed as e:
            self.signFailed.emit(repr(e))
        else:
            self.signSuccess.emit(tx.txid())
