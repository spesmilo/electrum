from typing import TYPE_CHECKING

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.storage import WalletStorage
from electrum.wallet_db import WalletDB, WalletRequiresSplit
from electrum.wallet import Wallet
from electrum.util import InvalidPassword, WalletFileException, send_exception_to_crash_reporter

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig


class QEWalletDB(QObject):
    _logger = get_logger(__name__)

    fileNotFound = pyqtSignal()
    walletOpenProblem = pyqtSignal([str], arguments=['error'])
    pathChanged = pyqtSignal([bool], arguments=['ready'])
    needsPasswordChanged = pyqtSignal()
    needsHWDeviceChanged = pyqtSignal()
    passwordChanged = pyqtSignal()
    validPasswordChanged = pyqtSignal()
    readyChanged = pyqtSignal()
    invalidPassword = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

        from .qeapp import ElectrumQmlApplication
        self.daemon = ElectrumQmlApplication._daemon
        self._config = self.daemon.config  # type: SimpleConfig

        self.reset()

    def reset(self):
        self._path = None
        self._needsPassword = False
        self._needsHWDevice = False
        self._password = ''
        self._validPassword = True

        self._storage = None

        self._ready = False

    @pyqtProperty('QString', notify=pathChanged)
    def path(self):
        return self._path

    @path.setter
    def path(self, wallet_path):
        self._logger.debug('setting path: ' + wallet_path)
        self.reset()
        self._path = wallet_path

        self.pathChanged.emit(self._ready)

    @pyqtProperty(bool, notify=needsPasswordChanged)
    def needsPassword(self):
        return self._needsPassword

    @needsPassword.setter
    def needsPassword(self, wallet_needs_password):
        if wallet_needs_password == self._needsPassword:
            return

        self._needsPassword = wallet_needs_password
        self.needsPasswordChanged.emit()

    @pyqtProperty(bool, notify=needsHWDeviceChanged)
    def needsHWDevice(self):
        return self._needsHWDevice

    @needsHWDevice.setter
    def needsHWDevice(self, wallet_needs_hw_device):
        if wallet_needs_hw_device == self._needsHWDevice:
            return

        self._needsHWDevice = wallet_needs_hw_device
        self.needsHWDeviceChanged.emit()

    @pyqtProperty('QString', notify=passwordChanged)
    def password(self):
        return ''  # no read access

    @password.setter
    def password(self, wallet_password):
        if wallet_password == self._password:
            return

        self._password = wallet_password
        self.passwordChanged.emit()

    @pyqtProperty(bool, notify=validPasswordChanged)
    def validPassword(self):
        return self._validPassword

    @validPassword.setter
    def validPassword(self, validPassword):
        if self._validPassword != validPassword:
            self._validPassword = validPassword
            self.validPasswordChanged.emit()

    @pyqtProperty(bool, notify=readyChanged)
    def ready(self):
        return self._ready

    @pyqtSlot()
    def verify(self):
        try:
            self._load_storage()
            if self._storage:
                self._load_db()
        except WalletFileException as e:
            self._logger.error(f"verify errored: {repr(e)}")
            self._storage = None
            self.walletOpenProblem.emit(str(e))
            if e.should_report_crash:
                send_exception_to_crash_reporter(e)

    def _load_storage(self):
        """can raise WalletFileException"""
        self._storage = WalletStorage(self._path)
        if not self._storage.file_exists():
            self._logger.warning('file does not exist')
            self.fileNotFound.emit()
            self._storage = None
            return

        if self._storage.is_encrypted():
            self.needsPassword = True

            try:
                self._storage.decrypt('' if not self._password else self._password)
                self.validPassword = True
            except InvalidPassword as e:
                self.validPassword = False
                self.invalidPassword.emit()
        else:  # storage not encrypted; but it might still have a keystore pw
            # FIXME hack... load both db and full wallet, just to tell if it has keystore pw.
            try:
                db = WalletDB(self._storage.read(), storage=None, upgrade=True)
            except WalletRequiresSplit as e:
                raise WalletFileException(_('This wallet requires to be split. This is currently not supported on mobile'))
            wallet = Wallet(db, config=self._config)
            self.needsPassword = wallet.has_password()
            if self.needsPassword:
                try:
                    wallet.check_password('' if not self._password else self._password)
                    self.validPassword = True
                except InvalidPassword as e:
                    self.validPassword = False
                    self._storage = None
                    self.invalidPassword.emit()

        if self._storage:
            if not self._storage.is_past_initial_decryption():
                self._storage = None

    def _load_db(self):
        """can raise WalletFileException"""
        # needs storage accessible
        try:
            db = WalletDB(self._storage.read(), storage=None, upgrade=True)
        except WalletRequiresSplit as e:
            self._logger.warning('wallet requires split')
            raise WalletFileException(_('This wallet needs splitting. This is not supported on mobile'))
        if db.get_action():
            self._logger.warning('action pending. QML version doesn\'t support continuation of wizard')
            raise WalletFileException(_('This wallet has an action pending. This is currently not supported on mobile'))

        self._ready = True
        self.readyChanged.emit()
