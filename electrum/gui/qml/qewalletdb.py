import os

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import Logger, get_logger
from electrum.storage import WalletStorage, StorageEncryptionVersion
from electrum.wallet_db import WalletDB
from electrum.util import InvalidPassword
from electrum import keystore

from .qedaemon import QEDaemon

class QEWalletDB(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)

        from .qeapp import ElectrumQmlApplication
        self.daemon = ElectrumQmlApplication._daemon

        self.reset()

    _logger = get_logger(__name__)

    fileNotFound = pyqtSignal()
    pathChanged = pyqtSignal([bool], arguments=["ready"])
    needsPasswordChanged = pyqtSignal()
    needsHWDeviceChanged = pyqtSignal()
    passwordChanged = pyqtSignal()
    invalidPasswordChanged = pyqtSignal()
    requiresSplitChanged = pyqtSignal()
    requiresUpgradeChanged = pyqtSignal()
    upgradingChanged = pyqtSignal()
    splitFinished = pyqtSignal()
    readyChanged = pyqtSignal()
    createError = pyqtSignal([str], arguments=["error"])
    createSuccess = pyqtSignal()

    def reset(self):
        self._path = None
        self._needsPassword = False
        self._needsHWDevice = False
        self._password = ''
        self._requiresSplit = False
        self._requiresUpgrade = False
        self._upgrading = False
        self._invalidPassword = False

        self._storage = None
        self._db = None

        self._ready = False

    @pyqtProperty('QString', notify=pathChanged)
    def path(self):
        return self._path

    @path.setter
    def path(self, wallet_path):
        if wallet_path == self._path:
            return

        self.reset()
        self._logger.warning('path: ' + wallet_path)
        self._path = wallet_path

        self.load_storage()
        if self._storage:
            self.load_db()

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
        return '' # no read access

    @password.setter
    def password(self, wallet_password):
        if wallet_password == self._password:
            return

        self._password = wallet_password
        self.passwordChanged.emit()

        self.load_storage()

        if self._storage:
            self.needsPassword = False
            self.load_db()

    @pyqtProperty(bool, notify=requiresSplitChanged)
    def requiresSplit(self):
        return self._requiresSplit

    @pyqtProperty(bool, notify=requiresUpgradeChanged)
    def requiresUpgrade(self):
        return self._requiresUpgrade

    @pyqtProperty(bool, notify=upgradingChanged)
    def upgrading(self):
        return self._upgrading

    @pyqtProperty(bool, notify=invalidPasswordChanged)
    def invalidPassword(self):
        return self._invalidPassword

    @pyqtProperty(bool, notify=readyChanged)
    def ready(self):
        return self._ready


    @pyqtSlot()
    def doSplit(self):
        self._logger.warning('doSplit')
        if not self._requiresSplit:
            return

        self._db.split_accounts(self._path)

        self.splitFinished.emit()

    @pyqtSlot()
    def doUpgrade(self):
        self._logger.warning('doUpgrade')
        if not self._requiresUpgrade:
            return

        self._logger.warning('upgrading')

        self._upgrading = True
        self.upgradingChanged.emit()

        self._db.upgrade()
        self._db.write(self._storage)

        self._upgrading = False
        self.upgradingChanged.emit()

    def load_storage(self):
        self._storage = WalletStorage(self._path)
        if not self._storage.file_exists():
            self._logger.warning('file does not exist')
            self.fileNotFound.emit()
            self._storage = None
            return

        if self._storage.is_encrypted():
            self.needsPassword = True

            try:
                self._storage.decrypt(self._password)
                self._invalidPassword = False
            except InvalidPassword as e:
                self._invalidPassword = True
            self.invalidPasswordChanged.emit()

        if not self._storage.is_past_initial_decryption():
            self._storage = None

    def load_db(self):
        # needs storage accessible
        self._db = WalletDB(self._storage.read(), manual_upgrades=True)
        if self._db.requires_split():
            self._logger.warning('wallet requires split')
            self._requiresSplit = True
            self.requiresSplitChanged.emit()
            return
        if self._db.requires_upgrade():
            self._logger.warning('requires upgrade')
            self._requiresUpgrade = True
            self.requiresUpgradeChanged.emit()
            return
        if self._db.get_action():
            self._logger.warning('action pending. QML version doesn\'t support continuation of wizard')
            return

        self._ready = True
        self.readyChanged.emit()

        self.daemon.load_wallet(self._path, self._password)

        #wallet = Wallet(db, storage, config=self.config)
        #wallet.start_network(self.network)
        #self._wallets[path] = wallet
        #return wallet

    @pyqtSlot('QJSValue')
    def create_storage(self, js_data):
        self._logger.info('Creating wallet from wizard data')
        data = js_data.toVariant()
        self._logger.debug(str(data))

        try:
            path = os.path.join(os.path.dirname(self.daemon.config.get_wallet_path()), data['wallet_name'])
            if os.path.exists(path):
                raise Exception('file already exists at path')
            storage = WalletStorage(path)

            k = keystore.from_seed(data['seed'], data['seed_extra_words'], data['wallet_type'] == 'multisig')

            if data['encrypt']:
                storage.set_password(data['password'], enc_version=StorageEncryptionVersion.USER_PASSWORD)

            db = WalletDB('', manual_upgrades=False)
            db.set_keystore_encryption(bool(data['password']) and data['encrypt'])

            db.put('wallet_type', data['wallet_type'])
            db.put('seed_type', data['seed_type'])
            db.put('keystore', k.dump())
            if k.can_have_deterministic_lightning_xprv():
                db.put('lightning_xprv', k.get_lightning_xprv(None))

            db.load_plugins()
            db.write(storage)

            self.createSuccess.emit()
        except Exception as e:
            self._logger.error(str(e))
            self.createError.emit(str(e))


