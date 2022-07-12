import os
from decimal import Decimal

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.util import register_callback, get_new_wallet_name, WalletFileException, standardize_path
from electrum.logging import get_logger
from electrum.wallet import Wallet, Abstract_Wallet
from electrum.storage import WalletStorage, StorageReadWriteError
from electrum.wallet_db import WalletDB

from .qewallet import QEWallet
from .qewalletdb import QEWalletDB
from .qefx import QEFX
from .auth import AuthMixin, auth_protect

# wallet list model. supports both wallet basenames (wallet file basenames)
# and whole Wallet instances (loaded wallets)
class QEWalletListModel(QAbstractListModel):
    _logger = get_logger(__name__)
    def __init__(self, parent=None):
        QAbstractListModel.__init__(self, parent)
        self.wallets = []

    # define listmodel rolemap
    _ROLE_NAMES= ('name','path','active')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def rowCount(self, index):
        return len(self.wallets)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        (wallet_name, wallet_path, wallet) = self.wallets[index.row()]
        role_index = role - Qt.UserRole
        role_name = self._ROLE_NAMES[role_index]
        if role_name == 'name':
            return wallet_name
        if role_name == 'path':
            return wallet_path
        if role_name == 'active':
            return wallet != None

    def add_wallet(self, wallet_path = None, wallet: Abstract_Wallet = None):
        if wallet_path == None and wallet == None:
            return
        # only add wallet instance if instance not yet in model
        if wallet:
            for name,path,w in self.wallets:
                if w == wallet:
                    return
        self.beginInsertRows(QModelIndex(), len(self.wallets), len(self.wallets));
        if wallet == None:
            wallet_name = os.path.basename(wallet_path)
        else:
            wallet_name = wallet.basename()
        item = (wallet_name, wallet_path, wallet)
        self.wallets.append(item);
        self.endInsertRows();

class QEAvailableWalletListModel(QEWalletListModel):
    def __init__(self, daemon, parent=None):
        QEWalletListModel.__init__(self, parent)
        self.daemon = daemon
        self.reload()

    @pyqtSlot()
    def reload(self):
        if len(self.wallets) > 0:
            self.beginRemoveRows(QModelIndex(), 0, len(self.wallets) - 1)
            self.wallets = []
            self.endRemoveRows()

        available = []
        wallet_folder = os.path.dirname(self.daemon.config.get_wallet_path())
        with os.scandir(wallet_folder) as it:
            for i in it:
                if i.is_file() and not i.name.startswith('.'):
                    available.append(i.path)
        for path in sorted(available):
            wallet = self.daemon.get_wallet(path)
            self.add_wallet(wallet_path = path, wallet = wallet)

    def wallet_name_exists(self, name):
        for wallet_name, wallet_path, wallet in self.wallets:
            if name == wallet_name:
                return True
        return False

class QEDaemon(AuthMixin, QObject):
    def __init__(self, daemon, parent=None):
        super().__init__(parent)
        self.daemon = daemon
        self.qefx = QEFX(daemon.fx, daemon.config)
        self._walletdb = QEWalletDB()
        self._walletdb.validPasswordChanged.connect(self.passwordValidityCheck)

    _logger = get_logger(__name__)
    _loaded_wallets = QEWalletListModel()
    _available_wallets = None
    _current_wallet = None
    _path = None
    _use_single_password = False
    _password = None

    walletLoaded = pyqtSignal()
    walletRequiresPassword = pyqtSignal()
    activeWalletsChanged = pyqtSignal()
    availableWalletsChanged = pyqtSignal()
    walletOpenError = pyqtSignal([str], arguments=["error"])
    fxChanged = pyqtSignal()

    @pyqtSlot()
    def passwordValidityCheck(self):
        if not self._walletdb._validPassword:
            self.walletRequiresPassword.emit()

    @pyqtSlot()
    @pyqtSlot(str)
    @pyqtSlot(str, str)
    def load_wallet(self, path=None, password=None):
        if path == None:
            self._path = self.daemon.config.get('gui_last_wallet')
        else:
            self._path = path
        if self._path is None:
            return

        self._path = standardize_path(self._path)
        self._logger.debug('load wallet ' + str(self._path))

        if not password:
            password = self._password

        if self._path not in self.daemon._wallets:
            # pre-checks, let walletdb trigger any necessary user interactions
            self._walletdb.path = self._path
            self._walletdb.password = password
            self._walletdb.verify()
            if not self._walletdb.ready:
                return

        try:
            wallet = self.daemon.load_wallet(self._path, password)
            if wallet != None:
                self._loaded_wallets.add_wallet(wallet=wallet)
                self._current_wallet = QEWallet.getInstanceFor(wallet)
                self._current_wallet.password = password
                self.walletLoaded.emit()

                if self.daemon.config.get('single_password'):
                    self._use_single_password = self.daemon.update_password_for_directory(old_password=password, new_password=password)
                    self._password = password
                    self.singlePasswordChanged.emit()
                    self._logger.info(f'use single password: {self._use_single_password}')
                else:
                    self._logger.info('use single password disabled by config')

                self.daemon.config.save_last_wallet(wallet)
            else:
                self._logger.info('could not open wallet')
                self.walletOpenError.emit('could not open wallet')
        except WalletFileException as e:
            self._logger.error(str(e))
            self.walletOpenError.emit(str(e))

    @pyqtSlot(QEWallet)
    @auth_protect
    def delete_wallet(self, wallet):
        path = wallet.wallet.storage.path
        self._logger.debug('Ok to delete wallet with path %s' % path)
        # TODO checks, e.g. existing LN channels, unpaid requests, etc
        self._logger.debug('Not deleting yet, just unloading for now')
        # TODO actually delete
        # TODO walletLoaded signal is confusing
        self.daemon.stop_wallet(path)
        self._current_wallet = None
        self.walletLoaded.emit()

    @pyqtProperty('QString')
    def path(self):
        return self._path

    @pyqtProperty(QEWallet, notify=walletLoaded)
    def currentWallet(self):
        return self._current_wallet

    @pyqtProperty(QEWalletListModel, notify=activeWalletsChanged)
    def activeWallets(self):
        return self._loaded_wallets

    @pyqtProperty(QEAvailableWalletListModel, notify=availableWalletsChanged)
    def availableWallets(self):
        if not self._available_wallets:
            self._available_wallets = QEAvailableWalletListModel(self.daemon)

        return self._available_wallets

    @pyqtProperty(QEFX, notify=fxChanged)
    def fx(self):
        return self.qefx

    singlePasswordChanged = pyqtSignal()
    @pyqtProperty(bool, notify=singlePasswordChanged)
    def singlePasswordEnabled(self):
        return self._use_single_password

    @pyqtProperty(str, notify=singlePasswordChanged)
    def singlePassword(self):
        return self._password

    @pyqtSlot(result=str)
    def suggestWalletName(self):
        i = 1
        while self.availableWallets.wallet_name_exists(f'wallet_{i}'):
            i = i + 1
        return f'wallet_{i}'

    requestNewPassword = pyqtSignal()
    @pyqtSlot()
    @auth_protect
    def start_change_password(self):
        if self._use_single_password:
            self.requestNewPassword.emit()
        else:
            self.currentWallet.requestNewPassword.emit()

    @pyqtSlot(str)
    def set_password(self, password):
        assert self._use_single_password
        self._logger.debug('about to set password for ALL wallets')
        self.daemon.update_password_for_directory(old_password=self._password, new_password=password)
        self._password = password

