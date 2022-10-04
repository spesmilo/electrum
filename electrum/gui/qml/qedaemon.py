import os

from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex
from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import WalletFileException, standardize_path
from electrum.wallet import Abstract_Wallet
from electrum.plugin import run_hook
from electrum.lnchannel import ChannelState

from .auth import AuthMixin, auth_protect
from .qefx import QEFX
from .qewallet import QEWallet
from .qewalletdb import QEWalletDB

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
        wallet_path = standardize_path(wallet_path)
        item = (wallet_name, wallet_path, wallet)
        self.wallets.append(item);
        self.endInsertRows();

    def remove_wallet(self, path):
        i = 0
        wallets = []
        remove = -1
        for wallet_name, wallet_path, wallet in self.wallets:
            if wallet_path == path:
                remove = i
            else:
                self._logger.debug('HM, %s is not %s', wallet_path, path)
                wallets.append((wallet_name, wallet_path, wallet))
            i += 1

        if remove >= 0:
            self.beginRemoveRows(QModelIndex(), i, i)
            self.wallets = wallets
            self.endRemoveRows()

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
    walletDeleteError = pyqtSignal([str,str], arguments=['code', 'message'])

    @pyqtSlot()
    def passwordValidityCheck(self):
        if not self._walletdb._validPassword:
            self.walletRequiresPassword.emit()

    @pyqtSlot()
    @pyqtSlot(str)
    @pyqtSlot(str, str)
    def load_wallet(self, path=None, password=None):
        if path == None:
            self._path = self.daemon.config.get('wallet_path') # command line -w option
            if self._path is None:
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
                self._loaded_wallets.add_wallet(wallet_path=self._path, wallet=wallet)
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
                run_hook('load_wallet', wallet)
            else:
                self._logger.info('could not open wallet')
                self.walletOpenError.emit('could not open wallet')
        except WalletFileException as e:
            self._logger.error(str(e))
            self.walletOpenError.emit(str(e))

    @pyqtSlot(QEWallet)
    @pyqtSlot(QEWallet, bool)
    @pyqtSlot(QEWallet, bool, bool)
    def check_then_delete_wallet(self, wallet, confirm_requests=False, confirm_balance=False):
        if wallet.wallet.lnworker:
            lnchannels = wallet.wallet.lnworker.get_channel_objects()
            if any([channel.get_state() != ChannelState.REDEEMED for channel in lnchannels.values()]):
                self.walletDeleteError.emit('unclosed_channels', _('There are still channels that are not fully closed'))
                return

        num_requests = len(wallet.wallet.get_unpaid_requests())
        if num_requests > 0 and not confirm_requests:
            self.walletDeleteError.emit('unpaid_requests', _('There are still unpaid requests. Really delete?'))
            return

        c, u, x = wallet.wallet.get_balance()
        if c+u+x > 0 and not wallet.wallet.is_watching_only() and not confirm_balance:
            self.walletDeleteError.emit('balance', _('There are still coins present in this wallet. Really delete?'))
            return

        self.delete_wallet(wallet)

    @pyqtSlot(QEWallet)
    @auth_protect
    def delete_wallet(self, wallet):
        path = standardize_path(wallet.wallet.storage.path)
        self._logger.debug('deleting wallet with path %s' % path)
        self._current_wallet = None
        # TODO walletLoaded signal is confusing
        self.walletLoaded.emit()

        if not self.daemon.delete_wallet(path):
            self.walletDeleteError.emit('error', _('Problem deleting wallet'))
            return

        self.activeWallets.remove_wallet(path)
        self.availableWallets.remove_wallet(path)

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

