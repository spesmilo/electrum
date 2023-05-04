import os
import threading

from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex
from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import WalletFileException, standardize_path
from electrum.wallet import Abstract_Wallet
from electrum.plugin import run_hook
from electrum.lnchannel import ChannelState
from electrum.daemon import Daemon

from .auth import AuthMixin, auth_protect
from .qefx import QEFX
from .qewallet import QEWallet
from .qewalletdb import QEWalletDB
from .qewizard import QENewWalletWizard, QEServerConnectWizard

# wallet list model. supports both wallet basenames (wallet file basenames)
# and whole Wallet instances (loaded wallets)
class QEWalletListModel(QAbstractListModel):
    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES= ('name','path','active')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def __init__(self, daemon, parent=None):
        QAbstractListModel.__init__(self, parent)
        self.daemon = daemon
        self.reload()

    def rowCount(self, index):
        return len(self.wallets)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        (wallet_name, wallet_path) = self.wallets[index.row()]
        role_index = role - Qt.UserRole
        role_name = self._ROLE_NAMES[role_index]
        if role_name == 'name':
            return wallet_name
        if role_name == 'path':
            return wallet_path
        if role_name == 'active':
            return self.daemon.get_wallet(wallet_path) is not None

    @pyqtSlot()
    def reload(self):
        self._logger.debug('enumerating available wallets')
        self.beginResetModel()
        self.wallets = []
        self.endResetModel()

        available = []
        wallet_folder = os.path.dirname(self.daemon.config.get_wallet_path())
        with os.scandir(wallet_folder) as it:
            for i in it:
                if i.is_file() and not i.name.startswith('.'):
                    available.append(i.path)
        for path in sorted(available):
            wallet = self.daemon.get_wallet(path)
            self.add_wallet(wallet_path = path)

    def add_wallet(self, wallet_path):
        self.beginInsertRows(QModelIndex(), len(self.wallets), len(self.wallets))
        wallet_name = os.path.basename(wallet_path)
        wallet_path = standardize_path(wallet_path)
        item = (wallet_name, wallet_path)
        self.wallets.append(item)
        self.endInsertRows()

    def remove_wallet(self, path):
        i = 0
        wallets = []
        remove = -1
        for wallet_name, wallet_path in self.wallets:
            if wallet_path == path:
                remove = i
            else:
                wallets.append((wallet_name, wallet_path))
            i += 1

        if remove >= 0:
            self.beginRemoveRows(QModelIndex(), i, i)
            self.wallets = wallets
            self.endRemoveRows()

    @pyqtSlot(str, result=bool)
    def wallet_name_exists(self, name):
        for wallet_name, wallet_path in self.wallets:
            if name == wallet_name:
                return True
        return False

    @pyqtSlot(str)
    def updateWallet(self, path):
        i = 0
        for wallet_name, wallet_path in self.wallets:
            if wallet_path == path:
                mi = self.createIndex(i, i)
                self.dataChanged.emit(mi, mi, self._ROLE_KEYS)
                return
            i += 1

class QEDaemon(AuthMixin, QObject):
    _logger = get_logger(__name__)

    _available_wallets = None
    _current_wallet = None
    _new_wallet_wizard = None
    _server_connect_wizard = None
    _path = None
    _name = None
    _use_single_password = False
    _password = None
    _loading = False

    _backendWalletLoaded = pyqtSignal([str], arguments=['password'])

    availableWalletsChanged = pyqtSignal()
    fxChanged = pyqtSignal()
    newWalletWizardChanged = pyqtSignal()
    serverConnectWizardChanged = pyqtSignal()
    loadingChanged = pyqtSignal()
    requestNewPassword = pyqtSignal()

    walletLoaded = pyqtSignal([str,str], arguments=['name','path'])
    walletRequiresPassword = pyqtSignal([str,str], arguments=['name','path'])
    walletOpenError = pyqtSignal([str], arguments=["error"])
    walletDeleteError = pyqtSignal([str,str], arguments=['code', 'message'])

    def __init__(self, daemon: 'Daemon', parent=None):
        super().__init__(parent)
        self.daemon = daemon
        self.qefx = QEFX(daemon.fx, daemon.config)

        self._backendWalletLoaded.connect(self._on_backend_wallet_loaded)

        self._walletdb = QEWalletDB()
        self._walletdb.validPasswordChanged.connect(self.passwordValidityCheck)
        self._walletdb.walletOpenProblem.connect(self.onWalletOpenProblem)

    @pyqtSlot()
    def passwordValidityCheck(self):
        if not self._walletdb._validPassword:
            self.walletRequiresPassword.emit(self._name, self._path)

    @pyqtSlot(str)
    def onWalletOpenProblem(self, error):
        self.walletOpenError.emit(error)

    @pyqtSlot()
    @pyqtSlot(str)
    @pyqtSlot(str, str)
    def loadWallet(self, path=None, password=None):
        if path is None:
            self._path = self.daemon.config.get('wallet_path') # command line -w option
            if self._path is None:
                self._path = self.daemon.config.get('gui_last_wallet')
        else:
            self._path = path
        if self._path is None:
            return

        self._path = standardize_path(self._path)
        self._name = os.path.basename(self._path)

        self._logger.debug('load wallet ' + str(self._path))

        # map empty string password to None
        if password == '':
            password = None

        if not password:
            password = self._password

        wallet_already_open = self._path in self.daemon._wallets

        if not wallet_already_open:
            # pre-checks, let walletdb trigger any necessary user interactions
            self._walletdb.path = self._path
            self._walletdb.password = password
            self._walletdb.verify()
            if not self._walletdb.ready:
                return

        def load_wallet_task():
            self._loading = True
            self.loadingChanged.emit()

            try:
                local_password = password # need this in local scope
                wallet = self.daemon.load_wallet(self._path, local_password)

                if wallet is None:
                    self._logger.info('could not open wallet')
                    self.walletOpenError.emit('could not open wallet')
                    return

                if wallet_already_open:
                    # wallet already open. daemon.load_wallet doesn't mind, but
                    # we need the correct current wallet password below
                    local_password = QEWallet.getInstanceFor(wallet).password

                if self.daemon.config.get('single_password'):
                    self._use_single_password = self.daemon.update_password_for_directory(old_password=local_password, new_password=local_password)
                    self._password = local_password
                    self.singlePasswordChanged.emit()
                    self._logger.info(f'use single password: {self._use_single_password}')
                else:
                    self._logger.info('use single password disabled by config')

                self.daemon.config.save_last_wallet(wallet)

                run_hook('load_wallet', wallet)

                self._backendWalletLoaded.emit(local_password)
            except WalletFileException as e:
                self._logger.error(f"load_wallet_task errored opening wallet: {e!r}")
                self.walletOpenError.emit(str(e))
            finally:
                self._loading = False
                self.loadingChanged.emit()

        threading.Thread(target=load_wallet_task, daemon=True).start()

    @pyqtSlot()
    @pyqtSlot(str)
    def _on_backend_wallet_loaded(self, password = None):
        self._logger.debug('_on_backend_wallet_loaded')
        wallet = self.daemon._wallets[self._path]
        self._current_wallet = QEWallet.getInstanceFor(wallet)
        self.availableWallets.updateWallet(self._path)
        self._current_wallet.password = password if password else None
        self.walletLoaded.emit(self._name, self._path)


    @pyqtSlot(QEWallet)
    @pyqtSlot(QEWallet, bool)
    @pyqtSlot(QEWallet, bool, bool)
    def checkThenDeleteWallet(self, wallet, confirm_requests=False, confirm_balance=False):
        if wallet.wallet.lnworker:
            lnchannels = wallet.wallet.lnworker.get_channel_objects()
            if any([channel.get_state() != ChannelState.REDEEMED and not channel.is_backup() for channel in lnchannels.values()]):
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

    @auth_protect(method='wallet_password', message=_('Really delete this wallet?'))
    def delete_wallet(self, wallet, password=None):
        path = standardize_path(wallet.wallet.storage.path)
        self._logger.debug('deleting wallet with path %s' % path)
        self._current_wallet = None
        # TODO walletLoaded signal is confusing
        self.walletLoaded.emit(None, None)

        if not self.daemon.delete_wallet(path):
            self.walletDeleteError.emit('error', _('Problem deleting wallet'))
            return

        self.availableWallets.remove_wallet(path)

    @pyqtProperty(bool, notify=loadingChanged)
    def loading(self):
        return self._loading

    @pyqtProperty(QEWallet, notify=walletLoaded)
    def currentWallet(self):
        return self._current_wallet

    @pyqtProperty(QEWalletListModel, notify=availableWalletsChanged)
    def availableWallets(self):
        if not self._available_wallets:
            self._available_wallets = QEWalletListModel(self.daemon)

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
        # FIXME why not use util.get_new_wallet_name ?
        i = 1
        while self.availableWallets.wallet_name_exists(f'wallet_{i}'):
            i = i + 1
        return f'wallet_{i}'

    @pyqtSlot()
    def startChangePassword(self):
        if self._use_single_password:
            self._do_start_change_all_passwords()
        else:
            self.currentWallet.startChangePassword()

    @auth_protect(method='wallet_password')
    def _do_start_change_all_passwords(self, password=None):
        self.requestNewPassword.emit()

    @pyqtSlot(str, result=bool)
    def setPassword(self, password):
        assert self._use_single_password
        assert password
        if not self.daemon.update_password_for_directory(old_password=self._password, new_password=password):
            return False
        self._password = password
        return True

    @pyqtProperty(QENewWalletWizard, notify=newWalletWizardChanged)
    def newWalletWizard(self):
        if not self._new_wallet_wizard:
            self._new_wallet_wizard = QENewWalletWizard(self)

        return self._new_wallet_wizard

    @pyqtProperty(QEServerConnectWizard, notify=serverConnectWizardChanged)
    def serverConnectWizard(self):
        if not self._server_connect_wizard:
            self._server_connect_wizard = QEServerConnectWizard(self)

        return self._server_connect_wizard

    @pyqtSlot()
    def startNetwork(self):
        self.daemon.start_network()
