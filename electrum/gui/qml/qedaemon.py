import base64
import os
import threading
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QAbstractListModel, QModelIndex
from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import WalletFileException, standardize_path, InvalidPassword, send_exception_to_crash_reporter
from electrum.plugin import run_hook
from electrum.lnchannel import ChannelState
from electrum.bitcoin import is_address
from electrum.bitcoin import verify_usermessage_with_address
from electrum.storage import StorageReadWriteError

from .auth import AuthMixin, auth_protect
from .qefx import QEFX
from .qewallet import QEWallet
from .qewizard import QENewWalletWizard, QEServerConnectWizard

if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.plugin import Plugins


# wallet list model. supports both wallet basenames (wallet file basenames)
# and whole Wallet instances (loaded wallets)
from .util import check_password_strength


class QEWalletListModel(QAbstractListModel):
    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES= ('name', 'path', 'active')
    _ROLE_KEYS = range(Qt.ItemDataRole.UserRole, Qt.ItemDataRole.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def __init__(self, daemon, parent=None):
        QAbstractListModel.__init__(self, parent)
        self.daemon = daemon
        self._wallets = []
        self.reload()

    def rowCount(self, index):
        return len(self._wallets)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        (wallet_name, wallet_path) = self._wallets[index.row()]
        role_index = role - Qt.ItemDataRole.UserRole
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
        self._wallets = []
        self.endResetModel()

        available = []
        wallet_folder = os.path.dirname(self.daemon.config.get_wallet_path())
        with os.scandir(wallet_folder) as it:
            for i in it:
                if i.is_file() and not i.name.startswith('.'):
                    available.append(i.path)
        for path in sorted(available):
            wallet = self.daemon.get_wallet(path)
            self.add_wallet(wallet_path=path)

    def add_wallet(self, wallet_path):
        self.beginInsertRows(QModelIndex(), len(self._wallets), len(self._wallets))
        wallet_name = os.path.basename(wallet_path)
        wallet_path = standardize_path(wallet_path)
        item = (wallet_name, wallet_path)
        self._wallets.append(item)
        self.endInsertRows()

    def remove_wallet(self, path):
        i = 0
        wallets = []
        remove = -1
        for wallet_name, wallet_path in self._wallets:
            if wallet_path == path:
                remove = i
            else:
                wallets.append((wallet_name, wallet_path))
            i += 1

        if remove >= 0:
            self.beginRemoveRows(QModelIndex(), i, i)
            self._wallets = wallets
            self.endRemoveRows()

    @pyqtSlot(str, result=bool)
    def wallet_name_exists(self, name):
        for wallet_name, wallet_path in self._wallets:
            if name == wallet_name:
                return True
        return False

    @pyqtSlot(str)
    def updateWallet(self, path):
        i = 0
        for wallet_name, wallet_path in self._wallets:
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

    walletLoaded = pyqtSignal([str, str], arguments=['name', 'path'])
    walletRequiresPassword = pyqtSignal([str, str], arguments=['name', 'path'])
    walletOpenError = pyqtSignal([str], arguments=["error"])
    walletDeleteError = pyqtSignal([str, str], arguments=['code', 'message'])

    def __init__(self, daemon: 'Daemon', plugins: 'Plugins', parent=None):
        super().__init__(parent)
        self.daemon = daemon
        self.plugins = plugins
        self.qefx = QEFX(daemon.fx, daemon.config)

        self._backendWalletLoaded.connect(self._on_backend_wallet_loaded)

    @pyqtSlot()
    def passwordValidityCheck(self):
        if not self._walletdb._validPassword:
            self.walletRequiresPassword.emit(self._name, self._path)

    @pyqtSlot()
    @pyqtSlot(str)
    @pyqtSlot(str, str)
    def loadWallet(self, path=None, password=None):
        if self._loading:
            return
        self._loading = True

        if path is None:
            self._path = self.daemon.config.get('wallet_path')  # command line -w option
            if self._path is None:
                self._path = self.daemon.config.GUI_LAST_WALLET
        else:
            self._path = path
        if self._path is None:
            self._loading = False
            return

        self.loadingChanged.emit()

        self._path = standardize_path(self._path)
        self._name = os.path.basename(self._path)

        self._logger.debug('load wallet ' + str(self._path))

        # map empty string password to None
        if password == '':
            password = None

        if not password:
            password = self._password

        wallet_already_open = self.daemon.get_wallet(self._path)
        if wallet_already_open is not None:
            wallet_already_open_password = QEWallet.getInstanceFor(wallet_already_open).password

        def load_wallet_task():
            success = False
            try:
                local_password = password  # need this in local scope
                wallet = None
                try:
                    wallet = self.daemon.load_wallet(self._path, local_password, upgrade=True)
                except InvalidPassword:
                    self.walletRequiresPassword.emit(self._name, self._path)
                except FileNotFoundError:
                    self.walletOpenError.emit(_('File not found'))
                except StorageReadWriteError:
                    self.walletOpenError.emit(_('Could not read/write file'))
                except WalletFileException as e:
                    self.walletOpenError.emit(_('Could not open wallet: {}').format(str(e)))
                    if e.should_report_crash:
                        send_exception_to_crash_reporter(e)

                if wallet is None:
                    return

                if wallet_already_open is not None:
                    # wallet already open. daemon.load_wallet doesn't mind, but
                    # we need the correct current wallet password below
                    local_password = wallet_already_open_password

                if self.daemon.config.WALLET_USE_SINGLE_PASSWORD:
                    self._use_single_password = self.daemon.update_password_for_directory(old_password=local_password, new_password=local_password)
                    self._password = local_password
                    self.singlePasswordChanged.emit()
                    self._logger.info(f'use single password: {self._use_single_password}')
                else:
                    self._logger.info('use single password disabled by config')

                self.daemon.config.save_last_wallet(wallet)

                run_hook('load_wallet', wallet)

                success = True
                self._backendWalletLoaded.emit(local_password)
            finally:
                if not success:  # if successful, _loading guard will be reset by _on_backend_wallet_loaded
                    self._loading = False
                    self.loadingChanged.emit()

        threading.Thread(target=load_wallet_task, daemon=False).start()

    @pyqtSlot()
    @pyqtSlot(str)
    def _on_backend_wallet_loaded(self, password=None):
        self._logger.debug('_on_backend_wallet_loaded')
        wallet = self.daemon.get_wallet(self._path)
        assert wallet is not None
        self._current_wallet = QEWallet.getInstanceFor(wallet)
        self.availableWallets.updateWallet(self._path)
        self._current_wallet.password = password if password else None
        self._loading = False
        self.loadingChanged.emit()
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

    @auth_protect(message=_('Really delete this wallet?'))
    def delete_wallet(self, wallet):
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
    @auth_protect(method='wallet')
    def startChangePassword(self):
        if self._use_single_password:
            self.requestNewPassword.emit()
        else:
            self.currentWallet.requestNewPassword.emit()

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
            self._new_wallet_wizard = QENewWalletWizard(self, self.plugins)

        return self._new_wallet_wizard

    @pyqtProperty(QEServerConnectWizard, notify=serverConnectWizardChanged)
    def serverConnectWizard(self):
        if not self._server_connect_wizard:
            self._server_connect_wizard = QEServerConnectWizard(self)

        return self._server_connect_wizard

    @pyqtSlot()
    def startNetwork(self):
        self.daemon.start_network()

    @pyqtSlot(str, str, str, result=bool)
    def verifyMessage(self, address, message, signature):
        address = address.strip()
        message = message.strip().encode('utf-8')
        if not is_address(address):
            return False
        try:
            # This can throw on invalid base64
            sig = base64.b64decode(str(signature.strip()))
            verified = verify_usermessage_with_address(address, sig, message)
        except Exception as e:
            verified = False
        return verified

    @pyqtSlot(str, result=int)
    def passwordStrength(self, password):
        if len(password) == 0:
            return 0
        return check_password_strength(password)[0]
