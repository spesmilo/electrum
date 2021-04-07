import os

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.util import register_callback, get_new_wallet_name
from electrum.logging import get_logger
from electrum.wallet import Wallet, Abstract_Wallet

from .qewallet import QEWallet

# wallet list model. supports both wallet basenames (wallet file basenames)
# and whole Wallet instances (loaded wallets)
class QEWalletListModel(QAbstractListModel):
    _logger = get_logger(__name__)
    def __init__(self, parent=None):
        QAbstractListModel.__init__(self, parent)
        self.wallets = []

    # define listmodel rolemap
    _ROLE_NAMES= ('name','path','active')
    _ROLE_KEYS = range(Qt.UserRole + 1, Qt.UserRole + 1 + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def rowCount(self, index):
        return len(self.wallets)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        (wallet_name, wallet_path, wallet) = self.wallets[index.row()]
        role_index = role - (Qt.UserRole + 1)
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
        self.beginInsertRows(QModelIndex(), len(self.wallets), len(self.wallets));
        if wallet == None:
            wallet_name = os.path.basename(wallet_path)
        else:
            wallet_name = wallet.basename()
        item = (wallet_name, wallet_path, wallet)
        self.wallets.append(item);
        self.endInsertRows();


class QEDaemon(QObject):
    def __init__(self, daemon, parent=None):
        super().__init__(parent)
        self.daemon = daemon

    _logger = get_logger(__name__)
    _loaded_wallets = QEWalletListModel()

    walletLoaded = pyqtSignal()
    walletRequiresPassword = pyqtSignal()

    _current_wallet = None

    @pyqtSlot()
    @pyqtSlot(str)
    @pyqtSlot(str, str)
    def load_wallet(self, path=None, password=None):
        self._logger.debug('load wallet ' + str(path))
        if path == None:
            path = self.daemon.config.get('gui_last_wallet')
        wallet = self.daemon.load_wallet(path, password)
        if wallet != None:
            self._loaded_wallets.add_wallet(wallet=wallet)
            self._current_wallet = QEWallet(wallet)
            self.walletLoaded.emit()
        else:
            self._logger.info('fail open wallet')
            self.walletRequiresPassword.emit()

    @pyqtProperty(QEWallet,notify=walletLoaded)
    def currentWallet(self):
        return self._current_wallet

    @pyqtProperty('QString',notify=walletLoaded)
    def walletName(self):
        if self._current_wallet != None:
            return self._current_wallet.wallet.basename()
        return ''

    @pyqtProperty(QEWalletListModel)
    def activeWallets(self):
        return self._loaded_wallets

    @pyqtProperty(QEWalletListModel)
    def availableWallets(self):
        available = []
        availableListModel = QEWalletListModel(self)
        wallet_folder = os.path.dirname(self.daemon.config.get_wallet_path())
        with os.scandir(wallet_folder) as it:
            for i in it:
                if i.is_file():
                    available.append(i.path)
        for path in sorted(available):
            wallet = self.daemon.get_wallet(path)
            availableListModel.add_wallet(wallet_path = path, wallet = wallet)
        return availableListModel
