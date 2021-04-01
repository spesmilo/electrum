from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QUrl
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.util import register_callback
from electrum.logging import get_logger
from electrum.wallet import Wallet, Abstract_Wallet

from .qewallet import QEWallet

class QENetwork(QObject):
    def __init__(self, network, parent=None):
        super().__init__(parent)
        self.network = network
        register_callback(self.on_network_updated, ['network_updated'])
        register_callback(self.on_blockchain_updated, ['blockchain_updated'])
        register_callback(self.on_default_server_changed, ['default_server_changed'])
        register_callback(self.on_proxy_set, ['proxy_set'])
        register_callback(self.on_status, ['status'])

    _logger = get_logger(__name__)

    network_updated = pyqtSignal()
    blockchain_updated = pyqtSignal()
    default_server_changed = pyqtSignal()
    proxy_set = pyqtSignal()
    status_updated = pyqtSignal()

    _num_updates = 0
    _server = ""
    _height = 0
    _status = ""

    def on_network_updated(self, event, *args):
        self._num_updates = self._num_updates + 1
        self.network_updated.emit()

    def on_blockchain_updated(self, event, *args):
        self._logger.info('chainupdate: ' + str(event) + str(args))
        self._height = self.network.get_local_height()
        self.blockchain_updated.emit()

    def on_default_server_changed(self, event, *args):
        netparams = self.network.get_parameters()
        self._server = str(netparams.server)
        self.default_server_changed.emit()

    def on_proxy_set(self, event, *args):
        self._logger.info('proxy set')
        self.proxy_set.emit()

    def on_status(self, event, *args):
        self._logger.info('status updated')
        self._status = self.network.connection_status
        self.status_updated.emit()

    @pyqtProperty(int,notify=network_updated)
    def updates(self):
        return self._num_updates

    @pyqtProperty(int,notify=blockchain_updated)
    def height(self):
        return self._height

    @pyqtProperty('QString',notify=default_server_changed)
    def server(self):
        return self._server

    @pyqtProperty('QString',notify=status_updated)
    def status(self):
        return self._status

class QEWalletListModel(QAbstractListModel):
    def __init__(self, parent=None):
        QAbstractListModel.__init__(self, parent)
        self.wallets = []

    def rowCount(self, index):
        return len(self.wallets)

    def data(self, index, role):
        if role == Qt.DisplayRole:
            return self.wallets[index.row()].basename()

    def add_wallet(self, wallet: Abstract_Wallet = None):
        if wallet == None:
            return
        self.beginInsertRows(QModelIndex(), len(self.wallets), len(self.wallets));
        self.wallets.append(wallet);
        self.endInsertRows();


class QEDaemon(QObject):
    def __init__(self, daemon, parent=None):
        super().__init__(parent)
        self.daemon = daemon

    _logger = get_logger(__name__)
    _wallet = ''
    _loaded_wallets = QEWalletListModel()

    wallet_loaded = pyqtSignal()

    @pyqtSlot()
    def load_wallet(self, path=None, password=None):
        self._logger.info(str(self.daemon.get_wallets()))
        if path == None:
            path = self.daemon.config.get('recently_open')[0]
        wallet = self.daemon.load_wallet(path, password)
        if wallet != None:
            self._loaded_wallets.add_wallet(wallet)
            self._wallet = wallet.basename()
            self._current_wallet = QEWallet(wallet)
            self.wallet_loaded.emit()
            self._logger.info(str(self.daemon.get_wallets()))
        else:
            self._logger.info('fail open wallet')

    @pyqtProperty('QString',notify=wallet_loaded)
    def walletName(self):
        return self._wallet

    @pyqtProperty(QEWalletListModel)
    def activeWallets(self):
        return self._loaded_wallets

    @pyqtProperty(QEWallet,notify=wallet_loaded)
    def currentWallet(self):
        return self._current_wallet
