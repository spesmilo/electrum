from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.util import register_callback
from electrum.logging import get_logger
from electrum import constants

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

    networkUpdated = pyqtSignal()
    blockchainUpdated = pyqtSignal()
    defaultServerChanged = pyqtSignal()
    proxySet = pyqtSignal()
    statusUpdated = pyqtSignal()

    dataChanged = pyqtSignal() # dummy to silence warnings

    _num_updates = 0
    _server = ""
    _height = 0
    _status = ""

    def on_network_updated(self, event, *args):
        self._num_updates = self._num_updates + 1
        self.networkUpdated.emit()

    def on_blockchain_updated(self, event, *args):
        self._logger.info('chainupdate: ' + str(event) + str(args))
        self._height = self.network.get_local_height()
        self.blockchainUpdated.emit()

    def on_default_server_changed(self, event, *args):
        netparams = self.network.get_parameters()
        self._server = str(netparams.server)
        self.defaultServerChanged.emit()

    def on_proxy_set(self, event, *args):
        self._logger.info('proxy set')
        self.proxySet.emit()

    def on_status(self, event, *args):
        self._logger.info('status updated')
        self._status = self.network.connection_status
        self.statusUpdated.emit()

    @pyqtProperty(int,notify=networkUpdated)
    def updates(self):
        return self._num_updates

    @pyqtProperty(int,notify=blockchainUpdated)
    def height(self):
        return self._height

    @pyqtProperty('QString',notify=defaultServerChanged)
    def server(self):
        return self._server

    @pyqtProperty('QString',notify=statusUpdated)
    def status(self):
        return self._status

    @pyqtProperty(bool, notify=dataChanged)
    def isTestNet(self):
        return constants.net.TESTNET

    @pyqtProperty('QString', notify=dataChanged)
    def networkName(self):
        return constants.net.__name__.replace('Bitcoin','')

