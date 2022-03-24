from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.util import register_callback
from electrum.logging import get_logger
from electrum import constants
from electrum.interface import ServerAddr

class QENetwork(QObject):
    def __init__(self, network, parent=None):
        super().__init__(parent)
        self.network = network
        register_callback(self.on_network_updated, ['network_updated'])
        register_callback(self.on_blockchain_updated, ['blockchain_updated'])
        register_callback(self.on_default_server_changed, ['default_server_changed'])
        register_callback(self.on_proxy_set, ['proxy_set'])
        register_callback(self.on_status, ['status'])
        register_callback(self.on_fee_histogram, ['fee_histogram'])

    _logger = get_logger(__name__)

    networkUpdated = pyqtSignal()
    blockchainUpdated = pyqtSignal()
    defaultServerChanged = pyqtSignal()
    proxySet = pyqtSignal()
    proxyChanged = pyqtSignal()
    statusChanged = pyqtSignal()
    feeHistogramUpdated = pyqtSignal()

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
        self._logger.debug('status updated: %s' % self.network.connection_status)
        self._status = self.network.connection_status
        self.statusChanged.emit()

    def on_fee_histogram(self, event, *args):
        self._logger.debug('fee histogram updated')
        self.feeHistogramUpdated.emit()

    @pyqtProperty(int,notify=networkUpdated)
    def updates(self):
        return self._num_updates

    @pyqtProperty(int,notify=blockchainUpdated)
    def height(self):
        return self._height

    @pyqtProperty('QString',notify=defaultServerChanged)
    def server(self):
        return self._server

    @server.setter
    def server(self, server):
        net_params = self.network.get_parameters()
        try:
            server = ServerAddr.from_str_with_inference(server)
            if not server: raise Exception("failed to parse")
        except Exception:
            return
        net_params = net_params._replace(server=server)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))

    @pyqtProperty('QString',notify=statusChanged)
    def status(self):
        return self._status

    @pyqtProperty(bool, notify=dataChanged)
    def isTestNet(self):
        return constants.net.TESTNET

    @pyqtProperty('QString', notify=dataChanged)
    def networkName(self):
        return constants.net.__name__.replace('Bitcoin','')

    @pyqtProperty('QVariantMap', notify=proxyChanged)
    def proxy(self):
        net_params = self.network.get_parameters()
        return net_params

    @proxy.setter
    def proxy(self, proxy_settings):
        net_params = self.network.get_parameters()
        if not proxy_settings['enabled']:
            proxy_settings = None
        net_params = net_params._replace(proxy=proxy_settings)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))
        self.proxyChanged.emit()

    @pyqtProperty('QVariant',notify=feeHistogramUpdated)
    def feeHistogram(self):
        return self.network.get_status_value('fee_histogram')

