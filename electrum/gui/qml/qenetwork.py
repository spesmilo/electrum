from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum import constants
from electrum.interface import ServerAddr

from .util import QtEventListener, qt_event_listener

class QENetwork(QObject, QtEventListener):
    def __init__(self, network, parent=None):
        super().__init__(parent)
        self.network = network
        self.register_callbacks()

    _logger = get_logger(__name__)

    networkUpdated = pyqtSignal()
    blockchainUpdated = pyqtSignal()
    heightChanged = pyqtSignal([int], arguments=['height'])
    defaultServerChanged = pyqtSignal()
    proxySet = pyqtSignal()
    proxyChanged = pyqtSignal()
    statusChanged = pyqtSignal()
    feeHistogramUpdated = pyqtSignal()

    # shared signal for static properties
    dataChanged = pyqtSignal()

    _height = 0
    _status = ""

    @qt_event_listener
    def on_event_network_updated(self, *args):
        self.networkUpdated.emit()

    @qt_event_listener
    def on_event_blockchain_updated(self, *args):
        if self._height != self.network.get_local_height():
            self._height = self.network.get_local_height()
            self._logger.debug('new height: %d' % self._height)
            self.heightChanged.emit(self._height)
        self.blockchainUpdated.emit()

    @qt_event_listener
    def on_event_default_server_changed(self, *args):
        self.defaultServerChanged.emit()

    @qt_event_listener
    def on_event_proxy_set(self, *args):
        self._logger.debug('proxy set')
        self.proxySet.emit()

    @qt_event_listener
    def on_event_status(self, *args):
        self._logger.debug('status updated: %s' % self.network.connection_status)
        if self._status != self.network.connection_status:
            self._status = self.network.connection_status
            self.statusChanged.emit()

    @qt_event_listener
    def on_event_fee_histogram(self, *args):
        self._logger.debug('fee histogram updated')
        self.feeHistogramUpdated.emit()

    @pyqtProperty(int, notify=heightChanged)
    def height(self):
        return self._height

    @pyqtProperty('QString', notify=defaultServerChanged)
    def server(self):
        return str(self.network.get_parameters().server)

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

    @pyqtProperty('QString', notify=statusChanged)
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

    @pyqtProperty('QVariant', notify=feeHistogramUpdated)
    def feeHistogram(self):
        return self.network.get_status_value('fee_histogram')

