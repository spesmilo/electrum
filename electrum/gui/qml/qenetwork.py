from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum import constants
from electrum.interface import ServerAddr

from .util import QtEventListener, event_listener

class QENetwork(QObject, QtEventListener):
    def __init__(self, network, qeconfig, parent=None):
        super().__init__(parent)
        self.network = network
        self._qeconfig = qeconfig
        self._height = network.get_local_height() # init here, update event can take a while
        self.register_callbacks()

        self._qeconfig.useGossipChanged.connect(self.on_gossip_setting_changed)


    _logger = get_logger(__name__)

    networkUpdated = pyqtSignal()
    blockchainUpdated = pyqtSignal()
    heightChanged = pyqtSignal([int], arguments=['height'])
    defaultServerChanged = pyqtSignal()
    proxySet = pyqtSignal()
    proxyChanged = pyqtSignal()
    statusChanged = pyqtSignal()
    feeHistogramUpdated = pyqtSignal()
    chaintipsChanged = pyqtSignal()
    isLaggingChanged = pyqtSignal()
    gossipUpdated = pyqtSignal()

    # shared signal for static properties
    dataChanged = pyqtSignal()

    _height = 0
    _status = ""
    _chaintips = 1
    _islagging = False
    _fee_histogram = []
    _gossipPeers = 0
    _gossipUnknownChannels = 0
    _gossipDbNodes = 0
    _gossipDbChannels = 0
    _gossipDbPolicies = 0

    @event_listener
    def on_event_network_updated(self, *args):
        self.networkUpdated.emit()

    @event_listener
    def on_event_blockchain_updated(self):
        if self._height != self.network.get_local_height():
            self._height = self.network.get_local_height()
            self._logger.debug('new height: %d' % self._height)
            self.heightChanged.emit(self._height)
        self.blockchainUpdated.emit()

    @event_listener
    def on_event_default_server_changed(self, *args):
        self.defaultServerChanged.emit()

    @event_listener
    def on_event_proxy_set(self, *args):
        self._logger.debug('proxy set')
        self.proxySet.emit()

    @event_listener
    def on_event_status(self, *args):
        self._logger.debug('status updated: %s' % self.network.connection_status)
        if self._status != self.network.connection_status:
            self._status = self.network.connection_status
            self.statusChanged.emit()
        chains = len(self.network.get_blockchains())
        if chains != self._chaintips:
            self._logger.debug('chain tips # changed: ' + chains)
            self._chaintips = chains
            self.chaintipsChanged.emit()
        server_lag = self.network.get_local_height() - self.network.get_server_height()
        if self._islagging ^ (server_lag > 1):
            self._logger.debug('lagging changed: ' + (server_lag > 1))
            self._islagging = server_lag > 1
            self.isLaggingChanged.emit()

    @event_listener
    def on_event_fee_histogram(self, histogram):
        self._logger.debug('fee histogram updated')
        self._fee_histogram = histogram if histogram else []
        self.feeHistogramUpdated.emit()

    @event_listener
    def on_event_channel_db(self, num_nodes, num_channels, num_policies):
        self._logger.debug(f'channel_db: {num_nodes} nodes, {num_channels} channels, {num_policies} policies')
        self._gossipDbNodes = num_nodes
        self._gossipDbChannels = num_channels
        self._gossipDbPolicies = num_policies
        self.gossipUpdated.emit()

    @event_listener
    def on_event_gossip_peers(self, num_peers):
        self._logger.debug(f'gossip peers {num_peers}')
        self._gossipPeers = num_peers
        self.gossipUpdated.emit()

    @event_listener
    def on_event_unknown_channels(self, unknown):
        if unknown == 0 and self._gossipUnknownChannels == 0: # TODO: backend sends a lot of unknown=0 events
            return
        self._logger.debug(f'unknown channels {unknown}')
        self._gossipUnknownChannels = unknown
        self.gossipUpdated.emit()
        #self.lightning_gossip_num_queries = unknown

    def on_gossip_setting_changed(self):
        if not self.network:
            return
        if self._qeconfig.useGossip:
            self.network.start_gossip()
        else:
            self.network.run_from_another_thread(self.network.stop_gossip())

    @pyqtProperty(int, notify=heightChanged)
    def height(self):
        return self._height

    @pyqtProperty(str, notify=defaultServerChanged)
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

    @pyqtProperty(str, notify=statusChanged)
    def status(self):
        return self._status

    @pyqtProperty(int, notify=chaintipsChanged)
    def chaintips(self):
        return self._chaintips

    @pyqtProperty(bool, notify=isLaggingChanged)
    def isLagging(self):
        return self._islagging

    @pyqtProperty(bool, notify=dataChanged)
    def isTestNet(self):
        return constants.net.TESTNET

    @pyqtProperty(str, notify=dataChanged)
    def networkName(self):
        return constants.net.__name__.replace('Bitcoin','')

    @pyqtProperty('QVariantMap', notify=proxyChanged)
    def proxy(self):
        net_params = self.network.get_parameters()
        return net_params.proxy if net_params.proxy else {}

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
        return self._fee_histogram

    @pyqtProperty('QVariantMap', notify=gossipUpdated)
    def gossipInfo(self):
        return {
            'peers': self._gossipPeers,
            'unknown_channels': self._gossipUnknownChannels,
            'db_nodes': self._gossipDbNodes,
            'db_channels': self._gossipDbChannels ,
            'db_policies': self._gossipDbPolicies
        }
