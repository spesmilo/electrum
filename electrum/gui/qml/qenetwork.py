from typing import TYPE_CHECKING

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject

from electrum.logging import get_logger
from electrum import constants
from electrum.interface import ServerAddr
from electrum.simple_config import FEERATE_DEFAULT_RELAY

from .util import QtEventListener, event_listener
from .qeserverlistmodel import QEServerListModel

if TYPE_CHECKING:
    from .qeconfig import QEConfig
    from electrum.network import Network


class QENetwork(QObject, QtEventListener):
    _logger = get_logger(__name__)

    networkUpdated = pyqtSignal()
    blockchainUpdated = pyqtSignal()
    heightChanged = pyqtSignal([int], arguments=['height'])  # local blockchain height
    serverHeightChanged = pyqtSignal([int], arguments=['height'])
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
    _server = ""
    _is_connected = False
    _server_status = ""
    _network_status = ""
    _chaintips = 1
    _islagging = False
    _fee_histogram = []
    _gossipPeers = 0
    _gossipUnknownChannels = 0
    _gossipDbNodes = 0
    _gossipDbChannels = 0
    _gossipDbPolicies = 0

    def __init__(self, network: 'Network', qeconfig: 'QEConfig', parent=None):
        super().__init__(parent)
        assert network, "--offline is not yet implemented for this GUI"  # TODO
        self.network = network
        self._qeconfig = qeconfig
        self._serverListModel = None
        self._height = network.get_local_height()  # init here, update event can take a while
        self._server_height = network.get_server_height()  # init here, update event can take a while
        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

        self._qeconfig.useGossipChanged.connect(self.on_gossip_setting_changed)

    def on_destroy(self):
        self.unregister_callbacks()

    @event_listener
    def on_event_network_updated(self, *args):
        self.networkUpdated.emit()
        self._update_status()

    @event_listener
    def on_event_blockchain_updated(self):
        if self._height != self.network.get_local_height():
            self._height = self.network.get_local_height()
            self._logger.debug('new height: %d' % self._height)
            self.heightChanged.emit(self._height)
        self.blockchainUpdated.emit()

    @event_listener
    def on_event_default_server_changed(self, *args):
        self._update_status()

    @event_listener
    def on_event_proxy_set(self, *args):
        self._logger.debug('proxy set')
        self.proxySet.emit()
        self.proxyTorChanged.emit()

    def _update_status(self):
        server = str(self.network.get_parameters().server)
        if self._server != server:
            self._server = server
            self.statusChanged.emit()
        network_status = self.network.get_status()
        if self._network_status != network_status:
            self._logger.debug('network_status updated: %s' % network_status)
            self._network_status = network_status
            self.statusChanged.emit()
        is_connected = self.network.is_connected()
        if self._is_connected != is_connected:
            self._is_connected = is_connected
            self.statusChanged.emit()
        server_status = self.network.get_connection_status_for_GUI()
        if self._server_status != server_status:
            self._logger.debug('server_status updated: %s' % server_status)
            self._server_status = server_status
            self.statusChanged.emit()
        server_height = self.network.get_server_height()
        if self._server_height != server_height:
            self._logger.debug(f'server_height updated: {server_height}')
            self._server_height = server_height
            self.serverHeightChanged.emit(server_height)
        chains = len(self.network.get_blockchains())
        if chains != self._chaintips:
            self._logger.debug('chain tips # changed: %d', chains)
            self._chaintips = chains
            self.chaintipsChanged.emit()
        server_lag = self.network.get_local_height() - self.network.get_server_height()
        if self._islagging ^ (server_lag > 1):
            self._logger.debug('lagging changed: %s', str(server_lag > 1))
            self._islagging = server_lag > 1
            self.isLaggingChanged.emit()

    @event_listener
    def on_event_status(self, *args):
        self._update_status()

    @event_listener
    def on_event_fee_histogram(self, histogram):
        self._logger.debug(f'fee histogram updated')
        self.update_histogram(histogram)

    def update_histogram(self, histogram):
        if not histogram:
            histogram = [[FEERATE_DEFAULT_RELAY/1000,1]]
        # cap the histogram to a limited number of megabytes
        bytes_limit=10*1000*1000
        bytes_current = 0
        capped_histogram = []
        for item in sorted(histogram, key=lambda x: x[0], reverse=True):
            if bytes_current >= bytes_limit:
                break
            slot = min(item[1], bytes_limit-bytes_current)
            bytes_current += slot
            capped_histogram.append([
                max(FEERATE_DEFAULT_RELAY/1000, item[0]),  # clamped to [FEERATE_DEFAULT_RELAY/1000,inf[
                slot,  # width of bucket
                bytes_current,  # cumulative depth at far end of bucket
            ])

        # add clamping attributes for the GUI
        self._fee_histogram = {
            'histogram': capped_histogram,
            'total': bytes_current,
            'min_fee': capped_histogram[-1][0] if capped_histogram else FEERATE_DEFAULT_RELAY/1000,
            'max_fee': capped_histogram[0][0] if capped_histogram else FEERATE_DEFAULT_RELAY/1000
        }
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
    def height(self):  # local blockchain height
        return self._height

    @pyqtProperty(int, notify=serverHeightChanged)
    def server_height(self):
        return self._server_height

    @pyqtProperty(str, notify=statusChanged)
    def server(self):
        return self._server

    @server.setter
    def server(self, server: str):
        net_params = self.network.get_parameters()
        try:
            server = ServerAddr.from_str_with_inference(server)
            if not server: raise Exception("failed to parse")
        except Exception:
            return
        net_params = net_params._replace(server=server, auto_connect=self._qeconfig.autoConnect)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))

    @pyqtProperty(str, notify=statusChanged)
    def serverWithStatus(self):
        server = self._server
        if not self.network.is_connected():  # connecting or disconnected
            return f"{server} (connecting...)"
        return server

    @pyqtProperty(str, notify=statusChanged)
    def status(self):
        return self._network_status

    @pyqtProperty(str, notify=statusChanged)
    def server_status(self):
        return self.network.get_connection_status_for_GUI()

    @pyqtProperty(bool, notify=statusChanged)
    def is_connected(self):
        return self._is_connected

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

    proxyTorChanged = pyqtSignal()
    @pyqtProperty(bool, notify=proxyTorChanged)
    def isProxyTor(self):
        return self.network.tor_proxy

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

    serverListModelChanged = pyqtSignal()
    @pyqtProperty(QEServerListModel, notify=serverListModelChanged)
    def serverListModel(self):
        if self._serverListModel is None:
            self._serverListModel = QEServerListModel(self.network)
        return self._serverListModel
