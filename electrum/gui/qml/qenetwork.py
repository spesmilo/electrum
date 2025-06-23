from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtProperty, pyqtSignal, QObject, pyqtSlot

from electrum.logging import get_logger
from electrum import constants
from electrum.network import ProxySettings
from electrum.interface import ServerAddr
from electrum.fee_policy import FEERATE_DEFAULT_RELAY

from .util import QtEventListener, event_listener
from .qeconfig import QEConfig
from .qeserverlistmodel import QEServerListModel

if TYPE_CHECKING:
    from electrum.network import Network


class QENetwork(QObject, QtEventListener):
    _logger = get_logger(__name__)

    networkUpdated = pyqtSignal()
    blockchainUpdated = pyqtSignal()
    heightChanged = pyqtSignal([int], arguments=['height'])  # local blockchain height
    serverHeightChanged = pyqtSignal([int], arguments=['height'])
    proxySet = pyqtSignal()
    proxyChanged = pyqtSignal()
    torProbeFinished = pyqtSignal([str, int], arguments=['host', 'port'])
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

    def __init__(self, network: 'Network', parent=None):
        super().__init__(parent)
        assert network, "--offline is not yet implemented for this GUI"  # TODO
        self.network = network
        self._serverListModel = None
        self._height = network.get_local_height()  # init here, update event can take a while
        self._server_height = network.get_server_height()  # init here, update event can take a while
        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

        QEConfig.instance.useGossipChanged.connect(self.on_gossip_setting_changed)

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

    @event_listener
    def on_event_tor_probed(self, *args):
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
        capped_histogram, bytes_current = histogram.get_capped_data()
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
        changed = False
        if self._gossipDbNodes != num_nodes:
            self._gossipDbNodes = num_nodes
            changed = True
        if self._gossipDbChannels != num_channels:
            self._gossipDbChannels = num_channels
            changed = True
        if self._gossipDbPolicies != num_policies:
            self._gossipDbPolicies = num_policies
            changed = True
        if changed:
            self._logger.debug(f'channel_db: {num_nodes} nodes, {num_channels} channels, {num_policies} policies')
        self.gossipUpdated.emit()

    @event_listener
    def on_event_gossip_peers(self, num_peers):
        self._logger.debug(f'gossip peers {num_peers}')
        self._gossipPeers = num_peers
        self.gossipUpdated.emit()

    @event_listener
    def on_event_unknown_channels(self, unknown):
        if unknown == 0 and self._gossipUnknownChannels == 0:  # TODO: backend sends a lot of unknown=0 events
            return
        self._logger.debug(f'unknown channels {unknown}')
        self._gossipUnknownChannels = unknown
        self.gossipUpdated.emit()

    def on_gossip_setting_changed(self):
        if not self.network:
            return
        if QEConfig.instance.useGossip:
            self.network.start_gossip()
        else:
            self.network.run_from_another_thread(self.network.stop_gossip())

    @pyqtProperty(int, notify=heightChanged)
    def height(self):  # local blockchain height
        return self._height

    @pyqtProperty(int, notify=serverHeightChanged)
    def serverHeight(self):
        return self._server_height

    autoConnectChanged = pyqtSignal()
    @pyqtProperty(bool, notify=autoConnectChanged)
    def autoConnect(self):
        return self.network.config.NETWORK_AUTO_CONNECT

    # auto_connect is actually a tri-state, expose the undefined case
    @pyqtProperty(bool, notify=autoConnectChanged)
    def autoConnectDefined(self):
        return self.network.config.cv.NETWORK_AUTO_CONNECT.is_set()

    @pyqtProperty(str, notify=statusChanged)
    def server(self):
        return self._server

    @pyqtSlot(str, bool, bool)
    def setServerParameters(self, server: str, auto_connect: bool, one_server: bool):
        net_params = self.network.get_parameters()
        if server == net_params.server and auto_connect == net_params.auto_connect and one_server == net_params.oneserver:
            return
        if server != str(net_params.server):
            try:
                server = ServerAddr.from_str_with_inference(server)
                if not server:
                    raise Exception('failed to parse')
            except Exception:
                if not auto_connect:
                    return
                server = net_params.server
            self.statusChanged.emit()
        if auto_connect != net_params.auto_connect:
            self.network.config.NETWORK_AUTO_CONNECT = auto_connect
            self.autoConnectChanged.emit()
        net_params = net_params._replace(server=server, auto_connect=auto_connect, oneserver=one_server)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))

    @pyqtProperty(str, notify=statusChanged)
    def serverWithStatus(self):
        server = self._server
        if not self.network.is_connected():  # connecting or disconnected
            return f'{server} (connecting...)'
        return server

    @pyqtProperty(str, notify=statusChanged)
    def status(self):
        return self._network_status

    @pyqtProperty(str, notify=statusChanged)
    def serverStatus(self):
        return self.network.get_connection_status_for_GUI()

    @pyqtProperty(bool, notify=statusChanged)
    def isConnected(self):
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
        return constants.net.__name__.replace('Bitcoin', '')

    @pyqtProperty('QVariantMap', notify=proxyChanged)
    def proxy(self):
        net_params = self.network.get_parameters()
        proxy = net_params.proxy
        return proxy.to_dict()

    @proxy.setter
    def proxy(self, proxy_dict):
        net_params = self.network.get_parameters()
        proxy = ProxySettings.from_dict(proxy_dict)
        net_params = net_params._replace(proxy=proxy)
        self.network.run_from_another_thread(self.network.set_parameters(net_params))
        self.proxyChanged.emit()

    proxyTorChanged = pyqtSignal()
    @pyqtProperty(bool, notify=proxyTorChanged)
    def isProxyTor(self):
        return bool(self.network.is_proxy_tor)

    @pyqtProperty(bool, notify=statusChanged)
    def oneServer(self):
        return self.network.oneserver

    @pyqtProperty('QVariant', notify=feeHistogramUpdated)
    def feeHistogram(self):
        return self._fee_histogram

    @pyqtProperty('QVariantMap', notify=gossipUpdated)
    def gossipInfo(self):
        return {
            'peers': self._gossipPeers,
            'unknown_channels': self._gossipUnknownChannels,
            'db_nodes': self._gossipDbNodes,
            'db_channels': self._gossipDbChannels,
            'db_policies': self._gossipDbPolicies
        }

    serverListModelChanged = pyqtSignal()
    @pyqtProperty(QEServerListModel, notify=serverListModelChanged)
    def serverListModel(self):
        if self._serverListModel is None:
            self._serverListModel = QEServerListModel(self.network)
        return self._serverListModel

    @pyqtSlot()
    def probeTor(self):
        ProxySettings.probe_tor(self.torProbeFinished.emit)  # via signal
