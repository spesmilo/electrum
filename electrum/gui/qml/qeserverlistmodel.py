from abc import abstractmethod

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import Satoshis, format_time
from electrum.interface import ServerAddr, PREFERRED_NETWORK_PROTOCOL
from electrum import blockchain

from .util import QtEventListener, qt_event_listener, event_listener

class QEServerListModel(QAbstractListModel, QtEventListener):
    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('name', 'address', 'is_connected', 'is_primary', 'is_tor', 'chain', 'height')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    def __init__(self, network, parent=None):
        super().__init__(parent)

        self._chaintips = 0

        self.network = network
        self.init_model()
        self.register_callbacks()
        self.destroyed.connect(lambda: self.unregister_callbacks())

    @qt_event_listener
    def on_event_network_updated(self):
        self._logger.info(f'network updated')
        self.init_model()

    @qt_event_listener
    def on_event_blockchain_updated(self):
        self._logger.info(f'blockchain updated')
        self.init_model()

    @qt_event_listener
    def on_event_default_server_changed(self):
        self._logger.info(f'default server changed')
        self.init_model()

    def rowCount(self, index):
        return len(self.servers)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        server = self.servers[index.row()]
        role_index = role - Qt.UserRole
        value = server[self._ROLE_NAMES[role_index]]

        if isinstance(value, (bool, list, int, str)) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.servers = []
        self.endResetModel()

    chaintipsChanged = pyqtSignal()
    @pyqtProperty(int, notify=chaintipsChanged)
    def chaintips(self):
        return self._chaintips

    def get_chains(self):
        chains = self.network.get_blockchains()
        n_chains = len(chains)
        if n_chains != self._chaintips:
            self._chaintips = n_chains
            self.chaintipsChanged.emit()
        return chains

    @pyqtSlot()
    def init_model(self):
        self.clear()

        servers = []

        chains = self.get_chains()

        for chain_id, interfaces in chains.items():
            self._logger.debug(f'chain {chain_id} has {len(interfaces)} interfaces')
            b = blockchain.blockchains.get(chain_id)
            if b is None:
                continue

            name = b.get_name()

            self._logger.debug(f'chain {chain_id} has name={name}, max_forkpoint=@{b.get_max_forkpoint()}, height={b.height()}')

            for i in interfaces:
                server = {}
                server['chain'] = name
                server['chain_height'] = b.height()
                server['is_primary'] = i == self.network.interface
                server['is_connected'] = True
                server['name'] = str(i.server)
                server['address'] = i.server.to_friendly_name()
                server['height'] = i.tip

                #self._logger.debug(f'adding server: {repr(server)}')
                servers.append(server)

        # disconnected servers
        all_servers = self.network.get_servers()
        connected_hosts = set([iface.host for ifaces in chains.values() for iface in ifaces])
        protocol = PREFERRED_NETWORK_PROTOCOL
        for _host, d in sorted(all_servers.items()):
            if _host in connected_hosts:
                continue
            if _host.endswith('.onion') and not self.network.tor_proxy:
                continue
            port = d.get(protocol)
            if port:
                s = ServerAddr(_host, port, protocol=protocol)
                server = {}
                server['chain'] = ''
                server['chain_height'] = 0
                server['height'] = 0
                server['is_primary'] = False
                server['is_connected'] = False
                server['name'] = s.net_addr_str()
                server['address'] = server['name']

                # self._logger.debug(f'adding server: {repr(server)}')
                servers.append(server)

        self.beginInsertRows(QModelIndex(), 0, len(servers) - 1)
        self.servers = servers
        self.endInsertRows()
