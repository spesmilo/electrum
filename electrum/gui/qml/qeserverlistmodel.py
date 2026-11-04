from typing import TYPE_CHECKING, List, Dict, Any

from PyQt6.QtCore import pyqtSlot
from PyQt6.QtCore import Qt, QAbstractListModel, QModelIndex, QSortFilterProxyModel

from electrum.logging import get_logger
from electrum.util import Satoshis

from electrum.gui.common_qt.util import QtEventListener, qt_event_listener

if TYPE_CHECKING:
    from electrum.network import Network


class QEServerListModel(QAbstractListModel, QtEventListener):
    """List of known servers, connected and disconnected.

    Rows are updated in place and keep their position in this model; the view should
    use QEServerListSortModel to get connected servers grouped by chain first and
    disconnected servers last.
    """
    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('name', 'address', 'is_connected', 'is_primary', 'is_tor', 'chain', 'height')
    _ROLE_KEYS = range(Qt.ItemDataRole.UserRole, Qt.ItemDataRole.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    def __init__(self, network: 'Network', parent=None):
        super().__init__(parent)

        self._servers = []  # type: List[Dict[str, Any]]

        self.network = network
        self.initModel()
        self.register_callbacks()
        self.destroyed.connect(lambda: self.unregister_callbacks())

    @qt_event_listener
    def on_event_network_updated(self):
        self._logger.debug(f'network updated')
        self.updateModel()

    @qt_event_listener
    def on_event_default_server_changed(self):
        self._logger.info(f'default server changed')
        self.updatePrimary()

    def rowCount(self, index):
        return len(self._servers)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        server = self._servers[index.row()]
        role_index = role - Qt.ItemDataRole.UserRole
        value = server[self._ROLE_NAMES[role_index]]

        if isinstance(value, (bool, list, int, str)) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self._servers = []
        self.endResetModel()

    def _is_primary(self, server: dict) -> bool:
        interface = self.network.interface
        if interface is None or not server['is_connected']:
            return False
        return server['name'] == str(interface.server)

    @pyqtSlot()
    def updatePrimary(self):
        role = self._ROLE_RMAP['is_primary']
        for row, server in enumerate(self._servers):
            is_primary = self._is_primary(server)
            if server['is_primary'] == is_primary:
                continue
            server['is_primary'] = is_primary
            idx = self.index(row, 0)
            self.dataChanged.emit(idx, idx, [role])

    def _build_servers(self) -> List[Dict[str, Any]]:
        """Collect the current server state from the network as a list of row dicts."""
        servers = []

        for chain_id, interfaces in self.network.get_blockchains().items():
            b = interfaces[0].blockchain

            name = b.get_name()

            self._logger.debug(f'chain {chain_id} has name={name}, max_forkpoint=@{b.get_max_forkpoint()}, '
                               f'height={b.height()}, interfaces={len(interfaces)}')

            for i in interfaces:
                server = {
                    'chain': name,
                    'is_primary': i == self.network.interface,
                    'is_connected': True,
                    'is_tor': i.server.host.endswith('.onion'),
                    'name': str(i.server),
                    'address': i.server.to_friendly_name(),
                    'height': i.tip,
                }

                servers.append(server)

        # disconnected servers
        for s in self.network.get_disconnected_server_addrs():
            server = {
                'chain': '',
                'height': 0,
                'is_primary': False,
                'is_connected': False,
                'is_tor': s.host.endswith('.onion'),
                'name': str(s),
                'address': s.to_friendly_name(),
            }

            servers.append(server)

        return servers

    @pyqtSlot()
    def updateModel(self):
        """Bring the model in sync with the network, updating rows in place.

        Existing rows keep their position: changed roles are signalled through
        dataChanged, vanished servers are removed and new servers are appended.
        """
        new_servers = self._build_servers()
        new_by_name = {}
        for server in new_servers:
            new_by_name.setdefault(server['name'], server)

        # remove rows for servers that are gone
        for row in reversed(range(len(self._servers))):
            if self._servers[row]['name'] in new_by_name:
                continue
            self.beginRemoveRows(QModelIndex(), row, row)
            del self._servers[row]
            self.endRemoveRows()

        # update rows for servers that are still there
        existing = {server['name']: row for row, server in enumerate(self._servers)}
        for name, row in existing.items():
            current = self._servers[row]
            new = new_by_name[name]
            changed_roles = [self._ROLE_RMAP[k] for k in self._ROLE_NAMES if current.get(k) != new.get(k)]
            if not changed_roles:
                continue
            current.update(new)
            idx = self.index(row, 0)
            self.dataChanged.emit(idx, idx, changed_roles)

        # append rows for new servers
        to_add = [server for name, server in new_by_name.items() if name not in existing]
        if to_add:
            first = len(self._servers)
            self.beginInsertRows(QModelIndex(), first, first + len(to_add) - 1)
            self._servers.extend(to_add)
            self.endInsertRows()

    @pyqtSlot()
    def initModel(self):
        self.clear()
        self.updateModel()


class QEServerListSortModel(QSortFilterProxyModel):
    """Presents QEServerListModel with connected servers first, grouped by chain,
    and disconnected servers last, so the view can use ListView.section on 'chain'.

    Within a group the source model order is kept (QSortFilterProxyModel sorts stable).
    """
    _logger = get_logger(__name__)

    def __init__(self, source: QEServerListModel, parent=None):
        super().__init__(parent)
        self.setSourceModel(source)
        self.setDynamicSortFilter(True)
        self.sort(0)

    def _sort_key(self, source_index: QModelIndex):
        server = self.sourceModel()._servers[source_index.row()]
        return not server['is_connected'], server['chain']

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        return self._sort_key(left) < self._sort_key(right)
