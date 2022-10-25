from typing import TYPE_CHECKING

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis

from .qetypes import QEAmount

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet


class QEAddressListModel(QAbstractListModel):
    def __init__(self, wallet: 'Abstract_Wallet', parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.setDirty()
        self.init_model()

    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('type','iaddr','address','label','balance','numtx', 'held')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def rowCount(self, index):
        return len(self.receive_addresses) + len(self.change_addresses)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        if index.row() > len(self.receive_addresses) - 1:
            address = self.change_addresses[index.row() - len(self.receive_addresses)]
        else:
            address = self.receive_addresses[index.row()]
        role_index = role - Qt.UserRole
        value = address[self._ROLE_NAMES[role_index]]
        if isinstance(value, (bool, list, int, str, QEAmount)) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.receive_addresses = []
        self.change_addresses = []
        self.endResetModel()

    def addr_to_model(self, address):
        item = {}
        item['address'] = address
        item['numtx'] = self.wallet.adb.get_address_history_len(address)
        item['label'] = self.wallet.get_label_for_address(address)
        c, u, x = self.wallet.get_addr_balance(address)
        item['balance'] = QEAmount(amount_sat=c + u + x)
        item['held'] = self.wallet.is_frozen_address(address)
        return item

    @pyqtSlot()
    def setDirty(self):
        self._dirty = True

    # initial model data
    @pyqtSlot()
    def init_model(self):
        if not self._dirty:
            return

        r_addresses = self.wallet.get_receiving_addresses()
        c_addresses = self.wallet.get_change_addresses()
        n_addresses = len(r_addresses) + len(c_addresses) if self.wallet.use_change else 0

        def insert_row(atype, alist, address, iaddr):
            item = self.addr_to_model(address)
            item['type'] = atype
            item['iaddr'] = iaddr
            alist.append(item)

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, n_addresses - 1)
        i = 0
        for address in r_addresses:
            insert_row('receive', self.receive_addresses, address, i)
            i = i + 1
        i = 0
        for address in c_addresses if self.wallet.use_change else []:
            insert_row('change', self.change_addresses, address, i)
            i = i + 1
        self.endInsertRows()

        self._dirty = False

    @pyqtSlot(str)
    def update_address(self, address):
        i = 0
        for a in self.receive_addresses:
            if a['address'] == address:
                self.do_update(i,a)
                return
            i = i + 1
        for a in self.change_addresses:
            if a['address'] == address:
                self.do_update(i,a)
                return
            i = i + 1

    def do_update(self, modelindex, modelitem):
        mi = self.createIndex(modelindex, 0)
        self._logger.debug(repr(modelitem))
        modelitem.update(self.addr_to_model(modelitem['address']))
        self._logger.debug(repr(modelitem))
        self.dataChanged.emit(mi, mi, self._ROLE_KEYS)
