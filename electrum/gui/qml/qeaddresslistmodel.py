from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis

class QEAddressListModel(QAbstractListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.receive_addresses = []
        self.change_addresses = []


    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('type','iaddr','address','label','balance','numtx', 'held')
    _ROLE_KEYS = range(Qt.UserRole + 1, Qt.UserRole + 1 + len(_ROLE_NAMES))
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
        role_index = role - (Qt.UserRole + 1)
        value = address[self._ROLE_NAMES[role_index]]
        if isinstance(value, bool) or isinstance(value, list) or isinstance(value, int) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.receive_addresses = []
        self.change_addresses = []
        self.endResetModel()

    # initial model data
    @pyqtSlot()
    def init_model(self):
        r_addresses = self.wallet.get_receiving_addresses()
        c_addresses = self.wallet.get_change_addresses()
        n_addresses = len(r_addresses) + len(c_addresses)

        def insert_row(atype, alist, address, iaddr):
            item = {}
            item['type'] = atype
            item['address'] = address
            item['numtx'] = self.wallet.get_address_history_len(address)
            item['label'] = self.wallet.get_label(address)
            c, u, x = self.wallet.get_addr_balance(address)
            item['balance'] = c + u + x
            item['held'] = self.wallet.is_frozen_address(address)
            alist.append(item)
            item['iaddr'] = iaddr

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, n_addresses - 1)
        i = 0
        for address in r_addresses:
            insert_row('receive', self.receive_addresses, address, i)
            i = i + 1
        i = 0
        for address in c_addresses:
            insert_row('change', self.change_addresses, address, i)
            i = i + 1
        self.endInsertRows()

