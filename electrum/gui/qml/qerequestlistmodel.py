from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis, format_time
from electrum.invoices import Invoice

class QERequestListModel(QAbstractListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.requests = []

    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('key','type','timestamp','date','message','amount','status','status_str','address','expiration')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    def rowCount(self, index):
        return len(self.requests)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        request = self.requests[index.row()]
        role_index = role - Qt.UserRole
        value = request[self._ROLE_NAMES[role_index]]
        if isinstance(value, bool) or isinstance(value, list) or isinstance(value, int) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.requests = []
        self.endResetModel()

    def request_to_model(self, req: Invoice):
        item = self.wallet.export_request(req)
        item['key'] = self.wallet.get_key_for_receive_request(req)
        item['type'] = req.type # 0=onchain, 2=LN
        item['date'] = format_time(item['timestamp'])
        item['amount'] = req.get_amount_sat()

        return item

    @pyqtSlot()
    def init_model(self):
        requests = []
        for req in self.wallet.get_unpaid_requests():
            item = self.request_to_model(req)
            self._logger.debug(str(item))
            requests.append(item)

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, len(self.requests) - 1)
        self.requests = requests
        self.endInsertRows()

    def add_request(self, request: Invoice):
        item = self.request_to_model(request)
        self._logger.debug(str(item))

        self.beginInsertRows(QModelIndex(), 0, 0)
        self.requests.insert(0, item)
        self.endInsertRows()

    def delete_request(self, key: str):
        i = 0
        for request in self.requests:
            if request['key'] == key:
                self.beginRemoveRows(QModelIndex(), i, i)
                self.requests.pop(i)
                self.endRemoveRows()
                break
            i = i + 1

    @pyqtSlot(str, int)
    def updateRequest(self, key, status):
        self._logger.debug('updating request for %s to %d' % (key,status))
        i = 0
        for item in self.requests:
            if item['key'] == key:
                req = self.wallet.get_request(key)
                item['status'] = status
                item['status_str'] = req.get_status_str(status)
                index = self.index(i,0)
                self.dataChanged.emit(index, index, [self._ROLE_RMAP['status'], self._ROLE_RMAP['status_str']])
            i = i + 1
