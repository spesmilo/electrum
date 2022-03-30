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
    _ROLE_NAMES=('key','type','timestamp','message','amount','status','address')
    _ROLE_KEYS = range(Qt.UserRole + 1, Qt.UserRole + 1 + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))

    def rowCount(self, index):
        return len(self.requests)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        request = self.requests[index.row()]
        role_index = role - (Qt.UserRole + 1)
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
        item = {}
        key = self.wallet.get_key_for_receive_request(req) # (verified) address for onchain, rhash for LN
        status = self.wallet.get_request_status(key)
        item['status'] = req.get_status_str(status)
        item['type'] = req.type # 0=onchain, 2=LN
        timestamp = req.time
        item['timestamp'] = format_time(timestamp)
        item['amount'] = req.get_amount_sat()
        item['message'] = req.message
        if req.type == 0: # OnchainInvoice
            item['key'] = item['address'] = req.get_address()
        elif req.type == 2: # LNInvoice
            #item['key'] = req.getrhash()
            pass

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
