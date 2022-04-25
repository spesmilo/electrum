from abc import abstractmethod

from PyQt5.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject
from PyQt5.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis, format_time
from electrum.invoices import Invoice

from .qetypes import QEAmount

class QEAbstractInvoiceListModel(QAbstractListModel):
    _logger = get_logger(__name__)

    def __init__(self, wallet, parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self.invoices = []

    # define listmodel rolemap
    _ROLE_NAMES=('key','type','timestamp','date','message','amount','status','status_str','address','expiration')
    _ROLE_KEYS = range(Qt.UserRole, Qt.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    def rowCount(self, index):
        return len(self.invoices)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        invoice = self.invoices[index.row()]
        role_index = role - Qt.UserRole
        value = invoice[self._ROLE_NAMES[role_index]]
        if isinstance(value, bool) or isinstance(value, list) or isinstance(value, int) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        if isinstance(value, QEAmount):
            return value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self.invoices = []
        self.endResetModel()

    @pyqtSlot()
    def init_model(self):
        invoices = []
        for invoice in self.get_invoice_list():
            item = self.invoice_to_model(invoice)
            self._logger.debug(str(item))
            invoices.append(item)

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, len(invoices) - 1)
        self.invoices = invoices
        self.endInsertRows()

    def add_invoice(self, invoice: Invoice):
        item = self.invoice_to_model(invoice)
        self._logger.debug(str(item))

        self.beginInsertRows(QModelIndex(), 0, 0)
        self.invoices.insert(0, item)
        self.endInsertRows()

    def delete_invoice(self, key: str):
        i = 0
        for invoice in self.invoices:
            if invoice['key'] == key:
                self.beginRemoveRows(QModelIndex(), i, i)
                self.invoices.pop(i)
                self.endRemoveRows()
                break
            i = i + 1

    @pyqtSlot(str, int)
    def updateInvoice(self, key, status):
        self._logger.debug('updating invoice for %s to %d' % (key,status))
        i = 0
        for item in self.invoices:
            if item['key'] == key:
                invoice = self.get_invoice_for_key(key)
                item['status'] = status
                item['status_str'] = invoice.get_status_str(status)
                index = self.index(i,0)
                self.dataChanged.emit(index, index, [self._ROLE_RMAP['status'], self._ROLE_RMAP['status_str']])
            i = i + 1

    @abstractmethod
    def get_invoice_for_key(self, key: str):
        raise Exception('provide impl')

    @abstractmethod
    def get_invoice_list(self):
        raise Exception('provide impl')

    @abstractmethod
    def invoice_to_model(self, invoice: Invoice):
        raise Exception('provide impl')

class QEInvoiceListModel(QEAbstractInvoiceListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(wallet, parent)

    _logger = get_logger(__name__)

    def get_invoice_list(self):
        return self.wallet.get_unpaid_invoices()

    def invoice_to_model(self, invoice: Invoice):
        item = self.wallet.export_invoice(invoice)
        item['type'] = invoice.type # 0=onchain, 2=LN
        item['date'] = format_time(item['timestamp'])
        item['amount'] = QEAmount(amount_sat=invoice.get_amount_sat())
        if invoice.type == 0:
            item['key'] = invoice.id
        elif invoice.type == 2:
            item['key'] = invoice.rhash

        return item

    def get_invoice_for_key(self, key: str):
        return self.wallet.get_invoice(key)

class QERequestListModel(QEAbstractInvoiceListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(wallet, parent)

    _logger = get_logger(__name__)

    def get_invoice_list(self):
        return self.wallet.get_unpaid_requests()

    def invoice_to_model(self, req: Invoice):
        item = self.wallet.export_request(req)
        item['key'] = self.wallet.get_key_for_receive_request(req)
        item['type'] = req.type # 0=onchain, 2=LN
        item['date'] = format_time(item['timestamp'])
        item['amount'] = QEAmount(amount_sat=req.get_amount_sat())

        return item

    def get_invoice_for_key(self, key: str):
        return self.wallet.get_request(key)

    @pyqtSlot(str, int)
    def updateRequest(self, key, status):
        self.updateInvoice(key, status)
