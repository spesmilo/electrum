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
        self.init_model()

    # define listmodel rolemap
    _ROLE_NAMES=('key', 'is_lightning', 'timestamp', 'date', 'message', 'amount',
                 'status', 'status_str', 'address', 'expiration', 'type', 'onchain_fallback',
                 'lightning_invoice')
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

        if isinstance(value, (bool, list, int, str, QEAmount)) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
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
            #self._logger.debug(str(item))
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

    def get_model_invoice(self, key: str):
        for invoice in self.invoices:
            if invoice['key'] == key:
                return invoice
        return None

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
                return
            i = i + 1

    def invoice_to_model(self, invoice: Invoice):
        item = self.get_invoice_as_dict(invoice)
        #item['key'] = invoice.get_id()
        item['is_lightning'] = invoice.is_lightning()
        if invoice.is_lightning() and 'address' not in item:
            item['address'] = ''
        item['date'] = format_time(item['timestamp'])
        item['amount'] = QEAmount(from_invoice=invoice)
        item['onchain_fallback'] = invoice.is_lightning() and invoice._lnaddr.get_fallback_address()
        item['type'] = 'invoice'

        return item

    @abstractmethod
    def get_invoice_for_key(self, key: str):
        raise Exception('provide impl')

    @abstractmethod
    def get_invoice_list(self):
        raise Exception('provide impl')

    @abstractmethod
    def get_invoice_as_dict(self, invoice: Invoice):
        raise Exception('provide impl')


class QEInvoiceListModel(QEAbstractInvoiceListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(wallet, parent)

    _logger = get_logger(__name__)

    def invoice_to_model(self, invoice: Invoice):
        item = super().invoice_to_model(invoice)
        item['type'] = 'invoice'
        item['key'] = invoice.get_id()

        return item

    def get_invoice_list(self):
        return self.wallet.get_unpaid_invoices()

    def get_invoice_for_key(self, key: str):
        return self.wallet.get_invoice(key)

    def get_invoice_as_dict(self, invoice: Invoice):
        return self.wallet.export_invoice(invoice)

class QERequestListModel(QEAbstractInvoiceListModel):
    def __init__(self, wallet, parent=None):
        super().__init__(wallet, parent)

    _logger = get_logger(__name__)

    def invoice_to_model(self, invoice: Invoice):
        item = super().invoice_to_model(invoice)
        item['type'] = 'request'
        item['key'] = invoice.get_id() if invoice.is_lightning() else invoice.get_address()

        return item

    def get_invoice_list(self):
        return self.wallet.get_unpaid_requests()

    def get_invoice_for_key(self, key: str):
        return self.wallet.get_request(key)

    def get_invoice_as_dict(self, invoice: Invoice):
        return self.wallet.export_request(invoice)

    @pyqtSlot(str, int)
    def updateRequest(self, key, status):
        self.updateInvoice(key, status)
