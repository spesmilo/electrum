from abc import abstractmethod
from typing import TYPE_CHECKING, List, Dict, Any

from PyQt6.QtCore import pyqtSlot, QTimer
from PyQt6.QtCore import Qt, QAbstractListModel, QModelIndex

from electrum.logging import get_logger
from electrum.util import Satoshis, format_time
from electrum.invoices import BaseInvoice, PR_EXPIRED, LN_EXPIRY_NEVER, Invoice, Request, PR_PAID

from .util import QtEventListener, qt_event_listener, status_update_timer_interval
from .qetypes import QEAmount

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet


class QEAbstractInvoiceListModel(QAbstractListModel):
    _logger = get_logger(__name__)

    # define listmodel rolemap
    _ROLE_NAMES=('key', 'is_lightning', 'timestamp', 'date', 'message', 'amount',
                 'status', 'status_str', 'address', 'expiry', 'type', 'onchain_fallback',
                 'lightning_invoice')
    _ROLE_KEYS = range(Qt.ItemDataRole.UserRole, Qt.ItemDataRole.UserRole + len(_ROLE_NAMES))
    _ROLE_MAP  = dict(zip(_ROLE_KEYS, [bytearray(x.encode()) for x in _ROLE_NAMES]))
    _ROLE_RMAP = dict(zip(_ROLE_NAMES, _ROLE_KEYS))

    def __init__(self, wallet: 'Abstract_Wallet', parent=None):
        super().__init__(parent)
        self.wallet = wallet
        self._invoices = []

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.updateStatusStrings)

        try:
            self.initModel()
        except Exception as e:
            self._logger.error(f'{repr(e)}')
            raise e

    def rowCount(self, index):
        return len(self._invoices)

    def roleNames(self):
        return self._ROLE_MAP

    def data(self, index, role):
        invoice = self._invoices[index.row()]
        role_index = role - Qt.ItemDataRole.UserRole
        value = invoice[self._ROLE_NAMES[role_index]]

        if isinstance(value, (bool, list, int, str, QEAmount)) or value is None:
            return value
        if isinstance(value, Satoshis):
            return value.value
        return str(value)

    def clear(self):
        self.beginResetModel()
        self._invoices = []
        self.endResetModel()

    @pyqtSlot()
    def initModel(self):
        invoices = []
        for invoice in self.get_invoice_list():
            item = self.invoice_to_model(invoice)
            invoices.append(item)

        self.clear()
        self.beginInsertRows(QModelIndex(), 0, len(invoices) - 1)
        self._invoices = invoices
        self.endInsertRows()

        self.set_status_timer()

    def add_invoice(self, invoice: BaseInvoice):
        # skip if already in list
        key = invoice.get_id()
        for x in self._invoices:
            if x['key'] == key:
                return

        item = self.invoice_to_model(invoice)
        self._logger.debug(str(item))

        self.beginInsertRows(QModelIndex(), 0, 0)
        self._invoices.insert(0, item)
        self.endInsertRows()

        self.set_status_timer()

    @pyqtSlot(str)
    def addInvoice(self, key):
        self.add_invoice(self.get_invoice_for_key(key))

    def delete_invoice(self, key: str):
        for i, invoice in enumerate(self._invoices):
            if invoice['key'] == key:
                self.beginRemoveRows(QModelIndex(), i, i)
                self._invoices.pop(i)
                self.endRemoveRows()
                break
        self.set_status_timer()

    def get_model_invoice(self, key: str):
        for invoice in self._invoices:
            if invoice['key'] == key:
                return invoice
        return None

    @pyqtSlot(str, int)
    def updateInvoice(self, key, status):
        self._logger.debug(f'updating invoice for {key} to {status}')
        for i, item in enumerate(self._invoices):
            if item['key'] == key:
                invoice = self.get_invoice_for_key(key)
                item['status'] = status
                item['status_str'] = invoice.get_status_str(status)
                index = self.index(i, 0)
                self.dataChanged.emit(index, index, [self._ROLE_RMAP['status'], self._ROLE_RMAP['status_str']])
                return

    def invoice_to_model(self, invoice: BaseInvoice):
        item = self.get_invoice_as_dict(invoice)
        item['key'] = invoice.get_id()
        item['is_lightning'] = invoice.is_lightning()
        if invoice.is_lightning() and 'address' not in item:
            item['address'] = ''
        item['date'] = format_time(item['timestamp'])
        item['amount'] = QEAmount(from_invoice=invoice)
        item['onchain_fallback'] = invoice.is_lightning() and bool(invoice.get_address())

        return item

    def set_status_timer(self):
        nearest_interval = LN_EXPIRY_NEVER
        for invoice in self._invoices:
            if invoice['status'] != PR_EXPIRED:
                if invoice['expiry'] > 0 and invoice['expiry'] != LN_EXPIRY_NEVER:
                    interval = status_update_timer_interval(invoice['timestamp'] + invoice['expiry'])
                    if interval > 0:
                        nearest_interval = nearest_interval if nearest_interval < interval else interval

        if nearest_interval != LN_EXPIRY_NEVER:
            self._timer.setInterval(nearest_interval)  # msec
            self._timer.start()

    @pyqtSlot()
    def updateStatusStrings(self):
        for i, item in enumerate(self._invoices):
            invoice = self.get_invoice_for_key(item['key'])
            if invoice is None:  # invoice might be removed from the backend
                self._logger.debug(f'invoice {item["key"]} not found')
                continue
            item['status'] = self.wallet.get_invoice_status(invoice)
            item['status_str'] = invoice.get_status_str(item['status'])
            index = self.index(i, 0)
            self.dataChanged.emit(index, index, [self._ROLE_RMAP['status'], self._ROLE_RMAP['status_str']])

        self.set_status_timer()

    @abstractmethod
    def get_invoice_for_key(self, key: str):
        raise Exception('provide impl')

    @abstractmethod
    def get_invoice_list(self) -> List[BaseInvoice]:
        raise Exception('provide impl')

    @abstractmethod
    def get_invoice_as_dict(self, invoice: BaseInvoice) -> Dict[str, Any]:
        raise Exception('provide impl')


class QEInvoiceListModel(QEAbstractInvoiceListModel, QtEventListener):
    def __init__(self, wallet, parent=None):
        super().__init__(wallet, parent)
        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

    _logger = get_logger(__name__)

    def on_destroy(self):
        self.unregister_callbacks()

    @qt_event_listener
    def on_event_invoice_status(self, wallet, key, status):
        if wallet == self.wallet:
            self._logger.debug(f'invoice status update for key {key} to {status}')
            self.updateInvoice(key, status)

    def invoice_to_model(self, invoice: BaseInvoice):
        item = super().invoice_to_model(invoice)
        item['type'] = 'invoice'

        return item

    def get_invoice_list(self):
        lst = self.wallet.get_unpaid_invoices()
        lst.reverse()
        return lst

    def get_invoice_for_key(self, key: str):
        return self.wallet.get_invoice(key)

    def get_invoice_as_dict(self, invoice: Invoice):
        return self.wallet.export_invoice(invoice)


class QERequestListModel(QEAbstractInvoiceListModel, QtEventListener):
    def __init__(self, wallet, parent=None):
        super().__init__(wallet, parent)
        self.register_callbacks()
        self.destroyed.connect(lambda: self.on_destroy())

    _logger = get_logger(__name__)

    def on_destroy(self):
        self.unregister_callbacks()

    @qt_event_listener
    def on_event_request_status(self, wallet, key, status):
        if wallet == self.wallet:
            self._logger.debug(f'request status update for key {key} to {status}')
            self.updateRequest(key, status)

    def invoice_to_model(self, invoice: BaseInvoice):
        item = super().invoice_to_model(invoice)
        item['type'] = 'request'

        return item

    def get_invoice_list(self):
        lst = self.wallet.get_unpaid_requests()
        lst.reverse()
        return lst

    def get_invoice_for_key(self, key: str):
        return self.wallet.get_request(key)

    def get_invoice_as_dict(self, invoice: Request):
        return self.wallet.export_request(invoice)

    @pyqtSlot(str, int)
    def updateRequest(self, key, status):
        if status == PR_PAID:
            self.delete_invoice(key)
        else:
            self.updateInvoice(key, status)
