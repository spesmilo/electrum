#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from enum import IntEnum

from PyQt5.QtCore import Qt, QItemSelectionModel
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView
from PyQt5.QtWidgets import QHeaderView, QMenu, QVBoxLayout, QGridLayout, QLabel, QTreeWidget, QTreeWidgetItem

from electrum.i18n import _
from electrum.util import format_time, PR_UNPAID, PR_PAID, PR_INFLIGHT
from electrum.util import get_request_status
from electrum.util import PR_TYPE_ONCHAIN, PR_TYPE_LN
from electrum.lnutil import format_short_channel_id
from electrum.bitcoin import COIN
from electrum import constants

from .util import (MyTreeView, read_QIcon, MONOSPACE_FONT,
                   import_meta_gui, export_meta_gui, pr_icons)
from .util import CloseButton, Buttons
from .util import WindowModalDialog
from ...three_keys.tx_type import TxType

ROLE_REQUEST_TYPE = Qt.UserRole
ROLE_REQUEST_ID = Qt.UserRole + 1


class InvoiceList(MyTreeView):

    class Columns(IntEnum):
        DATE = 0
        DESCRIPTION = 1
        TXTYPE = 2
        AMOUNT = 3
        STATUS = 4

    headers = {
        Columns.DATE: _('Date'),
        Columns.DESCRIPTION: _('Description'),
        Columns.TXTYPE: _('Type'),
        Columns.AMOUNT: _('Amount'),
        Columns.STATUS: _('Status'),
    }
    filter_columns = [Columns.DATE, Columns.DESCRIPTION, Columns.TXTYPE, Columns.AMOUNT]

    def __init__(self, parent):
        super().__init__(parent, self.create_menu,
                         stretch_column=self.Columns.DESCRIPTION,
                         editable_columns=[])
        self.setSortingEnabled(True)
        self.setModel(QStandardItemModel(self))
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.update()

    def update_item(self, key, status):
        req = self.parent.wallet.get_invoice(key)
        if req is None:
            return
        model = self.model()
        for row in range(0, model.rowCount()):
            item = model.item(row, 0)
            if item.data(ROLE_REQUEST_ID) == key:
                break
        else:
            return
        status_item = model.item(row, self.Columns.STATUS)
        status, status_str = get_request_status(req)
        if self.parent.wallet.lnworker:
            log = self.parent.wallet.lnworker.logs.get(key)
            if log and status == PR_INFLIGHT:
                status_str += '... (%d)'%len(log)
        status_item.setText(status_str)
        status_item.setIcon(read_QIcon(pr_icons.get(status)))

    def update(self):
        _list = self.parent.wallet.get_invoices()
        # filter out paid invoices unless we have the log
        lnworker_logs = self.parent.wallet.lnworker.logs if self.parent.wallet.lnworker else {}
        _list = [x for x in _list if x and x.get('status') != PR_PAID or x.get('rhash') in lnworker_logs]
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, item in enumerate(_list):
            invoice_type = item['type']
            if invoice_type == PR_TYPE_LN:
                key = item['rhash']
                icon_name = 'lightning.png'
            elif invoice_type == PR_TYPE_ONCHAIN:
                key = item['id']
                icon_name = 'bitcoin.png'
                if item.get('bip70'):
                    icon_name = 'seal.png'
            else:
                raise Exception('Unsupported type')
            status, status_str = get_request_status(item)
            message = item['message']
            amount = item['amount']
            timestamp = item.get('time', 0)
            date_str = format_time(timestamp) if timestamp else _('Unknown')
            txtype_str = TxType.NONVAULT.name if 'txtype' not in item else item['txtype']
            amount_str = self.parent.format_amount(amount, whitespaces=True)
            labels = [date_str, message, txtype_str, amount_str, status_str]
            items = [QStandardItem(e) for e in labels]
            self.set_editability(items)
            items[self.Columns.DATE].setIcon(read_QIcon(icon_name))
            items[self.Columns.STATUS].setIcon(read_QIcon(pr_icons.get(status)))
            items[self.Columns.DATE].setData(key, role=ROLE_REQUEST_ID)
            items[self.Columns.DATE].setData(invoice_type, role=ROLE_REQUEST_TYPE)
            self.model().insertRow(idx, items)

        self.selectionModel().select(self.model().index(0,0), QItemSelectionModel.SelectCurrent)
        # sort requests by date
        self.model().sort(self.Columns.DATE)
        # hide list if empty
        if self.parent.isVisible():
            b = self.model().rowCount() > 0
            self.setVisible(b)
            self.parent.invoices_label.setVisible(b)
        self.filter()

    def import_invoices(self):
        import_meta_gui(self.parent, _('invoices'), self.parent.invoices.import_file, self.update)

    def export_invoices(self):
        export_meta_gui(self.parent, _('invoices'), self.parent.invoices.export_file)

    def create_menu(self, position):
        items = self.selected_in_column(0)
        if len(items)>1:
            keys = [ item.data(ROLE_REQUEST_ID)  for item in items]
            invoices = [ self.parent.wallet.get_invoice(key) for key in keys]
            invoices = [ invoice for invoice in invoices if invoice['status'] == PR_UNPAID and invoice['type'] == PR_TYPE_ONCHAIN]
            if len(invoices) > 1:
                menu = QMenu(self)
                menu.addAction(_("Pay multiple invoices"), lambda: self.parent.pay_multiple_invoices(invoices))
                menu.exec_(self.viewport().mapToGlobal(position))
            return
        idx = self.indexAt(position)
        item = self.model().itemFromIndex(idx)
        item_col0 = self.model().itemFromIndex(idx.sibling(idx.row(), self.Columns.DATE))
        if not item or not item_col0:
            return
        key = item_col0.data(ROLE_REQUEST_ID)
        request_type = item_col0.data(ROLE_REQUEST_TYPE)
        menu = QMenu(self)
        self.add_copy_menu(menu, idx)
        invoice = self.parent.wallet.get_invoice(key)
        menu.addAction(_("Details"), lambda: self.parent.show_invoice(key))
        if invoice['status'] == PR_UNPAID:
            menu.addAction(_("Pay"), lambda: self.parent.do_pay_invoice(invoice))
        if self.parent.wallet.lnworker:
            log = self.parent.wallet.lnworker.logs.get(key)
            if log:
                menu.addAction(_("View log"), lambda: self.show_log(key, log))
        menu.addAction(_("Delete"), lambda: self.parent.delete_invoice(key))
        menu.exec_(self.viewport().mapToGlobal(position))

    def show_log(self, key, log):
        d = WindowModalDialog(self, _("Payment log"))
        vbox = QVBoxLayout(d)
        log_w = QTreeWidget()
        log_w.setHeaderLabels([_('Route'), _('Channel ID'), _('Message'), _('Blacklist')])
        for i, (route, success, failure_log) in enumerate(log):
            route_str = '%d'%len(route)
            if not success:
                sender_idx, failure_msg, blacklist = failure_log
                short_channel_id = route[sender_idx+1].short_channel_id
                data = failure_msg.data
                message = repr(failure_msg.code)
            else:
                short_channel_id = route[-1].short_channel_id
                message = _('Success')
                blacklist = False
            chan_str = format_short_channel_id(short_channel_id)
            x = QTreeWidgetItem([route_str, chan_str, message, repr(blacklist)])
            log_w.addTopLevelItem(x)
        vbox.addWidget(log_w)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec_()
