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

import enum
from typing import Sequence, TYPE_CHECKING

from PyQt6.QtCore import Qt, QItemSelectionModel
from PyQt6.QtGui import QStandardItemModel, QStandardItem
from PyQt6.QtWidgets import QAbstractItemView
from PyQt6.QtWidgets import QMenu, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QHeaderView

from electrum.i18n import _
from electrum.util import format_time
from electrum.invoices import Invoice, PR_UNPAID, PR_PAID, PR_INFLIGHT, PR_FAILED
from electrum.lnutil import HtlcLog

from .util import read_QIcon, pr_icons
from .util import CloseButton, Buttons
from .util import WindowModalDialog

from .my_treeview import MyTreeView, MySortModel

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .send_tab import SendTab


ROLE_REQUEST_TYPE = Qt.ItemDataRole.UserRole
ROLE_REQUEST_ID = Qt.ItemDataRole.UserRole + 1
ROLE_SORT_ORDER = Qt.ItemDataRole.UserRole + 2


class InvoiceList(MyTreeView):
    key_role = ROLE_REQUEST_ID

    class Columns(MyTreeView.BaseColumnsEnum):
        DATE = enum.auto()
        DESCRIPTION = enum.auto()
        AMOUNT = enum.auto()
        STATUS = enum.auto()

    headers = {
        Columns.DATE: _('Date'),
        Columns.DESCRIPTION: _('Description'),
        Columns.AMOUNT: _('Amount'),
        Columns.STATUS: _('Status'),
    }
    filter_columns = [Columns.DATE, Columns.DESCRIPTION, Columns.AMOUNT]

    def __init__(self, send_tab: 'SendTab'):
        window = send_tab.window
        super().__init__(
            main_window=window,
            stretch_column=self.Columns.DESCRIPTION,
        )
        self.wallet = window.wallet
        self.send_tab = send_tab
        self.std_model = QStandardItemModel(self)
        self.proxy = MySortModel(self, sort_role=ROLE_SORT_ORDER)
        self.proxy.setSourceModel(self.std_model)
        self.setModel(self.proxy)
        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)

    def on_double_click(self, idx):
        key = idx.sibling(idx.row(), self.Columns.DATE).data(ROLE_REQUEST_ID)
        self.show_invoice(key)

    def refresh_row(self, key, row):
        assert row is not None
        invoice = self.wallet.get_invoice(key)
        if invoice is None:
            return
        model = self.std_model
        status_item = model.item(row, self.Columns.STATUS)
        status = self.wallet.get_invoice_status(invoice)
        status_str = invoice.get_status_str(status)
        if self.wallet.lnworker:
            log = self.wallet.lnworker.logs.get(key)
            if log and status == PR_INFLIGHT:
                status_str += '... (%d)'%len(log)
        status_item.setText(status_str)
        status_item.setIcon(read_QIcon(pr_icons.get(status)))

    def update(self):
        # not calling maybe_defer_update() as it interferes with conditional-visibility
        self.proxy.setDynamicSortFilter(False)  # temp. disable re-sorting after every change
        self.std_model.clear()
        self.update_headers(self.__class__.headers)
        for idx, item in enumerate(self.wallet.get_unpaid_invoices()):
            key = item.get_id()
            if item.is_lightning():
                icon_name = 'lightning.png'
            else:
                icon_name = 'bitcoin.png'
                if item.bip70:
                    icon_name = 'seal.png'
            status = self.wallet.get_invoice_status(item)
            amount = item.get_amount_sat()
            amount_str = self.main_window.format_amount(amount, whitespaces=True) if amount else ""
            amount_str_nots = self.main_window.format_amount(amount, whitespaces=True, add_thousands_sep=False) if amount else ""
            timestamp = item.time or 0
            labels = [""] * len(self.Columns)
            labels[self.Columns.DATE] = format_time(timestamp) if timestamp else _('Unknown')
            labels[self.Columns.DESCRIPTION] = item.message
            labels[self.Columns.AMOUNT] = amount_str
            labels[self.Columns.STATUS] = item.get_status_str(status)
            items = [QStandardItem(e) for e in labels]
            self.set_editability(items)
            items[self.Columns.DATE].setIcon(read_QIcon(icon_name))
            items[self.Columns.STATUS].setIcon(read_QIcon(pr_icons.get(status)))
            items[self.Columns.DATE].setData(key, role=ROLE_REQUEST_ID)
            #items[self.Columns.DATE].setData(item.type, role=ROLE_REQUEST_TYPE)
            items[self.Columns.DATE].setData(timestamp, role=ROLE_SORT_ORDER)
            items[self.Columns.AMOUNT].setData(amount_str_nots.strip(), role=self.ROLE_CLIPBOARD_DATA)
            self.std_model.insertRow(idx, items)
        self.filter()
        self.proxy.setDynamicSortFilter(True)
        # sort requests by date
        self.sortByColumn(self.Columns.DATE, Qt.SortOrder.DescendingOrder)
        self.hide_if_empty()

    def show_invoice(self, key):
        invoice = self.wallet.get_invoice(key)
        if invoice.is_lightning():
            self.main_window.show_lightning_invoice(invoice)
        else:
            self.main_window.show_onchain_invoice(invoice)

    def hide_if_empty(self):
        b = self.std_model.rowCount() > 0
        self.setVisible(b)
        self.send_tab.invoices_label.setVisible(b)

    def create_menu(self, position):
        wallet = self.wallet
        items = self.selected_in_column(0)
        if len(items)>1:
            keys = [item.data(ROLE_REQUEST_ID) for item in items]
            invoices = [wallet.get_invoice(key) for key in keys]
            can_batch_pay = all([not i.is_lightning() and wallet.get_invoice_status(i) == PR_UNPAID for i in invoices])
            menu = QMenu(self)
            if can_batch_pay:
                menu.addAction(_("Batch pay invoices") + "...", lambda: self.send_tab.pay_multiple_invoices(invoices))
            menu.addAction(_("Delete invoices"), lambda: self.delete_invoices(keys))
            menu.exec(self.viewport().mapToGlobal(position))
            return
        idx = self.indexAt(position)
        item = self.item_from_index(idx)
        item_col0 = self.item_from_index(idx.sibling(idx.row(), self.Columns.DATE))
        if not item or not item_col0:
            return
        key = item_col0.data(ROLE_REQUEST_ID)
        invoice = self.wallet.get_invoice(key)
        menu = QMenu(self)
        menu.addAction(_("Details"), lambda: self.show_invoice(key))
        copy_menu = self.add_copy_menu(menu, idx)
        address = invoice.get_address()
        if address:
            copy_menu.addAction(_("Address"), lambda: self.main_window.do_copy(invoice.get_address(), title='Bitcoin Address'))
        status = wallet.get_invoice_status(invoice)
        if status == PR_UNPAID:
            if bool(invoice.get_amount_sat()):
                menu.addAction(_("Pay") + "...", lambda: self.send_tab.do_pay_invoice(invoice))
            else:
                menu.addAction(_("Pay") + "...", lambda: self.send_tab.do_edit_invoice(invoice))
        if status == PR_FAILED:
            menu.addAction(_("Retry"), lambda: self.send_tab.do_pay_invoice(invoice))
        if self.wallet.lnworker:
            log = self.wallet.lnworker.logs.get(key)
            if log:
                menu.addAction(_("View log"), lambda: self.show_log(key, log))
        menu.addAction(_("Delete"), lambda: self.delete_invoices([key]))
        menu.exec(self.viewport().mapToGlobal(position))

    def show_log(self, key, log: Sequence[HtlcLog]):
        d = WindowModalDialog(self, _("Payment log"))
        d.setMinimumWidth(600)
        vbox = QVBoxLayout(d)
        log_w = QTreeWidget()
        log_w.setHeaderLabels([_('Hops'), _('Channel ID'), _('Message')])
        log_w.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        log_w.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        for payment_attempt_log in log:
            route_str, chan_str, message = payment_attempt_log.formatted_tuple()
            x = QTreeWidgetItem([route_str, chan_str, message])
            log_w.addTopLevelItem(x)
        vbox.addWidget(log_w)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.exec()

    def delete_invoices(self, keys):
        for key in keys:
            self.wallet.delete_invoice(key, write_to_disk=False)
            self.delete_item(key)
        self.wallet.save_db()
