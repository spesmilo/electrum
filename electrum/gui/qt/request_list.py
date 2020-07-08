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
from typing import Optional

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QMenu, QAbstractItemView
from PyQt5.QtCore import Qt, QItemSelectionModel, QModelIndex

from electrum.i18n import _
from electrum.util import format_time
from electrum.invoices import PR_TYPE_ONCHAIN, PR_TYPE_LN, LNInvoice, OnchainInvoice
from electrum.plugin import run_hook

from .util import MyTreeView, pr_icons, read_QIcon, webopen, MySortModel


ROLE_REQUEST_TYPE = Qt.UserRole
ROLE_KEY = Qt.UserRole + 1
ROLE_SORT_ORDER = Qt.UserRole + 2


class RequestList(MyTreeView):

    class Columns(IntEnum):
        DATE = 0
        DESCRIPTION = 1
        AMOUNT = 2
        STATUS = 3

    headers = {
        Columns.DATE: _('Date'),
        Columns.DESCRIPTION: _('Description'),
        Columns.AMOUNT: _('Amount'),
        Columns.STATUS: _('Status'),
    }
    filter_columns = [Columns.DATE, Columns.DESCRIPTION, Columns.AMOUNT]

    def __init__(self, parent):
        super().__init__(parent, self.create_menu,
                         stretch_column=self.Columns.DESCRIPTION,
                         editable_columns=[])
        self.wallet = self.parent.wallet
        self.std_model = QStandardItemModel(self)
        self.proxy = MySortModel(self, sort_role=ROLE_SORT_ORDER)
        self.proxy.setSourceModel(self.std_model)
        self.setModel(self.proxy)
        self.setSortingEnabled(True)
        self.selectionModel().currentRowChanged.connect(self.item_changed)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.update()

    def select_key(self, key):
        for i in range(self.model().rowCount()):
            item = self.model().index(i, self.Columns.DATE)
            row_key = item.data(ROLE_KEY)
            if key == row_key:
                self.selectionModel().setCurrentIndex(item, QItemSelectionModel.SelectCurrent | QItemSelectionModel.Rows)
                break

    def item_changed(self, idx: Optional[QModelIndex]):
        if idx is None:
            self.parent.receive_payreq_e.setText('')
            self.parent.receive_address_e.setText('')
            return
        if not idx.isValid():
            return
        # TODO use siblingAtColumn when min Qt version is >=5.11
        item = self.item_from_index(idx.sibling(idx.row(), self.Columns.DATE))
        key = item.data(ROLE_KEY)
        req = self.wallet.get_request(key)
        if req is None:
            self.update()
            return
        if req.is_lightning():
            self.parent.receive_payreq_e.setText(req.invoice)  # TODO maybe prepend "lightning:" ??
            self.parent.receive_address_e.setText(req.invoice)
        else:
            self.parent.receive_payreq_e.setText(self.parent.wallet.get_request_URI(req))
            self.parent.receive_address_e.setText(req.get_address())
        self.parent.receive_payreq_e.repaint()  # macOS hack (similar to #4777)
        self.parent.receive_address_e.repaint()  # macOS hack (similar to #4777)

    def clearSelection(self):
        super().clearSelection()
        self.selectionModel().clearCurrentIndex()

    def refresh_status(self):
        m = self.std_model
        for r in range(m.rowCount()):
            idx = m.index(r, self.Columns.STATUS)
            date_idx = idx.sibling(idx.row(), self.Columns.DATE)
            date_item = m.itemFromIndex(date_idx)
            status_item = m.itemFromIndex(idx)
            key = date_item.data(ROLE_KEY)
            req = self.wallet.get_request(key)
            if req:
                status = self.parent.wallet.get_request_status(key)
                status_str = req.get_status_str(status)
                status_item.setText(status_str)
                status_item.setIcon(read_QIcon(pr_icons.get(status)))

    def update(self):
        # not calling maybe_defer_update() as it interferes with conditional-visibility
        self.parent.update_receive_address_styling()
        self.proxy.setDynamicSortFilter(False)  # temp. disable re-sorting after every change
        self.std_model.clear()
        self.update_headers(self.__class__.headers)
        for req in self.wallet.get_sorted_requests():
            if req.is_lightning():
                assert isinstance(req, LNInvoice)
                key = req.rhash
            else:
                assert isinstance(req, OnchainInvoice)
                key = req.id
            status = self.parent.wallet.get_request_status(key)
            status_str = req.get_status_str(status)
            request_type = req.type
            timestamp = req.time
            amount = req.get_amount_sat()
            message = req.message
            date = format_time(timestamp)
            amount_str = self.parent.format_amount(amount) if amount else ""
            labels = [date, message, amount_str, status_str]
            if req.is_lightning():
                assert isinstance(req, LNInvoice)
                key = req.rhash
                icon = read_QIcon("lightning.png")
                tooltip = 'lightning request'
            else:
                assert isinstance(req, OnchainInvoice)
                key = req.get_address()
                icon = read_QIcon("bitcoin.png")
                tooltip = 'onchain request'
            items = [QStandardItem(e) for e in labels]
            self.set_editability(items)
            items[self.Columns.DATE].setData(request_type, ROLE_REQUEST_TYPE)
            items[self.Columns.DATE].setData(key, ROLE_KEY)
            items[self.Columns.DATE].setData(timestamp, ROLE_SORT_ORDER)
            items[self.Columns.DATE].setIcon(icon)
            items[self.Columns.STATUS].setIcon(read_QIcon(pr_icons.get(status)))
            items[self.Columns.DATE].setToolTip(tooltip)
            self.std_model.insertRow(self.std_model.rowCount(), items)
        self.filter()
        self.proxy.setDynamicSortFilter(True)
        # sort requests by date
        self.sortByColumn(self.Columns.DATE, Qt.DescendingOrder)
        # hide list if empty
        if self.parent.isVisible():
            b = self.std_model.rowCount() > 0
            self.setVisible(b)
            self.parent.receive_requests_label.setVisible(b)
            if not b:
                # list got hidden, so selected item should also be cleared:
                self.item_changed(None)

    def create_menu(self, position):
        items = self.selected_in_column(0)
        if len(items)>1:
            keys = [ item.data(ROLE_KEY)  for item in items]
            menu = QMenu(self)
            menu.addAction(_("Delete requests"), lambda: self.parent.delete_requests(keys))
            menu.exec_(self.viewport().mapToGlobal(position))
            return
        idx = self.indexAt(position)
        # TODO use siblingAtColumn when min Qt version is >=5.11
        item = self.item_from_index(idx.sibling(idx.row(), self.Columns.DATE))
        if not item:
            return
        key = item.data(ROLE_KEY)
        req = self.wallet.get_request(key)
        if req is None:
            self.update()
            return
        menu = QMenu(self)
        self.add_copy_menu(menu, idx)
        if req.is_lightning():
            menu.addAction(_("Copy Request"), lambda: self.parent.do_copy(req.invoice, title='Lightning Request'))
        else:
            URI = self.wallet.get_request_URI(req)
            menu.addAction(_("Copy Request"), lambda: self.parent.do_copy(URI, title='Bitcoin URI'))
            menu.addAction(_("Copy Address"), lambda: self.parent.do_copy(req.get_address(), title='Bitcoin Address'))
        #if 'view_url' in req:
        #    menu.addAction(_("View in web browser"), lambda: webopen(req['view_url']))
        menu.addAction(_("Delete"), lambda: self.parent.delete_requests([key]))
        run_hook('receive_list_menu', menu, key)
        menu.exec_(self.viewport().mapToGlobal(position))
