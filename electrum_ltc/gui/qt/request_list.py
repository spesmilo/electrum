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
from typing import Optional, TYPE_CHECKING

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QMenu, QAbstractItemView
from PyQt5.QtCore import Qt, QItemSelectionModel, QModelIndex

from electrum_ltc.i18n import _
from electrum_ltc.util import format_time
from electrum_ltc.plugin import run_hook
from electrum_ltc.invoices import Invoice

from .util import MyTreeView, pr_icons, read_QIcon, webopen, MySortModel

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .receive_tab import ReceiveTab


ROLE_REQUEST_TYPE = Qt.UserRole
ROLE_KEY = Qt.UserRole + 1
ROLE_SORT_ORDER = Qt.UserRole + 2


class RequestList(MyTreeView):
    key_role = ROLE_KEY

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

    def __init__(self, receive_tab: 'ReceiveTab'):
        window = receive_tab.window
        super().__init__(window, self.create_menu,
                         stretch_column=self.Columns.DESCRIPTION)
        self.wallet = window.wallet
        self.receive_tab = receive_tab
        self.std_model = QStandardItemModel(self)
        self.proxy = MySortModel(self, sort_role=ROLE_SORT_ORDER)
        self.proxy.setSourceModel(self.std_model)
        self.setModel(self.proxy)
        self.setSortingEnabled(True)
        self.selectionModel().currentRowChanged.connect(self.item_changed)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

    def set_current_key(self, key):
        for i in range(self.model().rowCount()):
            item = self.model().index(i, self.Columns.DATE)
            row_key = item.data(ROLE_KEY)
            if key == row_key:
                self.selectionModel().setCurrentIndex(item, QItemSelectionModel.SelectCurrent | QItemSelectionModel.Rows)
                break

    def get_current_key(self):
        return self.get_role_data_for_current_item(col=self.Columns.DATE, role=ROLE_KEY)

    def item_changed(self, idx: Optional[QModelIndex]):
        if idx is None:
            self.receive_tab.update_current_request()
            return
        if not idx.isValid():
            return
        # TODO use siblingAtColumn when min Qt version is >=5.11
        item = self.item_from_index(idx.sibling(idx.row(), self.Columns.DATE))
        key = item.data(ROLE_KEY)
        req = self.wallet.get_request(key)
        if req is None:
            self.update()
        self.receive_tab.update_current_request()

    def clearSelection(self):
        super().clearSelection()
        self.selectionModel().clearCurrentIndex()

    def refresh_row(self, key, row):
        assert row is not None
        model = self.std_model
        request = self.wallet.get_request(key)
        if request is None:
            return
        status_item = model.item(row, self.Columns.STATUS)
        status = self.wallet.get_invoice_status(request)
        status_str = request.get_status_str(status)
        status_item.setText(status_str)
        status_item.setIcon(read_QIcon(pr_icons.get(status)))

    def update(self):
        current_key = self.get_current_key()
        # not calling maybe_defer_update() as it interferes with conditional-visibility
        self.proxy.setDynamicSortFilter(False)  # temp. disable re-sorting after every change
        self.std_model.clear()
        self.update_headers(self.__class__.headers)
        for req in self.wallet.get_unpaid_requests():
            key = req.get_id()
            status = self.wallet.get_invoice_status(req)
            status_str = req.get_status_str(status)
            timestamp = req.get_time()
            amount = req.get_amount_sat()
            message = req.get_message()
            date = format_time(timestamp)
            amount_str = self.parent.format_amount(amount) if amount else ""
            labels = [date, message, amount_str, status_str]
            items = [QStandardItem(e) for e in labels]
            self.set_editability(items)
            #items[self.Columns.DATE].setData(request_type, ROLE_REQUEST_TYPE)
            items[self.Columns.DATE].setData(key, ROLE_KEY)
            items[self.Columns.DATE].setData(timestamp, ROLE_SORT_ORDER)
            items[self.Columns.STATUS].setIcon(read_QIcon(pr_icons.get(status)))
            self.std_model.insertRow(self.std_model.rowCount(), items)
        self.filter()
        self.proxy.setDynamicSortFilter(True)
        # sort requests by date
        self.sortByColumn(self.Columns.DATE, Qt.DescendingOrder)
        self.hide_if_empty()
        if current_key is not None:
            self.set_current_key(current_key)

    def hide_if_empty(self):
        b = self.std_model.rowCount() > 0
        self.setVisible(b)
        self.receive_tab.receive_requests_label.setVisible(b)
        if not b:
            # list got hidden, so selected item should also be cleared:
            self.item_changed(None)

    def create_menu(self, position):
        items = self.selected_in_column(0)
        if len(items)>1:
            keys = [item.data(ROLE_KEY)  for item in items]
            menu = QMenu(self)
            menu.addAction(_("Delete requests"), lambda: self.delete_requests(keys))
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
        if req.get_address():
            menu.addAction(_("Copy Address"), lambda: self.parent.do_copy(req.get_address(), title='Litecoin Address'))
        if URI := self.wallet.get_request_URI(req):
            menu.addAction(_("Copy URI"), lambda: self.parent.do_copy(URI, title='Litecoin URI'))
        if req.is_lightning():
            menu.addAction(_("Copy Lightning Request"), lambda: self.parent.do_copy(req.lightning_invoice, title='Lightning Request'))
        self.add_copy_menu(menu, idx)
        #if 'view_url' in req:
        #    menu.addAction(_("View in web browser"), lambda: webopen(req['view_url']))
        menu.addAction(_("Delete"), lambda: self.delete_requests([key]))
        run_hook('receive_list_menu', self.parent, menu, key)
        menu.exec_(self.viewport().mapToGlobal(position))

    def delete_requests(self, keys):
        for key in keys:
            self.wallet.delete_request(key, write_to_disk=False)
            self.delete_item(key)
        self.wallet.save_db()
        self.receive_tab.do_clear()
