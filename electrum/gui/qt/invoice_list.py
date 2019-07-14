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
from PyQt5.QtWidgets import QHeaderView, QMenu

from electrum.i18n import _
from electrum.util import format_time

from .util import (MyTreeView, read_QIcon, MONOSPACE_FONT, PR_UNPAID,
                   pr_tooltips, import_meta_gui, export_meta_gui, pr_icons)


class InvoiceList(MyTreeView):

    class Columns(IntEnum):
        DATE = 0
        REQUESTOR = 1
        DESCRIPTION = 2
        AMOUNT = 3
        STATUS = 4

    headers = {
        Columns.DATE: _('Expires'),
        Columns.REQUESTOR: _('Requestor'),
        Columns.DESCRIPTION: _('Description'),
        Columns.AMOUNT: _('Amount'),
        Columns.STATUS: _('Status'),
    }
    filter_columns = [Columns.DATE, Columns.REQUESTOR, Columns.DESCRIPTION, Columns.AMOUNT]

    def __init__(self, parent):
        super().__init__(parent, self.create_menu,
                         stretch_column=self.Columns.DESCRIPTION,
                         editable_columns=[])
        self.setSortingEnabled(True)
        self.setColumnWidth(self.Columns.REQUESTOR, 200)
        self.setModel(QStandardItemModel(self))
        self.update()

    def update(self):
        inv_list = self.parent.invoices.unpaid_invoices()
        self.model().clear()
        self.update_headers(self.__class__.headers)
        self.header().setSectionResizeMode(self.Columns.REQUESTOR, QHeaderView.Interactive)
        for idx, pr in enumerate(inv_list):
            key = pr.get_id()
            status = self.parent.invoices.get_status(key)
            if status is None:
                continue
            requestor = pr.get_requestor()
            exp = pr.get_expiration_date()
            date_str = format_time(exp) if exp else _('Never')
            labels = [date_str, requestor, pr.memo, self.parent.format_amount(pr.get_amount(), whitespaces=True), pr_tooltips.get(status,'')]
            items = [QStandardItem(e) for e in labels]
            self.set_editability(items)
            items[self.Columns.STATUS].setIcon(read_QIcon(pr_icons.get(status)))
            items[self.Columns.DATE].setData(key, role=Qt.UserRole)
            items[self.Columns.REQUESTOR].setFont(QFont(MONOSPACE_FONT))
            items[self.Columns.AMOUNT].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(idx, items)
        self.selectionModel().select(self.model().index(0,0), QItemSelectionModel.SelectCurrent)
        if self.parent.isVisible():
            b = len(inv_list) > 0
            self.setVisible(b)
            self.parent.invoices_label.setVisible(b)
        self.filter()

    def import_invoices(self):
        import_meta_gui(self.parent, _('invoices'), self.parent.invoices.import_file, self.update)

    def export_invoices(self):
        export_meta_gui(self.parent, _('invoices'), self.parent.invoices.export_file)

    def create_menu(self, position):
        idx = self.indexAt(position)
        item = self.model().itemFromIndex(idx)
        item_col0 = self.model().itemFromIndex(idx.sibling(idx.row(), self.Columns.DATE))
        if not item or not item_col0:
            return
        key = item_col0.data(Qt.UserRole)
        column = idx.column()
        column_title = self.model().horizontalHeaderItem(column).text()
        column_data = item.text()
        status = self.parent.invoices.get_status(key)
        menu = QMenu(self)
        if column_data:
            if column == self.Columns.AMOUNT:
                column_data = column_data.strip()
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
        menu.addAction(_("Details"), lambda: self.parent.show_invoice(key))
        if status == PR_UNPAID:
            menu.addAction(_("Pay Now"), lambda: self.parent.do_pay_invoice(key))
        menu.addAction(_("Delete"), lambda: self.parent.delete_invoice(key))
        menu.exec_(self.viewport().mapToGlobal(position))
