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


from util import *
from electrum.i18n import _
from electrum.util import block_explorer_URL, format_satoshis, format_time
from electrum.plugins import run_hook


class InvoiceList(MyTreeWidget):

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Expires'), _('Requestor'), _('Description'), _('Amount'), _('Status')], 2)
        self.setSortingEnabled(True)
        self.header().setResizeMode(1, QHeaderView.Interactive)
        self.setColumnWidth(1, 200)

    def on_update(self):
        inv_list = self.parent.invoices.sorted_list()
        self.clear()
        for pr in inv_list:
            key = pr.get_id()
            status = self.parent.invoices.get_status(key)
            requestor = pr.get_requestor()
            exp = pr.get_expiration_date()
            date_str = format_time(exp) if exp else _('Never')
            item = QTreeWidgetItem([date_str, requestor, pr.memo, self.parent.format_amount(pr.get_amount(), whitespaces=True), pr_tooltips.get(status,'')])
            item.setIcon(4, QIcon(pr_icons.get(status)))
            item.setData(0, Qt.UserRole, key)
            item.setFont(1, QFont(MONOSPACE_FONT))
            item.setFont(3, QFont(MONOSPACE_FONT))
            self.addTopLevelItem(item)
        self.setCurrentItem(self.topLevelItem(0))
        self.setVisible(len(inv_list))
        self.parent.invoices_label.setVisible(len(inv_list))

    def create_menu(self, position):
        item = self.itemAt(position)
        if not item:
            return
        key = str(item.data(0, 32).toString())
        column = self.currentColumn()        
        column_title = self.headerItem().text(column)
        column_data = item.text(column)
        pr = self.parent.invoices.get(key)
        status = self.parent.invoices.get_status(key)
        menu = QMenu()
        if column_data:
            menu.addAction(_("Copy %s")%column_title, lambda: self.parent.app.clipboard().setText(column_data))
        menu.addAction(_("Details"), lambda: self.parent.show_invoice(key))
        if status == PR_UNPAID:
            menu.addAction(_("Pay Now"), lambda: self.parent.do_pay_invoice(key))
        menu.addAction(_("Delete"), lambda: self.parent.delete_invoice(key))
        menu.exec_(self.viewport().mapToGlobal(position))
