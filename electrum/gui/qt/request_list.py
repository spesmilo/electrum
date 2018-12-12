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

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QMenu
from PyQt5.QtCore import Qt

from electrum.i18n import _
from electrum.util import format_time, age
from electrum.plugin import run_hook
from electrum.paymentrequest import PR_UNKNOWN
from electrum.wallet import InternalAddressCorruption

from .util import MyTreeView, pr_tooltips, pr_icons

class RequestList(MyTreeView):
    filter_columns = [0, 1, 2, 3, 4]  # Date, Account, Address, Description, Amount


    def __init__(self, parent):
        super().__init__(parent, self.create_menu, 3, editable_columns=[])
        self.setModel(QStandardItemModel(self))
        self.setSortingEnabled(True)
        self.setColumnWidth(0, 180)
        self.update()
        self.selectionModel().currentRowChanged.connect(self.item_changed)

    def item_changed(self, idx):
        # TODO use siblingAtColumn when min Qt version is >=5.11
        addr = self.model().itemFromIndex(idx.sibling(idx.row(), 1)).text()
        req = self.wallet.receive_requests.get(addr)
        if req is None:
            self.update()
            return
        expires = age(req['time'] + req['exp']) if req.get('exp') else _('Never')
        amount = req['amount']
        message = req['memo']
        self.parent.receive_address_e.setText(addr)
        self.parent.receive_message_e.setText(message)
        self.parent.receive_amount_e.setAmount(amount)
        self.parent.expires_combo.hide()
        self.parent.expires_label.show()
        self.parent.expires_label.setText(expires)
        self.parent.new_request_button.setEnabled(True)

    def update(self):
        self.wallet = self.parent.wallet
        # hide receive tab if no receive requests available
        if self.parent.isVisible():
            b = len(self.wallet.receive_requests) > 0
            self.setVisible(b)
            self.parent.receive_requests_label.setVisible(b)
            if not b:
                self.parent.expires_label.hide()
                self.parent.expires_combo.show()

        # update the receive address if necessary
        current_address = self.parent.receive_address_e.text()
        domain = self.wallet.get_receiving_addresses()
        try:
            addr = self.wallet.get_unused_address()
        except InternalAddressCorruption as e:
            self.parent.show_error(str(e))
            addr = ''
        if not current_address in domain and addr:
            self.parent.set_receive_address(addr)
        self.parent.new_request_button.setEnabled(addr != current_address)

        self.model().clear()
        self.update_headers([_('Date'), _('Address'), '', _('Description'), _('Amount'), _('Status')])
        self.hideColumn(1) # hide address column
        for req in self.wallet.get_sorted_requests(self.config):
            address = req['address']
            if address not in domain:
                continue
            timestamp = req.get('time', 0)
            amount = req.get('amount')
            expiration = req.get('exp', None)
            message = req['memo']
            date = format_time(timestamp)
            status = req.get('status')
            signature = req.get('sig')
            requestor = req.get('name', '')
            amount_str = self.parent.format_amount(amount) if amount else ""
            labels = [date, address, '', message, amount_str, pr_tooltips.get(status,'')]
            items = [QStandardItem(e) for e in labels]
            self.set_editability(items)
            if signature is not None:
                items[2].setIcon(self.icon_cache.get(":icons/seal.png"))
                items[2].setToolTip('signed by '+ requestor)
            if status is not PR_UNKNOWN:
                items[5].setIcon(self.icon_cache.get(pr_icons.get(status)))
            items[3].setData(address, Qt.UserRole)
            self.model().insertRow(self.model().rowCount(), items)

    def create_menu(self, position):
        idx = self.indexAt(position)
        # TODO use siblingAtColumn when min Qt version is >=5.11
        item = self.model().itemFromIndex(idx.sibling(idx.row(), 1))
        if not item:
            return
        addr = item.text()
        req = self.wallet.receive_requests.get(addr)
        if req is None:
            self.update()
            return
        column = idx.column()
        column_title = self.model().horizontalHeaderItem(column).text()
        column_data = item.text()
        menu = QMenu(self)
        if column != 2:
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
        menu.addAction(_("Copy URI"), lambda: self.parent.view_and_paste('URI', '', self.parent.get_request_URI(addr)))
        menu.addAction(_("Save as BIP70 file"), lambda: self.parent.export_payment_request(addr))
        menu.addAction(_("Delete"), lambda: self.parent.delete_payment_request(addr))
        run_hook('receive_list_menu', menu, addr)
        menu.exec_(self.viewport().mapToGlobal(position))
