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

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QMenu, QHeaderView
from PyQt5.QtCore import Qt, QItemSelectionModel

from electrum.i18n import _
from electrum.util import format_time, age
from electrum.plugin import run_hook
from electrum.paymentrequest import PR_UNKNOWN
from electrum.wallet import InternalAddressCorruption
from electrum.bitcoin import COIN
from electrum.lnaddr import lndecode
import electrum.constants as constants

from .util import MyTreeView, pr_tooltips, pr_icons, read_QIcon

REQUEST_TYPE_BITCOIN = 0
REQUEST_TYPE_LN = 1

ROLE_REQUEST_TYPE = Qt.UserRole
ROLE_RHASH_OR_ADDR = Qt.UserRole + 1

class RequestList(MyTreeView):

    class Columns(IntEnum):
        DATE = 0
        ADDRESS = 1
        SIGNATURE = 2
        DESCRIPTION = 3
        AMOUNT = 4
        STATUS = 5

    headers = {
        Columns.DATE: _('Date'),
        Columns.ADDRESS: _('Address'),
        Columns.SIGNATURE: '',
        Columns.DESCRIPTION: _('Description'),
        Columns.AMOUNT: _('Amount'),
        Columns.STATUS: _('Status'),
    }
    filter_columns = [Columns.DATE, Columns.ADDRESS, Columns.SIGNATURE, Columns.DESCRIPTION, Columns.AMOUNT]

    def __init__(self, parent):
        super().__init__(parent, self.create_menu,
                         stretch_column=self.Columns.DESCRIPTION,
                         editable_columns=[])
        self.setModel(QStandardItemModel(self))
        self.setSortingEnabled(True)
        self.update()
        self.selectionModel().currentRowChanged.connect(self.item_changed)
        self.setColumnWidth(self.Columns.ADDRESS, 250)

    def select_key(self, key):
        for i in range(self.model().rowCount()):
            item = self.model().index(i, 0)
            row_key = item.data(ROLE_RHASH_OR_ADDR)
            if item.data(ROLE_REQUEST_TYPE) == REQUEST_TYPE_LN:
                row_key = self.wallet.lnworker.invoices[row_key][1]
            if key == row_key:
                self.selectionModel().setCurrentIndex(item, QItemSelectionModel.SelectCurrent | QItemSelectionModel.Rows)
                break

    def item_changed(self, idx):
        # TODO use siblingAtColumn when min Qt version is >=5.11
        addr = self.model().itemFromIndex(idx.sibling(idx.row(), self.Columns.ADDRESS)).text()
        req = self.wallet.receive_requests.get(addr)
        item = self.model().itemFromIndex(idx.sibling(idx.row(), 0))
        request_type = item.data(ROLE_REQUEST_TYPE)
        key = item.data(ROLE_RHASH_OR_ADDR)
        if request_type == REQUEST_TYPE_BITCOIN:
            if req is None:
                self.update()
                return
            req = self.parent.get_request_URI(key)
        elif request_type == REQUEST_TYPE_LN:
            preimage, req = self.wallet.lnworker.invoices.get(key, (None, None))
            if req is None:
                self.update()
                return
        self.parent.receive_address_e.setText(req)

    def update(self):
        self.wallet = self.parent.wallet
        # hide receive tab if no receive requests available
        if self.parent.isVisible():
            b = len(self.wallet.receive_requests) > 0 or len(self.wallet.lnworker.invoices) > 0
            self.setVisible(b)
            self.parent.receive_requests_label.setVisible(b)
            if not b:
                self.parent.expires_label.hide()
                self.parent.expires_combo.show()

        domain = self.wallet.get_receiving_addresses()
        try:
            addr = self.wallet.get_unused_address()
        except InternalAddressCorruption as e:
            self.parent.show_error(str(e))
            addr = ''
        if current_address not in domain and addr:
            self.parent.set_receive_address(addr)
        self.parent.new_request_button.setEnabled(addr != current_address)
        self.parent.update_receive_address_styling()

        self.model().clear()
        self.update_headers(self.__class__.headers)
        self.header().setSectionResizeMode(self.Columns.ADDRESS, QHeaderView.Interactive) # override resizemode in update_headers
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
                items[self.Columns.SIGNATURE].setIcon(read_QIcon("seal.png"))
                items[self.Columns.SIGNATURE].setToolTip(f'signed by {requestor}')
            if status is not PR_UNKNOWN:
                items[self.Columns.STATUS].setIcon(read_QIcon(pr_icons.get(status)))
            self.model().insertRow(self.model().rowCount(), items)
            items[0].setData(REQUEST_TYPE_BITCOIN, ROLE_REQUEST_TYPE)
            items[0].setData(address, ROLE_RHASH_OR_ADDR)
        self.filter()
        # lightning
        for payreq_key, (preimage_hex, invoice) in self.wallet.lnworker.invoices.items():
            lnaddr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
            amount_sat = lnaddr.amount*COIN if lnaddr.amount else None
            amount_str = self.parent.format_amount(amount_sat) if amount_sat else ''
            description = ''
            for k,v in lnaddr.tags:
                if k == 'd':
                    description = v
                    break
            date = format_time(lnaddr.date)
            labels = [date, invoice, '', description, amount_str, '']
            items = [QStandardItem(e) for e in labels]
            items[2].setIcon(self.icon_cache.get(":icons/lightning.png"))
            items[0].setData(REQUEST_TYPE_LN, ROLE_REQUEST_TYPE)
            items[0].setData(payreq_key, ROLE_RHASH_OR_ADDR)
            self.model().insertRow(self.model().rowCount(), items)

    def create_menu(self, position):
        idx = self.indexAt(position)
        item = self.model().itemFromIndex(idx)
        # TODO use siblingAtColumn when min Qt version is >=5.11
        item = self.model().itemFromIndex(idx.sibling(idx.row(), self.Columns.DATE))
        if not item:
            return
        addr = item.data(ROLE_RHASH_OR_ADDR)
        request_type = item.data(ROLE_REQUEST_TYPE)
        menu = None
        assert request_type in [REQUEST_TYPE_BITCOIN, REQUEST_TYPE_LN]
        if request_type == REQUEST_TYPE_BITCOIN:
            req = self.wallet.receive_requests.get(addr)
        elif request_type == REQUEST_TYPE_LN:
            preimage, req = self.wallet.lnworker.invoices.get(addr)
        if req is None:
            self.update()
            return
        column = idx.column()
        column_title = self.model().horizontalHeaderItem(column).text()
        column_data = self.model().itemFromIndex(idx).text()
        menu = QMenu(self)
        if column != self.Columns.SIGNATURE:
            if column == self.Columns.AMOUNT:
                column_data = column_data.strip()
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
        if request_type == REQUEST_TYPE_BITCOIN:
            self.create_menu_bitcoin_payreq(menu, addr)
        elif request_type == REQUEST_TYPE_LN:
            self.create_menu_ln_payreq(menu, addr, req)
        menu.exec_(self.viewport().mapToGlobal(position))

    def create_menu_bitcoin_payreq(self, menu, addr):
        menu.addAction(_("Copy URI"), lambda: self.parent.view_and_paste('URI', '', self.parent.get_request_URI(addr)))
        menu.addAction(_("Save as BIP70 file"), lambda: self.parent.export_payment_request(addr))
        menu.addAction(_("Delete"), lambda: self.parent.delete_payment_request(addr))
        run_hook('receive_list_menu', menu, addr)

    def create_menu_ln_payreq(self, menu, payreq_key, req):
        menu.addAction(_("Copy Lightning invoice"), lambda: self.parent.view_and_paste('Invoice', '', req))
        menu.addAction(_("Delete"), lambda: self.parent.delete_lightning_payreq(payreq_key))
