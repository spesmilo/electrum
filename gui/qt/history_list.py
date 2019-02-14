#!/usr/bin/env python3
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

import webbrowser

from .util import *
import electroncash.web as web
from electroncash.i18n import _
from electroncash.util import timestamp_to_datetime, profiler, Weak


TX_ICONS = [
    "warning.png",
    "warning.png",
    "unconfirmed.png",
    "unconfirmed.png",
    "clock1.png",
    "clock2.png",
    "clock3.png",
    "clock4.png",
    "clock5.png",
    "confirmed.png",
]


class HistoryList(MyTreeWidget):
    filter_columns = [2, 3, 4]  # Date, Description, Amount
    statusIcons = {}

    def __init__(self, parent=None):
        super().__init__(parent, self.create_menu, [], 3)
        self.refresh_headers()
        self.setColumnHidden(1, True)
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.AscendingOrder)
        # force attributes to always be defined, even if None, at construction.
        self.wallet = self.parent.wallet if hasattr(self.parent, 'wallet') else None

        self.monospaceFont = QFont(MONOSPACE_FONT)
        self.withdrawalBrush = QBrush(QColor("#BC1E1E"))
        self.invoiceIcon = QIcon(":icons/seal")
        self._item_cache = Weak.ValueDictionary()

    def refresh_headers(self):
        headers = ['', '', _('Date'), _('Description') , _('Amount'), _('Balance')]
        fx = self.parent.fx
        if fx and fx.show_history():
            headers.extend(['%s '%fx.ccy + _('Amount'), '%s '%fx.ccy + _('Balance')])
        self.update_headers(headers)

    def get_domain(self):
        '''Replaced in address_dialog.py'''
        return self.wallet.get_addresses()

    @rate_limited(1.0, classlevel=True, ts_after=True) # We rate limit the history list refresh no more than once every second, app-wide
    def update(self):
        if self.wallet and (not self.wallet.thread or not self.wallet.thread.isRunning()):
            # short-cut return if window was closed and wallet is stopped
            return
        super().update()

    def clear(self):
        self._item_cache.clear()
        super().clear()

    def insertTopLevelItem(self, index, item, tx_hash=None):
        super().insertTopLevelItem(index, item)
        tx_hash = tx_hash or item.data(0, Qt.UserRole)
        if tx_hash:
            self._item_cache[tx_hash] = item

    @classmethod
    def _get_icon_for_status(cls, status):
        ret = cls.statusIcons.get(status)
        if not ret:
            cls.statusIcons[status] = ret = QIcon(":icons/" + TX_ICONS[status])
        return ret

    @profiler
    def on_update(self):
        self.wallet = self.parent.wallet
        h = self.wallet.get_history(self.get_domain())
        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole) if item else None
        del item  #  make sure not to hold stale ref to C++ item which will be deleted in clear() call below
        self.clear()
        fx = self.parent.fx
        if fx: fx.history_used_spot = False
        for h_item in h:
            tx_hash, height, conf, timestamp, value, balance = h_item
            status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
            has_invoice = self.wallet.invoices.paid.get(tx_hash)
            icon = self._get_icon_for_status(status)
            v_str = self.parent.format_amount(value, True, whitespaces=True)
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            label = self.wallet.get_label(tx_hash)
            entry = ['', tx_hash, status_str, label, v_str, balance_str]
            if fx and fx.show_history():
                date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
                for amount in [value, balance]:
                    text = fx.historical_value_str(amount, date)
                    entry.append(text)
            item = SortableTreeWidgetItem(entry)
            if icon: item.setIcon(0, icon)
            item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))
            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            if has_invoice:
                item.setIcon(3, self.invoiceIcon)
            for i in range(len(entry)):
                if i>3:
                    item.setTextAlignment(i, Qt.AlignRight)
                if i!=2:
                    item.setFont(i, self.monospaceFont)
            if value and value < 0:
                item.setForeground(3, self.withdrawalBrush)
                item.setForeground(4, self.withdrawalBrush)
            item.setData(0, Qt.UserRole, tx_hash)
            self.insertTopLevelItem(0, item, tx_hash)
            if current_tx == tx_hash:
                self.setCurrentItem(item)

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            super(HistoryList, self).on_doubleclick(item, column)
        else:
            tx_hash = item.data(0, Qt.UserRole)
            tx = self.wallet.transactions.get(tx_hash)
            if tx:
                label = self.wallet.get_label(tx_hash) or None
                self.parent.show_transaction(tx, label)

    def update_labels(self):
        root = self.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            txid = item.data(0, Qt.UserRole)
            label = self.wallet.get_label(txid)
            item.setText(3, label)

    def update_item(self, tx_hash, height, conf, timestamp):
        if not self.wallet: return # can happen on startup if this is called before self.on_update()
        item = self._item_cache.get(tx_hash)
        if item:
            status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
            icon = self._get_icon_for_status(status)
            if icon: item.setIcon(0, icon)
            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            item.setText(2, status_str)
        return bool(item)  # indicate to client code whether an actual update occurred

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return
        column = self.currentColumn()
        tx_hash = item.data(0, Qt.UserRole)
        if not tx_hash:
            return
        if column is 0:
            column_title = "ID"
            column_data = tx_hash
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column)

        tx_URL = web.BE_URL(self.config, 'tx', tx_hash)
        height, conf, timestamp = self.wallet.get_tx_height(tx_hash)
        tx = self.wallet.transactions.get(tx_hash)
        if not tx: return # this happens sometimes on wallet synch when first starting up.
        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
        is_unconfirmed = height <= 0
        pr_key = self.wallet.invoices.paid.get(tx_hash)

        menu = QMenu()

        menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
        if column in self.editable_columns:
            # We grab a fresh reference to the current item, as it has been deleted in a reported issue.
            menu.addAction(_("Edit {}").format(column_title),
                lambda: self.currentItem() and self.editItem(self.currentItem(), column))
        label = self.wallet.get_label(tx_hash) or None
        menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx, label))
        if is_unconfirmed and tx:
            child_tx = self.wallet.cpfp(tx, 0)
            if child_tx:
                menu.addAction(_("Child pays for parent"), lambda: self.parent.cpfp(tx, child_tx))
        if pr_key:
            menu.addAction(self.invoiceIcon, _("View invoice"), lambda: self.parent.show_invoice(pr_key))
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webbrowser.open(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))
