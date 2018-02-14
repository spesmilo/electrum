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

import webbrowser

from electrum.wallet import UnrelatedTransactionException, TX_HEIGHT_LOCAL
from .util import *
from electrum.i18n import _
from electrum.util import block_explorer_URL
from electrum.util import timestamp_to_datetime, profiler


# note: this list needs to be kept in sync with another in kivy
TX_ICONS = [
    "warning.png",
    "warning.png",
    "unconfirmed.png",
    "unconfirmed.png",
    "offline_tx.png",
    "clock1.png",
    "clock2.png",
    "clock3.png",
    "clock4.png",
    "clock5.png",
    "confirmed.png",
]


class HistoryList(MyTreeWidget, AcceptFileDragDrop):
    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 3)
        AcceptFileDragDrop.__init__(self, ".txn")
        self.refresh_headers()
        self.setColumnHidden(1, True)

    def refresh_headers(self):
        headers = ['', '', _('Date'), _('Description') , _('Amount'), _('Balance')]
        fx = self.parent.fx
        if fx and fx.show_history():
            headers.extend(['%s '%fx.ccy + _('Value')])
            headers.extend(['%s '%fx.ccy + _('Acquisition price')])
            headers.extend(['%s '%fx.ccy + _('Capital Gains')])
            self.editable_columns.extend([6])
        self.update_headers(headers)

    def get_domain(self):
        '''Replaced in address_dialog.py'''
        return self.wallet.get_addresses()

    @profiler
    def on_update(self):
        self.wallet = self.parent.wallet
        h = self.wallet.get_history(self.get_domain())
        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole) if item else None
        self.clear()
        fx = self.parent.fx
        if fx: fx.history_used_spot = False
        for h_item in h:
            tx_hash, height, conf, timestamp, value, balance = h_item
            status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
            has_invoice = self.wallet.invoices.paid.get(tx_hash)
            icon = QIcon(":icons/" + TX_ICONS[status])
            v_str = self.parent.format_amount(value, True, whitespaces=True)
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            label = self.wallet.get_label(tx_hash)
            entry = ['', tx_hash, status_str, label, v_str, balance_str]
            fiat_value = None
            if value is not None and fx and fx.show_history():
                date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
                fiat_value = self.wallet.get_fiat_value(tx_hash, fx.ccy)
                if not fiat_value:
                    fiat_value = fx.historical_value(value, date)
                    fiat_default = True
                else:
                    fiat_default = False
                value_str = fx.format_fiat(fiat_value)
                entry.append(value_str)
                # fixme: should use is_mine
                if value < 0:
                    ap, lp = self.wallet.capital_gain(tx_hash, fx.timestamp_rate, fx.ccy)
                    cg = None if lp is None or ap is None else lp - ap
                    entry.append(fx.format_fiat(ap))
                    entry.append(fx.format_fiat(cg))
            item = QTreeWidgetItem(entry)
            item.setIcon(0, icon)
            item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))
            if has_invoice:
                item.setIcon(3, QIcon(":icons/seal"))
            for i in range(len(entry)):
                if i>3:
                    item.setTextAlignment(i, Qt.AlignRight)
                if i!=2:
                    item.setFont(i, QFont(MONOSPACE_FONT))
            if value and value < 0:
                item.setForeground(3, QBrush(QColor("#BC1E1E")))
                item.setForeground(4, QBrush(QColor("#BC1E1E")))
            if fiat_value and not fiat_default:
                item.setForeground(6, QBrush(QColor("#1E1EFF")))
            if tx_hash:
                item.setData(0, Qt.UserRole, tx_hash)
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash:
                self.setCurrentItem(item)

    def on_edited(self, item, column, prior):
        '''Called only when the text actually changes'''
        key = item.data(0, Qt.UserRole)
        text = item.text(column)
        # fixme
        if column == 3:
            self.parent.wallet.set_label(key, text)
            self.update_labels()
            self.parent.update_completions()
        elif column == 6:
            self.parent.wallet.set_fiat_value(key, self.parent.fx.ccy, text)
            self.on_update()

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            super(HistoryList, self).on_doubleclick(item, column)
        else:
            tx_hash = item.data(0, Qt.UserRole)
            tx = self.wallet.transactions.get(tx_hash)
            self.parent.show_transaction(tx)

    def update_labels(self):
        root = self.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            txid = item.data(0, Qt.UserRole)
            label = self.wallet.get_label(txid)
            item.setText(3, label)

    def update_item(self, tx_hash, height, conf, timestamp):
        status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
        icon = QIcon(":icons/" +  TX_ICONS[status])
        items = self.findItems(tx_hash, Qt.UserRole|Qt.MatchContains|Qt.MatchRecursive, column=1)
        if items:
            item = items[0]
            item.setIcon(0, icon)
            item.setText(2, status_str)

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

        tx_URL = block_explorer_URL(self.config, 'tx', tx_hash)
        height, conf, timestamp = self.wallet.get_tx_height(tx_hash)
        tx = self.wallet.transactions.get(tx_hash)
        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
        is_unconfirmed = height <= 0
        pr_key = self.wallet.invoices.paid.get(tx_hash)

        menu = QMenu()

        if height == TX_HEIGHT_LOCAL:
            menu.addAction(_("Remove"), lambda: self.remove_local_tx(tx_hash))

        menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
        for c in self.editable_columns:
            menu.addAction(_("Edit {}").format(self.headerItem().text(c)), lambda: self.editItem(item, c))

        menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx))

        if is_unconfirmed and tx:
            rbf = is_mine and not tx.is_final()
            if rbf:
                menu.addAction(_("Increase fee"), lambda: self.parent.bump_fee_dialog(tx))
            else:
                child_tx = self.wallet.cpfp(tx, 0)
                if child_tx:
                    menu.addAction(_("Child pays for parent"), lambda: self.parent.cpfp(tx, child_tx))
        if pr_key:
            menu.addAction(QIcon(":icons/seal"), _("View invoice"), lambda: self.parent.show_invoice(pr_key))
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webbrowser.open(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))

    def remove_local_tx(self, delete_tx):
        to_delete = {delete_tx}
        to_delete |= self.wallet.get_depending_transactions(delete_tx)

        question = _("Are you sure you want to remove this transaction?")
        if len(to_delete) > 1:
            question = _(
                "Are you sure you want to remove this transaction and {} child transactions?".format(len(to_delete) - 1)
            )

        answer = QMessageBox.question(self.parent, _("Please confirm"), question, QMessageBox.Yes, QMessageBox.No)
        if answer == QMessageBox.No:
            return
        for tx in to_delete:
            self.wallet.remove_transaction(tx)
        self.wallet.save_transactions(write=True)
        # need to update at least: history_list, utxo_list, address_list
        self.parent.need_update.set()

    def onFileAdded(self, fn):
        with open(fn) as f:
            tx = self.parent.tx_from_text(f.read())
            try:
                self.wallet.add_transaction(tx.txid(), tx)
            except UnrelatedTransactionException as e:
                self.parent.show_error(e)
            else:
                self.wallet.save_transactions(write=True)
                # need to update at least: history_list, utxo_list, address_list
                self.parent.need_update.set()
