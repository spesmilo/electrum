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

from util import *
from electrum.i18n import _
from electrum.util import block_explorer_URL, format_satoshis, format_time
from electrum.plugins import run_hook


class HistoryWidget(MyTreeWidget):

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 3)
        self.refresh_headers()
        self.setColumnHidden(1, True)
        self.config = self.parent.config

    def refresh_headers(self):
        headers = ['', '', _('Date'), _('Description') , _('Amount'),
                   _('Balance')]
        run_hook('history_tab_headers', headers)
        self.update_headers(headers)

    def get_icon(self, conf, timestamp):
        time_str = _("unknown")
        if conf > 0:
            time_str = format_time(timestamp)
        if conf == -1:
            time_str = _('Not Verified')
            icon = QIcon(":icons/unconfirmed.png")
        elif conf == 0:
            time_str = _('Unconfirmed')
            icon = QIcon(":icons/unconfirmed.png")
        elif conf < 6:
            icon = QIcon(":icons/clock%d.png"%conf)
        else:
            icon = QIcon(":icons/confirmed.png")
        return icon, time_str

    def get_domain(self):
        '''Replaced in address_dialog.py'''
        return self.wallet.get_account_addresses(self.parent.current_account)

    def on_update(self):
        self.wallet = self.parent.wallet
        h = self.wallet.get_history(self.get_domain())

        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole).toString() if item else None
        self.clear()
        run_hook('history_tab_update_begin')
        for tx in h:
            tx_hash, conf, value, timestamp, balance = tx
            if conf is None and timestamp is None:
                continue  # skip history in offline mode
            icon, time_str = self.get_icon(conf, timestamp)
            v_str = self.parent.format_amount(value, True, whitespaces=True)
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            label = self.wallet.get_label(tx_hash)
            entry = ['', tx_hash, time_str, label, v_str, balance_str]
            run_hook('history_tab_update', tx, entry)
            item = QTreeWidgetItem(entry)
            item.setIcon(0, icon)
            for i in range(len(entry)):
                if i>3:
                    item.setTextAlignment(i, Qt.AlignRight)
                if i!=2:
                    item.setFont(i, QFont(MONOSPACE_FONT))
            if value < 0:
                item.setForeground(3, QBrush(QColor("#BC1E1E")))
                item.setForeground(4, QBrush(QColor("#BC1E1E")))
            if tx_hash:
                item.setData(0, Qt.UserRole, tx_hash)
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash:
                self.setCurrentItem(item)

    def update_item(self, tx_hash, conf, timestamp):
        icon, time_str = self.get_icon(conf, timestamp)
        items = self.findItems(tx_hash, Qt.UserRole|Qt.MatchContains|Qt.MatchRecursive, column=1)
        if items:
            item = items[0]
            item.setIcon(0, icon)
            item.setText(2, time_str)

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return
        tx_hash = str(item.data(0, Qt.UserRole).toString())
        if not tx_hash:
            return
        tx_URL = block_explorer_URL(self.config, 'tx', tx_hash)
        if not tx_URL:
            return
        menu = QMenu()
        menu.addAction(_("Copy ID to Clipboard"), lambda: self.parent.app.clipboard().setText(tx_hash))
        menu.addAction(_("Details"), lambda: self.parent.show_transaction(self.wallet.transactions.get(tx_hash)))
        menu.addAction(_("Edit description"), lambda: self.editItem(item, self.editable_columns[0]))
        menu.addAction(_("View on block explorer"), lambda: webbrowser.open(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))
