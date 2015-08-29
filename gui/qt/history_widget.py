#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import webbrowser

from util import *
from electrum.i18n import _
from electrum.util import block_explorer_URL, format_satoshis, format_time
from electrum.plugins import run_hook


class HistoryWidget(MyTreeWidget):

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, ['', '', _('Date'), _('Description') , _('Amount'), _('Balance')], 3)
        self.setColumnHidden(1, True)
        self.config = self.parent.config
        self.setSortingEnabled(False)

    def get_icon(self, conf, timestamp):
        time_str = _("unknown")
        if conf > 0:
            time_str = format_time(timestamp)
        if conf == -1:
            time_str = 'unverified'
            icon = QIcon(":icons/unconfirmed.png")
        elif conf == 0:
            time_str = 'pending'
            icon = QIcon(":icons/unconfirmed.png")
        elif conf < 6:
            icon = QIcon(":icons/clock%d.png"%conf)
        else:
            icon = QIcon(":icons/confirmed.png")
        return icon, time_str

    def update(self, h):
        self.wallet = self.parent.wallet
        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole).toString() if item else None
        self.clear()
        for item in h:
            tx_hash, conf, value, timestamp, balance = item
            if conf is None and timestamp is None:
                continue  # skip history in offline mode
            icon, time_str = self.get_icon(conf, timestamp)
            v_str = self.parent.format_amount(value, True, whitespaces=True)
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            label, is_default_label = self.wallet.get_label(tx_hash)
            item = EditableItem(['', tx_hash, time_str, label, v_str, balance_str])
            item.setIcon(0, icon)
            item.setFont(3, QFont(MONOSPACE_FONT))
            item.setFont(4, QFont(MONOSPACE_FONT))
            item.setFont(5, QFont(MONOSPACE_FONT))
            if value < 0:
                item.setForeground(4, QBrush(QColor("#BC1E1E")))
            if tx_hash:
                item.setData(0, Qt.UserRole, tx_hash)
            if is_default_label:
                item.setForeground(3, QBrush(QColor('grey')))
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash:
                self.setCurrentItem(item)
        run_hook('history_tab_update')

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
        menu.addAction(_("Edit description"), lambda: self.edit_label(item))
        menu.addAction(_("View on block explorer"), lambda: webbrowser.open(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))
