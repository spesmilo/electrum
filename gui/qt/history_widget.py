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
from electrum.util import format_satoshis, format_time
from electrum.plugins import run_hook


class HistoryWidget(MyTreeWidget):

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [ '', _('Date'), _('Description') , _('Amount'), _('Balance')], [40, 140, None, 140, 140])
        self.config = self.parent.config

    def update(self, h):
        self.wallet = self.parent.wallet
        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole).toString() if item else None
        self.clear()
        for item in h:
            tx_hash, conf, value, timestamp, balance = item
            time_str = _("unknown")
            if conf is None and timestamp is None:
                continue  # skip history in offline mode
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
            v_str = self.parent.format_amount(value, True, whitespaces=True)
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            label, is_default_label = self.wallet.get_label(tx_hash)
            item = QTreeWidgetItem( [ '', time_str, label, v_str, balance_str] )
            item.setFont(2, QFont(MONOSPACE_FONT))
            item.setFont(3, QFont(MONOSPACE_FONT))
            item.setFont(4, QFont(MONOSPACE_FONT))
            if value < 0:
                item.setForeground(3, QBrush(QColor("#BC1E1E")))
            if tx_hash:
                item.setData(0, Qt.UserRole, tx_hash)
            if is_default_label:
                item.setForeground(2, QBrush(QColor('grey')))
            item.setIcon(0, icon)
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash:
                self.setCurrentItem(item)

        run_hook('history_tab_update')


    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        be = self.config.get('block_explorer', 'Blockchain.info')
        if be == 'Blockchain.info':
            block_explorer = 'https://blockchain.info/tx/'
        elif be == 'Blockr.io':
            block_explorer = 'https://blockr.io/tx/info/'
        elif be == 'Insight.is':
            block_explorer = 'http://live.insight.is/tx/'
        elif be == "Blocktrail.com":
            block_explorer = 'https://www.blocktrail.com/BTC/tx/'
        if not item:
            return
        tx_hash = str(item.data(0, Qt.UserRole).toString())
        if not tx_hash:
            return
        menu = QMenu()
        menu.addAction(_("Copy ID to Clipboard"), lambda: self.parent.app.clipboard().setText(tx_hash))
        menu.addAction(_("Details"), lambda: self.parent.show_transaction(self.wallet.transactions.get(tx_hash)))
        menu.addAction(_("Edit description"), lambda: self.edit_label(item))
        menu.addAction(_("View on block explorer"), lambda: webbrowser.open(block_explorer + tx_hash))
        menu.exec_(self.viewport().mapToGlobal(position))

