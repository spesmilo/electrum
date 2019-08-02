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

from typing import Optional, List
from enum import IntEnum

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView, QMenu

from electrum.i18n import _

from .util import MyTreeView, ColorScheme, MONOSPACE_FONT

class UTXOList(MyTreeView):

    class Columns(IntEnum):
        OUTPOINT = 0
        ADDRESS = 1
        LABEL = 2
        AMOUNT = 3
        HEIGHT = 4

    headers = {
        Columns.ADDRESS: _('Address'),
        Columns.LABEL: _('Label'),
        Columns.AMOUNT: _('Amount'),
        Columns.HEIGHT: _('Height'),
        Columns.OUTPOINT: _('Output point'),
    }
    filter_columns = [Columns.ADDRESS, Columns.LABEL, Columns.OUTPOINT]

    def __init__(self, parent=None):
        super().__init__(parent, self.create_menu,
                         stretch_column=self.Columns.LABEL,
                         editable_columns=[])
        self.setModel(QStandardItemModel(self))
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.update()

    def update(self):
        self.wallet = self.parent.wallet
        utxos = self.wallet.get_utxos()
        self.utxo_dict = {}
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, x in enumerate(utxos):
            self.insert_utxo(idx, x)
        self.filter()

    def insert_utxo(self, idx, x):
        address = x['address']
        height = x.get('height')
        name = x.get('prevout_hash') + ":%d"%x.get('prevout_n')
        name_short = x.get('prevout_hash')[:16] + '...' + ":%d"%x.get('prevout_n')
        self.utxo_dict[name] = x
        label = self.wallet.get_label(x.get('prevout_hash'))
        amount = self.parent.format_amount(x['value'], whitespaces=True)
        labels = [name_short, address, label, amount, '%d'%height]
        utxo_item = [QStandardItem(x) for x in labels]
        self.set_editability(utxo_item)
        utxo_item[self.Columns.ADDRESS].setFont(QFont(MONOSPACE_FONT))
        utxo_item[self.Columns.AMOUNT].setFont(QFont(MONOSPACE_FONT))
        utxo_item[self.Columns.OUTPOINT].setFont(QFont(MONOSPACE_FONT))
        utxo_item[self.Columns.ADDRESS].setData(name, Qt.UserRole)
        if self.wallet.is_frozen_address(address):
            utxo_item[self.Columns.ADDRESS].setBackground(ColorScheme.BLUE.as_color(True))
            utxo_item[self.Columns.ADDRESS].setToolTip(_('Address is frozen'))
        if self.wallet.is_frozen_coin(x):
            utxo_item[self.Columns.OUTPOINT].setBackground(ColorScheme.BLUE.as_color(True))
            utxo_item[self.Columns.OUTPOINT].setToolTip(f"{name}\n{_('Coin is frozen')}")
        else:
            utxo_item[self.Columns.OUTPOINT].setToolTip(name)
        self.model().insertRow(idx, utxo_item)

    def get_selected_outpoints(self) -> Optional[List[str]]:
        if not self.model():
            return None
        items = self.selected_in_column(self.Columns.ADDRESS)
        if not items:
            return None
        return [x.data(Qt.UserRole) for x in items]

    def create_menu(self, position):
        selected = self.get_selected_outpoints()
        if not selected:
            return
        menu = QMenu()
        menu.setSeparatorsCollapsible(True)  # consecutive separators are merged together
        coins = [self.utxo_dict[name] for name in selected]
        menu.addAction(_("Spend"), lambda: self.parent.spend_coins(coins))
        assert len(coins) >= 1, len(coins)
        if len(coins) == 1:
            utxo_dict = coins[0]
            addr = utxo_dict['address']
            txid = utxo_dict['prevout_hash']
            # "Details"
            tx = self.wallet.db.get_transaction(txid)
            if tx:
                label = self.wallet.get_label(txid) or None # Prefer None if empty (None hides the Description: field in the window)
                menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx, label))
            # "Copy ..."
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            col = idx.column()
            column_title = self.model().horizontalHeaderItem(col).text()
            copy_text = self.model().itemFromIndex(idx).text() if col != self.Columns.OUTPOINT else selected[0]
            if col == self.Columns.AMOUNT:
                copy_text = copy_text.strip()
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(copy_text))
            # "Freeze coin"
            if not self.wallet.is_frozen_coin(utxo_dict):
                menu.addAction(_("Freeze Coin"), lambda: self.parent.set_frozen_state_of_coins([utxo_dict], True))
            else:
                menu.addSeparator()
                menu.addAction(_("Coin is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Coin"), lambda: self.parent.set_frozen_state_of_coins([utxo_dict], False))
                menu.addSeparator()
            # "Freeze address"
            if not self.wallet.is_frozen_address(addr):
                menu.addAction(_("Freeze Address"), lambda: self.parent.set_frozen_state_of_addresses([addr], True))
            else:
                menu.addSeparator()
                menu.addAction(_("Address is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Address"), lambda: self.parent.set_frozen_state_of_addresses([addr], False))
                menu.addSeparator()
        else:
            # multiple items selected
            menu.addSeparator()
            addrs = [utxo_dict['address'] for utxo_dict in coins]
            is_coin_frozen = [self.wallet.is_frozen_coin(utxo_dict) for utxo_dict in coins]
            is_addr_frozen = [self.wallet.is_frozen_address(utxo_dict['address']) for utxo_dict in coins]
            if not all(is_coin_frozen):
                menu.addAction(_("Freeze Coins"), lambda: self.parent.set_frozen_state_of_coins(coins, True))
            if any(is_coin_frozen):
                menu.addAction(_("Unfreeze Coins"), lambda: self.parent.set_frozen_state_of_coins(coins, False))
            if not all(is_addr_frozen):
                menu.addAction(_("Freeze Addresses"), lambda: self.parent.set_frozen_state_of_addresses(addrs, True))
            if any(is_addr_frozen):
                menu.addAction(_("Unfreeze Addresses"), lambda: self.parent.set_frozen_state_of_addresses(addrs, False))

        menu.exec_(self.viewport().mapToGlobal(position))
