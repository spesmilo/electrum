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

from electrum.i18n import _

from .util import *

class UTXOList(MyTreeView):
    filter_columns = [0, 1]  # Address, Label

    def __init__(self, parent=None):
        super().__init__(parent, self.create_menu, 1, editable_columns=[])
        self.setModel(QStandardItemModel(self))
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.update()

    def update(self):
        self.wallet = self.parent.wallet
        utxos = self.wallet.get_utxos()
        self.utxo_dict = {}
        self.model().clear()
        self.update_headers([ _('Address'), _('Label'), _('Amount'), _('Height'), _('Output point')])
        for idx, x in enumerate(utxos):
            address = x.get('address')
            height = x.get('height')
            name = x.get('prevout_hash') + ":%d"%x.get('prevout_n')
            self.utxo_dict[name] = x
            label = self.wallet.get_label(x.get('prevout_hash'))
            amount = self.parent.format_amount(x['value'], whitespaces=True)
            labels = [address, label, amount, '%d'%height, name[0:10] + '...' + name[-2:]]
            utxo_item = [QStandardItem(x) for x in labels]
            self.set_editability(utxo_item)
            utxo_item[0].setFont(QFont(MONOSPACE_FONT))
            utxo_item[2].setFont(QFont(MONOSPACE_FONT))
            utxo_item[4].setFont(QFont(MONOSPACE_FONT))
            utxo_item[0].setData(name, Qt.UserRole)
            if self.wallet.is_frozen(address):
                utxo_item[0].setBackground(ColorScheme.BLUE.as_color(True))
            self.model().insertRow(idx, utxo_item)

    def selected_column_0_user_roles(self) -> Optional[List[str]]:
        if not self.model():
            return None
        items = self.selected_in_column(0)
        if not items:
            return None
        return [x.data(Qt.UserRole) for x in items]

    def create_menu(self, position):
        selected = self.selected_column_0_user_roles()
        if not selected:
            return
        menu = QMenu()
        coins = (self.utxo_dict[name] for name in selected)
        menu.addAction(_("Spend"), lambda: self.parent.spend_coins(coins))
        if len(selected) == 1:
            txid = selected[0].split(':')[0]
            tx = self.wallet.transactions.get(txid)
            if tx:
                label = self.wallet.get_label(txid) or None # Prefer None if empty (None hides the Description: field in the window)
                menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx, label))

        menu.exec_(self.viewport().mapToGlobal(position))
