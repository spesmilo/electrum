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
from .util import *
from electrum_ltc.i18n import _


class UTXOList(MyTreeWidget):
    filter_columns = [0, 2]  # Address, Label

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [ _('Address'), _('Label'), _('Amount'), _('Height'), _('Output point')], 1)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    def get_name(self, x):
        return x.get('prevout_hash') + ":%d"%x.get('prevout_n')

    def on_update(self):
        self.wallet = self.parent.wallet
        item = self.currentItem()
        self.clear()
        self.utxos = self.wallet.get_utxos()
        for x in self.utxos:
            address = x.get('address')
            height = x.get('height')
            name = self.get_name(x)
            label = self.wallet.get_label(x.get('prevout_hash'))
            amount = self.parent.format_amount(x['value'], whitespaces=True)
            utxo_item = SortableTreeWidgetItem([address, label, amount, '%d'%height, name[0:10] + '...' + name[-2:]])
            utxo_item.setFont(0, QFont(MONOSPACE_FONT))
            utxo_item.setFont(2, QFont(MONOSPACE_FONT))
            utxo_item.setFont(4, QFont(MONOSPACE_FONT))
            utxo_item.setData(0, Qt.UserRole, name)
            if self.wallet.is_frozen(address):
                utxo_item.setBackground(0, ColorScheme.BLUE.as_color(True))
            self.addChild(utxo_item)

    def create_menu(self, position):
        selected = [x.data(0, Qt.UserRole) for x in self.selectedItems()]
        if not selected:
            return
        menu = QMenu()
        coins = filter(lambda x: self.get_name(x) in selected, self.utxos)

        menu.addAction(_("Spend"), lambda: self.parent.spend_coins(coins))
        if len(selected) == 1:
            txid = selected[0].split(':')[0]
            tx = self.wallet.transactions.get(txid)
            menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx))

        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # disable editing fields in this tab (labels)
        return False
