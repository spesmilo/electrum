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

from util import *
from electrum.i18n import _


class UTXOList(MyTreeWidget):

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [ _('Output'), _('Address'), _('Label'), _('Amount'), ''], 2)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

    def get_name(self, x):
        return x.get('prevout_hash') + ":%d"%x.get('prevout_n')

    def on_update(self):
        self.wallet = self.parent.wallet
        item = self.currentItem()
        self.clear()
        self.utxos = self.wallet.get_utxos()
        for x in self.utxos:
            address = x.get('address')
            name = self.get_name(x)
            label = self.wallet.get_label(x.get('prevout_hash'))
            amount = self.parent.format_amount(x['value'])
            utxo_item = QTreeWidgetItem([name[0:10]+'...'+name[-10:], address, label, amount])
            utxo_item.setFont(0, QFont(MONOSPACE_FONT))
            utxo_item.setFont(1, QFont(MONOSPACE_FONT))
            utxo_item.setData(0, Qt.UserRole, name)
            if self.wallet.is_frozen(address):
                utxo_item.setBackgroundColor(0, QColor('lightblue'))
            self.addChild(utxo_item)

    def create_menu(self, position):
        from electrum.wallet import Multisig_Wallet
        selected = [ x.data(0, Qt.UserRole).toString() for x in self.selectedItems()]
        if not selected:
            return
        coins = filter(lambda x: self.get_name(x) in selected, self.utxos)
        menu = QMenu()
        if len(selected) == 1:
            coin = coins[0]
            menu.addAction(_("Copy Address"), lambda: self.parent.app.clipboard().setText(coin.get('address')))
        menu.addAction(_("Spend"), lambda: self.parent.spend_coins(coins))
        menu.exec_(self.viewport().mapToGlobal(position))

