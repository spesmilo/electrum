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
from .util import *
from electroncash.i18n import _


class UTXOList(MyTreeWidget):
    filter_columns = [0, 2]  # Address, Label

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [ _('Address'), _('Label'), _('Amount'), _('Height'), _('Output point')], 1)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        # force attributes to always be defined, even if None, at construction.
        self.wallet = self.parent.wallet if hasattr(self.parent, 'wallet') else None
        self.utxos = list()

    def get_name(self, x):
        return x.get('prevout_hash') + ":%d"%x.get('prevout_n')

    def get_name_short(self, x):
        return x.get('prevout_hash')[:10] + '...' + ":%d"%x.get('prevout_n')

    @rate_limited(1.0, ts_after=True) # performance tweak -- limit updates to no more than oncer per second
    def update(self):
        if self.wallet and (not self.wallet.thread or not self.wallet.thread.isRunning()):
            # short-cut return if window was closed and wallet is stopped
            return
        super().update()

    def on_update(self):
        prev_selection = self.get_selected() # cache previous selection, if any
        self.clear()
        self.wallet = self.parent.wallet
        if not self.wallet: return
        self.utxos = self.wallet.get_utxos()
        for x in self.utxos:
            address = x['address']
            address_text = address.to_ui_string()
            height = x['height']
            name = self.get_name(x)
            name_short = self.get_name_short(x)
            label = self.wallet.get_label(x['prevout_hash'])
            amount = self.parent.format_amount(x['value'])
            utxo_item = SortableTreeWidgetItem([address_text, label, amount,
                                                str(height), name_short])
            utxo_item.DataRole = Qt.UserRole+100 # set this here to avoid sorting based on Qt.UserRole+1
            utxo_item.setFont(0, QFont(MONOSPACE_FONT))
            utxo_item.setFont(4, QFont(MONOSPACE_FONT))
            utxo_item.setData(0, Qt.UserRole, name)
            a_frozen = self.wallet.is_frozen(address)
            c_frozen = x['is_frozen_coin']
            if a_frozen and not c_frozen:
                # address is frozen, coin is not frozen
                # emulate the "Look" off the address_list .py's frozen entry
                utxo_item.setBackground(0, QColor('lightblue'))
            elif c_frozen and not a_frozen:
                # coin is frozen, address is not frozen
                utxo_item.setBackground(0, ColorScheme.BLUE.as_color(True))
            elif c_frozen and a_frozen:
                # both coin and address are frozen so color-code it to indicate that.
                utxo_item.setBackground(0, QColor('lightblue'))
                utxo_item.setForeground(0, QColor('#3399ff'))
            # save the address-level-frozen and coin-level-frozen flags to the data item for retrieval later in create_menu() below.
            utxo_item.setData(0, Qt.UserRole+1, "{}{}".format(("a" if a_frozen else ""), ("c" if c_frozen else "")))
            self.addChild(utxo_item)
            if name in prev_selection:
                # NB: This needs to be here after the item is added to the widget. See #979.
                utxo_item.setSelected(True) # restore previous selection

    def get_selected(self):
        return { x.data(0, Qt.UserRole) : x.data(0, Qt.UserRole+1) # dict of "name" -> frozen flags string (eg: "ac")
                for x in self.selectedItems() }

    def create_menu(self, position):
        selected = self.get_selected()
        if not selected:
            return
        menu = QMenu()
        coins = filter(lambda x: self.get_name(x) in selected, self.utxos)
        spendable_coins = list(filter(lambda x: not selected.get(self.get_name(x), ''), coins))
        # Unconditionally add the "Spend" option but leave it disabled if there are no spendable_coins
        menu.addAction(_("Spend"), lambda: self.parent.spend_coins(spendable_coins)).setEnabled(bool(spendable_coins))
        if len(selected) == 1:
            # single selection, offer them the "Details" option and also coin/address "freeze" status, if any
            txid = list(selected.keys())[0].split(':')[0]
            frozen_flags = list(selected.values())[0]
            tx = self.wallet.transactions.get(txid)
            if tx:
                label = self.wallet.get_label(txid) or None
                menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx, label))
            act = None
            needsep = True
            if 'c' in frozen_flags:
                menu.addSeparator()
                menu.addAction(_("Coin is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Coin"), lambda: self.set_frozen_coins(list(selected.keys()), False))
                menu.addSeparator()
                needsep = False
            else:
                menu.addAction(_("Freeze Coin"), lambda: self.set_frozen_coins(list(selected.keys()), True))
            if 'a' in frozen_flags:
                if needsep: menu.addSeparator()
                menu.addAction(_("Address is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Address"), lambda: self.set_frozen_addresses_for_coins(list(selected.keys()), False))
            else:
                menu.addAction(_("Freeze Address"), lambda: self.set_frozen_addresses_for_coins(list(selected.keys()), True))
        else:
            # multi-selection
            menu.addSeparator()
            if any(['c' not in flags for flags in selected.values()]):
                # they have some coin-level non-frozen in the selection, so add the menu action "Freeze coins"
                menu.addAction(_("Freeze Coins"), lambda: self.set_frozen_coins(list(selected.keys()), True))
            if any(['c' in flags for flags in selected.values()]):
                # they have some coin-level frozen in the selection, so add the menu action "Unfreeze coins"
                menu.addAction(_("Unfreeze Coins"), lambda: self.set_frozen_coins(list(selected.keys()), False))
            if any(['a' not in flags for flags in selected.values()]):
                # they have some address-level non-frozen in the selection, so add the menu action "Freeze addresses"
                menu.addAction(_("Freeze Addresses"), lambda: self.set_frozen_addresses_for_coins(list(selected.keys()), True))
            if any(['a' in flags for flags in selected.values()]):
                # they have some address-level frozen in the selection, so add the menu action "Unfreeze addresses"
                menu.addAction(_("Unfreeze Addresses"), lambda: self.set_frozen_addresses_for_coins(list(selected.keys()), False))

        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # disable editing fields in this tab (labels)
        return False

    def set_frozen_coins(self, coins, b):
        if self.parent:
            self.parent.set_frozen_coin_state(coins, b)

    def set_frozen_addresses_for_coins(self, coins, b):
        if not self.parent: return
        addrs = set()
        for utxo in self.utxos:
            name = self.get_name(utxo)
            if name in coins:
                addrs.add(utxo['address'])
        if addrs:
            self.parent.set_frozen_state(list(addrs), b)

    def update_labels(self):
        root = self.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            try:
                txid = item.data(0, Qt.UserRole).split(':', 1)[0]
            except IndexError:
                continue # name is iinvalid. should be txid:prevout_n
            label = self.wallet.get_label(txid)
            item.setText(1, label)
