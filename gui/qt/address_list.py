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

from functools import partial

from .util import MyTreeWidget, MONOSPACE_FONT, SortableTreeWidgetItem
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QKeySequence
from PyQt5.QtWidgets import QTreeWidgetItem, QAbstractItemView, QMenu
from electroncash.i18n import _
from electroncash.address import Address
from electroncash.plugins import run_hook
import electroncash.web as web


class AddressList(MyTreeWidget):
    filter_columns = [0, 1, 2]  # Address, Label, Balance

    def __init__(self, parent=None):
        super().__init__(parent, self.create_menu, [], 2)
        self.refresh_headers()
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    def refresh_headers(self):
        headers = [ ('Address'), _('Index'),_('Label'), _('Balance'), _('Tx')]
        fx = self.parent.fx
        if fx and fx.get_fiat_address_config():
            headers.insert(4, '{} {}'.format(fx.get_currency(), _(' Balance')))
        self.update_headers(headers)

    def on_update(self):
        def remember_expanded_items():
            # save the set of expanded items... so that address list updates don't annoyingly collapse
            # our tree list widget due to the update.
            expanded_item_names = set()
            for i in range(0, self.topLevelItemCount()):
                it = self.topLevelItem(i)
                if it and it.childCount():
                    if it.isExpanded():
                        expanded_item_names.add(it.text(0))
                    for j in range(0, it.childCount()):
                        it2 = it.child(j)
                        if it2 and it2.childCount() and it2.isExpanded():
                            expanded_item_names.add(it.text(0) + "/" + it2.text(0))
            return expanded_item_names
        def restore_expanded_items(seq_item, used_item, expanded_item_names):
            # restore expanded items.
            if isinstance(seq_item, QTreeWidgetItem) and not seq_item.isExpanded() and seq_item.text(0) in expanded_item_names:
                seq_item.setExpanded(True)
            used_item_name = used_item.text(0) if not used_item.parent() else used_item.parent().text(0) + "/" + used_item.text(0)
            if not used_item.isExpanded() and used_item_name in expanded_item_names:
                used_item.setExpanded(True)       
        self.wallet = self.parent.wallet
        had_item_count = self.topLevelItemCount()
        item = self.currentItem()
        current_address = item.data(0, Qt.UserRole) if item else None
        expanded_item_names = remember_expanded_items()
        self.clear()
        receiving_addresses = self.wallet.get_receiving_addresses()
        change_addresses = self.wallet.get_change_addresses()

        if self.parent.fx and self.parent.fx.get_fiat_address_config():
            fx = self.parent.fx
        else:
            fx = None
        account_item = self
        sequences = [0,1] if change_addresses else [0]
        for is_change in sequences:
            if len(sequences) > 1:
                name = _("Receiving") if not is_change else _("Change")
                seq_item = QTreeWidgetItem( [ name, '', '', '', '', ''] )
                account_item.addChild(seq_item)
                if not is_change and not had_item_count: # first time we create this widget, auto-expand the default address list
                    seq_item.setExpanded(True)
            else:
                seq_item = account_item
            used_item = QTreeWidgetItem( [ _("Used"), '', '', '', '', ''] )
            used_flag = False
            addr_list = change_addresses if is_change else receiving_addresses
            for n, address in enumerate(addr_list):
                num = len(self.wallet.get_address_history(address))
                is_used = self.wallet.is_used(address)
                balance = sum(self.wallet.get_addr_balance(address))
                address_text = address.to_ui_string()
                label = self.wallet.labels.get(address.to_storage_string(), '')
                balance_text = self.parent.format_amount(balance, whitespaces=True)
                columns = [address_text, str(n), label, balance_text, str(num)]
                if fx:
                    rate = fx.exchange_rate()
                    fiat_balance = fx.value_str(balance, rate)
                    columns.insert(4, fiat_balance)
                address_item = SortableTreeWidgetItem(columns)
                address_item.setTextAlignment(3, Qt.AlignRight)
                address_item.setFont(3, QFont(MONOSPACE_FONT))
                if fx:
                    address_item.setTextAlignment(4, Qt.AlignRight)
                    address_item.setFont(4, QFont(MONOSPACE_FONT))

                address_item.setFont(0, QFont(MONOSPACE_FONT))
                address_item.setData(0, Qt.UserRole, address)
                address_item.setData(0, Qt.UserRole+1, True) # label can be edited
                if self.wallet.is_frozen(address):
                    address_item.setBackground(0, QColor('lightblue'))
                if self.wallet.is_beyond_limit(address, is_change):
                    address_item.setBackground(0, QColor('red'))
                if is_used:
                    if not used_flag:
                        seq_item.insertChild(0, used_item)
                        used_flag = True
                    used_item.addChild(address_item)
                else:
                    seq_item.addChild(address_item)
                if address == current_address:
                    self.setCurrentItem(address_item)
            restore_expanded_items(seq_item, used_item, expanded_item_names)

    def create_menu(self, position):
        from electroncash.wallet import Multisig_Wallet
        is_multisig = isinstance(self.wallet, Multisig_Wallet)
        can_delete = self.wallet.can_delete_address()
        selected = self.selectedItems()
        multi_select = len(selected) > 1
        addrs = [item.data(0, Qt.UserRole) for item in selected]
        if not addrs:
            return
        addrs = [addr for addr in addrs if isinstance(addr, Address)]

        menu = QMenu()

        if not multi_select:
            item = self.itemAt(position)
            col = self.currentColumn()
            if not item:
                return
            if not addrs:
                item.setExpanded(not item.isExpanded())
                return
            addr = addrs[0]

            column_title = self.headerItem().text(col)
            if col == 0:
                copy_text = addr.to_full_ui_string()
            else:
                copy_text = item.text(col)
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(copy_text))
            menu.addAction(_('Details'), lambda: self.parent.show_address(addr))
            if col in self.editable_columns:
                menu.addAction(_("Edit {}").format(column_title), lambda: self.editItem(item, col))
            menu.addAction(_("Request payment"), lambda: self.parent.receive_at(addr))
            if self.wallet.can_export():
                menu.addAction(_("Private key"), lambda: self.parent.show_private_key(addr))
            if not is_multisig and not self.wallet.is_watching_only():
                menu.addAction(_("Sign/verify message"), lambda: self.parent.sign_verify_message(addr))
                menu.addAction(_("Encrypt/decrypt message"), lambda: self.parent.encrypt_message(addr))
            if can_delete:
                menu.addAction(_("Remove from wallet"), lambda: self.parent.remove_address(addr))
            addr_URL = web.BE_URL(self.config, 'addr', addr)
            if addr_URL:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(addr_URL))

        freeze = self.parent.set_frozen_state
        if any(self.wallet.is_frozen(addr) for addr in addrs):
            menu.addAction(_("Unfreeze"), partial(freeze, addrs, False))
        if not all(self.wallet.is_frozen(addr) for addr in addrs):
            menu.addAction(_("Freeze"), partial(freeze, addrs, True))

        coins = self.wallet.get_utxos(addrs)
        if coins:
            menu.addAction(_("Spend from"),
                           partial(self.parent.spend_coins, coins))

        run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec_(self.viewport().mapToGlobal(position))

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.Copy) and self.currentColumn() == 0:
            addrs = [i.data(0, Qt.UserRole) for i in self.selectedItems()]
            if addrs and isinstance(addrs[0], Address):
                text = addrs[0].to_full_ui_string()
                self.parent.app.clipboard().setText(text)
        else:
            super().keyPressEvent(event)
