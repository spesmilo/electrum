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
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import six

import webbrowser

from .util import *
from electrum.i18n import _
from electrum.util import block_explorer_URL, format_satoshis, format_time
from electrum.plugins import run_hook
from electrum.bitcoin import is_address


class AddressList(MyTreeWidget):
    filter_columns = [0, 1, 2]  # Address, Label, Balance

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 1)
        self.refresh_headers()
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

    def refresh_headers(self):
        headers = [ _('Address'), _('Label'), _('Balance')]
        fx = self.parent.fx
        if fx and fx.get_fiat_address_config():
            headers.extend([_(fx.get_currency()+' Balance')])
        headers.extend([_('Tx')])
        self.update_headers(headers)

    def on_update(self):
        self.wallet = self.parent.wallet
        item = self.currentItem()
        current_address = item.data(0, Qt.UserRole) if item else None
        self.clear()
        receiving_addresses = self.wallet.get_receiving_addresses()
        change_addresses = self.wallet.get_change_addresses()
        if True:
            account_item = self
            sequences = [0,1] if change_addresses else [0]
            for is_change in sequences:
                if len(sequences) > 1:
                    name = _("Receiving") if not is_change else _("Change")
                    seq_item = QTreeWidgetItem( [ name, '', '', '', ''] )
                    account_item.addChild(seq_item)
                    if not is_change:
                        seq_item.setExpanded(True)
                else:
                    seq_item = account_item
                used_item = QTreeWidgetItem( [ _("Used"), '', '', '', ''] )
                used_flag = False
                addr_list = change_addresses if is_change else receiving_addresses
                for address in addr_list:
                    num = len(self.wallet.history.get(address,[]))
                    is_used = self.wallet.is_used(address)
                    label = self.wallet.labels.get(address,'')
                    c, u, x = self.wallet.get_addr_balance(address)
                    balance = self.parent.format_amount(c + u + x)
                    fx = self.parent.fx
                    if fx and fx.get_fiat_address_config():
                        rate = fx.exchange_rate()
                        fiat_balance = fx.value_str(c + u + x, rate)
                        address_item = QTreeWidgetItem([address, label, balance, fiat_balance, "%d"%num])
                        address_item.setTextAlignment(3, Qt.AlignRight)
                    else:
                        address_item = QTreeWidgetItem([address, label, balance, "%d"%num])
                    address_item.setTextAlignment(2, Qt.AlignRight)
                    address_item.setFont(0, QFont(MONOSPACE_FONT))
                    address_item.setData(0, Qt.UserRole, address)
                    address_item.setData(0, Qt.UserRole+1, True) # label can be edited
                    if self.wallet.is_frozen(address):
                        address_item.setBackgroundColor(0, QColor('lightblue'))
                    if self.wallet.is_beyond_limit(address, is_change):
                        address_item.setBackgroundColor(0, QColor('red'))
                    if is_used:
                        if not used_flag:
                            seq_item.insertChild(0, used_item)
                            used_flag = True
                        used_item.addChild(address_item)
                    else:
                        seq_item.addChild(address_item)
                    if address == current_address:
                        self.setCurrentItem(address_item)

    def create_menu(self, position):
        from electrum.wallet import Multisig_Wallet
        is_multisig = isinstance(self.wallet, Multisig_Wallet)
        can_delete = self.wallet.can_delete_address()
        selected = self.selectedItems()
        multi_select = len(selected) > 1
        addrs = [item.text(0) for item in selected]
        if not addrs:
            return
        if not multi_select:
            item = self.itemAt(position)
            col = self.currentColumn()
            if not item:
                return
            addr = addrs[0]
            if not is_address(addr):
                item.setExpanded(not item.isExpanded())
                return

        menu = QMenu()
        if not multi_select:
            column_title = self.headerItem().text(col)
            menu.addAction(_("Copy %s")%column_title, lambda: self.parent.app.clipboard().setText(item.text(col)))
            menu.addAction(_('Details'), lambda: self.parent.show_address(addr))
            if col in self.editable_columns:
                menu.addAction(_("Edit %s")%column_title, lambda: self.editItem(item, col))
            menu.addAction(_("Request payment"), lambda: self.parent.receive_at(addr))
            if self.wallet.can_export():
                menu.addAction(_("Private key"), lambda: self.parent.show_private_key(addr))
            if not is_multisig and not self.wallet.is_watching_only():
                menu.addAction(_("Sign/verify message"), lambda: self.parent.sign_verify_message(addr))
                menu.addAction(_("Encrypt/decrypt message"), lambda: self.parent.encrypt_message(addr))
            if can_delete:
                menu.addAction(_("Remove from wallet"), lambda: self.parent.remove_address(addr))
            addr_URL = block_explorer_URL(self.config, 'addr', addr)
            if addr_URL:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(addr_URL))

            if not self.wallet.is_frozen(addr):
                menu.addAction(_("Freeze"), lambda: self.parent.set_frozen_state([addr], True))
            else:
                menu.addAction(_("Unfreeze"), lambda: self.parent.set_frozen_state([addr], False))

        coins = self.wallet.get_utxos(addrs)
        if coins:
            menu.addAction(_("Spend from"), lambda: self.parent.spend_coins(coins))

        run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec_(self.viewport().mapToGlobal(position))

