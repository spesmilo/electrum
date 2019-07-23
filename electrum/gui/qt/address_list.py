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

from enum import IntEnum

from PyQt5.QtCore import Qt, QPersistentModelIndex, QModelIndex
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QLabel, QMenu

from electrum.i18n import _
from electrum.util import block_explorer_URL, profiler
from electrum.plugin import run_hook
from electrum.bitcoin import is_address
from electrum.wallet import InternalAddressCorruption

from .util import MyTreeView, MONOSPACE_FONT, ColorScheme, webopen


class AddressList(MyTreeView):

    class Columns(IntEnum):
        TYPE = 0
        ADDRESS = 1
        LABEL = 2
        COIN_BALANCE = 3
        FIAT_BALANCE = 4
        NUM_TXS = 5

    filter_columns = [Columns.TYPE, Columns.ADDRESS, Columns.LABEL, Columns.COIN_BALANCE]

    def __init__(self, parent=None):
        super().__init__(parent, self.create_menu, stretch_column=self.Columns.LABEL)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.show_change = 0
        self.show_used = 0
        self.change_button = QComboBox(self)
        self.change_button.currentIndexChanged.connect(self.toggle_change)
        for t in [_('All'), _('Receiving'), _('Change')]:
            self.change_button.addItem(t)
        self.used_button = QComboBox(self)
        self.used_button.currentIndexChanged.connect(self.toggle_used)
        for t in [_('All'), _('Unused'), _('Funded'), _('Used')]:
            self.used_button.addItem(t)
        self.setModel(QStandardItemModel(self))
        self.update()

    def get_toolbar_buttons(self):
        return QLabel(_("Filter:")), self.change_button, self.used_button

    def on_hide_toolbar(self):
        self.show_change = 0
        self.show_used = 0
        self.update()

    def save_toolbar_state(self, state, config):
        config.set_key('show_toolbar_addresses', state)

    def refresh_headers(self):
        fx = self.parent.fx
        if fx and fx.get_fiat_address_config():
            ccy = fx.get_currency()
        else:
            ccy = _('Fiat')
        headers = {
            self.Columns.TYPE: _('Type'),
            self.Columns.ADDRESS: _('Address'),
            self.Columns.LABEL: _('Label'),
            self.Columns.COIN_BALANCE: _('Balance'),
            self.Columns.FIAT_BALANCE: ccy + ' ' + _('Balance'),
            self.Columns.NUM_TXS: _('Tx'),
        }
        self.update_headers(headers)

    def toggle_change(self, state):
        if state == self.show_change:
            return
        self.show_change = state
        self.update()

    def toggle_used(self, state):
        if state == self.show_used:
            return
        self.show_used = state
        self.update()

    @profiler
    def update(self):
        self.wallet = self.parent.wallet
        current_address = self.current_item_user_role(col=self.Columns.LABEL)
        if self.show_change == 1:
            addr_list = self.wallet.get_receiving_addresses()
        elif self.show_change == 2:
            addr_list = self.wallet.get_change_addresses()
        else:
            addr_list = self.wallet.get_addresses()
        self.model().clear()
        self.refresh_headers()
        fx = self.parent.fx
        set_address = None
        for address in addr_list:
            num = self.wallet.get_address_history_len(address)
            label = self.wallet.labels.get(address, '')
            c, u, x = self.wallet.get_addr_balance(address)
            balance = c + u + x
            is_used_and_empty = self.wallet.is_used(address) and balance == 0
            if self.show_used == 1 and (balance or is_used_and_empty):
                continue
            if self.show_used == 2 and balance == 0:
                continue
            if self.show_used == 3 and not is_used_and_empty:
                continue
            balance_text = self.parent.format_amount(balance, whitespaces=True)
            # create item
            if fx and fx.get_fiat_address_config():
                rate = fx.exchange_rate()
                fiat_balance = fx.value_str(balance, rate)
            else:
                fiat_balance = ''
            labels = ['', address, label, balance_text, fiat_balance, "%d"%num]
            address_item = [QStandardItem(e) for e in labels]
            # align text and set fonts
            for i, item in enumerate(address_item):
                item.setTextAlignment(Qt.AlignVCenter)
                if i not in (self.Columns.TYPE, self.Columns.LABEL):
                    item.setFont(QFont(MONOSPACE_FONT))
                item.setEditable(i in self.editable_columns)
            address_item[self.Columns.FIAT_BALANCE].setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            # setup column 0
            if self.wallet.is_change(address):
                address_item[self.Columns.TYPE].setText(_('change'))
                address_item[self.Columns.TYPE].setBackground(ColorScheme.YELLOW.as_color(True))
            else:
                address_item[self.Columns.TYPE].setText(_('receiving'))
                address_item[self.Columns.TYPE].setBackground(ColorScheme.GREEN.as_color(True))
            address_item[self.Columns.LABEL].setData(address, Qt.UserRole)
            # setup column 1
            if self.wallet.is_frozen_address(address):
                address_item[self.Columns.ADDRESS].setBackground(ColorScheme.BLUE.as_color(True))
            if self.wallet.is_beyond_limit(address):
                address_item[self.Columns.ADDRESS].setBackground(ColorScheme.RED.as_color(True))
            # add item
            count = self.model().rowCount()
            self.model().insertRow(count, address_item)
            address_idx = self.model().index(count, self.Columns.LABEL)
            if address == current_address:
                set_address = QPersistentModelIndex(address_idx)
        self.set_current_idx(set_address)
        # show/hide columns
        if fx and fx.get_fiat_address_config():
            self.showColumn(self.Columns.FIAT_BALANCE)
        else:
            self.hideColumn(self.Columns.FIAT_BALANCE)
        self.filter()

    def create_menu(self, position):
        from electrum.wallet import Multisig_Wallet
        is_multisig = isinstance(self.wallet, Multisig_Wallet)
        can_delete = self.wallet.can_delete_address()
        selected = self.selected_in_column(self.Columns.ADDRESS)
        if not selected:
            return
        multi_select = len(selected) > 1
        addrs = [self.model().itemFromIndex(item).text() for item in selected]
        menu = QMenu()
        if not multi_select:
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            col = idx.column()
            item = self.model().itemFromIndex(idx)
            if not item:
                return
            addr = addrs[0]

            addr_column_title = self.model().horizontalHeaderItem(self.Columns.LABEL).text()
            addr_idx = idx.sibling(idx.row(), self.Columns.LABEL)

            column_title = self.model().horizontalHeaderItem(col).text()
            copy_text = self.model().itemFromIndex(idx).text()
            if col == self.Columns.COIN_BALANCE or col == self.Columns.FIAT_BALANCE:
                copy_text = copy_text.strip()
            menu.addAction(_("Copy {}").format(column_title), lambda: self.place_text_on_clipboard(copy_text))
            menu.addAction(_('Details'), lambda: self.parent.show_address(addr))
            persistent = QPersistentModelIndex(addr_idx)
            menu.addAction(_("Edit {}").format(addr_column_title), lambda p=persistent: self.edit(QModelIndex(p)))
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
                menu.addAction(_("View on block explorer"), lambda: webopen(addr_URL))

            if not self.wallet.is_frozen_address(addr):
                menu.addAction(_("Freeze"), lambda: self.parent.set_frozen_state_of_addresses([addr], True))
            else:
                menu.addAction(_("Unfreeze"), lambda: self.parent.set_frozen_state_of_addresses([addr], False))

        coins = self.wallet.get_spendable_coins(addrs, config=self.config)
        if coins:
            menu.addAction(_("Spend from"), lambda: self.parent.spend_coins(coins))

        run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec_(self.viewport().mapToGlobal(position))

    def place_text_on_clipboard(self, text):
        if is_address(text):
            try:
                self.wallet.check_address(text)
            except InternalAddressCorruption as e:
                self.parent.show_error(str(e))
                raise
        self.parent.app.clipboard().setText(text)
