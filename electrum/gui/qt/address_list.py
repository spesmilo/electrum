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

import enum
from enum import IntEnum
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QPersistentModelIndex, QModelIndex
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt6.QtWidgets import QAbstractItemView, QComboBox, QLabel, QMenu

from electrum.i18n import _
from electrum.util import block_explorer_URL, profiler
from electrum.plugin import run_hook
from electrum.bitcoin import is_address
from electrum.wallet import InternalAddressCorruption
from electrum.simple_config import SimpleConfig

from .util import MONOSPACE_FONT, ColorScheme, webopen
from .my_treeview import MyTreeView, MySortModel
from ..messages import MSG_FREEZE_ADDRESS

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class AddressUsageStateFilter(IntEnum):
    ALL = 0
    UNUSED = 1
    FUNDED = 2
    USED_AND_EMPTY = 3
    FUNDED_OR_UNUSED = 4

    def ui_text(self) -> str:
        return {
            self.ALL: _('All status'),
            self.UNUSED: _('Unused'),
            self.FUNDED: _('Funded'),
            self.USED_AND_EMPTY: _('Used'),
            self.FUNDED_OR_UNUSED: _('Funded or Unused'),
        }[self]


class AddressTypeFilter(IntEnum):
    ALL = 0
    RECEIVING = 1
    CHANGE = 2

    def ui_text(self) -> str:
        return {
            self.ALL: _('All types'),
            self.RECEIVING: _('Receiving'),
            self.CHANGE: _('Change'),
        }[self]


class AddressList(MyTreeView):

    class Columns(MyTreeView.BaseColumnsEnum):
        TYPE = enum.auto()
        ADDRESS = enum.auto()
        LABEL = enum.auto()
        COIN_BALANCE = enum.auto()
        FIAT_BALANCE = enum.auto()
        NUM_TXS = enum.auto()

    filter_columns = [Columns.TYPE, Columns.ADDRESS, Columns.LABEL, Columns.COIN_BALANCE]

    ROLE_SORT_ORDER = Qt.ItemDataRole.UserRole + 1000
    ROLE_ADDRESS_STR = Qt.ItemDataRole.UserRole + 1001
    key_role = ROLE_ADDRESS_STR

    def __init__(self, main_window: 'ElectrumWindow'):
        super().__init__(
            main_window=main_window,
            stretch_column=self.Columns.LABEL,
            editable_columns=[self.Columns.LABEL],
        )
        self.wallet = self.main_window.wallet
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setSortingEnabled(True)
        self.show_change = AddressTypeFilter.ALL  # type: AddressTypeFilter
        self.show_used = AddressUsageStateFilter.ALL  # type: AddressUsageStateFilter
        self.change_button = QComboBox(self)
        self.change_button.currentIndexChanged.connect(self.toggle_change)
        for addr_type in AddressTypeFilter.__members__.values():  # type: AddressTypeFilter
            self.change_button.addItem(addr_type.ui_text())
        self.used_button = QComboBox(self)
        self.used_button.currentIndexChanged.connect(self.toggle_used)
        for addr_usage_state in AddressUsageStateFilter.__members__.values():  # type: AddressUsageStateFilter
            self.used_button.addItem(addr_usage_state.ui_text())
        self.std_model = QStandardItemModel(self)
        self.proxy = MySortModel(self, sort_role=self.ROLE_SORT_ORDER)
        self.proxy.setSourceModel(self.std_model)
        self.setModel(self.proxy)
        self.update()
        self.sortByColumn(self.Columns.TYPE, Qt.SortOrder.AscendingOrder)
        if self.config:
            self.configvar_show_toolbar = self.config.cv.GUI_QT_ADDRESSES_TAB_SHOW_TOOLBAR

    def on_double_click(self, idx):
        addr = self.get_role_data_for_current_item(col=0, role=self.ROLE_ADDRESS_STR)
        self.main_window.show_address(addr)

    def create_toolbar(self, config: 'SimpleConfig'):
        toolbar, menu = self.create_toolbar_with_menu('')
        self.num_addr_label = toolbar.itemAt(0).widget()
        self._toolbar_checkbox = menu.addToggle(_("Show Filter"), lambda: self.toggle_toolbar())
        menu.addConfig(config.cv.FX_SHOW_FIAT_BALANCE_FOR_ADDRESSES, callback=self.main_window.app.update_fiat_signal.emit)
        hbox = self.create_toolbar_buttons()
        toolbar.insertLayout(1, hbox)
        return toolbar

    def should_show_fiat(self):
        return self.main_window.fx and self.main_window.fx.is_enabled() and self.config.FX_SHOW_FIAT_BALANCE_FOR_ADDRESSES

    def get_toolbar_buttons(self):
        return self.change_button, self.used_button

    def on_hide_toolbar(self):
        self.show_change = AddressTypeFilter.ALL  # type: AddressTypeFilter
        self.show_used = AddressUsageStateFilter.ALL  # type: AddressUsageStateFilter
        self.update()

    def refresh_headers(self):
        if self.should_show_fiat():
            ccy = self.main_window.fx.get_currency()
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

    def toggle_change(self, state: int):
        if state == self.show_change:
            return
        self.show_change = AddressTypeFilter(state)
        self.update()

    def toggle_used(self, state: int):
        if state == self.show_used:
            return
        self.show_used = AddressUsageStateFilter(state)
        self.update()

    @profiler
    def update(self):
        if self.maybe_defer_update():
            return
        current_address = self.get_role_data_for_current_item(col=0, role=self.ROLE_ADDRESS_STR)
        if self.show_change == AddressTypeFilter.RECEIVING:
            addr_list = self.wallet.get_receiving_addresses()
        elif self.show_change == AddressTypeFilter.CHANGE:
            addr_list = self.wallet.get_change_addresses()
        else:
            addr_list = self.wallet.get_addresses()
        self.proxy.setDynamicSortFilter(False)  # temp. disable re-sorting after every change
        self.std_model.clear()
        self.refresh_headers()
        fx = self.main_window.fx
        set_address = None
        num_shown = 0
        self.addresses_beyond_gap_limit = self.wallet.get_all_known_addresses_beyond_gap_limit()
        for address in addr_list:
            c, u, x = self.wallet.get_addr_balance(address)
            balance = c + u + x
            is_used_and_empty = self.wallet.adb.is_used(address) and balance == 0
            if self.show_used == AddressUsageStateFilter.UNUSED and (balance or is_used_and_empty):
                continue
            if self.show_used == AddressUsageStateFilter.FUNDED and balance == 0:
                continue
            if self.show_used == AddressUsageStateFilter.USED_AND_EMPTY and not is_used_and_empty:
                continue
            if self.show_used == AddressUsageStateFilter.FUNDED_OR_UNUSED and is_used_and_empty:
                continue
            num_shown += 1
            labels = [""] * len(self.Columns)
            labels[self.Columns.ADDRESS] = address
            address_item = [QStandardItem(e) for e in labels]
            # align text and set fonts
            for i, item in enumerate(address_item):
                item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter)
                if i not in (self.Columns.TYPE, self.Columns.LABEL):
                    item.setFont(QFont(MONOSPACE_FONT))
            self.set_editability(address_item)
            address_item[self.Columns.FIAT_BALANCE].setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            # setup column 0
            if self.wallet.is_change(address):
                address_item[self.Columns.TYPE].setText(_('change'))
                address_item[self.Columns.TYPE].setBackground(ColorScheme.YELLOW.as_color(True))
            else:
                address_item[self.Columns.TYPE].setText(_('receiving'))
                address_item[self.Columns.TYPE].setBackground(ColorScheme.GREEN.as_color(True))
            address_item[0].setData(address, self.ROLE_ADDRESS_STR)
            address_path = self.wallet.get_address_index(address)
            address_item[self.Columns.TYPE].setData(address_path, self.ROLE_SORT_ORDER)
            address_path_str = self.wallet.get_address_path_str(address)
            if address_path_str is not None:
                address_item[self.Columns.TYPE].setToolTip(address_path_str)
            # add item
            count = self.std_model.rowCount()
            self.std_model.insertRow(count, address_item)
            self.refresh_row(address, count)
            address_idx = self.std_model.index(count, self.Columns.LABEL)
            if address == current_address:
                set_address = QPersistentModelIndex(address_idx)
        self.set_current_idx(set_address)
        # show/hide columns
        if self.should_show_fiat():
            self.showColumn(self.Columns.FIAT_BALANCE)
        else:
            self.hideColumn(self.Columns.FIAT_BALANCE)
        self.filter()
        self.proxy.setDynamicSortFilter(True)
        # update counter
        self.num_addr_label.setText(_("{} addresses").format(num_shown))

    def refresh_row(self, key, row):
        assert row is not None
        address = key
        label = self.wallet.get_label_for_address(address)
        num = self.wallet.adb.get_address_history_len(address)
        c, u, x = self.wallet.get_addr_balance(address)
        balance = c + u + x
        balance_text = self.main_window.format_amount(balance, whitespaces=True)
        balance_text_nots = self.main_window.format_amount(balance, whitespaces=False, add_thousands_sep=False)
        # create item
        fx = self.main_window.fx
        if self.should_show_fiat():
            rate = fx.exchange_rate()
            fiat_balance_str = fx.value_str(balance, rate, add_thousands_sep=True)
            fiat_balance_str_nots = fx.value_str(balance, rate, add_thousands_sep=False)
        else:
            fiat_balance_str = ''
            fiat_balance_str_nots = ''
        address_item = [self.std_model.item(row, col) for col in self.Columns]
        address_item[self.Columns.LABEL].setText(label)
        address_item[self.Columns.COIN_BALANCE].setText(balance_text)
        address_item[self.Columns.COIN_BALANCE].setData(balance, self.ROLE_SORT_ORDER)
        address_item[self.Columns.COIN_BALANCE].setData(balance_text_nots, self.ROLE_CLIPBOARD_DATA)
        address_item[self.Columns.FIAT_BALANCE].setText(fiat_balance_str)
        address_item[self.Columns.FIAT_BALANCE].setData(balance, self.ROLE_SORT_ORDER)
        address_item[self.Columns.FIAT_BALANCE].setData(fiat_balance_str_nots, self.ROLE_CLIPBOARD_DATA)
        address_item[self.Columns.NUM_TXS].setText("%d"%num)
        c = ColorScheme.BLUE.as_color(True) if self.wallet.is_frozen_address(address) else self._default_bg_brush
        address_item[self.Columns.ADDRESS].setBackground(c)
        if address in self.addresses_beyond_gap_limit:
            address_item[self.Columns.ADDRESS].setBackground(ColorScheme.RED.as_color(True))

    def create_menu(self, position):
        from electrum.wallet import Multisig_Wallet
        is_multisig = isinstance(self.wallet, Multisig_Wallet)
        can_delete = self.wallet.can_delete_address()
        selected = self.selected_in_column(self.Columns.ADDRESS)
        if not selected:
            return
        multi_select = len(selected) > 1
        addrs = [self.item_from_index(item).text() for item in selected]
        menu = QMenu()
        menu.setToolTipsVisible(True)
        if not multi_select:
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            item = self.item_from_index(idx)
            if not item:
                return
            addr = addrs[0]
            menu.addAction(_('Details'), lambda: self.main_window.show_address(addr))
            addr_column_title = self.std_model.horizontalHeaderItem(self.Columns.LABEL).text()
            addr_idx = idx.sibling(idx.row(), self.Columns.LABEL)
            self.add_copy_menu(menu, idx)
            persistent = QPersistentModelIndex(addr_idx)
            menu.addAction(_("Edit {}").format(addr_column_title), lambda p=persistent: self.edit(QModelIndex(p)))
            #menu.addAction(_("Request payment"), lambda: self.main_window.receive_at(addr))
            if self.wallet.can_export():
                menu.addAction(_("Private key"), lambda: self.main_window.show_private_key(addr))
            if not is_multisig and not self.wallet.is_watching_only():
                menu.addAction(_("Sign/verify message"), lambda: self.main_window.sign_verify_message(addr))
                menu.addAction(_("Encrypt/decrypt message"), lambda: self.main_window.encrypt_message(addr))
            if can_delete:
                menu.addAction(_("Remove from wallet"), lambda: self.main_window.remove_address(addr))
            addr_URL = block_explorer_URL(self.config, 'addr', addr)
            if addr_URL:
                menu.addAction(_("View on block explorer"), lambda: webopen(addr_URL))

            if not self.wallet.is_frozen_address(addr):
                act = menu.addAction(_("Freeze"), lambda: self.main_window.set_frozen_state_of_addresses([addr], True))
            else:
                act = menu.addAction(_("Unfreeze"), lambda: self.main_window.set_frozen_state_of_addresses([addr], False))
            act.setToolTip(MSG_FREEZE_ADDRESS)

        else:
            # multiple items selected
            act = menu.addAction(_("Freeze"), lambda: self.main_window.set_frozen_state_of_addresses(addrs, True))
            act.setToolTip(MSG_FREEZE_ADDRESS)
            act = menu.addAction(_("Unfreeze"), lambda: self.main_window.set_frozen_state_of_addresses(addrs, False))
            act.setToolTip(MSG_FREEZE_ADDRESS)

        coins = self.wallet.get_spendable_coins(addrs)
        if coins:
            if self.main_window.utxo_list.are_in_coincontrol(coins):
                menu.addAction(_("Remove from coin control"), lambda: self.main_window.utxo_list.remove_from_coincontrol(coins))
            else:
                menu.addAction(_("Add to coin control"), lambda: self.main_window.utxo_list.add_to_coincontrol(coins))

        run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec(self.viewport().mapToGlobal(position))

    def place_text_on_clipboard(self, text: str, *, title: str = None) -> None:
        if is_address(text):
            try:
                self.wallet.check_address_for_corruption(text)
            except InternalAddressCorruption as e:
                self.main_window.show_error(str(e))
                raise
        super().place_text_on_clipboard(text, title=title)

    def get_edit_key_from_coordinate(self, row, col):
        if col != self.Columns.LABEL:
            return None
        return self.get_role_data_from_coordinate(row, 0, role=self.ROLE_ADDRESS_STR)

    def on_edited(self, idx, edit_key, *, text):
        self.wallet.set_label(edit_key, text)
        self.main_window.history_model.refresh('address label edited')
        self.main_window.utxo_list.update()
        self.main_window.update_completions()
