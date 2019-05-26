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
from electrum.i18n import _
from electrum.plugin import run_hook
from electrum.bitcoin import is_address
from electrum.wallet import InternalAddressCorruption
from .util import *
from enum import IntEnum

from PyQt5.QtCore import Qt, QPersistentModelIndex, QModelIndex
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QLabel, QMenu


class AssetList(MyTreeView):
    class Columns(IntEnum):
        GUID = 0
        SYMBOL = 1
        ADDRESS = 2
        BALANCE = 3

    filter_columns = [0, 1, 2, 3]  # Guid, Symbol, Address, Balance

    def __init__(self, parent=None):
        super().__init__(parent, self.create_menu, stretch_column=self.Columns.ADDRESS)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.setModel(QStandardItemModel(self))
        self.update()

    def get_toolbar_buttons(self):
        return None

    def on_hide_toolbar(self):
        self.update()

    def save_toolbar_state(self, state, config):
        config.set_key('show_toolbar_assets', state)

    def refresh_headers(self):
        headers = [_('Asset Guid'),_('Symbol'), _('Address'), _('Balance')]
        self.update_headers(headers)

    def update(self):
        self.network = self.parent.network
        self.wallet = self.parent.wallet
        current_asset = self.current_item_user_role(col=2)
        asset_list = self.wallet.get_assets()
        self.model().clear()
        self.refresh_headers()
        set_asset = None
        for asset in asset_list:
            asset_symbol = asset['symbol']
            asset_guid = asset['asset_guid']
            asset_address = asset['address']
            balance = asset['balance']
            balance_text = self.parent.format_amount(balance, whitespaces=True)

            # create item
            labels = [asset_guid, asset_symbol, asset_address, balance_text]
            asset_item = [QStandardItem(e) for e in labels]

            # align text and set fonts
            for i, item in enumerate(asset_item):
                item.setTextAlignment(Qt.AlignVCenter)
                item.setFont(QFont(MONOSPACE_FONT))
                item.setEditable(i in self.editable_columns)

            # add item
            count = self.model().rowCount()
            self.model().insertRow(count, asset_item)
            asset_idx = self.model().index(count, 2)
            if asset == current_asset:
                set_asset = QPersistentModelIndex(asset_idx)
        self.set_current_idx(set_asset)

    def create_menu(self, position):
        selected = self.selected_in_column(1)
        if not selected:
            return
        multi_select = len(selected) > 1
        addrs = [self.model().itemFromIndex(item).text() for item in selected]
        menu = QMenu()
        if not multi_select:
            idx = self.indexAt(position)
            col = idx.column()
            item = self.model().itemFromIndex(idx)
            if not item:
                return
            asset_name = addrs[0]

            guid_idx = idx.sibling(idx.row(), self.Columns.GUID)
            address_idx = idx.sibling(idx.row(), self.Columns.ADDRESS)

            column_title = self.model().horizontalHeaderItem(col).text()
            asset_guid = self.model().itemFromIndex(guid_idx).text()
            asset_address = self.model().itemFromIndex(address_idx).text()
            copy_text = self.model().itemFromIndex(idx).text()

            menu.addAction(_("Copy {}").format(column_title), lambda: self.place_text_on_clipboard(copy_text))
            menu.addAction(_("Send {}").format(asset_name), lambda: self.parent.spend_asset(asset_guid, asset_address))
            menu.addAction(_("Request payment"), lambda: self.parent.receive_at(asset_name))

        run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec_(self.viewport().mapToGlobal(position))

    def place_text_on_clipboard(self, text):
        print(text)
        if is_address(text):
            try:
                self.wallet.check_address(text)
            except InternalAddressCorruption as e:
                self.parent.show_error(str(e))
                raise
        self.parent.app.clipboard().setText(text)
