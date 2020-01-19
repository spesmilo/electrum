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

from typing import Optional, List, Dict, Sequence, Set
from enum import IntEnum
import copy

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView, QMenu, QLabel, QHBoxLayout

from electrum.i18n import _
from electrum.transaction import PartialTxInput

from .util import MyTreeView, ColorScheme, MONOSPACE_FONT, EnterButton


class UTXOList(MyTreeView):
    _spend_set: Optional[Set[str]]  # coins selected by the user to spend from
    _utxo_dict: Dict[str, PartialTxInput]  # coin name -> coin

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

    def __init__(self, parent):
        super().__init__(parent, self.create_menu,
                         stretch_column=self.Columns.LABEL,
                         editable_columns=[])
        self._spend_set = None
        self._utxo_dict = {}
        self.wallet = self.parent.wallet

        self.setModel(QStandardItemModel(self))
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.update()

    def update(self):
        if self.maybe_defer_update():
            return
        utxos = self.wallet.get_utxos()
        self._maybe_reset_spend_list(utxos)
        self._utxo_dict = {}
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, utxo in enumerate(utxos):
            self.insert_utxo(idx, utxo)
        self.filter()
        # update coincontrol status bar
        if self._spend_set is not None:
            coins = [self._utxo_dict[x] for x in self._spend_set]
            coins = self._filter_frozen_coins(coins)
            amount = sum(x.value_sats() for x in coins)
            amount_str = self.parent.format_amount_and_units(amount)
            num_outputs_str = _("{} outputs available ({} total)").format(len(coins), len(utxos))
            self.parent.set_coincontrol_msg(_("Coin control active") + f': {num_outputs_str}, {amount_str}')
        else:
            self.parent.set_coincontrol_msg(None)

    def insert_utxo(self, idx, utxo: PartialTxInput):
        address = utxo.address
        height = utxo.block_height
        name = utxo.prevout.to_str()
        name_short = utxo.prevout.txid.hex()[:16] + '...' + ":%d" % utxo.prevout.out_idx
        self._utxo_dict[name] = utxo
        label = self.wallet.get_label(utxo.prevout.txid.hex())
        amount = self.parent.format_amount(utxo.value_sats(), whitespaces=True)
        labels = [name_short, address, label, amount, '%d'%height]
        utxo_item = [QStandardItem(x) for x in labels]
        self.set_editability(utxo_item)
        utxo_item[self.Columns.OUTPOINT].setData(name, self.ROLE_CLIPBOARD_DATA)
        utxo_item[self.Columns.ADDRESS].setFont(QFont(MONOSPACE_FONT))
        utxo_item[self.Columns.AMOUNT].setFont(QFont(MONOSPACE_FONT))
        utxo_item[self.Columns.OUTPOINT].setFont(QFont(MONOSPACE_FONT))
        utxo_item[self.Columns.ADDRESS].setData(name, Qt.UserRole)
        SELECTED_TO_SPEND_TOOLTIP = _('Coin selected to be spent')
        if name in (self._spend_set or set()):
            for col in utxo_item:
                col.setBackground(ColorScheme.GREEN.as_color(True))
                if col != self.Columns.OUTPOINT:
                    col.setToolTip(SELECTED_TO_SPEND_TOOLTIP)
        if self.wallet.is_frozen_address(address):
            utxo_item[self.Columns.ADDRESS].setBackground(ColorScheme.BLUE.as_color(True))
            utxo_item[self.Columns.ADDRESS].setToolTip(_('Address is frozen'))
        if self.wallet.is_frozen_coin(utxo):
            utxo_item[self.Columns.OUTPOINT].setBackground(ColorScheme.BLUE.as_color(True))
            utxo_item[self.Columns.OUTPOINT].setToolTip(f"{name}\n{_('Coin is frozen')}")
        else:
            tooltip = ("\n" + SELECTED_TO_SPEND_TOOLTIP) if name in (self._spend_set or set()) else ""
            utxo_item[self.Columns.OUTPOINT].setToolTip(name + tooltip)
        self.model().insertRow(idx, utxo_item)

    def get_selected_outpoints(self) -> Optional[List[str]]:
        if not self.model():
            return None
        items = self.selected_in_column(self.Columns.ADDRESS)
        return [x.data(Qt.UserRole) for x in items]

    def _filter_frozen_coins(self, coins: List[PartialTxInput]) -> List[PartialTxInput]:
        coins = [utxo for utxo in coins
                 if (not self.wallet.is_frozen_address(utxo.address) and
                     not self.wallet.is_frozen_coin(utxo))]
        return coins

    def set_spend_list(self, coins: Optional[List[PartialTxInput]]):
        if coins is not None:
            coins = self._filter_frozen_coins(coins)
            self._spend_set = {utxo.prevout.to_str() for utxo in coins}
        else:
            self._spend_set = None
        self.update()

    def get_spend_list(self) -> Optional[Sequence[PartialTxInput]]:
        if self._spend_set is None:
            return None
        utxos = [self._utxo_dict[x] for x in self._spend_set]
        return copy.deepcopy(utxos)  # copy so that side-effects don't affect utxo_dict

    def _maybe_reset_spend_list(self, current_wallet_utxos: Sequence[PartialTxInput]) -> None:
        if self._spend_set is None:
            return
        # if we spent one of the selected UTXOs, just reset selection
        utxo_set = {utxo.prevout.to_str() for utxo in current_wallet_utxos}
        if not all([prevout_str in utxo_set for prevout_str in self._spend_set]):
            self._spend_set = None

    def create_menu(self, position):
        selected = self.get_selected_outpoints()
        if selected is None:
            return
        menu = QMenu()
        menu.setSeparatorsCollapsible(True)  # consecutive separators are merged together
        coins = [self._utxo_dict[name] for name in selected]
        if len(coins) == 0:
            menu.addAction(_("Spend (select none)"), lambda: self.set_spend_list(coins))
        else:
            menu.addAction(_("Spend"), lambda: self.set_spend_list(coins))

        if len(coins) == 1:
            utxo = coins[0]
            addr = utxo.address
            txid = utxo.prevout.txid.hex()
            # "Details"
            tx = self.wallet.db.get_transaction(txid)
            if tx:
                label = self.wallet.get_label(txid) or None # Prefer None if empty (None hides the Description: field in the window)
                menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx, tx_desc=label))
            # "Copy ..."
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            self.add_copy_menu(menu, idx)
            # "Freeze coin"
            if not self.wallet.is_frozen_coin(utxo):
                menu.addAction(_("Freeze Coin"), lambda: self.parent.set_frozen_state_of_coins([utxo], True))
            else:
                menu.addSeparator()
                menu.addAction(_("Coin is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Coin"), lambda: self.parent.set_frozen_state_of_coins([utxo], False))
                menu.addSeparator()
            # "Freeze address"
            if not self.wallet.is_frozen_address(addr):
                menu.addAction(_("Freeze Address"), lambda: self.parent.set_frozen_state_of_addresses([addr], True))
            else:
                menu.addSeparator()
                menu.addAction(_("Address is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Address"), lambda: self.parent.set_frozen_state_of_addresses([addr], False))
                menu.addSeparator()
        elif len(coins) > 1:  # multiple items selected
            menu.addSeparator()
            addrs = [utxo.address for utxo in coins]
            is_coin_frozen = [self.wallet.is_frozen_coin(utxo) for utxo in coins]
            is_addr_frozen = [self.wallet.is_frozen_address(utxo.address) for utxo in coins]
            if not all(is_coin_frozen):
                menu.addAction(_("Freeze Coins"), lambda: self.parent.set_frozen_state_of_coins(coins, True))
            if any(is_coin_frozen):
                menu.addAction(_("Unfreeze Coins"), lambda: self.parent.set_frozen_state_of_coins(coins, False))
            if not all(is_addr_frozen):
                menu.addAction(_("Freeze Addresses"), lambda: self.parent.set_frozen_state_of_addresses(addrs, True))
            if any(is_addr_frozen):
                menu.addAction(_("Unfreeze Addresses"), lambda: self.parent.set_frozen_state_of_addresses(addrs, False))

        menu.exec_(self.viewport().mapToGlobal(position))
