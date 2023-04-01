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

from typing import Optional, List, Dict, Sequence, Set, TYPE_CHECKING
import enum
import copy

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView, QMenu, QLabel, QHBoxLayout

from electrum.i18n import _
from electrum.bitcoin import is_address
from electrum.transaction import PartialTxInput, PartialTxOutput
from electrum.lnutil import LN_MAX_FUNDING_SAT, MIN_FUNDING_SAT

from .util import ColorScheme, MONOSPACE_FONT, EnterButton
from .my_treeview import MyTreeView
from .new_channel_dialog import NewChannelDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class UTXOList(MyTreeView):
    _spend_set: Set[str]  # coins selected by the user to spend from
    _utxo_dict: Dict[str, PartialTxInput]  # coin name -> coin

    class Columns(MyTreeView.BaseColumnsEnum):
        OUTPOINT = enum.auto()
        ADDRESS = enum.auto()
        LABEL = enum.auto()
        AMOUNT = enum.auto()
        PARENTS = enum.auto()

    headers = {
        Columns.OUTPOINT: _('Output point'),
        Columns.ADDRESS: _('Address'),
        Columns.PARENTS: _('Parents'),
        Columns.LABEL: _('Label'),
        Columns.AMOUNT: _('Amount'),
    }
    filter_columns = [Columns.ADDRESS, Columns.LABEL, Columns.OUTPOINT]
    stretch_column = Columns.LABEL

    ROLE_PREVOUT_STR = Qt.UserRole + 1000
    key_role = ROLE_PREVOUT_STR

    def __init__(self, main_window: 'ElectrumWindow'):
        super().__init__(
            main_window=main_window,
            stretch_column=self.stretch_column,
        )
        self._spend_set = set()
        self._utxo_dict = {}
        self.wallet = self.main_window.wallet
        self.std_model = QStandardItemModel(self)
        self.setModel(self.std_model)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    def create_toolbar(self, config):
        toolbar, menu = self.create_toolbar_with_menu('')
        self.num_coins_label = toolbar.itemAt(0).widget()
        menu.addAction(_('Coin control'), lambda: self.add_selection_to_coincontrol())
        return toolbar

    def update(self):
        # not calling maybe_defer_update() as it interferes with coincontrol status bar
        utxos = self.wallet.get_utxos()
        utxos.sort(key=lambda x: x.block_height, reverse=True)
        self._maybe_reset_coincontrol(utxos)
        self._utxo_dict = {}
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for idx, utxo in enumerate(utxos):
            name = utxo.prevout.to_str()
            self._utxo_dict[name] = utxo
            labels = [""] * len(self.Columns)
            labels[self.Columns.OUTPOINT] = str(utxo.short_id)
            labels[self.Columns.ADDRESS] = utxo.address
            labels[self.Columns.AMOUNT] = self.main_window.format_amount(utxo.value_sats(), whitespaces=True)
            utxo_item = [QStandardItem(x) for x in labels]
            self.set_editability(utxo_item)
            utxo_item[self.Columns.OUTPOINT].setData(name, self.ROLE_PREVOUT_STR)
            utxo_item[self.Columns.ADDRESS].setFont(QFont(MONOSPACE_FONT))
            utxo_item[self.Columns.AMOUNT].setFont(QFont(MONOSPACE_FONT))
            utxo_item[self.Columns.PARENTS].setFont(QFont(MONOSPACE_FONT))
            utxo_item[self.Columns.OUTPOINT].setFont(QFont(MONOSPACE_FONT))
            self.model().insertRow(idx, utxo_item)
            self.refresh_row(name, idx)
        self.filter()
        self.update_coincontrol_bar()
        self.num_coins_label.setText(_('{} unspent transaction outputs').format(len(utxos)))

    def update_coincontrol_bar(self):
        # update coincontrol status bar
        if bool(self._spend_set):
            coins = [self._utxo_dict[x] for x in self._spend_set]
            coins = self._filter_frozen_coins(coins)
            amount = sum(x.value_sats() for x in coins)
            amount_str = self.main_window.format_amount_and_units(amount)
            num_outputs_str = _("{} outputs available ({} total)").format(len(coins), len(self._utxo_dict))
            self.main_window.set_coincontrol_msg(_("Coin control active") + f': {num_outputs_str}, {amount_str}')
        else:
            self.main_window.set_coincontrol_msg(None)

    def refresh_row(self, key, row):
        assert row is not None
        utxo = self._utxo_dict[key]
        utxo_item = [self.std_model.item(row, col) for col in self.Columns]
        txid = utxo.prevout.txid.hex()
        parents = self.wallet.get_tx_parents(txid)
        utxo_item[self.Columns.PARENTS].setText('%6s'%len(parents))
        label = self.wallet.get_label_for_txid(txid) or ''
        utxo_item[self.Columns.LABEL].setText(label)
        SELECTED_TO_SPEND_TOOLTIP = _('Coin selected to be spent')
        if key in self._spend_set:
            tooltip = key + "\n" + SELECTED_TO_SPEND_TOOLTIP
            color = ColorScheme.GREEN.as_color(True)
        else:
            tooltip = key
            color = self._default_bg_brush
        for col in utxo_item:
            col.setBackground(color)
            col.setToolTip(tooltip)
        if self.wallet.is_frozen_address(utxo.address):
            utxo_item[self.Columns.ADDRESS].setBackground(ColorScheme.BLUE.as_color(True))
            utxo_item[self.Columns.ADDRESS].setToolTip(_('Address is frozen'))
        if self.wallet.is_frozen_coin(utxo):
            utxo_item[self.Columns.OUTPOINT].setBackground(ColorScheme.BLUE.as_color(True))
            utxo_item[self.Columns.OUTPOINT].setToolTip(f"{key}\n{_('Coin is frozen')}")

    def get_selected_outpoints(self) -> List[str]:
        if not self.model():
            return []
        items = self.selected_in_column(self.Columns.OUTPOINT)
        return [x.data(self.ROLE_PREVOUT_STR) for x in items]

    def _filter_frozen_coins(self, coins: List[PartialTxInput]) -> List[PartialTxInput]:
        coins = [utxo for utxo in coins
                 if (not self.wallet.is_frozen_address(utxo.address) and
                     not self.wallet.is_frozen_coin(utxo))]
        return coins

    def are_in_coincontrol(self, coins: List[PartialTxInput]) -> bool:
        return all([utxo.prevout.to_str() in self._spend_set for utxo in coins])

    def add_to_coincontrol(self, coins: List[PartialTxInput]):
        coins = self._filter_frozen_coins(coins)
        for utxo in coins:
            self._spend_set.add(utxo.prevout.to_str())
        self._refresh_coincontrol()

    def remove_from_coincontrol(self, coins: List[PartialTxInput]):
        for utxo in coins:
            self._spend_set.remove(utxo.prevout.to_str())
        self._refresh_coincontrol()

    def clear_coincontrol(self):
        self._spend_set.clear()
        self._refresh_coincontrol()

    def add_selection_to_coincontrol(self):
        if bool(self._spend_set):
            self.clear_coincontrol()
            return
        selected = self.get_selected_outpoints()
        coins = [self._utxo_dict[name] for name in selected]
        if not coins:
            self.main_window.show_error(_('You need to select coins from the list first.\nUse ctrl+left mouse button to select multiple items'))
            return
        self.add_to_coincontrol(coins)

    def _refresh_coincontrol(self):
        self.refresh_all()
        self.update_coincontrol_bar()
        self.selectionModel().clearSelection()

    def get_spend_list(self) -> Optional[Sequence[PartialTxInput]]:
        if not bool(self._spend_set):
            return None
        utxos = [self._utxo_dict[x] for x in self._spend_set]
        return copy.deepcopy(utxos)  # copy so that side-effects don't affect utxo_dict

    def _maybe_reset_coincontrol(self, current_wallet_utxos: Sequence[PartialTxInput]) -> None:
        if not bool(self._spend_set):
            return
        # if we spent one of the selected UTXOs, just reset selection
        utxo_set = {utxo.prevout.to_str() for utxo in current_wallet_utxos}
        if not all([prevout_str in utxo_set for prevout_str in self._spend_set]):
            self._spend_set.clear()

    def can_swap_coins(self, coins):
        # fixme: min and max_amounts are known only after first request
        if self.wallet.lnworker is None:
            return False
        value = sum(x.value_sats() for x in coins)
        min_amount = self.wallet.lnworker.swap_manager.get_min_amount()
        max_amount = self.wallet.lnworker.swap_manager.max_amount_forward_swap()
        if value < min_amount:
            return False
        if max_amount is None or value > max_amount:
            return False
        return True

    def swap_coins(self, coins):
        #self.clear_coincontrol()
        self.add_to_coincontrol(coins)
        self.main_window.run_swap_dialog(is_reverse=False, recv_amount_sat='!')
        self.clear_coincontrol()

    def can_open_channel(self, coins):
        if self.wallet.lnworker is None:
            return False
        value = sum(x.value_sats() for x in coins)
        return value >= MIN_FUNDING_SAT and value <= LN_MAX_FUNDING_SAT

    def open_channel_with_coins(self, coins):
        # todo : use a single dialog in new flow
        #self.clear_coincontrol()
        self.add_to_coincontrol(coins)
        d = NewChannelDialog(self.main_window)
        d.max_button.setChecked(True)
        d.max_button.setEnabled(False)
        d.min_button.setEnabled(False)
        d.clear_button.setEnabled(False)
        d.amount_e.setFrozen(True)
        d.spend_max()
        d.run()
        self.clear_coincontrol()

    def clipboard_contains_address(self):
        text = self.main_window.app.clipboard().text()
        return is_address(text)

    def pay_to_clipboard_address(self, coins):
        addr = self.main_window.app.clipboard().text()
        outputs = [PartialTxOutput.from_address_and_value(addr, '!')]
        #self.clear_coincontrol()
        self.add_to_coincontrol(coins)
        self.main_window.send_tab.pay_onchain_dialog(outputs)
        self.clear_coincontrol()

    def on_double_click(self, idx):
        outpoint = idx.sibling(idx.row(), self.Columns.OUTPOINT).data(self.ROLE_PREVOUT_STR)
        utxo = self._utxo_dict[outpoint]
        self.main_window.show_utxo(utxo)

    def create_menu(self, position):
        selected = self.get_selected_outpoints()
        menu = QMenu()
        menu.setSeparatorsCollapsible(True)  # consecutive separators are merged together
        coins = [self._utxo_dict[name] for name in selected]
        if not coins:
            return
        if len(coins) == 1:
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            utxo = coins[0]
            txid = utxo.prevout.txid.hex()
            # "Details"
            tx = self.wallet.adb.get_transaction(txid)
            if tx:
                label = self.wallet.get_label_for_txid(txid)
                menu.addAction(_("Privacy analysis"), lambda: self.main_window.show_utxo(utxo))
            cc = self.add_copy_menu(menu, idx)
            cc.addAction(_("Long Output point"), lambda: self.place_text_on_clipboard(utxo.prevout.to_str(), title="Long Output point"))
        # fully spend
        menu_spend = menu.addMenu(_("Fully spend") + '…')
        m = menu_spend.addAction(_("send to address in clipboard"), lambda: self.pay_to_clipboard_address(coins))
        m.setEnabled(self.clipboard_contains_address())
        m = menu_spend.addAction(_("in new channel"), lambda: self.open_channel_with_coins(coins))
        m.setEnabled(self.can_open_channel(coins))
        m = menu_spend.addAction(_("in submarine swap"), lambda: self.swap_coins(coins))
        m.setEnabled(self.can_swap_coins(coins))
        # coin control
        if self.are_in_coincontrol(coins):
            menu.addAction(_("Remove from coin control"), lambda: self.remove_from_coincontrol(coins))
        else:
            menu.addAction(_("Add to coin control"), lambda: self.add_to_coincontrol(coins))
        # Freeze menu
        if len(coins) == 1:
            utxo = coins[0]
            addr = utxo.address
            menu_freeze = menu.addMenu(_("Freeze"))
            if not self.wallet.is_frozen_coin(utxo):
                menu_freeze.addAction(_("Freeze Coin"), lambda: self.main_window.set_frozen_state_of_coins([utxo], True))
            else:
                menu_freeze.addAction(_("Unfreeze Coin"), lambda: self.main_window.set_frozen_state_of_coins([utxo], False))
            if not self.wallet.is_frozen_address(addr):
                menu_freeze.addAction(_("Freeze Address"), lambda: self.main_window.set_frozen_state_of_addresses([addr], True))
            else:
                menu_freeze.addAction(_("Unfreeze Address"), lambda: self.main_window.set_frozen_state_of_addresses([addr], False))
        elif len(coins) > 1:  # multiple items selected
            menu.addSeparator()
            addrs = [utxo.address for utxo in coins]
            is_coin_frozen = [self.wallet.is_frozen_coin(utxo) for utxo in coins]
            is_addr_frozen = [self.wallet.is_frozen_address(utxo.address) for utxo in coins]
            menu_freeze = menu.addMenu(_("Freeze"))
            if not all(is_coin_frozen):
                menu_freeze.addAction(_("Freeze Coins"), lambda: self.main_window.set_frozen_state_of_coins(coins, True))
            if any(is_coin_frozen):
                menu_freeze.addAction(_("Unfreeze Coins"), lambda: self.main_window.set_frozen_state_of_coins(coins, False))
            if not all(is_addr_frozen):
                menu_freeze.addAction(_("Freeze Addresses"), lambda: self.main_window.set_frozen_state_of_addresses(addrs, True))
            if any(is_addr_frozen):
                menu_freeze.addAction(_("Unfreeze Addresses"), lambda: self.main_window.set_frozen_state_of_addresses(addrs, False))

        menu.exec_(self.viewport().mapToGlobal(position))

    def get_filter_data_from_coordinate(self, row, col):
        if col == self.Columns.OUTPOINT:
            return self.get_role_data_from_coordinate(row, col, role=self.ROLE_PREVOUT_STR)
        return super().get_filter_data_from_coordinate(row, col)
