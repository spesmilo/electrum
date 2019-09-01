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
from electroncash.plugins import run_hook
from electroncash.address import Address
from electroncash import cashacct
from collections import defaultdict
from functools import wraps
from enum import IntEnum


class UTXOList(MyTreeWidget):
    class Col(IntEnum):
        '''Column numbers. This is to make code in on_update easier to read.
        If you modify these, make sure to modify the column header names in
        the MyTreeWidget constructor.'''
        address = 0
        label   = 1
        amount  = 2
        height  = 3
        output_point = 4
    class DataRoles(IntEnum):
        '''Data roles. Again, to make code in on_update easier to read.'''
        name         = Qt.UserRole + 0
        frozen_flags = Qt.UserRole + 1
        address      = Qt.UserRole + 2
        cash_account = Qt.UserRole + 3  # this may not always be there for a particular item
        slp_token    = Qt.UserRole + 4  # this is either a tuple of (token_id, qty) or None

    filter_columns = [Col.address, Col.label]
    default_sort = MyTreeWidget.SortSpec(Col.amount, Qt.DescendingOrder)  # sort by amount, descending

    def __init__(self, parent=None):
        columns = [ _('Address'), _('Label'), _('Amount'), _('Height'), _('Output point') ]
        MyTreeWidget.__init__(self, parent, self.create_menu, columns,
                              stretch_column = UTXOList.Col.label,
                              deferred_updates = True, save_sort_settings = True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.wallet = self.parent.wallet
        self.parent.ca_address_default_changed_signal.connect(self._ca_on_address_default_change)
        self.parent.gui_object.cashaddr_toggled_signal.connect(self.update)
        self.utxos = list()
        # cache some values to avoid constructing Qt objects for every pass through self.on_update (this is important for large wallets)
        self.monospaceFont = QFont(MONOSPACE_FONT)
        self.lightBlue = QColor('lightblue') if not ColorScheme.dark_scheme else QColor('blue')
        self.blue = ColorScheme.BLUE.as_color(True)
        self.cyanBlue = QColor('#3399ff')
        self.slpBG = ColorScheme.SLPGREEN.as_color(True)

        self.cleaned_up = False

    def clean_up(self):
        self.cleaned_up = True
        try: self.parent.ca_address_default_changed_signal.disconnect(self._ca_on_address_default_change)
        except TypeError: pass
        try: self.parent.gui_object.cashaddr_toggled_signal.disconnect(self.update)
        except TypeError: pass

    def if_not_dead(func):
        '''Boilerplate: Check if cleaned up, and if so, don't execute method'''
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.cleaned_up or not self.wallet or not self.parent:
                return
            else:
                func(self, *args, **kwargs)
        return wrapper

    def get_name(self, x):
        return x.get('prevout_hash') + ":%d"%x.get('prevout_n')

    def get_name_short(self, x):
        return x.get('prevout_hash')[:10] + '...' + ":%d"%x.get('prevout_n')

    @rate_limited(1.0, ts_after=True) # performance tweak -- limit updates to no more than oncer per second
    def update(self):
        if self.cleaned_up:
            # short-cut return if window was closed and wallet is stopped
            return
        super().update()

    @if_not_dead
    def on_update(self):
        prev_selection = self.get_selected() # cache previous selection, if any
        self.clear()
        ca_by_addr = defaultdict(list)
        if self.show_cash_accounts:
            addr_set = set()
            self.utxos = self.wallet.get_utxos(addr_set_out=addr_set, exclude_slp=False)
            # grab all cash accounts so that we may add the emoji char
            for info in self.wallet.cashacct.get_cashaccounts(addr_set):
                ca_by_addr[info.address].append(info)
                del info
            for ca_list in ca_by_addr.values():
                ca_list.sort(key=lambda info: ((info.number or 0), str(info.collision_hash)))  # sort the ca_lists by number, required by cashacct.get_address_default
                del ca_list  # reference still exists inside ca_by_addr dict, this is just deleted here because we re-use this name below.
            del addr_set  # clean-up. We don't want the below code to ever depend on the existence of this cell.
        else:
            self.utxos = self.wallet.get_utxos(exclude_slp=False)
        for x in self.utxos:
            address = x['address']
            address_text = address.to_ui_string()
            ca_info = None
            ca_list = ca_by_addr.get(address)
            tool_tip0 = None
            if ca_list:
                ca_info = self.wallet.cashacct.get_address_default(ca_list)
                address_text = f'{ca_info.emoji} {address_text}'  # prepend the address emoji char
                tool_tip0 = self.wallet.cashacct.fmt_info(ca_info, emoji=True)
            height = x['height']
            name = self.get_name(x)
            name_short = self.get_name_short(x)
            label = self.wallet.get_label(x['prevout_hash'])
            amount = self.parent.format_amount(x['value'], is_diff=False, whitespaces=True)
            utxo_item = SortableTreeWidgetItem([address_text, label, amount,
                                                str(height), name_short])
            if label:
                utxo_item.setToolTip(1, label)  # just in case it doesn't fit horizontally, we also provide it as a tool tip where hopefully it won't be elided
            if tool_tip0:
                utxo_item.setToolTip(0, tool_tip0)
            utxo_item.setToolTip(4, name)  # just in case they like to see lots of hex digits :)
            utxo_item.DataRole = Qt.UserRole+100 # set this here to avoid sorting based on Qt.UserRole+1
            utxo_item.setFont(0, self.monospaceFont)
            utxo_item.setFont(2, self.monospaceFont)
            utxo_item.setFont(4, self.monospaceFont)
            utxo_item.setData(0, self.DataRoles.name, name)
            a_frozen = self.wallet.is_frozen(address)
            c_frozen = x['is_frozen_coin']
            toolTipMisc = ''
            slp_token = x['slp_token']
            if slp_token:
                utxo_item.setBackground(0, self.slpBG)
                toolTipMisc = _('Coin contains an SLP token')
            elif a_frozen and not c_frozen:
                # address is frozen, coin is not frozen
                # emulate the "Look" off the address_list .py's frozen entry
                utxo_item.setBackground(0, self.lightBlue)
                toolTipMisc = _("Address is frozen")
            elif c_frozen and not a_frozen:
                # coin is frozen, address is not frozen
                utxo_item.setBackground(0, self.blue)
                toolTipMisc = _("Coin is frozen")
            elif c_frozen and a_frozen:
                # both coin and address are frozen so color-code it to indicate that.
                utxo_item.setBackground(0, self.lightBlue)
                utxo_item.setForeground(0, self.cyanBlue)
                toolTipMisc = _("Coin & Address are frozen")
            # save the address-level-frozen and coin-level-frozen flags to the data item for retrieval later in create_menu() below.
            utxo_item.setData(0, self.DataRoles.frozen_flags, "{}{}{}".format(("a" if a_frozen else ""), ("c" if c_frozen else ""), ("s" if slp_token else "")))
            # store the address
            utxo_item.setData(0, self.DataRoles.address, address)
            # store the ca_info for this address -- if any
            if ca_info:
                utxo_item.setData(0, self.DataRoles.cash_account, ca_info)
            # store the slp_token
            utxo_item.setData(0, self.DataRoles.slp_token, slp_token)
            if toolTipMisc:
                utxo_item.setToolTip(0, toolTipMisc)
            run_hook("utxo_list_item_setup", self, utxo_item, x, name)
            self.addChild(utxo_item)
            if name in prev_selection:
                # NB: This needs to be here after the item is added to the widget. See #979.
                utxo_item.setSelected(True) # restore previous selection

    def get_selected(self):
        return { x.data(0, self.DataRoles.name) : x.data(0, self.DataRoles.frozen_flags) # dict of "name" -> frozen flags string (eg: "ac")
                for x in self.selectedItems() }

    @if_not_dead
    def create_menu(self, position):
        menu = QMenu()
        selected = self.get_selected()
        def create_menu_inner():
            if not selected:
                return
            coins = filter(lambda x: self.get_name(x) in selected, self.utxos)
            if not coins:
                return
            spendable_coins = list(filter(lambda x: not selected.get(self.get_name(x), ''), coins))
            # Unconditionally add the "Spend" option but leave it disabled if there are no spendable_coins
            spend_action = menu.addAction(_("Spend"), lambda: self.parent.spend_coins(spendable_coins))
            spend_action.setEnabled(bool(spendable_coins))
            if len(selected) == 1:
                # "Copy ..."
                item = self.itemAt(position)
                if not item:
                    return

                col = self.currentColumn()
                column_title = self.headerItem().text(col)
                alt_column_title, alt_copy_text = None, None
                slp_token = item.data(0, self.DataRoles.slp_token)
                ca_info = None
                if col == self.Col.output_point:
                    copy_text = item.data(0, self.DataRoles.name)
                elif col == self.Col.address:
                    addr = item.data(0, self.DataRoles.address)
                    # Determine the "alt copy text" "Legacy Address" or "Cash Address"
                    copy_text = addr.to_full_ui_string()
                    if Address.FMT_UI == Address.FMT_LEGACY:
                        alt_copy_text, alt_column_title = addr.to_full_string(Address.FMT_CASHADDR), _('Cash Address')
                    else:
                        alt_copy_text, alt_column_title = addr.to_full_string(Address.FMT_LEGACY), _('Legacy Address')
                    ca_info = item.data(0, self.DataRoles.cash_account)  # may be None
                    del addr
                else:
                    copy_text = item.text(col)
                if copy_text:
                    copy_text = copy_text.strip()  # make sure formatted amount is not whitespaced
                menu.addAction(_("Copy {}").format(column_title), lambda: QApplication.instance().clipboard().setText(copy_text))
                if alt_copy_text and alt_column_title:
                    menu.addAction(_("Copy {}").format(alt_column_title), lambda: QApplication.instance().clipboard().setText(alt_copy_text))
                if ca_info:
                    self.wallet.cashacct.fmt_info(ca_info)  # paranoia: pre-cache minimal chash (may go out to network)
                    menu.addAction(_("Copy Cash Account"), lambda: self.wallet and QApplication.instance().clipboard().setText(self.wallet.cashacct.fmt_info(ca_info, emoji=True)))

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
                if slp_token and not spend_action.isEnabled():
                    spend_action.setText(_("SLP Token: Spend Locked"))
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

        create_menu_inner()

        run_hook('utxo_list_context_menu_setup', self, menu, selected)

        # add optional toggle actions
        menu.addSeparator()
        def toggle():
            self.show_cash_accounts = not self.show_cash_accounts
        a = menu.addAction(_("Show Cash Accounts"), toggle)
        a.setCheckable(True)
        a.setChecked(self.show_cash_accounts)

        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # disable editing fields in this tab (labels)
        return False

    @if_not_dead
    def set_frozen_coins(self, coins, b):
        self.parent.set_frozen_coin_state(coins, b)

    @if_not_dead
    def set_frozen_addresses_for_coins(self, coins, b):
        addrs = set()
        for utxo in self.utxos:
            name = self.get_name(utxo)
            if name in coins:
                addrs.add(utxo['address'])
        if addrs:
            self.parent.set_frozen_state(list(addrs), b)

    @if_not_dead
    def update_labels(self):
        if self.should_defer_update_incr():
            return
        root = self.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            try:
                txid = item.data(0, self.DataRoles.name).split(':', 1)[0]
            except IndexError:
                continue # name is iinvalid. should be txid:prevout_n
            label = self.wallet.get_label(txid)
            item.setText(1, label)

    def _ca_on_address_default_change(self, info):
        if self.show_cash_accounts:
            self.update()

    @property
    def show_cash_accounts(self):
        return bool(self.wallet.storage.get('utxo_list_show_cash_accounts', False))

    @show_cash_accounts.setter
    def show_cash_accounts(self, b):
        b = bool(b)
        was = self.show_cash_accounts
        if was != b:
            self.wallet.storage.put('utxo_list_show_cash_accounts', b)
            self.update()
