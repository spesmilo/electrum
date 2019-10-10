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

from functools import partial
from collections import defaultdict

from .util import MyTreeWidget, MONOSPACE_FONT, SortableTreeWidgetItem, rate_limited, webopen
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QKeySequence, QCursor, QIcon
from PyQt5.QtWidgets import QTreeWidgetItem, QAbstractItemView, QMenu, QToolTip
from electroncash.i18n import _
from electroncash.address import Address
from electroncash.plugins import run_hook
import electroncash.web as web
from electroncash.util import profiler
from electroncash import networks
from enum import IntEnum
from . import cashacctqt

class AddressList(MyTreeWidget):
    filter_columns = [0, 1, 2]  # Address, Label, Balance

    _ca_minimal_chash_updated_signal = pyqtSignal(object, str)
    _cashacct_icon = None

    class DataRoles(IntEnum):
        address        = Qt.UserRole + 0
        can_edit_label = Qt.UserRole + 1
        cash_accounts  = Qt.UserRole + 2

    def __init__(self, parent, *, picker=False):
        super().__init__(parent, self.create_menu, [], 2, deferred_updates=True)
        self.refresh_headers()
        self.picker = picker
        if self.picker:
            self.setSelectionMode(QAbstractItemView.SingleSelection)
            self.editable_columns = []
        else:
            self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.wallet = self.parent.wallet
        self.monospace_font = QFont(MONOSPACE_FONT)
        assert self.wallet
        self.cleaned_up = False

        # Cash Accounts support
        self._ca_cb_registered = False
        self._ca_minimal_chash_updated_signal.connect(self._ca_update_chash)

        self.parent.gui_object.cashaddr_toggled_signal.connect(self.update)
        self.parent.ca_address_default_changed_signal.connect(self._ca_on_address_default_change)

        if not __class__._cashacct_icon:
            # lazy init the icon
            __class__._cashacct_icon = QIcon(":icons/cashacct-logo.png")  # TODO: make this an SVG

    def clean_up(self):
        self.cleaned_up = True
        if self.wallet.network:
            self.wallet.network.unregister_callback(self._ca_updated_minimal_chash_callback)
            self._ca_cb_registered = False
        # paranoia -- we have seen Qt not clean up the signal before the object is destroyed on Python 3.7.3 PyQt 5.12.3, see #1531
        try: self.parent.gui_object.cashaddr_toggled_signal.disconnect(self.update)
        except TypeError: pass
        try: self.parent.ca_address_default_changed_signal.disconnect(self._ca_on_address_default_change)
        except TypeError: pass

    def filter(self, p):
        ''' Reimplementation from superclass filter.  Chops off the
        "bitcoincash:" prefix so that address filters ignore this prefix.
        Closes #1440. '''
        cashaddr_prefix = f"{networks.net.CASHADDR_PREFIX}:".lower()
        p = p.strip()
        if len(p) > len(cashaddr_prefix) and p.lower().startswith(cashaddr_prefix):
            p = p[len(cashaddr_prefix):]  # chop off prefix
        super().filter(p)  # call super on chopped-off-piece

    def refresh_headers(self):
        headers = [ _('Address'), _('Index'),_('Label'), _('Balance'), _('Tx')]
        fx = self.parent.fx
        if fx and fx.get_fiat_address_config():
            headers.insert(4, '{} {}'.format(fx.get_currency(), _('Balance')))
        self.update_headers(headers)

    @rate_limited(1.0, ts_after=True) # We rate limit the address list refresh no more than once every second
    def update(self):
        if self.cleaned_up:
            # short-cut return if window was closed and wallet is stopped
            return
        super().update()

    @profiler
    def on_update(self):
        def item_path(item): # Recursively builds the path for an item eg 'parent_name/item_name'
            return item.text(0) if not item.parent() else item_path(item.parent()) + "/" + item.text(0)
        def remember_expanded_items(root):
            # Save the set of expanded items... so that address list updates don't annoyingly collapse
            # our tree list widget due to the update. This function recurses. Pass self.invisibleRootItem().
            expanded_item_names = set()
            for i in range(0, root.childCount()):
                it = root.child(i)
                if it and it.childCount():
                    if it.isExpanded():
                        expanded_item_names.add(item_path(it))
                    expanded_item_names |= remember_expanded_items(it) # recurse
            return expanded_item_names
        def restore_expanded_items(root, expanded_item_names):
            # Recursively restore the expanded state saved previously. Pass self.invisibleRootItem().
            for i in range(0, root.childCount()):
                it = root.child(i)
                if it and it.childCount():
                    restore_expanded_items(it, expanded_item_names) # recurse, do leaves first
                    old = bool(it.isExpanded())
                    new = bool(item_path(it) in expanded_item_names)
                    if old != new:
                        it.setExpanded(new)
        if not self._ca_cb_registered and self.wallet.network:
            self.wallet.network.register_callback(self._ca_updated_minimal_chash_callback, ['ca_updated_minimal_chash'])
            self._ca_cb_registered = True
        had_item_count = self.topLevelItemCount()
        sels = self.selectedItems()
        addresses_to_re_select = {item.data(0, self.DataRoles.address) for item in sels}
        expanded_item_names = remember_expanded_items(self.invisibleRootItem())
        del sels  # avoid keeping reference to about-to-be delete C++ objects
        self.clear()
        # Note we take a shallow list-copy because we want to avoid
        # race conditions with the wallet while iterating here. The wallet may
        # touch/grow the returned lists at any time if a history comes (it
        # basically returns a reference to its own internal lists). The wallet
        # may then, in another thread such as the Synchronizer thread, grow
        # the receiving or change addresses on Deterministic wallets.  While
        # probably safe in a language like Python -- and especially since
        # the lists only grow at the end, we want to avoid bad habits.
        # The performance cost of the shallow copy below is negligible for 10k+
        # addresses even on huge wallets because, I suspect, internally CPython
        # does this type of operation extremely cheaply (probably returning
        # some copy-on-write-semantics handle to the same list).
        receiving_addresses = list(self.wallet.get_receiving_addresses())
        change_addresses = list(self.wallet.get_change_addresses())

        if self.parent.fx and self.parent.fx.get_fiat_address_config():
            fx = self.parent.fx
        else:
            fx = None
        account_item = self
        sequences = [0,1] if change_addresses else [0]
        items_to_re_select = []
        for is_change in sequences:
            if len(sequences) > 1:
                name = _("Receiving") if not is_change else _("Change")
                seq_item = QTreeWidgetItem( [ name, '', '', '', '', ''] )
                account_item.addChild(seq_item)
                if not had_item_count: # first time we create this widget, auto-expand the default address list
                    seq_item.setExpanded(True)
                    expanded_item_names.add(item_path(seq_item))
            else:
                seq_item = account_item
            hidden_item = QTreeWidgetItem( [ _("Empty") if is_change else _("Used"), '', '', '', '', ''] )
            has_hidden = False
            addr_list = change_addresses if is_change else receiving_addresses
            # Cash Account support - we do this here with the already-prepared addr_list for performance reasons
            ca_list_all = self.wallet.cashacct.get_cashaccounts(addr_list)
            ca_by_addr = defaultdict(list)
            for info in ca_list_all:
                ca_by_addr[info.address].append(info)
            del ca_list_all
            # / cash account
            for n, address in enumerate(addr_list):
                num = len(self.wallet.get_address_history(address))
                if is_change:
                    is_hidden = self.wallet.is_empty(address)
                else:
                    is_hidden = self.wallet.is_used(address)
                balance = sum(self.wallet.get_addr_balance(address))
                address_text = address.to_ui_string()
                # Cash Accounts
                ca_info, ca_list = None, ca_by_addr.get(address)
                if ca_list:
                    # Add Cash Account emoji -- the emoji used is the most
                    # recent cash account registration for said address
                    ca_list.sort(key=lambda x: ((x.number or 0), str(x.collision_hash)))
                    for ca in ca_list:
                        # grab minimal_chash and stash in an attribute. this may kick off the network
                        ca.minimal_chash = self.wallet.cashacct.get_minimal_chash(ca.name, ca.number, ca.collision_hash)
                    ca_info = self._ca_get_default(ca_list)
                    if ca_info:
                        address_text = ca_info.emoji + " " + address_text
                # /Cash Accounts
                label = self.wallet.labels.get(address.to_storage_string(), '')
                balance_text = self.parent.format_amount(balance, whitespaces=True)
                columns = [address_text, str(n), label, balance_text, str(num)]
                if fx:
                    rate = fx.exchange_rate()
                    fiat_balance = fx.value_str(balance, rate)
                    columns.insert(4, fiat_balance)
                address_item = SortableTreeWidgetItem(columns)
                if ca_info:
                    # Set Cash Accounts: tool tip.. this will read the minimal_chash attribute we added to this object above
                    self._ca_set_item_tooltip(address_item, ca_info)
                address_item.setTextAlignment(3, Qt.AlignRight)
                address_item.setFont(3, self.monospace_font)
                if fx:
                    address_item.setTextAlignment(4, Qt.AlignRight)
                    address_item.setFont(4, self.monospace_font)

                # Set col0 address font to monospace
                address_item.setFont(0, self.monospace_font)

                # Set UserRole data items:
                address_item.setData(0, self.DataRoles.address, address)
                address_item.setData(0, self.DataRoles.can_edit_label, True) # label can be edited
                if ca_list:
                    # Save the list of cashacct infos, if any
                    address_item.setData(0, self.DataRoles.cash_accounts, ca_list)

                if self.wallet.is_frozen(address):
                    address_item.setBackground(0, QColor('lightblue'))
                if self.wallet.is_beyond_limit(address, is_change):
                    address_item.setBackground(0, QColor('red'))
                if is_hidden:
                    if not has_hidden:
                        seq_item.insertChild(0, hidden_item)
                        has_hidden = True
                    hidden_item.addChild(address_item)
                else:
                    seq_item.addChild(address_item)
                if address in addresses_to_re_select:
                    items_to_re_select.append(address_item)

        for item in items_to_re_select:
            # NB: Need to select the item at the end becasue internally Qt does some index magic
            # to pick out the selected item and the above code mutates the TreeList, invalidating indices
            # and other craziness, which might produce UI glitches. See #1042
            item.setSelected(True)

        # Now, at the very end, enforce previous UI state with respect to what was expanded or not. See #1042
        restore_expanded_items(self.invisibleRootItem(), expanded_item_names)


    def create_menu(self, position):
        if self.picker:
            # picker mode has no menu
            return
        from electroncash.wallet import Multisig_Wallet
        is_multisig = isinstance(self.wallet, Multisig_Wallet)
        can_delete = self.wallet.can_delete_address()
        selected = self.selectedItems()
        multi_select = len(selected) > 1
        addrs = [item.data(0, self.DataRoles.address) for item in selected]
        if not addrs:
            return
        addrs = [addr for addr in addrs if isinstance(addr, Address)]

        menu = QMenu()

        where_to_insert_dupe_copy_cash_account = None

        def doCopy(txt):
            txt = txt.strip()
            self.parent.copy_to_clipboard(txt)

        col = self.currentColumn()
        column_title = self.headerItem().text(col)

        if not multi_select:
            item = self.itemAt(position)
            if not item:
                return
            if not addrs:
                item.setExpanded(not item.isExpanded())
                return
            addr = addrs[0]

            alt_copy_text, alt_column_title = None, None
            if col == 0:
                copy_text = addr.to_full_ui_string()
                if Address.FMT_UI == Address.FMT_LEGACY:
                    alt_copy_text, alt_column_title = addr.to_full_string(Address.FMT_CASHADDR), _('Cash Address')
                else:
                    alt_copy_text, alt_column_title = addr.to_full_string(Address.FMT_LEGACY), _('Legacy Address')
            else:
                copy_text = item.text(col)
            menu.addAction(_("Copy {}").format(column_title), lambda: doCopy(copy_text))
            if alt_copy_text and alt_column_title:
                # Add 'Copy Legacy Address' and 'Copy Cash Address' alternates if right-click is on column 0
                menu.addAction(_("Copy {}").format(alt_column_title), lambda: doCopy(alt_copy_text))
            a = menu.addAction(_('Details') + "...", lambda: self.parent.show_address(addr))
            if col == 0:
                where_to_insert_dupe_copy_cash_account = a
            if col in self.editable_columns:
                menu.addAction(_("Edit {}").format(column_title), lambda: self.editItem(self.itemAt(position), # NB: C++ item may go away if this widget is refreshed while menu is up -- so need to re-grab and not store in lamba. See #953
                                                                                        col))
            a = menu.addAction(_("Request payment"), lambda: self.parent.receive_at(addr))
            if self.wallet.get_num_tx(addr) or self.wallet.has_payment_request(addr):
                # This address cannot be used for a payment request because
                # the receive tab will refuse to display it and will instead
                # create a request with a new address, if we were to call
                # self.parent.receive_at(addr). This is because the recieve tab
                # now strongly enforces no-address-reuse. See #1552.
                a.setDisabled(True)
            if self.wallet.can_export():
                menu.addAction(_("Private key"), lambda: self.parent.show_private_key(addr))
            if not is_multisig and not self.wallet.is_watching_only():
                menu.addAction(_("Sign/verify message"), lambda: self.parent.sign_verify_message(addr))
                menu.addAction(_("Encrypt/decrypt message"), lambda: self.parent.encrypt_message(addr))
            if can_delete:
                menu.addAction(_("Remove from wallet"), lambda: self.parent.remove_address(addr))
            addr_URL = web.BE_URL(self.config, 'addr', addr)
            if addr_URL:
                menu.addAction(_("View on block explorer"), lambda: webopen(addr_URL))
        else:
            # multi-select
            if col > -1:
                texts, alt_copy, alt_copy_text = None, None, None
                if col == 0: # address column
                    texts = [a.to_ui_string() for a in addrs]
                    # Add additional copy option: "Address, Balance (n)"
                    alt_copy = _("Copy {}").format(_("Address") + ", " + _("Balance")) + f" ({len(addrs)})"
                    alt_copy_text = "\n".join([a.to_ui_string() + ", " + self.parent.format_amount(sum(self.wallet.get_addr_balance(a)))
                                              for a in addrs])
                else:
                    texts = [i.text(col).strip() for i in selected]
                    texts = [t for t in texts if t]  # omit empty items
                if texts:
                    copy_text = '\n'.join(texts)
                    menu.addAction(_("Copy {}").format(column_title) + f" ({len(texts)})", lambda: doCopy(copy_text))
                if alt_copy and alt_copy_text:
                    menu.addAction(alt_copy, lambda: doCopy(alt_copy_text))

        freeze = self.parent.set_frozen_state
        if any(self.wallet.is_frozen(addr) for addr in addrs):
            menu.addAction(_("Unfreeze"), partial(freeze, addrs, False))
        if not all(self.wallet.is_frozen(addr) for addr in addrs):
            menu.addAction(_("Freeze"), partial(freeze, addrs, True))

        coins = self.wallet.get_spendable_coins(domain = addrs, config = self.config)
        if coins:
            menu.addAction(_("Spend from"),
                           partial(self.parent.spend_coins, coins))

        # Add Cash Accounts section at the end, if relevant
        if not multi_select:
            ca_list = item.data(0, self.DataRoles.cash_accounts)
            menu.addSeparator()
            a1 = menu.addAction(_("Cash Accounts"), lambda: None)
            a1.setDisabled(True)
            if ca_list:
                ca_default = self._ca_get_default(ca_list)
                for ca_info in ca_list:
                    ca_text = self.wallet.cashacct.fmt_info(ca_info, ca_info.minimal_chash)
                    ca_text_em = self.wallet.cashacct.fmt_info(ca_info, ca_info.minimal_chash, emoji=True)
                    m = menu.addMenu(ca_info.emoji + " " + ca_text)
                    a_ca_copy = m.addAction(_("Copy Cash Account"), lambda x=None, text=ca_text_em: doCopy(text))
                    a = m.addAction(_("Details") + "...", lambda x=None,ca_text=ca_text: cashacctqt.cash_account_detail_dialog(self.parent, ca_text))
                    a = m.addAction(_("View registration tx") + "...", lambda x=None, ca=ca_info: self.parent.do_process_from_txid(txid=ca.txid))
                    a = a_def = m.addAction(_("Make default for address"), lambda x=None, ca=ca_info: self._ca_set_default(ca, True))
                    if ca_info == ca_default:
                        if where_to_insert_dupe_copy_cash_account and a_ca_copy:
                            # insert a dupe of "Copy Cash Account" for the default cash account for this address in the top-level menu
                            menu.insertAction(where_to_insert_dupe_copy_cash_account, a_ca_copy)
                        m.setTitle(m.title() + "    " + "★")
                        a_def.setDisabled(True)
                        a_def.setCheckable(True)
                        a_def.setChecked(True)
                        a_def.setText(_("Is default for address"))
            else:
                a1.setText(_("No Cash Accounts"))
            a_new = menu.addAction(_("Register new..."), lambda x=None, addr=addr: self.parent.register_new_cash_account(addr))
            a_new.setIcon(__class__._cashacct_icon)


        run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec_(self.viewport().mapToGlobal(position))

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.Copy) and self.currentColumn() == 0:
            addrs = [i.data(0, self.DataRoles.address) for i in self.selectedItems()]
            if addrs and isinstance(addrs[0], Address):
                text = addrs[0].to_full_ui_string()
                self.parent.app.clipboard().setText(text)
        else:
            super().keyPressEvent(event)

    def update_labels(self):
        if self.should_defer_update_incr():
            return
        def update_recurse(root):
            child_count = root.childCount()
            for i in range(child_count):
                item = root.child(i)
                addr = item.data(0, self.DataRoles.address)
                if isinstance(addr, Address):
                    label = self.wallet.labels.get(addr.to_storage_string(), '')
                    item.setText(2, label)
                if item.childCount():
                    update_recurse(item)
        update_recurse(self.invisibleRootItem())

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            super(AddressList, self).on_doubleclick(item, column)
        else:
            addr = item.data(0, self.DataRoles.address)
            if isinstance(addr, Address):
                self.parent.show_address(addr)

    #########################
    # Cash Accounts related #
    #########################
    def _ca_set_item_tooltip(self, item, ca_info):
        minimal_chash = getattr(ca_info, 'minimal_chash', None)
        info_str = self.wallet.cashacct.fmt_info(ca_info, minimal_chash)
        item.setToolTip(0, "<i>" + _("Cash Account:") + "</i><p>&nbsp;&nbsp;<b>"
                           + f"{info_str}</b>")

    def _ca_update_chash(self, ca_info, minimal_chash):
        ''' Called in GUI thread as a result of the cash account subsystem
        figuring out that a collision_hash can be represented shorter.
        Kicked off by a get_minimal_chash() call that results in a cache miss. '''
        if self.cleaned_up:
            return
        items = self.findItems(ca_info.address.to_ui_string(), Qt.MatchContains|Qt.MatchWrap|Qt.MatchRecursive, 0) or []
        for item in items:  # really items should contain just 1 element...
            ca_list = item.data(0, self.DataRoles.cash_accounts) or []
            ca_info_default = self._ca_get_default(ca_list)
            for ca_info_saved in ca_list:
                if ( (ca_info_saved.name.lower(), ca_info_saved.number, ca_info_saved.collision_hash)
                        == (ca_info.name.lower(), ca_info.number, ca_info.collision_hash) ):
                    ca_info_saved.minimal_chash = minimal_chash  # save minimal_chash as a property
                    if ca_info_saved == ca_info_default:
                        # this was the default one, also set the tooltip
                        self._ca_set_item_tooltip(item, ca_info)

    def _ca_updated_minimal_chash_callback(self, event, *args):
        ''' Called from the cash accounts minimal_chash thread after a network
        round-trip determined that the minimal collision hash can be shorter.'''
        if (event == 'ca_updated_minimal_chash'
                and not self.cleaned_up
                and args[0] is self.wallet.cashacct):
            self._ca_minimal_chash_updated_signal.emit(args[1], args[2])

    def _ca_get_default(self, ca_list):
        ''' Alias for self.wallet.cashacct.get_address_default '''
        return self.wallet.cashacct.get_address_default(ca_list)

    def _ca_set_default(self, ca_info, show_tip = False):
        ''' Similar to self.wallet.cashacct.set_address_default, but also
        shows a tooltip optionally, and updates self. '''
        self.wallet.cashacct.set_address_default(ca_info)
        if show_tip:
            QToolTip.showText(QCursor.pos(), _("Cash Account has been made the default for this address"), self)
        self.parent.ca_address_default_changed_signal.emit(ca_info)  # eventually calls self.update

    def _ca_on_address_default_change(self, ignored):
        self.update()
