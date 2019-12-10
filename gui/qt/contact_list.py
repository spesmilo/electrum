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

from electroncash.i18n import _, ngettext
import electroncash.web as web
from electroncash.address import Address
from electroncash.contacts import Contact, contact_types
from electroncash.plugins import run_hook
from electroncash.util import FileImportFailed, PrintError, finalization_print_error
# TODO: whittle down these * imports to what we actually use when done with
# our changes to this class -Calin
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from .util import (MyTreeWidget, webopen, WindowModalDialog, Buttons,
                   CancelButton, OkButton, HelpLabel, WWLabel,
                   destroyed_print_error, webopen, ColorScheme, MONOSPACE_FONT,
                   rate_limited)
from enum import IntEnum
from collections import defaultdict
from typing import List, Set, Dict, Tuple
from . import cashacctqt

class ContactList(PrintError, MyTreeWidget):
    filter_columns = [1, 2, 3]  # Name, Label, Address
    default_sort = MyTreeWidget.SortSpec(1, Qt.AscendingOrder)

    do_update_signal = pyqtSignal()
    _ca_minimal_chash_updated_signal = pyqtSignal(object, str)

    class DataRoles(IntEnum):
        Contact     = Qt.UserRole + 0

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu,
                              ["", _('Name'), _('Label'), _('Address'), _('Type') ], 2, [1,2],  # headers, stretch_column, editable_columns
                              deferred_updates=True, save_sort_settings=True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.wallet = parent.wallet
        self.setIndentation(0)
        self._edited_item_cur_sel = (None,) * 3
        self.monospace_font = QFont(MONOSPACE_FONT)
        self.cleaned_up = False
        self.do_update_signal.connect(self.update)
        self.icon_cashacct = QIcon(":icons/cashacct-logo.png" if not ColorScheme.dark_scheme else ":icons/cashacct-button-darkmode.png")
        self.icon_openalias = QIcon(":icons/openalias-logo.svg")
        self.icon_contacts = QIcon(":icons/tab_contacts.png")
        self.icon_unverif = QIcon(":/icons/unconfirmed.svg")
        # the below dict is ephemeral and goes away on wallet close --
        # it's populated ultimately by the notify() subsystem in main_window
        self._ca_pending_conf : Dict[str, Tuple[str, Address]] = dict()  #  "txid" -> ("name", Address)

        if self.wallet.network:
            self.wallet.network.register_callback(self._ca_callback, ['ca_verified_tx', 'ca_updated_minimal_chash'] )
        self._ca_minimal_chash_updated_signal.connect(self._ca_update_chash)
        self.parent.gui_object.cashaddr_toggled_signal.connect(self.update)


    def clean_up(self):
        self.cleaned_up = True
        try: self._ca_minimal_chash_updated_signal.disconnect(self._ca_update_chash)
        except TypeError: pass
        try: self.do_update_signal.disconnect(self.update)
        except TypeError: pass
        try: self.parent.gui_object.cashaddr_toggled_signal.disconnect(self.update)
        except TypeError: pass
        if self.wallet.network:
            self.wallet.network.unregister_callback(self._ca_callback)

    def on_permit_edit(self, item, column):
        # openalias items shouldn't be editable
        if column == 2: # Label, always editable
            return True
        return item.data(0, self.DataRoles.Contact).type in ('address', 'cashacct')

    def on_edited(self, item, column, prior_value):
        contact = item.data(0, self.DataRoles.Contact)
        if column == 2: # Label
            label_key = contact.address
            try: label_key = Address.from_string(label_key).to_storage_string()
            except: pass
            self.wallet.set_label(label_key, item.text(2))
            self.update() # force refresh in case 2 contacts use the same address
            return
        # else.. Name
        typ = contact.type
        was_cur, was_sel = bool(self.currentItem()), item.isSelected()
        name, value = item.text(1), item.text(3)
        del item  # paranoia

        # On success, parent.set_contact returns the new key (address text)
        # if 'cashacct'.. or always the same key for all other types.
        key = self.parent.set_contact(name, value, typ=typ, replace=contact)

        if key:
            # Due to deferred updates, on_update will actually be called later.
            # So, we have to save the edited item's "current" and "selected"
            # status here. 'on_update' will look at this tuple and clear it
            # after updating.
            self._edited_item_cur_sel = (key, was_cur, was_sel)

    def import_contacts(self):
        wallet_folder = self.parent.get_wallet_folder()
        filename, __ = QFileDialog.getOpenFileName(self.parent, "Select your wallet file", wallet_folder)
        if not filename:
            return
        try:
            num = self.parent.contacts.import_file(filename)
            self.parent.show_message(_("{} contacts successfully imported.").format(num))
        except Exception as e:
            self.parent.show_error(_("Electron Cash was unable to import your contacts.") + "\n" + repr(e))
        self.on_update()

    def export_contacts(self):
        if self.parent.contacts.empty:
            self.parent.show_error(_("Your contact list is empty."))
            return
        try:
            fileName = self.parent.getSaveFileName(_("Select file to save your contacts"), 'electron-cash-contacts.json', "*.json")
            if fileName:
                num = self.parent.contacts.export_file(fileName)
                self.parent.show_message(_("{} contacts exported to '{}'").format(num, fileName))
        except Exception as e:
            self.parent.show_error(_("Electron Cash was unable to export your contacts.") + "\n" + repr(e))

    def find_item(self, key: Contact) -> QTreeWidgetItem:
        ''' Rather than store the item reference in a lambda, we store its key.
        Storing the item reference can lead to C++ Runtime Errors if the
        underlying QTreeWidgetItem is deleted on .update() while the right-click
        menu is still up. This function returns a currently alive item given a
        key. '''
        for item in self.get_leaves():
            if item.data(0, self.DataRoles.Contact) == key:
                return item

    def _on_edit_item(self, key : Contact, column : int):
        ''' Callback from context menu, private method. '''
        item = self.find_item(key)
        if item:
            self.editItem(item, column)

    @staticmethod
    def _i2c(item : QTreeWidgetItem) -> Contact:
        return item.data(0, ContactList.DataRoles.Contact)

    def _get_ca_unverified(self, include_temp=False) -> Set[Contact]:
        i2c = self._i2c
        types = ('cashacct', 'cashacct_W')
        if include_temp:
            types = (*types, 'cashacct_T')
        return set(
            i2c(item)
            for item in self.get_leaves()
            if i2c(item).type in types and not self.wallet.cashacct.get_verified(i2c(item).name)
        )

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        i2c = self._i2c
        ca_unverified = self._get_ca_unverified(include_temp=False)
        if selected:
            names = [item.text(1) for item in selected]
            keys = [i2c(item) for item in selected]
            payable_keys = [k for k in keys if k.type != 'cashacct_T']
            deletable_keys = [k for k in keys if k.type in contact_types]
            needs_verif_keys = [k for k in keys if k in ca_unverified]
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            item = self.currentItem()
            typ = i2c(item).type if item else 'unknown'
            ca_info = None
            if item and typ in ('cashacct', 'cashacct_W'):
                ca_info = self.wallet.cashacct.get_verified(i2c(item).name)
                if column == 1 and len(selected) == 1:
                    # hack .. for Cash Accounts just say "Copy Cash Account"
                    column_title = _('Cash Account')
                    if ca_info:
                        column_data = self.wallet.cashacct.fmt_info(ca_info, emoji=True)
            if len(selected) > 1:
                column_title += f" ({len(selected)})"
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
            if item and column in self.editable_columns and self.on_permit_edit(item, column):
                key = item.data(0, self.DataRoles.Contact)
                # this key & find_item business is so we don't hold a reference
                # to the ephemeral item, which may be deleted while the
                # context menu is up.  Accessing the item after on_update runs
                # means the item is deleted and you get a C++ object deleted
                # runtime error.
                menu.addAction(_("Edit {}").format(column_title), lambda: self._on_edit_item(key, column))
            a = menu.addAction(_("Pay to"), lambda: self.parent.payto_contacts(payable_keys))
            if needs_verif_keys or not payable_keys:
                a.setDisabled(True)
            a = menu.addAction(_("Delete"), lambda: self.parent.delete_contacts(deletable_keys))
            if not deletable_keys:
                a.setDisabled(True)
            # Add sign/verify and encrypt/decrypt menu - but only if just 1 thing selected
            if len(keys) == 1 and Address.is_valid(keys[0].address):
                signAddr = Address.from_string(keys[0].address)
                a = menu.addAction(_("Sign/verify message") + "...", lambda: self.parent.sign_verify_message(signAddr))
                if signAddr.kind != Address.ADDR_P2PKH:
                    a.setDisabled(True)  # We only allow this for P2PKH since it makes no sense for P2SH (ambiguous public key)
            URLs = [web.BE_URL(self.config, 'addr', Address.from_string(key.address))
                    for key in keys if Address.is_valid(key.address)]
            a = menu.addAction(_("View on block explorer"), lambda: [URL and webopen(URL) for URL in URLs])
            if not any(URLs):
                a.setDisabled(True)
            if ca_info:
                menu.addAction(_("View registration tx..."), lambda: self.parent.do_process_from_txid(txid=ca_info.txid, tx_desc=self.wallet.get_label(ca_info.txid)))
                if typ in ('cashacct_W', 'cashacct'):
                    _contact_d = i2c(item)
                    menu.addAction(_("Details..."), lambda: cashacctqt.cash_account_detail_dialog(self.parent, _contact_d.name))
            menu.addSeparator()

        menu.addAction(self.icon_cashacct,
                       _("Add Contact") + " - " + _("Cash Account"), self.new_cash_account_contact_dialog)
        menu.addAction(self.icon_contacts, _("Add Contact") + " - " + _("Address"), self.parent.new_contact_dialog)
        menu.addSeparator()
        menu.addAction(self.icon_cashacct,
                       _("Register Cash Account..."), self.parent.register_new_cash_account)
        menu.addSeparator()
        menu.addAction(QIcon(":icons/import.svg" if not ColorScheme.dark_scheme else ":icons/import_dark_theme.svg"),
                       _("Import file"), self.import_contacts)
        if not self.parent.contacts.empty:
            menu.addAction(QIcon(":icons/save.svg" if not ColorScheme.dark_scheme else ":icons/save_dark_theme.svg"),
                           _("Export file"), self.export_contacts)

        menu.addSeparator()
        a = menu.addAction(_("Show My Cash Accounts"), self.toggle_show_my_cashaccts)
        a.setCheckable(True)
        a.setChecked(self.show_my_cashaccts)

        if ca_unverified:
            def kick_off_verify():
                bnums = set()
                for contact in ca_unverified:
                    tup = self.wallet.cashacct.parse_string(contact.name)
                    if not tup:
                        continue
                    bnums.add(tup[1])  # number
                ret = cashacctqt.verify_multiple_blocks(bnums, self.parent, self.wallet)
                if ret is None:
                    # user cancel
                    return
                verified = ca_unverified - self._get_ca_unverified()
                if not verified:
                    self.parent.show_error(_("Cash Account verification failure"))

            menu.addSeparator()
            num = len(ca_unverified)
            a = menu.addAction(self.icon_unverif,
                               ngettext("Verify {count} Cash Account",
                                        "Verify {count} Cash Accounts",
                                        num).format(count=num), kick_off_verify)
            if not self.wallet.network:
                a.setDisabled(True)

        run_hook('create_contact_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))

    @property
    def show_my_cashaccts(self) -> bool:
        ''' Returns the current setting from wallet storage. '''
        return bool(self.wallet.storage.get('contact_list_show_cash_accounts', True))

    @show_my_cashaccts.setter
    def show_my_cashaccts(self, b : bool):
        ''' Saves the flag to wallet storage. Does not update GUI. '''
        self.wallet.storage.put('contact_list_show_cash_accounts', bool(b))

    def toggle_show_my_cashaccts(self):
        ''' Toggles the flag in wallet storage, also updates GUI. '''
        b = not self.show_my_cashaccts
        self.show_my_cashaccts = b
        self.update()
        if b:
            tip = _("Your own Cash Accounts are now shown")
        else:
            tip = _("Your own Cash Accounts are now hidden")
        QToolTip.showText(QCursor.pos(), tip, self)

    def get_full_contacts(self, include_pseudo: bool = True) -> List[Contact]:
        ''' Returns all the contacts, with the "My CashAcct" pseudo-contacts
        clobbering dupes of the same type that were manually added.
        Client code should scan for type == 'cashacct' and type == 'cashacct_W' '''
        if include_pseudo:
            # filter out cachaccts that are "Wallet", as they will be added
            # at the end as pseudo contacts if they also appear in real contacts
            real_contacts = [contact for contact in
                             self.parent.contacts.get_all(nocopy=True)
                             if contact.type != 'cashacct'  # accept anything that's not cashacct
                                or not Address.is_valid(contact.address)  # or if it is, it can have invalid address as it's clearly 'not mine"
                                or not self.wallet.is_mine(  # or if it's not mine
                                    Address.from_string(contact.address))
                            ]
            return real_contacts + self._make_wallet_cashacct_pseudo_contacts()
        else:
            return self.parent.contacts.get_all(nocopy=True)

    def _make_wallet_cashacct_pseudo_contacts(self, exclude_contacts = []) -> List[Contact]:
        ''' Returns a list of 'fake' contacts that come from the wallet's
        own registered Cash Accounts.  These contacts do not exist in the
        wallet.contacts object but are created on-the-fly from the
        wallet.cashacct list of registered & verified Cash Accounts.

        The creation of this list is relatively cheap and scales as the lookups
        are O(logN) in the cashaccts caches.

        This is a convenience so that the Contacts tab shows "my" cash accounts
        after registration as well as external Cash Accounts. Note that the
        "mine" entries won't be shown if the user explicitly added his own as
        "external"... '''
        try:
            excl_chk = set((c.name, Address.from_string(c.address)) for c in exclude_contacts if c.type == 'cashacct')
        except:
            # Hmm.. invalid address?
            excl_chk = set()
        wallet_cashaccts = []
        v_txids = set()
        # Add the [Mine] pseudo-contacts
        for ca_info in self.wallet.cashacct.get_wallet_cashaccounts():
            v_txids.add(ca_info.txid)
            name = self.wallet.cashacct.fmt_info(ca_info, emoji=False)
            if (name, ca_info.address) in excl_chk:
                continue
            wallet_cashaccts.append(Contact(
                name = name,
                address = ca_info.address.to_ui_string(),
                type = 'cashacct_W'
            ))
        # Add the [Pend] pseudo-contacts
        for txid, tup in self._ca_pending_conf.copy().items():
            if txid in v_txids or self.wallet.cashacct.is_verified(txid):
                self._ca_pending_conf.pop(txid, None)
                continue
            if tup in excl_chk:
                continue
            name, address = tup
            wallet_cashaccts.append(Contact(
                name = name,
                address = address.to_ui_string(),
                type = 'cashacct_T'
            ))
        return wallet_cashaccts

    @rate_limited(0.333, ts_after=True) # We rate limit the contact list refresh no more 3 per second
    def update(self):
        if self.cleaned_up:
            # short-cut return if window was closed and wallet is stopped
            return
        super().update()

    def on_update(self):
        if self.cleaned_up:
            return
        item = self.currentItem()
        current_contact = item.data(0, self.DataRoles.Contact) if item else None
        selected = self.selectedItems() or []
        selected_contacts = set(item.data(0, self.DataRoles.Contact) for item in selected)
        del item, selected  # must not hold a reference to a C++ object that will soon be deleted in self.clear()..
        self.clear()
        type_names = defaultdict(lambda: _("Unknown"))
        type_names.update({
            'openalias'  : _('OpenAlias'),
            'cashacct'   : _('Cash Account'),
            'cashacct_W' : _('Cash Account') + ' [' + _('Mine') + ']',
            'cashacct_T' : _('Cash Account') + ' [' + _('Pend') + ']',
            'address'    : _('Address'),
        })
        type_icons = {
            'openalias'  : self.icon_openalias,
            'cashacct'   : self.icon_cashacct,
            'cashacct_W' : self.icon_cashacct,
            'cashacct_T' : self.icon_unverif,
            'address'    : self.icon_contacts,
        }
        selected_items, current_item = [], None
        edited = self._edited_item_cur_sel
        for contact in self.get_full_contacts(include_pseudo=self.show_my_cashaccts):
            _type, name, address = contact.type, contact.name, contact.address
            label_key = address
            if _type in ('cashacct', 'cashacct_W', 'cashacct_T', 'address'):
                try:
                    # try and re-parse and re-display the address based on current UI string settings
                    addy = Address.from_string(address)
                    address = addy.to_ui_string()
                    label_key = addy.to_storage_string()
                    del addy
                except:
                    ''' This may happen because we may not have always enforced this as strictly as we could have in legacy code. Just move on.. '''
            label = self.wallet.get_label(label_key)
            item = QTreeWidgetItem(["", name, label, address, type_names[_type]])
            item.setData(0, self.DataRoles.Contact, contact)
            item.DataRole = self.DataRoles.Contact
            if _type in ('cashacct', 'cashacct_W', 'cashacct_T'):
                ca_info = self.wallet.cashacct.get_verified(name)
                tt_warn = None
                if ca_info:
                    if self.wallet.is_mine(ca_info.address) and not self.show_my_cashaccts:
                        # user may have added the contact to "self" manually
                        # but since they asked to not see their own cashaccts,
                        # we must do this to suppress it from being shown regardless
                        continue
                    item.setText(0, ca_info.emoji)
                    tt = _('Validated Cash Account: <b><pre>{emoji} {account_string}</pre></b>').format(
                        emoji = ca_info.emoji,
                        account_string = f'{ca_info.name}#{ca_info.number}.{ca_info.collision_hash};'
                    )
                else:
                    item.setIcon(0, self.icon_unverif)
                    if _type == 'cashacct_T':
                        tt_warn = tt = _('Cash Account pending confirmation and/or verification')
                    else:
                        tt_warn = tt = _('Warning: This Cash Account is not verified')
                item.setToolTip(0, tt)
                if tt_warn: item.setToolTip(1, tt_warn)
            if _type in type_icons:
                item.setIcon(4, type_icons[_type])
            # always give the "Address" field a monospace font even if it's
            # not strictly an address such as openalias...
            item.setFont(3, self.monospace_font)
            self.addTopLevelItem(item)
            if contact == current_contact or (contact == edited[0] and edited[1]):
                current_item = item  # this key was the current item before and it hasn't gone away
            if contact in selected_contacts or (contact == edited[0] and edited[2]):
                selected_items.append(item)  # this key was selected before and it hasn't gone away

        if selected_items:  # sometimes currentItem is set even if nothing actually selected. grr..
            # restore current item & selections
            if current_item:
                # set the current item. this may also implicitly select it
                self.setCurrentItem(current_item)
            for item in selected_items:
                # restore the previous selection
                item.setSelected(True)
        self._edited_item_cur_sel = (None,) * 3
        run_hook('update_contacts_tab', self)

    def new_cash_account_contact_dialog(self):
        ''' Context menu callback. Shows the "New Cash Account Contact"
        interface. '''

        items = cashacctqt.lookup_cash_account_dialog(
            self.parent, self.wallet, title=_("New Cash Account Contact"),
            blurb = _("<br>Add anyone's Cash Account to your Contacts"),
            button_type=cashacctqt.InfoGroupBox.ButtonType.Radio
        )
        if items:
            info, min_chash, name = items[0]
            self.parent.set_contact(name, info.address.to_ui_string(), typ='cashacct')
            run_hook('update_contacts_tab', self)

    def ca_update_potentially_unconfirmed_registrations(self, d : Dict[str, Tuple[str, Address]]):
        added = 0
        for txid, tup in d.items():
            if self.wallet.cashacct.is_verified(txid):
                continue
            if txid not in self._ca_pending_conf:
                name, address = tup
                name += "#???.???;"
                self._ca_pending_conf[txid] = (name, address)
                added += 1
        if added:
            self.update()

    def _ca_callback(self, e, *args):
        ''' Called from the network thread '''
        if self.cleaned_up or not args or args[0] != self.wallet.cashacct:
            # not for us or we are cleaned_up
            return
        if e == 'ca_verified_tx':
            # it's relevant to us when a verification comes in, so we need to
            # schedule an update then. We don't check if the info object
            # is "one of ours" because at this point it may be a NEW relevant
            # contact.
            self.do_update_signal.emit()
        elif e == 'ca_updated_minimal_chash':
            # In this case we do check if the update object is "one of ours"
            # in the slot that this signal targets.
            self._ca_minimal_chash_updated_signal.emit(args[1], args[2])

    def _ca_update_chash(self, ca_info, ignored):
        ''' Called in GUI thread as a result of the cash account subsystem
        figuring out that a collision_hash can be represented shorter.
        Kicked off by a get_minimal_chash() call that results in a cache miss. '''
        if self.cleaned_up:
            return
        # performance -- don't update unless the new minimal_chash is one
        # we care about
        key = f'{ca_info.name}#{ca_info.number}'
        items = self.findItems(key, Qt.MatchContains|Qt.MatchWrap|Qt.MatchRecursive, 1) or []
        if items:
            self.do_update_signal.emit()
