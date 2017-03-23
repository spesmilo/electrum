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

from electrum_ltc.i18n import _
from electrum_ltc.bitcoin import is_address
from electrum_ltc.util import block_explorer_URL, format_satoshis, format_time, age
from electrum_ltc.plugins import run_hook
from electrum_ltc.paymentrequest import PR_UNPAID, PR_PAID, PR_UNKNOWN, PR_EXPIRED
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from util import MyTreeWidget, pr_tooltips, pr_icons


class ContactList(MyTreeWidget):
    filter_columns = [0, 1]  # Key, Value

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Name'), _('Address')], 0, [0])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

    def on_permit_edit(self, item, column):
        # openalias items shouldn't be editable
        return item.text(1) != "openalias"

    def on_edited(self, item, column, prior):
        if column == 0:  # Remove old contact if renamed
            self.parent.contacts.pop(prior)
        self.parent.set_contact(unicode(item.text(0)), unicode(item.text(1)))

    def import_contacts(self):
        wallet_folder = self.parent.get_wallet_folder()
        filename = unicode(QFileDialog.getOpenFileName(self.parent, "Select your wallet file", wallet_folder))
        if not filename:
            return
        self.parent.contacts.import_file(filename)
        self.on_update()

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        if not selected:
            menu.addAction(_("New contact"), lambda: self.parent.new_contact_dialog())
            menu.addAction(_("Import file"), lambda: self.parent.import_contacts())
        else:
            names = [unicode(item.text(0)) for item in selected]
            keys = [unicode(item.text(1)) for item in selected]
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([unicode(item.text(column)) for item in selected])
            menu.addAction(_("Copy %s")%column_title, lambda: self.parent.app.clipboard().setText(column_data))
            if column in self.editable_columns:
                menu.addAction(_("Edit %s")%column_title, lambda: self.editItem(item, column))
            menu.addAction(_("Pay to"), lambda: self.parent.payto_contacts(keys))
            menu.addAction(_("Delete"), lambda: self.parent.delete_contacts(keys))
            URLs = [block_explorer_URL(self.config, 'addr', key) for key in filter(is_address, keys)]
            if URLs:
                menu.addAction(_("View on block explorer"), lambda: map(webbrowser.open, URLs))

        run_hook('create_contact_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_update(self):
        item = self.currentItem()
        current_key = item.data(0, Qt.UserRole).toString() if item else None
        self.clear()
        for key in sorted(self.parent.contacts.keys()):
            _type, name = self.parent.contacts[key]
            item = QTreeWidgetItem([name, key])
            item.setData(0, Qt.UserRole, key)
            self.addTopLevelItem(item)
            if key == current_key:
                self.setCurrentItem(item)
        run_hook('update_contacts_tab', self)
