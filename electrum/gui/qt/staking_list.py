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

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt, QPersistentModelIndex, QModelIndex
from PyQt5.QtWidgets import (QAbstractItemView, QMenu)

from electrum.i18n import _
from electrum.bitcoin import is_address
from electrum.util import block_explorer_URL
from electrum.plugin import run_hook

from .util import MyTreeView, webopen


class StakingList(MyTreeView):

    class Columns(IntEnum):
        START_DATE = 0
        AMOUNT = 1
        STAKING_PERIOD = 2
        BLOCKS_LEFT = 3
        TYPE = 4

    headers = {
        Columns.START_DATE: _('Start Date'),
        Columns.AMOUNT: _('Amount'),
        Columns.STAKING_PERIOD: _('Staking Period'),
        Columns.BLOCKS_LEFT: _('Blocks Left'),
        Columns.TYPE: _('Type'),
    }
    filter_columns = [Columns.START_DATE, Columns.TYPE]

    def __init__(self, parent):
        super().__init__(parent, self.create_menu,
                         stretch_column=self.Columns.START_DATE,
                         editable_columns=[self.Columns.START_DATE])
        self.setModel(QStandardItemModel(self))
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.update()

    def on_edited(self, idx, user_role, text):
        _type, prior_name = self.parent.contacts.pop(user_role)
        self.parent.set_contact(text, user_role)
        self.update()

    def create_menu(self, position):
        menu = QMenu()
        idx = self.indexAt(position)
        column = idx.column() or self.Columns.START_DATE
        selected_keys = []
        for s_idx in self.selected_in_column(self.Columns.START_DATE):
            sel_key = self.model().itemFromIndex(s_idx).data(Qt.UserRole)
            selected_keys.append(sel_key)
        if not selected_keys or not idx.isValid():
            pass  # co wyświetlić?
        else:
            column_title = self.model().horizontalHeaderItem(column).text()
            column_data = '\n'.join(self.model().itemFromIndex(s_idx).text()
                                    for s_idx in self.selected_in_column(column))
            menu.addAction(_("Copy {}").format(column_title), lambda: self.place_text_on_clipboard(column_data, title=column_title))

            URLs = [block_explorer_URL(self.config, 'addr', key) for key in filter(is_address, selected_keys)]
            if URLs:
                menu.addAction(_("View on block explorer"), lambda: [webopen(u) for u in URLs])

        menu.exec_(self.viewport().mapToGlobal(position))

    def update(self):
        if self.maybe_defer_update():
            return
        self.model().clear()
        self.update_headers(self.__class__.headers)
        for key in sorted(self.parent.contacts.keys()):
            pass
        self.sortByColumn(self.Columns.START_DATE, Qt.AscendingOrder)
        self.filter()
