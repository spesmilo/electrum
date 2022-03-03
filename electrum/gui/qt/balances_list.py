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
from electrum.util import block_explorer_URL, profiler, DECIMAL_POINT_DEFAULT
from electrum.logging import Logger

from electrum.plugin import run_hook
from electrum.bitcoin import is_address
from electrum.wallet import InternalAddressCorruption

from .util import MyTreeView, MONOSPACE_FONT, ColorScheme, webopen, MySortModel
from . import BalanceItem

# from dataclasses import dataclass


class BalancesList(MyTreeView, Logger):

    class Columns(IntEnum):
        NAME = 0
        DAT = 1
        LPS = 2
        LOAN = 3
        TOKEN_BALANCE = 4

    filter_columns = [Columns.NAME, Columns.DAT, Columns.LPS, Columns.LOAN, Columns.TOKEN_BALANCE]

    ROLE_SORT_ORDER = Qt.UserRole + 1000
    ROLE_NAME_STR = Qt.UserRole + 1001

    def __init__(self, parent):
        MyTreeView.__init__(self=self,
                            parent=parent, create_menu=self.create_menu,
                            stretch_column=self.Columns.TOKEN_BALANCE,
                            editable_columns=[])

        Logger.__init__(self)

        self.wallet = self.parent.wallet
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

        self.std_model = QStandardItemModel(self)
        self.proxy = MySortModel(self, sort_role=self.ROLE_SORT_ORDER)
        self.proxy.setSourceModel(self.std_model)
        self.setModel(self.proxy)
        self.sortByColumn(self.Columns.TOKEN_BALANCE, Qt.DescendingOrder)
        self.request_update_balances()

    def request_update_balances(self):
        self.logger.info('run request_update_balances')

        if self.wallet.network is not None and self.wallet.network.interface is not None:
            network = self.wallet.network
            interface = network.interface
            loop = network.asyncio_loop
            # addresses = self.wallet.get_addresses()
            loop.run_until_complete(
                interface.request_fetch_balances(lambda: self.wallet.get_addresses() )
            )

    def refresh_headers(self):
        headers = {
            self.Columns.NAME: _('Name'),
            self.Columns.DAT: _('is DAT'),
            self.Columns.LPS: _('is LPS'),
            self.Columns.LOAN: _('is Loan'),
            self.Columns.TOKEN_BALANCE: _('Token Balance')
        }
        self.update_headers(headers)

    @profiler
    def update(self):
        if self.maybe_defer_update():
            return

        if self.parent.network and self.parent.network.interface:
            balances = self.parent.network.interface.token_balances
        else:
            self.logger.error('failed to update token balances tab: network interface is not ready')
            return

        self.proxy.setDynamicSortFilter(False)  # temp. disable re-sorting after every change
        self.std_model.clear()
        self.refresh_headers()
        # fx = self.parent.fx

        def make_model_item(labels):
            model_item = [QStandardItem(e) for e in labels]
            for i, it in enumerate(model_item):
                alignment = Qt.AlignLeft | Qt.AlignVCenter if i == self.Columns.TOKEN_BALANCE else Qt.AlignVCenter
                it.setTextAlignment(alignment)
                it.setFont(QFont(MONOSPACE_FONT))
                it.setEditable(False)
            return model_item

        utxo_balance = self.wallet.get_balance()[0]
        utxo_item = ['DFI(utxo)', '', '', 'False', self.parent.format_amount(utxo_balance)]
        self.std_model.insertRow(0, make_model_item(utxo_item))

        for k, v in balances.items():
            # create item
            labels = [v.label(), v.isDat(), v.isLPS(), v.isLoan(), str(v.value())]
            model_item = make_model_item(labels)
            count = self.std_model.rowCount()
            self.std_model.insertRow(count, model_item)

        self.filter()
        self.proxy.setDynamicSortFilter(True)

    def create_menu(self, position):
        pass
