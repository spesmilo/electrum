#!/usr/bin/env python

import os
import sys
import datetime
from datetime import date
from typing import TYPE_CHECKING, Tuple, Dict
import threading
from enum import IntEnum
from decimal import Decimal

from PyQt5.QtGui import QMouseEvent, QFont, QBrush, QColor
from PyQt5.QtCore import (Qt, QPersistentModelIndex, QModelIndex, QAbstractItemModel,
                          QSortFilterProxyModel, QVariant, QItemSelectionModel, QDate, QPoint)
from PyQt5.QtWidgets import (QMenu, QHeaderView, QLabel, QMessageBox,
                             QPushButton, QComboBox, QVBoxLayout, QCalendarWidget,
                             QGridLayout, QTableWidget, QTableWidgetItem,
                             QAbstractItemView, QLayout, QHBoxLayout)

from electrum.address_synchronizer import TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE
from electrum.i18n import _
from electrum.util import (block_explorer_URL, profiler, TxMinedInfo,
                           OrderedDictWithIndex, timestamp_to_datetime,
                           Satoshis, format_time)
from electrum.logging import get_logger, Logger

from .util import (read_QIcon, MONOSPACE_FONT, Buttons, CancelButton, OkButton,
                   filename_field, MyTreeView, AcceptFileDragDrop, WindowModalDialog,
                   CloseButton, webopen)

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from .main_window import ElectrumWindow

class FundColumns(IntEnum):
    HASH = 0
    DESCRIPTION = 1
    AMOUNT = 2
    YES = 3
    NO = 4
    ABS = 5
    STATE = 6
    MYVOTE = 7

class FundFilter(QHBoxLayout):
    def __init__(self, parent, update):
        super().__init__(parent)

        self.combobox = QComboBox()
        self.combobox.addItem(_("Being voted"), 0)
        self.combobox.addItem(_("Accepted"), 1)
        self.combobox.addItem(_("Rejected"), 2)
        self.combobox.addItem(_("Expired"), 3)
        self.combobox.addItem(_("Pending funds"), 4)
        self.combobox.addItem(_("Pending voting requests"), 5)
        self.combobox.activated.connect(update)
        self.addWidget(QLabel(_("Community Fund Proposals. Right click to set vote.")))
        self.addStretch(1)
        self.addWidget(QLabel(_("Filter:")))
        self.addWidget(self.combobox)

    def get_filter(self):
        return self.combobox.currentData()

class FundList(QTableWidget):

    def __init__(self, parent, filter):
        super().__init__(parent)
        self.config = parent.config
        self.setSortingEnabled(True)
        self.parent = parent
        self.wallet = self.parent.wallet  # type: Abstract_Wallet
        self.network = self.parent.network
        self.stretch_column = FundColumns.DESCRIPTION
        self.list = []
        self.filter = filter
        self.sortByColumn(FundColumns.HASH, Qt.AscendingOrder)

        self.setColumnCount(FundColumns.MYVOTE + 1)
        self.setColumnHidden(FundColumns.HASH, True)
        self.setHorizontalHeaderLabels(["", _("Description"), _("Amount"), _("Yes"), _("No"), _("Abs"), _("State"), _("My Vote")])

        self.verticalHeader().setStretchLastSection(False)
        for col in FundColumns:
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.horizontalHeader().setSectionResizeMode(col, sm)

        self.horizontalHeaderItem(FundColumns.DESCRIPTION).setTextAlignment(Qt.AlignLeft)

        self.setContentsMargins(0,0,0,0)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers);
        self.setSelectionBehavior(QAbstractItemView.SelectRows);
        self.setSelectionMode(QAbstractItemView.SingleSelection);
        self.setFocusPolicy(Qt.NoFocus);
        self.setAlternatingRowColors(True);
        self.setShowGrid(False);
        self.setFocusPolicy(Qt.NoFocus);
        self.setEditTriggers(QAbstractItemView.NoEditTriggers);
        self.setSelectionMode(QAbstractItemView.NoSelection);
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel);
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed);
        self.verticalHeader().setVisible(False);
        self.horizontalHeader().setDefaultAlignment(Qt.AlignCenter);
        self.horizontalHeader().setSortIndicatorShown(True);
        self.horizontalHeader().setSectionsClickable(True);
        self.setContextMenuPolicy(Qt.CustomContextMenu);
        self.setWordWrap(True);

        self.customContextMenuRequested.connect(self.contextMenu)

    def contextMenu(self, position):
        item = self.itemAt(position)
        if not item:
            return

        menu = QMenu()
        hash = self.item(item.row(), FundColumns.HASH).data(Qt.DisplayRole)
        state = self.item(item.row(), FundColumns.STATE).data(Qt.DisplayRole)

        if state == _("Being voted"):
            current_vote = self.parent.find_vote(hash)

            def set_vote_placeholder(row):
                mv = QTableWidgetItem()
                mv.setData(Qt.DisplayRole, "Voting...")
                mv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(row, FundColumns.MYVOTE, mv);

            if current_vote != 1:
                menu.addAction(_("Vote yes"), lambda: (self.parent.vote_proposal(hash, 1), set_vote_placeholder(item.row())))
            if current_vote != 0:
                menu.addAction(_("Vote no"), lambda: (self.parent.vote_proposal(hash, 0), set_vote_placeholder(item.row())))
            if current_vote != -1:
                menu.addAction(_("Vote abstain"), lambda: (self.parent.vote_proposal(hash, -1), set_vote_placeholder(item.row())))
            if current_vote != None:
                menu.addAction(_("Remove vote"), lambda: (self.parent.vote_proposal(hash, -2), set_vote_placeholder(item.row())))

        menu.addAction(_("Copy hash"), lambda: self.parent.do_copy(hash, title="Hash"))

        menu.exec_(self.viewport().mapToGlobal(position))

    def state_to_string(self, state):
        if state == 1:
            return _("Accepted")
        if state == 2:
            return _("Rejected")
        if state == 3:
            return _("Expired")
        if state == 4:
            return _("Pending funds")
        if state == 5:
            return _("Pending voting requests")
        return _("Being voted")

    @profiler
    def refresh(self, reason=""):
        if len(self.wallet.dao) == 0:
            return

        if not "p" in self.wallet.dao:
            return

        filtered = []

        for p in self.wallet.dao["p"]:
            p_item = self.wallet.dao["p"][p]
            if p_item["state"] == self.filter():
                filtered.append(p_item)

        if filtered == self.list and reason != "votes":
            return

        self.list = filtered

        self.clearContents()
        self.setRowCount(len(self.list));

        for i, item in enumerate(self.list):
            proposal = item
            hash = QTableWidgetItem()
            hash.setData(Qt.DisplayRole, proposal["hash"])
            self.setItem(i, FundColumns.HASH, hash);

            desc = QTableWidgetItem()
            desc.setData(Qt.DisplayRole, proposal["description"])
            self.setItem(i, FundColumns.DESCRIPTION, desc);

            yes = QTableWidgetItem()
            yes.setData(Qt.DisplayRole, proposal["votesYes"])
            yes.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
            self.setItem(i, FundColumns.YES, yes);

            no = QTableWidgetItem()
            no.setData(Qt.DisplayRole, proposal["votesNo"])
            no.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
            self.setItem(i, FundColumns.NO, no);

            abs = QTableWidgetItem()
            abs.setData(Qt.DisplayRole, proposal["votesAbs"])
            abs.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
            self.setItem(i, FundColumns.ABS, abs);

            cv = QTableWidgetItem()
            cv.setData(Qt.DisplayRole, proposal["requestedAmount"])
            cv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
            self.setItem(i, FundColumns.AMOUNT, cv);

            st = QTableWidgetItem()
            st.setData(Qt.DisplayRole, self.state_to_string(proposal["state"]))
            st.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
            self.setItem(i, FundColumns.STATE, st);

            current_vote = self.parent.find_vote(proposal["hash"])

            mv = QTableWidgetItem()

            if current_vote == 1:
                mv.setData(Qt.DisplayRole, _("Yes"))
            if current_vote == 0:
                mv.setData(Qt.DisplayRole, _("No"))
            if current_vote == -1:
                mv.setData(Qt.DisplayRole, _("Abstain"))
            if current_vote == None:
                mv.setData(Qt.DisplayRole, _("None"))

            mv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
            self.setItem(i, FundColumns.MYVOTE, mv);
