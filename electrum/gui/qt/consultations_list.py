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
                             QAbstractItemView, QLayout, QHBoxLayout, QCheckBox,
                             QLineEdit, QSpinBox)

from electrum.address_synchronizer import TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE
from electrum.i18n import _
from electrum.util import (block_explorer_URL, profiler, TxMinedInfo,
                           OrderedDictWithIndex, timestamp_to_datetime,
                           Satoshis, format_time)
from electrum.logging import get_logger, Logger
from electrum.bitcoin import ConsensusParameters, ConsensusParametersTypes

from .util import (read_QIcon, MONOSPACE_FONT, Buttons, CancelButton, OkButton,
                   filename_field, MyTreeView, AcceptFileDragDrop, WindowModalDialog,
                   CloseButton, webopen, NavCoinListWidget)

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from .main_window import ElectrumWindow

class ConsultationsColumns(IntEnum):
    HASH = 0
    QUESTION = 1
    STATE = 2
    ANSWER = 3
    MYVOTE = 4

class ConsensusColumns(IntEnum):
    ID = 0
    HASH = 1
    DESCRIPTION = 2
    STATE = 3
    ANSWER= 4
    VALUE = 5
    MYVOTE = 6

class ConsultationsFilter(QHBoxLayout):
    def __init__(self, parent, update):
        super().__init__(parent)

        self.combobox = QComboBox()
        self.combobox.addItem(_("Being voted"), 1)
        self.combobox.addItem(_("Finished"), 3)
        self.combobox.addItem(_("Reflection"), 8)
        self.combobox.addItem(_("Found support"), 9)
        self.combobox.addItem(_("Looking for support"), 0)
        self.combobox.activated.connect(update)
        self.addWidget(QLabel(_("DAO Consultations")))
        self.addStretch(1)
        self.addWidget(QLabel(_("Filter:")))
        self.addWidget(self.combobox)

    def get_filter(self):
        return self.combobox.currentData()

class ConsultationsList(QTableWidget):

    def __init__(self, parent, filter, consensus=False):
        super().__init__(parent)
        self.config = parent.config
        self.setSortingEnabled(True)
        self.parent = parent
        self.wallet = self.parent.wallet  # type: Abstract_Wallet
        self.network = self.parent.network
        self.consensus = consensus
        self.stretch_column = (ConsensusColumns.DESCRIPTION if self.consensus else ConsultationsColumns.QUESTION)
        self.list = []
        self.cc = {}
        self.filter = filter
        self.sortByColumn((ConsensusColumns if self.consensus else ConsultationsColumns).HASH, Qt.AscendingOrder)

        self.setColumnCount((ConsensusColumns.MYVOTE if self.consensus else ConsultationsColumns.MYVOTE) + 1)
        self.setColumnHidden((ConsensusColumns if self.consensus else ConsultationsColumns).HASH, True)
        if self.consensus:
            self.setColumnHidden(ConsensusColumns.HASH, True)
            self.setColumnHidden(ConsensusColumns.ID, True)
            self.setHorizontalHeaderLabels(["", "", _("Description"), _("State"), _("Proposals"), _("Current value"), _("My vote")])
        else:
            self.setColumnHidden(ConsultationsColumns.HASH, True)
            self.setColumnHidden(ConsultationsColumns.QUESTION, False)
            self.setHorizontalHeaderLabels(["", _("Question"), _("Answers"), _("State"), _("My vote")])

        self.verticalHeader().setStretchLastSection(False)
        for col in (ConsensusColumns if self.consensus else ConsultationsColumns):
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.horizontalHeader().setSectionResizeMode(col, sm)

        self.horizontalHeaderItem(ConsensusColumns.DESCRIPTION if self.consensus else ConsultationsColumns.QUESTION).setTextAlignment(Qt.AlignLeft)

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
        hash = self.item(item.row(), (ConsensusColumns if self.consensus else ConsultationsColumns).HASH).data(Qt.DisplayRole)
        state = self.item(item.row(), (ConsensusColumns if self.consensus else ConsultationsColumns).STATE).data(Qt.DisplayRole)

        if state == _("Set") and self.consensus:
            id = self.item(item.row(), ConsensusColumns.ID).data(Qt.DisplayRole)
            menu.addAction(_("Propose a consensus change"), lambda: (self.propose_consensus(id, item.row())))
            menu.exec_(self.viewport().mapToGlobal(position))
            return

        if "c" not in self.wallet.dao:
            return

        if hash not in self.wallet.dao["c"]:
            return

        consultation = self.wallet.dao["c"][hash]
        fRange = consultation["version"]&1<<1
        fMoreAnswers = consultation["version"]&1<<2
        fConsensus = consultation["version"]&1<<3

        if state == _("Being voted"):
            current_vote = self.get_votes(consultation)

            if current_vote != None:
                menu.addAction(_("Change vote"), lambda: (self.vote(consultation, item.row())))
                if fRange:
                    menu.addAction(_("Remove vote"), lambda: (self.remove_vote(consultation, item.row())))
            else:
                menu.addAction(_("Vote"), lambda: (self.vote(consultation, item.row())))
        elif state == _("Looking for support") or state == _("Supported"):
            current_vote = self.get_votes(consultation)

            if fRange:
                if current_vote != None:
                    menu.addAction(_("Remove support"), lambda: (self.support(consultation, item.row())))
                else:
                    menu.addAction(_("Support"), lambda: (self.support(consultation, item.row())))
            else:
                if current_vote != None:
                    menu.addAction(_("Change support"), lambda: (self.support(consultation, item.row())))
                else:
                    menu.addAction(_("Support"), lambda: (self.support(consultation, item.row())))
                if fMoreAnswers:
                    menu.addAction(_("Propose a different answer"), lambda: (self.propose_answer(consultation, item.row())))

        menu.addAction(_("Copy hash"), lambda: self.parent.do_copy(hash, title="Hash"))

        menu.exec_(self.viewport().mapToGlobal(position))

    def remove_vote(self, consultation, row):
        self.parent.vote_consultations_values([], [], [consultation["hash"]])

        mv = QTableWidgetItem()
        mv.setData(Qt.DisplayRole, "Removing...")
        mv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
        self.setItem(row, ConsultationsColumns.MYVOTE, mv)

    def vote(self, consultation, row):
        fRange = consultation["version"]&1<<1
        fConsensus = consultation["version"]&1<<3

        if not fRange:
            d = WindowModalDialog(self, title=_('Vote answers of consultation'))
            vbox = QVBoxLayout(d)

            vbox.addWidget(QLabel(_('You can select up to {} answers').format(consultation["max"])))
            vbox.addStretch(1)

            voted = []
            unvoted = []

            count = 0

            for a in consultation["answers"]:
                cb = QCheckBox(a["answer"] if not fConsensus else self.format_value(a["answer"], consultation["min"]))
                cb.setProperty("id", a["hash"]);
                vote = self.parent.find_vote(a["hash"])
                cb.setChecked(vote == 1)
                if vote == 1:
                    count = count + 1
                def on_cb(x):
                    nonlocal voted
                    nonlocal unvoted
                    nonlocal count
                    hash = self.sender().property("id")
                    if x == Qt.Checked:
                        voted.append(hash)
                        if hash in unvoted:
                            unvoted.remove(hash)
                        count = count + 1
                    else:
                        unvoted.append(hash)
                        if hash in voted:
                            voted.remove(hash)
                        count = count - 1
                    if fConsensus:
                        button.setEnabled(count == 1)
                    else:
                        button.setEnabled(count >= consultation["min"] and count <= consultation["max"])
                cb.stateChanged.connect(on_cb)
                vbox.addWidget(cb)

            vbox.addStretch(1)
            button = OkButton(d, _('Save'))
            button.setEnabled(False)
            vbox.addLayout(Buttons(CancelButton(d), button))

            if not d.exec_():
                return

            self.parent.vote_consultations(voted, unvoted)
        else:
            d = WindowModalDialog(self, title=_('Vote consultation'))
            vbox = QVBoxLayout(d)

            vbox.addWidget(QLabel(_('You can vote a value between {} and {}').format(consultation["min"], consultation["max"])))
            vbox.addStretch(1)

            vote = QSpinBox()
            vote.setMinimum(consultation["min"])
            vote.setMaximum(consultation["max"])

            vbox.addWidget(vote)

            vbox.addStretch(1)
            button = OkButton(d, _('Save'))
            vbox.addLayout(Buttons(CancelButton(d), button))

            if not d.exec_():
                return

            self.parent.vote_consultations_values([consultation["hash"]], [vote.value()], [])

        mv = QTableWidgetItem()
        mv.setData(Qt.DisplayRole, "Voting...")
        mv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
        self.setItem(row, ConsultationsColumns.MYVOTE, mv)

    def is_valid_consensus(self, val, id):
        val = int(val)

        if id not in self.list:
            return False
        type = self.list[id]["type"]

        if type == ConsensusParametersTypes.TYPE_PERCENT:
            if val < 0 or val > 10000:
                return False

        if type == ConsensusParametersTypes.TYPE_NAV:
            if val < 0 or val > 65000000*100000000:
                return False

        if type == ConsensusParametersTypes.TYPE_NUMBER:
            if val < 0 or val > pow(2,24):
                return False

        if type == ConsensusParametersTypes.TYPE_BOOL:
            if val != 0 and val != 1:
                return False

        if id == ConsensusParameters.CONSULTATION_MIN_CYCLES and val > self.list[ConsensusParameters.CONSULTATION_MAX_SUPPORT_CYCLES]["value"]:
            return False

        if id == ConsensusParameters.CONSULTATION_MAX_SUPPORT_CYCLES and val < self.list[ConsensusParameters.CONSULTATION_MIN_CYCLES]["value"]:
            return False

        if val == self.list[id]["value"]:
            return False

        return True

    def remove_format(self, val, id):
        import re
        non_decimal = re.compile(r'[^\d.]+')
        val = float(non_decimal.sub('', val))

        if id not in self.list:
            return str(int(val))
        type = self.list[id]["type"]

        if type == 0:
            if id == ConsensusParameters.PROPOSAL_MAX_VOTING_CYCLES or id == ConsensusParameters.PAYMENT_REQUEST_MAX_VOTING_CYCLES:
                return str(int(val)-1)
            return str(int(val))
        elif type == 1:
            return str(int(val * 100))
        elif type == 2:
            return str(int(val * 100000000))

        return str(int(val))

    def propose_consensus(self, id, row):
        listWidget = NavCoinListWidget(_("Possible answers"), lambda x: self.is_valid_consensus(self.remove_format(x, id), id))

        d = WindowModalDialog(self, title=_('Create DAO Consultation'))
        vbox = QVBoxLayout(d)

        title = "Consensus change for: {}".format(self.list[id]["desc"])
        vbox.addWidget(QLabel(_("Propose a consensus change for {}").format(self.list[id]["desc"])))
        vbox.addSpacing(15)
        vbox.addWidget(listWidget)
        vbox.addSpacing(15)
        button = OkButton(d, _('Create'))
        vbox.addLayout(Buttons(CancelButton(d), button))
        button.setEnabled(False)

        def on_edit():
            valid = True

            if len(listWidget.getEntries()) == 0:
                valid = False

            button.setEnabled(valid)

        listWidget.onchange.connect(on_edit)

        if not d.exec_():
            return

        nMin = id
        nMax = 1

        nVersion = 1
        nVersion |= 1<<2
        nVersion |= 1<<3

        answers = listWidget.getEntries()

        answers_without_format = []

        for ans in answers:
            answers_without_format.append(self.remove_format(ans, id))

        # user pressed "create"
        self.parent.create_dao_consultation(title, nMin, nMax, answers_without_format, nVersion)

        mv = QTableWidgetItem()
        mv.setData(Qt.DisplayRole, "Proposing...")
        mv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
        self.setItem(row, ConsensusColumns.STATE, mv)

    def support(self, consultation, row):
        fRange = consultation["version"]&1<<1
        fConsensus = consultation["version"]&1<<3

        if not fRange:
            d = WindowModalDialog(self, title=_('Support answers of consultation'))
            vbox = QVBoxLayout(d)

            vbox.addWidget(QLabel(_('Which answers would you like to support?')))
            vbox.addStretch(1)

            supported = []
            unsupported = []

            for a in consultation["answers"]:
                cb = QCheckBox(a["answer"] if not fConsensus else self.format_value(a["answer"], consultation["min"]))
                cb.setProperty("id", a["hash"]);
                vote = self.parent.find_vote(a["hash"])
                cb.setChecked(vote == -3)
                def on_cb(x):
                    nonlocal supported
                    nonlocal unsupported
                    hash = self.sender().property("id")
                    if x == Qt.Checked:
                        supported.append(hash)
                        if hash in unsupported:
                            unsupported.remove(hash)
                    else:
                        unsupported.append(hash)
                        if hash in supported:
                            supported.remove(hash)
                cb.stateChanged.connect(on_cb)
                vbox.addWidget(cb)

            vbox.addStretch(1)
            button = OkButton(d, _('Save'))
            vbox.addLayout(Buttons(CancelButton(d), button))

            if not d.exec_():
                return

            self.parent.support_consultations(supported, unsupported)
        else:
            current_vote = self.parent.find_vote(consultation["hash"])
            supported = current_vote == -3
            if supported:
                self.parent.support_consultations([], [consultation["hash"]])
            else:
                self.parent.support_consultations([consultation["hash"]], [])

        mv = QTableWidgetItem()
        mv.setData(Qt.DisplayRole, "Supporting...")
        mv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
        self.setItem(row, (ConsensusColumns if self.consensus else ConsultationsColumns).MYVOTE, mv);

    def propose_answer(self, consultation, row):
        fRange = consultation["version"]&1<<1
        fMoreAnswers = consultation["version"]&1<<2
        fConsensus = consultation["version"]&1<<3

        if not fMoreAnswers:
            return

        if not consultation["state"] == 0:
            return

        if not fRange:
            d = WindowModalDialog(self, title=_('Propose a new answer'))
            vbox = QVBoxLayout(d)

            vbox.addWidget(QLabel(_('Which answer would you like to propose for the question {}?').format(consultation["question"])))
            vbox.addStretch(1)

            answer = QLineEdit()
            vbox.addWidget(answer)

            def on_cb(x):
                valid = True
                if not fConsensus:
                    if answer.text() == "":
                        valid = False
                else:
                    if not self.is_valid_consensus(self.remove_format(answer.text(), consultation["min"]), consultation["min"]):
                        valid = False
                for a in consultation["answers"]:
                    if a["answer"] == answer.text():
                        valid = False
                button.setEnabled(valid)

            answer.textChanged.connect(on_cb)

            vbox.addStretch(1)
            button = OkButton(d, _('Save'))
            button.setEnabled(False)
            vbox.addLayout(Buttons(CancelButton(d), button))

            if not d.exec_():
                return

            self.parent.propose_answer(consultation["hash"], answer.text() if not fConsensus else self.remove_format(answer.text(), consultation["min"]))

        mv = QTableWidgetItem()
        mv.setData(Qt.DisplayRole, "Proposing...")
        mv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
        self.setItem(row, (ConsensusColumns if self.consensus else ConsultationsColumns).ANSWER, mv);

    def get_votes(self, consultation):
        current_vote = None
        fRange = consultation["version"]&1<<1
        fConsensus = consultation["version"]&1<<3

        if self.state_to_string(consultation["state"]) == _("Being voted"):
            if fRange:
                vote = self.parent.find_vote(consultation["hash"])
                if vote >= -1:
                    current_vote = vote
            else:
                current_votes = []
                for a in consultation["answers"]:
                    vote = self.parent.find_vote(a["hash"])
                    if vote >= -1:
                        current_votes.append(a["answer"] if not fConsensus else self.format_value(consultation["min"], a["answer"]))
                if len(current_votes) > 0:
                    current_vote = ', '.join(current_votes)
        elif self.state_to_string(consultation["state"]) == _("Looking for support") or self.state_to_string(consultation["state"]) == _("Supported"):
            if fRange:
                vote = self.parent.find_vote(consultation["hash"])
                if vote == -3:
                    current_vote = vote
            else:
                current_votes = []
                for a in consultation["answers"]:
                    vote = self.parent.find_vote(a["hash"])
                    if vote == -3:
                        current_votes.append(a["answer"] if not fConsensus else self.format_value(consultation["min"], a["answer"]))
                if len(current_votes) > 0:
                    current_vote = ', '.join(current_votes)

        return current_vote

    def state_to_string(self, state):
        if state == 1:
            return _("Being voted")
        if state == 3:
            return _("Finished")
        if state == 8:
            return _("Reflection")
        if state == 9:
            return _("Found support")
        return _("Looking for support")

    @profiler
    def refresh(self, reason=""):
        if self.consensus:
            if not "c" in self.wallet.dao:
                return

            consultations = {}
            for c in self.wallet.dao["c"]:
                c_item = self.wallet.dao["c"][c]
                if c_item["version"] & (1<<3) and c_item["state"] != 3 and c_item["state"] != 7:
                    consultations[c_item["min"]] = c_item

            if self.list == self.wallet.consensus and self.cc == consultations and reason != "votes":
                return

            self.list = self.wallet.consensus
            self.cc = consultations

            self.clearContents()
            self.setRowCount(len(self.list));

            for i, item in enumerate(self.list):
                parameter = self.list[item]

                id = QTableWidgetItem()
                id.setData(Qt.DisplayRole, parameter["id"])
                id.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(i, ConsensusColumns.ID, id);

                hash = QTableWidgetItem()
                hash.setData(Qt.DisplayRole, _("") if not parameter["id"] in consultations else consultations[parameter["id"]]["hash"])
                hash.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(i, ConsensusColumns.HASH, hash);

                desc = QTableWidgetItem()
                desc.setData(Qt.DisplayRole, parameter["desc"])
                self.setItem(i, ConsensusColumns.DESCRIPTION, desc);

                answers = []
                if parameter["id"] in consultations:
                    for a in consultations[parameter["id"]]["answers"]:
                        answers.append(self.format_value(a["answer"], parameter["type"]))
                strVotes=', '.join(answers)

                ans = QTableWidgetItem()
                ans.setData(Qt.DisplayRole, strVotes)
                ans.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(i, ConsensusColumns.ANSWER, ans)

                state = QTableWidgetItem()
                state.setData(Qt.DisplayRole, _("Set") if not parameter["id"] in consultations else self.state_to_string(consultations[parameter["id"]]["state"]))
                state.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(i, ConsensusColumns.STATE, state);

                cv = QTableWidgetItem()
                cv.setData(Qt.DisplayRole, self.format_value(parameter["value"], parameter["id"]))
                cv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(i, ConsensusColumns.VALUE, cv);

                mv = QTableWidgetItem()
                votes = None if not parameter["id"] in consultations else self.get_votes(consultations[parameter["id"]])
                if votes == -3:
                    votes = "Supported"
                elif votes == -1:
                    votes = "Abstain"
                elif votes == None:
                    votes = "None"
                mv.setData(Qt.DisplayRole, votes)
                mv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(i, ConsensusColumns.MYVOTE, mv)
        else:
            if len(self.wallet.dao) == 0:
                return

            if not "c" in self.wallet.dao:
                return

            filtered = []

            for c in self.wallet.dao["c"]:
                c_item = self.wallet.dao["c"][c]
                if c_item["state"] == self.filter():
                    filtered.append(c_item)

            if filtered == self.list and reason != "votes":
                return

            self.list = filtered

            self.clearContents()
            self.setRowCount(len(self.list));

            for i, item in enumerate(self.list):
                consult = item

                fRange = consult["version"]&1<<1

                hash = QTableWidgetItem()
                hash.setData(Qt.DisplayRole, consult["hash"])
                self.setItem(i, (ConsensusColumns if self.consensus else ConsultationsColumns).HASH, hash)

                question = QTableWidgetItem()
                question.setData(Qt.DisplayRole, consult["question"])
                self.setItem(i, (ConsensusColumns if self.consensus else ConsultationsColumns).QUESTION, question)

                strVotes = _("Between {} and {}").format(consult["min"],consult["max"])
                if not fRange:
                    answers = []
                    for a in consult["answers"]:
                        answers.append(a["answer"])
                    strVotes=', '.join(answers)

                ans = QTableWidgetItem()
                ans.setData(Qt.DisplayRole, strVotes)
                ans.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(i, (ConsensusColumns if self.consensus else ConsultationsColumns).ANSWER, ans)

                st = QTableWidgetItem()
                st.setData(Qt.DisplayRole, self.state_to_string(consult["state"]))
                st.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(i, (ConsensusColumns if self.consensus else ConsultationsColumns).STATE, st)

                mv = QTableWidgetItem()
                votes = self.get_votes(consult)
                if votes == -3:
                    votes = "Supported"
                elif votes == -1:
                    votes = "Abstain"
                elif votes == None:
                    votes = "None"
                mv.setData(Qt.DisplayRole, votes)
                mv.setData(Qt.TextAlignmentRole, Qt.AlignCenter)
                self.setItem(i, (ConsensusColumns if self.consensus else ConsultationsColumns).MYVOTE, mv)

    def format_value(self, value, id):
        if id not in self.list:
            return str(value)
        type = self.list[id]["type"]
        if type == 0:
            if id == ConsensusParameters.PROPOSAL_MAX_VOTING_CYCLES or id == ConsensusParameters.PAYMENT_REQUEST_MAX_VOTING_CYCLES:
                return str(int(value)+1)
            return str(value)
        elif type == 1:
            return "{:.2f}%".format(float(value)/100.0)
        elif type == 2:
            return "{:.8f} NAV".format(int(value)/100000000)
        elif type == 3:
            return _("True") if int(value) == 1 else _("False")
        return str(value)
