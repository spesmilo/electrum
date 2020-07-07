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
                             QGridLayout)

from electrum.address_synchronizer import TX_HEIGHT_LOCAL, TX_HEIGHT_FUTURE
from electrum.i18n import _
from electrum.util import (block_explorer_URL, profiler, TxMinedInfo,
                           OrderedDictWithIndex, timestamp_to_datetime,
                           Satoshis, Fiat, format_time)
from electrum.logging import get_logger, Logger

from .custom_model import CustomNode, CustomModel
from .util import (read_QIcon, MONOSPACE_FONT, Buttons, CancelButton, OkButton,
                   filename_field, MyTreeView, AcceptFileDragDrop, WindowModalDialog,
                   CloseButton, webopen)

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from .main_window import ElectrumWindow


_logger = get_logger(__name__)


try:
    from electrum.plot import plot_history, NothingToPlotException
except:
    _logger.info("could not import electrum.plot. This feature needs matplotlib to be installed.")
    plot_history = None

# note: this list needs to be kept in sync with another in kivy
TX_ICONS = [
    "unconfirmed.png",
    "warning.png",
    "unconfirmed.png",
    "offline_tx.png",
    "clock1.png",
    "clock2.png",
    "clock3.png",
    "clock4.png",
    "clock5.png",
    "confirmed.png",
]

class HistoryColumns(IntEnum):
    STATUS = 0
    DESCRIPTION = 1
    AMOUNT = 2
    BALANCE = 3
    FIAT_VALUE = 4
    FIAT_ACQ_PRICE = 5
    FIAT_CAP_GAINS = 6
    TXID = 7

class HistorySortModel(QSortFilterProxyModel):
    def lessThan(self, source_left: QModelIndex, source_right: QModelIndex):
        item1 = self.sourceModel().data(source_left, Qt.UserRole)
        item2 = self.sourceModel().data(source_right, Qt.UserRole)
        if item1 is None or item2 is None:
            raise Exception(f'UserRole not set for column {source_left.column()}')
        v1 = item1.value()
        v2 = item2.value()
        if v1 is None or isinstance(v1, Decimal) and v1.is_nan(): v1 = -float("inf")
        if v2 is None or isinstance(v2, Decimal) and v2.is_nan(): v2 = -float("inf")
        try:
            return v1 < v2
        except:
            return False

def get_item_key(tx_item):
    return tx_item.get('txid') or tx_item['payment_hash']


class HistoryNode(CustomNode):

    def get_data_for_role(self, index: QModelIndex, role: Qt.ItemDataRole) -> QVariant:
        # note: this method is performance-critical.
        # it is called a lot, and so must run extremely fast.
        assert index.isValid()
        col = index.column()
        window = self.model.parent
        tx_item = self.get_data()
        is_lightning = tx_item.get('lightning', False)
        timestamp = tx_item['timestamp']
        if is_lightning:
            status = 0
            if timestamp is None:
                status_str = 'unconfirmed'
            else:
                status_str = format_time(int(timestamp))
        else:
            tx_hash = tx_item['txid']
            conf = tx_item['confirmations']
            try:
                status, status_str = self.model.tx_status_cache[tx_hash]
            except KeyError:
                tx_mined_info = self.model.tx_mined_info_from_tx_item(tx_item)
                status, status_str = window.wallet.get_tx_status(tx_hash, tx_mined_info)

        if role == Qt.UserRole:
            # for sorting
            d = {
                HistoryColumns.STATUS:
                    # respect sort order of self.transactions (wallet.get_full_history)
                    -index.row(),
                HistoryColumns.DESCRIPTION:
                    tx_item['label'] if 'label' in tx_item else None,
                HistoryColumns.AMOUNT:
                    (tx_item['bc_value'].value if 'bc_value' in tx_item else 0)\
                    + (tx_item['ln_value'].value if 'ln_value' in tx_item else 0),
                HistoryColumns.BALANCE:
                    (tx_item['balance'].value if 'balance' in tx_item else 0),
                HistoryColumns.FIAT_VALUE:
                    tx_item['fiat_value'].value if 'fiat_value' in tx_item else None,
                HistoryColumns.FIAT_ACQ_PRICE:
                    tx_item['acquisition_price'].value if 'acquisition_price' in tx_item else None,
                HistoryColumns.FIAT_CAP_GAINS:
                    tx_item['capital_gain'].value if 'capital_gain' in tx_item else None,
                HistoryColumns.TXID: tx_hash if not is_lightning else None,
            }
            return QVariant(d[col])
        if role not in (Qt.DisplayRole, Qt.EditRole):
            if col == HistoryColumns.STATUS and role == Qt.DecorationRole:
                icon = "lightning" if is_lightning else TX_ICONS[status]
                return QVariant(read_QIcon(icon))
            elif col == HistoryColumns.STATUS and role == Qt.ToolTipRole:
                if is_lightning:
                    msg = 'lightning transaction'
                else:  # on-chain
                    if tx_item['height'] == TX_HEIGHT_LOCAL:
                        # note: should we also explain double-spends?
                        msg = _("This transaction is only available on your local machine.\n"
                                "The currently connected server does not know about it.\n"
                                "You can either broadcast it now, or simply remove it.")
                    else:
                        msg = str(conf) + _(" confirmation" + ("s" if conf != 1 else ""))
                return QVariant(msg)
            elif col > HistoryColumns.DESCRIPTION and role == Qt.TextAlignmentRole:
                return QVariant(Qt.AlignRight | Qt.AlignVCenter)
            elif col > HistoryColumns.DESCRIPTION and role == Qt.FontRole:
                monospace_font = QFont(MONOSPACE_FONT)
                return QVariant(monospace_font)
            #elif col == HistoryColumns.DESCRIPTION and role == Qt.DecorationRole and not is_lightning\
            #        and self.parent.wallet.invoices.paid.get(tx_hash):
            #    return QVariant(read_QIcon("seal"))
            elif col in (HistoryColumns.DESCRIPTION, HistoryColumns.AMOUNT) \
                    and role == Qt.ForegroundRole and tx_item['value'].value < 0:
                red_brush = QBrush(QColor("#BC1E1E"))
                return QVariant(red_brush)
            elif col == HistoryColumns.FIAT_VALUE and role == Qt.ForegroundRole \
                    and not tx_item.get('fiat_default') and tx_item.get('fiat_value') is not None:
                blue_brush = QBrush(QColor("#1E1EFF"))
                return QVariant(blue_brush)
            return QVariant()
        if col == HistoryColumns.STATUS:
            return QVariant(status_str)
        elif col == HistoryColumns.DESCRIPTION and 'label' in tx_item:
            return QVariant(tx_item['label'])
        elif col == HistoryColumns.AMOUNT:
            bc_value = tx_item['bc_value'].value if 'bc_value' in tx_item else 0
            ln_value = tx_item['ln_value'].value if 'ln_value' in tx_item else 0
            value = bc_value + ln_value
            v_str = window.format_amount(value, is_diff=True, whitespaces=True)
            return QVariant(v_str)
        elif col == HistoryColumns.BALANCE:
            balance = tx_item['balance'].value
            balance_str = window.format_amount(balance, whitespaces=True)
            return QVariant(balance_str)
        elif col == HistoryColumns.FIAT_VALUE and 'fiat_value' in tx_item:
            value_str = window.fx.format_fiat(tx_item['fiat_value'].value)
            return QVariant(value_str)
        elif col == HistoryColumns.FIAT_ACQ_PRICE and \
                tx_item['value'].value < 0 and 'acquisition_price' in tx_item:
            # fixme: should use is_mine
            acq = tx_item['acquisition_price'].value
            return QVariant(window.fx.format_fiat(acq))
        elif col == HistoryColumns.FIAT_CAP_GAINS and 'capital_gain' in tx_item:
            cg = tx_item['capital_gain'].value
            return QVariant(window.fx.format_fiat(cg))
        elif col == HistoryColumns.TXID:
            return QVariant(tx_hash) if not is_lightning else QVariant('')
        return QVariant()


class HistoryModel(CustomModel, Logger):

    def __init__(self, parent: 'ElectrumWindow'):
        CustomModel.__init__(self, parent, len(HistoryColumns))
        Logger.__init__(self)
        self.parent = parent
        self.view = None  # type: HistoryList
        self.transactions = OrderedDictWithIndex()
        self.tx_status_cache = {}  # type: Dict[str, Tuple[int, str]]

    def set_view(self, history_list: 'HistoryList'):
        # FIXME HistoryModel and HistoryList mutually depend on each other.
        # After constructing both, this method needs to be called.
        self.view = history_list  # type: HistoryList
        self.set_visibility_of_columns()

    def update_label(self, index):
        tx_item = index.internalPointer().get_data()
        tx_item['label'] = self.parent.wallet.get_label(get_item_key(tx_item))
        topLeft = bottomRight = self.createIndex(index.row(), HistoryColumns.DESCRIPTION)
        self.dataChanged.emit(topLeft, bottomRight, [Qt.DisplayRole])
        self.parent.utxo_list.update()

    def get_domain(self):
        """Overridden in address_dialog.py"""
        return self.parent.wallet.get_addresses()

    def should_include_lightning_payments(self) -> bool:
        """Overridden in address_dialog.py"""
        return True

    @profiler
    def refresh(self, reason: str):
        self.logger.info(f"refreshing... reason: {reason}")
        assert self.parent.gui_thread == threading.current_thread(), 'must be called from GUI thread'
        assert self.view, 'view not set'
        if self.view.maybe_defer_update():
            return
        selected = self.view.selectionModel().currentIndex()
        selected_row = None
        if selected:
            selected_row = selected.row()
        fx = self.parent.fx
        if fx: fx.history_used_spot = False
        wallet = self.parent.wallet
        self.set_visibility_of_columns()
        transactions = wallet.get_full_history(
            self.parent.fx,
            onchain_domain=self.get_domain(),
            include_lightning=self.should_include_lightning_payments())
        if transactions == list(self.transactions.values()):
            return
        old_length = self._root.childCount()
        if old_length != 0:
            self.beginRemoveRows(QModelIndex(), 0, old_length)
            self.transactions.clear()
            self._root = HistoryNode(self, None)
            self.endRemoveRows()
        parents = {}
        for tx_item in transactions.values():
            node = HistoryNode(self, tx_item)
            group_id = tx_item.get('group_id')
            if group_id is None:
                self._root.addChild(node)
            else:
                parent = parents.get(group_id)
                if parent is None:
                    # create parent if it does not exist
                    self._root.addChild(node)
                    parents[group_id] = node
                else:
                    # if parent has no children, create two children
                    if parent.childCount() == 0:
                        child_data = dict(parent.get_data())
                        node1 = HistoryNode(self, child_data)
                        parent.addChild(node1)
                        parent._data['label'] = child_data.get('group_label')
                        parent._data['bc_value'] = child_data.get('bc_value', Satoshis(0))
                        parent._data['ln_value'] = child_data.get('ln_value', Satoshis(0))
                    # add child to parent
                    parent.addChild(node)
                    # update parent data
                    parent._data['balance'] = tx_item['balance']
                    parent._data['value'] += tx_item['value']
                    if 'group_label' in tx_item:
                        parent._data['label'] = tx_item['group_label']
                    if 'bc_value' in tx_item:
                        parent._data['bc_value'] += tx_item['bc_value']
                    if 'ln_value' in tx_item:
                        parent._data['ln_value'] += tx_item['ln_value']
                    if 'fiat_value' in tx_item:
                        parent._data['fiat_value'] += tx_item['fiat_value']
                    if tx_item.get('txid') == group_id:
                        parent._data['lightning'] = False
                        parent._data['txid'] = tx_item['txid']
                        parent._data['timestamp'] = tx_item['timestamp']
                        parent._data['height'] = tx_item['height']
                        parent._data['confirmations'] = tx_item['confirmations']

        new_length = self._root.childCount()
        self.beginInsertRows(QModelIndex(), 0, new_length-1)
        self.transactions = transactions
        self.endInsertRows()

        if selected_row:
            self.view.selectionModel().select(self.createIndex(selected_row, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        self.view.filter()
        # update time filter
        if not self.view.years and self.transactions:
            start_date = date.today()
            end_date = date.today()
            if len(self.transactions) > 0:
                start_date = self.transactions.value_from_pos(0).get('date') or start_date
                end_date = self.transactions.value_from_pos(len(self.transactions) - 1).get('date') or end_date
            self.view.years = [str(i) for i in range(start_date.year, end_date.year + 1)]
            self.view.period_combo.insertItems(1, self.view.years)
        # update tx_status_cache
        self.tx_status_cache.clear()
        for txid, tx_item in self.transactions.items():
            if not tx_item.get('lightning', False):
                tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
                self.tx_status_cache[txid] = self.parent.wallet.get_tx_status(txid, tx_mined_info)

    def set_visibility_of_columns(self):
        def set_visible(col: int, b: bool):
            self.view.showColumn(col) if b else self.view.hideColumn(col)
        # txid
        set_visible(HistoryColumns.TXID, False)
        # fiat
        history = self.parent.fx.show_history()
        cap_gains = self.parent.fx.get_history_capital_gains_config()
        set_visible(HistoryColumns.FIAT_VALUE, history)
        set_visible(HistoryColumns.FIAT_ACQ_PRICE, history and cap_gains)
        set_visible(HistoryColumns.FIAT_CAP_GAINS, history and cap_gains)

    def update_fiat(self, idx):
        tx_item = idx.internalPointer().get_data()
        key = tx_item['txid']
        fee = tx_item.get('fee')
        value = tx_item['value'].value
        fiat_fields = self.parent.wallet.get_tx_item_fiat(key, value, self.parent.fx, fee.value if fee else None)
        tx_item.update(fiat_fields)
        self.dataChanged.emit(idx, idx, [Qt.DisplayRole, Qt.ForegroundRole])

    def update_tx_mined_status(self, tx_hash: str, tx_mined_info: TxMinedInfo):
        try:
            row = self.transactions.pos_from_key(tx_hash)
            tx_item = self.transactions[tx_hash]
        except KeyError:
            return
        self.tx_status_cache[tx_hash] = self.parent.wallet.get_tx_status(tx_hash, tx_mined_info)
        tx_item.update({
            'confirmations':  tx_mined_info.conf,
            'timestamp':      tx_mined_info.timestamp,
            'txpos_in_block': tx_mined_info.txpos,
            'date':           timestamp_to_datetime(tx_mined_info.timestamp),
        })
        topLeft = self.createIndex(row, 0)
        bottomRight = self.createIndex(row, len(HistoryColumns) - 1)
        self.dataChanged.emit(topLeft, bottomRight)

    def on_fee_histogram(self):
        for tx_hash, tx_item in list(self.transactions.items()):
            if tx_item.get('lightning'):
                continue
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            if tx_mined_info.conf > 0:
                # note: we could actually break here if we wanted to rely on the order of txns in self.transactions
                continue
            self.update_tx_mined_status(tx_hash, tx_mined_info)

    def headerData(self, section: int, orientation: Qt.Orientation, role: Qt.ItemDataRole):
        assert orientation == Qt.Horizontal
        if role != Qt.DisplayRole:
            return None
        fx = self.parent.fx
        fiat_title = 'n/a fiat value'
        fiat_acq_title = 'n/a fiat acquisition price'
        fiat_cg_title = 'n/a fiat capital gains'
        if fx and fx.show_history():
            fiat_title = '%s '%fx.ccy + _('Value')
            fiat_acq_title = '%s '%fx.ccy + _('Acquisition price')
            fiat_cg_title =  '%s '%fx.ccy + _('Capital Gains')
        return {
            HistoryColumns.STATUS: _('Date'),
            HistoryColumns.DESCRIPTION: _('Description'),
            HistoryColumns.AMOUNT: _('Amount'),
            HistoryColumns.BALANCE: _('Balance'),
            HistoryColumns.FIAT_VALUE: fiat_title,
            HistoryColumns.FIAT_ACQ_PRICE: fiat_acq_title,
            HistoryColumns.FIAT_CAP_GAINS: fiat_cg_title,
            HistoryColumns.TXID: 'TXID',
        }[section]

    def flags(self, idx):
        extra_flags = Qt.NoItemFlags # type: Qt.ItemFlag
        if idx.column() in self.view.editable_columns:
            extra_flags |= Qt.ItemIsEditable
        return super().flags(idx) | extra_flags

    @staticmethod
    def tx_mined_info_from_tx_item(tx_item):
        tx_mined_info = TxMinedInfo(height=tx_item['height'],
                                    conf=tx_item['confirmations'],
                                    timestamp=tx_item['timestamp'])
        return tx_mined_info

class HistoryList(MyTreeView, AcceptFileDragDrop):
    filter_columns = [HistoryColumns.STATUS,
                      HistoryColumns.DESCRIPTION,
                      HistoryColumns.AMOUNT,
                      HistoryColumns.TXID]

    def tx_item_from_proxy_row(self, proxy_row):
        hm_idx = self.model().mapToSource(self.model().index(proxy_row, 0))
        return hm_idx.internalPointer().get_data()

    def should_hide(self, proxy_row):
        if self.start_timestamp and self.end_timestamp:
            tx_item = self.tx_item_from_proxy_row(proxy_row)
            date = tx_item['date']
            if date:
                in_interval = self.start_timestamp <= date <= self.end_timestamp
                if not in_interval:
                    return True
            return False

    def __init__(self, parent, model: HistoryModel):
        super().__init__(parent, self.create_menu, stretch_column=HistoryColumns.DESCRIPTION)
        self.config = parent.config
        self.hm = model
        self.proxy = HistorySortModel(self)
        self.proxy.setSourceModel(model)
        self.setModel(self.proxy)
        AcceptFileDragDrop.__init__(self, ".txn")
        self.setSortingEnabled(True)
        self.start_timestamp = None
        self.end_timestamp = None
        self.years = []
        self.create_toolbar_buttons()
        self.wallet = self.parent.wallet  # type: Abstract_Wallet
        self.sortByColumn(HistoryColumns.STATUS, Qt.AscendingOrder)
        self.editable_columns |= {HistoryColumns.FIAT_VALUE}
        self.setRootIsDecorated(True)
        self.header().setStretchLastSection(False)
        for col in HistoryColumns:
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col, sm)

    def update(self):
        self.hm.refresh('HistoryList.update()')

    def format_date(self, d):
        return str(datetime.date(d.year, d.month, d.day)) if d else _('None')

    def on_combo(self, x):
        s = self.period_combo.itemText(x)
        x = s == _('Custom')
        self.start_button.setEnabled(x)
        self.end_button.setEnabled(x)
        if s == _('All'):
            self.start_timestamp = None
            self.end_timestamp = None
            self.start_button.setText("-")
            self.end_button.setText("-")
        else:
            try:
                year = int(s)
            except:
                return
            self.start_timestamp = start_date = datetime.datetime(year, 1, 1)
            self.end_timestamp = end_date = datetime.datetime(year+1, 1, 1)
            self.start_button.setText(_('From') + ' ' + self.format_date(start_date))
            self.end_button.setText(_('To') + ' ' + self.format_date(end_date))
        self.hide_rows()

    def create_toolbar_buttons(self):
        self.period_combo = QComboBox()
        self.start_button = QPushButton('-')
        self.start_button.pressed.connect(self.select_start_date)
        self.start_button.setEnabled(False)
        self.end_button = QPushButton('-')
        self.end_button.pressed.connect(self.select_end_date)
        self.end_button.setEnabled(False)
        self.period_combo.addItems([_('All'), _('Custom')])
        self.period_combo.activated.connect(self.on_combo)

    def get_toolbar_buttons(self):
        return self.period_combo, self.start_button, self.end_button

    def on_hide_toolbar(self):
        self.start_timestamp = None
        self.end_timestamp = None
        self.hide_rows()

    def save_toolbar_state(self, state, config):
        config.set_key('show_toolbar_history', state)

    def select_start_date(self):
        self.start_timestamp = self.select_date(self.start_button)
        self.hide_rows()

    def select_end_date(self):
        self.end_timestamp = self.select_date(self.end_button)
        self.hide_rows()

    def select_date(self, button):
        d = WindowModalDialog(self, _("Select date"))
        d.setMinimumSize(600, 150)
        d.date = None
        vbox = QVBoxLayout()
        def on_date(date):
            d.date = date
        cal = QCalendarWidget()
        cal.setGridVisible(True)
        cal.clicked[QDate].connect(on_date)
        vbox.addWidget(cal)
        vbox.addLayout(Buttons(OkButton(d), CancelButton(d)))
        d.setLayout(vbox)
        if d.exec_():
            if d.date is None:
                return None
            date = d.date.toPyDate()
            button.setText(self.format_date(date))
            return datetime.datetime(date.year, date.month, date.day)

    def show_summary(self):
        h = self.parent.wallet.get_detailed_history()['summary']
        if not h:
            self.parent.show_message(_("Nothing to summarize."))
            return
        start_date = h.get('start_date')
        end_date = h.get('end_date')
        format_amount = lambda x: self.parent.format_amount(x.value) + ' ' + self.parent.base_unit()
        d = WindowModalDialog(self, _("Summary"))
        d.setMinimumSize(600, 150)
        vbox = QVBoxLayout()
        grid = QGridLayout()
        grid.addWidget(QLabel(_("Start")), 0, 0)
        grid.addWidget(QLabel(self.format_date(start_date)), 0, 1)
        grid.addWidget(QLabel(str(h.get('fiat_start_value')) + '/BTC'), 0, 2)
        grid.addWidget(QLabel(_("Initial balance")), 1, 0)
        grid.addWidget(QLabel(format_amount(h['start_balance'])), 1, 1)
        grid.addWidget(QLabel(str(h.get('fiat_start_balance'))), 1, 2)
        grid.addWidget(QLabel(_("End")), 2, 0)
        grid.addWidget(QLabel(self.format_date(end_date)), 2, 1)
        grid.addWidget(QLabel(str(h.get('fiat_end_value')) + '/BTC'), 2, 2)
        grid.addWidget(QLabel(_("Final balance")), 4, 0)
        grid.addWidget(QLabel(format_amount(h['end_balance'])), 4, 1)
        grid.addWidget(QLabel(str(h.get('fiat_end_balance'))), 4, 2)
        grid.addWidget(QLabel(_("Income")), 5, 0)
        grid.addWidget(QLabel(format_amount(h.get('incoming'))), 5, 1)
        grid.addWidget(QLabel(str(h.get('fiat_incoming'))), 5, 2)
        grid.addWidget(QLabel(_("Expenditures")), 6, 0)
        grid.addWidget(QLabel(format_amount(h.get('outgoing'))), 6, 1)
        grid.addWidget(QLabel(str(h.get('fiat_outgoing'))), 6, 2)
        grid.addWidget(QLabel(_("Capital gains")), 7, 0)
        grid.addWidget(QLabel(str(h.get('fiat_capital_gains'))), 7, 2)
        grid.addWidget(QLabel(_("Unrealized gains")), 8, 0)
        grid.addWidget(QLabel(str(h.get('fiat_unrealized_gains', ''))), 8, 2)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)
        d.exec_()

    def plot_history_dialog(self):
        if plot_history is None:
            self.parent.show_message(
                _("Can't plot history.") + '\n' +
                _("Perhaps some dependencies are missing...") + " (matplotlib?)")
            return
        try:
            plt = plot_history(list(self.hm.transactions.values()))
            plt.show()
        except NothingToPlotException as e:
            self.parent.show_message(str(e))

    def on_edited(self, index, user_role, text):
        index = self.model().mapToSource(index)
        tx_item = index.internalPointer().get_data()
        column = index.column()
        key = get_item_key(tx_item)
        if column == HistoryColumns.DESCRIPTION:
            if self.wallet.set_label(key, text): #changed
                self.hm.update_label(index)
                self.parent.update_completions()
        elif column == HistoryColumns.FIAT_VALUE:
            self.wallet.set_fiat_value(key, self.parent.fx.ccy, text, self.parent.fx, tx_item['value'].value)
            value = tx_item['value'].value
            if value is not None:
                self.hm.update_fiat(index)
        else:
            assert False

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        idx = self.indexAt(event.pos())
        if not idx.isValid():
            return
        tx_item = self.tx_item_from_proxy_row(idx.row())
        if self.hm.flags(self.model().mapToSource(idx)) & Qt.ItemIsEditable:
            super().mouseDoubleClickEvent(event)
        else:
            if tx_item.get('lightning'):
                if tx_item['type'] == 'payment':
                    self.parent.show_lightning_transaction(tx_item)
                return
            tx_hash = tx_item['txid']
            tx = self.wallet.db.get_transaction(tx_hash)
            if not tx:
                return
            self.show_transaction(tx_item, tx)

    def show_transaction(self, tx_item, tx):
        tx_hash = tx_item['txid']
        label = self.wallet.get_label(tx_hash) or None # prefer 'None' if not defined (force tx dialog to hide Description field if missing)
        self.parent.show_transaction(tx, tx_desc=label)

    def add_copy_menu(self, menu, idx):
        cc = menu.addMenu(_("Copy"))
        for column in HistoryColumns:
            if self.isColumnHidden(column):
                continue
            column_title = self.hm.headerData(column, Qt.Horizontal, Qt.DisplayRole)
            idx2 = idx.sibling(idx.row(), column)
            column_data = (self.hm.data(idx2, Qt.DisplayRole).value() or '').strip()
            cc.addAction(
                column_title,
                lambda text=column_data, title=column_title:
                self.place_text_on_clipboard(text, title=title))
        return cc

    def create_menu(self, position: QPoint):
        org_idx: QModelIndex = self.indexAt(position)
        idx = self.proxy.mapToSource(org_idx)
        if not idx.isValid():
            # can happen e.g. before list is populated for the first time
            return
        tx_item = idx.internalPointer().get_data()
        if tx_item.get('lightning') and tx_item['type'] == 'payment':
            menu = QMenu()
            menu.addAction(_("View Payment"), lambda: self.parent.show_lightning_transaction(tx_item))
            cc = self.add_copy_menu(menu, idx)
            cc.addAction(_("Payment Hash"), lambda: self.place_text_on_clipboard(tx_item['payment_hash'], title="Payment Hash"))
            cc.addAction(_("Preimage"), lambda: self.place_text_on_clipboard(tx_item['preimage'], title="Preimage"))
            menu.exec_(self.viewport().mapToGlobal(position))
            return
        tx_hash = tx_item['txid']
        if tx_item.get('lightning'):
            tx = self.wallet.lnworker.lnwatcher.db.get_transaction(tx_hash)
        else:
            tx = self.wallet.db.get_transaction(tx_hash)
        if not tx:
            return
        tx_URL = block_explorer_URL(self.config, 'tx', tx_hash)
        tx_details = self.wallet.get_tx_info(tx)
        is_unconfirmed = tx_details.tx_mined_status.height <= 0
        invoice_keys = self.wallet.get_relevant_invoice_keys_for_tx(tx)
        menu = QMenu()
        if tx_details.can_remove:
            menu.addAction(_("Remove"), lambda: self.remove_local_tx(tx_hash))
        cc = self.add_copy_menu(menu, idx)
        cc.addAction(_("Transaction ID"), lambda: self.place_text_on_clipboard(tx_hash, title="TXID"))
        for c in self.editable_columns:
            if self.isColumnHidden(c): continue
            label = self.hm.headerData(c, Qt.Horizontal, Qt.DisplayRole)
            # TODO use siblingAtColumn when min Qt version is >=5.11
            persistent = QPersistentModelIndex(org_idx.sibling(org_idx.row(), c))
            menu.addAction(_("Edit {}").format(label), lambda p=persistent: self.edit(QModelIndex(p)))
        menu.addAction(_("View Transaction"), lambda: self.show_transaction(tx_item, tx))
        channel_id = tx_item.get('channel_id')
        if channel_id:
            menu.addAction(_("View Channel"), lambda: self.parent.show_channel(bytes.fromhex(channel_id)))
        if is_unconfirmed and tx:
            # note: the current implementation of RBF *needs* the old tx fee
            if tx_details.can_bump and tx_details.fee is not None:
                menu.addAction(_("Increase fee"), lambda: self.parent.bump_fee_dialog(tx))
            else:
                child_tx = self.wallet.cpfp(tx, 0)
                if child_tx:
                    menu.addAction(_("Child pays for parent"), lambda: self.parent.cpfp(tx, child_tx))
        for key in invoice_keys:
            invoice = self.parent.wallet.get_invoice(key)
            if invoice:
                menu.addAction(_("View invoice"), lambda: self.parent.show_onchain_invoice(invoice))
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webopen(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))

    def remove_local_tx(self, tx_hash: str):
        to_delete = {tx_hash}
        to_delete |= self.wallet.get_depending_transactions(tx_hash)
        question = _("Are you sure you want to remove this transaction?")
        if len(to_delete) > 1:
            question = (_("Are you sure you want to remove this transaction and {} child transactions?")
                        .format(len(to_delete) - 1))
        if not self.parent.question(msg=question,
                                    title=_("Please confirm")):
            return
        for tx in to_delete:
            self.wallet.remove_transaction(tx)
        self.wallet.save_db()
        # need to update at least: history_list, utxo_list, address_list
        self.parent.need_update.set()

    def onFileAdded(self, fn):
        try:
            with open(fn) as f:
                tx = self.parent.tx_from_text(f.read())
        except IOError as e:
            self.parent.show_error(e)
            return
        if not tx:
            return
        self.parent.save_transaction_into_wallet(tx)

    def export_history_dialog(self):
        d = WindowModalDialog(self, _('Export History'))
        d.setMinimumSize(400, 200)
        vbox = QVBoxLayout(d)
        defaultname = os.path.expanduser('~/electrum-history.csv')
        select_msg = _('Select file to export your wallet transactions to')
        hbox, filename_e, csv_button = filename_field(self, self.config, defaultname, select_msg)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        hbox = Buttons(CancelButton(d), OkButton(d, _('Export')))
        vbox.addLayout(hbox)
        #run_hook('export_history_dialog', self, hbox)
        self.update()
        if not d.exec_():
            return
        filename = filename_e.text()
        if not filename:
            return
        try:
            self.do_export_history(filename, csv_button.isChecked())
        except (IOError, os.error) as reason:
            export_error_label = _("Electrum was unable to produce a transaction export.")
            self.parent.show_critical(export_error_label + "\n" + str(reason), title=_("Unable to export history"))
            return
        self.parent.show_message(_("Your wallet history has been successfully exported."))

    def do_export_history(self, file_name, is_csv):
        hist = self.wallet.get_detailed_history(fx=self.parent.fx)
        txns = hist['transactions']
        lines = []
        if is_csv:
            for item in txns:
                lines.append([item['txid'],
                              item.get('label', ''),
                              item['confirmations'],
                              item['bc_value'],
                              item.get('fiat_value', ''),
                              item.get('fee', ''),
                              item.get('fiat_fee', ''),
                              item['date']])
        with open(file_name, "w+", encoding='utf-8') as f:
            if is_csv:
                import csv
                transaction = csv.writer(f, lineterminator='\n')
                transaction.writerow(["transaction_hash",
                                      "label",
                                      "confirmations",
                                      "value",
                                      "fiat_value",
                                      "fee",
                                      "fiat_fee",
                                      "timestamp"])
                for line in lines:
                    transaction.writerow(line)
            else:
                from electrum.util import json_encode
                f.write(json_encode(txns))

    def get_text_and_userrole_from_coordinate(self, row, col):
        idx = self.model().mapToSource(self.model().index(row, col))
        tx_item = idx.internalPointer().get_data()
        return self.hm.data(idx, Qt.DisplayRole).value(), get_item_key(tx_item)
