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
import datetime
from datetime import date
from typing import TYPE_CHECKING, Tuple, Dict
import threading

from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum.i18n import _
from electrum.util import (block_explorer_URL, profiler, print_error, TxMinedInfo,
                           OrderedDictWithIndex, PrintError)

from .util import *

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet

try:
    from electrum.plot import plot_history, NothingToPlotException
except:
    print_error("qt/history_list: could not import electrum.plot. This feature needs matplotlib to be installed.")
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

class HistorySortModel(QSortFilterProxyModel):
    def lessThan(self, source_left: QModelIndex, source_right: QModelIndex):
        item1 = self.sourceModel().data(source_left, Qt.UserRole)
        item2 = self.sourceModel().data(source_right, Qt.UserRole)
        if item1 is None or item2 is None:
            raise Exception(f'UserRole not set for column {source_left.column()}')
        if item1.value() is None or item2.value() is None:
            return False
        return item1.value() < item2.value()

class HistoryModel(QAbstractItemModel, PrintError):

    NUM_COLUMNS = 8

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.transactions = OrderedDictWithIndex()
        self.tx_status_cache = {}  # type: Dict[str, Tuple[int, str]]

    def columnCount(self, parent: QModelIndex):
        return self.NUM_COLUMNS

    def rowCount(self, parent: QModelIndex):
        return len(self.transactions)

    def index(self, row: int, column: int, parent: QModelIndex):
        return self.createIndex(row, column)

    def data(self, index: QModelIndex, role: Qt.ItemDataRole):
        # requires PyQt5 5.11
        # indexIsValid = QAbstractItemModel.CheckIndexOptions(QAbstractItemModel.CheckIndexOption.IndexIsValid.value)
        # assert self.checkIndex(index, indexIsValid)
        assert index.isValid()
        col = index.column()
        tx_item = self.transactions.value_from_pos(index.row())
        tx_hash = tx_item['txid']
        conf = tx_item['confirmations']
        txpos = tx_item['txpos_in_block'] or 0
        height = tx_item['height']
        try:
            status, status_str = self.tx_status_cache[tx_hash]
        except KeyError:
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            status, status_str = self.parent.wallet.get_tx_status(tx_hash, tx_mined_info)
        if role == Qt.UserRole:
            # for sorting
            d = {
                # height breaks ties for unverified txns
                # txpos breaks ties for verified same block txns
                0: (status, conf, -height, -txpos),
                1: status_str,
                2: tx_item['label'],
                3: tx_item['value'].value,
                4: tx_item['balance'].value,
                5: tx_item['fiat_value'].value if 'fiat_value' in tx_item else None,
                6: tx_item['acquisition_price'].value if 'acquisition_price' in tx_item else None,
                7: tx_item['capital_gain'].value if 'capital_gain' in tx_item else None,
            }
            return QVariant(d[col])
        if role not in (Qt.DisplayRole, Qt.EditRole):
            if col == 0 and role == Qt.DecorationRole:
                return QVariant(self.parent.history_list.icon_cache.get(":icons/" +  TX_ICONS[status]))
            elif col == 0 and role == Qt.ToolTipRole:
                return QVariant(str(conf) + _(" confirmation" + ("s" if conf != 1 else "")))
            elif col > 2 and role == Qt.TextAlignmentRole:
                return QVariant(Qt.AlignRight | Qt.AlignVCenter)
            elif col != 1 and role == Qt.FontRole:
                monospace_font = QFont(MONOSPACE_FONT)
                return QVariant(monospace_font)
            elif col == 2 and role == Qt.DecorationRole and self.parent.wallet.invoices.paid.get(tx_hash):
                return QVariant(self.parent.history_list.icon_cache.get(":icons/seal"))
            elif col in (2, 3) and role == Qt.ForegroundRole and tx_item['value'].value < 0:
                red_brush = QBrush(QColor("#BC1E1E"))
                return QVariant(red_brush)
            elif col == 5 and role == Qt.ForegroundRole and not tx_item.get('fiat_default') and tx_item.get('fiat_value') is not None:
                blue_brush = QBrush(QColor("#1E1EFF"))
                return QVariant(blue_brush)
            return None
        if col == 1:
            return QVariant(status_str)
        elif col == 2:
            return QVariant(tx_item['label'])
        elif col == 3:
            value = tx_item['value'].value
            v_str = self.parent.format_amount(value, is_diff=True, whitespaces=True)
            return QVariant(v_str)
        elif col == 4:
            balance = tx_item['balance'].value
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            return QVariant(balance_str)
        elif col == 5 and 'fiat_value' in tx_item:
            value_str = self.parent.fx.format_fiat(tx_item['fiat_value'].value)
            return QVariant(value_str)
        elif col == 6 and tx_item['value'].value < 0 and 'acquisition_price' in tx_item:
            # fixme: should use is_mine
            acq = tx_item['acquisition_price'].value
            return QVariant(self.parent.fx.format_fiat(acq))
        elif col == 7 and 'capital_gain' in tx_item:
            cg = tx_item['capital_gain'].value
            return QVariant(self.parent.fx.format_fiat(cg))
        return None

    def parent(self, index: QModelIndex):
        return QModelIndex()

    def hasChildren(self, index: QModelIndex):
        return not index.isValid()

    def update_label(self, row):
        tx_item = self.transactions.value_from_pos(row)
        tx_item['label'] = self.parent.wallet.get_label(tx_item['txid'])
        topLeft = bottomRight = self.createIndex(row, 2)
        self.dataChanged.emit(topLeft, bottomRight, [Qt.DisplayRole])

    def get_domain(self):
        '''Overridden in address_dialog.py'''
        return self.parent.wallet.get_addresses()

    def refresh(self, reason: str):
        self.print_error(f"refreshing... reason: {reason}")
        assert self.parent.gui_thread == threading.current_thread(), 'must be called from GUI thread'
        selected = self.parent.history_list.selectionModel().currentIndex()
        selected_row = None
        if selected:
            selected_row = selected.row()
        fx = self.parent.fx
        if fx: fx.history_used_spot = False
        r = self.parent.wallet.get_full_history(domain=self.get_domain(), from_timestamp=None, to_timestamp=None, fx=fx)
        if r['transactions'] == list(self.transactions.values()):
            return
        old_length = len(self.transactions)
        if old_length != 0:
            self.beginRemoveRows(QModelIndex(), 0, old_length)
            self.transactions.clear()
            self.endRemoveRows()
        self.beginInsertRows(QModelIndex(), 0, len(r['transactions'])-1)
        for tx_item in r['transactions']:
            txid = tx_item['txid']
            self.transactions[txid] = tx_item
        self.endInsertRows()
        if selected_row:
            self.parent.history_list.selectionModel().select(self.createIndex(selected_row, 0), QItemSelectionModel.Rows | QItemSelectionModel.SelectCurrent)
        f = self.parent.history_list.current_filter
        if f:
            self.parent.history_list.filter(f)
        # update summary
        self.summary = r['summary']
        if not self.parent.history_list.years and self.transactions:
            start_date = date.today()
            end_date = date.today()
            if len(self.transactions) > 0:
                start_date = self.transactions.value_from_pos(0).get('date') or start_date
                end_date = self.transactions.value_from_pos(len(self.transactions) - 1).get('date') or end_date
            self.parent.history_list.years = [str(i) for i in range(start_date.year, end_date.year + 1)]
            self.parent.history_list.period_combo.insertItems(1, self.parent.history_list.years)
        # update tx_status_cache
        self.tx_status_cache.clear()
        for txid, tx_item in self.transactions.items():
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            self.tx_status_cache[txid] = self.parent.wallet.get_tx_status(txid, tx_mined_info)

        history = self.parent.fx.show_history()
        cap_gains = self.parent.fx.get_history_capital_gains_config()
        hide = self.parent.history_list.hideColumn
        show = self.parent.history_list.showColumn
        if history and cap_gains:
            show(5)
            show(6)
            show(7)
        elif history:
            show(5)
            hide(6)
            hide(7)
        else:
            hide(5)
            hide(6)
            hide(7)

    def update_fiat(self, row, idx):
        tx_item = self.transactions.value_from_pos(row)
        key = tx_item['txid']
        fee = tx_item.get('fee')
        value = tx_item['value'].value
        fiat_fields = self.parent.wallet.get_tx_item_fiat(key, value, self.parent.fx, fee.value if fee else None)
        tx_item.update(fiat_fields)
        self.dataChanged.emit(idx, idx, [Qt.DisplayRole, Qt.ForegroundRole])

    def update_tx_mined_status(self, tx_hash: str, tx_mined_info: TxMinedInfo):
        self.tx_status_cache[tx_hash] = self.parent.wallet.get_tx_status(tx_hash, tx_mined_info)
        try:
            row = self.transactions.pos_from_key(tx_hash)
        except KeyError:
            return
        topLeft = self.createIndex(row, 0)
        bottomRight = self.createIndex(row, self.NUM_COLUMNS-1)
        self.dataChanged.emit(topLeft, bottomRight)

    def on_fee_histogram(self):
        for tx_hash, tx_item in self.transactions.items():
            tx_mined_info = self.tx_mined_info_from_tx_item(tx_item)
            if tx_mined_info.conf > 0:
                # note: we could actually break here if we wanted to rely on the order of txns in self.transactions
                continue
            self.tx_status_cache[tx_hash] = self.parent.wallet.get_tx_status(tx_hash, tx_mined_info)
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
            if fx.get_history_capital_gains_config():
                fiat_acq_title = '%s '%fx.ccy + _('Acquisition price')
                fiat_cg_title =  '%s '%fx.ccy + _('Capital Gains')
        return {
            0: '',
            1: _('Date'),
            2: _('Description'),
            3: _('Amount'),
            4: _('Balance'),
            5: fiat_title,
            6: fiat_acq_title,
            7: fiat_cg_title,
        }[section]

    def flags(self, idx):
        extra_flags = Qt.NoItemFlags # type: Qt.ItemFlag
        if idx.column() in self.parent.history_list.editable_columns:
            extra_flags |= Qt.ItemIsEditable
        return super().flags(idx) | extra_flags

    @staticmethod
    def tx_mined_info_from_tx_item(tx_item):
        tx_mined_info = TxMinedInfo(height=tx_item['height'],
                                    conf=tx_item['confirmations'],
                                    timestamp=tx_item['timestamp'])
        return tx_mined_info

class HistoryList(MyTreeView, AcceptFileDragDrop):
    filter_columns = [1, 2, 3]  # Date, Description, Amount

    def tx_item_from_proxy_row(self, proxy_row):
        hm_idx = self.model().mapToSource(self.model().index(proxy_row, 0))
        return self.hm.transactions.value_from_pos(hm_idx.row())

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
        super().__init__(parent, self.create_menu, 2)
        self.hm = model
        self.proxy = HistorySortModel(self)
        self.proxy.setSourceModel(model)
        self.setModel(self.proxy)

        self.config = parent.config
        AcceptFileDragDrop.__init__(self, ".txn")
        self.setSortingEnabled(True)
        self.start_timestamp = None
        self.end_timestamp = None
        self.years = []
        self.create_toolbar_buttons()
        self.wallet = self.parent.wallet  # type: Abstract_Wallet
        self.sortByColumn(0, Qt.AscendingOrder)
        self.editable_columns |= {5}

        self.header().setStretchLastSection(False)
        for col in range(8):
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col, sm)

    def format_date(self, d):
        return str(datetime.date(d.year, d.month, d.day)) if d else _('None')

    def update_headers(self, headers):
        raise NotImplementedError

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
        h = self.model().sourceModel().summary
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
        grid.addWidget(QLabel(str(h.get('start_fiat_value')) + '/BTC'), 0, 2)
        grid.addWidget(QLabel(_("Initial balance")), 1, 0)
        grid.addWidget(QLabel(format_amount(h['start_balance'])), 1, 1)
        grid.addWidget(QLabel(str(h.get('start_fiat_balance'))), 1, 2)
        grid.addWidget(QLabel(_("End")), 2, 0)
        grid.addWidget(QLabel(self.format_date(end_date)), 2, 1)
        grid.addWidget(QLabel(str(h.get('end_fiat_value')) + '/BTC'), 2, 2)
        grid.addWidget(QLabel(_("Final balance")), 4, 0)
        grid.addWidget(QLabel(format_amount(h['end_balance'])), 4, 1)
        grid.addWidget(QLabel(str(h.get('end_fiat_balance'))), 4, 2)
        grid.addWidget(QLabel(_("Income")), 5, 0)
        grid.addWidget(QLabel(format_amount(h.get('income'))), 5, 1)
        grid.addWidget(QLabel(str(h.get('fiat_income'))), 5, 2)
        grid.addWidget(QLabel(_("Expenditures")), 6, 0)
        grid.addWidget(QLabel(format_amount(h.get('expenditures'))), 6, 1)
        grid.addWidget(QLabel(str(h.get('fiat_expenditures'))), 6, 2)
        grid.addWidget(QLabel(_("Capital gains")), 7, 0)
        grid.addWidget(QLabel(str(h.get('capital_gains'))), 7, 2)
        grid.addWidget(QLabel(_("Unrealized gains")), 8, 0)
        grid.addWidget(QLabel(str(h.get('unrealized_gains', ''))), 8, 2)
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
        row, column = index.row(), index.column()
        tx_item = self.hm.transactions.value_from_pos(row)
        key = tx_item['txid']
        # fixme
        if column == 2:
            if self.wallet.set_label(key, text): #changed
                self.hm.update_label(row)
                self.parent.update_completions()
        elif column == 5:
            self.wallet.set_fiat_value(key, self.parent.fx.ccy, text, self.parent.fx, tx_item['value'].value)
            value = tx_item['value'].value
            if value is not None:
                self.hm.update_fiat(row, index)
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
            self.show_transaction(tx_item['txid'])

    def show_transaction(self, tx_hash):
        tx = self.wallet.transactions.get(tx_hash)
        if not tx:
            return
        label = self.wallet.get_label(tx_hash) or None # prefer 'None' if not defined (force tx dialog to hide Description field if missing)
        self.parent.show_transaction(tx, label)

    def create_menu(self, position: QPoint):
        org_idx: QModelIndex = self.indexAt(position)
        idx = self.proxy.mapToSource(org_idx)
        if not idx.isValid():
            # can happen e.g. before list is populated for the first time
            return
        tx_item = self.hm.transactions.value_from_pos(idx.row())
        column = idx.column()
        if column == 0:
            column_title = _('Transaction ID')
            column_data = tx_item['txid']
        else:
            column_title = self.hm.headerData(column, Qt.Horizontal, Qt.DisplayRole)
            column_data = self.hm.data(idx, Qt.DisplayRole).value()
        tx_hash = tx_item['txid']
        tx = self.wallet.transactions[tx_hash]
        tx_URL = block_explorer_URL(self.config, 'tx', tx_hash)
        height = self.wallet.get_tx_height(tx_hash).height
        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
        is_unconfirmed = height <= 0
        pr_key = self.wallet.invoices.paid.get(tx_hash)
        menu = QMenu()
        if height == TX_HEIGHT_LOCAL:
            menu.addAction(_("Remove"), lambda: self.remove_local_tx(tx_hash))
        menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
        for c in self.editable_columns:
            label = self.hm.headerData(c, Qt.Horizontal, Qt.DisplayRole)
            # TODO use siblingAtColumn when min Qt version is >=5.11
            persistent = QPersistentModelIndex(org_idx.sibling(org_idx.row(), c))
            menu.addAction(_("Edit {}").format(label), lambda p=persistent: self.edit(QModelIndex(p)))
        menu.addAction(_("Details"), lambda: self.show_transaction(tx_hash))
        if is_unconfirmed and tx:
            # note: the current implementation of RBF *needs* the old tx fee
            rbf = is_mine and not tx.is_final() and fee is not None
            if rbf:
                menu.addAction(_("Increase fee"), lambda: self.parent.bump_fee_dialog(tx))
            else:
                child_tx = self.wallet.cpfp(tx, 0)
                if child_tx:
                    menu.addAction(_("Child pays for parent"), lambda: self.parent.cpfp(tx, child_tx))
        if pr_key:
            menu.addAction(self.icon_cache.get(":icons/seal"), _("View invoice"), lambda: self.parent.show_invoice(pr_key))
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webbrowser.open(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))

    def remove_local_tx(self, delete_tx):
        to_delete = {delete_tx}
        to_delete |= self.wallet.get_depending_transactions(delete_tx)
        question = _("Are you sure you want to remove this transaction?")
        if len(to_delete) > 1:
            question = _(
                "Are you sure you want to remove this transaction and {} child transactions?".format(len(to_delete) - 1)
            )
        answer = QMessageBox.question(self.parent, _("Please confirm"), question, QMessageBox.Yes, QMessageBox.No)
        if answer == QMessageBox.No:
            return
        for tx in to_delete:
            self.wallet.remove_transaction(tx)
        self.wallet.save_transactions(write=True)
        # need to update at least: history_list, utxo_list, address_list
        self.parent.need_update.set()

    def onFileAdded(self, fn):
        try:
            with open(fn) as f:
                tx = self.parent.tx_from_text(f.read())
                self.parent.save_transaction_into_wallet(tx)
        except IOError as e:
            self.parent.show_error(e)

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
        hist = self.wallet.get_full_history(domain=self.get_domain(),
                                            from_timestamp=None,
                                            to_timestamp=None,
                                            fx=self.parent.fx,
                                            show_fees=True)
        txns = hist['transactions']
        lines = []
        if is_csv:
            for item in txns:
                lines.append([item['txid'],
                              item.get('label', ''),
                              item['confirmations'],
                              item['value'],
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

    def text_txid_from_coordinate(self, row, col):
        idx = self.model().mapToSource(self.model().index(row, col))
        tx_item = self.hm.transactions.value_from_pos(idx.row())
        return self.hm.data(idx, Qt.DisplayRole).value(), tx_item['txid']
