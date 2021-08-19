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
import datetime
import os
from enum import IntEnum

from PyQt5.QtGui import QStandardItemModel, QStandardItem, QMouseEvent
from PyQt5.QtCore import Qt, QPersistentModelIndex, QModelIndex, QDate, QPoint
from PyQt5.QtWidgets import (QAbstractItemView, QMenu, QHeaderView, QComboBox, QPushButton, QVBoxLayout,
                             QCalendarWidget, QGridLayout, QLabel)

from electrum.i18n import _
from electrum.bitcoin import is_address
from electrum.util import block_explorer_URL
from electrum.plugin import run_hook
from .history_list import HistoryModel
from .staking_sort_model import StakingSortModel, StakingColumns, get_item_key

from .util import MyTreeView, webopen, WindowModalDialog, Buttons, OkButton, CancelButton, CloseButton, filename_field
from ...plot import plot_history, NothingToPlotException

mock = {
    'start_date'
}


class StakingList(MyTreeView):

    headers = {
        StakingColumns.START_DATE: _('Start Date'),
        StakingColumns.AMOUNT: _('Amount'),
        StakingColumns.STAKING_PERIOD: _('Staking Period'),
        StakingColumns.BLOCKS_LEFT: _('Blocks Left'),
        StakingColumns.TYPE: _('Type'),
    }
    filter_columns = [StakingColumns.START_DATE, StakingColumns.TYPE]

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
        super().__init__(parent, self.create_menu)
        self.config = parent.config
        self.hm = model
        self.proxy = StakingSortModel(self)
        self.proxy.setSourceModel(model)
        self.setModel(self.proxy)
        self.setSortingEnabled(True)
        self.start_timestamp = None
        self.end_timestamp = None
        self.years = []
        self.create_toolbar_buttons()
        self.wallet = self.parent.wallet
        self.sortByColumn(StakingColumns.STATUS, Qt.AscendingOrder)
        self.editable_columns |= {StakingColumns.FIAT_VALUE}
        self.setRootIsDecorated(True)
        self.header().setStretchLastSection(False)
        for col in StakingColumns:
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
            self.end_timestamp = end_date = datetime.datetime(year + 1, 1, 1)
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
        grid.addWidget(QLabel(str(h.get('fiat_start_value')) + '/ELCASH'), 0, 2)
        grid.addWidget(QLabel(_("Initial balance")), 1, 0)
        grid.addWidget(QLabel(format_amount(h['start_balance'])), 1, 1)
        grid.addWidget(QLabel(str(h.get('fiat_start_balance'))), 1, 2)
        grid.addWidget(QLabel(_("End")), 2, 0)
        grid.addWidget(QLabel(self.format_date(end_date)), 2, 1)
        grid.addWidget(QLabel(str(h.get('fiat_end_value')) + '/ELCASH'), 2, 2)
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
        if column == StakingColumns.DESCRIPTION:
            if self.wallet.set_label(key, text):  # changed
                self.hm.update_label(index)
                self.parent.update_completions()
        elif column == StakingColumns.FIAT_VALUE:
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
        label = self.wallet.get_label_for_txid(
            tx_hash) or None  # prefer 'None' if not defined (force tx dialog to hide Description field if missing)
        self.parent.show_transaction(tx, tx_desc=label)

    def add_copy_menu(self, menu, idx):
        cc = menu.addMenu(_("Copy"))
        for column in StakingColumns:
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
            cc.addAction(_("Payment Hash"),
                         lambda: self.place_text_on_clipboard(tx_item['payment_hash'], title="Payment Hash"))
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
        tx_url = block_explorer_URL(self.config, 'tx', tx_hash)
        tx_details = self.wallet.get_tx_info(tx)
        is_unconfirmed = tx_details.tx_mined_status.height <= 0
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
            if tx_details.can_bump:
                menu.addAction(_("Increase fee"), lambda: self.parent.bump_fee_dialog(tx))
            else:
                child_tx = self.wallet.cpfp(tx, 0)
                if child_tx:
                    menu.addAction(_("Child pays for parent"), lambda: self.parent.cpfp(tx, child_tx))
            if tx_details.can_dscancel:
                menu.addAction(_("Cancel (double-spend)"), lambda: self.parent.dscancel_dialog(tx))
        invoices = self.wallet.get_relevant_invoices_for_tx(tx)
        if len(invoices) == 1:
            menu.addAction(_("View invoice"), lambda inv=invoices[0]: self.parent.show_onchain_invoice(inv))
        elif len(invoices) > 1:
            menu_invs = menu.addMenu(_("Related invoices"))
            for inv in invoices:
                menu_invs.addAction(_("View invoice"), lambda inv=inv: self.parent.show_onchain_invoice(inv))
        if tx_url:
            menu.addAction(_("View on block explorer"), lambda: webopen(tx_url))
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
        # run_hook('export_history_dialog', self, hbox)
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
