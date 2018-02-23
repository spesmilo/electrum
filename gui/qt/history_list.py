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

from electrum.wallet import AddTransactionException, TX_HEIGHT_LOCAL
from .util import *
from electrum.i18n import _
from electrum.util import block_explorer_URL
from electrum.util import timestamp_to_datetime, profiler

try:
    from electrum.plot import plot_history
except:
    plot_history = None

# note: this list needs to be kept in sync with another in kivy
TX_ICONS = [
    "warning.png",
    "warning.png",
    "unconfirmed.png",
    "unconfirmed.png",
    "offline_tx.png",
    "clock1.png",
    "clock2.png",
    "clock3.png",
    "clock4.png",
    "clock5.png",
    "confirmed.png",
]


class HistoryList(MyTreeWidget, AcceptFileDragDrop):
    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 3)
        AcceptFileDragDrop.__init__(self, ".txn")
        self.refresh_headers()
        self.setColumnHidden(1, True)
        self.start_timestamp = None
        self.end_timestamp = None
        self.years = []

    def refresh_headers(self):
        headers = ['', '', _('Date'), _('Description'), _('Amount'), _('Balance')]
        fx = self.parent.fx
        if fx and fx.show_history():
            headers.extend(['%s '%fx.ccy + _('Value')])
            headers.extend(['%s '%fx.ccy + _('Acquisition price')])
            headers.extend(['%s '%fx.ccy + _('Capital Gains')])
            self.editable_columns |= {6}
        else:
            self.editable_columns -= {6}
        self.update_headers(headers)

    def get_domain(self):
        '''Replaced in address_dialog.py'''
        return self.wallet.get_addresses()

    def on_combo(self, x):
        s = self.period_combo.itemText(x)
        if s == _('All'):
            self.start_timestamp = None
            self.end_timestamp = None
        elif s == _('Custom'):
            start_date = self.select_date()
        else:
            try:
                year = int(s)
            except:
                return
            start_date = datetime.datetime(year, 1, 1)
            end_date = datetime.datetime(year+1, 1, 1)
            self.start_timestamp = time.mktime(start_date.timetuple())
            self.end_timestamp = time.mktime(end_date.timetuple())
        self.update()

    def get_list_header(self):
        self.period_combo = QComboBox()
        self.period_combo.addItems([_('All'), _('Custom')])
        self.period_combo.activated.connect(self.on_combo)
        self.summary_button = QPushButton(_('Summary'))
        self.summary_button.pressed.connect(self.show_summary)
        self.export_button = QPushButton(_('Export'))
        self.export_button.pressed.connect(self.export_history_dialog)
        self.plot_button = QPushButton(_('Plot'))
        self.plot_button.pressed.connect(self.plot_history_dialog)
        return self.period_combo, self.summary_button, self.export_button, self.plot_button

    def select_date(self):
        h = self.summary
        d = WindowModalDialog(self, _("Custom dates"))
        d.setMinimumSize(600, 150)
        d.b = True
        d.start_date = None
        d.end_date = None
        vbox = QVBoxLayout()
        grid = QGridLayout()
        start_edit = QPushButton()
        def on_start():
            start_edit.setText('')
            d.b = True
            d.start_date = None
        start_edit.pressed.connect(on_start)
        def on_end():
            end_edit.setText('')
            d.b = False
            d.end_date = None
        end_edit = QPushButton()
        end_edit.pressed.connect(on_end)
        grid.addWidget(QLabel(_("Start date")), 0, 0)
        grid.addWidget(start_edit, 0, 1)
        grid.addWidget(QLabel(_("End date")), 1, 0)
        grid.addWidget(end_edit, 1, 1)
        def on_date(date):
            ts = time.mktime(date.toPyDate().timetuple())
            if d.b:
                d.start_date = ts
                start_edit.setText(date.toString())
            else:
                d.end_date = ts
                end_edit.setText(date.toString())
        cal = QCalendarWidget()
        cal.setGridVisible(True)
        cal.clicked[QDate].connect(on_date)
        vbox.addLayout(grid)
        vbox.addWidget(cal)
        vbox.addLayout(Buttons(OkButton(d), CancelButton(d)))
        d.setLayout(vbox)
        if d.exec_():
            self.start_timestamp = d.start_date
            self.end_timestamp = d.end_date
            self.update()

    def show_summary(self):
        h = self.summary
        format_amount = lambda x: self.parent.format_amount(x) + ' '+ self.parent.base_unit()
        d = WindowModalDialog(self, _("Summary"))
        d.setMinimumSize(600, 150)
        vbox = QVBoxLayout()
        grid = QGridLayout()
        start_date = h.get('start_date')
        end_date = h.get('end_date')
        if start_date is None and end_date is None:
            return
        grid.addWidget(QLabel(_("Start")), 0, 0)
        grid.addWidget(QLabel(start_date.isoformat(' ')), 0, 1)
        grid.addWidget(QLabel(_("End")), 1, 0)
        grid.addWidget(QLabel(end_date.isoformat(' ')), 1, 1)
        grid.addWidget(QLabel(_("Initial balance")), 2, 0)
        grid.addWidget(QLabel(format_amount(h['start_balance'].value)), 2, 1)
        grid.addWidget(QLabel(str(h.get('start_fiat_balance'))), 2, 2)
        grid.addWidget(QLabel(_("Final balance")), 4, 0)
        grid.addWidget(QLabel(format_amount(h['end_balance'].value)), 4, 1)
        grid.addWidget(QLabel(str(h.get('end_fiat_balance'))), 4, 2)
        grid.addWidget(QLabel(_("Income")), 6, 0)
        grid.addWidget(QLabel(str(h.get('fiat_income'))), 6, 2)
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
            return
        if len(self.transactions) > 0:
            plt = plot_history(self.transactions)
            plt.show()

    @profiler
    def on_update(self):
        self.wallet = self.parent.wallet
        fx = self.parent.fx
        r = self.wallet.get_full_history(domain=self.get_domain(), from_timestamp=self.start_timestamp, to_timestamp=self.end_timestamp, fx=fx)
        self.transactions = r['transactions']
        self.summary = r['summary']
        if not self.years and self.start_timestamp is None and self.end_timestamp is None:
            start_date = self.summary.get('start_date')
            end_date = self.summary.get('end_date')
            if start_date and end_date:
                self.years = [str(i) for i in range(start_date.year, end_date.year + 1)]
                self.period_combo.insertItems(1, self.years)
        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole) if item else None
        self.clear()
        if fx: fx.history_used_spot = False
        for tx_item in self.transactions:
            tx_hash = tx_item['txid']
            height = tx_item['height']
            conf = tx_item['confirmations']
            timestamp = tx_item['timestamp']
            value = tx_item['value'].value
            balance = tx_item['balance'].value
            label = tx_item['label']
            status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
            has_invoice = self.wallet.invoices.paid.get(tx_hash)
            icon = QIcon(":icons/" + TX_ICONS[status])
            v_str = self.parent.format_amount(value, True, whitespaces=True)
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            entry = ['', tx_hash, status_str, label, v_str, balance_str]
            fiat_value = None
            if value is not None and fx and fx.show_history():
                date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
                fiat_value = tx_item['fiat_value'].value
                value_str = fx.format_fiat(fiat_value)
                entry.append(value_str)
                # fixme: should use is_mine
                if value < 0:
                    entry.append(fx.format_fiat(tx_item['acquisition_price'].value))
                    entry.append(fx.format_fiat(tx_item['capital_gain'].value))
            item = QTreeWidgetItem(entry)
            item.setIcon(0, icon)
            item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))
            if has_invoice:
                item.setIcon(3, QIcon(":icons/seal"))
            for i in range(len(entry)):
                if i>3:
                    item.setTextAlignment(i, Qt.AlignRight)
                if i!=2:
                    item.setFont(i, QFont(MONOSPACE_FONT))
            if value and value < 0:
                item.setForeground(3, QBrush(QColor("#BC1E1E")))
                item.setForeground(4, QBrush(QColor("#BC1E1E")))
            if fiat_value and not tx_item['fiat_default']:
                item.setForeground(6, QBrush(QColor("#1E1EFF")))
            if tx_hash:
                item.setData(0, Qt.UserRole, tx_hash)
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash:
                self.setCurrentItem(item)

    def on_edited(self, item, column, prior):
        '''Called only when the text actually changes'''
        key = item.data(0, Qt.UserRole)
        text = item.text(column)
        # fixme
        if column == 3:
            self.parent.wallet.set_label(key, text)
            self.update_labels()
            self.parent.update_completions()
        elif column == 6:
            self.parent.wallet.set_fiat_value(key, self.parent.fx.ccy, text)
            self.on_update()

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            super(HistoryList, self).on_doubleclick(item, column)
        else:
            tx_hash = item.data(0, Qt.UserRole)
            tx = self.wallet.transactions.get(tx_hash)
            self.parent.show_transaction(tx)

    def update_labels(self):
        root = self.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            txid = item.data(0, Qt.UserRole)
            label = self.wallet.get_label(txid)
            item.setText(3, label)

    def update_item(self, tx_hash, height, conf, timestamp):
        status, status_str = self.wallet.get_tx_status(tx_hash, height, conf, timestamp)
        icon = QIcon(":icons/" +  TX_ICONS[status])
        items = self.findItems(tx_hash, Qt.UserRole|Qt.MatchContains|Qt.MatchRecursive, column=1)
        if items:
            item = items[0]
            item.setIcon(0, icon)
            item.setText(2, status_str)

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return
        column = self.currentColumn()
        tx_hash = item.data(0, Qt.UserRole)
        if not tx_hash:
            return
        if column is 0:
            column_title = "ID"
            column_data = tx_hash
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column)
        tx_URL = block_explorer_URL(self.config, 'tx', tx_hash)
        height, conf, timestamp = self.wallet.get_tx_height(tx_hash)
        tx = self.wallet.transactions.get(tx_hash)
        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
        is_unconfirmed = height <= 0
        pr_key = self.wallet.invoices.paid.get(tx_hash)
        menu = QMenu()
        if height == TX_HEIGHT_LOCAL:
            menu.addAction(_("Remove"), lambda: self.remove_local_tx(tx_hash))
        menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
        for c in self.editable_columns:
            menu.addAction(_("Edit {}").format(self.headerItem().text(c)), lambda: self.editItem(item, c))
        menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx))
        if is_unconfirmed and tx:
            rbf = is_mine and not tx.is_final()
            if rbf:
                menu.addAction(_("Increase fee"), lambda: self.parent.bump_fee_dialog(tx))
            else:
                child_tx = self.wallet.cpfp(tx, 0)
                if child_tx:
                    menu.addAction(_("Child pays for parent"), lambda: self.parent.cpfp(tx, child_tx))
        if pr_key:
            menu.addAction(QIcon(":icons/seal"), _("View invoice"), lambda: self.parent.show_invoice(pr_key))
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
            self.do_export_history(self.wallet, filename, csv_button.isChecked())
        except (IOError, os.error) as reason:
            export_error_label = _("Electrum was unable to produce a transaction export.")
            self.parent.show_critical(export_error_label + "\n" + str(reason), title=_("Unable to export history"))
            return
        self.parent.show_message(_("Your wallet history has been successfully exported."))

    def do_export_history(self, wallet, fileName, is_csv):
        history = self.transactions
        lines = []
        for item in history:
            if is_csv:
                lines.append([item['txid'], item.get('label', ''), item['confirmations'], item['value'], item['date']])
            else:
                lines.append(item)
        with open(fileName, "w+") as f:
            if is_csv:
                import csv
                transaction = csv.writer(f, lineterminator='\n')
                transaction.writerow(["transaction_hash","label", "confirmations", "value", "timestamp"])
                for line in lines:
                    transaction.writerow(line)
            else:
                from electrum.util import json_encode
                f.write(json_encode(history))
