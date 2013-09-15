#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys, time, datetime, re, threading
from electrum.i18n import _, set_language
from electrum.util import print_error, print_msg
import os.path, json, ast, traceback
import shutil
import StringIO


try:
    import PyQt4
except:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum import transaction


class TxDialog(QDialog):

    def __init__(self, tx, parent):
        self.tx = tx
        tx_dict = tx.as_dict()
        self.parent = parent
        self.wallet = parent.wallet
            
        QDialog.__init__(self)
        self.setMinimumWidth(600)
        self.setWindowTitle(_('Transaction'))
        self.setModal(1)

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel("Transaction ID:"))
        self.tx_hash_e  = QLineEdit()
        self.tx_hash_e.setReadOnly(True)
        vbox.addWidget(self.tx_hash_e)
        self.status_label = QLabel()
        vbox.addWidget(self.status_label)

        self.date_label = QLabel()
        vbox.addWidget(self.date_label)
        self.amount_label = QLabel()
        vbox.addWidget(self.amount_label)
        self.fee_label = QLabel()
        vbox.addWidget(self.fee_label)

        self.io = self.io_widget(tx)
        vbox.addWidget( self.io )
        vbox.addStretch(1)

        buttons = QHBoxLayout()
        vbox.addLayout( buttons )

        buttons.addStretch(1)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)
        buttons.addWidget(b)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.broadcast)
        b.hide()
        buttons.addWidget(b)

        self.save_button = b = QPushButton(_("Save"))
        b.clicked.connect(self.save)
        buttons.addWidget(b)

        cancelButton = QPushButton(_("Close"))
        cancelButton.clicked.connect(lambda: self.done(0))
        buttons.addWidget(cancelButton)

        self.update()




    def sign(self):
        tx_dict = self.tx.as_dict()
        input_info = json.loads(tx_dict["input_info"])
        self.parent.sign_raw_transaction(self.tx, input_info)
        self.update()


    def save(self):
        fileName = self.parent.getSaveFileName(_("Select where to save your signed transaction"), 'signed_%s.txn' % (self.tx.hash()[0:8]), "*.txn")
        if fileName:
            with open(fileName, "w+") as f:
                f.write(json.dumps(self.tx.as_dict(),indent=4) + '\n')
            self.show_message(_("Transaction saved successfully"))


    def update(self):
        tx_hash = self.tx.hash()

        is_relevant, is_mine, v, fee = self.wallet.get_tx_value(self.tx)

        if self.tx.is_complete:
            status = "Status: Signed"
            self.sign_button.hide()

            if tx_hash in self.wallet.transactions.keys():
                conf, timestamp = self.wallet.verifier.get_confirmations(tx_hash)
                if timestamp:
                    time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
                else:
                    time_str = 'pending'
                status = "Status: %d confirmations"%conf
                self.broadcast_button.hide()
            else:
                time_str = None
                conf = 0
                self.broadcast_button.show()
        else:
            status = "Status: Unsigned"
            time_str = None
            self.sign_button.show()
            self.broadcast_button.hide()

        self.tx_hash_e.setText(tx_hash)
        self.status_label.setText(status)

        if time_str is not None:
            self.date_label.setText("Date: %s"%time_str)
            self.date_label.show()
        else:
            self.date_label.hide()

        if is_relevant:    
            if is_mine:
                if fee is not None: 
                    self.amount_label.setText("Amount sent: %s"% self.parent.format_amount(v-fee))
                    self.fee_label.setText("Transaction fee: %s"% self.parent.format_amount(fee))
                else:
                    self.amount_label.setText("Amount sent: %s"% self.parent.format_amount(v))
                    self.fee_label.setText("Transaction fee: unknown")
            else:
                self.amount_label.setText("Amount received: %s"% self.parent.format_amount(v))
        else:
            self.amount_label.setText("Transaction unrelated to your wallet")



    def io_widget(self, tx):
        tabs = QTabWidget(self)

        tab1 = QWidget()
        grid_ui = QGridLayout(tab1)
        grid_ui.setColumnStretch(0,1)
        tabs.addTab(tab1, _('Outputs') )

        tree_widget = QTreeWidget(self)
        tree_widget.setColumnCount(2)
        tree_widget.setHeaderLabels( [_('Address'), _('Amount')] )
        tree_widget.setColumnWidth(0, 300)
        tree_widget.setColumnWidth(1, 50)

        for address, value in tx.outputs:
            item = QTreeWidgetItem( [address, "%s" % ( self.parent.format_amount(value))] )
            tree_widget.addTopLevelItem(item)

        tree_widget.setMaximumHeight(100)

        grid_ui.addWidget(tree_widget)

        tab2 = QWidget()
        grid_ui = QGridLayout(tab2)
        grid_ui.setColumnStretch(0,1)
        tabs.addTab(tab2, _('Inputs') )
        
        tree_widget = QTreeWidget(self)
        tree_widget.setColumnCount(2)
        tree_widget.setHeaderLabels( [ _('Address'), _('Previous output')] )

        for input_line in tx.inputs:
            item = QTreeWidgetItem( [ str(input_line["address"]), str(input_line.get("prevout_hash"))] )
            tree_widget.addTopLevelItem(item)

        tree_widget.setMaximumHeight(100)

        grid_ui.addWidget(tree_widget)
        return tabs


    def broadcast(self):
        result, result_message = self.wallet.sendtx( self.tx )
        if result:
            self.show_message("Transaction successfully sent: %s" % (result_message))
            if dialog:
                dialog.done(0)
        else:
            self.show_message("There was a problem sending your transaction:\n %s" % (result_message))

    def show_message(self, msg):
        QMessageBox.information(self, _('Message'), msg, _('OK'))




