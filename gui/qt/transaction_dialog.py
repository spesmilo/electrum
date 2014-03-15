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
except Exception:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

from electrum import transaction
from util import MyTreeWidget

class TxDialog(QDialog):

    def __init__(self, tx, parent):
        self.tx = tx
        tx_dict = tx.as_dict()
        self.parent = parent
        self.wallet = parent.wallet
            
        QDialog.__init__(self)
        self.setMinimumWidth(600)
        self.setWindowTitle(_("Transaction"))
        self.setModal(1)

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
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

        self.add_io(vbox)

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
        cancelButton.setDefault(True)
        
        self.update()




    def sign(self):
        tx_dict = self.tx.as_dict()
        input_info = json.loads(tx_dict["input_info"])
        self.parent.sign_raw_transaction(self.tx, input_info)
        self.update()


    def save(self):
        name = 'signed_%s.txn' % (self.tx.hash()[0:8]) if self.tx.is_complete else 'unsigned.txn'
        fileName = self.parent.getSaveFileName(_("Select where to save your signed transaction"), name, "*.txn")
        if fileName:
            with open(fileName, "w+") as f:
                f.write(json.dumps(self.tx.as_dict(),indent=4) + '\n')
            self.show_message(_("Transaction saved successfully"))



    def update(self):

        is_relevant, is_mine, v, fee = self.wallet.get_tx_value(self.tx)

        if self.tx.is_complete:
            status = _("Status: Signed")
            self.sign_button.hide()
            tx_hash = self.tx.hash()

            if tx_hash in self.wallet.transactions.keys():
                conf, timestamp = self.wallet.verifier.get_confirmations(tx_hash)
                if timestamp:
                    time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
                else:
                    time_str = 'pending'
                status = _("Status: %d confirmations")%conf
                self.broadcast_button.hide()
            else:
                time_str = None
                conf = 0
                self.broadcast_button.show()
        else:
            status = _("Status: Unsigned")
            time_str = None
            if not self.wallet.is_watching_only():
                self.sign_button.show()
            else:
                self.sign_button.hide()
            self.broadcast_button.hide()
            tx_hash = 'unknown'

        self.tx_hash_e.setText(tx_hash)
        self.status_label.setText(status)

        if time_str is not None:
            self.date_label.setText(_("Date: %s")%time_str)
            self.date_label.show()
        else:
            self.date_label.hide()


        # if we are not synchronized, we cannot tell
        if self.parent.network is None or not self.parent.network.is_running() or not self.parent.network.is_connected():
            return
        if not self.wallet.up_to_date:
            return

        if is_relevant:    
            if is_mine:
                if fee is not None: 
                    self.amount_label.setText(_("Amount sent:")+' %s'% self.parent.format_amount(v-fee) + ' ' + self.parent.base_unit())
                    self.fee_label.setText(_("Transaction fee")+': %s'% self.parent.format_amount(fee) + ' ' + self.parent.base_unit())
                else:
                    self.amount_label.setText(_("Amount sent:")+' %s'% self.parent.format_amount(v) + ' ' + self.parent.base_unit())
                    self.fee_label.setText(_("Transaction fee")+': '+ _("unknown"))
            else:
                self.amount_label.setText(_("Amount received:")+' %s'% self.parent.format_amount(v) + ' ' + self.parent.base_unit())
        else:
            self.amount_label.setText(_("Transaction unrelated to your wallet"))


    def exec_menu(self, position,l):
        item = l.itemAt(position)
        if not item: return
        addr = unicode(item.text(0))
        menu = QMenu()
        menu.addAction(_("Copy to clipboard"), lambda: self.parent.app.clipboard().setText(addr))
        menu.exec_(l.viewport().mapToGlobal(position))


    def add_io(self, vbox):

        if self.tx.locktime > 0:
            vbox.addWidget(QLabel("LockTime: %d\n" % self.tx.locktime))

        vbox.addWidget(QLabel(_("Inputs")))
        lines = map(lambda x: x.get('prevout_hash') + ":%d"%x.get('prevout_n') + u'\t' + "%s"%x.get('address') , self.tx.inputs )
        i_text = QTextEdit()
        i_text.setText('\n'.join(lines))
        i_text.setReadOnly(True)
        i_text.setMaximumHeight(100)
        vbox.addWidget(i_text)

        vbox.addWidget(QLabel(_("Outputs")))
        lines = map(lambda x: x[0] + u'\t\t' + self.parent.format_amount(x[1]), self.tx.outputs)
        o_text = QTextEdit()
        o_text.setText('\n'.join(lines))
        o_text.setReadOnly(True)
        o_text.setMaximumHeight(100)
        vbox.addWidget(o_text)

        


    def broadcast(self):
        result, result_message = self.wallet.sendtx( self.tx )
        if result:
            self.show_message(_("Transaction successfully sent")+': %s' % (result_message))
        else:
            self.show_message(_("There was a problem sending your transaction:") + '\n %s' % (result_message))

    def show_message(self, msg):
        QMessageBox.information(self, _('Message'), msg, _('OK'))




