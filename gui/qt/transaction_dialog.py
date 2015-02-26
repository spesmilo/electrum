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
from electrum.bitcoin import base_encode
from electrum.plugins import run_hook

from util import MyTreeWidget
from util import MONOSPACE_FONT

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

        self.buttons = buttons = QHBoxLayout()
        vbox.addLayout( buttons )

        buttons.addStretch(1)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)
        buttons.addWidget(b)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(lambda: self.parent.broadcast_transaction(self.tx))

        b.hide()
        buttons.addWidget(b)

        self.save_button = b = QPushButton(_("Save"))
        b.clicked.connect(self.save)
        buttons.addWidget(b)

        cancelButton = QPushButton(_("Close"))
        cancelButton.clicked.connect(lambda: self.done(0))
        buttons.addWidget(cancelButton)
        cancelButton.setDefault(True)

        b = QPushButton()
        b.setIcon(QIcon(":icons/qrcode.png"))
        b.clicked.connect(self.show_qr)
        buttons.insertWidget(1,b)

        run_hook('transaction_dialog', self)

        self.update()


    def show_qr(self):
        text = self.tx.raw.decode('hex')
        text = base_encode(text, base=43)
        try:
            self.parent.show_qrcode(text, 'Transaction')
        except Exception as e:
            self.show_message(str(e))


    def sign(self):
        self.parent.sign_raw_transaction(self.tx)
        self.update()


    def save(self):
        name = 'signed_%s.txn' % (self.tx.hash()[0:8]) if self.tx.is_complete() else 'unsigned.txn'
        fileName = self.parent.getSaveFileName(_("Select where to save your signed transaction"), name, "*.txn")
        if fileName:
            with open(fileName, "w+") as f:
                f.write(json.dumps(self.tx.as_dict(),indent=4) + '\n')
            self.show_message(_("Transaction saved successfully"))



    def update(self):

        is_relevant, is_mine, v, fee = self.wallet.get_tx_value(self.tx)
        if self.wallet.can_sign(self.tx):
            self.sign_button.show()
        else:
            self.sign_button.hide()

        if self.tx.is_complete():
            status = _("Signed")
            tx_hash = self.tx.hash()

            if tx_hash in self.wallet.transactions.keys():
                conf, timestamp = self.wallet.verifier.get_confirmations(tx_hash)
                if timestamp:
                    time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
                else:
                    time_str = 'pending'
                status = _("%d confirmations")%conf
                self.broadcast_button.hide()
            else:
                time_str = None
                conf = 0
                self.broadcast_button.show()
        else:
            s, r = self.tx.signature_count()
            status = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)
            time_str = None
            self.broadcast_button.hide()
            tx_hash = 'unknown'

        self.tx_hash_e.setText(tx_hash)
        self.status_label.setText(_('Status:') + ' ' + status)

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

        run_hook('transaction_dialog_update', self)



    def add_io(self, vbox):

        if self.tx.locktime > 0:
            vbox.addWidget(QLabel("LockTime: %d\n" % self.tx.locktime))

        vbox.addWidget(QLabel(_("Inputs")))
        def format_input(x):
            if x.get('is_coinbase'):
                return 'coinbase'
            else:
                _hash = x.get('prevout_hash')
                return _hash[0:8] + '...' + _hash[-8:] + ":%d"%x.get('prevout_n') + u'\t' + "%s"%x.get('address')
        lines = map(format_input, self.tx.inputs )
        i_text = QTextEdit()
        i_text.setFont(QFont(MONOSPACE_FONT))
        i_text.setText('\n'.join(lines))
        i_text.setReadOnly(True)
        i_text.setMaximumHeight(100)
        vbox.addWidget(i_text)

        vbox.addWidget(QLabel(_("Outputs")))
        lines = map(lambda x: x[0] + u'\t\t' + self.parent.format_amount(x[1]) if x[1] else x[0], self.tx.get_outputs())
        o_text = QTextEdit()
        o_text.setFont(QFont(MONOSPACE_FONT))
        o_text.setText('\n'.join(lines))
        o_text.setReadOnly(True)
        o_text.setMaximumHeight(100)
        vbox.addWidget(o_text)



    def show_message(self, msg):
        QMessageBox.information(self, _('Message'), msg, _('OK'))
