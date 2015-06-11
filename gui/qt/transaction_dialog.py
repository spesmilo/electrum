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

from util import *


class TxDialog(QWidget):

    def __init__(self, tx, parent):
        self.tx = tx
        tx_dict = tx.as_dict()
        self.parent = parent
        self.wallet = parent.wallet
        self.saved = True

        QWidget.__init__(self)
        self.setMinimumWidth(600)
        self.setWindowTitle(_("Transaction"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e  = ButtonsLineEdit()
        qr_show = lambda: self.parent.show_qrcode(str(self.tx_hash_e.text()), 'Transaction ID')
        self.tx_hash_e.addButton(":icons/qrcode.png", qr_show, _("Show as QR code"))
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

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.do_broadcast)
        b.hide()

        self.save_button = b = QPushButton(_("Save"))
        b.clicked.connect(self.save)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.qr_button = b = QPushButton()
        b.setIcon(QIcon(":icons/qrcode.png"))
        b.clicked.connect(self.show_qr)

        self.copy_button = CopyButton(lambda: str(self.tx), self.parent.app)

        self.buttons = [self.copy_button, self.qr_button, self.sign_button, self.broadcast_button, self.save_button, self.cancel_button]
        run_hook('transaction_dialog', self)

        vbox.addLayout(Buttons(*self.buttons))
        self.update()

    def do_broadcast(self):
        self.parent.broadcast_transaction(self.tx)
        self.saved = True

    def close(self):
        if not self.saved:
            if QMessageBox.question(
                    self, _('Message'), _('This transaction is not saved. Close anyway?'),
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.No:
                return
        QWidget.close(self)

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
            self.saved = True


    def update(self):
        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(self.tx)
        tx_hash = self.tx.hash()
        if self.wallet.can_sign(self.tx):
            self.sign_button.show()
        else:
            self.sign_button.hide()

        if self.tx.is_complete():
            status = _("Signed")

            if tx_hash in self.wallet.transactions.keys():
                conf, timestamp = self.wallet.get_confirmations(tx_hash)
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
        if self.parent.network is None:
            self.broadcast_button.hide()  # cannot broadcast when offline
            return
        if not self.wallet.up_to_date:
            return

        if is_relevant:
            if is_mine:
                if fee is not None:
                    self.amount_label.setText(_("Amount sent:")+' %s'% self.parent.format_amount(-v+fee) + ' ' + self.parent.base_unit())
                    self.fee_label.setText(_("Transaction fee")+': %s'% self.parent.format_amount(-fee) + ' ' + self.parent.base_unit())
                else:
                    self.amount_label.setText(_("Amount sent:")+' %s'% self.parent.format_amount(-v) + ' ' + self.parent.base_unit())
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

        ext = QTextCharFormat()
        own = QTextCharFormat()
        own.setBackground(QBrush(QColor("lightgreen")))
        own.setToolTip(_("Own address"))

        i_text = QTextEdit()
        i_text.setFont(QFont(MONOSPACE_FONT))
        i_text.setReadOnly(True)
        i_text.setMaximumHeight(100)
        cursor = i_text.textCursor()
        for x in self.tx.inputs:
            if x.get('is_coinbase'):
                cursor.insertText('coinbase')
            else:
                prevout_hash = x.get('prevout_hash')
                prevout_n = x.get('prevout_n')
                cursor.insertText(prevout_hash[0:8] + '...' + prevout_hash[-8:] + ":%d"%prevout_n, ext)
                cursor.insertText('\t')
                addr = x.get('address')
                if addr == "(pubkey)":
                    _addr = self.wallet.find_pay_to_pubkey_address(prevout_hash, prevout_n)
                    if _addr:
                        addr = _addr
                if addr is None:
                    addr = _('unknown')
                cursor.insertText(addr, own if self.wallet.is_mine(addr) else ext)
            cursor.insertBlock()

        vbox.addWidget(i_text)
        vbox.addWidget(QLabel(_("Outputs")))
        o_text = QTextEdit()
        o_text.setFont(QFont(MONOSPACE_FONT))
        o_text.setReadOnly(True)
        o_text.setMaximumHeight(100)
        cursor = o_text.textCursor()
        for addr, v in self.tx.get_outputs():
            cursor.insertText(addr, own if self.wallet.is_mine(addr) else ext)
            if v is not None:
                cursor.insertText('\t', ext)
                cursor.insertText(self.parent.format_amount(v), ext)
            cursor.insertBlock()
        vbox.addWidget(o_text)



    def show_message(self, msg):
        QMessageBox.information(self, _('Message'), msg, _('OK'))
