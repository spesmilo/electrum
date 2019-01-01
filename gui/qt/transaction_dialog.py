#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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

import copy
import datetime
from functools import partial
import json

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from electroncash.address import Address, PublicKey
from electroncash.bitcoin import base_encode
from electroncash.i18n import _
from electroncash.plugins import run_hook

from electroncash.util import bfh, Weak
from .util import *

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_transaction(tx, parent, desc=None, prompt_if_unsaved=False):
    d = TxDialog(tx, parent, desc, prompt_if_unsaved)
    dialogs.append(d)
    d.show()

class TxDialog(QDialog, MessageBoxMixin):

    def __init__(self, tx, parent, desc, prompt_if_unsaved):
        '''Transactions in the wallet will show their description.
        Pass desc to give a description for txs not yet in the wallet.
        '''
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)
        # Take a copy; it might get updated in the main window by
        # e.g. the FX plugin.  If this happens during or after a long
        # sign operation the signatures are lost.
        self.tx = copy.deepcopy(tx)
        self.tx.deserialize()
        self.main_window = parent
        self.wallet = parent.wallet
        self.prompt_if_unsaved = prompt_if_unsaved
        self.saved = False
        self.desc = desc
        self.cashaddr_signal_slots = []

        self.setMinimumWidth(750)
        self.setWindowTitle(_("Transaction"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e  = ButtonsLineEdit()
        weakSelfRef = Weak.ref(self)
        qr_show = lambda: weakSelfRef() and parent.show_qrcode(str(weakSelfRef().tx_hash_e.text()), 'Transaction ID', parent=weakSelfRef())
        self.tx_hash_e.addButton(":icons/qrcode.png", qr_show, _("Show as QR code"))
        self.tx_hash_e.setReadOnly(True)
        vbox.addWidget(self.tx_hash_e)
        self.tx_desc = QLabel()
        vbox.addWidget(self.tx_desc)
        self.status_label = QLabel()
        vbox.addWidget(self.status_label)
        self.date_label = QLabel()
        vbox.addWidget(self.date_label)
        self.amount_label = QLabel()
        vbox.addWidget(self.amount_label)
        self.size_label = QLabel()
        vbox.addWidget(self.size_label)
        self.fee_label = QLabel()
        vbox.addWidget(self.fee_label)

        self.add_io(vbox)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.do_broadcast)

        self.save_button = b = QPushButton(_("Save"))
        b.clicked.connect(self.save)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.qr_button = b = QPushButton()
        b.setIcon(QIcon(":icons/qrcode.png"))
        b.clicked.connect(self.show_qr)

        self.copy_button = CopyButton(lambda: str(weakSelfRef() and weakSelfRef().tx), parent.app)

        # Action buttons
        buttons = [self.sign_button, self.broadcast_button, self.cancel_button]
        # Transaction sharing buttons
        sharing_buttons = [self.copy_button, self.qr_button, self.save_button]

        run_hook('transaction_dialog', self)

        hbox = QHBoxLayout()
        hbox.addLayout(Buttons(*sharing_buttons))
        hbox.addStretch(1)
        hbox.addLayout(Buttons(*buttons))
        vbox.addLayout(hbox)
        self.update()

        # connect slots so we update in realtime as blocks come in, etc
        parent.history_updated_signal.connect(self.update_tx_if_in_wallet)
        parent.labels_updated_signal.connect(self.update_tx_if_in_wallet)
        parent.network_signal.connect(self.got_verified_tx)

    def got_verified_tx(self, event, args):
        if event == 'verified' and args[0] == self.tx.txid():
            self.update()

    def update_tx_if_in_wallet(self):
        if self.tx.txid() in self.wallet.transactions:
            self.update()

    def do_broadcast(self):
        self.main_window.push_top_level_window(self)
        try:
            self.main_window.broadcast_transaction(self.tx, self.desc)
        finally:
            self.main_window.pop_top_level_window(self)
        self.saved = True
        self.update()

    def closeEvent(self, event):
        if (self.prompt_if_unsaved and not self.saved
            and not self.question(_('This transaction is not saved. Close anyway?'), title=_("Warning"))):
            event.ignore()
        else:
            event.accept()
            parent = self.main_window
            if parent:
                # clean up connections so window gets gc'd
                try: parent.history_updated_signal.disconnect(self.update_tx_if_in_wallet)
                except TypeError: pass
                try: parent.network_signal.disconnect(self.got_verified_tx)
                except TypeError: pass
                try: parent.labels_updated_signal.disconnect(self.update_tx_if_in_wallet)
                except TypeError: pass
                for slot in self.cashaddr_signal_slots:
                    try: parent.cashaddr_toggled_signal.disconnect(slot)
                    except TypeError: pass
                self.cashaddr_signal_slots = []

            try:
                dialogs.remove(self)
            except ValueError:  # wasn't in list
                pass
            while True:
                try:
                    # Esoteric bug happens when user rejects password dialog on top of this window.. so we must keep popping self off the top_level_windows
                    self.main_window.pop_top_level_window(self)
                except ValueError:
                    break

    def reject(self):
        # Override escape-key to close normally (and invoke closeEvent)
        self.close()

    def show_qr(self):
        text = bfh(str(self.tx))
        text = base_encode(text, base=43)
        try:
            self.main_window.show_qrcode(text, 'Transaction', parent=self)
        except Exception as e:
            self.show_message(str(e))

    def sign(self):
        def sign_done(success):
            if success:
                self.prompt_if_unsaved = True
                self.saved = False
            self.update()
            self.main_window.pop_top_level_window(self)

        self.sign_button.setDisabled(True)
        self.main_window.push_top_level_window(self)
        self.main_window.sign_tx(self.tx, sign_done)

    def save(self):
        name = 'signed_%s.txn' % (self.tx.txid()[0:8]) if self.tx.is_complete() else 'unsigned.txn'
        fileName = self.main_window.getSaveFileName(_("Select where to save your signed transaction"), name, "*.txn")
        if fileName:
            tx_dict = self.tx.as_dict()
            with open(fileName, "w+") as f:
                f.write(json.dumps(tx_dict, indent=4) + '\n')
            self.show_message(_("Transaction saved successfully"))
            self.saved = True

    def update(self):
        desc = self.desc
        base_unit = self.main_window.base_unit()
        format_amount = self.main_window.format_amount
        tx_hash, status, label, can_broadcast, amount, fee, height, conf, timestamp, exp_n = self.wallet.get_tx_info(self.tx)
        desc = label or desc
        size = self.tx.estimated_size()
        self.broadcast_button.setEnabled(can_broadcast)
        can_sign = not self.tx.is_complete() and \
            (self.wallet.can_sign(self.tx) or bool(self.main_window.tx_external_keypairs))
        self.sign_button.setEnabled(can_sign)
        self.tx_hash_e.setText(tx_hash or _('Unknown'))
        if fee is None:
            try:
                fee = self.tx.get_fee() # Try and compute fee. We don't always have 'value' in all the inputs though. :/
            except KeyError: # Value key missing from an input
                pass
        if desc is None:
            self.tx_desc.hide()
        else:
            self.tx_desc.setText(_("Description") + ': ' + desc)
            self.tx_desc.show()
        self.status_label.setText(_('Status:') + ' ' + status)

        if timestamp:
            time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
            self.date_label.setText(_("Date: {}").format(time_str))
            self.date_label.show()
        elif exp_n:
            text = '%d blocks'%(exp_n) if exp_n > 0 else _('unknown (low fee)')
            self.date_label.setText(_('Expected confirmation time') + ': ' + text)
            self.date_label.show()
        else:
            self.date_label.hide()
        if amount is None:
            amount_str = _("Transaction unrelated to your wallet")
        elif amount > 0:
            amount_str = _("Amount received:") + ' %s'% format_amount(amount) + ' ' + base_unit
        else:
            amount_str = _("Amount sent:") + ' %s'% format_amount(-amount) + ' ' + base_unit
        size_str = _("Size:") + ' %d bytes'% size
        fee_str = _("Fee") + ': %s'% (format_amount(fee) + ' ' + base_unit if fee is not None else _('unknown'))
        dusty_fee = self.tx.ephemeral.get('dust_to_fee', 0)
        if fee is not None:
            fee_str += '  ( %s ) '%  self.main_window.format_fee_rate(fee/size*1000)
            if dusty_fee:
                fee_str += ' <font color=#999999>' + (_("( %s in dust was added to fee )") % format_amount(dusty_fee)) + '</font>'
        self.amount_label.setText(amount_str)
        self.fee_label.setText(fee_str)
        self.size_label.setText(size_str)
        run_hook('transaction_dialog_update', self)

    def add_io(self, vbox):
        if self.tx.locktime > 0:
            vbox.addWidget(QLabel("LockTime: %d\n" % self.tx.locktime))

        vbox.addWidget(QLabel(_("Inputs") + ' (%d)'%len(self.tx.inputs())))

        i_text = QTextEdit()
        i_text.setFont(QFont(MONOSPACE_FONT))
        i_text.setReadOnly(True)

        vbox.addWidget(i_text)
        vbox.addWidget(QLabel(_("Outputs") + ' (%d)'%len(self.tx.outputs())))
        o_text = QTextEdit()
        o_text.setFont(QFont(MONOSPACE_FONT))
        o_text.setReadOnly(True)
        vbox.addWidget(o_text)
        slot = partial(self.update_io, i_text, o_text)
        self.cashaddr_signal_slots.append(slot)
        self.main_window.cashaddr_toggled_signal.connect(slot)
        self.update_io(i_text, o_text)

    def update_io(self, i_text, o_text):
        ext = QTextCharFormat()
        rec = QTextCharFormat()
        rec.setBackground(QBrush(ColorScheme.GREEN.as_color(background=True)))
        rec.setToolTip(_("Wallet receive address"))
        chg = QTextCharFormat()
        chg.setBackground(QBrush(QColor("yellow")))
        chg.setToolTip(_("Wallet change address"))

        def text_format(addr):
            if isinstance(addr, Address) and self.wallet.is_mine(addr):
                return chg if self.wallet.is_change(addr) else rec
            return ext

        def format_amount(amt):
            return self.main_window.format_amount(amt, whitespaces = True)

        i_text.clear()
        cursor = i_text.textCursor()
        for x in self.tx.inputs():
            if x['type'] == 'coinbase':
                cursor.insertText('coinbase')
            else:
                prevout_hash = x.get('prevout_hash')
                prevout_n = x.get('prevout_n')
                cursor.insertText(prevout_hash[0:8] + '...', ext)
                cursor.insertText(prevout_hash[-8:] + ":%-4d " % prevout_n, ext)
                addr = x['address']
                if isinstance(addr, PublicKey):
                    addr = addr.toAddress()
                if addr is None:
                    addr_text = _('unknown')
                else:
                    addr_text = addr.to_ui_string()
                cursor.insertText(addr_text, text_format(addr))
                if x.get('value'):
                    cursor.insertText(format_amount(x['value']), ext)
            cursor.insertBlock()

        o_text.clear()
        cursor = o_text.textCursor()
        for addr, v in self.tx.get_outputs():
            addrstr = addr.to_ui_string()
            cursor.insertText(addrstr, text_format(addr))
            if v is not None:
                if len(addrstr) > 42: # for long outputs, make a linebreak.
                    cursor.insertBlock()
                    addrstr = '\u21b3'
                    cursor.insertText(addrstr, ext)
                # insert enough spaces until column 43, to line up amounts
                cursor.insertText(' '*(43 - len(addrstr)), ext)
                cursor.insertText(format_amount(v), ext)
            cursor.insertBlock()
