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
import json
import traceback

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

import qrcode
from qrcode import exceptions

from electrum_ltc.bitcoin import base_encode
from electrum_ltc.i18n import _
from electrum_ltc.plugin import run_hook
from electrum_ltc import simple_config

from electrum_ltc.util import bfh
from electrum_ltc.transaction import SerializationError

from .util import *


SAVE_BUTTON_ENABLED_TOOLTIP = _("Save transaction offline")
SAVE_BUTTON_DISABLED_TOOLTIP = _("Please sign this transaction in order to save it")


dialogs = []  # Otherwise python randomly garbage collects the dialogs...


def show_transaction(tx, parent, desc=None, prompt_if_unsaved=False):
    try:
        d = TxDialog(tx, parent, desc, prompt_if_unsaved)
    except SerializationError as e:
        traceback.print_exc(file=sys.stderr)
        parent.show_critical(_("Electrum was unable to deserialize the transaction:") + "\n" + str(e))
    else:
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
        self.tx = tx = copy.deepcopy(tx)
        try:
            self.tx.deserialize()
        except BaseException as e:
            raise SerializationError(e)
        self.main_window = parent
        self.wallet = parent.wallet
        self.prompt_if_unsaved = prompt_if_unsaved
        self.saved = False
        self.desc = desc

        # if the wallet can populate the inputs with more info, do it now.
        # as a result, e.g. we might learn an imported address tx is segwit,
        # in which case it's ok to display txid
        self.wallet.add_input_info_to_all_inputs(tx)

        self.setMinimumWidth(950)
        self.setWindowTitle(_("Transaction"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e  = ButtonsLineEdit()
        qr_show = lambda: parent.show_qrcode(str(self.tx_hash_e.text()), 'Transaction ID', parent=self)
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

        vbox.addStretch(1)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.do_broadcast)

        self.save_button = b = QPushButton(_("Save"))
        save_button_disabled = not tx.is_complete()
        b.setDisabled(save_button_disabled)
        if save_button_disabled:
            b.setToolTip(SAVE_BUTTON_DISABLED_TOOLTIP)
        else:
            b.setToolTip(SAVE_BUTTON_ENABLED_TOOLTIP)
        b.clicked.connect(self.save)

        self.export_button = b = QPushButton(_("Export"))
        b.clicked.connect(self.export)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.qr_button = b = QPushButton()
        b.setIcon(QIcon(":icons/qrcode.png"))
        b.clicked.connect(self.show_qr)

        self.copy_button = CopyButton(lambda: str(self.tx), parent.app)

        # Action buttons
        self.buttons = [self.sign_button, self.broadcast_button, self.cancel_button]
        # Transaction sharing buttons
        self.sharing_buttons = [self.copy_button, self.qr_button, self.export_button, self.save_button]

        run_hook('transaction_dialog', self)

        hbox = QHBoxLayout()
        hbox.addLayout(Buttons(*self.sharing_buttons))
        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        vbox.addLayout(hbox)
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
            try:
                dialogs.remove(self)
            except ValueError:
                pass  # was not in list already

    def show_qr(self):
        text = bfh(str(self.tx))
        text = base_encode(text, base=43)
        try:
            self.main_window.show_qrcode(text, 'Transaction', parent=self)
        except qrcode.exceptions.DataOverflowError:
            self.show_error(_('Failed to display QR code.') + '\n' +
                            _('Transaction is too large in size.'))
        except Exception as e:
            self.show_error(_('Failed to display QR code.') + '\n' + str(e))

    def sign(self):
        def sign_done(success):
            # note: with segwit we could save partially signed tx, because they have a txid
            if self.tx.is_complete():
                self.prompt_if_unsaved = True
                self.saved = False
                self.save_button.setDisabled(False)
                self.save_button.setToolTip(SAVE_BUTTON_ENABLED_TOOLTIP)
            self.update()
            self.main_window.pop_top_level_window(self)

        self.sign_button.setDisabled(True)
        self.main_window.push_top_level_window(self)
        self.main_window.sign_tx(self.tx, sign_done)

    def save(self):
        self.main_window.push_top_level_window(self)
        if self.main_window.save_transaction_into_wallet(self.tx):
            self.save_button.setDisabled(True)
            self.saved = True
        self.main_window.pop_top_level_window(self)


    def export(self):
        name = 'signed_%s.txn' % (self.tx.txid()[0:8]) if self.tx.is_complete() else 'unsigned.txn'
        fileName = self.main_window.getSaveFileName(_("Select where to save your signed transaction"), name, "*.txn")
        if fileName:
            with open(fileName, "w+") as f:
                f.write(json.dumps(self.tx.as_dict(), indent=4) + '\n')
            self.show_message(_("Transaction exported successfully"))
            self.saved = True

    def update(self):
        desc = self.desc
        base_unit = self.main_window.base_unit()
        format_amount = self.main_window.format_amount
        tx_hash, status, label, can_broadcast, can_rbf, amount, fee, height, conf, timestamp, exp_n = self.wallet.get_tx_info(self.tx)
        size = self.tx.estimated_size()
        self.broadcast_button.setEnabled(can_broadcast)
        can_sign = not self.tx.is_complete() and \
            (self.wallet.can_sign(self.tx) or bool(self.main_window.tx_external_keypairs))
        self.sign_button.setEnabled(can_sign)
        self.tx_hash_e.setText(tx_hash or _('Unknown'))
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
            text = '%.2f MB'%(exp_n/1000000)
            self.date_label.setText(_('Position in mempool: {} from tip').format(text))
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
        fee_str = _("Fee") + ': %s' % (format_amount(fee) + ' ' + base_unit if fee is not None else _('unknown'))
        if fee is not None:
            fee_rate = fee/size*1000
            fee_str += '  ( %s ) ' % self.main_window.format_fee_rate(fee_rate)
            confirm_rate = simple_config.FEERATE_WARNING_HIGH_FEE
            if fee_rate > confirm_rate:
                fee_str += ' - ' + _('Warning') + ': ' + _("high fee") + '!'
        self.amount_label.setText(amount_str)
        self.fee_label.setText(fee_str)
        self.size_label.setText(size_str)
        run_hook('transaction_dialog_update', self)

    def add_io(self, vbox):
        if self.tx.locktime > 0:
            vbox.addWidget(QLabel("LockTime: %d\n" % self.tx.locktime))

        vbox.addWidget(QLabel(_("Inputs") + ' (%d)'%len(self.tx.inputs())))
        ext = QTextCharFormat()
        rec = QTextCharFormat()
        rec.setBackground(QBrush(ColorScheme.GREEN.as_color(background=True)))
        rec.setToolTip(_("Wallet receive address"))
        chg = QTextCharFormat()
        chg.setBackground(QBrush(ColorScheme.YELLOW.as_color(background=True)))
        chg.setToolTip(_("Wallet change address"))
        twofactor = QTextCharFormat()
        twofactor.setBackground(QBrush(ColorScheme.BLUE.as_color(background=True)))
        twofactor.setToolTip(_("TrustedCoin (2FA) fee for the next batch of transactions"))

        def text_format(addr):
            if self.wallet.is_mine(addr):
                return chg if self.wallet.is_change(addr) else rec
            elif self.wallet.is_billing_address(addr):
                return twofactor
            return ext

        def format_amount(amt):
            return self.main_window.format_amount(amt, whitespaces=True)

        i_text = QTextEdit()
        i_text.setFont(QFont(MONOSPACE_FONT))
        i_text.setReadOnly(True)
        i_text.setMaximumHeight(100)
        cursor = i_text.textCursor()
        for x in self.tx.inputs():
            if x['type'] == 'coinbase':
                cursor.insertText('coinbase')
            else:
                prevout_hash = x.get('prevout_hash')
                prevout_n = x.get('prevout_n')
                cursor.insertText(prevout_hash + ":%-4d " % prevout_n, ext)
                addr = self.wallet.get_txin_address(x)
                if addr is None:
                    addr = ''
                cursor.insertText(addr, text_format(addr))
                if x.get('value'):
                    cursor.insertText(format_amount(x['value']), ext)
            cursor.insertBlock()

        vbox.addWidget(i_text)
        vbox.addWidget(QLabel(_("Outputs") + ' (%d)'%len(self.tx.outputs())))
        o_text = QTextEdit()
        o_text.setFont(QFont(MONOSPACE_FONT))
        o_text.setReadOnly(True)
        o_text.setMaximumHeight(100)
        cursor = o_text.textCursor()
        for addr, v in self.tx.get_outputs():
            cursor.insertText(addr, text_format(addr))
            if v is not None:
                cursor.insertText('\t', ext)
                cursor.insertText(format_amount(v), ext)
            cursor.insertBlock()
        vbox.addWidget(o_text)
