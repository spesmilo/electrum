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

import sys
import copy
import datetime
import traceback
import time
from typing import TYPE_CHECKING, Callable

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QTextCharFormat, QBrush, QFont, QPixmap
from PyQt5.QtWidgets import (QDialog, QLabel, QPushButton, QHBoxLayout, QVBoxLayout,
                             QTextEdit, QFrame, QAction, QToolButton, QMenu)
import qrcode
from qrcode import exceptions

from electrum.bitcoin import base_encode
from electrum.i18n import _
from electrum.plugin import run_hook
from electrum import simple_config
from electrum.util import bfh
from electrum.transaction import SerializationError, Transaction, PartialTransaction, PartialTxInput
from electrum.logging import get_logger

from .util import (MessageBoxMixin, read_QIcon, Buttons, CopyButton, icon_path,
                   MONOSPACE_FONT, ColorScheme, ButtonsLineEdit, text_dialog,
                   char_width_in_lineedit)

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


SAVE_BUTTON_ENABLED_TOOLTIP = _("Save transaction offline")
SAVE_BUTTON_DISABLED_TOOLTIP = _("Please sign this transaction in order to save it")


_logger = get_logger(__name__)
dialogs = []  # Otherwise python randomly garbage collects the dialogs...


def show_transaction(tx: Transaction, *, parent: 'ElectrumWindow', invoice=None, desc=None, prompt_if_unsaved=False):
    try:
        d = TxDialog(tx, parent=parent, invoice=invoice, desc=desc, prompt_if_unsaved=prompt_if_unsaved)
    except SerializationError as e:
        _logger.exception('unable to deserialize the transaction')
        parent.show_critical(_("Electrum was unable to deserialize the transaction:") + "\n" + str(e))
    else:
        dialogs.append(d)
        d.show()


class TxDialog(QDialog, MessageBoxMixin):

    def __init__(self, tx: Transaction, *, parent: 'ElectrumWindow', invoice, desc, prompt_if_unsaved):
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
        self.invoice = invoice

        # if the wallet can populate the inputs with more info, do it now.
        # as a result, e.g. we might learn an imported address tx is segwit,
        # or that a beyond-gap-limit address is is_mine
        tx.add_info_from_wallet(self.wallet)

        self.setMinimumWidth(950)
        self.setWindowTitle(_("Transaction"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e  = ButtonsLineEdit()
        qr_show = lambda: parent.show_qrcode(str(self.tx_hash_e.text()), 'Transaction ID', parent=self)
        qr_icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.tx_hash_e.addButton(qr_icon, qr_show, _("Show as QR code"))
        self.tx_hash_e.setReadOnly(True)
        vbox.addWidget(self.tx_hash_e)

        self.add_tx_stats(vbox)
        vbox.addSpacing(10)

        self.inputs_header = QLabel()
        vbox.addWidget(self.inputs_header)
        self.inputs_textedit = QTextEditWithDefaultSize()
        vbox.addWidget(self.inputs_textedit)
        self.outputs_header = QLabel()
        vbox.addWidget(self.outputs_header)
        self.outputs_textedit = QTextEditWithDefaultSize()
        vbox.addWidget(self.outputs_textedit)

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

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.export_actions_menu = export_actions_menu = QMenu()
        self.add_export_actions_to_menu(export_actions_menu)
        export_actions_menu.addSeparator()
        if isinstance(tx, PartialTransaction):
            export_for_coinjoin_submenu = export_actions_menu.addMenu(_("For CoinJoin; strip privates"))
            self.add_export_actions_to_menu(export_for_coinjoin_submenu, gettx=self._gettx_for_coinjoin)

        self.export_actions_button = QToolButton()
        self.export_actions_button.setText(_("Export"))
        self.export_actions_button.setMenu(export_actions_menu)
        self.export_actions_button.setPopupMode(QToolButton.InstantPopup)

        partial_tx_actions_menu = QMenu()
        ptx_merge_sigs_action = QAction(_("Merge signatures from"), self)
        ptx_merge_sigs_action.triggered.connect(self.merge_sigs)
        partial_tx_actions_menu.addAction(ptx_merge_sigs_action)
        ptx_join_txs_action = QAction(_("Join inputs/outputs"), self)
        ptx_join_txs_action.triggered.connect(self.join_tx_with_another)
        partial_tx_actions_menu.addAction(ptx_join_txs_action)
        self.partial_tx_actions_button = QToolButton()
        self.partial_tx_actions_button.setText(_("Combine"))
        self.partial_tx_actions_button.setMenu(partial_tx_actions_menu)
        self.partial_tx_actions_button.setPopupMode(QToolButton.InstantPopup)

        # Action buttons
        self.buttons = []
        if isinstance(tx, PartialTransaction):
            self.buttons.append(self.partial_tx_actions_button)
        self.buttons += [self.sign_button, self.broadcast_button, self.cancel_button]
        # Transaction sharing buttons
        self.sharing_buttons = [self.export_actions_button, self.save_button]

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
            self.main_window.broadcast_transaction(self.tx, invoice=self.invoice, tx_desc=self.desc)
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

    def reject(self):
        # Override escape-key to close normally (and invoke closeEvent)
        self.close()

    def add_export_actions_to_menu(self, menu: QMenu, *, gettx: Callable[[], Transaction] = None) -> None:
        if gettx is None:
            gettx = lambda: None

        action = QAction(_("Copy to clipboard"), self)
        action.triggered.connect(lambda: self.copy_to_clipboard(tx=gettx()))
        menu.addAction(action)

        qr_icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        action = QAction(read_QIcon(qr_icon), _("Show as QR code"), self)
        action.triggered.connect(lambda: self.show_qr(tx=gettx()))
        menu.addAction(action)

        action = QAction(_("Export to file"), self)
        action.triggered.connect(lambda: self.export_to_file(tx=gettx()))
        menu.addAction(action)

    def _gettx_for_coinjoin(self) -> PartialTransaction:
        if not isinstance(self.tx, PartialTransaction):
            raise Exception("Can only export partial transactions for coinjoins.")
        tx = copy.deepcopy(self.tx)
        tx.prepare_for_export_for_coinjoin()
        return tx

    def copy_to_clipboard(self, *, tx: Transaction = None):
        if tx is None:
            tx = self.tx
        self.main_window.app.clipboard().setText(str(tx))

    def show_qr(self, *, tx: Transaction = None):
        if tx is None:
            tx = self.tx
        tx = copy.deepcopy(tx)  # make copy as we mutate tx
        if isinstance(tx, PartialTransaction):
            # this makes QR codes a lot smaller (or just possible in the first place!)
            tx.convert_all_utxos_to_witness_utxos()
        text = tx.serialize_as_bytes()
        text = base_encode(text, base=43)
        try:
            self.main_window.show_qrcode(text, 'Transaction', parent=self)
        except qrcode.exceptions.DataOverflowError:
            self.show_error(_('Failed to display QR code.') + '\n' +
                            _('Transaction is too large in size.'))
        except Exception as e:
            self.show_error(_('Failed to display QR code.') + '\n' + repr(e))

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

    def export_to_file(self, *, tx: Transaction = None):
        if tx is None:
            tx = self.tx
        if isinstance(tx, PartialTransaction):
            tx.finalize_psbt()
        if tx.is_complete():
            name = 'signed_%s.txn' % (tx.txid()[0:8])
        else:
            name = self.wallet.basename() + time.strftime('-%Y%m%d-%H%M.psbt')
        fileName = self.main_window.getSaveFileName(_("Select where to save your signed transaction"), name, "*.txn;;*.psbt")
        if not fileName:
            return
        if tx.is_complete():  # network tx hex
            with open(fileName, "w+") as f:
                network_tx_hex = tx.serialize_to_network()
                f.write(network_tx_hex + '\n')
        else:  # if partial: PSBT bytes
            assert isinstance(tx, PartialTransaction)
            with open(fileName, "wb+") as f:
                f.write(tx.serialize_as_bytes())

        self.show_message(_("Transaction exported successfully"))
        self.saved = True

    def merge_sigs(self):
        if not isinstance(self.tx, PartialTransaction):
            return
        text = text_dialog(self, _('Input raw transaction'),
                           _("Transaction to merge signatures from") + ":",
                           _("Load transaction"))
        if not text:
            return
        tx = self.main_window.tx_from_text(text)
        if not tx:
            return
        try:
            self.tx.combine_with_other_psbt(tx)
        except Exception as e:
            self.show_error(_("Error combining partial transactions") + ":\n" + repr(e))
            return
        self.update()

    def join_tx_with_another(self):
        if not isinstance(self.tx, PartialTransaction):
            return
        text = text_dialog(self, _('Input raw transaction'),
                           _("Transaction to join with") + " (" + _("add inputs and outputs") + "):",
                           _("Load transaction"))
        if not text:
            return
        tx = self.main_window.tx_from_text(text)
        if not tx:
            return
        try:
            self.tx.join_with_other_psbt(tx)
        except Exception as e:
            self.show_error(_("Error joining partial transactions") + ":\n" + repr(e))
            return
        self.update()

    def update(self):
        self.update_io()
        desc = self.desc
        base_unit = self.main_window.base_unit()
        format_amount = self.main_window.format_amount
        tx_details = self.wallet.get_tx_info(self.tx)
        tx_mined_status = tx_details.tx_mined_status
        exp_n = tx_details.mempool_depth_bytes
        amount, fee = tx_details.amount, tx_details.fee
        size = self.tx.estimated_size()
        self.broadcast_button.setEnabled(tx_details.can_broadcast)
        can_sign = not self.tx.is_complete() and \
            (self.wallet.can_sign(self.tx) or bool(self.main_window.tx_external_keypairs))
        self.sign_button.setEnabled(can_sign)
        self.tx_hash_e.setText(tx_details.txid or _('Unknown'))
        if desc is None:
            self.tx_desc.hide()
        else:
            self.tx_desc.setText(_("Description") + ': ' + desc)
            self.tx_desc.show()
        self.status_label.setText(_('Status:') + ' ' + tx_details.status)

        if tx_mined_status.timestamp:
            time_str = datetime.datetime.fromtimestamp(tx_mined_status.timestamp).isoformat(' ')[:-3]
            self.date_label.setText(_("Date: {}").format(time_str))
            self.date_label.show()
        elif exp_n:
            text = '%.2f MB'%(exp_n/1000000)
            self.date_label.setText(_('Position in mempool: {} from tip').format(text))
            self.date_label.show()
        else:
            self.date_label.hide()
        self.locktime_label.setText(f"LockTime: {self.tx.locktime}")
        self.rbf_label.setText(f"RBF: {not self.tx.is_final()}")
        if tx_mined_status.header_hash:
            self.block_hash_label.setText(_("Included in block: {}")
                                          .format(tx_mined_status.header_hash))
            self.block_height_label.setText(_("At block height: {}")
                                            .format(tx_mined_status.height))
        else:
            self.block_hash_label.hide()
            self.block_height_label.hide()
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
            feerate_warning = simple_config.FEERATE_WARNING_HIGH_FEE
            if fee_rate > feerate_warning:
                fee_str += ' - ' + _('Warning') + ': ' + _("high fee") + '!'
        if isinstance(self.tx, PartialTransaction):
            risk_of_burning_coins = (can_sign and fee is not None
                                     and self.tx.is_there_risk_of_burning_coins_as_fees())
            self.fee_warning_icon.setVisible(risk_of_burning_coins)
        self.amount_label.setText(amount_str)
        self.fee_label.setText(fee_str)
        self.size_label.setText(size_str)
        run_hook('transaction_dialog_update', self)

    def update_io(self):
        self.inputs_header.setText(_("Inputs") + ' (%d)'%len(self.tx.inputs()))
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

        i_text = self.inputs_textedit
        i_text.clear()
        i_text.setFont(QFont(MONOSPACE_FONT))
        i_text.setReadOnly(True)
        cursor = i_text.textCursor()
        for txin in self.tx.inputs():
            if txin.is_coinbase():
                cursor.insertText('coinbase')
            else:
                prevout_hash = txin.prevout.txid.hex()
                prevout_n = txin.prevout.out_idx
                cursor.insertText(prevout_hash + ":%-4d " % prevout_n, ext)
                addr = self.wallet.get_txin_address(txin)
                if addr is None:
                    addr = ''
                cursor.insertText(addr, text_format(addr))
                if isinstance(txin, PartialTxInput) and txin.value_sats() is not None:
                    cursor.insertText(format_amount(txin.value_sats()), ext)
            cursor.insertBlock()

        self.outputs_header.setText(_("Outputs") + ' (%d)'%len(self.tx.outputs()))
        o_text = self.outputs_textedit
        o_text.clear()
        o_text.setFont(QFont(MONOSPACE_FONT))
        o_text.setReadOnly(True)
        cursor = o_text.textCursor()
        for o in self.tx.outputs():
            addr, v = o.get_ui_address_str(), o.value
            cursor.insertText(addr, text_format(addr))
            if v is not None:
                cursor.insertText('\t', ext)
                cursor.insertText(format_amount(v), ext)
            cursor.insertBlock()

    def add_tx_stats(self, vbox):
        hbox_stats = QHBoxLayout()

        # left column
        vbox_left = QVBoxLayout()
        self.tx_desc = TxDetailLabel(word_wrap=True)
        vbox_left.addWidget(self.tx_desc)
        self.status_label = TxDetailLabel()
        vbox_left.addWidget(self.status_label)
        self.date_label = TxDetailLabel()
        vbox_left.addWidget(self.date_label)
        self.amount_label = TxDetailLabel()
        vbox_left.addWidget(self.amount_label)

        fee_hbox = QHBoxLayout()
        self.fee_label = TxDetailLabel()
        fee_hbox.addWidget(self.fee_label)
        self.fee_warning_icon = QLabel()
        pixmap = QPixmap(icon_path("warning"))
        pixmap_size = round(2 * char_width_in_lineedit())
        pixmap = pixmap.scaled(pixmap_size, pixmap_size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.fee_warning_icon.setPixmap(pixmap)
        self.fee_warning_icon.setToolTip(_("Warning") + ": "
                                         + _("The fee could not be verified. Signing non-segwit inputs is risky:\n"
                                             "if this transaction was maliciously modified before you sign,\n"
                                             "you might end up paying a higher mining fee than displayed."))
        self.fee_warning_icon.setVisible(False)
        fee_hbox.addWidget(self.fee_warning_icon)
        fee_hbox.addStretch(1)
        vbox_left.addLayout(fee_hbox)

        vbox_left.addStretch(1)
        hbox_stats.addLayout(vbox_left, 50)

        # vertical line separator
        line_separator = QFrame()
        line_separator.setFrameShape(QFrame.VLine)
        line_separator.setFrameShadow(QFrame.Sunken)
        line_separator.setLineWidth(1)
        hbox_stats.addWidget(line_separator)

        # right column
        vbox_right = QVBoxLayout()
        self.size_label = TxDetailLabel()
        vbox_right.addWidget(self.size_label)
        self.rbf_label = TxDetailLabel()
        vbox_right.addWidget(self.rbf_label)
        self.locktime_label = TxDetailLabel()
        vbox_right.addWidget(self.locktime_label)
        self.block_hash_label = TxDetailLabel(word_wrap=True)
        vbox_right.addWidget(self.block_hash_label)
        self.block_height_label = TxDetailLabel()
        vbox_right.addWidget(self.block_height_label)
        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addLayout(hbox_stats)


class QTextEditWithDefaultSize(QTextEdit):
    def sizeHint(self):
        return QSize(0, 100)


class TxDetailLabel(QLabel):
    def __init__(self, *, word_wrap=None):
        super().__init__()
        self.setTextInteractionFlags(Qt.TextSelectableByMouse)
        if word_wrap is not None:
            self.setWordWrap(word_wrap)
