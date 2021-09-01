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
from typing import TYPE_CHECKING, Callable, Optional, List

import qrcode
from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (QDialog, QLabel, QPushButton, QHBoxLayout, QVBoxLayout, QWidget, QTextEdit, QFrame,
                             QAction, QMenu, QCheckBox)
from qrcode import exceptions

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.transaction import SerializationError, Transaction
from ..locktimeedit import LockTimeEdit
from ..util import (MessageBoxMixin, read_QIcon, Buttons, icon_path,
                    ColorScheme, ButtonsLineEdit, char_width_in_lineedit, BlockingWaitingDialog)

if TYPE_CHECKING:
    from ..main_window import ElectrumWindow


class TxSizeLabel(QLabel):
    def setAmount(self, byte_size):
        self.setText(('x   %s bytes   =' % byte_size) if byte_size else '')


class QTextEditWithDefaultSize(QTextEdit):
    def sizeHint(self):
        return QSize(0, 100)


_logger = get_logger(__name__)
dialogs = []  # Otherwise python randomly garbage collects the dialogs...


def show_transaction(tx: Transaction, *, parent: 'ElectrumWindow', desc=None, prompt_if_unsaved=False):
    try:
        d = TxDialog(tx, parent=parent, desc=desc, prompt_if_unsaved=prompt_if_unsaved)
    except SerializationError as e:
        _logger.exception('unable to deserialize the transaction')
        parent.show_critical(_("Electrum was unable to deserialize the transaction:") + "\n" + str(e))
    else:
        d.show()


class BaseTxDialog(QDialog, MessageBoxMixin):

    def __init__(self, *, parent: 'ElectrumWindow', desc, prompt_if_unsaved, finalized: bool, external_keypairs=None):
        """
        Transactions in the wallet will show their description.
        Pass desc to give a description for txs not yet in the wallet.
        """
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)
        self.tx = None  # type: Optional[Transaction]
        self.external_keypairs = external_keypairs
        self.finalized = finalized
        self.main_window = parent
        self.config = parent.config
        self.wallet = parent.wallet
        self.prompt_if_unsaved = prompt_if_unsaved
        self.saved = False
        self.desc = desc
        self.setMinimumWidth(950)
        self.set_title()

        self.psbt_only_widgets = []  # type: List[QWidget]

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e = ButtonsLineEdit()
        self.tx_hash_e.setFixedHeight(35)
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

        self.unstake_button = b = QPushButton(_("Unstake"))
        # b.clicked.connect(self.)

        self.restake_button = b = QPushButton(_("Restake"))
        # b.clicked.connect(self.)

        self.claim_reword_button = b = QPushButton(_("Claim Reword"))
        # b.clicked.connect(self.)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.buttons = [self.unstake_button, self.restake_button, self.claim_reword_button, self.cancel_button]

        self.hbox = hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        vbox.addLayout(hbox)
        self.set_buttons_visibility()

        dialogs.append(self)

    def set_buttons_visibility(self):
        for b in [self.export_actions_button, self.save_button, self.unstake_button, self.restake_button,
                  self.partial_tx_actions_button]:
            b.setVisible(self.finalized)
        for b in [self.finalize_button]:
            b.setVisible(not self.finalized)

    def set_tx(self, tx: 'Transaction'):
        # Take a copy; it might get updated in the main window by
        # e.g. the FX plugin.  If this happens during or after a long
        # sign operation the signatures are lost.
        self.tx = tx = copy.deepcopy(tx)
        try:
            self.tx.deserialize()
        except BaseException as e:
            raise SerializationError(e)
        # If the wallet can populate the inputs with more info, do it now.
        # As a result, e.g. we might learn an imported address tx is segwit,
        # or that a beyond-gap-limit address is is_mine.
        # note: this might fetch prev txs over the network.
        BlockingWaitingDialog(
            self,
            _("Adding info to tx, from wallet and network..."),
            lambda: tx.add_info_from_wallet(self.wallet),
        )

    def do_broadcast(self):
        self.main_window.push_top_level_window(self)
        self.main_window.save_pending_invoice()
        try:
            self.main_window.broadcast_transaction(self.tx)
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

    def show_qr(self, *, tx: Transaction = None):
        if tx is None:
            tx = self.tx
        qr_data = tx.to_qr_data()
        try:
            self.main_window.show_qrcode(qr_data, 'Transaction', parent=self)
        except qrcode.exceptions.DataOverflowError:
            self.show_error(_('Failed to display QR code.') + '\n' +
                            _('Transaction is too large in size.'))
        except Exception as e:
            self.show_error(_('Failed to display QR code.') + '\n' + repr(e))

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
        # todo uncomment when turn on lightning
        #        self.ln_amount_label = TxDetailLabel()
        #        vbox_left.addWidget(self.ln_amount_label)

        fee_hbox = QHBoxLayout()
        self.fee_label = TxDetailLabel()
        fee_hbox.addWidget(self.fee_label)
        self.fee_warning_icon = QLabel()
        pixmap = QPixmap(icon_path("warning"))
        pixmap_size = round(2 * char_width_in_lineedit())
        pixmap = pixmap.scaled(pixmap_size, pixmap_size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.fee_warning_icon.setPixmap(pixmap)
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
        self.rbf_cb = QCheckBox(_('Replace by fee'))
        self.rbf_cb.setChecked(bool(self.config.get('use_rbf', True)))
        vbox_right.addWidget(self.rbf_cb)

        self.locktime_final_label = TxDetailLabel()
        vbox_right.addWidget(self.locktime_final_label)

        locktime_setter_hbox = QHBoxLayout()
        locktime_setter_hbox.setContentsMargins(0, 0, 0, 0)
        locktime_setter_hbox.setSpacing(0)
        locktime_setter_label = TxDetailLabel()
        locktime_setter_label.setText("LockTime: ")
        self.locktime_e = LockTimeEdit(self)
        locktime_setter_hbox.addWidget(locktime_setter_label)
        locktime_setter_hbox.addWidget(self.locktime_e)
        locktime_setter_hbox.addStretch(1)
        self.locktime_setter_widget = QWidget()
        self.locktime_setter_widget.setLayout(locktime_setter_hbox)
        vbox_right.addWidget(self.locktime_setter_widget)

        self.block_height_label = TxDetailLabel()
        vbox_right.addWidget(self.block_height_label)
        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addLayout(hbox_stats)

        # below columns
        self.block_hash_label = TxDetailLabel(word_wrap=True)
        vbox.addWidget(self.block_hash_label)

        # set visibility after parenting can be determined by Qt
        self.rbf_label.setVisible(self.finalized)
        self.rbf_cb.setVisible(not self.finalized)
        self.locktime_final_label.setVisible(self.finalized)
        self.locktime_setter_widget.setVisible(not self.finalized)

    def set_title(self):
        self.setWindowTitle(_("Create transaction") if not self.finalized else _("Transaction"))

    def can_finalize(self) -> bool:
        return False

    def on_finalize(self):
        pass  # overridden in subclass

    def update_fee_fields(self):
        pass  # overridden in subclass


class TxDetailLabel(QLabel):
    def __init__(self, *, word_wrap=None):
        super().__init__()
        self.setTextInteractionFlags(Qt.TextSelectableByMouse)
        if word_wrap is not None:
            self.setWordWrap(word_wrap)


class TxDialog(BaseTxDialog):
    def __init__(self, tx: Transaction, *, parent: 'ElectrumWindow', desc, prompt_if_unsaved):
        BaseTxDialog.__init__(self, parent=parent, desc=desc, prompt_if_unsaved=prompt_if_unsaved, finalized=True)
        self.set_tx(tx)
        self.update()
