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

import asyncio
import sys
import concurrent.futures
import copy
import datetime
import traceback
import time
from typing import TYPE_CHECKING, Callable, Optional, List, Union, Tuple, Mapping
from functools import partial
from decimal import Decimal

from PyQt6.QtCore import QSize, Qt, QUrl, QPoint, pyqtSignal
from PyQt6.QtGui import QTextCharFormat, QBrush, QFont, QPixmap, QTextCursor, QAction
from PyQt6.QtWidgets import (QDialog, QLabel, QPushButton, QHBoxLayout, QVBoxLayout, QWidget, QGridLayout,
                             QTextEdit, QFrame, QToolButton, QMenu, QCheckBox, QTextBrowser, QToolTip,
                             QApplication, QSizePolicy)
import qrcode
from qrcode import exceptions

from electrum.simple_config import SimpleConfig
from electrum.util import quantize_feerate
from electrum import bitcoin

from electrum.bitcoin import base_encode, NLOCKTIME_BLOCKHEIGHT_MAX, DummyAddress
from electrum.i18n import _
from electrum.plugin import run_hook
from electrum import simple_config
from electrum.transaction import SerializationError, Transaction, PartialTransaction, TxOutpoint, TxinDataFetchProgress
from electrum.logging import get_logger
from electrum.util import ShortID, get_asyncio_loop, UI_UNIT_NAME_TXSIZE_VBYTES
from electrum.network import Network
from electrum.wallet import TxSighashRiskLevel, TxSighashDanger

from . import util
from .util import (MessageBoxMixin, read_QIcon, Buttons, icon_path,
                   MONOSPACE_FONT, ColorScheme, ButtonsLineEdit, ShowQRLineEdit, text_dialog,
                   char_width_in_lineedit, TRANSACTION_FILE_EXTENSION_FILTER_SEPARATE,
                   TRANSACTION_FILE_EXTENSION_FILTER_ONLY_COMPLETE_TX,
                   TRANSACTION_FILE_EXTENSION_FILTER_ONLY_PARTIAL_TX,
                   BlockingWaitingDialog, getSaveFileName, ColorSchemeItem,
                   get_iconname_qrcode, VLine, WaitingDialog)
from .rate_limiter import rate_limited
from .my_treeview import create_toolbar_with_menu, QMenuWithConfig

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet
    from electrum.payment_identifier import PaymentIdentifier


_logger = get_logger(__name__)
dialogs = []  # Otherwise python randomly garbage collects the dialogs...


class TxSizeLabel(QLabel):
    def setAmount(self, byte_size):
        text = ""
        if byte_size:
            text = f"x   {byte_size} {UI_UNIT_NAME_TXSIZE_VBYTES}   ="
        self.setText(text)


class TxFiatLabel(QLabel):
    def setAmount(self, fiat_fee):
        self.setText(('≈  %s' % fiat_fee) if fiat_fee else '')


class QTextBrowserWithDefaultSize(QTextBrowser):
    def __init__(self, width: int = 0, height: int = 0):
        self._width = width
        self._height = height
        QTextBrowser.__init__(self)
        self.setLineWrapMode(QTextBrowser.LineWrapMode.NoWrap)

    def sizeHint(self):
        return QSize(self._width, self._height)


class TxInOutWidget(QWidget):
    def __init__(self, main_window: 'ElectrumWindow', wallet: 'Abstract_Wallet'):
        QWidget.__init__(self)

        self.wallet = wallet
        self.main_window = main_window
        self.tx = None  # type: Optional[Transaction]
        self.inputs_header = QLabel()
        self.inputs_textedit = QTextBrowserWithDefaultSize(750, 100)
        self.inputs_textedit.setOpenLinks(False)  # disable automatic link opening
        self.inputs_textedit.anchorClicked.connect(self._open_internal_link)  # send links to our handler
        self.inputs_textedit.setTextInteractionFlags(
            self.inputs_textedit.textInteractionFlags() | Qt.TextInteractionFlag.LinksAccessibleByMouse | Qt.TextInteractionFlag.LinksAccessibleByKeyboard)
        self.inputs_textedit.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.inputs_textedit.customContextMenuRequested.connect(self.on_context_menu_for_inputs)

        self.sighash_label = QLabel()
        self.sighash_label.setStyleSheet('font-weight: bold')
        self.sighash_danger = TxSighashDanger()
        self.inputs_warning_icon = QLabel()
        pixmap = QPixmap(icon_path("warning"))
        pixmap_size = round(2 * char_width_in_lineedit())
        pixmap = pixmap.scaled(pixmap_size, pixmap_size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        self.inputs_warning_icon.setPixmap(pixmap)
        self.inputs_warning_icon.setVisible(False)

        self.inheader_hbox = QHBoxLayout()
        self.inheader_hbox.setContentsMargins(0, 0, 0, 0)
        self.inheader_hbox.addWidget(self.inputs_header)
        self.inheader_hbox.addStretch(2)
        self.inheader_hbox.addWidget(self.sighash_label)
        self.inheader_hbox.addWidget(self.inputs_warning_icon)

        self.txo_color_recv = TxOutputColoring(
            legend=_("Wallet Address"), color=ColorScheme.GREEN, tooltip=_("Wallet receiving address"))
        self.txo_color_change = TxOutputColoring(
            legend=_("Change Address"), color=ColorScheme.YELLOW, tooltip=_("Wallet change address"))
        self.txo_color_2fa = TxOutputColoring(
            legend=_("TrustedCoin (2FA) batch fee"), color=ColorScheme.BLUE, tooltip=_("TrustedCoin (2FA) fee for the next batch of transactions"))
        self.txo_color_swap = TxOutputColoring(
            legend=_("Submarine swap address"), color=ColorScheme.BLUE, tooltip=_("Submarine swap address"))
        self.outputs_header = QLabel()
        self.outputs_textedit = QTextBrowserWithDefaultSize(750, 100)
        self.outputs_textedit.setOpenLinks(False)  # disable automatic link opening
        self.outputs_textedit.anchorClicked.connect(self._open_internal_link)  # send links to our handler
        self.outputs_textedit.setTextInteractionFlags(
            self.outputs_textedit.textInteractionFlags() | Qt.TextInteractionFlag.LinksAccessibleByMouse | Qt.TextInteractionFlag.LinksAccessibleByKeyboard)
        self.outputs_textedit.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.outputs_textedit.customContextMenuRequested.connect(self.on_context_menu_for_outputs)

        outheader_hbox = QHBoxLayout()
        outheader_hbox.setContentsMargins(0, 0, 0, 0)
        outheader_hbox.addWidget(self.outputs_header)
        outheader_hbox.addStretch(2)
        outheader_hbox.addWidget(self.txo_color_recv.legend_label)
        outheader_hbox.addWidget(self.txo_color_change.legend_label)
        outheader_hbox.addWidget(self.txo_color_2fa.legend_label)
        outheader_hbox.addWidget(self.txo_color_swap.legend_label)

        vbox = QVBoxLayout()
        vbox.addLayout(self.inheader_hbox)
        vbox.addWidget(self.inputs_textedit)
        vbox.addLayout(outheader_hbox)
        vbox.addWidget(self.outputs_textedit)
        self.setLayout(vbox)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def update(self, tx: Optional[Transaction]):
        self.tx = tx
        if tx is None:
            self.inputs_header.setText('')
            self.inputs_textedit.setText('')
            self.outputs_header.setText('')
            self.outputs_textedit.setText('')
            return

        inputs_header_text = _("Inputs") + ' (%d)'%len(self.tx.inputs())
        self.inputs_header.setText(inputs_header_text)
        ext = QTextCharFormat()  # "external"
        lnk = QTextCharFormat()
        lnk.setToolTip(_('Click to open, right-click for menu'))
        lnk.setAnchor(True)
        lnk.setUnderlineStyle(QTextCharFormat.UnderlineStyle.SingleUnderline)
        tf_used_recv, tf_used_change, tf_used_2fa, tf_used_swap = False, False, False, False
        def addr_text_format(addr: str) -> QTextCharFormat:
            nonlocal tf_used_recv, tf_used_change, tf_used_2fa, tf_used_swap
            sm = self.wallet.lnworker.swap_manager if self.wallet.lnworker else None
            if self.wallet.is_mine(addr):
                if self.wallet.is_change(addr):
                    tf_used_change = True
                    fmt = QTextCharFormat(self.txo_color_change.text_char_format)
                else:
                    tf_used_recv = True
                    fmt = QTextCharFormat(self.txo_color_recv.text_char_format)
                fmt.setAnchorHref(addr)
                fmt.setToolTip(_('Click to open, right-click for menu'))
                fmt.setAnchor(True)
                fmt.setUnderlineStyle(QTextCharFormat.UnderlineStyle.SingleUnderline)
                return fmt
            elif sm and sm.is_lockup_address_for_a_swap(addr) or addr == DummyAddress.SWAP:
                tf_used_swap = True
                return self.txo_color_swap.text_char_format
            elif self.wallet.is_billing_address(addr):
                tf_used_2fa = True
                return self.txo_color_2fa.text_char_format
            return ext

        def insert_tx_io(
            *,
            cursor: QTextCursor,
            txio_idx: int,
            is_coinbase: bool,
            tcf_shortid: QTextCharFormat = None,
            short_id: str,
            addr: Optional[str],
            value: Optional[int],
        ):
            tcf_ext = QTextCharFormat(ext)
            tcf_addr = addr_text_format(addr)
            if tcf_shortid is None:
                tcf_shortid = tcf_ext
            a_name = f"txio_idx {txio_idx}"
            for tcf in (tcf_ext, tcf_shortid, tcf_addr):  # used by context menu creation
                tcf.setAnchorNames([a_name])
            if is_coinbase:
                cursor.insertText('coinbase', tcf_ext)
            else:
                # short_id
                cursor.insertText(short_id, tcf_shortid)
                cursor.insertText(" " * max(0, 15 - len(short_id)), tcf_ext)  # padding
                cursor.insertText('\t', tcf_ext)
                # addr
                if addr is None:
                    address_str = '<address unknown>'
                elif len(addr) <= 42:
                    address_str = addr
                else:
                    address_str = addr[0:30] + '…' + addr[-11:]
                cursor.insertText(address_str, tcf_addr)
                cursor.insertText(" " * max(0, 42 - len(address_str)), tcf_ext)  # padding
                cursor.insertText('\t', tcf_ext)
                # value
                value_str = self.main_window.format_amount(value, whitespaces=True)
                cursor.insertText(value_str, tcf_ext)
            cursor.insertBlock()

        i_text = self.inputs_textedit
        i_text.clear()
        i_text.setFont(QFont(MONOSPACE_FONT))
        i_text.setReadOnly(True)
        cursor = i_text.textCursor()
        for txin_idx, txin in enumerate(self.tx.inputs()):
            addr = self.wallet.adb.get_txin_address(txin)
            txin_value = self.wallet.adb.get_txin_value(txin)
            tcf_shortid = QTextCharFormat(lnk)
            tcf_shortid.setAnchorHref(txin.prevout.txid.hex())
            insert_tx_io(
                cursor=cursor, is_coinbase=txin.is_coinbase_input(), txio_idx=txin_idx,
                tcf_shortid=tcf_shortid,
                short_id=str(txin.short_id), addr=addr, value=txin_value,
            )

        if isinstance(self.tx, PartialTransaction):
            self.sighash_danger = self.wallet.check_sighash(self.tx)
            if self.sighash_danger.risk_level >= TxSighashRiskLevel.WEIRD_SIGHASH:
                self.sighash_label.setText(self.sighash_danger.short_message)
                self.inputs_warning_icon.setVisible(True)
                self.inputs_warning_icon.setToolTip(self.sighash_danger.get_long_message())

        self.outputs_header.setText(_("Outputs") + ' (%d)'%len(self.tx.outputs()))
        o_text = self.outputs_textedit
        o_text.clear()
        o_text.setFont(QFont(MONOSPACE_FONT))
        o_text.setReadOnly(True)
        tx_height, tx_pos = None, None
        tx_hash = self.tx.txid()
        if tx_hash:
            tx_mined_info = self.wallet.adb.get_tx_height(tx_hash)
            tx_height = tx_mined_info.height
            tx_pos = tx_mined_info.txpos
        cursor = o_text.textCursor()
        for txout_idx, o in enumerate(self.tx.outputs()):
            if tx_height is not None and tx_pos is not None and tx_pos >= 0:
                short_id = ShortID.from_components(tx_height, tx_pos, txout_idx)
            elif tx_hash:
                short_id = TxOutpoint(bytes.fromhex(tx_hash), txout_idx).short_name()
            else:
                short_id = f"unknown:{txout_idx}"
            addr = o.get_ui_address_str()
            insert_tx_io(
                cursor=cursor, is_coinbase=False, txio_idx=txout_idx,
                short_id=str(short_id), addr=addr, value=o.value,
            )

        self.txo_color_recv.legend_label.setVisible(tf_used_recv)
        self.txo_color_change.legend_label.setVisible(tf_used_change)
        self.txo_color_2fa.legend_label.setVisible(tf_used_2fa)
        self.txo_color_swap.legend_label.setVisible(tf_used_swap)

    def _open_internal_link(self, target):
        """Accepts either a str txid, str address, or a QUrl which should be
        of the bare form "txid" and/or "address" -- used by the clickable
        links in the inputs/outputs QTextBrowsers"""
        if isinstance(target, QUrl):
            target = target.toString(QUrl.UrlFormattingOption.None_)
        assert target
        if bitcoin.is_address(target):
            # target was an address, open address dialog
            self.main_window.show_address(target, parent=self)
        else:
            # target was a txid, open new tx dialog
            self.main_window.do_process_from_txid(txid=target, parent=self)

    def on_context_menu_for_inputs(self, pos: QPoint):
        i_text = self.inputs_textedit
        global_pos = i_text.viewport().mapToGlobal(pos)

        cursor = i_text.cursorForPosition(pos)
        charFormat = cursor.charFormat()
        name = charFormat.anchorNames() and charFormat.anchorNames()[0]
        if not name:
            menu = i_text.createStandardContextMenu()
            menu.exec(global_pos)
            return

        menu = QMenu()
        show_list = []
        copy_list = []
        # figure out which input they right-clicked on. input lines have an anchor named "txio_idx N"
        txin_idx = int(name.split()[1])  # split "txio_idx N", translate N -> int
        txin = self.tx.inputs()[txin_idx]

        menu.addAction(f"Tx Input #{txin_idx}").setDisabled(True)
        menu.addSeparator()
        if txin.is_coinbase_input():
            menu.addAction(_("Coinbase Input")).setDisabled(True)
        else:
            show_list += [(_("Show Prev Tx"), lambda: self._open_internal_link(txin.prevout.txid.hex()))]
            copy_list += [(_("Copy") + " " + _("Outpoint"), lambda: self.main_window.do_copy(txin.prevout.to_str()))]
            addr = self.wallet.adb.get_txin_address(txin)
            if addr:
                if self.wallet.is_mine(addr):
                    show_list += [(_("Address Details"), lambda: self.main_window.show_address(addr, parent=self))]
                copy_list += [(_("Copy Address"), lambda: self.main_window.do_copy(addr))]
            txin_value = self.wallet.adb.get_txin_value(txin)
            if txin_value:
                value_str = self.main_window.format_amount(txin_value, add_thousands_sep=False)
                copy_list += [(_("Copy Amount"), lambda: self.main_window.do_copy(value_str))]

        for item in show_list:
            menu.addAction(*item)
        if show_list and copy_list:
            menu.addSeparator()
        for item in copy_list:
            menu.addAction(*item)

        menu.addSeparator()
        std_menu = i_text.createStandardContextMenu()
        menu.addActions(std_menu.actions())
        menu.exec(global_pos)

    def on_context_menu_for_outputs(self, pos: QPoint):
        o_text = self.outputs_textedit
        global_pos = o_text.viewport().mapToGlobal(pos)

        cursor = o_text.cursorForPosition(pos)
        charFormat = cursor.charFormat()
        name = charFormat.anchorNames() and charFormat.anchorNames()[0]
        if not name:
            menu = o_text.createStandardContextMenu()
            menu.exec(global_pos)
            return

        menu = QMenu()
        show_list = []
        copy_list = []
        # figure out which output they right-clicked on. output lines have an anchor named "txio_idx N"
        txout_idx = int(name.split()[1])  # split "txio_idx N", translate N -> int
        menu.addAction(f"Tx Output #{txout_idx}").setDisabled(True)
        menu.addSeparator()
        if tx_hash := self.tx.txid():
            outpoint = TxOutpoint(bytes.fromhex(tx_hash), txout_idx)
            copy_list += [(_("Copy") + " " + _("Outpoint"), lambda: self.main_window.do_copy(outpoint.to_str()))]
        if addr := self.tx.outputs()[txout_idx].address:
            if self.wallet.is_mine(addr):
                show_list += [(_("Address Details"), lambda: self.main_window.show_address(addr, parent=self))]
            copy_list += [(_("Copy Address"), lambda: self.main_window.do_copy(addr))]
        else:
            spk = self.tx.outputs()[txout_idx].scriptpubkey
            copy_list += [(_("Copy scriptPubKey"), lambda: self.main_window.do_copy(spk.hex()))]
        txout_value = self.tx.outputs()[txout_idx].value
        value_str = self.main_window.format_amount(txout_value, add_thousands_sep=False)
        copy_list += [(_("Copy Amount"), lambda: self.main_window.do_copy(value_str))]

        for item in show_list:
            menu.addAction(*item)
        if show_list and copy_list:
            menu.addSeparator()
        for item in copy_list:
            menu.addAction(*item)

        menu.addSeparator()
        std_menu = o_text.createStandardContextMenu()
        menu.addActions(std_menu.actions())
        menu.exec(global_pos)


def show_transaction(
    tx: Transaction,
    *,
    parent: 'ElectrumWindow',
    prompt_if_unsaved: bool = False,
    external_keypairs: Mapping[bytes, bytes] = None,
    payment_identifier: 'PaymentIdentifier' = None,
):
    try:
        d = TxDialog(
            tx,
            parent=parent,
            prompt_if_unsaved=prompt_if_unsaved,
            external_keypairs=external_keypairs,
            payment_identifier=payment_identifier,
        )
    except SerializationError as e:
        _logger.exception('unable to deserialize the transaction')
        parent.show_critical(_("Electrum was unable to deserialize the transaction:") + "\n" + str(e))
    else:
        d.show()


class TxDialog(QDialog, MessageBoxMixin):

    throttled_update_sig = pyqtSignal()  # emit from thread to do update in main thread

    def __init__(
        self,
        tx: Transaction,
        *,
        parent: 'ElectrumWindow',
        prompt_if_unsaved: bool,
        external_keypairs: Mapping[bytes, bytes] = None,
        payment_identifier: 'PaymentIdentifier' = None,
    ):
        '''Transactions in the wallet will show their description.
        Pass desc to give a description for txs not yet in the wallet.
        '''
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)
        self.tx = None  # type: Optional[Transaction]
        self.external_keypairs = external_keypairs
        self.main_window = parent
        self.config = parent.config
        self.wallet = parent.wallet
        self.payment_identifier = payment_identifier
        self.prompt_if_unsaved = prompt_if_unsaved
        self.saved = False
        self.desc = None
        if txid := tx.txid():
            self.desc = self.wallet.get_label_for_txid(txid) or None
        self.setMinimumWidth(640)

        self.psbt_only_widgets = []  # type: List[Union[QWidget, QAction]]

        vbox = QVBoxLayout()
        self.setLayout(vbox)
        toolbar, menu = create_toolbar_with_menu(self.config, '')
        menu.addConfig(
            self.config.cv.GUI_QT_TX_DIALOG_FETCH_TXIN_DATA,
            callback=self.maybe_fetch_txin_data)
        vbox.addLayout(toolbar)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e = ShowQRLineEdit('', self.config, title=_('Transaction ID'))
        vbox.addWidget(self.tx_hash_e)
        self.tx_desc_label = QLabel(_("Description:"))
        vbox.addWidget(self.tx_desc_label)
        self.tx_desc = ButtonsLineEdit('')
        def on_edited():
            text = self.tx_desc.text()
            if self.wallet.set_label(txid, text):
                self.main_window.history_list.update()
                self.main_window.utxo_list.update()
                self.main_window.labels_changed_signal.emit()
        self.tx_desc.editingFinished.connect(on_edited)
        self.tx_desc.addCopyButton()
        vbox.addWidget(self.tx_desc)

        self.add_tx_stats(vbox)

        vbox.addSpacing(10)

        self.io_widget = TxInOutWidget(self.main_window, self.wallet)
        vbox.addWidget(self.io_widget)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.do_broadcast)

        self.save_button = b = QPushButton(_("Add to History"))
        b.clicked.connect(self.save)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.export_actions_menu = export_actions_menu = QMenuWithConfig(config=self.config)
        self.add_export_actions_to_menu(export_actions_menu)
        export_actions_menu.addSeparator()
        export_option = export_actions_menu.addConfig(
            self.config.cv.GUI_QT_TX_DIALOG_EXPORT_STRIP_SENSITIVE_METADATA)
        self.psbt_only_widgets.append(export_option)
        export_option = export_actions_menu.addConfig(
            self.config.cv.GUI_QT_TX_DIALOG_EXPORT_INCLUDE_GLOBAL_XPUBS)
        self.psbt_only_widgets.append(export_option)
        if self.wallet.has_support_for_slip_19_ownership_proofs():
            export_option = export_actions_menu.addAction(
                _('Include SLIP-19 ownership proofs'),
                self._add_slip_19_ownership_proofs_to_tx)
            export_option.setToolTip(_("Some cosigners (e.g. Trezor) might require this for coinjoins."))
            self._export_option_slip19 = export_option
            export_option.setCheckable(True)
            export_option.setChecked(False)
            self.psbt_only_widgets.append(export_option)

        self.export_actions_button = QToolButton()
        self.export_actions_button.setText(_("Share"))
        self.export_actions_button.setMenu(export_actions_menu)
        self.export_actions_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

        partial_tx_actions_menu = QMenu()
        ptx_merge_sigs_action = QAction(_("Merge signatures from"), self)
        ptx_merge_sigs_action.triggered.connect(self.merge_sigs)
        partial_tx_actions_menu.addAction(ptx_merge_sigs_action)
        self._ptx_join_txs_action = QAction(_("Join inputs/outputs"), self)
        self._ptx_join_txs_action.triggered.connect(self.join_tx_with_another)
        partial_tx_actions_menu.addAction(self._ptx_join_txs_action)
        self.partial_tx_actions_button = QToolButton()
        self.partial_tx_actions_button.setText(_("Combine"))
        self.partial_tx_actions_button.setMenu(partial_tx_actions_menu)
        self.partial_tx_actions_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.psbt_only_widgets.append(self.partial_tx_actions_button)

        # Action buttons
        self.buttons = [self.partial_tx_actions_button, self.sign_button, self.broadcast_button, self.cancel_button]
        # Transaction sharing buttons
        self.sharing_buttons = [self.export_actions_button, self.save_button]
        run_hook('transaction_dialog', self)
        self.hbox = hbox = QHBoxLayout()
        hbox.addLayout(Buttons(*self.sharing_buttons))
        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        vbox.addLayout(hbox)
        dialogs.append(self)

        self._fetch_txin_data_fut = None  # type: Optional[concurrent.futures.Future]
        self._fetch_txin_data_progress = None  # type: Optional[TxinDataFetchProgress]
        self.throttled_update_sig.connect(self._throttled_update, Qt.ConnectionType.QueuedConnection)

        self.set_tx(tx)
        self.update()
        self.set_title()

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
        tx.add_info_from_wallet(self.wallet)
        # FIXME for PSBTs, we do a blocking fetch, as the missing data might be needed for e.g. signing
        # - otherwise, the missing data is for display-completeness only, e.g. fee, input addresses (we do it async)
        if not tx.is_complete() and tx.is_missing_info_from_network():
            BlockingWaitingDialog(
                self,
                _("Adding info to tx, from network..."),
                lambda: Network.run_from_another_thread(
                    tx.add_info_from_network(self.wallet.network, timeout=10)),
            )
        else:
            self.maybe_fetch_txin_data()

    def do_broadcast(self):
        self.main_window.push_top_level_window(self)
        self.main_window.send_tab.save_pending_invoice()
        try:
            self.main_window.broadcast_transaction(self.tx, payment_identifier=self.payment_identifier)
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
        if self._fetch_txin_data_fut:
            self._fetch_txin_data_fut.cancel()
            self._fetch_txin_data_fut = None

    def reject(self):
        # Override escape-key to close normally (and invoke closeEvent)
        self.close()

    def add_export_actions_to_menu(self, menu: QMenu) -> None:
        def gettx() -> Transaction:
            if not isinstance(self.tx, PartialTransaction):
                return self.tx
            tx = copy.deepcopy(self.tx)
            if self.config.GUI_QT_TX_DIALOG_EXPORT_INCLUDE_GLOBAL_XPUBS:
                Network.run_from_another_thread(
                    tx.prepare_for_export_for_hardware_device(self.wallet))
            if self.config.GUI_QT_TX_DIALOG_EXPORT_STRIP_SENSITIVE_METADATA:
                tx.prepare_for_export_for_coinjoin()
            return tx

        action = QAction(_("Copy to clipboard"), self)
        action.triggered.connect(lambda: self.copy_to_clipboard(tx=gettx()))
        menu.addAction(action)

        action = QAction(read_QIcon(get_iconname_qrcode()), _("Show as QR code"), self)
        action.triggered.connect(lambda: self.show_qr(tx=gettx()))
        menu.addAction(action)

        action = QAction(_("Save to file"), self)
        action.triggered.connect(lambda: self.export_to_file(tx=gettx()))
        menu.addAction(action)

    def _add_slip_19_ownership_proofs_to_tx(self):
        assert isinstance(self.tx, PartialTransaction)
        def on_success(result):
            self._export_option_slip19.setEnabled(False)
            self.main_window.pop_top_level_window(self)
        def on_failure(exc_info):
            self._export_option_slip19.setChecked(False)
            self.main_window.on_error(exc_info)
            self.main_window.pop_top_level_window(self)
        task = partial(self.wallet.add_slip_19_ownership_proofs_to_tx, self.tx)
        msg = _('Adding SLIP-19 ownership proofs to transaction...')
        self.main_window.push_top_level_window(self)
        WaitingDialog(self, msg, task, on_success, on_failure)

    def copy_to_clipboard(self, *, tx: Transaction = None):
        if tx is None:
            tx = self.tx
        self.main_window.do_copy(str(tx), title=_("Transaction"))

    def show_qr(self, *, tx: Transaction = None):
        if tx is None:
            tx = self.tx
        qr_data, is_complete = tx.to_qr_data()
        help_text = None
        if not is_complete:
            help_text = _(
                """Warning: Some data (prev txs / "full utxos") was left """
                """out of the QR code as it would not fit. This might cause issues if signing offline. """
                """As a workaround, try exporting the tx as file or text instead.""")
        try:
            self.main_window.show_qrcode(qr_data, 'Transaction', parent=self, help_text=help_text)
        except qrcode.exceptions.DataOverflowError:
            self.show_error(_('Failed to display QR code.') + '\n' +
                            _('Transaction is too large in size.'))
        except Exception as e:
            self.show_error(_('Failed to display QR code.') + '\n' + repr(e))

    def sign(self):
        def sign_done(success):
            if self.tx.is_complete():
                self.prompt_if_unsaved = True
                self.saved = False
            self.update()
            self.main_window.pop_top_level_window(self)

        if self.io_widget.sighash_danger.needs_confirm():
            if not self.question(
                msg='\n'.join([
                    self.io_widget.sighash_danger.get_long_message(),
                    '',
                    _('Are you sure you want to sign this transaction?')
                ]),
                title=self.io_widget.sighash_danger.short_message,
            ):
                return
        self.sign_button.setDisabled(True)
        self.main_window.push_top_level_window(self)
        self.main_window.sign_tx(self.tx, callback=sign_done, external_keypairs=self.external_keypairs)

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
        txid = tx.txid()
        suffix = txid[0:8] if txid is not None else time.strftime('%Y%m%d-%H%M')
        if tx.is_complete():
            extension = 'txn'
            default_filter = TRANSACTION_FILE_EXTENSION_FILTER_ONLY_COMPLETE_TX
        else:
            extension = 'psbt'
            default_filter = TRANSACTION_FILE_EXTENSION_FILTER_ONLY_PARTIAL_TX
        name = f'{self.wallet.basename()}-{suffix}.{extension}'
        fileName = getSaveFileName(
            parent=self,
            title=_("Select where to save your transaction"),
            filename=name,
            filter=TRANSACTION_FILE_EXTENSION_FILTER_SEPARATE,
            default_extension=extension,
            default_filter=default_filter,
            config=self.config,
        )
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
        text = text_dialog(
            parent=self,
            title=_('Input raw transaction'),
            header_layout=_("Transaction to merge signatures from") + ":",
            ok_label=_("Load transaction"),
            config=self.config,
        )
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
        text = text_dialog(
            parent=self,
            title=_('Input raw transaction'),
            header_layout=_("Transaction to join with") + " (" + _("add inputs and outputs") + "):",
            ok_label=_("Load transaction"),
            config=self.config,
        )
        if not text:
            return
        tx = self.main_window.tx_from_text(text)
        if not tx:
            return
        try:
            self.tx.join_with_other_psbt(tx, config=self.config)
        except Exception as e:
            self.show_error(_("Error joining partial transactions") + ":\n" + repr(e))
            return
        self.update()

    @rate_limited(0.5, ts_after=True)
    def _throttled_update(self):
        self.update()

    def update(self):
        if self.tx is None:
            return
        self.io_widget.update(self.tx)
        desc = self.desc
        base_unit = self.main_window.base_unit()
        format_amount = self.main_window.format_amount
        format_fiat_and_units = self.main_window.format_fiat_and_units
        tx_details = self.wallet.get_tx_info(self.tx)
        tx_mined_status = tx_details.tx_mined_status
        exp_n = tx_details.mempool_depth_bytes
        amount, fee = tx_details.amount, tx_details.fee
        size = self.tx.estimated_size()
        txid = self.tx.txid()
        fx = self.main_window.fx
        tx_item_fiat = None
        if (txid is not None and fx.is_enabled() and amount is not None):
            tx_item_fiat = self.wallet.get_tx_item_fiat(
                tx_hash=txid, amount_sat=abs(amount), fx=fx, tx_fee=fee)
        lnworker_history = self.wallet.lnworker.get_onchain_history() if self.wallet.lnworker else {}
        if txid in lnworker_history:
            item = lnworker_history[txid]
            ln_amount = item['amount_msat'] / 1000
            if amount is None:
                tx_mined_status = self.wallet.adb.get_tx_height(txid)
        else:
            ln_amount = None
        self.broadcast_button.setEnabled(tx_details.can_broadcast)
        can_sign = not self.tx.is_complete() and \
            (self.wallet.can_sign(self.tx) or bool(self.external_keypairs))
        self.sign_button.setEnabled(can_sign and not self.io_widget.sighash_danger.needs_reject())
        if sh_danger_msg := self.io_widget.sighash_danger.get_long_message():
            self.sign_button.setToolTip(sh_danger_msg)
        if tx_details.txid:
            self.tx_hash_e.setText(tx_details.txid)
        else:
            # note: when not finalized, RBF and locktime changes do not trigger
            #       a make_tx, so the txid is unreliable, hence:
            self.tx_hash_e.setText(_('Unknown'))
        if not self.wallet.adb.get_transaction(txid):
            self.tx_desc.hide()
            self.tx_desc_label.hide()
        else:
            self.tx_desc.setText(desc)
            self.tx_desc.show()
            self.tx_desc_label.show()
        self.status_label.setText(_('Status:') + ' ' + tx_details.status)

        if tx_mined_status.timestamp:
            time_str = datetime.datetime.fromtimestamp(tx_mined_status.timestamp).isoformat(' ')[:-3]
            self.date_label.setText(_("Date: {}").format(time_str))
            self.date_label.show()
        elif exp_n is not None:
            text = "{}: {}".format(
                _('Position in mempool'),
                self.config.depth_tooltip(exp_n))
            self.date_label.setText(text)
            self.date_label.show()
        else:
            self.date_label.hide()
        if self.tx.locktime <= NLOCKTIME_BLOCKHEIGHT_MAX:
            locktime_final_str = f"LockTime: {self.tx.locktime} (height)"
        else:
            locktime_final_str = f"LockTime: {self.tx.locktime} ({datetime.datetime.fromtimestamp(self.tx.locktime)})"
        self.locktime_final_label.setText(locktime_final_str)

        self.rbf_label.setText(_('Replace by fee') + f": {self.tx.is_rbf_enabled()}")

        if tx_mined_status.header_hash:
            self.block_height_label.setText(_("At block height: {}")
                                            .format(tx_mined_status.height))
        else:
            self.block_height_label.hide()
        if amount is None and ln_amount is None:
            amount_str = _("Transaction unrelated to your wallet")
        elif amount is None:
            amount_str = ''
        else:
            if amount > 0:
                amount_str = _("Amount received:") + ' %s'% format_amount(amount) + ' ' + base_unit
            else:
                amount_str = _("Amount sent:") + ' %s' % format_amount(-amount) + ' ' + base_unit
            if fx.is_enabled():
                if tx_item_fiat:  # historical tx -> using historical price
                    amount_str += ' ({})'.format(tx_item_fiat['fiat_value'].to_ui_string())
                elif tx_details.is_related_to_wallet:  # probably "tx preview" -> using current price
                    amount_str += ' ({})'.format(format_fiat_and_units(abs(amount)))
        if amount_str:
            self.amount_label.setText(amount_str)
        else:
            self.amount_label.hide()
        size_str = _("Size:") + f" {size} {UI_UNIT_NAME_TXSIZE_VBYTES}"
        if fee is None:
            if prog := self._fetch_txin_data_progress:
                if not prog.has_errored:
                    fee_str = _("Downloading input data...") + f" ({prog.num_tasks_done}/{prog.num_tasks_total})"
                else:
                    fee_str = _("Downloading input data...") + f" error."
            else:
                fee_str = _("Fee") + ': ' + _("unknown")
        else:
            fee_str = _("Fee") + f': {format_amount(fee)} {base_unit}'
            if fx.is_enabled():
                if tx_item_fiat:  # historical tx -> using historical price
                    fee_str += ' ({})'.format(tx_item_fiat['fiat_fee'].to_ui_string())
                elif tx_details.is_related_to_wallet:  # probably "tx preview" -> using current price
                    fee_str += ' ({})'.format(format_fiat_and_units(fee))
        if fee is not None:
            fee_rate = Decimal(fee) / size  # sat/byte
            fee_str += '  ( %s ) ' % self.main_window.format_fee_rate(fee_rate * 1000)
            if isinstance(self.tx, PartialTransaction):
                invoice_amt = amount
                fee_warning_tuple = self.wallet.get_tx_fee_warning(
                    invoice_amt=invoice_amt, tx_size=size, fee=fee)
                if fee_warning_tuple:
                    allow_send, long_warning, short_warning = fee_warning_tuple
                    fee_str += " - <font color={color}>{header}: {body}</font>".format(
                        header=_('Warning'),
                        body=short_warning,
                        color=ColorScheme.RED.as_color().name(),
                    )
        if isinstance(self.tx, PartialTransaction):
            sh_warning = self.io_widget.sighash_danger.get_long_message()
            self.fee_warning_icon.setToolTip(str(sh_warning))
            self.fee_warning_icon.setVisible(can_sign and bool(sh_warning))
        self.fee_label.setText(fee_str)
        self.size_label.setText(size_str)
        if ln_amount is None or ln_amount == 0:
            ln_amount_str = ''
        elif ln_amount > 0:
            ln_amount_str = _('Amount received in channels') + ': ' + format_amount(ln_amount) + ' ' + base_unit
        else:
            assert ln_amount < 0, f"{ln_amount!r}"
            ln_amount_str = _('Amount withdrawn from channels') + ': ' + format_amount(-ln_amount) + ' ' + base_unit
        if ln_amount_str:
            self.ln_amount_label.setText(ln_amount_str)
        else:
            self.ln_amount_label.hide()
        show_psbt_only_widgets = isinstance(self.tx, PartialTransaction)
        for widget in self.psbt_only_widgets:
            if isinstance(widget, QMenu):
                widget.menuAction().setVisible(show_psbt_only_widgets)
            else:
                widget.setVisible(show_psbt_only_widgets)
        if tx_details.is_lightning_funding_tx:
            self._ptx_join_txs_action.setEnabled(False)  # would change txid

        self.save_button.setEnabled(tx_details.can_save_as_local)
        if tx_details.can_save_as_local:
            self.save_button.setToolTip(_("Add transaction to history, without broadcasting it"))
        else:
            self.save_button.setToolTip(_("Transaction already in history or not yet signed."))

        run_hook('transaction_dialog_update', self)

    def add_tx_stats(self, vbox):
        hbox_stats = QHBoxLayout()
        hbox_stats.setContentsMargins(0, 0, 0, 0)
        hbox_stats_w = QWidget()
        hbox_stats_w.setLayout(hbox_stats)
        hbox_stats_w.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)

        # left column
        vbox_left = QVBoxLayout()
        self.status_label = TxDetailLabel()
        vbox_left.addWidget(self.status_label)
        self.date_label = TxDetailLabel()
        vbox_left.addWidget(self.date_label)
        self.amount_label = TxDetailLabel()
        vbox_left.addWidget(self.amount_label)
        self.ln_amount_label = TxDetailLabel()
        vbox_left.addWidget(self.ln_amount_label)

        fee_hbox = QHBoxLayout()
        self.fee_label = TxDetailLabel()
        fee_hbox.addWidget(self.fee_label)
        self.fee_warning_icon = QLabel()
        pixmap = QPixmap(icon_path("warning"))
        pixmap_size = round(2 * char_width_in_lineedit())
        pixmap = pixmap.scaled(pixmap_size, pixmap_size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        self.fee_warning_icon.setPixmap(pixmap)
        self.fee_warning_icon.setVisible(False)
        fee_hbox.addWidget(self.fee_warning_icon)
        fee_hbox.addStretch(1)
        vbox_left.addLayout(fee_hbox)

        vbox_left.addStretch(1)
        hbox_stats.addLayout(vbox_left, 50)

        # vertical line separator
        hbox_stats.addWidget(VLine())

        # right column
        vbox_right = QVBoxLayout()
        self.size_label = TxDetailLabel()
        vbox_right.addWidget(self.size_label)
        self.rbf_label = TxDetailLabel()
        vbox_right.addWidget(self.rbf_label)

        self.locktime_final_label = TxDetailLabel()
        vbox_right.addWidget(self.locktime_final_label)

        self.block_height_label = TxDetailLabel()
        vbox_right.addWidget(self.block_height_label)
        vbox_right.addStretch(1)
        hbox_stats.addLayout(vbox_right, 50)

        vbox.addWidget(hbox_stats_w)

        # set visibility after parenting can be determined by Qt
        self.rbf_label.setVisible(True)
        self.locktime_final_label.setVisible(True)

    def set_title(self):
        txid = self.tx.txid() or "<no txid yet>"
        self.setWindowTitle(_("Transaction") + ' ' + txid)

    def maybe_fetch_txin_data(self):
        """Download missing input data from the network, asynchronously.
        Note: we fetch the prev txs, which allows calculating the fee and showing "input addresses".
              We could also SPV-verify the tx, to fill in missing tx_mined_status (block height, blockhash, timestamp),
              but this is not done currently.
        """
        if not self.config.GUI_QT_TX_DIALOG_FETCH_TXIN_DATA:
            return
        tx = self.tx
        if not tx:
            return
        if self._fetch_txin_data_fut is not None:
            return
        network = self.wallet.network
        def progress_cb(prog: TxinDataFetchProgress):
            self._fetch_txin_data_progress = prog
            self.throttled_update_sig.emit()
        async def wrapper():
            try:
                await tx.add_info_from_network(network, progress_cb=progress_cb)
            finally:
                self._fetch_txin_data_fut = None

        self._fetch_txin_data_progress = None
        self._fetch_txin_data_fut = asyncio.run_coroutine_threadsafe(wrapper(), get_asyncio_loop())


class TxDetailLabel(QLabel):
    def __init__(self, *, word_wrap=None):
        super().__init__()
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if word_wrap is not None:
            self.setWordWrap(word_wrap)


class TxOutputColoring:
    # used for both inputs and outputs

    def __init__(
            self,
            *,
            legend: str,
            color: ColorSchemeItem,
            tooltip: str,
    ):
        self.color = color.as_color(background=True)
        self.legend_label = QLabel("<font color={color}>{box_char}</font> = {label}".format(
            color=self.color.name(),
            box_char="█",
            label=legend,
        ))
        font = self.legend_label.font()
        font.setPointSize(font.pointSize() - 1)
        self.legend_label.setFont(font)
        self.legend_label.setVisible(False)
        self.text_char_format = QTextCharFormat()
        self.text_char_format.setBackground(QBrush(self.color))
        self.text_char_format.setToolTip(tooltip)

