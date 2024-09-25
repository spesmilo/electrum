#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2023 The Electrum Developers
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

from typing import TYPE_CHECKING
import copy

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QTextCharFormat, QFont
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QTextBrowser

from electrum.i18n import _

from .util import WindowModalDialog, ButtonsLineEdit, ShowQRLineEdit, ColorScheme, Buttons, CloseButton, MONOSPACE_FONT, WWLabel
from .history_list import HistoryList, HistoryModel
from .qrtextedit import ShowQRTextEdit
from .transaction_dialog import TxOutputColoring, QTextBrowserWithDefaultSize

if TYPE_CHECKING:
    from electrum.transaction import PartialTxInput
    from .main_window import ElectrumWindow



class UTXODialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow', utxo: 'PartialTxInput'):
        WindowModalDialog.__init__(self, window, _("Coin Privacy Analysis"))
        self.main_window = window
        self.config = window.config
        self.wallet = window.wallet
        self.utxo = utxo

        self.parents_list = QTextBrowserWithDefaultSize(800, 400)
        self.parents_list.setOpenLinks(False)  # disable automatic link opening
        self.parents_list.anchorClicked.connect(self.open_tx)  # send links to our handler
        self.parents_list.setFont(QFont(MONOSPACE_FONT))
        self.parents_list.setReadOnly(True)
        self.parents_list.setTextInteractionFlags(self.parents_list.textInteractionFlags() | Qt.TextInteractionFlag.LinksAccessibleByMouse | Qt.TextInteractionFlag.LinksAccessibleByKeyboard)
        self.txo_color_parent = TxOutputColoring(
            legend=_("Direct parent"), color=ColorScheme.BLUE, tooltip=_("Direct parent"))
        self.txo_color_uncle = TxOutputColoring(
            legend=_("Address reuse"), color=ColorScheme.RED, tooltip=_("Address reuse"))

        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_("Output point") + ": " + str(self.utxo.short_id)))
        vbox.addWidget(QLabel(_("Amount") + ": " + self.main_window.format_amount_and_units(self.utxo.value_sats())))
        self.stats_label = WWLabel()
        vbox.addWidget(self.stats_label)
        vbox.addWidget(self.parents_list)
        legend_hbox = QHBoxLayout()
        legend_hbox.setContentsMargins(0, 0, 0, 0)
        legend_hbox.addStretch(2)
        legend_hbox.addWidget(self.txo_color_parent.legend_label)
        legend_hbox.addWidget(self.txo_color_uncle.legend_label)
        vbox.addLayout(legend_hbox)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)
        self.update()
        self.main_window.labels_changed_signal.connect(self.update)

    def update(self):

        txid = self.utxo.prevout.txid.hex()
        parents = self.wallet.get_tx_parents(txid)
        num_parents = len(parents)
        parents_copy = copy.deepcopy(parents)
        cursor = self.parents_list.textCursor()
        ext = QTextCharFormat()

        if num_parents < 200:
            ASCII_EDGE   = '└─'
            ASCII_BRANCH = '├─'
            ASCII_PIPE   = '│ '
            ASCII_SPACE  = '  '
        else:
            ASCII_EDGE   = '└'
            ASCII_BRANCH = '├'
            ASCII_PIPE   = '│'
            ASCII_SPACE  = ' '

        self.parents_list.clear()
        self.num_reuse = 0
        def print_ascii_tree(_txid, prefix, is_last, is_uncle):
            if _txid not in parents:
                return
            tx_mined_info = self.wallet.adb.get_tx_height(_txid)
            tx_height = tx_mined_info.height
            tx_pos = tx_mined_info.txpos
            key = "%dx%d"%(tx_height, tx_pos) if tx_pos is not None else _txid[0:8]
            label = self.wallet.get_label_for_txid(_txid) or ""
            if _txid not in parents_copy:
                label = '[duplicate]'
            c = '' if _txid == txid else (ASCII_EDGE if is_last else ASCII_BRANCH)
            cursor.insertText(prefix + c, ext)
            if is_uncle:
                self.num_reuse += 1
                lnk = QTextCharFormat(self.txo_color_uncle.text_char_format)
            else:
                lnk = QTextCharFormat(self.txo_color_parent.text_char_format)
            lnk.setToolTip(_('Click to open, right-click for menu'))
            lnk.setAnchorHref(_txid)
            #lnk.setAnchorNames([a_name])
            lnk.setAnchor(True)
            lnk.setUnderlineStyle(QTextCharFormat.UnderlineStyle.SingleUnderline)
            cursor.insertText(key, lnk)
            cursor.insertText(" ", ext)
            cursor.insertText(label, ext)
            cursor.insertBlock()
            next_prefix = '' if txid == _txid else prefix + (ASCII_SPACE if is_last else ASCII_PIPE)
            parents_list, uncle_list = parents_copy.pop(_txid, ([],[]))
            for i, p in enumerate(parents_list + uncle_list):
                is_last = (i == len(parents_list) + len(uncle_list)- 1)
                is_uncle = (i > len(parents_list) - 1)
                print_ascii_tree(p, next_prefix, is_last, is_uncle)

        # recursively build the tree
        print_ascii_tree(txid, '', False, False)
        msg = _("This UTXO has {} parent transactions in your wallet.").format(num_parents)
        if self.num_reuse:
            msg += '\n' + _('This does not include transactions that are downstream of address reuse.')
        self.stats_label.setText(msg)
        self.txo_color_parent.legend_label.setVisible(True)
        self.txo_color_uncle.legend_label.setVisible(bool(self.num_reuse))
        # set cursor to top
        cursor.setPosition(0)
        self.parents_list.setTextCursor(cursor)

    def open_tx(self, txid):
        if isinstance(txid, QUrl):
            txid = txid.toString(QUrl.UrlFormattingOption.None_)
        tx = self.wallet.adb.get_transaction(txid)
        if not tx:
            return
        self.main_window.show_transaction(tx)
