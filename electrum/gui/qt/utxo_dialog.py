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

from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QTextCharFormat, QFont
from PyQt5.QtWidgets import QVBoxLayout, QLabel, QTextBrowser

from electrum.i18n import _

from .util import WindowModalDialog, ButtonsLineEdit, ShowQRLineEdit, ColorScheme, Buttons, CloseButton, MONOSPACE_FONT, WWLabel
from .history_list import HistoryList, HistoryModel
from .qrtextedit import ShowQRTextEdit

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

# todo:
#  - edit label in tx detail window


class UTXODialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow', utxo):
        WindowModalDialog.__init__(self, window, _("Coin Privacy Analysis"))
        self.main_window = window
        self.config = window.config
        self.wallet = window.wallet
        self.utxo = utxo

        txid = self.utxo.prevout.txid.hex()
        parents = self.wallet.get_tx_parents(txid)
        num_parents = len(parents)
        parents_copy = copy.deepcopy(parents)

        self.parents_list = QTextBrowser()
        self.parents_list.setOpenLinks(False)  # disable automatic link opening
        self.parents_list.anchorClicked.connect(self.open_tx)  # send links to our handler
        self.parents_list.setFont(QFont(MONOSPACE_FONT))
        self.parents_list.setReadOnly(True)
        self.parents_list.setTextInteractionFlags(self.parents_list.textInteractionFlags() | Qt.LinksAccessibleByMouse | Qt.LinksAccessibleByKeyboard)
        self.parents_list.setMinimumWidth(900)
        self.parents_list.setMinimumHeight(400)
        self.parents_list.setLineWrapMode(QTextBrowser.NoWrap)

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

        def print_ascii_tree(_txid, prefix, is_last):
            if _txid not in parents:
                return
            tx_height, tx_pos = self.wallet.adb.get_txpos(_txid)
            key = "%dx%d"%(tx_height, tx_pos) if tx_pos >= 0 else _txid[0:8]
            label = self.wallet.get_label_for_txid(_txid) or ""
            if _txid not in parents_copy:
                label = '[duplicate]'
            c = '' if _txid == txid else (ASCII_EDGE if is_last else ASCII_BRANCH)
            cursor.insertText(prefix + c, ext)
            lnk = QTextCharFormat()
            lnk.setToolTip(_('Click to open, right-click for menu'))
            lnk.setAnchorHref(_txid)
            #lnk.setAnchorNames([a_name])
            lnk.setAnchor(True)
            lnk.setUnderlineStyle(QTextCharFormat.SingleUnderline)
            cursor.insertText(key, lnk)
            cursor.insertText(" ", ext)
            cursor.insertText(label, ext)
            cursor.insertBlock()
            next_prefix = '' if txid == _txid else prefix + (ASCII_SPACE if is_last else ASCII_PIPE)
            parents_list = parents_copy.pop(_txid, [])
            for i, p in enumerate(parents_list):
                is_last = i == len(parents_list) - 1
                print_ascii_tree(p, next_prefix, is_last)
        # recursively build the tree
        print_ascii_tree(txid, '', False)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_("Output point") + ": " + str(self.utxo.short_id)))
        vbox.addWidget(QLabel(_("Amount") + ": " + self.main_window.format_amount_and_units(self.utxo.value_sats())))
        vbox.addWidget(QLabel(_("This UTXO has {} parent transactions in your wallet").format(num_parents)))
        vbox.addWidget(self.parents_list)
        msg = ' '.join([
            _("Note: This analysis only shows parent transactions, and does not take address reuse into consideration."),
            _("If you reuse addresses, more links can be established between your transactions, that are not displayed here.")
        ])
        vbox.addWidget(WWLabel(msg))
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)
        # set cursor to top
        cursor.setPosition(0)
        self.parents_list.setTextCursor(cursor)

    def open_tx(self, txid):
        if isinstance(txid, QUrl):
            txid = txid.toString(QUrl.None_)
        tx = self.wallet.adb.get_transaction(txid)
        if not tx:
            return
        self.main_window.show_transaction(tx)
