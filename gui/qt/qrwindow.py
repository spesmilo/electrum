#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget, QDialog, QPushButton, QSizePolicy


from electroncash_gui.qt.qrcodewidget import QRCodeWidget, save_to_file, copy_to_clipboard
from .util import WWLabel, Buttons, MessageBoxMixin
from electroncash.i18n import _
from electroncash.util import Weak

class QR_Window(QWidget, MessageBoxMixin):

    def __init__(self):
        super().__init__() # Top-level window. Parent needs to hold a reference to us and clean us up appropriately.
        self.setWindowTitle('Electron Cash - ' + _('Payment Request'))
        self.label = ''
        self.amount = 0
        self.setFocusPolicy(Qt.NoFocus)
        self.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)

        main_box = QHBoxLayout(self)
        main_box.setContentsMargins(12,12,12,12)
        self.qrw = QRCodeWidget()
        self.qrw.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
        main_box.addWidget(self.qrw, 2)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(12,12,12,12)
        main_box.addLayout(vbox,2)
        main_box.addStretch(1)

        self.address_label = WWLabel()
        self.address_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(self.address_label)

        self.msg_label = WWLabel()
        self.msg_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(self.msg_label)

        self.amount_label = WWLabel()
        self.amount_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(self.amount_label)

        self.op_return_label = WWLabel()
        self.op_return_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        vbox.addWidget(self.op_return_label)

        vbox.addStretch(2)

        copyBut = QPushButton(_("Copy QR Image"))
        saveBut = QPushButton(_("Save QR Image"))
        vbox.addLayout(Buttons(copyBut, saveBut))

        weakSelf = Weak.ref(self)  # Qt & Python GC hygeine: don't hold references to self in non-method slots as it appears Qt+Python GC don't like this too much and may leak memory in that case.
        weakQ = Weak.ref(self.qrw)
        weakBut = Weak.ref(copyBut)
        copyBut.clicked.connect(lambda: copy_to_clipboard(weakQ(), weakBut()))
        saveBut.clicked.connect(lambda: save_to_file(weakQ(), weakSelf()))



    def set_content(self, win, address_text, amount, message, url, *, op_return = None, op_return_raw = None):
        if op_return is not None and op_return_raw is not None:
            raise ValueError('Must specify exactly one of op_return or op_return_hex as kwargs to QR_Window.set_content')
        self.address_label.setText(address_text)
        if amount:
            amount_text = '{} {}'.format(win.format_amount(amount), win.base_unit())
        else:
            amount_text = ''
        self.amount_label.setText(amount_text)
        self.msg_label.setText(message)
        self.qrw.setData(url)
        if op_return:
            self.op_return_label.setText(f'OP_RETURN: {str(op_return)}')
        elif op_return_raw:
            self.op_return_label.setText(f'OP_RETURN (raw): {str(op_return_raw)}')
        self.op_return_label.setVisible(bool(op_return or op_return_raw))
        self.layout().activate()

    def closeEvent(self, e):
        # May have modal up when closed -- because wallet window may force-close
        # us when it is gets closed (See ElectrumWindow.clean_up in
        # main_window.py).
        # .. So kill the "QR Code Copied to clipboard" modal dialog that may
        # be up as it can cause a crash for this window to be closed with it
        # still up.
        for c in self.findChildren(QDialog):
            if c.isWindow() and c.isModal() and c.isVisible():
                c.reject()  # break out of local event loop for dialog as we are about to die and we will be invalidated.
        super().closeEvent(e)
