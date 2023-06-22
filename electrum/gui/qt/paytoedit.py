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

from functools import partial
from typing import NamedTuple, Sequence, Optional, List, TYPE_CHECKING

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtGui import QFontMetrics, QFont
from PyQt5.QtWidgets import QApplication, QTextEdit, QVBoxLayout

from electrum.i18n import _
from electrum.payment_identifier import PaymentIdentifier
from electrum.logging import Logger

from .qrtextedit import ScanQRTextEdit
from .completion_text_edit import CompletionTextEdit
from . import util
from .util import MONOSPACE_FONT, GenericInputHandler, editor_contextMenuEvent

if TYPE_CHECKING:
    from .send_tab import SendTab


frozen_style = "QWidget {border:none;}"
normal_style = "QPlainTextEdit { }"


class InvalidPaymentIdentifier(Exception):
    pass


class ResizingTextEdit(QTextEdit):

    def __init__(self):
        QTextEdit.__init__(self)
        document = self.document()
        document.contentsChanged.connect(self.update_size)
        fontMetrics = QFontMetrics(document.defaultFont())
        self.fontSpacing = fontMetrics.lineSpacing()
        margins = self.contentsMargins()
        documentMargin = document.documentMargin()
        self.verticalMargins = margins.top() + margins.bottom()
        self.verticalMargins += self.frameWidth() * 2
        self.verticalMargins += documentMargin * 2
        self.heightMin = self.fontSpacing + self.verticalMargins
        self.heightMax = (self.fontSpacing * 10) + self.verticalMargins
        self.single_line = True
        self.update_size()

    def update_size(self):
        docLineCount = self.document().lineCount()
        docHeight = max(1 if self.single_line else 3, docLineCount) * self.fontSpacing
        h = docHeight + self.verticalMargins
        h = min(max(h, self.heightMin), self.heightMax)
        self.setMinimumHeight(int(h))
        self.setMaximumHeight(int(h))
        if self.single_line:
            self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        else:
            self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            self.verticalScrollBar().setHidden(docHeight + self.verticalMargins < self.heightMax)
            self.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

class PayToEdit(QObject, Logger, GenericInputHandler):

    paymentIdentifierChanged = pyqtSignal()

    def __init__(self, send_tab: 'SendTab'):
        QObject.__init__(self, parent=send_tab)
        Logger.__init__(self)
        GenericInputHandler.__init__(self)

        self.text_edit = ResizingTextEdit()
        self.text_edit.textChanged.connect(self._handle_text_change)
        self._is_paytomany = False
        self.text_edit.setFont(QFont(MONOSPACE_FONT))
        self.send_tab = send_tab
        self.config = send_tab.config
        self.app = QApplication.instance()

        self.logger.debug(util.ColorScheme.RED.as_stylesheet(True))
        self.is_multiline = False
        # self.is_alias = False
        self.payto_scriptpubkey = None  # type: Optional[bytes]
        self.previous_payto = ''
        # editor methods
        self.setStyleSheet = self.text_edit.setStyleSheet
        self.setText = self.text_edit.setText
        self.setFocus = self.text_edit.setFocus
        self.setToolTip = self.text_edit.setToolTip
        # button handlers
        self.on_qr_from_camera_input_btn = partial(
            self.input_qr_from_camera,
            config=self.config,
            allow_multi=False,
            show_error=self.send_tab.show_error,
            setText=self.try_payment_identifier,
            parent=self.send_tab.window,
        )
        self.on_qr_from_screenshot_input_btn = partial(
            self.input_qr_from_screenshot,
            allow_multi=False,
            show_error=self.send_tab.show_error,
            setText=self.try_payment_identifier,
        )
        self.on_input_file = partial(
            self.input_file,
            config=self.config,
            show_error=self.send_tab.show_error,
            setText=self.try_payment_identifier,
        )

        self.text_edit.contextMenuEvent = partial(editor_contextMenuEvent, self.text_edit, self)

        self.edit_timer = QTimer(self)
        self.edit_timer.setSingleShot(True)
        self.edit_timer.setInterval(1000)
        self.edit_timer.timeout.connect(self._on_edit_timer)

        self.payment_identifier = None

    def set_text(self, text: str):
        self.text_edit.setText(text)

    def update_editor(self):
        if self.text_edit.toPlainText() != self.payment_identifier.text:
            self.text_edit.setText(self.payment_identifier.text)
        self.text_edit.single_line = not self.payment_identifier.is_multiline()
        self.text_edit.update_size()

    '''set payment identifier only if valid, else exception'''
    def try_payment_identifier(self, text):
        text = text.strip()
        pi = PaymentIdentifier(self.send_tab.wallet, text)
        if not pi.is_valid():
            raise InvalidPaymentIdentifier('Invalid payment identifier')
        self.set_payment_identifier(text)

    def set_payment_identifier(self, text):
        text = text.strip()
        if self.payment_identifier and self.payment_identifier.text == text:
            # no change.
            return

        self.payment_identifier = PaymentIdentifier(self.send_tab.wallet, text)

        # toggle to multiline if payment identifier is a multiline
        self.is_multiline = self.payment_identifier.is_multiline()
        if self.is_multiline and not self._is_paytomany:
            self.set_paytomany(True)

        # if payment identifier gets set externally, we want to update the text_edit
        # Note: this triggers the change handler, but we shortcut if it's the same payment identifier
        self.update_editor()

        self.paymentIdentifierChanged.emit()

    def set_paytomany(self, b):
        self._is_paytomany = b
        self.text_edit.single_line = not self._is_paytomany
        self.text_edit.update_size()
        self.send_tab.paytomany_menu.setChecked(b)

    def toggle_paytomany(self):
        self.set_paytomany(not self._is_paytomany)

    def is_paytomany(self):
        return self._is_paytomany

    def setFrozen(self, b):
        self.text_edit.setReadOnly(b)
        if not b:
            self.setStyleSheet(normal_style)

    def isFrozen(self):
        return self.text_edit.isReadOnly()

    def do_clear(self):
        self.is_multiline = False
        self.set_paytomany(False)
        self.text_edit.setText('')
        self.payment_identifier = None

    def setGreen(self):
        self.setStyleSheet(util.ColorScheme.GREEN.as_stylesheet(True))

    def setExpired(self):
        self.setStyleSheet(util.ColorScheme.RED.as_stylesheet(True))

    def _handle_text_change(self):
        if self.isFrozen():
            # if editor is frozen, we ignore text changes as they might not be a payment identifier
            # but a user friendly representation.
            return

        # pushback timer if timer active or PI needs resolving
        pi = PaymentIdentifier(self.send_tab.wallet, self.text_edit.toPlainText())
        if pi.need_resolve() or self.edit_timer.isActive():
            self.edit_timer.start()
        else:
            self.set_payment_identifier(self.text_edit.toPlainText())

        # self.set_payment_identifier(text)
        # if self.app.clipboard().text() and self.app.clipboard().text().strip() == self.payment_identifier.text:
        #     # user pasted from clipboard
        #     self.logger.debug('from clipboard')
        #     if self.payment_identifier.error:
        #         self.send_tab.show_error(_('Clipboard text is not a valid payment identifier') + '\n' + self.payment_identifier.error)

    def _on_edit_timer(self):
        self.set_payment_identifier(self.text_edit.toPlainText())
