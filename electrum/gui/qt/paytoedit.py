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
from typing import Optional, TYPE_CHECKING

from PyQt6.QtCore import Qt, QTimer, QSize
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QFontMetrics, QFont
from PyQt6.QtWidgets import QApplication, QTextEdit, QWidget, QLineEdit, QStackedLayout, QSizePolicy

from electrum.payment_identifier import PaymentIdentifier
from electrum.logging import Logger

from . import util
from .util import MONOSPACE_FONT, GenericInputHandler, editor_contextMenuEvent, ColorScheme

if TYPE_CHECKING:
    from .send_tab import SendTab


frozen_style = "QWidget {border:none;}"
normal_style = "QPlainTextEdit { }"


class InvalidPaymentIdentifier(Exception):
    pass


class ResizingTextEdit(QTextEdit):

    textReallyChanged = pyqtSignal()
    resized = pyqtSignal()

    def __init__(self):
        QTextEdit.__init__(self)
        self._text = ''
        self.setAcceptRichText(False)
        self.textChanged.connect(self.on_text_changed)
        document = self.document()
        fontMetrics = QFontMetrics(document.defaultFont())
        self.fontSpacing = fontMetrics.lineSpacing()
        margins = self.contentsMargins()
        documentMargin = document.documentMargin()
        self.verticalMargins = margins.top() + margins.bottom()
        self.verticalMargins += self.frameWidth() * 2
        self.verticalMargins += documentMargin * 2
        self.heightMin = self.fontSpacing + self.verticalMargins
        self.heightMax = (self.fontSpacing * 10) + self.verticalMargins
        self.update_size()

    def on_text_changed(self):
        # QTextEdit emits spurious textChanged events
        if self.toPlainText() != self._text:
            self._text = self.toPlainText()
            self.textReallyChanged.emit()
            self.update_size()

    def update_size(self):
        docLineCount = self.document().lineCount()
        docHeight = max(3, docLineCount) * self.fontSpacing
        h = docHeight + self.verticalMargins
        h = min(max(h, self.heightMin), self.heightMax)
        self.setMinimumHeight(int(h))
        self.setMaximumHeight(int(h))
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.verticalScrollBar().setHidden(docHeight + self.verticalMargins < self.heightMax)
        self.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.resized.emit()

    def sizeHint(self) -> QSize:
        return QSize(0, self.minimumHeight())


class PayToEdit(QWidget, Logger, GenericInputHandler):
    paymentIdentifierChanged = pyqtSignal()
    textChanged = pyqtSignal()

    def __init__(self, send_tab: 'SendTab'):
        QWidget.__init__(self, parent=send_tab)
        Logger.__init__(self)
        GenericInputHandler.__init__(self)

        self._text = ''
        self._layout = QStackedLayout()
        self.setLayout(self._layout)

        def text_edit_changed():
            text = self.text_edit.toPlainText()
            if self._text != text:
                # sync and emit
                self._text = text
                self.line_edit.setText(text)
                self.textChanged.emit()

        def text_edit_resized():
            self.update_height()

        def line_edit_changed():
            text = self.line_edit.text()
            if self._text != text:
                # sync and emit
                self._text = text
                self.text_edit.setPlainText(text)
                self.textChanged.emit()

        self.line_edit = QLineEdit()
        self.line_edit.textChanged.connect(line_edit_changed)
        self.text_edit = ResizingTextEdit()
        self.text_edit.setTabChangesFocus(True)
        self.text_edit.textReallyChanged.connect(text_edit_changed)
        self.text_edit.resized.connect(text_edit_resized)

        self.textChanged.connect(self._handle_text_change)

        self._layout.addWidget(self.line_edit)
        self._layout.addWidget(self.text_edit)

        self.multiline = False

        self._is_paytomany = False
        self.line_edit.setFont(QFont(MONOSPACE_FONT))
        self.text_edit.setFont(QFont(MONOSPACE_FONT))
        self.send_tab = send_tab
        self.config = send_tab.config

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
        self.line_edit.contextMenuEvent = partial(editor_contextMenuEvent, self.line_edit, self)

        self.edit_timer = QTimer(self)
        self.edit_timer.setSingleShot(True)
        self.edit_timer.setInterval(1000)
        self.edit_timer.timeout.connect(self._on_edit_timer)

        self.payment_identifier = None  # type: Optional[PaymentIdentifier]

    @property
    def multiline(self):
        return self._multiline

    @multiline.setter
    def multiline(self, b: bool) -> None:
        if b is None:
            return
        self._multiline = b
        self._layout.setCurrentWidget(self.text_edit if b else self.line_edit)
        self.update_height()

    def update_height(self) -> None:
        h = self._layout.currentWidget().sizeHint().height()
        self.setMaximumHeight(h)

    def setText(self, text: str) -> None:
        if self._text != text:
            self.line_edit.setText(text)
            self.text_edit.setText(text)

    def setFocus(self, reason=Qt.FocusReason.OtherFocusReason) -> None:
        if self.multiline:
            self.text_edit.setFocus(reason)
        else:
            self.line_edit.setFocus(reason)

    def setToolTip(self, tt: str) -> None:
        self.line_edit.setToolTip(tt)
        self.text_edit.setToolTip(tt)

    def try_payment_identifier(self, text) -> None:
        '''set payment identifier only if valid, else exception'''
        text = text.strip()
        pi = PaymentIdentifier(self.send_tab.wallet, text)
        if not pi.is_valid():
            raise InvalidPaymentIdentifier('Invalid payment identifier')
        self.set_payment_identifier(text)

    def set_payment_identifier(self, text) -> None:
        text = text.strip()
        if self.payment_identifier and self.payment_identifier.text == text:
            # no change.
            return

        self.payment_identifier = PaymentIdentifier(self.send_tab.wallet, text)

        # toggle to multiline if payment identifier is a multiline
        if self.payment_identifier.is_multiline() and not self._is_paytomany:
            self.set_paytomany(True)

        # if payment identifier gets set externally, we want to update the edit control
        # Note: this triggers the change handler, but we shortcut if it's the same payment identifier
        self.setText(text)

        self.paymentIdentifierChanged.emit()

    def set_paytomany(self, b):
        self._is_paytomany = b
        self.multiline = b
        self.send_tab.paytomany_menu.setChecked(b)

    def toggle_paytomany(self) -> None:
        self.set_paytomany(not self._is_paytomany)

    def is_paytomany(self):
        return self._is_paytomany

    def setReadOnly(self, b: bool) -> None:
        self.line_edit.setReadOnly(b)
        self.text_edit.setReadOnly(b)

    def isReadOnly(self):
        return self.line_edit.isReadOnly()

    def setStyleSheet(self, stylesheet: str) -> None:
        self.line_edit.setStyleSheet(stylesheet)
        self.text_edit.setStyleSheet(stylesheet)

    def setFrozen(self, b) -> None:
        self.setReadOnly(b)
        self.setStyleSheet(ColorScheme.LIGHTBLUE.as_stylesheet(True) if b else '')

    def isFrozen(self):
        return self.isReadOnly()

    def do_clear(self) -> None:
        self.set_paytomany(False)
        self.setText('')
        self.setToolTip('')
        self.payment_identifier = None

    def setGreen(self) -> None:
        self.setStyleSheet(util.ColorScheme.GREEN.as_stylesheet(True))

    def setExpired(self) -> None:
        self.setStyleSheet(util.ColorScheme.RED.as_stylesheet(True))

    def _handle_text_change(self) -> None:
        if self.isFrozen():
            # if editor is frozen, we ignore text changes as they might not be a payment identifier
            # but a user friendly representation.
            return

        # pushback timer if timer active or PI needs resolving
        pi = PaymentIdentifier(self.send_tab.wallet, self._text)
        if not pi.is_valid() or pi.need_resolve() or self.edit_timer.isActive():
            self.edit_timer.start()
        else:
            self.set_payment_identifier(self._text)

    def _on_edit_timer(self) -> None:
        if not self.isFrozen():
            self.set_payment_identifier(self._text)
