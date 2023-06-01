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

from PyQt5.QtGui import QFontMetrics, QFont
from PyQt5.QtWidgets import QApplication, QWidget, QLineEdit, QTextEdit, QVBoxLayout

from electrum.i18n import _
from electrum.util import parse_max_spend
from electrum.payment_identifier import PaymentIdentifier
from electrum.logging import Logger

from .qrtextedit import ScanQRTextEdit
from .completion_text_edit import CompletionTextEdit
from . import util
from .util import MONOSPACE_FONT, GenericInputHandler, editor_contextMenuEvent

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .send_tab import SendTab


frozen_style = "QWidget {border:none;}"
normal_style = "QPlainTextEdit { }"


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
        self.update_size()

    def update_size(self):
        docLineCount = self.document().lineCount()
        docHeight = max(3, docLineCount) * self.fontSpacing
        h = docHeight + self.verticalMargins
        h = min(max(h, self.heightMin), self.heightMax)
        self.setMinimumHeight(int(h))
        self.setMaximumHeight(int(h))
        self.verticalScrollBar().setHidden(docHeight + self.verticalMargins < self.heightMax)


class PayToEdit(Logger, GenericInputHandler):

    def __init__(self, send_tab: 'SendTab'):
        Logger.__init__(self)
        GenericInputHandler.__init__(self)
        self.line_edit = QLineEdit()
        self.text_edit = ResizingTextEdit()
        self.text_edit.hide()
        self._is_paytomany = False
        for w in [self.line_edit, self.text_edit]:
            w.setFont(QFont(MONOSPACE_FONT))
            w.textChanged.connect(self._on_text_changed)
        self.send_tab = send_tab
        self.config = send_tab.config
        self.win = send_tab.window
        self.app = QApplication.instance()
        self.amount_edit = self.send_tab.amount_e

        self.is_multiline = False
        self.disable_checks = False
        self.is_alias = False
        self.payto_scriptpubkey = None  # type: Optional[bytes]
        self.previous_payto = ''
        # editor methods
        self.setStyleSheet = self.editor.setStyleSheet
        self.setText = self.editor.setText
        self.setEnabled = self.editor.setEnabled
        self.setReadOnly = self.editor.setReadOnly
        self.setFocus = self.editor.setFocus
        # button handlers
        self.on_qr_from_camera_input_btn = partial(
            self.input_qr_from_camera,
            config=self.config,
            allow_multi=False,
            show_error=self.win.show_error,
            setText=self._on_input_btn,
            parent=self.win,
        )
        self.on_qr_from_screenshot_input_btn = partial(
            self.input_qr_from_screenshot,
            allow_multi=False,
            show_error=self.win.show_error,
            setText=self._on_input_btn,
        )
        self.on_input_file = partial(
            self.input_file,
            config=self.config,
            show_error=self.win.show_error,
            setText=self._on_input_btn,
        )
        #
        self.line_edit.contextMenuEvent = partial(editor_contextMenuEvent, self.line_edit, self)
        self.text_edit.contextMenuEvent = partial(editor_contextMenuEvent, self.text_edit, self)

    @property
    def editor(self):
        return self.text_edit if self.is_paytomany() else self.line_edit

    def set_paytomany(self, b):
        has_focus = self.editor.hasFocus()
        self._is_paytomany = b
        self.line_edit.setVisible(not b)
        self.text_edit.setVisible(b)
        self.send_tab.paytomany_menu.setChecked(b)
        if has_focus:
            self.editor.setFocus()

    def toggle_paytomany(self):
        self.set_paytomany(not self._is_paytomany)

    def toPlainText(self):
        return self.text_edit.toPlainText() if self.is_paytomany() else self.line_edit.text()

    def is_paytomany(self):
        return self._is_paytomany

    def setFrozen(self, b):
        self.setReadOnly(b)
        if not b:
            self.setStyleSheet(normal_style)

    def setTextNoCheck(self, text: str):
        """Sets the text, while also ensuring the new value will not be resolved/checked."""
        self.previous_payto = text
        self.setText(text)

    def do_clear(self):
        self.is_multiline = False
        self.set_paytomany(False)
        self.disable_checks = False
        self.is_alias = False
        self.line_edit.setText('')
        self.text_edit.setText('')
        self.setFrozen(False)
        self.setEnabled(True)

    def setGreen(self):
        self.setStyleSheet(util.ColorScheme.GREEN.as_stylesheet(True))

    def setExpired(self):
        self.setStyleSheet(util.ColorScheme.RED.as_stylesheet(True))

    def _on_input_btn(self, text: str):
        self.setText(text)

    def _on_text_changed(self):
        text = self.toPlainText()
        # False if user pasted from clipboard
        full_check = self.app.clipboard().text() != text
        self._check_text(text, full_check=full_check)
        if self.is_multiline and not self._is_paytomany:
            self.set_paytomany(True)
            self.text_edit.setText(text)
            self.text_edit.setFocus()

    def on_timer_check_text(self):
        if self.editor.hasFocus():
            return
        text = self.toPlainText()
        self._check_text(text, full_check=True)

    def _check_text(self, text, *, full_check: bool):
        """ side effects: self.is_multiline """
        text = str(text).strip()
        if not text:
            return
        if self.previous_payto == text:
            return
        if full_check:
            self.previous_payto = text
        if self.disable_checks:
            return
        pi = PaymentIdentifier(self.send_tab.wallet, text)
        self.is_multiline = bool(pi.multiline_outputs) # TODO: why both is_multiline and set_paytomany(True)??
        self.logger.debug(f'is_multiline {self.is_multiline}')
        if pi.is_valid():
            self.send_tab.set_payment_identifier(text)
        else:
            if not full_check and pi.error:
                self.send_tab.show_error(
                    _('Clipboard text is not a valid payment identifier') + '\n' + str(pi.error))
                return

    def handle_multiline(self, outputs):
        total = 0
        is_max = False
        for output in outputs:
            if parse_max_spend(output.value):
                is_max = True
            else:
                total += output.value
        self.send_tab.set_onchain(True)
        self.send_tab.max_button.setChecked(is_max)
        if self.send_tab.max_button.isChecked():
            self.send_tab.spend_max()
        else:
            self.amount_edit.setAmount(total if outputs else None)
        #self.send_tab.lock_amount(self.send_tab.max_button.isChecked() or bool(outputs))
