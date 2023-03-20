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

import re
import decimal
from functools import partial
from decimal import Decimal
from typing import NamedTuple, Sequence, Optional, List, TYPE_CHECKING

from PyQt5.QtGui import QFontMetrics, QFont
from PyQt5.QtWidgets import QApplication, QWidget, QLineEdit, QTextEdit, QVBoxLayout

from electrum import bitcoin
from electrum.util import parse_max_spend, FailedToParsePaymentIdentifier
from electrum.transaction import PartialTxOutput
from electrum.bitcoin import opcodes, construct_script
from electrum.logging import Logger
from electrum.lnurl import LNURLError

from .qrtextedit import ScanQRTextEdit
from .completion_text_edit import CompletionTextEdit
from . import util
from .util import MONOSPACE_FONT, GenericInputHandler, editor_contextMenuEvent

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .send_tab import SendTab


RE_ALIAS = r'(.*?)\s*\<([0-9A-Za-z]{1,})\>'

frozen_style = "QWidget {border:none;}"
normal_style = "QPlainTextEdit { }"


class PayToLineError(NamedTuple):
    line_content: str
    exc: Exception
    idx: int = 0  # index of line
    is_multiline: bool = False



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
        self.outputs = []  # type: List[PartialTxOutput]
        self.errors = []  # type: List[PayToLineError]
        self.disable_checks = False
        self.is_alias = False
        self.payto_scriptpubkey = None  # type: Optional[bytes]
        self.lightning_invoice = None
        self.previous_payto = ''
        # editor methods
        self.setStyleSheet = self.editor.setStyleSheet
        self.setText = self.editor.setText
        self.setEnabled = self.editor.setEnabled
        self.setReadOnly = self.editor.setReadOnly
        # button handlers
        self.on_qr_from_camera_input_btn = partial(
            self.input_qr_from_camera,
            config=self.config,
            allow_multi=False,
            show_error=self.win.show_error,
            setText=self._on_input_btn,
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
        self._is_paytomany = b
        self.line_edit.setVisible(not b)
        self.text_edit.setVisible(b)
        self.send_tab.paytomany_menu.setChecked(b)

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

    def parse_address_and_amount(self, line) -> PartialTxOutput:
        try:
            x, y = line.split(',')
        except ValueError:
            raise Exception("expected two comma-separated values: (address, amount)") from None
        scriptpubkey = self.parse_output(x)
        amount = self.parse_amount(y)
        return PartialTxOutput(scriptpubkey=scriptpubkey, value=amount)

    def parse_output(self, x) -> bytes:
        try:
            address = self.parse_address(x)
            return bytes.fromhex(bitcoin.address_to_script(address))
        except Exception:
            pass
        try:
            script = self.parse_script(x)
            return bytes.fromhex(script)
        except Exception:
            pass
        raise Exception("Invalid address or script.")

    def parse_script(self, x):
        script = ''
        for word in x.split():
            if word[0:3] == 'OP_':
                opcode_int = opcodes[word]
                script += construct_script([opcode_int])
            else:
                bytes.fromhex(word)  # to test it is hex data
                script += construct_script([word])
        return script

    def parse_amount(self, x):
        x = x.strip()
        if not x:
            raise Exception("Amount is empty")
        if parse_max_spend(x):
            return x
        p = pow(10, self.amount_edit.decimal_point())
        try:
            return int(p * Decimal(x))
        except decimal.InvalidOperation:
            raise Exception("Invalid amount")

    def parse_address(self, line):
        r = line.strip()
        m = re.match('^'+RE_ALIAS+'$', r)
        address = str(m.group(2) if m else r)
        assert bitcoin.is_address(address)
        return address

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

    def on_timer_check_text(self):
        if self.editor.hasFocus():
            return
        text = self.toPlainText()
        self._check_text(text, full_check=True)

    def _check_text(self, text, *, full_check: bool):
        """
        side effects: self.is_multiline, self.errors, self.outputs
        """
        if self.previous_payto == str(text).strip():
            return
        if full_check:
            self.previous_payto = str(text).strip()
        self.errors = []
        errors = []
        if self.disable_checks:
            return
        # filter out empty lines
        lines = text.split('\n')
        lines = [i for i in lines if i]
        self.is_multiline = len(lines)>1

        self.payto_scriptpubkey = None
        self.lightning_invoice = None
        self.outputs = []

        if len(lines) == 1:
            data = lines[0]
            try:
                self.send_tab.handle_payment_identifier(data, can_use_network=full_check)
            except LNURLError as e:
                self.logger.exception("")
                self.send_tab.show_error(e)
            except FailedToParsePaymentIdentifier:
                pass
            else:
                return
            # try "address, amount" on-chain format
            try:
                self._parse_as_multiline(lines, raise_errors=True)
            except Exception as e:
                pass
            else:
                return
            # try address/script
            try:
                self.payto_scriptpubkey = self.parse_output(data)
            except Exception as e:
                errors.append(PayToLineError(line_content=data, exc=e))
            else:
                self.send_tab.set_onchain(True)
                self.send_tab.lock_amount(False)
                return
            if full_check:  # network requests  # FIXME blocking GUI thread
                # try openalias
                oa_data = self._resolve_openalias(data)
                if oa_data:
                    self._set_openalias(key=data, data=oa_data)
                    return
            # all parsing attempts failed, so now expose the errors:
            if errors:
                self.errors = errors
        else:
            # there are multiple lines
            self._parse_as_multiline(lines, raise_errors=False)


    def _parse_as_multiline(self, lines, *, raise_errors: bool):
        outputs = []  # type: List[PartialTxOutput]
        total = 0
        is_max = False
        for i, line in enumerate(lines):
            try:
                output = self.parse_address_and_amount(line)
            except Exception as e:
                if raise_errors:
                    raise
                else:
                    self.errors.append(PayToLineError(
                        idx=i, line_content=line.strip(), exc=e, is_multiline=True))
                    continue
            outputs.append(output)
            if parse_max_spend(output.value):
                is_max = True
            else:
                total += output.value
        if outputs:
            self.send_tab.set_onchain(True)

        self.send_tab.max_button.setChecked(is_max)
        self.outputs = outputs
        self.payto_scriptpubkey = None

        if self.send_tab.max_button.isChecked():
            self.send_tab.spend_max()
        else:
            self.amount_edit.setAmount(total if outputs else None)
        self.send_tab.lock_amount(self.send_tab.max_button.isChecked() or bool(outputs))

    def get_errors(self) -> Sequence[PayToLineError]:
        return self.errors

    def get_destination_scriptpubkey(self) -> Optional[bytes]:
        return self.payto_scriptpubkey

    def get_outputs(self, is_max: bool) -> List[PartialTxOutput]:
        if self.payto_scriptpubkey:
            if is_max:
                amount = '!'
            else:
                amount = self.send_tab.get_amount()
            self.outputs = [PartialTxOutput(scriptpubkey=self.payto_scriptpubkey, value=amount)]

        return self.outputs[:]

    def _resolve_openalias(self, text: str) -> Optional[dict]:
        key = text
        key = key.strip()  # strip whitespaces
        if not (('.' in key) and ('<' not in key) and (' ' not in key)):
            return None
        parts = key.split(sep=',')  # assuming single line
        if parts and len(parts) > 0 and bitcoin.is_address(parts[0]):
            return None
        try:
            data = self.win.contacts.resolve(key)
        except Exception as e:
            self.logger.info(f'error resolving address/alias: {repr(e)}')
            return None
        return data or None

    def _set_openalias(self, *, key: str, data: dict) -> bool:
        self.is_alias = True
        self.setFrozen(True)
        key = key.strip()  # strip whitespaces
        address = data.get('address')
        name = data.get('name')
        new_url = key + ' <' + address + '>'
        self.setText(new_url)

        #if self.win.config.get('openalias_autoadd') == 'checked':
        self.win.contacts[key] = ('openalias', name)
        self.win.contact_list.update()

        if data.get('type') == 'openalias':
            self.validated = data.get('validated')
            if self.validated:
                self.setGreen()
            else:
                self.setExpired()
        else:
            self.validated = None
        return True
