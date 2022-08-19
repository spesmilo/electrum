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
from decimal import Decimal
from typing import NamedTuple, Sequence, Optional, List, TYPE_CHECKING

from PyQt5.QtGui import QFontMetrics, QFont
from PyQt5.QtWidgets import QApplication

from electrum_ltc import bitcoin
from electrum_ltc.util import bfh, parse_max_spend, FailedToParsePaymentIdentifier
from electrum_ltc.transaction import PartialTxOutput
from electrum_ltc.bitcoin import opcodes, construct_script
from electrum_ltc.logging import Logger
from electrum_ltc.lnurl import LNURLError

from .qrtextedit import ScanQRTextEdit
from .completion_text_edit import CompletionTextEdit
from . import util
from .util import MONOSPACE_FONT

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


class PayToEdit(CompletionTextEdit, ScanQRTextEdit, Logger):

    def __init__(self, send_tab: 'SendTab'):
        CompletionTextEdit.__init__(self)
        ScanQRTextEdit.__init__(self, config=send_tab.config, setText=self._on_input_btn)
        Logger.__init__(self)
        self.send_tab = send_tab
        self.win = send_tab.window
        self.app = QApplication.instance()
        self.amount_edit = self.send_tab.amount_e
        self.setFont(QFont(MONOSPACE_FONT))
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

        self.c = None
        self.addPasteButton(setText=self._on_input_btn)
        self.textChanged.connect(self._on_text_changed)
        self.outputs = []  # type: List[PartialTxOutput]
        self.errors = []  # type: List[PayToLineError]
        self.disable_checks = False
        self.is_alias = False
        self.update_size()
        self.payto_scriptpubkey = None  # type: Optional[bytes]
        self.lightning_invoice = None
        self.previous_payto = ''

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setStyleSheet(frozen_style if b else normal_style)
        self.overlay_widget.setHidden(b)

    def setTextNoCheck(self, text: str):
        """Sets the text, while also ensuring the new value will not be resolved/checked."""
        self.previous_payto = text
        self.setText(text)

    def do_clear(self):
        self.disable_checks = False
        self.is_alias = False
        self.setText('')
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
            return bfh(bitcoin.address_to_script(address))
        except Exception:
            pass
        try:
            script = self.parse_script(x)
            return bfh(script)
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
                bfh(word)  # to test it is hex data
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
        self._check_text(full_check=True)

    def _on_text_changed(self):
        if self.app.clipboard().text() == self.toPlainText():
            # user likely pasted from clipboard
            self._check_text(full_check=True)
        else:
            self._check_text(full_check=False)

    def on_timer_check_text(self):
        if self.hasFocus():
            return
        self._check_text(full_check=True)

    def _check_text(self, *, full_check: bool):
        if self.previous_payto == str(self.toPlainText()).strip():
            return
        if full_check:
            self.previous_payto = str(self.toPlainText()).strip()
        self.errors = []
        if self.disable_checks:
            return
        # filter out empty lines
        lines = [i for i in self.lines() if i]

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
                self.errors.append(PayToLineError(line_content=data, exc=e))
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
                amount = self.amount_edit.get_amount()
                if amount is None:
                    return []
            self.outputs = [PartialTxOutput(scriptpubkey=self.payto_scriptpubkey, value=amount)]

        return self.outputs[:]

    def lines(self):
        return self.toPlainText().split('\n')

    def is_multiline(self):
        return len(self.lines()) > 1

    def paytomany(self):
        self.setTextNoCheck("\n\n\n")
        self.update_size()

    def update_size(self):
        docLineCount = self.document().lineCount()
        if self.cursorRect().right() + 1 >= self.overlay_widget.pos().x():
            # Add a line if we are under the overlay widget
            docLineCount += 1
        docHeight = docLineCount * self.fontSpacing

        h = docHeight + self.verticalMargins
        h = min(max(h, self.heightMin), self.heightMax)
        self.setMinimumHeight(int(h))
        self.setMaximumHeight(int(h))

        self.verticalScrollBar().setHidden(docHeight + self.verticalMargins < self.heightMax)

        # The scrollbar visibility can have changed so we update the overlay position here
        self._updateOverlayPos()

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
        self.setTextNoCheck(new_url)

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
