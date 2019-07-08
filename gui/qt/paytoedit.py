#!/usr/bin/env python3
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

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import QCompleter, QPlainTextEdit
from .qrtextedit import ScanQRTextEdit

import re
import sys
from decimal import Decimal as PyDecimal  # Qt 5.12 also exports Decimal
from electroncash import bitcoin
from electroncash.address import Address, ScriptOutput
from electroncash import networks
from electroncash.util import PrintError
from electroncash.contacts import Contact

from . import util

RE_ALIAS = r'^(.*?)\s*<\s*([0-9A-Za-z:]{26,})\s*>$'
RE_COINTEXT = r'^\s*cointext:([-+() 0-9]+)\s*$'

RX_ALIAS = re.compile(RE_ALIAS)
RX_COINTEXT = re.compile(RE_COINTEXT, re.I)

frozen_style = "PayToEdit { border:none;}"
normal_style = "PayToEdit { }"

class PayToEdit(PrintError, ScanQRTextEdit):

    def __init__(self, win):
        ScanQRTextEdit.__init__(self)
        self.win = win
        self.amount_edit = win.amount_e
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
        self.textChanged.connect(self.check_text)
        self.outputs = []
        self.errors = []
        self.is_pr = False
        self.is_alias = False
        self.scan_f = win.pay_to_URI
        self.update_size()
        self.payto_address = None
        self.cointext = None

        self.previous_payto = ''

        if sys.platform in ('darwin',):
            # See issue #1411 -- on *some* macOS systems, clearing the
            # payto field with setText('') ends up leaving "ghost" pixels
            # in the field, which look like the text that was just there.
            # This situation corrects itself eventually if another repaint
            # is issued to the widget. I couldn't figure out why it is happening
            # and the workaround is simply to force a repaint using this trick
            # for all textChanged events. -Calin
            self.textChanged.connect(self.repaint)

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setStyleSheet(frozen_style if b else normal_style)
        self.overlay_widget.setHidden(b)

    def setGreen(self):
        self.setStyleSheet(util.ColorScheme.GREEN.as_stylesheet(True))

    def setExpired(self):
        self.setStyleSheet(util.ColorScheme.RED.as_stylesheet(True))

    def parse_address_and_amount(self, line):
        x, y = line.split(',')
        out_type, out = self.parse_output(x)
        amount = self.parse_amount(y)
        return out_type, out, amount

    @classmethod
    def parse_output(cls, x):
        try:
            address = cls.parse_address(x)
            return bitcoin.TYPE_ADDRESS, address
        except:
            return bitcoin.TYPE_SCRIPT, ScriptOutput.from_string(x)

    @staticmethod
    def parse_cointext(txt):
        ''' Returns a non-empty string which is the phone number in a cointext:
        style pseudo-url, if x matches the cointext re (eg: cointext:NUMBERS),
        otherwise returns None. '''
        m = RX_COINTEXT.match(txt)
        if m: return ''.join(x for x in m[1].strip() if x.isdigit()) or None
        return None

    @staticmethod
    def parse_address(line):
        r = line.strip()
        m = RX_ALIAS.match(r)
        address = m.group(2) if m else r
        return Address.from_string(address)

    def parse_amount(self, x):
        if x.strip() == '!':
            return '!'
        p = pow(10, self.amount_edit.decimal_point())
        return int(p * PyDecimal(x.strip()))

    def check_text(self):
        self.errors = []
        if self.is_pr:
            return
        # filter out empty lines
        lines = [i for i in self.lines() if i]
        outputs = []
        total = 0
        self.payto_address = None
        self.cointext = None
        if len(lines) == 1:
            data = lines[0]
            if data.lower().startswith(networks.net.CASHADDR_PREFIX + ":"):
                self.scan_f(data)
                return
            try:
                self.payto_address = self.parse_output(data)
            except:
                try:
                    self.cointext = self.parse_cointext(data)
                except:
                    pass
            if self.payto_address or self.cointext:
                self.win.lock_amount(False)
                return

        is_max = False
        for i, line in enumerate(lines):
            try:
                _type, to_address, amount = self.parse_address_and_amount(line)
            except:
                self.errors.append((i, line.strip()))
                continue

            outputs.append((_type, to_address, amount))
            if amount == '!':
                is_max = True
            else:
                total += amount

        self.win.max_button.setChecked(is_max)
        self.outputs = outputs
        self.payto_address = None

        if self.win.max_button.isChecked():
            self.win.do_update_fee()
        else:
            self.amount_edit.setAmount(total if outputs else None)
            self.win.lock_amount(total or len(lines)>1)

    def get_errors(self):
        return self.errors

    def get_recipient(self):
        return self.payto_address

    def get_outputs(self, is_max):
        if self.payto_address:
            if is_max:
                amount = '!'
            else:
                amount = self.amount_edit.get_amount()

            _type, addr = self.payto_address
            self.outputs = [(_type, addr, amount)]

        return self.outputs[:]

    def lines(self):
        return self.toPlainText().split('\n')

    def is_multiline(self):
        return len(self.lines()) > 1

    def paytomany(self):
        self.setText("\n\n\n")
        self.update_size()

    def update_size(self):
        docLineCount = self.document().lineCount()
        if self.cursorRect().right() + 1 >= self.overlay_widget.pos().x():
            # Add a line if we are under the overlay widget
            docLineCount += 1
        docHeight = docLineCount * self.fontSpacing

        h = docHeight + self.verticalMargins
        h = min(max(h, self.heightMin), self.heightMax)

        self.setMinimumHeight(h)
        self.setMaximumHeight(h)

        self.verticalScrollBar().setHidden(docHeight + self.verticalMargins < self.heightMax)

        # The scrollbar visibility can have changed so we update the overlay position here
        self._updateOverlayPos()


    def setCompleter(self, completer):
        self.c = completer
        self.c.setWidget(self)
        self.c.setCompletionMode(QCompleter.PopupCompletion)
        self.c.activated.connect(self.insertCompletion)


    def insertCompletion(self, completion):
        if self.c.widget() != self:
            return
        tc = self.textCursor()
        extra = len(completion) - len(self.c.completionPrefix())
        tc.movePosition(QTextCursor.Left)
        tc.movePosition(QTextCursor.EndOfWord)
        tc.insertText(completion[-extra:])
        self.setTextCursor(tc)


    def textUnderCursor(self):
        tc = self.textCursor()
        tc.select(QTextCursor.WordUnderCursor)
        return tc.selectedText()


    def keyPressEvent(self, e):
        if self.isReadOnly():
            return

        if self.c.popup().isVisible():
            if e.key() in [Qt.Key_Enter, Qt.Key_Return]:
                e.ignore()
                return

        if e.key() in [Qt.Key_Tab]:
            e.ignore()
            return

        if e.key() in [Qt.Key_Down, Qt.Key_Up] and not self.is_multiline():
            e.ignore()
            return

        QPlainTextEdit.keyPressEvent(self, e)

        ctrlOrShift = e.modifiers() and (Qt.ControlModifier or Qt.ShiftModifier)
        if self.c is None or (ctrlOrShift and not e.text()):
            return

        eow = "~!@#$%^&*()_+{}|:\"<>?,./;'[]\\-="
        hasModifier = (e.modifiers() != Qt.NoModifier) and not ctrlOrShift
        completionPrefix = self.textUnderCursor()

        if hasModifier or not e.text() or len(completionPrefix) < 1 or eow.find(e.text()[-1]) >= 0:
            self.c.popup().hide()
            return

        if completionPrefix != self.c.completionPrefix():
            self.c.setCompletionPrefix(completionPrefix)
            self.c.popup().setCurrentIndex(self.c.completionModel().index(0, 0))

        cr = self.cursorRect()
        cr.setWidth(self.c.popup().sizeHintForColumn(0) + self.c.popup().verticalScrollBar().sizeHint().width())
        self.c.complete(cr)

    def qr_input(self):
        def _on_qr_success(result):
            if result and result.startswith(networks.net.CASHADDR_PREFIX + ":"):
                self.scan_f(result)
                # TODO: update fee
        super(PayToEdit,self).qr_input(_on_qr_success)

    def resolve(self):
        self.is_alias = False
        if self.hasFocus():
            return
        if self.is_multiline():  # only supports single line entries atm
            return
        if self.is_pr:
            return
        key = str(self.toPlainText())
        key = key.strip()  # strip whitespaces
        if key == self.previous_payto:
            return
        self.previous_payto = key
        if not (('.' in key) and (not '<' in key) and (not ' ' in key)):
            return
        parts = key.split(sep=',')  # assuming single line
        if parts and len(parts) > 0 and Address.is_valid(parts[0]):
            return
        try:
            data = self.win.contacts.resolve(key)
        except Exception as e:
            self.print_error(f'error resolving alias: {repr(e)}')
            return
        if not data:
            return
        self.is_alias = True

        address = data.get('address')
        name = data.get('name')

        address_str = None
        if isinstance(address, str):
            address_str = address
        elif isinstance(address, Address):
            address_str = address.to_ui_string()
        else:
            raise RuntimeError('unknown address type')

        new_url = key + ' <' + address_str + '>'
        self.setText(new_url)
        self.previous_payto = new_url

        self.win.contacts.add(Contact(name=name, address=key, type='openalias'), unique=True)
        self.win.contact_list.on_update()

        self.setFrozen(True)
        if data.get('type') == 'openalias':
            self.validated = data.get('validated')
            if self.validated:
                self.setGreen()
            else:
                self.setExpired()
        else:
            self.validated = None
