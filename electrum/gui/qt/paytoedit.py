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
from decimal import Decimal

from PyQt5.QtGui import QFontMetrics

from electrum import bitcoin
from electrum.util import bfh
from electrum.transaction import TxOutput, push_script
from electrum.bitcoin import opcodes
from electrum.logging import Logger

from .qrtextedit import ScanQRTextEdit
from .completion_text_edit import CompletionTextEdit
from . import util

RE_ALIAS = r'(.*?)\s*\<([0-9A-Za-z]{1,})\>'

frozen_style = "QWidget {border:none;}"
normal_style = "QPlainTextEdit { }"


class PayToEdit(CompletionTextEdit, ScanQRTextEdit, Logger):

    def __init__(self, win):
        CompletionTextEdit.__init__(self)
        ScanQRTextEdit.__init__(self)
        Logger.__init__(self)
        self.win = win
        self.amount_edit = win.amount_e
        self.document().contentsChanged.connect(self.update_size)
        self.heightMin = 0
        self.heightMax = 150
        self.c = None
        self.textChanged.connect(self.check_text)
        self.outputs = []
        self.errors = []
        self.is_pr = False
        self.is_alias = False
        self.is_lightning = False
        self.update_size()
        self.payto_address = None
        self.previous_payto = ''

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setStyleSheet(frozen_style if b else normal_style)
        for button in self.buttons:
            button.setHidden(b)

    def setGreen(self):
        self.setStyleSheet(util.ColorScheme.GREEN.as_stylesheet(True))

    def setExpired(self):
        self.setStyleSheet(util.ColorScheme.RED.as_stylesheet(True))

    def parse_address_and_amount(self, line):
        x, y = line.split(',')
        out_type, out = self.parse_output(x)
        amount = self.parse_amount(y)
        return TxOutput(out_type, out, amount)

    def parse_output(self, x):
        try:
            address = self.parse_address(x)
            return bitcoin.TYPE_ADDRESS, address
        except:
            script = self.parse_script(x)
            return bitcoin.TYPE_SCRIPT, script

    def parse_script(self, x):
        script = ''
        for word in x.split():
            if word[0:3] == 'OP_':
                opcode_int = opcodes[word]
                assert opcode_int < 256  # opcode is single-byte
                script += bitcoin.int_to_hex(opcode_int)
            else:
                bfh(word)  # to test it is hex data
                script += push_script(word)
        return script

    def parse_amount(self, x):
        if x.strip() == '!':
            return '!'
        p = pow(10, self.amount_edit.decimal_point())
        return int(p * Decimal(x.strip()))

    def parse_address(self, line):
        r = line.strip()
        m = re.match('^'+RE_ALIAS+'$', r)
        address = str(m.group(2) if m else r)
        assert bitcoin.is_address(address)
        return address

    def check_text(self):
        self.errors = []
        if self.is_pr:
            return
        # filter out empty lines
        lines = [i for i in self.lines() if i]
        outputs = []
        total = 0
        self.payto_address = None
        if len(lines) == 1:
            data = lines[0]
            if data.startswith("bitcoin:"):
                self.win.pay_to_URI(data)
                return
            l = data.lower()
            if l.startswith("lightning:"):
                data = l[10:]
            if data.startswith("ln"):
                self.win.parse_lightning_invoice(data)
                self.lightning_invoice = data
                return
            try:
                self.payto_address = self.parse_output(data)
            except:
                pass
            if self.payto_address:
                self.win.lock_amount(False)
                return

        is_max = False
        for i, line in enumerate(lines):
            try:
                output = self.parse_address_and_amount(line)
            except:
                self.errors.append((i, line.strip()))
                continue

            outputs.append(output)
            if output.value == '!':
                is_max = True
            else:
                total += output.value

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
            self.outputs = [TxOutput(_type, addr, amount)]

        return self.outputs[:]

    def lines(self):
        return self.toPlainText().split('\n')

    def is_multiline(self):
        return len(self.lines()) > 1

    def paytomany(self):
        self.setText("\n\n\n")
        self.update_size()

    def update_size(self):
        lineHeight = QFontMetrics(self.document().defaultFont()).height()
        docHeight = self.document().size().height()
        h = docHeight * lineHeight + 11
        h = min(max(h, self.heightMin), self.heightMax)
        self.setMinimumHeight(h)
        self.setMaximumHeight(h)
        self.verticalScrollBar().hide()

    def qr_input(self):
        data = super(PayToEdit,self).qr_input()
        if data.startswith("bitcoin:"):
            self.win.pay_to_URI(data)
            # TODO: update fee

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
        if parts and len(parts) > 0 and bitcoin.is_address(parts[0]):
            return
        try:
            data = self.win.contacts.resolve(key)
        except Exception as e:
            self.logger.info(f'error resolving address/alias: {repr(e)}')
            return
        if not data:
            return
        self.is_alias = True

        address = data.get('address')
        name = data.get('name')
        new_url = key + ' <' + address + '>'
        self.setText(new_url)
        self.previous_payto = new_url

        #if self.win.config.get('openalias_autoadd') == 'checked':
        self.win.contacts[key] = ('openalias', name)
        self.win.contact_list.update()

        self.setFrozen(True)
        if data.get('type') == 'openalias':
            self.validated = data.get('validated')
            if self.validated:
                self.setGreen()
            else:
                self.setExpired()
        else:
            self.validated = None
