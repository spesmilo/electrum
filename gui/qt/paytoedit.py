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
from electroncash import web

from . import util
from . import cashacctqt

RE_ALIAS = r'^(.*?)\s*<\s*([0-9A-Za-z:]{26,})\s*>$'
RE_COINTEXT = r'^\s*cointext:([-+() 0-9]+)\s*$'
RE_AMT = r'^.*\s*,\s*([0-9,.]*)\s*$'

RX_ALIAS = re.compile(RE_ALIAS)
RX_COINTEXT = re.compile(RE_COINTEXT, re.I)
RX_AMT = re.compile(RE_AMT)

frozen_style = "PayToEdit { border:none;}"
normal_style = "PayToEdit { }"

class PayToEdit(PrintError, ScanQRTextEdit):

    def __init__(self, win):
        from .main_window import ElectrumWindow
        assert isinstance(win, ElectrumWindow) and win.amount_e and win.wallet
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
        self.is_alias = self.validated = False
        self.scan_f = win.pay_to_URI
        self.update_size()
        self.payto_address = None
        self.cointext = None
        self._ca_busy = False

        self.previous_payto = ''
        self.preivous_ca_could_not_verify = set()

        if sys.platform in ('darwin',):
            # See issue #1411 -- on *some* macOS systems, clearing the
            # payto field with setText('') ends up leaving "ghost" pixels
            # in the field, which look like the text that was just there.
            # This situation corrects itself eventually if another repaint
            # is issued to the widget. I couldn't figure out why it is happening
            # and the workaround is simply to force a repaint using this trick
            # for all textChanged events. -Calin
            self.textChanged.connect(self.repaint)

        self.verticalScrollBar().valueChanged.connect(self._vertical_scroll_bar_changed)

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
            lc_data = data.lower()
            if any(lc_data.startswith(scheme + ":") for scheme in web.parseable_schemes()):
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

    def _vertical_scroll_bar_changed(self, value):
        ''' Fix for bug #1521 -- Contents of payto edit can disappear
        unexpectedly when selecting with mouse on a single-liner. '''
        vb = self.verticalScrollBar()
        docLineCount = self.document().lineCount()
        if docLineCount == 1 and vb.maximum()-vb.minimum() == 1 and value != vb.minimum():
            self.print_error(f"Workaround #1521: forcing scrollbar value back to {vb.minimum()} for single line payto_e.")
            vb.setValue(vb.minimum())

    def setCompleter(self, completer):
        self.c = completer
        self.c.setWidget(self)
        self.c.setCompletionMode(QCompleter.PopupCompletion)
        self.c.activated.connect(self.insertCompletion)


    def insertCompletion(self, completion):
        if self.c.widget() != self:
            return
        tc = self.textCursor()
        # new! because of the way Cash Accounts works we must delete the whole
        # line under cursor and insert the full completion. This ends up
        # working reasonably well.
        tc.select(QTextCursor.LineUnderCursor)
        tc.removeSelectedText()
        tc.insertText(completion + " ")
        self.setTextCursor(tc)


    def textUnderCursor(self):
        tc = self.textCursor()
        tc.select(QTextCursor.LineUnderCursor)
        return tc.selectedText()

    def keyPressEvent(self, e):
        if self.isReadOnly() or not self.hasFocus():
            e.ignore()
            return

        if self.c.popup().isVisible():
            if e.key() in [Qt.Key_Enter, Qt.Key_Return]:
                e.ignore()
                return

        if e.key() in [Qt.Key_Tab, Qt.Key_Backtab]:
            e.ignore()
            return

        if e.key() in [Qt.Key_Down, Qt.Key_Up] and not self.is_multiline():
            e.ignore()
            return

        super().keyPressEvent(e)

        ctrlOrShift = e.modifiers() and (Qt.ControlModifier or Qt.ShiftModifier)
        if self.c is None or (ctrlOrShift and not e.text()):
            return

        hasModifier = (e.modifiers() != Qt.NoModifier) and not ctrlOrShift
        completionPrefix = self.textUnderCursor()

        if hasModifier or not e.text() or len(completionPrefix) < 1:
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

    def _resolve_open_alias(self, *, force_if_has_focus=False):
        prev_vals = self.is_alias, self.validated  # used only if early return due to unchanged text below
        self.is_alias, self.validated = False, False
        if not force_if_has_focus and self.hasFocus():
            return
        if self.is_multiline():  # only supports single line entries atm
            return
        if self.is_pr:
            return
        key = str(self.toPlainText())
        key = key.strip()  # strip whitespaces
        if key == self.previous_payto:
            # unchanged, restore previous state, abort early.
            self.is_alias, self.validated = prev_vals
            return self.is_alias
        self.previous_payto = key
        if '.' not in key or '<' in key or ' ' in key:
            # not an openalias or an openalias with extra info in it, bail..!
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

        address = data.get('address')
        name = data.get('name')
        _type = data.get('type')

        if _type != 'openalias':
            return

        address_str = None
        if isinstance(address, str):
            address_str = address
        elif isinstance(address, Address):
            address_str = address.to_ui_string()
        else:
            raise RuntimeError('unknown address type')

        self.is_alias = True

        new_url = key + ' <' + address_str + '>'
        self.setText(new_url)
        self.previous_payto = new_url

        self.win.contacts.add(Contact(name=name, address=key, type='openalias'), unique=True)
        self.win.contact_list.update()

        self.setFrozen(True)

        self.validated = bool(data.get('validated'))
        if self.validated:
            self.setGreen()
        else:
            self.setExpired()

        return True

    _rx_split = re.compile(r'(\s+)|(\s*,\s*)')  # split on ',' or on <whitespace>
    def _resolve_cash_accounts(self, skip_verif=False):
        ''' This should be called if not hasFocus(). Will run through the
        text in the payto and rewrite any verified cash accounts we find. '''
        wallet = self.win.wallet
        lines = self.lines()
        lines_orig = lines.copy()
        need_verif = set()
        for n, line in enumerate(lines):
            line = line.strip()
            parts = self._rx_split.split(line, maxsplit=1)
            if not parts:
                # nothing there..
                continue
            ca_string = parts[0]
            while ca_string.endswith(','):
                # string trailing ',', if any
                ca_string = ca_string[:-1]
                parts.insert(1, ',') # push stripped ',' into the 'parts' list
            ca_tup = wallet.cashacct.parse_string(ca_string)
            if not ca_tup:
                # not a cashaccount
                continue
            # strip the '<' piece... in case user edited and stale <address> is present
            m = RX_AMT.match(line)
            if m:
                parts = [ca_string, ',', m.group(1)]  # strip down to just ca_string + , + amount
            else:
                parts = [ca_string]  # strip down to JUST ca_string
            ca_info = wallet.cashacct.get_verified(ca_string)
            if ca_info:
                resolved = wallet.cashacct.fmt_info(ca_info) + " " + ca_info.emoji + " <" + ca_info.address.to_ui_string() + ">"
                lines[n] = line = resolved + " ".join(parts[1:])  # rewrite line, putting the resolved cash account + <address> at the beginning, amount at the end (if any)
            else:
                lines[n] = line = " ".join(parts)  # rewrite line, possibly stripping <> address here
                # user specified cash account not found.. potentially kick off verify
                need_verif.add(ca_tup[1])
        if (need_verif and not skip_verif
                and need_verif != self.preivous_ca_could_not_verify  # this makes it so we don't keep retrying when verif fails due to bad cashacct spec
                and wallet.network and wallet.network.is_connected()):
            # Note: verify_multiple_blocks here throws up a waiting dialog
            # and spawns a local event loop, so this call path may block for
            # up to 10 seconds. The waiting dialog is however cancellable with
            # the ESC key, so it's not too bad UX-wise. Just bear in mind that
            # the local event loop can cause this code path to execute again
            # if not careful (see the self._ca_busy flag documented inside
            # function `resolve` below).
            res = cashacctqt.verify_multiple_blocks(list(need_verif), self.win, wallet)
            if res is None:
                # user abort
                return
            elif res > 0:
                # got some verifications...
                # call self again, to redo the payto edit with the verified pieces
                self._resolve_cash_accounts(skip_verif=True)
                return # above call takes care of rewriting self, so just return early

        self.preivous_ca_could_not_verify = need_verif

        if lines_orig != lines:
            # set text only if we changed something since setText kicks off more
            # parsing elsewehre in this class on textChanged
            self.setText('\n'.join(lines))


    def resolve(self, *, force_if_has_focus = False):
        ''' This is called by the main window periodically from a timer. See
        main_window.py function `timer_actions`.

        It will resolve OpenAliases in the send tab and will also alternatively
        resolve Cash Accounts by attempting to verify them in the background
        and rewriting the payto field with completed information.

        Note that OpenAlias is assumed to be a single-line payto. Also note
        that OpenAlias blocks the GUI thread whereas Cash Accounts does this
        by throwing up a WaitingDialog (which may be aborted/cancelled and
        doesn't lock the UI event loop).

        TODO/FIXME: Make OpenAlias also use a Waiting Dialog

        Cash Accounts supports full multiline with mixed address/cash accounts
        in the payto lines.

        OpenAlias and other payto types are mutually exclusive (that is, if
        OpenAlias, you are such with 1 payee which is OpenAlias, and cannot
        mix with regular and/or Cash Accounts).

        Note that this mechanism was piggy-backed onto code we inherited from
        Electrum.  It's my opinion that this mechanism is a bit complex for what
        it is since it requires the progremmer to spend considerable time
        reading this code to modfy/enhance it.  But we will work with that
        we have for now. -Calin '''
        if self._ca_busy:
            # See the comment at the end of this function about why this flag is
            # here.
            return
        if self._resolve_open_alias(force_if_has_focus=force_if_has_focus):
            # it was an openalias -- abort and don't proceed to cash account
            # resolve
            return
        if (not force_if_has_focus and self.hasFocus()) or self.is_pr:
            # PR by definition can't proceed.
            # We also don't proceed if user is still editing.
            return

        # self._ca_busy is a reentrancy prevention flag, needed because
        # _resolve_cash_acconts causes a local event loop to happen in some
        # cases as it resolves cash accounts by throwing up a WaitingDialog,
        # which may cause the timer that calls this function to fire again.
        # The below mechanism prevents that situation as it may lead to
        # multiple "Verifying, please wait... " dialogs on top of each other.
        try:
            self._ca_busy = True
            self._resolve_cash_accounts()
        finally:
            self._ca_busy = False
