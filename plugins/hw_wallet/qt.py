#!/usr/bin/env python2
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import threading

from PyQt4.Qt import QVBoxLayout, QLabel, SIGNAL
from electrum_gui.qt.password_dialog import PasswordDialog, PW_PASSPHRASE
from electrum_gui.qt.util import *

from electrum.i18n import _
from electrum.util import PrintError
from electrum.wallet import BIP44_Wallet

# The trickiest thing about this handler was getting windows properly
# parented on MacOSX.
class QtHandlerBase(QObject, PrintError):
    '''An interface between the GUI (here, QT) and the device handling
    logic for handling I/O.'''

    qcSig = pyqtSignal(object, object)
    ynSig = pyqtSignal(object)

    def __init__(self, win, device):
        super(QtHandlerBase, self).__init__()
        win.connect(win, SIGNAL('clear_dialog'), self.clear_dialog)
        win.connect(win, SIGNAL('error_dialog'), self.error_dialog)
        win.connect(win, SIGNAL('message_dialog'), self.message_dialog)
        win.connect(win, SIGNAL('passphrase_dialog'), self.passphrase_dialog)
        win.connect(win, SIGNAL('word_dialog'), self.word_dialog)
        self.qcSig.connect(self.win_query_choice)
        self.ynSig.connect(self.win_yes_no_question)
        self.win = win
        self.device = device
        self.dialog = None
        self.done = threading.Event()

    def top_level_window(self):
        return self.win.top_level_window()

    def watching_only_changed(self):
        self.win.emit(SIGNAL('watching_only_changed'))

    def query_choice(self, msg, labels):
        self.done.clear()
        self.qcSig.emit(msg, labels)
        self.done.wait()
        return self.choice

    def yes_no_question(self, msg):
        self.done.clear()
        self.ynSig.emit(msg)
        self.done.wait()
        return self.ok

    def show_message(self, msg, on_cancel=None):
        self.win.emit(SIGNAL('message_dialog'), msg, on_cancel)

    def show_error(self, msg):
        self.win.emit(SIGNAL('error_dialog'), msg)

    def finished(self):
        self.win.emit(SIGNAL('clear_dialog'))

    def get_word(self, msg):
        self.done.clear()
        self.win.emit(SIGNAL('word_dialog'), msg)
        self.done.wait()
        return self.word

    def get_passphrase(self, msg):
        self.done.clear()
        self.win.emit(SIGNAL('passphrase_dialog'), msg)
        self.done.wait()
        return self.passphrase

    def passphrase_dialog(self, msg):
        d = PasswordDialog(self.top_level_window(), None, msg, PW_PASSPHRASE)
        confirmed, p, passphrase = d.run()
        if confirmed:
            passphrase = BIP44_Wallet.normalize_passphrase(passphrase)
        self.passphrase = passphrase
        self.done.set()

    def word_dialog(self, msg):
        dialog = WindowModalDialog(self.top_level_window(), "")
        hbox = QHBoxLayout(dialog)
        hbox.addWidget(QLabel(msg))
        text = QLineEdit()
        text.setMaximumWidth(100)
        text.returnPressed.connect(dialog.accept)
        hbox.addWidget(text)
        hbox.addStretch(1)
        dialog.exec_()  # Firmware cannot handle cancellation
        self.word = unicode(text.text())
        self.done.set()

    def message_dialog(self, msg, on_cancel):
        # Called more than once during signing, to confirm output and fee
        self.clear_dialog()
        title = _('Please check your %s device') % self.device
        self.dialog = dialog = WindowModalDialog(self.top_level_window(), title)
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(l)
        if on_cancel:
            dialog.rejected.connect(on_cancel)
            vbox.addLayout(Buttons(CancelButton(dialog)))
        dialog.show()

    def error_dialog(self, msg):
        self.win.show_error(msg, parent=self.top_level_window())

    def clear_dialog(self):
        if self.dialog:
            self.dialog.accept()
            self.dialog = None

    def win_query_choice(self, msg, labels):
        self.choice = self.win.query_choice(msg, labels)
        self.done.set()

    def win_yes_no_question(self, msg):
        self.ok = self.top_level_window().question(msg)
        self.done.set()
