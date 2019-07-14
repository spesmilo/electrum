#!/usr/bin/env python3
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
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

import threading
from functools import partial

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QVBoxLayout, QLineEdit, QHBoxLayout, QLabel

from electrum.gui.qt.password_dialog import PasswordLayout, PW_PASSPHRASE
from electrum.gui.qt.util import (read_QIcon, WWLabel, OkButton, WindowModalDialog,
                                  Buttons, CancelButton, TaskThread, char_width_in_lineedit)

from electrum.i18n import _
from electrum.logging import Logger

from .plugin import OutdatedHwFirmwareException


# The trickiest thing about this handler was getting windows properly
# parented on macOS.
class QtHandlerBase(QObject, Logger):
    '''An interface between the GUI (here, QT) and the device handling
    logic for handling I/O.'''

    passphrase_signal = pyqtSignal(object, object)
    message_signal = pyqtSignal(object, object)
    error_signal = pyqtSignal(object, object)
    word_signal = pyqtSignal(object)
    clear_signal = pyqtSignal()
    query_signal = pyqtSignal(object, object)
    yes_no_signal = pyqtSignal(object)
    status_signal = pyqtSignal(object)

    def __init__(self, win, device):
        QObject.__init__(self)
        Logger.__init__(self)
        self.clear_signal.connect(self.clear_dialog)
        self.error_signal.connect(self.error_dialog)
        self.message_signal.connect(self.message_dialog)
        self.passphrase_signal.connect(self.passphrase_dialog)
        self.word_signal.connect(self.word_dialog)
        self.query_signal.connect(self.win_query_choice)
        self.yes_no_signal.connect(self.win_yes_no_question)
        self.status_signal.connect(self._update_status)
        self.win = win
        self.device = device
        self.dialog = None
        self.done = threading.Event()

    def top_level_window(self):
        return self.win.top_level_window()

    def update_status(self, paired):
        self.status_signal.emit(paired)

    def _update_status(self, paired):
        if hasattr(self, 'button'):
            button = self.button
            icon_name = button.icon_paired if paired else button.icon_unpaired
            button.setIcon(read_QIcon(icon_name))

    def query_choice(self, msg, labels):
        self.done.clear()
        self.query_signal.emit(msg, labels)
        self.done.wait()
        return self.choice

    def yes_no_question(self, msg):
        self.done.clear()
        self.yes_no_signal.emit(msg)
        self.done.wait()
        return self.ok

    def show_message(self, msg, on_cancel=None):
        self.message_signal.emit(msg, on_cancel)

    def show_error(self, msg, blocking=False):
        self.done.clear()
        self.error_signal.emit(msg, blocking)
        if blocking:
            self.done.wait()

    def finished(self):
        self.clear_signal.emit()

    def get_word(self, msg):
        self.done.clear()
        self.word_signal.emit(msg)
        self.done.wait()
        return self.word

    def get_passphrase(self, msg, confirm):
        self.done.clear()
        self.passphrase_signal.emit(msg, confirm)
        self.done.wait()
        return self.passphrase

    def passphrase_dialog(self, msg, confirm):
        # If confirm is true, require the user to enter the passphrase twice
        parent = self.top_level_window()
        d = WindowModalDialog(parent, _("Enter Passphrase"))
        if confirm:
            OK_button = OkButton(d)
            playout = PasswordLayout(msg=msg, kind=PW_PASSPHRASE, OK_button=OK_button)
            vbox = QVBoxLayout()
            vbox.addLayout(playout.layout())
            vbox.addLayout(Buttons(CancelButton(d), OK_button))
            d.setLayout(vbox)
            passphrase = playout.new_password() if d.exec_() else None
        else:
            pw = QLineEdit()
            pw.setEchoMode(2)
            pw.setMinimumWidth(200)
            vbox = QVBoxLayout()
            vbox.addWidget(WWLabel(msg))
            vbox.addWidget(pw)
            vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
            d.setLayout(vbox)
            passphrase = pw.text() if d.exec_() else None
        self.passphrase = passphrase
        self.done.set()

    def word_dialog(self, msg):
        dialog = WindowModalDialog(self.top_level_window(), "")
        hbox = QHBoxLayout(dialog)
        hbox.addWidget(QLabel(msg))
        text = QLineEdit()
        text.setMaximumWidth(12 * char_width_in_lineedit())
        text.returnPressed.connect(dialog.accept)
        hbox.addWidget(text)
        hbox.addStretch(1)
        dialog.exec_()  # Firmware cannot handle cancellation
        self.word = text.text()
        self.done.set()

    def message_dialog(self, msg, on_cancel):
        # Called more than once during signing, to confirm output and fee
        self.clear_dialog()
        title = _('Please check your {} device').format(self.device)
        self.dialog = dialog = WindowModalDialog(self.top_level_window(), title)
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(l)
        if on_cancel:
            dialog.rejected.connect(on_cancel)
            vbox.addLayout(Buttons(CancelButton(dialog)))
        dialog.show()

    def error_dialog(self, msg, blocking):
        self.win.show_error(msg, parent=self.top_level_window())
        if blocking:
            self.done.set()

    def clear_dialog(self):
        if self.dialog:
            self.dialog.accept()
            self.dialog = None

    def win_query_choice(self, msg, labels):
        self.choice = self.win.query_choice(msg, labels)
        self.done.set()

    def win_yes_no_question(self, msg):
        self.ok = self.win.question(msg)
        self.done.set()



from electrum.plugin import hook
from electrum.util import UserCancelled
from electrum.gui.qt.main_window import StatusBarButton

class QtPluginBase(object):

    @hook
    def load_wallet(self, wallet, window):
        for keystore in wallet.get_keystores():
            if not isinstance(keystore, self.keystore_class):
                continue
            if not self.libraries_available:
                message = keystore.plugin.get_library_not_available_message()
                window.show_error(message)
                return
            tooltip = self.device + '\n' + (keystore.label or 'unnamed')
            cb = partial(self.show_settings_dialog, window, keystore)
            button = StatusBarButton(read_QIcon(self.icon_unpaired), tooltip, cb)
            button.icon_paired = self.icon_paired
            button.icon_unpaired = self.icon_unpaired
            window.statusBar().addPermanentWidget(button)
            handler = self.create_handler(window)
            handler.button = button
            keystore.handler = handler
            keystore.thread = TaskThread(window, on_error=partial(self.on_task_thread_error, window, keystore))
            self.add_show_address_on_hw_device_button_for_receive_addr(wallet, keystore, window)
            # Trigger a pairing
            keystore.thread.add(partial(self.get_client, keystore))

    def on_task_thread_error(self, window, keystore, exc_info):
        e = exc_info[1]
        if isinstance(e, OutdatedHwFirmwareException):
            if window.question(e.text_ignore_old_fw_and_continue(), title=_("Outdated device firmware")):
                self.set_ignore_outdated_fw()
                # will need to re-pair
                devmgr = self.device_manager()
                def re_pair_device():
                    device_id = self.choose_device(window, keystore)
                    devmgr.unpair_id(device_id)
                    self.get_client(keystore)
                keystore.thread.add(re_pair_device)
            return
        else:
            window.on_error(exc_info)

    def choose_device(self, window, keystore):
        '''This dialog box should be usable even if the user has
        forgotten their PIN or it is in bootloader mode.'''
        device_id = self.device_manager().xpub_id(keystore.xpub)
        if not device_id:
            try:
                info = self.device_manager().select_device(self, keystore.handler, keystore)
            except UserCancelled:
                return
            device_id = info.device.id_
        return device_id

    def show_settings_dialog(self, window, keystore):
        device_id = self.choose_device(window, keystore)

    def add_show_address_on_hw_device_button_for_receive_addr(self, wallet, keystore, main_window):
        plugin = keystore.plugin
        receive_address_e = main_window.receive_address_e

        def show_address():
            addr = receive_address_e.text()
            keystore.thread.add(partial(plugin.show_address, wallet, addr, keystore))
        receive_address_e.addButton("eye1.png", show_address, _("Show on {}").format(plugin.device))
