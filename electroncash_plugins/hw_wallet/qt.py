#!/usr/bin/env python3
# -*- mode: python3 -*-
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

from PyQt5.QtWidgets import QVBoxLayout, QLabel
from electroncash_gui.qt.password_dialog import PasswordDialog, PW_PASSPHRASE
from electroncash_gui.qt.util import *

from electroncash.i18n import _
from electroncash.util import PrintError

# The trickiest thing about this handler was getting windows properly
# parented on MacOSX.
class QtHandlerBase(QObject, PrintError):
    '''An interface between the GUI (here, Qt) and the device handling
    logic for handling I/O.'''

    passphrase_signal = pyqtSignal(object, object)
    message_signal = pyqtSignal(object, object)
    error_signal = pyqtSignal(object)
    warning_signal = pyqtSignal(object)
    word_signal = pyqtSignal(object)
    clear_signal = pyqtSignal()
    query_signal = pyqtSignal(object, object)
    yes_no_signal = pyqtSignal(object)
    status_signal = pyqtSignal(object)

    def __init__(self, win, device):
        super(QtHandlerBase, self).__init__()
        self.clear_signal.connect(self.clear_dialog)
        self.error_signal.connect(self.error_dialog)
        self.warning_signal.connect(self.warning_dialog)
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
        button = self.button
        icon = button.icon_paired if paired else button.icon_unpaired
        button.setIcon(QIcon(icon))

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

    def show_error(self, msg):
        self.error_signal.emit(msg)

    def show_warning(self, msg):
        self.done.clear()
        self.warning_signal.emit(msg)
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
        if confirm:
            d = PasswordDialog(parent, None, msg, PW_PASSPHRASE)
            confirmed, p, passphrase = d.run()
        else:
            d = WindowModalDialog(parent, _("Enter Passphrase"))
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
        text.setMaximumWidth(100)
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

    def error_dialog(self, msg):
        self.win.show_error(msg, parent=self.top_level_window())

    def warning_dialog(self, msg):
        self.win.show_warning(msg, parent=self.top_level_window())
        self.done.set()

    def clear_dialog(self):
        if self.dialog:
            try: self.dialog.accept()
            except RuntimeError: pass  # closes #1437. Yes, this is a band-aid but it's clean-up code anyway and so it doesn't matter. I also was unable to track down how it could ever happen.
            self.dialog = None

    def win_query_choice(self, msg, labels):
        self.choice = self.win.query_choice(msg, labels)
        self.done.set()

    def win_yes_no_question(self, msg):
        self.ok = self.win.question(msg)
        self.done.set()


import sys, queue
from electroncash.plugins import hook
from electroncash.util import UserCancelled
from electroncash_gui.qt.main_window import StatusBarButton

class ThreadJob_TaskThread_Facade(TaskThread):
    ''' This class is really a ThreadJob intended to mimic the TaskThread's
    semantics. (Which we need since it can send signals/callbacks to the GUI
    thread).

    Despite this class inheriting from QThread it does *not* run in its own
    thread, but instead runs in the Plugins DaemonThread.

    It runs in the 'Plugins' DaemonThread as that's the safest place to put
    operations that talk to the hardware wallet due to various race condition
    issues on platforms such as MacOS.  See #1598.

    (The Plugins thread already talks to the HW wallets because of the DeviceMgr
    class, so we must also live on that same thread). '''
    def __init__(self, plugin, on_error=None, *, name=None):
        super().__init__(parent=None, on_error=on_error, name=name)
        self.plugin = plugin
        self.plugin.parent.add_jobs([self])  # add self to Plugins thread
        self.print_error("Started")

    def start(self):
        ''' Overrides base; is a no-op since we do not want to actually
        start the QThread object '''

    def run(self):
        ''' Overrides base. This follows the ThreadJob API -- is called every
        100ms in a loop from the Plugins DaemonThread. '''
        while True:
            try:
                task = self.tasks.get_nowait()
                if not task:
                    return
            except queue.Empty:
                return
            try:
                result = task.task()
                self.doneSig.emit(result, task.cb_done, task.cb_success)
            except:
                self.doneSig.emit(sys.exc_info(), task.cb_done, task.cb_error)

    def stop(self, *args, **kwargs):
        ''' Overrides base. Remove us from DaemonThread jobs. '''
        try:
            self.plugin.parent.remove_jobs([self])
            self.print_error("Stopped")
        except ValueError:
            ''' Was already removed, silently ignore error. '''


class QtPluginBase(object):

    @hook
    def load_wallet(self, wallet, window):
        for i, keystore in enumerate(wallet.get_keystores()):
            if not isinstance(keystore, self.keystore_class):
                continue
            if not self.libraries_available:
                if hasattr(self, 'libraries_available_message'):
                    message = self.libraries_available_message + '\n'
                else:
                    message = _("Cannot find python library for") + " '{}'.\n".format(self.name)
                message += _("Make sure you install it with python3")
                window.show_error(message)
                return
            tooltip = self.device + '\n' + (keystore.label or 'unnamed')
            cb = partial(self.show_settings_dialog, window, keystore)
            button = StatusBarButton(QIcon(self.icon_unpaired), tooltip, cb)
            button.icon_paired = self.icon_paired
            button.icon_unpaired = self.icon_unpaired
            window.statusBar().addPermanentWidget(button)
            handler = self.create_handler(window)
            handler.button = button
            keystore.handler = handler
            keystore.thread = ThreadJob_TaskThread_Facade(self, window.on_error, name = wallet.diagnostic_name() + f'/keystore{i}')
            # Trigger a pairing
            keystore.thread.add(partial(self.get_client, keystore))

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
        try:
            device_id = self.choose_device(window, keystore)
        except:
            window.on_error(sys.exc_info())
