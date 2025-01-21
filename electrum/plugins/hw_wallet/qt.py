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
from typing import TYPE_CHECKING, Union, Optional, Sequence, Tuple

from PyQt6.QtCore import QObject, pyqtSignal, Qt
from PyQt6.QtWidgets import QVBoxLayout, QLineEdit, QHBoxLayout, QLabel

from electrum.gui.qt.password_dialog import PasswordLayout, PW_PASSPHRASE
from electrum.gui.qt.util import (read_QIcon, WWLabel, OkButton, WindowModalDialog,
                                  Buttons, CancelButton, TaskThread, char_width_in_lineedit,
                                  PasswordLineEdit)
from electrum.gui.qt.main_window import StatusBarButton
from electrum.gui.qt.util import read_QIcon_from_bytes

from electrum.i18n import _
from electrum.logging import Logger
from electrum.util import UserCancelled, UserFacingException
from electrum.plugin import hook, DeviceUnpairableError

from .plugin import OutdatedHwFirmwareException, HW_PluginBase, HardwareHandlerBase

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.keystore import Hardware_KeyStore
    from electrum.gui.qt import ElectrumWindow
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard


# The trickiest thing about this handler was getting windows properly
# parented on macOS.
class QtHandlerBase(HardwareHandlerBase, QObject, Logger):
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

    def __init__(self, win: Union['ElectrumWindow', 'QENewWalletWizard'], device: str):
        QObject.__init__(self)
        Logger.__init__(self)
        assert win.gui_thread == threading.current_thread(), 'must be called from GUI thread'
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
            icon_bytes = button.icon_paired if paired else button.icon_unpaired
            icon = read_QIcon_from_bytes(icon_bytes)
            button.setIcon(icon)

    def query_choice(self, msg: str, labels: Sequence[Tuple]):
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
            passphrase = playout.new_password() if d.exec() else None
        else:
            pw = PasswordLineEdit()
            pw.setMinimumWidth(200)
            vbox = QVBoxLayout()
            vbox.addWidget(WWLabel(msg))
            vbox.addWidget(pw)
            vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
            d.setLayout(vbox)
            passphrase = pw.text() if d.exec() else None
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
        dialog.exec()  # Firmware cannot handle cancellation
        self.word = text.text()
        self.done.set()

    MESSAGE_DIALOG_TITLE = None  # type: Optional[str]
    def message_dialog(self, msg, on_cancel=None):
        self.clear_dialog()
        title = self.MESSAGE_DIALOG_TITLE
        if title is None:
            title = _('Please check your {} device').format(self.device)
        self.dialog = dialog = WindowModalDialog(self.top_level_window(), title)
        label = QLabel(msg)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(label)
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

    def win_query_choice(self, msg: str, labels: Sequence[Tuple]):
        try:
            self.choice = self.win.query_choice(msg, labels)
        except UserCancelled:
            self.choice = None
        self.done.set()

    def win_yes_no_question(self, msg):
        self.ok = self.win.question(msg)
        self.done.set()


class QtPluginBase(object):

    @hook
    def load_wallet(self: Union['QtPluginBase', HW_PluginBase], wallet: 'Abstract_Wallet', window: 'ElectrumWindow'):
        relevant_keystores = [keystore for keystore in wallet.get_keystores()
                              if isinstance(keystore, self.keystore_class)]
        if not relevant_keystores:
            return
        for keystore in relevant_keystores:
            if not self.libraries_available:
                message = keystore.plugin.get_library_not_available_message()
                window.show_error(message)
                return
            tooltip = self.device + '\n' + (keystore.label or 'unnamed')
            cb = partial(self._on_status_bar_button_click, window=window, keystore=keystore)
            sb = window.statusBar()
            icon = read_QIcon_from_bytes(self.read_file(self.icon_unpaired))
            button = StatusBarButton(icon, tooltip, cb, sb.height())
            button.icon_paired = self.read_file(self.icon_paired)
            button.icon_unpaired = self.read_file(self.icon_unpaired)
            sb.addPermanentWidget(button)
            handler = self.create_handler(window)
            handler.button = button
            keystore.handler = handler
            keystore.thread = TaskThread(window, on_error=partial(self.on_task_thread_error, window, keystore))
            self.add_show_address_on_hw_device_button_for_receive_addr(wallet, keystore, window)
        # Trigger pairings
        devmgr = self.device_manager()
        trigger_pairings = partial(devmgr.trigger_pairings, relevant_keystores, allow_user_interaction=True)
        some_keystore = relevant_keystores[0]
        some_keystore.thread.add(trigger_pairings)

    def _on_status_bar_button_click(self, *, window: 'ElectrumWindow', keystore: 'Hardware_KeyStore'):
        try:
            self.show_settings_dialog(window=window, keystore=keystore)
        except (UserFacingException, UserCancelled) as e:
            exc_info = (type(e), e, e.__traceback__)
            self.on_task_thread_error(window=window, keystore=keystore, exc_info=exc_info)

    def on_task_thread_error(self: Union['QtPluginBase', HW_PluginBase], window: 'ElectrumWindow',
                             keystore: 'Hardware_KeyStore', exc_info):
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

    def choose_device(self: Union['QtPluginBase', HW_PluginBase], window: 'ElectrumWindow',
                      keystore: 'Hardware_KeyStore') -> Optional[str]:
        '''This dialog box should be usable even if the user has
        forgotten their PIN or it is in bootloader mode.'''
        assert window.gui_thread != threading.current_thread(), 'must not be called from GUI thread'
        device_id = self.device_manager().id_by_pairing_code(keystore.pairing_code())
        if not device_id:
            try:
                info = self.device_manager().select_device(self, keystore.handler, keystore)
            except UserCancelled:
                return
            device_id = info.device.id_
        return device_id

    def show_settings_dialog(self, window: 'ElectrumWindow', keystore: 'Hardware_KeyStore') -> None:
        # default implementation (if no dialog): just try to connect to device
        def connect():
            device_id = self.choose_device(window, keystore)
        keystore.thread.add(connect)

    def add_show_address_on_hw_device_button_for_receive_addr(self, wallet: 'Abstract_Wallet',
                                                              keystore: 'Hardware_KeyStore',
                                                              main_window: 'ElectrumWindow'):
        plugin = keystore.plugin
        receive_tab = main_window.receive_tab

        def show_address():
            addr = str(receive_tab.addr)
            keystore.thread.add(partial(plugin.show_address, wallet, addr, keystore))
        dev_name = f"{plugin.device} ({keystore.label})"
        receive_tab.toolbar_menu.addAction(read_QIcon("eye1.png"), _("Show address on {}").format(dev_name), show_address)

    def create_handler(self, window: Union['ElectrumWindow', 'QENewWalletWizard']) -> 'QtHandlerBase':
        raise NotImplementedError()
