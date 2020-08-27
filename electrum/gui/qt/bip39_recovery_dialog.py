# Copyright (C) 2020 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QGridLayout, QLabel, QListWidget, QListWidgetItem

from electrum.i18n import _
from electrum.network import Network
from electrum.bip39_recovery import account_discovery
from electrum.logging import get_logger

from .util import WindowModalDialog, MessageBoxMixin, TaskThread, Buttons, CancelButton, OkButton


_logger = get_logger(__name__)


class Bip39RecoveryDialog(WindowModalDialog):
    def __init__(self, parent: QWidget, get_account_xpub, on_account_select):
        self.get_account_xpub = get_account_xpub
        self.on_account_select = on_account_select
        WindowModalDialog.__init__(self, parent, _('BIP39 Recovery'))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        self.content = QVBoxLayout()
        self.content.addWidget(QLabel(_('Scanning common paths for existing accounts...')))
        vbox.addLayout(self.content)
        self.ok_button = OkButton(self)
        self.ok_button.clicked.connect(self.on_ok_button_click)
        self.ok_button.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(self), self.ok_button))
        self.finished.connect(self.on_finished)
        self.show()
        self.thread = TaskThread(self)
        self.thread.finished.connect(self.deleteLater) # see #3956
        self.thread.add(self.recovery, self.on_recovery_success, None, self.on_recovery_error)

    def on_finished(self):
        self.thread.stop()

    def on_ok_button_click(self):
        item = self.list.currentItem()
        account = item.data(Qt.UserRole)
        self.on_account_select(account)

    def recovery(self):
        network = Network.get_instance()
        coroutine = account_discovery(network, self.get_account_xpub)
        return network.run_from_another_thread(coroutine)

    def on_recovery_success(self, accounts):
        self.clear_content()
        if len(accounts) == 0:
            self.content.addWidget(QLabel(_('No existing accounts found.')))
            return
        self.content.addWidget(QLabel(_('Choose an account to restore.')))
        self.list = QListWidget()
        for account in accounts:
            item = QListWidgetItem(account['description'])
            item.setData(Qt.UserRole, account)
            self.list.addItem(item)
        self.list.clicked.connect(lambda: self.ok_button.setEnabled(True))
        self.content.addWidget(self.list)

    def on_recovery_error(self, exc_info):
        self.clear_content()
        self.content.addWidget(QLabel(_('Error: Account discovery failed.')))
        _logger.error(f"recovery error", exc_info=exc_info)

    def clear_content(self):
        for i in reversed(range(self.content.count())):
            self.content.itemAt(i).widget().setParent(None)
