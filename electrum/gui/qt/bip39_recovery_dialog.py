# Copyright (C) 2020 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import concurrent.futures

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QGridLayout, QLabel, QListWidget, QListWidgetItem

from electrum.i18n import _
from electrum.network import Network
from electrum.bip39_recovery import account_discovery
from electrum.logging import get_logger
from electrum.util import get_asyncio_loop, UserFacingException

from .util import WindowModalDialog, MessageBoxMixin, TaskThread, Buttons, CancelButton, OkButton


_logger = get_logger(__name__)


class Bip39RecoveryDialog(WindowModalDialog):

    ROLE_ACCOUNT = Qt.ItemDataRole.UserRole

    def __init__(self, parent: QWidget, get_account_xpub, on_account_select):
        self.get_account_xpub = get_account_xpub
        self.on_account_select = on_account_select
        WindowModalDialog.__init__(self, parent, _('BIP39 Recovery'))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        self.content = QVBoxLayout()
        self.content.addWidget(QLabel(_('Scanning common paths for existing accounts...')))
        vbox.addLayout(self.content)

        self.thread = TaskThread(self)
        self.thread.finished.connect(self.deleteLater) # see #3956
        network = Network.get_instance()
        coro = account_discovery(network, self.get_account_xpub)
        fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
        self.thread.add(
            fut.result,
            on_success=self.on_recovery_success,
            on_error=self.on_recovery_error,
            cancel=fut.cancel,
        )

        self.ok_button = OkButton(self)
        self.ok_button.clicked.connect(self.on_ok_button_click)
        self.ok_button.setEnabled(False)
        cancel_button = CancelButton(self)
        cancel_button.clicked.connect(fut.cancel)
        vbox.addLayout(Buttons(cancel_button, self.ok_button))
        self.finished.connect(self.on_finished)
        self.show()

    def on_finished(self):
        self.thread.stop()

    def on_ok_button_click(self):
        item = self.list.currentItem()
        account = item.data(self.ROLE_ACCOUNT)
        self.on_account_select(account)

    def on_recovery_success(self, accounts):
        self.clear_content()
        if len(accounts) == 0:
            self.content.addWidget(QLabel(_('No existing accounts found.')))
            return
        self.content.addWidget(QLabel(_('Choose an account to restore.')))
        self.list = QListWidget()
        for account in accounts:
            item = QListWidgetItem(account['description'])
            item.setData(self.ROLE_ACCOUNT, account)
            self.list.addItem(item)
        self.list.clicked.connect(lambda: self.ok_button.setEnabled(True))
        self.content.addWidget(self.list)

    def on_recovery_error(self, exc_info):
        e = exc_info[1]
        if isinstance(e, concurrent.futures.CancelledError):
            return
        self.clear_content()
        msg = _('Error: Account discovery failed.')
        if isinstance(e, UserFacingException):
            msg += f"\n{e}"
        else:
            _logger.error(f"recovery error", exc_info=exc_info)
        self.content.addWidget(QLabel(msg))

    def clear_content(self):
        for i in reversed(range(self.content.count())):
            self.content.itemAt(i).widget().setParent(None)
