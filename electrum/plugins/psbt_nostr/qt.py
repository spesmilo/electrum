#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum Developers
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
import asyncio
from functools import partial
from typing import TYPE_CHECKING, List, Tuple, Optional, Union

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QPushButton, QMessageBox

from electrum.plugin import hook
from electrum.i18n import _
from electrum.wallet import Multisig_Wallet, Abstract_Wallet
from electrum.util import UserCancelled, event_listener, EventListener
from electrum.gui.qt.transaction_dialog import show_transaction, TxDialog
from electrum.gui.qt.util import read_QIcon_from_bytes

from .psbt_nostr import PsbtNostrPlugin, CosignerWallet

if TYPE_CHECKING:
    from electrum.transaction import Transaction, PartialTransaction
    from electrum.gui.qt.main_window import ElectrumWindow


class QReceiveSignalObject(QObject):
    cosignerReceivedPsbt = pyqtSignal(str, str, object, str)


class Plugin(PsbtNostrPlugin):
    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self._init_qt_received = False

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet', window: 'ElectrumWindow'):
        if not isinstance(wallet, Multisig_Wallet):
            return
        if wallet.wallet_type == '2fa':
            return
        self.add_cosigner_wallet(wallet, QtCosignerWallet(wallet, window, self))

    @hook
    def on_close_window(self, window):
        wallet = window.wallet
        self.remove_cosigner_wallet(wallet)

    @hook
    def transaction_dialog(self, d: 'TxDialog'):
        if cw := self.cosigner_wallets.get(d.wallet):
            assert isinstance(cw, QtCosignerWallet)
            d.cosigner_send_button = b = QPushButton(_("Send to cosigner"))
            icon = read_QIcon_from_bytes(self.read_file("nostr_multisig.png"))
            b.setIcon(icon)
            b.clicked.connect(lambda: cw.send_to_cosigners(d.tx, d.desc))
            d.buttons.insert(0, b)
            b.setVisible(False)

    @hook
    def transaction_dialog_update(self, d: 'TxDialog'):
        if cw := self.cosigner_wallets.get(d.wallet):
            assert isinstance(cw, QtCosignerWallet)
            d.cosigner_send_button.setVisible(cw.can_send_psbt(d.tx))


class QtCosignerWallet(EventListener, CosignerWallet):
    def __init__(self, wallet: 'Multisig_Wallet', window: 'ElectrumWindow', plugin: 'Plugin'):
        db_storage = plugin.get_storage(wallet)
        CosignerWallet.__init__(self, wallet, db_storage)
        self.window = window
        self.obj = QReceiveSignalObject()
        self.obj.cosignerReceivedPsbt.connect(self.on_receive)
        self.register_callbacks()

    def close(self):
        super().close()
        self.unregister_callbacks()

    @event_listener
    def on_event_psbt_nostr_received(self, wallet, *args):
        if self.wallet == wallet:
            self.obj.cosignerReceivedPsbt.emit(*args)  # put on UI thread via signal

    def send_to_cosigners(self, tx: Union['Transaction', 'PartialTransaction'], label: str):
        self.add_transaction_to_wallet(tx, label=label, on_failure=self.on_add_fail)
        self.send_psbt(tx, label)

    def do_send(self, messages: List[Tuple[str, dict]], txid: Optional[str] = None):
        if not messages:
            return
        coro = self.send_direct_messages(messages)
        text = _('Sending transaction to your Nostr relays...')
        try:
            result = self.window.run_coroutine_dialog(coro, text)
        except UserCancelled:
            return
        except asyncio.exceptions.TimeoutError:
            self.window.show_error(_('relay timeout'))
            return
        except Exception as e:
            self.window.show_error(str(e))
            return
        self.window.show_message(
            _("Your transaction was sent to your cosigners via Nostr.") + '\n\n' + txid)

    def on_receive(self, pubkey, event_id, tx, label):
        msg = '<br/>'.join([
            _("A transaction was received from your cosigner.") if not label else
            _("A transaction was received from your cosigner with label: <br/><big>{}</big><br/>").format(label),
            _("Do you want to open it now?")
        ])
        result = self.window.show_message(msg, rich_text=True, icon=QMessageBox.Icon.Question, buttons=[
                QMessageBox.StandardButton.Open,
                (QPushButton('Discard'), QMessageBox.ButtonRole.DestructiveRole, 100),
                (QPushButton('Save to wallet'), QMessageBox.ButtonRole.AcceptRole, 101)]
        )
        if result == QMessageBox.StandardButton.Open:
            if label:
                self.wallet.set_label(tx.txid(), label)
            show_transaction(tx, parent=self.window, prompt_if_unsaved=True, on_closed=partial(self.on_tx_dialog_closed, event_id))
        else:
            self.mark_pending_event_rcvd(event_id)
            if result == 100:  # Discard
                return
            self.add_transaction_to_wallet(tx, label=label, on_failure=self.on_add_fail)
            self.window.update_tabs()

    def on_tx_dialog_closed(self, event_id, _tx: Optional['Transaction']):
        self.mark_pending_event_rcvd(event_id)

    def on_add_fail(self, msg: str):
        self.window.show_error(msg)
