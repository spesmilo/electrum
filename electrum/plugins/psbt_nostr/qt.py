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
from typing import TYPE_CHECKING, List, Tuple, Optional

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QPushButton

from electrum.plugin import hook
from electrum.i18n import _
from electrum.wallet import Multisig_Wallet, Abstract_Wallet
from electrum.util import UserCancelled, event_listener, EventListener
from electrum.gui.qt.transaction_dialog import show_transaction, TxDialog

from .psbt_nostr import PsbtNostrPlugin, CosignerWallet, now

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow

USER_PROMPT_COOLDOWN = 10


class QReceiveSignalObject(QObject):
    cosignerReceivedPsbt = pyqtSignal(str, str, object)


class Plugin(PsbtNostrPlugin):
    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self._init_qt_received = False

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet', window: 'ElectrumWindow'):
        if not isinstance(wallet, Multisig_Wallet):
            return
        self.add_cosigner_wallet(wallet, QtCosignerWallet(wallet, window))

    @hook
    def on_close_window(self, window):
        wallet = window.wallet
        self.remove_cosigner_wallet(wallet)

    @hook
    def transaction_dialog(self, d: 'TxDialog'):
        if cw := self.cosigner_wallets.get(d.wallet):
            assert isinstance(cw, QtCosignerWallet)
            cw.hook_transaction_dialog(d)

    @hook
    def transaction_dialog_update(self, d: 'TxDialog'):
        if cw := self.cosigner_wallets.get(d.wallet):
            assert isinstance(cw, QtCosignerWallet)
            cw.hook_transaction_dialog_update(d)


class QtCosignerWallet(EventListener, CosignerWallet):
    def __init__(self, wallet: 'Multisig_Wallet', window: 'ElectrumWindow'):
        CosignerWallet.__init__(self, wallet)
        self.window = window
        self.obj = QReceiveSignalObject()
        self.obj.cosignerReceivedPsbt.connect(self.on_receive)
        self.register_callbacks()
        self.user_prompt_cooldown = None

    def close(self):
        super().close()
        self.unregister_callbacks()

    @event_listener
    def on_event_psbt_nostr_received(self, wallet, *args):
        if self.wallet == wallet:
            self.obj.cosignerReceivedPsbt.emit(*args)  # put on UI thread via signal

    def hook_transaction_dialog(self, d: 'TxDialog'):
        d.cosigner_send_button = b = QPushButton(_("Send to cosigner"))
        b.clicked.connect(lambda: self.send_to_cosigners(d.tx))
        d.buttons.insert(0, b)
        b.setVisible(False)

    def hook_transaction_dialog_update(self, d: 'TxDialog'):
        assert self.wallet == d.wallet
        if d.tx.is_complete() or d.wallet.can_sign(d.tx):
            d.cosigner_send_button.setVisible(False)
            return
        for xpub, pubkey in self.cosigner_list:
            if self.cosigner_can_sign(d.tx, xpub):
                d.cosigner_send_button.setVisible(True)
                break
        else:
            d.cosigner_send_button.setVisible(False)

    def send_to_cosigners(self, tx):
        def ok():
            self.logger.debug('ADDED')
        def nok(msg: str):
            self.logger.debug(f'NOT ADDED: {msg}')
        self.add_transaction_to_wallet(tx, on_success=ok, on_failure=nok)
        self.send_psbt(tx)

    def do_send(self, messages: List[Tuple[str, str]], txid: Optional[str] = None):
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

    def on_receive(self, pubkey, event_id, tx):
        open_now = False
        if not (self.user_prompt_cooldown and self.user_prompt_cooldown > now()):
            open_now = self.window.question(
                    _("A transaction was received from your cosigner ({}).").format(str(event_id)[0:8]) + '\n' +
                    _("Do you want to open it now?"))
            if not open_now:
                self.user_prompt_cooldown = now() + USER_PROMPT_COOLDOWN
        if open_now:
            show_transaction(tx, parent=self.window, prompt_if_unsaved=True, on_closed=partial(self.on_tx_dialog_closed, event_id))
        else:
            self.mark_pending_event_rcvd(event_id)
            self.add_transaction_to_wallet(tx, on_failure=self.on_add_fail)

    def on_tx_dialog_closed(self, event_id):
        self.mark_pending_event_rcvd(event_id)

    def on_add_fail(self, msg: str):
        self.window.show_error(msg)
