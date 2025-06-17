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
import concurrent
from typing import TYPE_CHECKING, List, Tuple, Optional

from PyQt6.QtCore import QObject, pyqtSignal, pyqtProperty, pyqtSlot

from electrum import util
from electrum.plugin import hook
from electrum.transaction import PartialTransaction, tx_from_any
from electrum.wallet import Multisig_Wallet
from electrum.util import EventListener, event_listener

from electrum.gui.qml.qewallet import QEWallet

from .psbt_nostr import PsbtNostrPlugin, CosignerWallet

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qml import ElectrumQmlApplication


class QReceiveSignalObject(QObject):
    def __init__(self, plugin: 'Plugin'):
        QObject.__init__(self)
        self._plugin = plugin

    cosignerReceivedPsbt = pyqtSignal(str, str, str, str)
    sendPsbtFailed = pyqtSignal(str, arguments=['reason'])
    sendPsbtSuccess = pyqtSignal()

    @pyqtProperty(str)
    def loader(self):
        return 'main.qml'

    @pyqtSlot(QEWallet, str, result=bool)
    def canSendPsbt(self, wallet: 'QEWallet', tx: str) -> bool:
        cosigner_wallet = self._plugin.cosigner_wallets.get(wallet.wallet)
        if not cosigner_wallet:
            return False
        return cosigner_wallet.can_send_psbt(tx_from_any(tx, deserialize=True))

    @pyqtSlot(QEWallet, str)
    @pyqtSlot(QEWallet, str, str)
    def sendPsbt(self, wallet: 'QEWallet', tx: str, label: str = None):
        cosigner_wallet = self._plugin.cosigner_wallets.get(wallet.wallet)
        if not cosigner_wallet:
            return
        cosigner_wallet.send_psbt(tx_from_any(tx, deserialize=True), label)

    @pyqtSlot(QEWallet, str, str)
    def saveTxLabel(self, wallet: 'QEWallet', tx: str, label: str):
        cosigner_wallet = self._plugin.cosigner_wallets.get(wallet.wallet)
        if not cosigner_wallet:
            return
        cosigner_wallet.save_tx_label(tx_from_any(tx, deserialize=True), label)

    @pyqtSlot(QEWallet, str)
    @pyqtSlot(QEWallet, str, bool)
    def acceptPsbt(self, wallet: 'QEWallet', event_id: str, save_to_wallet: bool = False):
        cosigner_wallet = self._plugin.cosigner_wallets.get(wallet.wallet)
        if not cosigner_wallet:
            return
        cosigner_wallet.accept_psbt(event_id, save_to_wallet)
        if save_to_wallet:
            # let GUI update view through wallet_updated callback
            util.trigger_callback('wallet_updated', wallet.wallet)

    @pyqtSlot(QEWallet, str)
    def rejectPsbt(self, wallet: 'QEWallet', event_id: str):
        cosigner_wallet = self._plugin.cosigner_wallets.get(wallet.wallet)
        if not cosigner_wallet:
            return
        cosigner_wallet.reject_psbt(event_id)


class Plugin(PsbtNostrPlugin):
    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self.so = QReceiveSignalObject(self)
        self._app = None

    @hook
    def init_qml(self, app: 'ElectrumQmlApplication'):
        self._app = app
        self.so.setParent(app)  # parent in QObject tree
        # plugin enable for already open wallet
        wallet = app.daemon.currentWallet.wallet if app.daemon.currentWallet else None
        if wallet:
            self.load_wallet(wallet)

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet'):
        # remove existing, only foreground wallet active
        for _wallet in self.cosigner_wallets.copy().keys():
            self.remove_cosigner_wallet(_wallet)
        if not isinstance(wallet, Multisig_Wallet):
            return
        if wallet.wallet_type == '2fa':
            return
        self.add_cosigner_wallet(wallet, QmlCosignerWallet(wallet, self))


class QmlCosignerWallet(EventListener, CosignerWallet):

    def __init__(self, wallet: 'Multisig_Wallet', plugin: 'Plugin'):
        db_storage = plugin.get_storage(wallet)
        CosignerWallet.__init__(self, wallet, db_storage)
        self.plugin = plugin
        self.register_callbacks()

        self.tx = None

    @event_listener
    def on_event_psbt_nostr_received(self, wallet, pubkey, event_id, tx: 'PartialTransaction', label: str):
        if self.wallet == wallet:
            self.tx = tx
            self.plugin.so.cosignerReceivedPsbt.emit(pubkey, event_id, tx.serialize(), label)

    def close(self):
        super().close()
        self.unregister_callbacks()

    def do_send(self, messages: List[Tuple[str, dict]], txid: Optional[str] = None):
        if not messages:
            return
        coro = self.send_direct_messages(messages)

        loop = util.get_asyncio_loop()
        assert util.get_running_loop() != loop, 'must not be called from asyncio thread'
        self._result = None
        self._future = asyncio.run_coroutine_threadsafe(coro, loop)

        try:
            self._result = self._future.result()
            self.plugin.so.sendPsbtSuccess.emit()
        except concurrent.futures.CancelledError:
            pass
        except Exception as e:
            self.plugin.so.sendPsbtFailed.emit(str(e))

    def save_tx_label(self, tx, label):
        self.wallet.set_label(tx.txid(), label)

    def accept_psbt(self, event_id, save: bool = False):
        if save:
            self.add_transaction_to_wallet(self.tx, on_failure=self.on_add_fail)
        self.mark_pending_event_rcvd(event_id)

    def reject_psbt(self, event_id):
        self.mark_pending_event_rcvd(event_id)

    def on_add_fail(self):
        self.logger.error('failed to add tx to wallet')
