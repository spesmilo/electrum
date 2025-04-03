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
from typing import TYPE_CHECKING

from electrum.plugin import hook
from electrum.wallet import Multisig_Wallet

from .psbt_nostr import PsbtNostrPlugin, CosignerWallet

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet
    from electrum.gui.qml import ElectrumQmlApplication


class Plugin(PsbtNostrPlugin):
    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self._app = None

    @hook
    def init_qml(self, app: 'ElectrumQmlApplication'):
        # if self._init_qt_received:  # only need/want the first signal
        #     return
        # self._init_qt_received = True
        self._app = app
        # plugin enable for already open wallets
        for wallet in app.daemon.get_wallets():
            self.load_wallet(wallet)

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet'):
        if not isinstance(wallet, Multisig_Wallet):
            return
        self.add_cosigner_wallet(wallet, CosignerWallet(wallet))

    # @hook
    # def on_close_window(self, window):
    #     wallet = window.wallet
    #     self.remove_cosigner_wallet(wallet)
    #
    # @hook
    # def transaction_dialog(self, d: 'TxDialog'):
    #     if cw := self.cosigner_wallets.get(d.wallet):
    #         assert isinstance(cw, QtCosignerWallet)
    #         cw.hook_transaction_dialog(d)
    #
    # @hook
    # def transaction_dialog_update(self, d: 'TxDialog'):
    #     if cw := self.cosigner_wallets.get(d.wallet):
    #         assert isinstance(cw, QtCosignerWallet)
    #         cw.hook_transaction_dialog_update(d)
