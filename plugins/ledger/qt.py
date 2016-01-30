import threading

from PyQt4.Qt import (QDialog, QInputDialog, QLineEdit,
                      QVBoxLayout, QLabel, SIGNAL)
import PyQt4.QtCore as QtCore

from electrum.i18n import _
from electrum.plugins import hook
from .ledger import LedgerPlugin, BTChipWallet
from ..hw_wallet.qt import QtHandlerBase

class Plugin(LedgerPlugin):

    @hook
    def load_wallet(self, wallet, window):
        if type(wallet) != BTChipWallet:
            return
        wallet.handler = BTChipQTHandler(window)
        if self.btchip_is_connected(wallet):
            if not wallet.check_proper_device():
                window.show_error(_("This wallet does not match your Ledger device"))
                wallet.force_watching_only = True
        else:
            window.show_error(_("Ledger device not detected.\nContinuing in watching-only mode."))
            wallet.force_watching_only = True

    def on_create_wallet(self, wallet, wizard):
        assert type(wallet) == self.wallet_class
        wallet.handler = BTChipQTHandler(wizard)
#        self.select_device(wallet)
        wallet.create_hd_account(None)

class BTChipQTHandler(QtHandlerBase):

    def __init__(self, win):
        super(BTChipQTHandler, self).__init__(win, 'Ledger')


    def word_dialog(self, msg):
        response = QInputDialog.getText(self.top_level_window(), "Ledger Wallet Authentication", msg, QLineEdit.Password)
        if not response[1]:
            self.word = None
        else:
            self.word = str(response[0])
        self.done.set()                
