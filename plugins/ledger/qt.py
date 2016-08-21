import threading

from PyQt4.Qt import (QDialog, QInputDialog, QLineEdit,
                      QVBoxLayout, QLabel, SIGNAL)
import PyQt4.QtCore as QtCore

from electrum.i18n import _
from electrum.plugins import hook
from .ledger import LedgerPlugin, Ledger_KeyStore
from ..hw_wallet.qt import QtHandlerBase

class Plugin(LedgerPlugin):

    @hook
    def load_wallet(self, wallet, window):
        keystore = wallet.get_keystore()
        if type(keystore) != self.keystore_class:
            return
        keystore.handler = BTChipQTHandler(window)
        if self.btchip_is_connected(keystore):
            if not keystore.check_proper_device():
                window.show_error(_("This wallet does not match your Ledger device"))
                wallet.force_watching_only = True
        else:
            window.show_error(_("Ledger device not detected.\nContinuing in watching-only mode."))
            wallet.force_watching_only = True

    def create_keystore(self, hw_type, derivation, wizard):
        from electrum.keystore import hardware_keystore
        # create keystore
        handler = BTChipQTHandler(wizard)
        client = self.get_client()
        xpub = self.get_public_key(derivation)
        d = {
            'xpub': self.xpub,
            'type': 'hardware',
            'hw_type': hw_type,
            'derivation': derivation
        }
        k = hardware_keystore(hw_type, d)
        return k


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
