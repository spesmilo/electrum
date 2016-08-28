import threading

from PyQt4.Qt import (QDialog, QInputDialog, QLineEdit,
                      QVBoxLayout, QLabel, SIGNAL)
import PyQt4.QtCore as QtCore
from electrum_gui.qt.main_window import StatusBarButton

from electrum.i18n import _
from electrum.plugins import hook
from .ledger import LedgerPlugin, Ledger_KeyStore
from ..hw_wallet.qt import QtHandlerBase
from electrum_gui.qt.util import *

class Plugin(LedgerPlugin):
    icon_unpaired = ":icons/ledger_unpaired.png"
    icon_paired = ":icons/ledger.png"

    @hook
    def load_wallet(self, wallet, window):
        for keystore in wallet.get_keystores():
            if type(keystore) != self.keystore_class:
                continue
            tooltip = self.device
            cb = partial(self.show_settings_dialog, window, keystore)
            button = StatusBarButton(QIcon(self.icon_unpaired), tooltip, cb)
            button.icon_paired = self.icon_paired
            button.icon_unpaired = self.icon_unpaired
            window.statusBar().addPermanentWidget(button)
            handler = BTChipQTHandler(window)
            handler.button = button
            keystore.handler = handler
            keystore.thread = TaskThread(window, window.on_error)
            # Trigger a pairing
            keystore.thread.add(partial(self.get_client, keystore))

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

    def create_handler(self, wizard):
        return BTChipQTHandler(wizard)        

    def show_settings_dialog(self, window, keystore):
        pass

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
