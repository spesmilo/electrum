from functools import partial
from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QInputDialog, QLineEdit

from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Standard_Wallet

from .ledger import LedgerPlugin, Ledger_Client
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available
from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWUninitialized, WCHWUnlock, WCHWXPub

if TYPE_CHECKING:
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard


class Plugin(LedgerPlugin, QtPluginBase):
    icon_unpaired = "ledger_unpaired.png"
    icon_paired = "ledger.png"

    def create_handler(self, window):
        return Ledger_Handler(window)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        if type(wallet) is not Standard_Wallet:
            return
        keystore = wallet.get_keystore()
        if type(keystore) == self.keystore_class and len(addrs) == 1:
            def show_address():
                keystore.thread.add(partial(self.show_address, wallet, addrs[0], keystore=keystore))
            menu.addAction(_("Show on Ledger"), show_address)

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    # insert ledger pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'ledger_start': {'gui': WCScriptAndDerivation},
            'ledger_xpub': {'gui': WCHWXPub},
            'ledger_not_initialized': {'gui': WCHWUninitialized},
            'ledger_unlock': {'gui': WCHWUnlock}
        }
        wizard.navmap_merge(views)


class Ledger_Handler(QtHandlerBase):
    setup_signal = pyqtSignal()
    auth_signal = pyqtSignal(object, object)

    MESSAGE_DIALOG_TITLE = _("Ledger Status")

    def __init__(self, win):
        super(Ledger_Handler, self).__init__(win, 'Ledger')
        self.setup_signal.connect(self.setup_dialog)
        self.auth_signal.connect(self.auth_dialog)

    def word_dialog(self, msg):
        response = QInputDialog.getText(self.top_level_window(), "Ledger Wallet Authentication", msg, QLineEdit.Password)
        if not response[1]:
            self.word = None
        else:
            self.word = str(response[0])
        self.done.set()

    def auth_dialog(self, data, client: 'Ledger_Client'):
        try:
            from .auth2fa import LedgerAuthDialog
        except ImportError as e:
            self.message_dialog(repr(e))
            return
        dialog = LedgerAuthDialog(self, data, client=client)
        dialog.exec()
        self.word = dialog.pin
        self.done.set()

    def get_auth(self, data, *, client: 'Ledger_Client'):
        self.done.clear()
        self.auth_signal.emit(data, client)
        self.done.wait()
        return self.word

    def get_setup(self):
        self.done.clear()
        self.setup_signal.emit()
        self.done.wait()
        return

    def setup_dialog(self):
        self.show_error(_('Initialization of Ledger HW devices is currently disabled.'))
