from functools import partial
from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal

from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Standard_Wallet

from electrum.plugins.hw_wallet.qt import QtHandlerBase, QtPluginBase
from electrum.plugins.hw_wallet import plugin
from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWUnlock, WCHWXPub, WCHWUninitialized

from .jade import JadePlugin

if TYPE_CHECKING:
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard


class Plugin(JadePlugin, QtPluginBase):
    icon_unpaired = "jade_unpaired.png"
    icon_paired = "jade.png"

    def create_handler(self, window):
        return Jade_Handler(window)

    @plugin.only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        if type(wallet) is not Standard_Wallet:
            return
        keystore = wallet.get_keystore()
        if type(keystore) == self.keystore_class and len(addrs) == 1:
            def show_address():
                keystore.thread.add(partial(self.show_address, wallet, addrs[0]))
            menu.addAction(_("Show on Jade"), show_address)

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    # insert jade pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'jade_start': {'gui': WCScriptAndDerivation},
            'jade_xpub': {'gui': WCHWXPub},
            'jade_not_initialized': {'gui': WCHWUninitialized},
            'jade_unlock': {'gui': WCHWUnlock}
        }
        wizard.navmap_merge(views)


class Jade_Handler(QtHandlerBase):
    setup_signal = pyqtSignal()
    auth_signal = pyqtSignal(object, object)

    MESSAGE_DIALOG_TITLE = _("Jade Status")

    def __init__(self, win):
        super(Jade_Handler, self).__init__(win, 'Jade')

