from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWXPub, WCHWUnlock, WCHWUninitialized
from electrum.hw_wallet.qt import QtHandlerBase, QtPluginBase
from electrum.hw_wallet.plugin import only_hook_if_libraries_available
from electrum.i18n import _
from electrum.plugin import hook
from electrum.util import UserFacingException
from electrum.wallet import Standard_Wallet

from .onekey import OneKeyPlugin


class Plugin(OneKeyPlugin, QtPluginBase):
    icon_unpaired = "onekey.svg"
    icon_paired = "onekey.svg"

    def create_handler(self, window):
        return QtHandlerBase(window, "OneKey")

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        if len(addrs) == 1 and type(wallet) is Standard_Wallet:
            self._add_menu_action(menu, addrs[0], wallet)

    @only_hook_if_libraries_available
    @hook
    def transaction_dialog_address_menu(self, menu, addr, wallet):
        if type(wallet) is Standard_Wallet:
            self._add_menu_action(menu, addr, wallet)

    def extend_wizard(self, wizard):
        super().extend_wizard(wizard)
        wizard.navmap_merge({
            "onekey_start": {"gui": WCScriptAndDerivation},
            "onekey_xpub": {"gui": WCOneKeyXPub},
            "onekey_not_initialized": {"gui": WCHWUninitialized},
            "onekey_unlock": {"gui": WCHWUnlock},
        })


class WCOneKeyXPub(WCHWXPub):
    def get_xpub_from_client(self, client, derivation, xtype):
        if self.wizard_data["wallet_type"] != "standard":
            raise UserFacingException(_("Only single-signature OneKey wallets are supported."))
        return super().get_xpub_from_client(client, derivation, xtype)
