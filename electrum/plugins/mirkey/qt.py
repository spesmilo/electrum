from functools import partial

from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Standard_Wallet

from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available
from .mirkey import MIRkeyPlugin


class Plugin(MIRkeyPlugin, QtPluginBase):
    icon_unpaired = "mirkey_unpaired.png"
    icon_paired = "mirkey.png"

    def create_handler(self, window):
        return MIRkey_Handler(window)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        if type(wallet) is not Standard_Wallet:
            return

        keystore = wallet.get_keystore()
        if type(keystore) is not self.keystore_class:
            return

        if not self.is_mobile_paired():
            return

        if len(addrs) == 1:
            def show_address():
                keystore.thread.add(partial(self.show_address, wallet, addrs[0], keystore))

            menu.addAction(_("Show on {}").format(self.device), show_address)


class MIRkey_Handler(QtHandlerBase):

    def __init__(self, win):
        super(MIRkey_Handler, self).__init__(win, 'MIRkey')
