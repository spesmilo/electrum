from functools import partial

from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from .digitalbitbox import DigitalBitboxPlugin

from electrum_ltc.i18n import _
from electrum_ltc.plugin import hook
from electrum_ltc.wallet import Standard_Wallet


class Plugin(DigitalBitboxPlugin, QtPluginBase):
    icon_unpaired = ":icons/digitalbitbox_unpaired.png"
    icon_paired = ":icons/digitalbitbox.png"

    def create_handler(self, window):
        return DigitalBitbox_Handler(window)

    @hook
    def receive_menu(self, menu, addrs, wallet):
        if type(wallet) is not Standard_Wallet:
            return

        keystore = wallet.get_keystore()
        if type(keystore) is not self.keystore_class:
            return

        if not self.is_mobile_paired():
            return

        if not keystore.is_p2pkh():
            return

        if len(addrs) == 1:
            def show_address():
                keystore.thread.add(partial(self.show_address, wallet, addrs[0], keystore))

            menu.addAction(_("Show on {}").format(self.device), show_address)


class DigitalBitbox_Handler(QtHandlerBase):

    def __init__(self, win):
        super(DigitalBitbox_Handler, self).__init__(win, 'Digital Bitbox')
