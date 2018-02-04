from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from .digitalbitbox import DigitalBitboxPlugin

from electroncash.i18n import _
from electroncash.plugins import hook
from electroncash.wallet import Standard_Wallet


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
                change, index = wallet.get_address_index(addrs[0])
                keypath = '%s/%d/%d' % (keystore.derivation, change, index)
                xpub = self.get_client(keystore)._get_xpub(keypath)
                verify_request_payload = {
                    "type": 'p2pkh',
                    "echo": xpub['echo'],
                    }
                self.comserver_post_notification(verify_request_payload)

            menu.addAction(_("Show on {}").format(self.device), show_address)


class DigitalBitbox_Handler(QtHandlerBase):

    def __init__(self, win):
        super(DigitalBitbox_Handler, self).__init__(win, 'Digital Bitbox')
