from functools import partial

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QLabel, QVBoxLayout

from electrum_ltc.i18n import _
from electrum_ltc.plugin import hook
from electrum_ltc.wallet import Standard_Wallet
from electrum_ltc.gui.qt.util import WindowModalDialog

from .jade import JadePlugin
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available


class Plugin(JadePlugin, QtPluginBase):
    icon_unpaired = "jade_unpaired.png"
    icon_paired = "jade.png"

    def create_handler(self, window):
        return Jade_Handler(window)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        if type(wallet) is not Standard_Wallet:
            return
        keystore = wallet.get_keystore()
        if type(keystore) == self.keystore_class and len(addrs) == 1:
            def show_address():
                keystore.thread.add(partial(self.show_address, wallet, addrs[0]))
            menu.addAction(_("Show on Jade"), show_address)

class Jade_Handler(QtHandlerBase):
    setup_signal = pyqtSignal()
    auth_signal = pyqtSignal(object, object)

    def __init__(self, win):
        super(Jade_Handler, self).__init__(win, 'Jade')

    def message_dialog(self, msg):
        self.clear_dialog()
        self.dialog = dialog = WindowModalDialog(self.top_level_window(), _("Jade Status"))
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(l)
        dialog.show()
