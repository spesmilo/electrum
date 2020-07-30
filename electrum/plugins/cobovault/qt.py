from functools import partial

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QPushButton, QLabel, QVBoxLayout, QWidget, QGridLayout

from electrum.gui.qt.util import WindowModalDialog, CloseButton, get_parent_main_window, Buttons
from electrum.gui.qt.transaction_dialog import TxDialog
from electrum.gui.qt.main_window import StatusBarButton, ElectrumWindow
from electrum.gui.qt.util import (read_QIcon, WWLabel, OkButton, WindowModalDialog,
                                  Buttons, CancelButton, TaskThread, char_width_in_lineedit,
                                  PasswordLineEdit)
from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Multisig_Wallet
from electrum.transaction import PartialTransaction

from .cobovault import CoboVaultPlugin
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available

class Plugin(CoboVaultPlugin, QtPluginBase):
    icon_unpaired = "cobovault.png"
    icon_paired = "cobovault.png"

    def create_handler(self, window):
        return CoboVault_Handler(window)

    @hook
    def load_wallet(self: 'QtPluginBase', wallet: 'Abstract_Wallet', window: ElectrumWindow):
        relevant_keystores = [keystore for keystore in wallet.get_keystores()
                              if isinstance(keystore, self.keystore_class)]
        if not relevant_keystores:
            return
        for keystore in relevant_keystores:
            if not self.libraries_available:
                message = keystore.plugin.get_library_not_available_message()
                window.show_error(message)
                return
            tooltip = self.device + '\n' + (keystore.label or 'unnamed')
            cb = partial(self._on_status_bar_button_click, window=window, keystore=keystore)
            button = StatusBarButton(read_QIcon(self.icon_unpaired), tooltip, cb)
            button.icon_paired = self.icon_paired
            button.icon_unpaired = self.icon_unpaired
            window.statusBar().addPermanentWidget(button)
            handler = self.create_handler(window)
            handler.button = button
            keystore.handler = handler

    @only_hook_if_libraries_available
    @hook
    def wallet_info_buttons(self, main_window, dialog):
        # Wallet Information, add "Export" button
        wallet = main_window.wallet

        if type(wallet) is not Multisig_Wallet:
            return

        if not any(type(ks) == self.keystore_class for ks in wallet.get_keystores()):
            # doesn't involve a CoboVault wallet, hide feature
            return

        btn = QPushButton(_("Export"))
        btn.clicked.connect(lambda unused: self.export_multisig_setup(main_window, wallet))

        return btn

    def export_multisig_setup(self, main_window, wallet):
        # Wallet Information, "Export" button for export file
        basename = wallet.basename().rsplit('.', 1)[0]        # x.json
        name = f'export-{basename}.txt'.replace(' ', '-')
        fileName = main_window.getSaveFileName(_("Select where to save the setup file"),
                                                        name, "*.txt")
        if fileName:
            with open(fileName, "wt") as f:
                CoboVaultPlugin.export_ms_wallet(wallet, f, basename)
            main_window.show_message(_("Wallet setup file exported successfully"))

    def show_settings_dialog(self, window, keystore):
        # click on icon, do nothing
        pass


class CoboVault_Handler(QtHandlerBase):

    def __init__(self, win):
        super(CoboVault_Handler, self).__init__(win, 'CoboVault')
