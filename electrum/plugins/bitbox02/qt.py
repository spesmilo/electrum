from functools import partial
from typing import TYPE_CHECKING

from PyQt5.QtWidgets import (
    QPushButton,
    QLabel,
    QVBoxLayout,
    QLineEdit,
    QHBoxLayout,
)

from PyQt5.QtCore import Qt, QMetaObject, Q_RETURN_ARG, pyqtSlot

from electrum.gui.qt.util import (
    WindowModalDialog,
    OkButton,
    ButtonsTextEdit,
)

from electrum.i18n import _
from electrum.plugin import hook

from .bitbox02 import BitBox02Plugin
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available
from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWUnlock, WCHWUninitialized, WCHWXPub

if TYPE_CHECKING:
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard


class Plugin(BitBox02Plugin, QtPluginBase):
    icon_unpaired = "bitbox02_unpaired.png"
    icon_paired = "bitbox02.png"

    def create_handler(self, window):
        return BitBox02_Handler(window)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        # Context menu on each address in the Addresses Tab, right click...
        if len(addrs) != 1:
            return
        for keystore in wallet.get_keystores():
            if type(keystore) == self.keystore_class:

                def show_address(keystore=keystore):
                    keystore.thread.add(
                        partial(self.show_address, wallet, addrs[0], keystore=keystore)
                    )

                device_name = "{} ({})".format(self.device, keystore.label)
                menu.addAction(_("Show on {}").format(device_name), show_address)

    @only_hook_if_libraries_available
    @hook
    def show_xpub_button(self, mpk_text: ButtonsTextEdit, keystore):
        # user is about to see the "Wallet Information" dialog
        # - add a button to show the xpub on the BitBox02 device
        if type(keystore) != self.keystore_class:
            return

        def on_button_click():
            keystore.thread.add(
                partial(self.show_xpub, keystore=keystore)
            )

        device_name = "{} ({})".format(self.device, keystore.label)
        mpk_text.addButton("eye1.png", on_button_click, _("Show on {}").format(device_name))

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    # insert trezor pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'bitbox02_start': {'gui': WCScriptAndDerivation},
            'bitbox02_xpub': {'gui': WCHWXPub},
            'bitbox02_not_initialized': {'gui': WCHWUninitialized},
            'bitbox02_unlock': {'gui': WCHWUnlock}
        }
        wizard.navmap_merge(views)


class BitBox02_Handler(QtHandlerBase):
    MESSAGE_DIALOG_TITLE = _("BitBox02 Status")

    def __init__(self, win):
        super(BitBox02_Handler, self).__init__(win, "BitBox02")

    def name_multisig_account(self):
        return QMetaObject.invokeMethod(
            self,
            "_name_multisig_account",
            Qt.BlockingQueuedConnection,
            Q_RETURN_ARG(str),
        )

    @pyqtSlot(result=str)
    def _name_multisig_account(self):
        dialog = WindowModalDialog(None, "Create Multisig Account")
        vbox = QVBoxLayout()
        label = QLabel(
            _(
                "Enter a descriptive name for your multisig account.\nYou should later be able to use the name to uniquely identify this multisig account"
            )
        )
        hl = QHBoxLayout()
        hl.addWidget(label)
        name = QLineEdit()
        name.setMaxLength(30)
        name.resize(200, 40)
        he = QHBoxLayout()
        he.addWidget(name)
        okButton = OkButton(dialog)
        hlb = QHBoxLayout()
        hlb.addWidget(okButton)
        hlb.addStretch(2)
        vbox.addLayout(hl)
        vbox.addLayout(he)
        vbox.addLayout(hlb)
        dialog.setLayout(vbox)
        dialog.exec_()
        return name.text().strip()
