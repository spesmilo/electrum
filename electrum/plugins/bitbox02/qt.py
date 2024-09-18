import threading
from functools import partial
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QMetaObject, Q_RETURN_ARG, pyqtSlot, pyqtSignal
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QLineEdit, QHBoxLayout

from electrum.i18n import _
from electrum.plugin import hook
from electrum.util import UserCancelled, UserFacingException

from .bitbox02 import BitBox02Plugin
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available, OperationCancelled

from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWUnlock, WCHWUninitialized, WCHWXPub
from electrum.gui.qt.util import WindowModalDialog, OkButton, ButtonsTextEdit

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

    # insert bitbox02 pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'bitbox02_start': {'gui': WCBitbox02ScriptAndDerivation},
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
        return QMetaObject.invokeMethod(self, "_name_multisig_account", Qt.ConnectionType.BlockingQueuedConnection, Q_RETURN_ARG(str))

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
        dialog.exec()
        return name.text().strip()


class WCBitbox02ScriptAndDerivation(WCScriptAndDerivation):
    def __init__(self, parent, wizard):
        WCScriptAndDerivation.__init__(self, parent, wizard)
        self._busy = True
        self.title = ''
        self.client = None

    def on_ready(self):
        super().on_ready()
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        _name, _info = current_cosigner['hardware_device']
        plugin = self.wizard.plugins.get_plugin(_info.plugin_name)

        device_id = _info.device.id_
        self.client = self.wizard.plugins.device_manager.client_by_id(device_id, scan_now=False)
        if not self.client.handler:
            self.client.handler = plugin.create_handler(self.wizard)
        self.client.setupRunning = True
        self.check_device()

    def check_device(self):
        self.error = None
        self.valid = False
        self.busy = True

        def check_task():
            try:
                self.client.pairing_dialog()
                self.title = _('Script type and Derivation path')
                self.valid = True
            except (UserCancelled, OperationCancelled):
                self.error = _('Cancelled')
                self.wizard.requestPrev.emit()
            except UserFacingException as e:
                self.error = str(e)
            except Exception as e:
                self.error = repr(e)
                self.logger.exception(repr(e))
            finally:
                self.busy = False

        t = threading.Thread(target=check_task, daemon=True)
        t.start()
