import threading
from functools import partial
from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal

from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Standard_Wallet, Abstract_Wallet
from electrum.util import UserCancelled, UserFacingException

from electrum.hw_wallet.qt import QtHandlerBase, QtPluginBase
from electrum.hw_wallet.plugin import only_hook_if_libraries_available, OperationCancelled

from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWXPub, WCHWUnlock

from .digitalbitbox import DigitalBitboxPlugin, DeviceErased

if TYPE_CHECKING:
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard


class Plugin(DigitalBitboxPlugin, QtPluginBase):
    icon_unpaired = "digitalbitbox_unpaired.png"
    icon_paired = "digitalbitbox.png"

    def create_handler(self, window):
        return DigitalBitbox_Handler(window)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        if not self.is_mobile_paired():
            return
        if len(addrs) != 1:
            return
        if wallet.get_txin_type(addrs[0]) != 'p2pkh':
            return
        self._add_menu_action(menu, addrs[0], wallet)

    @only_hook_if_libraries_available
    @hook
    def transaction_dialog_address_menu(self, menu, addr, wallet):
        if not self.is_mobile_paired():
            return
        if wallet.get_txin_type(addr) != 'p2pkh':
            return
        self._add_menu_action(menu, addr, wallet)

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    # insert digitalbitbox pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'dbitbox_start': {'gui': WCDigitalBitboxScriptAndDerivation},
            'dbitbox_xpub': {'gui': WCHWXPub},
            'dbitbox_unlock': {'gui': WCHWUnlock}
        }
        wizard.navmap_merge(views)


class DigitalBitbox_Handler(QtHandlerBase):
    def __init__(self, win):
        super(DigitalBitbox_Handler, self).__init__(win, 'Digital Bitbox')


class WCDigitalBitboxScriptAndDerivation(WCScriptAndDerivation):
    requestRecheck = pyqtSignal()

    def __init__(self, parent, wizard):
        WCScriptAndDerivation.__init__(self, parent, wizard)
        self._busy = True
        self.title = ''
        self.client = None

        self.requestRecheck.connect(self.check_device)

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
        self.busy = True

        def check_task():
            try:
                self.client.check_device_dialog()
                self.title = _('Script type and Derivation path')
                self.valid = True
            except (UserCancelled, OperationCancelled):
                self.error = _('Cancelled')
                self.wizard.requestPrev.emit()
            except DeviceErased:
                self.error = _('Device erased')
                self.requestRecheck.emit()
            except UserFacingException as e:
                self.error = str(e)
            finally:
                self.busy = False

        t = threading.Thread(target=check_task, daemon=True)
        t.start()
