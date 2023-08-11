import threading
from functools import partial
from typing import TYPE_CHECKING

from PyQt5.QtCore import pyqtSignal, Qt

from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Standard_Wallet
from electrum.logging import Logger

from electrum.plugins.hw_wallet.qt import QtHandlerBase, QtPluginBase
from electrum.plugins.hw_wallet import plugin
from electrum.gui.qt.util import WWLabel
from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation
from electrum.gui.qt.wizard.wizard import WizardComponent

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

    # insert trezor pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'jade_start': { 'gui': WCScriptAndDerivation },
            'jade_xpub': { 'gui': WCJadeXPub },
            'jade_not_initialized': {'gui': WCJadeNope},
        }
        wizard.navmap_merge(views)


class Jade_Handler(QtHandlerBase):
    setup_signal = pyqtSignal()
    auth_signal = pyqtSignal(object, object)

    MESSAGE_DIALOG_TITLE = _("Jade Status")

    def __init__(self, win):
        super(Jade_Handler, self).__init__(win, 'Jade')


class WCJadeXPub(WizardComponent, Logger): # TODO: almost verbatim copy of trezor WCTrezorXPub, generalize!
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Hardware wallet information'))
        Logger.__init__(self)
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('jade')
        self.busy_msg = _('Unlock your Jade')
        self._busy = True

        self.xpub = None
        self.root_fingerprint = None
        self.label = None
        self.soft_device_id = None

        self.ok_l = WWLabel(_('Hardware keystore added to wallet'))
        self.ok_l.setAlignment(Qt.AlignCenter)
        self.layout().addWidget(self.ok_l)

    def on_ready(self):
        _name, _info = self.wizard_data['hardware_device']
        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        if not client.handler:
            client.handler = self.plugin.create_handler(self.wizard)

        cosigner = self.wizard.current_cosigner(self.wizard_data)
        xtype = cosigner['script_type']
        derivation = cosigner['derivation_path']

        def get_xpub_task(client, derivation, xtype):
            try:
                self.xpub = client.get_xpub(derivation, xtype)
                self.root_fingerprint = client.request_root_fingerprint_from_device()
                self.label = client.label()
                self.soft_device_id = client.get_soft_device_id()
            except Exception as e:
                # TODO: handle user interaction exceptions (e.g. invalid pin) more gracefully
                self.error = repr(e)
                self.logger.error(repr(e))
            self.xpub_done()

        t = threading.Thread(target=get_xpub_task, args=(client, derivation, xtype), daemon=True)
        t.start()

    def xpub_done(self):
        self.logger.debug(f'Done retrieve xpub: {self.xpub}')
        self.busy = False
        self.validate()

    def validate(self):
        if self.xpub and not self.error:
            self.apply()
            valid, error = self.wizard.check_multisig_constraints(self.wizard_data)
            if not valid:
                self.error = '\n'.join([
                    _('Could not add hardware keystore to wallet'),
                    error
                ])
            self.valid = valid
        else:
            self.valid = False

    def apply(self):
        cosigner_data = self.wizard.current_cosigner(self.wizard_data)
        cosigner_data['hw_type'] = 'jade'
        cosigner_data['master_key'] = self.xpub
        cosigner_data['root_fingerprint'] = self.root_fingerprint
        cosigner_data['label'] = self.label
        cosigner_data['soft_device_id'] = self.soft_device_id


class WCJadeNope(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Jade not initialized'))
        self.layout().addWidget(WWLabel(_('This Jade is not initialized. Cannot continue')))
