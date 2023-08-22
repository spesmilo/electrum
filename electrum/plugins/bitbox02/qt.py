import threading
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
    ButtonsTextEdit, WWLabel,
)

from electrum.i18n import _
from electrum.plugin import hook

from .bitbox02 import BitBox02Plugin
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available
from electrum.gui.qt.wizard.wizard import WizardComponent
from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWUnlock
from electrum.logging import Logger

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
            'bitbox_start': { 'gui': WCScriptAndDerivation },
            'bitbox_xpub': { 'gui': WCBitboxXPub },
            'bitbox_not_initialized': {'gui': WCBitboxNope},
            'bitbox_unlock': {'gui': WCHWUnlock}
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


# TODO: almost verbatim copy of trezor WCTrezorXPub, generalize!
# problem: client.get_xpub is not uniform
class WCBitboxXPub(WizardComponent, Logger):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Hardware wallet information'))
        Logger.__init__(self)
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('bitbox02')
        self.busy_msg = _('Unlock your Bitbox02')
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
        cosigner_data['hw_type'] = 'bitbox02'
        cosigner_data['master_key'] = self.xpub
        cosigner_data['root_fingerprint'] = self.root_fingerprint
        cosigner_data['label'] = self.label
        cosigner_data['soft_device_id'] = self.soft_device_id


class WCBitboxNope(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Bitbox02 not initialized'))
        self.layout().addWidget(WWLabel(_('This Bitbox02 is not initialized. Cannot continue')))

