from functools import partial
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QPushButton, QLabel, QVBoxLayout, QWidget, QGridLayout

from electrum.gui.qt.util import WindowModalDialog, CloseButton, getOpenFileName, getSaveFileName
from electrum.gui.qt.main_window import ElectrumWindow

from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Multisig_Wallet

from .coldcard import ColdcardPlugin, xfp2str
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available
from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWXPub, WCHWUninitialized, WCHWUnlock

if TYPE_CHECKING:
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard

CC_DEBUG = False


class Plugin(ColdcardPlugin, QtPluginBase):
    icon_unpaired = "coldcard_unpaired.png"
    icon_paired = "coldcard.png"

    def create_handler(self, window):
        return Coldcard_Handler(window)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        # Context menu on each address in the Addresses Tab, right click...
        if len(addrs) != 1:
            return
        for keystore in wallet.get_keystores():
            if type(keystore) == self.keystore_class:
                def show_address(keystore=keystore):
                    keystore.thread.add(partial(self.show_address, wallet, addrs[0], keystore=keystore))
                device_name = "{} ({})".format(self.device, keystore.label)
                menu.addAction(_("Show on {}").format(device_name), show_address)

    @only_hook_if_libraries_available
    @hook
    def wallet_info_buttons(self, main_window: 'ElectrumWindow', dialog):
        # user is about to see the "Wallet Information" dialog
        # - add a button if multisig wallet, and a Coldcard is a cosigner.
        assert isinstance(main_window, ElectrumWindow), f"{type(main_window)}"
        wallet = main_window.wallet

        if type(wallet) is not Multisig_Wallet:
            return

        if not any(type(ks) == self.keystore_class for ks in wallet.get_keystores()):
            # doesn't involve a Coldcard wallet, hide feature
            return

        btn = QPushButton(_("Export for Coldcard"))
        btn.clicked.connect(lambda unused: self.export_multisig_setup(main_window, wallet))

        return btn

    def export_multisig_setup(self, main_window, wallet):

        basename = wallet.basename().rsplit('.', 1)[0]        # trim .json
        name = f'{basename}-cc-export.txt'.replace(' ', '-')
        fileName = getSaveFileName(
            parent=main_window,
            title=_("Select where to save the setup file"),
            filename=name,
            filter="*.txt",
            config=self.config,
        )
        if fileName:
            with open(fileName, "wt") as f:
                ColdcardPlugin.export_ms_wallet(wallet, f, basename)
            main_window.show_message(_("Wallet setup file exported successfully"))

    def show_settings_dialog(self, window, keystore):
        # When they click on the icon for CC we come here.
        # - doesn't matter if device not connected, continue
        CKCCSettingsDialog(window, self, keystore).exec()

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    # insert coldcard pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'coldcard_start': {'gui': WCScriptAndDerivation},
            'coldcard_xpub': {'gui': WCHWXPub},
            'coldcard_not_initialized': {'gui': WCHWUninitialized},
            'coldcard_unlock': {'gui': WCHWUnlock}
        }
        wizard.navmap_merge(views)


class Coldcard_Handler(QtHandlerBase):
    MESSAGE_DIALOG_TITLE = _("Coldcard Status")

    def __init__(self, win):
        super(Coldcard_Handler, self).__init__(win, 'Coldcard')


class CKCCSettingsDialog(WindowModalDialog):

    def __init__(self, window: ElectrumWindow, plugin, keystore):
        title = _("{} Settings").format(plugin.device)
        super(CKCCSettingsDialog, self).__init__(window, title)
        self.setMaximumWidth(540)

        # Note: Coldcard may **not** be connected at present time. Keep working!

        devmgr = plugin.device_manager()
        #config = devmgr.config
        #handler = keystore.handler
        self.thread = thread = keystore.thread
        self.keystore = keystore
        assert isinstance(window, ElectrumWindow), f"{type(window)}"
        self.window = window

        def connect_and_doit():
            # Attempt connection to device, or raise.
            device_id = plugin.choose_device(window, keystore)
            if not device_id:
                raise RuntimeError("Device not connected")
            client = devmgr.client_by_id(device_id)
            if not client:
                raise RuntimeError("Device not connected")
            return client

        body = QWidget()
        body_layout = QVBoxLayout(body)
        grid = QGridLayout()
        grid.setColumnStretch(2, 1)

        # see <http://doc.qt.io/archives/qt-4.8/richtext-html-subset.html>
        title = QLabel('''<center>
<span style="font-size: x-large">Coldcard Wallet</span>
<br><span style="font-size: medium">from Coinkite Inc.</span>
<br><a href="https://coldcardwallet.com">coldcardwallet.com</a>''')
        title.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse)

        grid.addWidget(title, 0,0, 1,2, Qt.AlignmentFlag.AlignHCenter)
        y = 3

        rows = [
            ('xfp', _("Master Fingerprint")),
            ('serial', _("USB Serial")),
            ('fw_version', _("Firmware Version")),
            ('fw_built', _("Build Date")),
            ('bl_version', _("Bootloader")),
        ]
        for row_num, (member_name, label) in enumerate(rows):
            # XXX we know xfp already, even if not connected
            widget = QLabel('<tt>000000000000')
            widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)

            grid.addWidget(QLabel(label), y, 0, 1,1, Qt.AlignmentFlag.AlignRight)
            grid.addWidget(widget, y, 1, 1, 1, Qt.AlignmentFlag.AlignLeft)
            setattr(self, member_name, widget)
            y += 1
        body_layout.addLayout(grid)

        upg_btn = QPushButton(_('Upgrade'))
        #upg_btn.setDefault(False)
        def _start_upgrade():
            thread.add(connect_and_doit, on_success=self.start_upgrade)
        upg_btn.clicked.connect(_start_upgrade)

        y += 3
        grid.addWidget(upg_btn, y, 0)
        grid.addWidget(CloseButton(self), y, 1)

        dialog_vbox = QVBoxLayout(self)
        dialog_vbox.addWidget(body)

        # Fetch firmware/versions values and show them.
        thread.add(connect_and_doit, on_success=self.show_values, on_error=self.show_placeholders)

    def show_placeholders(self, unclear_arg):
        # device missing, so hide lots of detail.
        self.xfp.setText('<tt>%s' % self.keystore.get_root_fingerprint())
        self.serial.setText('(not connected)')
        self.fw_version.setText('')
        self.fw_built.setText('')
        self.bl_version.setText('')

    def show_values(self, client):

        dev = client.dev

        self.xfp.setText('<tt>%s' % xfp2str(dev.master_fingerprint))
        self.serial.setText('<tt>%s' % dev.serial)

        # ask device for versions: allow extras for future
        fw_date, fw_rel, bl_rel, *rfu = client.get_version()

        self.fw_version.setText('<tt>%s' % fw_rel)
        self.fw_built.setText('<tt>%s' % fw_date)
        self.bl_version.setText('<tt>%s' % bl_rel)

    def start_upgrade(self, client):
        # ask for a filename (must have already downloaded it)
        dev = client.dev

        fileName = getOpenFileName(
            parent=self,
            title="Select upgraded firmware file",
            filter="*.dfu",
            config=self.window.config,
        )
        if not fileName:
            return

        from ckcc.utils import dfu_parse
        from ckcc.sigheader import FW_HEADER_SIZE, FW_HEADER_OFFSET, FW_HEADER_MAGIC
        from ckcc.protocol import CCProtocolPacker
        from hashlib import sha256
        import struct

        try:
            with open(fileName, 'rb') as fd:

                # unwrap firmware from the DFU
                offset, size, *ignored = dfu_parse(fd)

                fd.seek(offset)
                firmware = fd.read(size)

            hpos = FW_HEADER_OFFSET
            hdr = bytes(firmware[hpos:hpos + FW_HEADER_SIZE])        # needed later too
            magic = struct.unpack_from("<I", hdr)[0]

            if magic != FW_HEADER_MAGIC:
                raise ValueError("Bad magic")
        except Exception as exc:
            self.window.show_error("Does not appear to be a Coldcard firmware file.\n\n%s" % exc)
            return

        # TODO:
        # - detect if they are trying to downgrade; aint gonna work
        # - warn them about the reboot?
        # - length checks
        # - add progress local bar
        self.window.show_message("Ready to Upgrade.\n\nBe patient. Unit will reboot itself when complete.")

        def doit():
            dlen, _ = dev.upload_file(firmware, verify=True)
            assert dlen == len(firmware)

            # append the firmware header a second time
            result = dev.send_recv(CCProtocolPacker.upload(size, size+FW_HEADER_SIZE, hdr))

            # make it reboot into bootloader which might install it
            dev.send_recv(CCProtocolPacker.reboot())

        self.thread.add(doit)
        self.close()
