import time
from functools import partial

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QPushButton, QLabel, QVBoxLayout, QWidget, QGridLayout

from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Standard_Wallet
from electrum.gui.qt.util import WindowModalDialog, CloseButton, get_parent_main_window

from .coldcard import ColdcardPlugin
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available


class Plugin(ColdcardPlugin, QtPluginBase):
    icon_unpaired = "coldcard_unpaired.png"
    icon_paired = "coldcard.png"

    def create_handler(self, window):
        return Coldcard_Handler(window)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        if type(wallet) is not Standard_Wallet:
            return
        keystore = wallet.get_keystore()
        if type(keystore) == self.keystore_class and len(addrs) == 1:
            def show_address():
                keystore.thread.add(partial(self.show_address, wallet, addrs[0]))
            menu.addAction(_("Show on Coldcard"), show_address)

    @only_hook_if_libraries_available
    @hook
    def transaction_dialog(self, dia):
        # see gui/qt/transaction_dialog.py

        keystore = dia.wallet.get_keystore()
        if type(keystore) != self.keystore_class:
            # not a Coldcard wallet, hide feature
            return

        # - add a new button, near "export"
        btn = QPushButton(_("Save PSBT"))
        btn.clicked.connect(lambda unused: self.export_psbt(dia))
        if dia.tx.is_complete():
            # but disable it for signed transactions (nothing to do if already signed)
            btn.setDisabled(True)

        dia.sharing_buttons.append(btn)

    def export_psbt(self, dia):
        # Called from hook in transaction dialog
        tx = dia.tx

        if tx.is_complete():
            # if they sign while dialog is open, it can transition from unsigned to signed,
            # which we don't support here, so do nothing
            return

        # can only expect Coldcard wallets to work with these files (right now)
        keystore = dia.wallet.get_keystore()
        assert type(keystore) == self.keystore_class

        # convert to PSBT
        raw_psbt = keystore.build_psbt(tx, wallet=dia.wallet)

        name = (dia.wallet.basename() + time.strftime('-%y%m%d-%H%M.psbt')).replace(' ', '-')
        fileName = dia.main_window.getSaveFileName(_("Select where to save the PSBT file"),
                                                        name, "*.psbt")
        if fileName:
            with open(fileName, "wb+") as f:
                f.write(raw_psbt)
            dia.show_message(_("Transaction exported successfully"))
            dia.saved = True

    def show_settings_dialog(self, window, keystore):
        # When they click on the icon for CC we come here.
        device_id = self.choose_device(window, keystore)
        if device_id:
            CKCCSettingsDialog(window, self, keystore, device_id).exec_()


class Coldcard_Handler(QtHandlerBase):
    setup_signal = pyqtSignal()
    #auth_signal = pyqtSignal(object)

    def __init__(self, win):
        super(Coldcard_Handler, self).__init__(win, 'Coldcard')
        self.setup_signal.connect(self.setup_dialog)
        #self.auth_signal.connect(self.auth_dialog)

    
    def message_dialog(self, msg):
        self.clear_dialog()
        self.dialog = dialog = WindowModalDialog(self.top_level_window(), _("Coldcard Status"))
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(l)
        dialog.show()
        
    def get_setup(self):
        self.done.clear()
        self.setup_signal.emit()
        self.done.wait()
        return 
        
    def setup_dialog(self):
        self.show_error(_('Please initialize your Coldcard while disconnected.'))
        return

class CKCCSettingsDialog(WindowModalDialog):
    '''This dialog doesn't require a device be paired with a wallet.
    We want users to be able to wipe a device even if they've forgotten
    their PIN.'''

    def __init__(self, window, plugin, keystore, device_id):
        title = _("{} Settings").format(plugin.device)
        super(CKCCSettingsDialog, self).__init__(window, title)
        self.setMaximumWidth(540)

        devmgr = plugin.device_manager()
        config = devmgr.config
        handler = keystore.handler
        self.thread = thread = keystore.thread

        def connect_and_doit():
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
        title.setTextInteractionFlags(Qt.LinksAccessibleByMouse)

        grid.addWidget(title , 0,0, 1,2, Qt.AlignHCenter)
        y = 3

        rows = [
            ('fw_version', _("Firmware Version")),
            ('fw_built', _("Build Date")),
            ('bl_version', _("Bootloader")),
            ('xfp', _("Master Fingerprint")),
            ('serial', _("USB Serial")),
        ]
        for row_num, (member_name, label) in enumerate(rows):
            widget = QLabel('<tt>000000000000')
            widget.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)

            grid.addWidget(QLabel(label), y, 0, 1,1, Qt.AlignRight)
            grid.addWidget(widget, y, 1, 1, 1, Qt.AlignLeft)
            setattr(self, member_name, widget)
            y += 1
        body_layout.addLayout(grid)

        upg_btn = QPushButton('Upgrade')
        #upg_btn.setDefault(False)
        def _start_upgrade():
            thread.add(connect_and_doit, on_success=self.start_upgrade)
        upg_btn.clicked.connect(_start_upgrade)

        y += 3
        grid.addWidget(upg_btn, y, 0)
        grid.addWidget(CloseButton(self), y, 1)

        dialog_vbox = QVBoxLayout(self)
        dialog_vbox.addWidget(body)

        # Fetch values and show them
        thread.add(connect_and_doit, on_success=self.show_values)

    def show_values(self, client):
        dev = client.dev

        self.xfp.setText('<tt>0x%08x' % dev.master_fingerprint)
        self.serial.setText('<tt>%s' % dev.serial)

        # ask device for versions: allow extras for future
        fw_date, fw_rel, bl_rel, *rfu = client.get_version()

        self.fw_version.setText('<tt>%s' % fw_rel)
        self.fw_built.setText('<tt>%s' % fw_date)
        self.bl_version.setText('<tt>%s' % bl_rel)

    def start_upgrade(self, client):
        # ask for a filename (must have already downloaded it)
        mw = get_parent_main_window(self)
        dev = client.dev

        fileName = mw.getOpenFileName("Select upgraded firmware file", "*.dfu")
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
            mw.show_error("Does not appear to be a Coldcard firmware file.\n\n%s" % exc)
            return

        # TODO: 
        # - detect if they are trying to downgrade; aint gonna work
        # - warn them about the reboot?
        # - length checks
        # - add progress local bar
        mw.show_message("Ready to Upgrade.\n\nBe patient. Unit will reboot itself when complete.")

        def doit():
            dlen, _ = dev.upload_file(firmware, verify=True)
            assert dlen == len(firmware)

            # append the firmware header a second time
            result = dev.send_recv(CCProtocolPacker.upload(size, size+FW_HEADER_SIZE, hdr))

            # make it reboot into bootlaoder which might install it
            dev.send_recv(CCProtocolPacker.reboot())

        self.thread.add(doit)
        self.close()
