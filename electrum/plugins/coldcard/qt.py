import time
from functools import partial

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QPushButton, QLabel, QVBoxLayout, QWidget, QGridLayout
from PyQt5.QtWidgets import QFileDialog

from electrum.i18n import _
from electrum.plugin import hook
from electrum.wallet import Standard_Wallet, Multisig_Wallet
from electrum.gui.qt.util import WindowModalDialog, CloseButton, get_parent_main_window, Buttons
from electrum.transaction import Transaction

from .coldcard import ColdcardPlugin, xfp2str
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available

from binascii import a2b_hex
from base64 import b64encode, b64decode

from .basic_psbt import BasicPSBT
from .build_psbt import build_psbt, combine_psbt

class Plugin(ColdcardPlugin, QtPluginBase):
    icon_unpaired = "coldcard_unpaired.png"
    icon_paired = "coldcard.png"

    def create_handler(self, window):
        return Coldcard_Handler(window)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        # Context menu on each address in the Addresses Tab, right click...

        if type(wallet) is Standard_Wallet:
            keystore = wallet.get_keystore()
        else:
            # find if any devices are connected and ready to go, use first of those.
            for ks in wallet.get_keystores():
                if ks.has_usable_connection_with_device():
                    keystore = ks
                    break
            else:
                # don't hook into menu
                return

        if type(keystore) == self.keystore_class and len(addrs) == 1:
            def show_address():
                keystore.thread.add(partial(self.show_address, wallet, addrs[0], keystore=keystore))
            menu.addAction(_("Show on Coldcard ({})").format(keystore.label), show_address)

    @only_hook_if_libraries_available
    @hook
    def wallet_info_buttons(self, main_window, dialog):
        # user is about to see the "Wallet Information" dialog
        # - add a button if multisig wallet, and a Coldcard is a cosigner.
        wallet = main_window.wallet

        if type(wallet) is not Multisig_Wallet:
            return

        if not any(type(ks) == self.keystore_class for ks in wallet.get_keystores()):
            # doesn't involve a Coldcard wallet, hide feature
            return

        btn = QPushButton(_("Export for Coldcard"))
        btn.clicked.connect(lambda unused: self.export_multisig_setup(main_window, wallet))

        return Buttons(btn, CloseButton(dialog))

    def export_multisig_setup(self, main_window, wallet):

        basename = wallet.basename().rsplit('.', 1)[0]        # trim .json
        name = f'{basename}-cc-export.txt'.replace(' ', '-')
        fileName = main_window.getSaveFileName(_("Select where to save the setup file"),
                                                        name, "*.txt")
        if fileName:
            with open(fileName, "wt") as f:
                ColdcardPlugin.export_ms_wallet(wallet, f, basename)
            main_window.show_message(_("Wallet setup file exported successfully"))

    @only_hook_if_libraries_available
    @hook
    def transaction_dialog(self, dia):
        # see gui/qt/transaction_dialog.py

        # if not a Coldcard wallet, hide feature
        if not any(type(ks) != self.keystore_class for ks in dia.wallet.get_keystores()):
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
        build_psbt(tx, dia.wallet)

        name = (dia.wallet.basename() + time.strftime('-%y%m%d-%H%M.psbt'))\
                    .replace(' ', '-').replace('.json', '')
        fileName = dia.main_window.getSaveFileName(_("Select where to save the PSBT file"),
                                                        name, "*.psbt")
        if fileName:
            with open(fileName, "wb+") as f:
                f.write(tx.raw_psbt)
            dia.show_message(_("Transaction exported successfully"))
            dia.saved = True

    def show_settings_dialog(self, window, keystore):
        # When they click on the icon for CC we come here.
        # - doesn't matter if device not connected, continue
        CKCCSettingsDialog(window, self, keystore).exec_()

    @hook
    def init_menubar_tools(self, main_window, tools_menu):
        # add some PSBT-related tools to the Tool menu.
        tools_menu.addSeparator()
        tools_menu.addAction(_("&Combine PSBT Files"), lambda: self.psbt_combiner(main_window))

    def psbt_combiner(self, window):
        title = _("Select the signed PSBT files to combine")
        directory = ''
        fnames, __ = QFileDialog.getOpenFileNames(window, title, directory, "PSBT Files (*.psbt)")

        psbts = []
        for fn in fnames:
            try:
                with open(fn, "rb") as f:
                    raw = f.read()

                    psbt = BasicPSBT()
                    psbt.parse(raw, fn)

                    psbts.append(psbt)
            except (AssertionError, ValueError, IOError, os.error) as reason:
                window.show_critical(_("Electrum was unable to open your PSBT file") + "\n" + str(reason), title=_("Unable to read file"))
                return

    
        if len(psbts) < 2:
            window.show_critical(_("Need 2 or more PSBT to be able to combine them."),
                                        title=_("Unable to combine PSBT files"))
            return

        # Consistency checks
        try:
            first = psbts[0]
            for p in psbts:
                assert (p.txn == first.txn), \
                    "All must relate to the same original transaction"

                for idx, inp in enumerate(p.inputs):
                    assert inp.part_sigs, "No partial signatures found in file"
                    assert first.inputs[idx].redeem_script == inp.redeem_script, "Mismatched redeem scripts"
                    assert first.inputs[idx].witness_script == inp.witness_script, "Mismatched witness"
                    
        except AssertionError as exc:
            window.show_critical(str(exc), title=_("Unable to combine PSBT files, check: ")+p.filename)
            return

        # Build the transaction, add sigs, and show to user for possible transmission.
        tx = Transaction(first.txn.hex())
        tx.deserialize(force_full_parse=True)

        from electrum.transaction import parse_redeemScript_multisig

        # .. add back some data that's been preserved in the PSBT, but isn't part of
        # of the unsigned bitcoin txn
        tx.is_partial_originally = True
        for idx, inp in enumerate(tx.inputs()):
            scr = first.inputs[idx].redeem_script
            if scr:
                M, N, __, pubkeys, __ = parse_redeemScript_multisig(scr)
                inp['pubkeys'] = pubkeys
                inp['x_pubkeys'] = pubkeys
                inp['num_sig'] = M
                inp['type'] = 'p2sh'        # XXX p2wsh
                # bugfix: transaction.pyparse_input puts dict here?
                inp['signatures'] = [None] * N      

        for p in psbts:
            try:
                combine_psbt(tx, p)
            except BaseException as exc:
                from PyQt5.QtCore import pyqtRemoveInputHook
                pyqtRemoveInputHook()
                import pdb; pdb.post_mortem()
                window.show_critical(str(exc), 
                    title=_("Unable to combine PSBT file: ") + p.filename)
                return

        # Display result, might not be complete yet.
        window.show_transaction(tx, "PSBT Combined")

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

    def __init__(self, window, plugin, keystore):
        title = _("{} Settings").format(plugin.device)
        super(CKCCSettingsDialog, self).__init__(window, title)
        self.setMaximumWidth(540)

        # Note: Coldcard may **not** be connected at present time. Keep working!

        devmgr = plugin.device_manager()
        #config = devmgr.config
        #handler = keystore.handler
        self.thread = thread = keystore.thread
        self.keystore = keystore

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
        title.setTextInteractionFlags(Qt.LinksAccessibleByMouse)

        grid.addWidget(title , 0,0, 1,2, Qt.AlignHCenter)
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
            widget.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)

            grid.addWidget(QLabel(label), y, 0, 1,1, Qt.AlignRight)
            grid.addWidget(widget, y, 1, 1, 1, Qt.AlignLeft)
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
        self.xfp.setText('<tt>%s' % xfp2str(self.keystore.ckcc_xfp))
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
