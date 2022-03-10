import os
import PyQt5.Qt
import hid
from contextlib import contextmanager
from PyQt5.QtWidgets import QPushButton, QVBoxLayout, QStackedWidget, QLabel, QCheckBox

from ckcc.client import COINKITE_VID, CKCC_PID
from ckcc.electrum import convert2cc, xfp2str, filepath_append_cc

from electrum.logging import get_logger
from electrum.gui.qt.util import WindowModalDialog, ChoicesLayout, CloseButton, Buttons, getSaveFileName
from electrum.i18n import _
from electrum.plugin import hook, BasePlugin
from electrum.plugins.coldcard.coldcard import CKCC_SIMULATED_PID, ElectrumColdcardDevice, CKCCClient
from electrum.wallet import Multisig_Wallet, Standard_Wallet


logger = get_logger(__name__)


class Plugin(BasePlugin):
    paired_icon = "coldcard.png"
    unpaired_icon = "coldcard_unpaired.png"

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

    @property
    def paired_cc_icon_path(self):
        return self.paired_icon

    @property
    def unpaired_cc_icon_path(self):
        return self.unpaired_icon

    @staticmethod
    def get_client(device):
        if device.product_key not in [
            (COINKITE_VID, CKCC_PID),
            (COINKITE_VID, CKCC_SIMULATED_PID)
        ]:
            # not a coldcard device - return
            return
        is_simulator = device.product_key[1] == CKCC_SIMULATED_PID
        if is_simulator:
            dev = ElectrumColdcardDevice(device.path, encrypt=True)
        else:
            # open the real HID device
            hd = hid.device(path=device.path)
            hd.open_path(device.path)
            dev = ElectrumColdcardDevice(dev=hd, encrypt=True)
        return dev

    @staticmethod
    def is_hardware_keystore(keystore):
        return keystore.type == "hardware"

    @staticmethod
    def is_coldcard_keystore(keystore):
        hw_type = getattr(keystore, "hw_type", None)
        return hw_type == "coldcard"

    @staticmethod
    def is_supported_wallet_type(wallet):
        # 1. must be standard or multisig wallet
        wallet_type = type(wallet)
        if wallet_type in [Standard_Wallet, Multisig_Wallet]:
            return True
        return False

    def opened_devmgr_cc_clients(self) -> dict:
        res = {}
        for client, (path, id_) in self.parent.device_manager.clients.items():
            if isinstance(client, CKCCClient):
                res[(path, id_)] = client
        return res

    def scan_devices(self):
        return self.parent.device_manager.scan_devices()

    @contextmanager
    def coldcards_connected(self):
        clients = []
        open_failed = []
        devices = self.scan_devices()
        cc_opened = self.opened_devmgr_cc_clients()
        hijacked_client = []
        for device in devices:
            # check if device is not already opened in electrum
            # if yes - use that connection
            ckcc_client = cc_opened.get((device.path, device.id_), None)
            if ckcc_client:
                dev_client = ckcc_client.dev
                hijacked_client.append(dev_client)
            else:
                try:
                    dev_client = self.get_client(device)
                except OSError as e:
                    logger.warning("Tried to connect to already connected Coldcard. Error: {}".format(e))
                    open_failed.append(device)
                    continue
            if dev_client:
                clients.append(dev_client)
        yield clients, open_failed
        for client in clients:
            if client not in hijacked_client:
                # only close the client if we have not hijacked the connection form electrum
                client.close()

    def hardware_keystore_not_coldcard(self, keystore) -> bool:
        return self.is_hardware_keystore(keystore) and not self.is_coldcard_keystore(keystore)

    def is_non_cc_hardware_keystore(self, wallet):
        # 2. at least one keystore must not be coldcard in multisig
        # 3. in single sig - keystore must not be coldcard
        if type(wallet) == Standard_Wallet:
            if self.hardware_keystore_not_coldcard(wallet.keystore):
                return True
        elif type(wallet) == Multisig_Wallet:
            for key, keystore in wallet.keystores.items():
                if self.hardware_keystore_not_coldcard(keystore):
                    return True
        return False

    @staticmethod
    def match_candidate_keystore_to_connected_cc_device(cc_clients, keystore):
        keystore_dict = keystore.dump()
        for cc_client in cc_clients:
            dev_xfp = xfp2str(cc_client.master_fingerprint).lower()
            fingerprint_match = dev_xfp == keystore_dict["root_fingerprint"].lower()
            # here we should probably check if derivation path generates same Vpub on cc
            if fingerprint_match:
                return cc_client

    @hook
    def wallet_info_buttons(self, main_window, dialog):
        # user is about to see the "Wallet Information" dialog
        # - add convert2cc button if plugin is ON
        buttons = []
        btn = QPushButton(_("convert2cc"))
        btn.clicked.connect(lambda unused: self.convert2cc_modal_dialog(main_window, dialog))
        buttons.append(btn)
        return buttons

    def convert2cc_modal_dialog(self, main_window, wi_dialog):
        can_convert = True
        description = """
<center>
<span style="font-size: x-large">Convert to Coldcard</span>
<br><a href="https://coldcardwallet.com">coldcardwallet.com</a>
</center>
<p style="text-align: center"><strong>convert2cc</strong> (a.k.a 'convert to Coldcard') is a electrum wallet utility,<br>
which allows users to create new converted wallet from existing wallet,<br>
where one chooses which hardware device gets converted to Coldcard.<br>
All wallet data like contacts, labels, payment requests etc. are preserved.<br>
If you've chosen to change your hardware wallet to Coldcard, convert2cc<br>
will save you the hustle.</p>
"""
        wallet = main_window.wallet
        dialog = WindowModalDialog(main_window, _("convert2cc"))
        dialog.setMinimumSize(600, 80)
        vbox = QVBoxLayout()
        if not self.is_supported_wallet_type(wallet):
            can_convert = False
            description = description + os.linesep + """
<p style="text-align: center"><strong>convert2cc not possible!</strong> Only standard and multisig wallets are supported.<br>
"""
        elif not self.is_non_cc_hardware_keystore(wallet):
            can_convert = False
            description = description + os.linesep + """
<p style="text-align: center"><strong>convert2cc nothing to convert!</strong> At least one of the cosigners/keystores must be<br>
hardware device other than Coldcard</p>
"""
        if not can_convert:
            vbox.addWidget(QLabel(_(description)))
            btn_close = CloseButton(dialog)
            vbox.addLayout(Buttons(btn_close))
        else:
            description = description + os.linesep + f"""
<p style="text-align: center">     
You're about to convert one of your keystores/cosigners to Coldcard.<br>
Please, close all other wallet windows. Make sure you have loaded the correct<br>
wallet (do not forget BIP39 passphrase if used). If you have not connected your<br>
Coldcard yet, please connect it (make sure no other app is using it) and close/re-open<br>
this window. After this your Coldcard should match target keystores/cosigner<br>
in this wallet. Your Coldcard does not need to be connected - but it is recommended.<br>
<br>
convert2cc does not rewrite your existing wallet file, but rather copy it<br>
and create new one. After successful convert, new wallet will be opened.<br>
</p>
            """
            non_cc_hw_keystores = [ks for ks in wallet.get_keystores() if self.hardware_keystore_not_coldcard(ks)]
            vbox.addWidget(QLabel(_(description)))
            if wallet.storage.is_encrypted():
                if wallet.storage.is_encrypted_with_hw_device():
                    encryption_warning = (
                        '<p style="text-align: center"><br><strong>WARNING:</strong><br>'
                        'Your wallet is encrypted with hardware device. Please, make sure to only preserve<br>'
                        ' encryption settings if you have the exact same wallet loaded in your connected<br>'
                        ' Coldcard. Without Coldcard connected you will not be able to open converted wallet.</p>'
                    )
                else:
                    assert wallet.storage.is_encrypted_with_user_pw()
                    encryption_warning = (
                        '<p style="text-align: center"><br><strong>WARNING:</strong><br>'
                        'Your wallet is encrypted with password. Please, make sure to only<br>'
                        ' preserve encryption settings if you remember your password.</p>'
                    )
                vbox.addWidget(QLabel(_(encryption_warning)))
                cb_preserve_encryption = QCheckBox(_('Preserve encryption settings'))
                cb_preserve_encryption.setChecked(True)
                vbox.addWidget(cb_preserve_encryption)
                vbox.setAlignment(cb_preserve_encryption, PyQt5.Qt.Qt.AlignCenter)

            ks_stack = QStackedWidget()

            def select_ks(index):
                ks_stack.setCurrentIndex(index)

            labels = []
            with self.coldcards_connected() as cc_res:
                connected_cc_clients, cc_open_failed = cc_res
                for idx, ks in enumerate(non_cc_hw_keystores):
                    dev = self.match_candidate_keystore_to_connected_cc_device(connected_cc_clients, ks)
                    if isinstance(wallet, Multisig_Wallet) and hasattr(ks, 'label'):
                        res = _("cosigner") + f' {idx + 1}: {ks.get_type_text()} {ks.label}'
                    else:
                        res = _("keystore") + f' {idx + 1}: {ks.get_type_text()}' + f' {ks.label}' if hasattr(ks,'label') else ""
                    if dev:
                        res = res + 20 * " " + "[matches connected Coldcard]", self.paired_cc_icon_path
                    else:
                        res = res, self.unpaired_cc_icon_path
                    labels.append(res)
            # close opened cc devices --> check self.coldcards_connected

            on_click = lambda clayout: select_ks(clayout.selected_index())
            labels_clayout = ChoicesLayout(_("Select keystore"), labels, on_click)
            vbox.addLayout(labels_clayout.layout())
            if cc_open_failed:
                # some coldcards are connected but are used by different application
                # show user the msg
                cc_conn_fail = ChoicesLayout(
                    _("Unable to connect to plugged in Coldcard:"),
                    ["Coldcard " + device.id_ + 20 * " " + "[re-connect device]" for device in cc_open_failed],
                    disable_buttons=True
                )
                vbox.addLayout(cc_conn_fail.layout())
            btn_close = CloseButton(dialog)
            btn_convert = QPushButton(_("convert"))
            btn_convert.clicked.connect(
                lambda unused: self.do_convert2cc(
                    main_window,
                    labels_clayout,
                    non_cc_hw_keystores,
                    dialog,
                    wi_dialog,
                    cb_preserve_encryption.isChecked()
                )
            )
            vbox.addLayout(Buttons(btn_convert, btn_close))
        vbox.addStretch()
        dialog.setLayout(vbox)
        dialog.exec_()

    def do_convert2cc(self, main_window, labels_clayout, keystores, convert2cc_dialog, wi_dialog, preserve_encryption):
        wallet = main_window.wallet
        selected_index = labels_clayout.selected_index()
        if selected_index is not None:
            target_keystore = keystores[selected_index]
            with self.coldcards_connected() as cc_res:
                connected_cc_clients, cc_open_failed = cc_res
                # dev = self.match_candidate_keystore_to_connected_cc_device(connected_cc_clients, target_keystore)
                dev = None
                try:
                    new_wallet_str = convert2cc(wallet.db.dump(), dev=dev, key="xpub", val=target_keystore.xpub)
                    if preserve_encryption:
                        new_wallet_str = wallet.storage.encrypt_before_writing(new_wallet_str)
                except Exception as e:
                    logger.exception("")
                    main_window.show_error(_('Error converting wallet') + ':\n' + str(e))
                    new_wallet_str = None

            if new_wallet_str:
                default_filename = filepath_append_cc(wallet.basename())
                user_filename = getSaveFileName(
                    parent=main_window,
                    title=_("Select where to save the new wallet file"),
                    filename=default_filename,
                    filter="*",
                    config=self.config,
                )
                convert2cc_dialog.close()  # close convert2cc dialog
                wi_dialog.close()  # close wallet information dialog
                if user_filename:
                    with open(user_filename, "w") as f:
                        f.write(new_wallet_str)
                    if main_window.question('\n'.join([
                        _('Open wallet file?'),
                        "%s" % user_filename,
                        _('This will open the converted wallet in current wallet window.')
                    ])):
                        main_window.open_wallet(filename=user_filename)  # open converted target wallet
                        main_window.close()  # close source wallet
