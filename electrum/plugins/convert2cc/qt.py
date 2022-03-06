import os
import hid
from contextlib import contextmanager
from PyQt5.QtWidgets import QPushButton, QVBoxLayout, QStackedWidget, QLabel

from ckcc.client import COINKITE_VID, CKCC_PID
from ckcc.electrum import convert2cc, xfp2str, filepath_append_cc

from electrum.gui.qt.util import WindowModalDialog, ChoicesLayout, CloseButton, Buttons, getSaveFileName
from electrum.i18n import _
from electrum.plugin import hook, BasePlugin
from electrum.plugins.coldcard.coldcard import CKCC_SIMULATED_PID, ElectrumColdcardDevice
from electrum.wallet import Multisig_Wallet, Standard_Wallet


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

    @contextmanager
    def coldcards_connected(self):
        clients = []
        devices = self.parent.device_manager.scan_devices()
        for device in devices:
            dev_client = self.get_client(device)
            if dev_client:
                clients.append(dev_client)
        yield clients
        for client in clients:
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
            wi_dialog.close()  # close wallet information dialog
            description = description + os.linesep + """
<p style="text-align: center">     
You're about to convert one of your keystores/cosigners to Coldcard.<br>
Please, close all other wallet windows. Make sure you have loaded the correct<br>
wallet and do not forget BIP39 passphrase if used. If you have not connected your<br>
new Coldcard yet, please connect it and close/re-open this window.<br>
After this your Coldcard should match target keystores/cosigner in this wallet.<br>
Your Coldcard does not need to be connected - but it is recommended.<br>
<br>
convert2cc does not rewrite your existing wallet file, but rather copy it<br>
and create new one. After successful convert, new wallet will be opened.<br>
</p>
            """
            non_cc_hw_keystores = [ks for ks in wallet.get_keystores() if self.hardware_keystore_not_coldcard(ks)]
            vbox.addWidget(QLabel(_(description)))
            ks_stack = QStackedWidget()

            def select_ks(index):
                ks_stack.setCurrentIndex(index)

            labels = []
            with self.coldcards_connected() as connected_cc_clients:
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
            btn_close = CloseButton(dialog)
            btn_convert = QPushButton(_("convert"))
            btn_convert.clicked.connect(lambda unused: self.do_convert2cc(main_window, labels_clayout, non_cc_hw_keystores, dialog))
            vbox.addLayout(Buttons(btn_convert, btn_close))
        vbox.addStretch(1)
        dialog.setLayout(vbox)
        dialog.exec_()

    def do_convert2cc(self, main_window, labels_clayout, keystores, dialog):
        wallet = main_window.wallet
        selected_index = labels_clayout.selected_index()
        if selected_index is not None:
            target_keystore = keystores[selected_index]
            with self.coldcards_connected() as connected_cc_clients:
                dev = self.match_candidate_keystore_to_connected_cc_device(connected_cc_clients, target_keystore)
                try:
                    new_wallet_str = convert2cc(wallet.db.dump(), dev=dev, key="xpub", val=target_keystore.xpub)
                except Exception as e:
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
                dialog.close()  # close convert2cc dialog
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
