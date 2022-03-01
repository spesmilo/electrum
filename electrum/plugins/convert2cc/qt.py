import hid
import json
from PyQt5.QtWidgets import QPushButton, QVBoxLayout, QStackedWidget, QLabel

from electrum.gui.qt.util import WindowModalDialog, ChoicesLayout, CloseButton, Buttons, getSaveFileName
from electrum.i18n import _
from electrum.logging import get_logger

from electrum.plugin import hook, BasePlugin
from electrum.plugins.coldcard.qt import Plugin as CCPlugin
from ckcc.electrum import convert2cc, xfp2str, filepath_append_cc

from electrum.wallet import Multisig_Wallet, Standard_Wallet

_logger = get_logger(__name__)


class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

    @staticmethod
    def paired_cc_icon_path():
        return "coldcard.png"

    @staticmethod
    def unpaired_cc_icon_path():
        return "coldcard_unpaired.png"

    # def get_client(self, device):
    #     is_simulator = device.product_key[1] == CKCC_SIMULATED_PID
    #     if is_simulator:
    #         dev = ElectrumColdcardDevice(device.path, encrypt=True)
    #     else:
    #         # open the real HID device
    #         hd = hid.device(path=device.path)
    #         hd.open_path(device.path)
    #
    #         dev = ElectrumColdcardDevice(dev=hd, encrypt=True)
    #     return dev

    @staticmethod
    def is_coldcard_keystore(keystore):
        hw_type = getattr(keystore, "hw_type", None)
        return hw_type == "coldcard"

    def hardware_keystore_not_coldcard(self, keystore) -> bool:
        return keystore.type == "hardware" and not self.is_coldcard_keystore(keystore)

    def coldcards_connected(self):
        clients = []
        devices = self.parent.device_manager.scan_devices()
        for device in devices:
            cc_plugin = CCPlugin(self.parent, self.config, "dummy")
            dev_client = cc_plugin.device_manager().create_client(device, handler=None, plugin=cc_plugin)
            try:
                device_name = dev_client.device
            except AttributeError:
                device_name = "unknown"
            if device_name == "Coldcard":
                clients.append(dev_client)
        return clients

    @staticmethod
    def match_candidate_keystore_to_connected_cc_device(cc_clients, keystore):
        keystore_dict = keystore.dump()
        for cc_client in cc_clients:
            dev = cc_client.dev
            dev_xfp = xfp2str(dev.master_fingerprint).lower()
            fingerprint_match = dev_xfp == keystore_dict["root_fingerprint"].lower()
            print("{} == {}                    {}".format(dev_xfp, keystore_dict["root_fingerprint"], fingerprint_match))
            # here we should probably check if derivation path generates same Vpub on cc
            if fingerprint_match:
                return dev

    @hook
    def wallet_info_buttons(self, main_window, dialog):
        # user is about to see the "Wallet Information" dialog
        # - add a button if multisig wallet, and a Coldcard is a cosigner.
        buttons = []
        show_button = False
        wallet = main_window.wallet
        # only show button if convert is possible
        # 1. must be standard or multisig wallet
        # 2. at least one keystore must not be coldcard in multisig
        # 3. in single sig - keystore must not be coldcard
        if type(wallet) == Standard_Wallet:
            if self.hardware_keystore_not_coldcard(wallet.keystore):
                show_button = True
        elif type(wallet) == Multisig_Wallet:
            for key, keystore in wallet.keystores.items():
                if self.hardware_keystore_not_coldcard(keystore):
                    show_button = True

        if show_button:
            btn = QPushButton(_("convert2cc"))
            btn.clicked.connect(lambda unused: self.convert2cc_modal_dialog(main_window))
            buttons.append(btn)
        return buttons

    def convert2cc_modal_dialog(self, main_window):
        connected_cc_clients = self.coldcards_connected()
        description = """
fkjslkdjflskjflkdsjflksdjflksdjflksdjfksdjfjlksdjflkdsjfslkdjfs
sfjlkdsjfdklsjflkdjflksdjflksdjflksdjflksdjflksdjflksdjflskdjf
sfdlksjfdlksdjflsjfslkdjflsdkjflksjfdlskjflkdsjflkdsjflksjflksjf
lfskdjflskjgdlkfjgsmocvsdjgadjrgmvaodjgrjrdgo,jgomadkrg,vodkga
adjumvadivadmoi,adg;oimori, i mdo;fkthpotim t iapord spothposfjt
        """
        wallet = main_window.wallet
        non_cc_hw_keystores = [ks for ks in wallet.get_keystores() if self.hardware_keystore_not_coldcard(ks)]
        print(non_cc_hw_keystores)
        dialog = WindowModalDialog(main_window, _("convert2cc"))
        dialog.setMinimumSize(600, 80)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_(description)))
        ks_stack = QStackedWidget()

        def select_ks(index):
            ks_stack.setCurrentIndex(index)

        # def label(idx, ks):
        #     dev = self.match_candidate_keystore_to_connected_cc_device(connected_cc_clients, ks)
        #     if isinstance(wallet, Multisig_Wallet) and hasattr(ks, 'label'):
        #         res = _("cosigner") + f' {idx + 1}: {ks.get_type_text()} {ks.label}'
        #     else:
        #         res = _("keystore") + f' {idx + 1}: {ks.get_type_text()}' + f' {ks.label}' if hasattr(ks, 'label') else ""
        #     if dev:
        #         res = res + 20 * " " + "[matches connected coldcard]", self.paired_cc_icon_path()
        #     else:
        #         res = res, self.unpaired_cc_icon_path()
        #     return res
        #
        # labels = [label(idx, ks) for idx, ks in enumerate(non_cc_hw_keystores)]

        labels = []
        ks_dev_lst = []
        for idx, ks in enumerate(non_cc_hw_keystores):
            dev = self.match_candidate_keystore_to_connected_cc_device(connected_cc_clients, ks)
            if isinstance(wallet, Multisig_Wallet) and hasattr(ks, 'label'):
                res = _("cosigner") + f' {idx + 1}: {ks.get_type_text()} {ks.label}'
            else:
                res = _("keystore") + f' {idx + 1}: {ks.get_type_text()}' + f' {ks.label}' if hasattr(ks,'label') else ""
            if dev:
                res = res + 20 * " " + "[matches connected coldcard]", self.paired_cc_icon_path()
            else:
                res = res, self.unpaired_cc_icon_path()
            labels.append(res)
            ks_dev_lst.append((ks, dev))

        on_click = lambda clayout: select_ks(clayout.selected_index())
        labels_clayout = ChoicesLayout(_("Select keystore"), labels, on_click)
        vbox.addLayout(labels_clayout.layout())
        vbox.addStretch(1)
        btn_close = CloseButton(dialog)
        btn_convert = QPushButton(_("convert"))
        btn_convert.clicked.connect(lambda unused: self.do_convert2cc(main_window, labels_clayout, ks_dev_lst, dialog))
        vbox.addLayout(Buttons(btn_convert, btn_close))
        dialog.setLayout(vbox)
        dialog.exec_()

    def do_convert2cc(self, main_window, labels_clayout, ks_dev_list, dialog):
        wallet = main_window.wallet
        selected_index = labels_clayout.selected_index()
        if selected_index is not None:
            target_keystore, dev = ks_dev_list[selected_index]
            try:
                new_wallet_str = convert2cc(wallet.db.dump(), dev=dev, key="xpub", val=target_keystore.xpub)

                default_filename = filepath_append_cc(wallet.basename())
                user_filename = getSaveFileName(
                    parent=main_window,
                    title=_("Select where to save the new wallet file"),
                    filename=default_filename,
                    filter="*",
                    config=self.config,
                )
                dialog.close()
                if user_filename:
                    with open(user_filename, "w") as f:
                        f.write(new_wallet_str)
                    if main_window.question('\n'.join([
                        _('Open wallet file?'),
                        "%s" % user_filename,
                        _('This will open a new wallet window with converted wallet.')
                    ])):
                        main_window.open_wallet(filename=user_filename)
            except Exception as e:
                print(e)
