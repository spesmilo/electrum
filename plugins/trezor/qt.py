from PyQt4.Qt import QVBoxLayout, QLabel, SIGNAL, QGridLayout, QInputDialog, QPushButton
import PyQt4.QtCore as QtCore
from electrum_ltc_gui.qt.util import *
from electrum_ltc_gui.qt.main_window import StatusBarButton, ElectrumWindow

from functools import partial
import unicodedata

from electrum_ltc.i18n import _
from electrum_ltc.plugins import hook

from plugins.trezor.qt_generic import QtHandler
from trezor import TrezorPlugin, TrezorWallet
from trezorlib.qt.pinmatrix import PinMatrixWidget

class TrezorQtHandler(QtHandler):
    device = 'Trezor'
    pin_matrix_widget_class = PinMatrixWidget

class Plugin(TrezorPlugin):

    @hook
    def load_wallet(self, wallet, window):
        self.print_error("load_wallet")
        self.wallet = wallet
        self.wallet.plugin = self
        self.trezor_button = StatusBarButton(QIcon(":icons/trezor.png"), _("Trezor"), partial(self.settings_dialog, window))
        if type(window) is ElectrumWindow:
            window.statusBar().addPermanentWidget(self.trezor_button)
        if self.handler is None:
            self.handler = TrezorQtHandler(window)
        msg = self.wallet.sanity_check()
        if msg:
            window.show_error(msg)

    @hook
    def installwizard_load_wallet(self, wallet, window):
        if type(wallet) != TrezorWallet:
            return
        self.load_wallet(wallet, window)

    @hook
    def installwizard_restore(self, wizard, storage):
        if storage.get('wallet_type') != 'trezor':
            return
        seed = wizard.enter_seed_dialog("Enter your Trezor seed", None, func=lambda x:True)
        if not seed:
            return
        wallet = TrezorWallet(storage)
        self.wallet = wallet
        handler = TrezorQtHandler(wizard)
        passphrase = handler.get_passphrase(_("Please enter your Trezor passphrase.") + '\n' + _("Press OK if you do not use one."))
        if passphrase is None:
            return
        password = wizard.password_dialog()
        wallet.add_seed(seed, password)
        wallet.add_cosigner_seed(seed, 'x/', password, passphrase)
        wallet.create_main_account(password)
        # disable trezor plugin
        self.set_enabled(False)
        return wallet

    @hook
    def receive_menu(self, menu, addrs):
        if not self.wallet.is_watching_only() and self.atleast_version(1, 3) and len(addrs) == 1:
            menu.addAction(_("Show on TREZOR"), lambda: self.show_address(addrs[0]))

    def show_address(self, address):
        if not self.wallet.check_proper_device():
            give_error('Wrong device or password')
        try:
            address_path = self.wallet.address_id(address)
            address_n = self.get_client().expand_path(address_path)
        except Exception, e:
            give_error(e)
        try:
            self.get_client().get_address('Litecoin', address_n, True)
        except Exception, e:
            give_error(e)
        finally:
            self.handler.stop()


    def settings_dialog(self, window):
        try:
            device_id = self.get_client().get_device_id()
        except BaseException as e:
            window.show_message(str(e))
            return
        get_label = lambda: self.get_client().features.label
        update_label = lambda: current_label_label.setText("Label: %s" % get_label())
        d = WindowModalDialog(window, _("Trezor Settings"))
        layout = QGridLayout(d)
        layout.addWidget(QLabel("Trezor Options"),0,0)
        layout.addWidget(QLabel("ID:"),1,0)
        layout.addWidget(QLabel(" %s" % device_id),1,1)

        def modify_label():
            response = QInputDialog().getText(None, "Set New Trezor Label", "New Trezor Label:  (upon submission confirm on Trezor)")
            if not response[1]:
                return
            new_label = str(response[0])
            self.handler.show_message("Please confirm label change on Trezor")
            status = self.get_client().apply_settings(label=new_label)
            self.handler.stop()
            update_label()

        current_label_label = QLabel()
        update_label()
        change_label_button = QPushButton("Modify")
        change_label_button.clicked.connect(modify_label)
        layout.addWidget(current_label_label,3,0)
        layout.addWidget(change_label_button,3,1)
        d.exec_()
