from PyQt4.Qt import QMessageBox, QDialog, QVBoxLayout, QLabel, QThread, SIGNAL, QGridLayout, QInputDialog, QPushButton
import PyQt4.QtCore as QtCore
from electrum_gui.qt.util import *
from electrum_gui.qt.main_window import StatusBarButton, ElectrumWindow
from electrum_gui.qt.installwizard import InstallWizard
from keepkeylib.qt.pinmatrix import PinMatrixWidget

from functools import partial

from keepkey import KeepKeyPlugin, KeepKeyWallet
from electrum.plugins import hook
from electrum.i18n import _

class Plugin(KeepKeyPlugin):

    @hook
    def load_wallet(self, wallet, window):
        self.print_error("load_wallet")
        self.wallet = wallet
        self.wallet.plugin = self
        self.keepkey_button = StatusBarButton(QIcon(":icons/keepkey.png"), _("KeepKey"), partial(self.settings_dialog, window))
        if type(window) is ElectrumWindow:
            window.statusBar().addPermanentWidget(self.keepkey_button)
        if self.handler is None:
            self.handler = KeepKeyQtHandler(window)
        try:
            self.get_client().ping('t')
        except BaseException as e:
            QMessageBox.information(window, _('Error'), _("KeepKey device not detected.\nContinuing in watching-only mode." + '\n\nReason:\n' + str(e)), _('OK'))
            self.wallet.force_watching_only = True
            return
        if self.wallet.addresses() and not self.wallet.check_proper_device():
            QMessageBox.information(window, _('Error'), _("This wallet does not match your KeepKey device"), _('OK'))
            self.wallet.force_watching_only = True

    @hook
    def installwizard_load_wallet(self, wallet, window):
        if type(wallet) != KeepKeyWallet:
            return
        self.load_wallet(wallet, window)

    @hook
    def installwizard_restore(self, wizard, storage):
        if storage.get('wallet_type') != 'keepkey':
            return
        seed = wizard.enter_seed_dialog("Enter your KeepKey seed", None, func=lambda x:True)
        if not seed:
            return
        wallet = KeepKeyWallet(storage)
        self.wallet = wallet
        handler = KeepKeyQtHandler(wizard)
        passphrase = handler.get_passphrase(_("Please enter your KeepKey passphrase.") + '\n' + _("Press OK if you do not use one."))
        if passphrase is None:
            return
        password = wizard.password_dialog()
        wallet.add_seed(seed, password)
        wallet.add_cosigner_seed(seed, 'x/', password, passphrase)
        wallet.create_main_account(password)
        # disable keepkey plugin
        self.set_enabled(False)
        return wallet

    @hook
    def receive_menu(self, menu, addrs):
        if not self.wallet.is_watching_only() and self.atleast_version(1, 3) and len(addrs) == 1:
            menu.addAction(_("Show on TREZOR"), lambda: self.show_address(addrs[0]))

    def settings_dialog(self, window):
        try:
            device_id = self.get_client().get_device_id()
        except BaseException as e:
            window.show_message(str(e))
            return
        get_label = lambda: self.get_client().features.label
        update_label = lambda: current_label_label.setText("Label: %s" % get_label())
        d = QDialog()
        layout = QGridLayout(d)
        layout.addWidget(QLabel("KeepKey Options"),0,0)
        layout.addWidget(QLabel("ID:"),1,0)
        layout.addWidget(QLabel(" %s" % device_id),1,1)

        def modify_label():
            response = QInputDialog().getText(None, "Set New KeepKey Label", "New KeepKey Label:  (upon submission confirm on KeepKey)")
            if not response[1]:
                return
            new_label = str(response[0])
            self.handler.show_message("Please confirm label change on KeepKey")
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


class KeepKeyQtHandler:

    def __init__(self, win):
        self.win = win
        self.win.connect(win, SIGNAL('keepkey_done'), self.dialog_stop)
        self.win.connect(win, SIGNAL('message_dialog'), self.message_dialog)
        self.win.connect(win, SIGNAL('pin_dialog'), self.pin_dialog)
        self.win.connect(win, SIGNAL('passphrase_dialog'), self.passphrase_dialog)
        self.done = threading.Event()

    def stop(self):
        self.win.emit(SIGNAL('keepkey_done'))

    def show_message(self, msg_code, msg, client):
        self.messsage_code = msg_code
        self.message = msg
        self.client = client
        self.win.emit(SIGNAL('message_dialog'))

    def get_pin(self, msg):
        self.done.clear()
        self.message = msg
        self.win.emit(SIGNAL('pin_dialog'))
        self.done.wait()
        return self.response

    def get_passphrase(self, msg):
        self.done.clear()
        self.message = msg
        self.win.emit(SIGNAL('passphrase_dialog'))
        self.done.wait()
        return self.passphrase

    def pin_dialog(self):
        d = QDialog(None)
        d.setModal(1)
        d.setWindowTitle(_("Enter PIN"))
        d.setWindowFlags(d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        matrix = PinMatrixWidget()
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(self.message))
        vbox.addWidget(matrix)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)
        if not d.exec_():
            self.response = None
        self.response = str(matrix.get_value())
        self.done.set()

    def passphrase_dialog(self):
        if type(self.win) is ElectrumWindow:
            passphrase = self.win.password_dialog(_("Please enter your KeepKey passphrase"))
            self.passphrase = unicodedata.normalize('NFKD', unicode(passphrase)) if passphrase else ''
        else:
            assert type(self.win) is InstallWizard
            from electrum_gui.qt.password_dialog import make_password_dialog, run_password_dialog
            d = QDialog()
            d.setModal(1)
            d.setLayout(make_password_dialog(d, None, self.message, False))
            confirmed, p, passphrase = run_password_dialog(d, None, None)
            if not confirmed:
                QMessageBox.critical(None, _('Error'), _("Password request canceled"), _('OK'))
                self.passphrase = None
            else:
                self.passphrase = unicodedata.normalize('NFKD', unicode(passphrase)) if passphrase else ''
        self.done.set()

    def message_dialog(self):
        self.d = QDialog()
        self.d.setModal(1)
        self.d.setWindowTitle('Please Check KeepKey Device')
        self.d.setWindowFlags(self.d.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        l = QLabel(self.message)
        vbox = QVBoxLayout(self.d)
        vbox.addWidget(l)

        if self.messsage_code in (3, 8):
            vbox.addLayout(Buttons(CancelButton(self.d)))
            self.d.connect(self.d, SIGNAL('rejected()'), self.client.cancel)

        self.d.show()

    def dialog_stop(self):
        self.d.hide()


