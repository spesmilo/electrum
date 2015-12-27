from functools import partial
from unicodedata import normalize
import threading

from PyQt4.Qt import QGridLayout, QInputDialog, QPushButton
from PyQt4.Qt import QVBoxLayout, QLabel, SIGNAL
from trezor import TrezorPlugin
from electrum_gui.qt.main_window import ElectrumWindow, StatusBarButton
from electrum_gui.qt.installwizard import InstallWizard
from electrum_gui.qt.password_dialog import PasswordDialog
from electrum_gui.qt.util import *

from electrum.i18n import _
from electrum.plugins import hook

class QtHandler:
    '''An interface between the GUI (here, QT) and the device handling
    logic for handling I/O.  This is a generic implementation of the
    Trezor protocol; derived classes can customize it.'''

    def __init__(self, win, pin_matrix_widget_class, device):
        win.connect(win, SIGNAL('message_done'), self.dialog_stop)
        win.connect(win, SIGNAL('message_dialog'), self.message_dialog)
        win.connect(win, SIGNAL('pin_dialog'), self.pin_dialog)
        win.connect(win, SIGNAL('passphrase_dialog'), self.passphrase_dialog)
        self.win = win
        self.pin_matrix_widget_class = pin_matrix_widget_class
        self.device = device
        self.done = threading.Event()
        self.dialog = None

    def stop(self):
        self.win.emit(SIGNAL('message_done'))

    def show_message(self, msg, cancel_callback=None):
        self.win.emit(SIGNAL('message_dialog'), msg, cancel_callback)

    def get_pin(self, msg):
        self.done.clear()
        self.win.emit(SIGNAL('pin_dialog'), msg)
        self.done.wait()
        return self.response

    def get_passphrase(self, msg):
        self.done.clear()
        self.win.emit(SIGNAL('passphrase_dialog'), msg)
        self.done.wait()
        return self.passphrase

    def pin_dialog(self, msg):
        d = WindowModalDialog(self.win, _("Enter PIN"))
        matrix = self.pin_matrix_widget_class()
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(msg))
        vbox.addWidget(matrix)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)
        if not d.exec_():
            self.response = None  # FIXME: this is lost?
        self.response = str(matrix.get_value())
        self.done.set()

    def passphrase_dialog(self, msg):
        if type(self.win) is ElectrumWindow:
            msg = _("Please enter your %s passphrase") % self.device
            passphrase = self.win.password_dialog(msg)
        else:
            assert type(self.win) is InstallWizard
            d = PasswordDialog(self.win, None, None, msg, False)
            confirmed, p, passphrase = d.run()

        if passphrase is None:
            self.win.show_critical(_("Passphrase request canceled"))
        else:
            passphrase = normalize('NFKD', unicode(passphrase))
        self.passphrase = passphrase
        self.done.set()

    def message_dialog(self, msg, cancel_callback):
        # Called more than once during signing, to confirm output and fee
        self.dialog_stop()
        msg = _('Please check your %s Device') % self.device
        dialog = self.dialog = WindowModalDialog(self.win, msg)
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        if cancel_callback:
            vbox.addLayout(Buttons(CancelButton(dialog)))
            dialog.connect(dialog, SIGNAL('rejected()'), cancel_callback)
        vbox.addWidget(l)
        dialog.show()

    def dialog_stop(self):
        if self.dialog:
            self.dialog.hide()
            self.dialog = None


class QtPlugin(TrezorPlugin):
    # Derived classes must provide the following class-static variables:
    #   icon_file
    #   pin_matrix_widget_class

    def create_handler(self, window):
        return QtHandler(window, self.pin_matrix_widget_class, self.device)

    @hook
    def load_wallet(self, wallet, window):
        self.print_error("load_wallet")
        self.wallet = wallet
        self.wallet.plugin = self
        self.button = StatusBarButton(QIcon(self.icon_file), self.device,
                                      partial(self.settings_dialog, window))
        if type(window) is ElectrumWindow:
            window.statusBar().addPermanentWidget(self.button)
        if self.handler is None:
            self.handler = self.create_handler(window)
        msg = self.wallet.sanity_check()
        if msg:
            window.show_error(msg)

    @hook
    def installwizard_load_wallet(self, wallet, window):
        if type(wallet) != self.wallet_class:
            return
        self.load_wallet(wallet, window)

    @hook
    def installwizard_restore(self, wizard, storage):
        if storage.get('wallet_type') != self.wallet_class.wallet_type:
            return
        seed = wizard.enter_seed_dialog(_("Enter your %s seed") % self.device,
                                        None, func=lambda x:True)
        if not seed:
            return
        wallet = self.wallet_class(storage)
        self.wallet = wallet
        handler = self.create_handler(wizard)
        msg = "\n".join([_("Please enter your %s passphrase.") % self.device,
                         _("Press OK if you do not use one.")])
        passphrase = handler.get_passphrase(msg)
        if passphrase is None:
            return
        password = wizard.password_dialog()
        wallet.add_seed(seed, password)
        wallet.add_cosigner_seed(seed, 'x/', password, passphrase)
        wallet.create_main_account(password)
        # disable plugin as this is a free-standing wallet
        self.set_enabled(False)
        return wallet

    @hook
    def receive_menu(self, menu, addrs):
        if (not self.wallet.is_watching_only() and self.atleast_version(1, 3)
            and len(addrs) == 1):
            menu.addAction(_("Show on %s") % self.device,
                           lambda: self.show_address(addrs[0]))

    def show_address(self, address):
        self.wallet.check_proper_device()
        try:
            address_path = self.wallet.address_id(address)
            address_n = self.get_client().expand_path(address_path)
        except Exception, e:
            self.give_error(e)
        try:
            self.get_client().get_address('Bitcoin', address_n, True)
        except Exception, e:
            self.give_error(e)
        finally:
            self.handler.stop()

    def settings_dialog(self, window):
        try:
            device_id = self.get_client().get_device_id()
        except BaseException as e:
            window.show_error(str(e))
            return
        get_label = lambda: self.get_client().features.label
        update_label = lambda: current_label.setText("Label: %s" % get_label())
        d = WindowModalDialog(window, _("%s Settings") % self.device)
        layout = QGridLayout(d)
        layout.addWidget(QLabel(_("%s Options") % self.device), 0, 0)
        layout.addWidget(QLabel("ID:"), 1, 0)
        layout.addWidget(QLabel(" %s" % device_id), 1, 1)

        def modify_label():
            title = _("Set New %s Label") % self.device
            msg = _("New Label: (upon submission confirm on %s)") % self.device
            response = QInputDialog().getText(None, title, msg)
            if not response[1]:
                return
            new_label = str(response[0])
            msg = _("Please confirm label change on %s") % self.device
            self.handler.show_message(msg)
            status = self.get_client().apply_settings(label=new_label)
            self.handler.stop()
            update_label()

        current_label = QLabel()
        update_label()
        change_label_button = QPushButton("Modify")
        change_label_button.clicked.connect(modify_label)
        layout.addWidget(current_label,3,0)
        layout.addWidget(change_label_button,3,1)
        d.exec_()
