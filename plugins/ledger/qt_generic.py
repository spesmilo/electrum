from functools import partial
import threading
from PIL import Image

from PyQt4.Qt import Qt
from PyQt4.Qt import QGridLayout, QInputDialog, QPushButton
from PyQt4.Qt import QVBoxLayout, QLabel, SIGNAL
from electrum_gui.qt.main_window import StatusBarButton
from electrum_gui.qt.password_dialog import PasswordDialog
from electrum_gui.qt.util import *

from electrum.i18n import _
from electrum.plugins import hook, DeviceMgr
from electrum.util import PrintError
from electrum.wallet import Wallet, BIP44_Wallet
from electrum.wizard import UserCancelled


# By far the trickiest thing about this handler is the window stack;
# MacOSX is very fussy the modal dialogs are perfectly parented
class QtHandler(PrintError):
    
    def __init__(self, win, device):
        win.connect(win, SIGNAL('ledger_clear_dialog'), self.clear_dialog)
        win.connect(win, SIGNAL('ledger_error_dialog'), self.error_dialog)
        win.connect(win, SIGNAL('ledger_message_dialog'), self.message_dialog)
        win.connect(win, SIGNAL('ledger_auth_dialog'), self.auth_dialog)
        self.win = win
        self.device = device
        self.dialog = None
        self.done = threading.Event()

    def top_level_window(self):
        return self.win.top_level_window()

    def watching_only_changed(self):
        self.win.emit(SIGNAL('watching_only_changed'))

    def show_message(self, msg, cancel_callback=None):
        self.win.emit(SIGNAL('ledger_message_dialog'), msg, cancel_callback)

    def show_error(self, msg):
        self.win.emit(SIGNAL('ledger_error_dialog'), msg)

    def finished(self):
        self.win.emit(SIGNAL('ledger_clear_dialog'))

    def get_auth(self, msg):
        self.done.clear()
        self.win.emit(SIGNAL('ledger_auth_dialog'), msg)
        self.done.wait()
        return self.response

    def auth_dialog(self, msg):
        response = QInputDialog.getText(None, "Ledger Wallet Authentication", msg, QLineEdit.Password)
        if not response[1]:
            self.response = None
        else:
            self.response = str(response[0])
        self.done.set()        

    def message_dialog(self, msg, cancel_callback):
        self.clear_dialog()
        title = _('Ledger')
        self.dialog = dialog = WindowModalDialog(self.top_level_window(), title)
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        if cancel_callback:
            vbox.addLayout(Buttons(CancelButton(dialog)))
            dialog.connect(dialog, SIGNAL('rejected()'), cancel_callback)
        vbox.addWidget(l)
        dialog.show()

    def error_dialog(self, msg):
        self.win.show_error(msg, parent=self.top_level_window())

    def clear_dialog(self):
        if self.dialog:
            self.dialog.accept()
            self.dialog = None

    def query_choice(self, msg, labels):
        return self.win.query_choice(msg, labels)


def qt_plugin_class(base_plugin_class):

  class QtPlugin(base_plugin_class):
    # Derived classes must provide the following class-static variables:
    #   icon_file
    #   pin_matrix_widget_class

    def create_handler(self, window):
        #return QtHandler(window, self.pin_matrix_widget_class(), self.device)
        return QtHandler(window, self.device)

    @hook
    def load_wallet(self, wallet, window):
        if type(wallet) != self.wallet_class:
            return
        window.tzb = StatusBarButton(QIcon(self.icon_file), self.device,
                                     partial(self.settings_dialog, window))
        window.statusBar().addPermanentWidget(window.tzb)
        wallet.handler = self.create_handler(window)
        # Trigger a pairing
	wallet.thread.add(partial(self.get_client, wallet))

    def on_create_wallet(self, wallet, wizard):
        assert type(wallet) == self.wallet_class
        wallet.handler = self.create_handler(wizard)
        wallet.thread = TaskThread(wizard, wizard.on_error)
        # Setup device and create accounts in separate thread; wait until done
        loop = QEventLoop()
        exc_info = []
        self.setup_device(wallet, on_done=loop.quit,
                          on_error=lambda info: exc_info.extend(info))
        loop.exec_()
        # If an exception was thrown, show to user and exit install wizard
        if exc_info:
            wizard.on_error(exc_info)
            raise UserCancelled

    def settings_dialog(self, window):
        pass

    def choose_device(self, window):
        handler = window.wallet.handler
        hid_id = self.device_manager().wallet_hid_id(window.wallet)
        if not hid_id:
            clients, labels = self.unpaired_clients(handler)
            if clients:
                msg = _("Select a %s device:") % self.device
                choice = self.query_choice(window, msg, labels)
                if choice is not None:
                    hid_id = clients[choice].hid_id()
            else:
                handler.show_error(_("No devices found"))
        return hid_id

    def query_choice(self, window, msg, choices):
        dialog = WindowModalDialog(window)
        clayout = ChoicesLayout(msg, choices)
        layout = clayout.layout()
        layout.addStretch(1)
        layout.addLayout(Buttons(CancelButton(dialog), OkButton(dialog)))
        dialog.setLayout(layout)
        if not dialog.exec_():
            return None
        return clayout.selected_index()


  return QtPlugin
