from functools import partial
import threading

from PyQt4.Qt import QGridLayout, QInputDialog, QPushButton
from PyQt4.Qt import QVBoxLayout, QLabel, SIGNAL
from electrum_gui.qt.main_window import StatusBarButton
from electrum_gui.qt.password_dialog import PasswordDialog
from electrum_gui.qt.util import *
from plugin import TrezorCompatiblePlugin

from electrum.i18n import _
from electrum.plugins import hook
from electrum.util import PrintError


# By far the trickiest thing about this handler is the window stack;
# MacOSX is very fussy the modal dialogs are perfectly parented
class QtHandler(PrintError):
    '''An interface between the GUI (here, QT) and the device handling
    logic for handling I/O.  This is a generic implementation of the
    Trezor protocol; derived classes can customize it.'''

    def __init__(self, win, pin_matrix_widget_class, device):
        win.connect(win, SIGNAL('clear_dialog'), self.clear_dialog)
        win.connect(win, SIGNAL('error_dialog'), self.error_dialog)
        win.connect(win, SIGNAL('message_dialog'), self.message_dialog)
        win.connect(win, SIGNAL('pin_dialog'), self.pin_dialog)
        win.connect(win, SIGNAL('passphrase_dialog'), self.passphrase_dialog)
        self.window_stack = [win]
        self.win = win
        self.pin_matrix_widget_class = pin_matrix_widget_class
        self.device = device
        self.dialog = None
        self.done = threading.Event()

    def watching_only_changed(self):
        self.win.emit(SIGNAL('watching_only_changed'))

    def show_message(self, msg, cancel_callback=None):
        self.win.emit(SIGNAL('message_dialog'), msg, cancel_callback)

    def show_error(self, msg):
        self.win.emit(SIGNAL('error_dialog'), msg)

    def finished(self):
        self.win.emit(SIGNAL('clear_dialog'))

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
        # Needed e.g. when renaming label and haven't entered PIN
        dialog = WindowModalDialog(self.window_stack[-1], _("Enter PIN"))
        matrix = self.pin_matrix_widget_class()
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(msg))
        vbox.addWidget(matrix)
        vbox.addLayout(Buttons(CancelButton(dialog), OkButton(dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()
        self.response = str(matrix.get_value())
        self.done.set()

    def passphrase_dialog(self, msg):
        d = PasswordDialog(self.window_stack[-1], None, msg,
                           PasswordDialog.PW_PASSPHRASE)
        confirmed, p, passphrase = d.run()
        if confirmed:
            passphrase = TrezorCompatiblePlugin.normalize_passphrase(passphrase)
        self.passphrase = passphrase
        self.done.set()

    def message_dialog(self, msg, cancel_callback):
        # Called more than once during signing, to confirm output and fee
        self.clear_dialog()
        title = _('Please check your %s device') % self.device
        self.dialog = dialog = WindowModalDialog(self.window_stack[-1], title)
        self.window_stack.append(dialog)
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        if cancel_callback:
            vbox.addLayout(Buttons(CancelButton(dialog)))
            dialog.connect(dialog, SIGNAL('rejected()'), cancel_callback)
        vbox.addWidget(l)
        dialog.show()

    def error_dialog(self, msg):
        self.win.show_error(msg, parent=self.window_stack[-1])

    def clear_dialog(self):
        if self.dialog:
            self.dialog.accept()
            self.window_stack.remove(self.dialog)
            self.dialog = None

    def exec_dialog(self, dialog):
        self.window_stack.append(dialog)
        try:
            dialog.exec_()
        finally:
            assert dialog == self.window_stack.pop()


def qt_plugin_class(base_plugin_class):

  class QtPlugin(base_plugin_class):
    # Derived classes must provide the following class-static variables:
    #   icon_file
    #   pin_matrix_widget_class

    def create_handler(self, window):
        return QtHandler(window, self.pin_matrix_widget_class(), self.device)

    @hook
    def load_wallet(self, wallet, window):
        if type(wallet) != self.wallet_class:
            return
        window.tzb = StatusBarButton(QIcon(self.icon_file), self.device,
                                     partial(self.settings_dialog, window))
        window.statusBar().addPermanentWidget(window.tzb)
        wallet.handler = self.create_handler(window)
        # Trigger a pairing
        self.client(wallet)

    def on_create_wallet(self, wallet, wizard):
        assert type(wallet) == self.wallet_class
        wallet.handler = self.create_handler(wizard)
        self.select_device(wallet, wizard)
        wallet.create_main_account(None)

    @hook
    def receive_menu(self, menu, addrs, wallet):
        if type(wallet) == self.wallet_class and len(addrs) == 1:
            menu.addAction(_("Show on %s") % self.device,
                           lambda: self.show_address(wallet, addrs[0]))

    def settings_dialog(self, window):
        handler = window.wallet.handler
        client = self.client(window.wallet)

        def rename():
            title = _("Set Device Label")
            msg = _("Enter new label:")
            response = QInputDialog().getText(dialog, title, msg)
            if not response[1]:
                return
            new_label = str(response[0])
            client.change_label(new_label)
            device_label.setText(new_label)

        def update_pin_info():
            features = client.features
            pin_label.setText(noyes[features.pin_protection])
            pin_button.setText(_("Change") if features.pin_protection
                               else _("Set"))
            clear_pin_button.setVisible(features.pin_protection)

        def set_pin(remove):
            client.set_pin(remove=remove)
            update_pin_info()

        features = client.features
        noyes = [_("No"), _("Yes")]
        bl_hash = features.bootloader_hash.encode('hex').upper()
        bl_hash = "%s...%s" % (bl_hash[:10], bl_hash[-10:])
        info_tab = QWidget()
        layout = QGridLayout(info_tab)
        device_label = QLabel(features.label)
        rename_button = QPushButton(_("Rename"))
        rename_button.clicked.connect(rename)
        pin_label = QLabel()
        pin_button = QPushButton()
        pin_button.clicked.connect(partial(set_pin, False))
        clear_pin_button = QPushButton(_("Clear"))
        clear_pin_button.clicked.connect(partial(set_pin, True))
        update_pin_info()

        version = "%d.%d.%d" % (features.major_version,
                                features.minor_version,
                                features.patch_version)
        rows = [
            (_("Bootloader Hash"), bl_hash),
            (_("Device ID"), features.device_id),
            (_("Device Label"), device_label, rename_button),
            (_("Firmware Version"), version),
            (_("Language"), features.language),
            (_("Has Passphrase"), noyes[features.passphrase_protection]),
            (_("Has PIN"), pin_label, pin_button, clear_pin_button)
        ]

        for row_num, items in enumerate(rows):
            for col_num, item in enumerate(items):
                widget = item if isinstance(item, QWidget) else QLabel(item)
                layout.addWidget(widget, row_num, col_num)

        dialog = WindowModalDialog(window, _("%s Settings") % self.device)
        vbox = QVBoxLayout()
        tabs = QTabWidget()
        tabs.addTab(info_tab, _("Information"))
        tabs.addTab(QWidget(), _("Advanced"))
        vbox.addWidget(tabs)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(dialog)))

        dialog.setLayout(vbox)
        handler.exec_dialog(dialog)

  return QtPlugin
