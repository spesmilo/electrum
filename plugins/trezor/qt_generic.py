from functools import partial
import threading

from PyQt4.Qt import Qt
from PyQt4.Qt import QGridLayout, QInputDialog, QPushButton
from PyQt4.Qt import QVBoxLayout, QLabel, SIGNAL
from electrum_gui.qt.main_window import StatusBarButton
from electrum_gui.qt.password_dialog import PasswordDialog
from electrum_gui.qt.util import *
from plugin import TrezorCompatiblePlugin

from electrum.i18n import _
from electrum.plugins import hook, DeviceMgr
from electrum.util import PrintError
from electrum.wallet import BIP44_Wallet


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
        win.connect(win, SIGNAL('word_dialog'), self.word_dialog)
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

    def get_word(self, msg):
        self.done.clear()
        self.win.emit(SIGNAL('word_dialog'), msg)
        self.done.wait()
        return self.word

    def get_passphrase(self, msg):
        self.done.clear()
        self.win.emit(SIGNAL('passphrase_dialog'), msg)
        self.done.wait()
        return self.passphrase

    def pin_dialog(self, msg):
        # Needed e.g. when resetting a device
        self.clear_dialog()
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
            passphrase = BIP44_Wallet.normalize_passphrase(passphrase)
        self.passphrase = passphrase
        self.done.set()

    def word_dialog(self, msg):
        dialog = WindowModalDialog(self.window_stack[-1], "")
        hbox = QHBoxLayout(dialog)
        hbox.addWidget(QLabel(msg))
        text = QLineEdit()
        text.setMaximumWidth(100)
        text.returnPressed.connect(dialog.accept)
        hbox.addWidget(text)
        hbox.addStretch(1)
        if not self.exec_dialog(dialog):
            return None
        self.word = unicode(text.text())
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
            return dialog.exec_()
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
        self.get_client(wallet)

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

        def get_client(lookup=DeviceMgr.PAIRED):
            return self.get_client(wallet, lookup)

        def add_rows_to_layout(layout, rows):
            for row_num, items in enumerate(rows):
                for col_num, txt in enumerate(items):
                    widget = txt if isinstance(txt, QWidget) else QLabel(txt)
                    layout.addWidget(widget, row_num, col_num)

        def refresh():
            features = get_client(DeviceMgr.PAIRED).features
            bl_hash = features.bootloader_hash.encode('hex').upper()
            bl_hash = "%s...%s" % (bl_hash[:10], bl_hash[-10:])
            version = "%d.%d.%d" % (features.major_version,
                                    features.minor_version,
                                    features.patch_version)

            bl_hash_label.setText(bl_hash)
            device_label.setText(features.label)
            device_id_label.setText(features.device_id)
            initialized_label.setText(noyes[features.initialized])
            version_label.setText(version)
            pin_label.setText(noyes[features.pin_protection])
            passphrase_label.setText(noyes[features.passphrase_protection])
            language_label.setText(features.language)

            pin_button.setText(_("Change") if features.pin_protection
                               else _("Set"))
            clear_pin_button.setVisible(features.pin_protection)

        def rename():
            title = _("Set Device Label")
            msg = _("Enter new label:")
            response = QInputDialog().getText(dialog, title, msg)
            if not response[1]:
                return
            get_client().change_label(str(response[0]))
            refresh()

        def set_pin():
            get_client().set_pin(remove=False)
            refresh()

        def clear_pin():
            title = _("Confirm Clear PIN")
            msg = _("WARNING: if your clear your PIN, anyone with physical "
                    "access to your %s device can spend your bitcoins.\n\n"
                    "Are you certain you want to remove your PIN?") % device
            if not dialog.question(msg, title=title):
                return
            get_client().set_pin(remove=True)
            refresh()

        def wipe_device():
            # FIXME: cannot yet wipe a device that is only plugged in
            title = _("Confirm Device Wipe")
            msg = _("Are you sure you want to wipe the device?  "
                    "You should make sure you have a copy of your recovery "
                    "seed and that your wallet holds no bitcoins.")
            if not dialog.question(msg, title=title):
                return
            if sum(wallet.get_balance()):
                title = _("Confirm Device Wipe")
                msg = _("Are you SURE you want to wipe the device?\n"
                        "Your wallet still has bitcoins in it!")
                if not dialog.question(msg, title=title,
                                       icon=QMessageBox.Critical):
                    return
            # Note: we use PRESENT so that a user who has forgotten
            # their PIN is not prevented from wiping their device
            get_client(DeviceMgr.PRESENT).wipe_device()
            wallet.wiped()
            self.device_manager().close_wallet(wallet)
            refresh()

        def slider_moved():
            mins = timeout_slider.sliderPosition()
            timeout_label.setText(_("%2d minutes") % mins)

        wallet = window.wallet
        handler = wallet.handler
        device = self.device

        info_tab = QWidget()
        tab_layout = QVBoxLayout(info_tab)
        info_layout = QGridLayout()
        noyes = [_("No"), _("Yes")]
        bl_hash_label = QLabel()
        device_label = QLabel()
        passphrase_label = QLabel()
        initialized_label = QLabel()
        device_id_label = QLabel()
        version_label = QLabel()
        pin_label = QLabel()
        language_label = QLabel()
        rename_button = QPushButton(_("Rename"))
        rename_button.clicked.connect(rename)
        pin_button = QPushButton()
        pin_button.clicked.connect(set_pin)
        clear_pin_button = QPushButton(_("Clear"))
        clear_pin_button.clicked.connect(clear_pin)

        add_rows_to_layout(info_layout, [
            (_("Device Label"), device_label, rename_button),
            (_("Has Passphrase"), passphrase_label),
            (_("Has PIN"), pin_label, pin_button, clear_pin_button),
            (_("Initialized"), initialized_label),
            (_("Device ID"), device_id_label),
            (_("Bootloader Hash"), bl_hash_label),
            (_("Firmware Version"), version_label),
            (_("Language"), language_label),
        ])
        tab_layout.addLayout(info_layout)

        timeout_layout = QHBoxLayout()
        timeout_label = QLabel()
        timeout_slider = QSlider(Qt.Horizontal)
        timeout_slider.setRange(1, 60)
        timeout_slider.setSingleStep(1)
        timeout_slider.setSliderPosition(wallet.session_timeout // 60)
        timeout_slider.setTickInterval(5)
        timeout_slider.setTickPosition(QSlider.TicksBelow)
        timeout_slider.setTracking(True)
        timeout_slider.valueChanged.connect(slider_moved)
        timeout_layout.addWidget(QLabel(_("Session Timeout")))
        timeout_layout.addWidget(timeout_slider)
        timeout_layout.addWidget(timeout_label)
        tab_layout.addLayout(timeout_layout)

        advanced_tab = QWidget()
        advanced_layout = QGridLayout(advanced_tab)
        wipe_device_button = QPushButton(_("Wipe Device"))
        wipe_device_button.clicked.connect(wipe_device)
        add_rows_to_layout(advanced_layout, [
            (wipe_device_button, ),
        ])

        dialog = WindowModalDialog(window, _("%s Settings") % device)
        vbox = QVBoxLayout()
        tabs = QTabWidget()
        tabs.addTab(info_tab, _("Information"))
        tabs.addTab(advanced_tab, _("Advanced"))
        vbox.addWidget(tabs)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(dialog)))

        # Show values
        slider_moved()
        refresh()
        dialog.setLayout(vbox)
        handler.exec_dialog(dialog)
        wallet.set_session_timeout(timeout_slider.sliderPosition() * 60)

  return QtPlugin
