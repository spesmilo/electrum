from functools import partial
import threading

from PyQt5.QtCore import Qt, QEventLoop, pyqtSignal, QRegExp
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtWidgets import (QVBoxLayout, QLabel, QGridLayout, QPushButton,
                             QHBoxLayout, QButtonGroup, QGroupBox, QDialog,
                             QTextEdit, QLineEdit, QRadioButton, QCheckBox, QWidget,
                             QMessageBox, QFileDialog, QSlider, QTabWidget)

from electrum.gui.qt.util import (WindowModalDialog, WWLabel, Buttons, CancelButton,
                                  OkButton, CloseButton)
from electrum.i18n import _
from electrum.plugin import hook
from electrum.util import bh2u

from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available
from .keepkey import KeepKeyPlugin, TIM_NEW, TIM_RECOVER, TIM_MNEMONIC


PASSPHRASE_HELP_SHORT =_(
    "Passphrases allow you to access new wallets, each "
    "hidden behind a particular case-sensitive passphrase.")
PASSPHRASE_HELP = PASSPHRASE_HELP_SHORT + "  " + _(
    "You need to create a separate Electrum wallet for each passphrase "
    "you use as they each generate different addresses.  Changing "
    "your passphrase does not lose other wallets, each is still "
    "accessible behind its own passphrase.")
RECOMMEND_PIN = _(
    "You should enable PIN protection.  Your PIN is the only protection "
    "for your bitcoins if your device is lost or stolen.")
PASSPHRASE_NOT_PIN = _(
    "If you forget a passphrase you will be unable to access any "
    "bitcoins in the wallet behind it.  A passphrase is not a PIN. "
    "Only change this if you are sure you understand it.")
CHARACTER_RECOVERY = (
    "Use the recovery cipher shown on your device to input your seed words.  "
    "The cipher changes with every keypress.\n"
    "After at most 4 letters the device will auto-complete a word.\n"
    "Press SPACE or the Accept Word button to accept the device's auto-"
    "completed word and advance to the next one.\n"
    "Press BACKSPACE to go back a character or word.\n"
    "Press ENTER or the Seed Entered button once the last word in your "
    "seed is auto-completed.")

class CharacterButton(QPushButton):
    def __init__(self, text=None):
        QPushButton.__init__(self, text)

    def keyPressEvent(self, event):
        event.setAccepted(False)   # Pass through Enter and Space keys


class CharacterDialog(WindowModalDialog):

    def __init__(self, parent):
        super(CharacterDialog, self).__init__(parent)
        self.setWindowTitle(_("KeepKey Seed Recovery"))
        self.character_pos = 0
        self.word_pos = 0
        self.loop = QEventLoop()
        self.word_help = QLabel()
        self.char_buttons = []

        vbox = QVBoxLayout(self)
        vbox.addWidget(WWLabel(CHARACTER_RECOVERY))
        hbox = QHBoxLayout()
        hbox.addWidget(self.word_help)
        for i in range(4):
            char_button = CharacterButton('*')
            char_button.setMaximumWidth(36)
            self.char_buttons.append(char_button)
            hbox.addWidget(char_button)
        self.accept_button = CharacterButton(_("Accept Word"))
        self.accept_button.clicked.connect(partial(self.process_key, 32))
        self.rejected.connect(partial(self.loop.exit, 1))
        hbox.addWidget(self.accept_button)
        hbox.addStretch(1)
        vbox.addLayout(hbox)

        self.finished_button = QPushButton(_("Seed Entered"))
        self.cancel_button = QPushButton(_("Cancel"))
        self.finished_button.clicked.connect(partial(self.process_key,
                                                     Qt.Key_Return))
        self.cancel_button.clicked.connect(self.rejected)
        buttons = Buttons(self.finished_button, self.cancel_button)
        vbox.addSpacing(40)
        vbox.addLayout(buttons)
        self.refresh()
        self.show()

    def refresh(self):
        self.word_help.setText("Enter seed word %2d:" % (self.word_pos + 1))
        self.accept_button.setEnabled(self.character_pos >= 3)
        self.finished_button.setEnabled((self.word_pos in (11, 17, 23)
                                         and self.character_pos >= 3))
        for n, button in enumerate(self.char_buttons):
            button.setEnabled(n == self.character_pos)
            if n == self.character_pos:
                button.setFocus()

    def is_valid_alpha_space(self, key):
        # Auto-completion requires at least 3 characters
        if key == ord(' ') and self.character_pos >= 3:
            return True
        # Firmware aborts protocol if the 5th character is non-space
        if self.character_pos >= 4:
            return False
        return (key >= ord('a') and key <= ord('z')
                or (key >= ord('A') and key <= ord('Z')))

    def process_key(self, key):
        self.data = None
        if key == Qt.Key_Return and self.finished_button.isEnabled():
            self.data = {'done': True}
        elif key == Qt.Key_Backspace and (self.word_pos or self.character_pos):
            self.data = {'delete': True}
        elif self.is_valid_alpha_space(key):
            self.data = {'character': chr(key).lower()}
        if self.data:
            self.loop.exit(0)

    def keyPressEvent(self, event):
        self.process_key(event.key())
        if not self.data:
            QDialog.keyPressEvent(self, event)

    def get_char(self, word_pos, character_pos):
        self.word_pos = word_pos
        self.character_pos = character_pos
        self.refresh()
        if self.loop.exec_():
            self.data = None  # User cancelled


class QtHandler(QtHandlerBase):

    char_signal = pyqtSignal(object)
    pin_signal = pyqtSignal(object)
    close_char_dialog_signal = pyqtSignal()

    def __init__(self, win, pin_matrix_widget_class, device):
        super(QtHandler, self).__init__(win, device)
        self.char_signal.connect(self.update_character_dialog)
        self.pin_signal.connect(self.pin_dialog)
        self.close_char_dialog_signal.connect(self._close_char_dialog)
        self.pin_matrix_widget_class = pin_matrix_widget_class
        self.character_dialog = None

    def get_char(self, msg):
        self.done.clear()
        self.char_signal.emit(msg)
        self.done.wait()
        data = self.character_dialog.data
        if not data or 'done' in data:
            self.close_char_dialog_signal.emit()
        return data

    def _close_char_dialog(self):
        if self.character_dialog:
            self.character_dialog.accept()
            self.character_dialog = None

    def get_pin(self, msg):
        self.done.clear()
        self.pin_signal.emit(msg)
        self.done.wait()
        return self.response

    def pin_dialog(self, msg):
        # Needed e.g. when resetting a device
        self.clear_dialog()
        dialog = WindowModalDialog(self.top_level_window(), _("Enter PIN"))
        matrix = self.pin_matrix_widget_class()
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(msg))
        vbox.addWidget(matrix)
        vbox.addLayout(Buttons(CancelButton(dialog), OkButton(dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()
        self.response = str(matrix.get_value())
        self.done.set()

    def update_character_dialog(self, msg):
        if not self.character_dialog:
            self.character_dialog = CharacterDialog(self.top_level_window())
        self.character_dialog.get_char(msg.word_pos, msg.character_pos)
        self.done.set()



class QtPlugin(QtPluginBase):
    # Derived classes must provide the following class-static variables:
    #   icon_file
    #   pin_matrix_widget_class

    def create_handler(self, window):
        return QtHandler(window, self.pin_matrix_widget_class(), self.device)

    @only_hook_if_libraries_available
    @hook
    def receive_menu(self, menu, addrs, wallet):
        if len(addrs) != 1:
            return
        for keystore in wallet.get_keystores():
            if type(keystore) == self.keystore_class:
                def show_address():
                    keystore.thread.add(partial(self.show_address, wallet, addrs[0], keystore))
                device_name = "{} ({})".format(self.device, keystore.label)
                menu.addAction(_("Show on {}").format(device_name), show_address)

    def show_settings_dialog(self, window, keystore):
        device_id = self.choose_device(window, keystore)
        if device_id:
            SettingsDialog(window, self, keystore, device_id).exec_()

    def request_trezor_init_settings(self, wizard, method, device):
        vbox = QVBoxLayout()
        next_enabled = True
        label = QLabel(_("Enter a label to name your device:"))
        name = QLineEdit()
        hl = QHBoxLayout()
        hl.addWidget(label)
        hl.addWidget(name)
        hl.addStretch(1)
        vbox.addLayout(hl)

        def clean_text(widget):
            text = widget.toPlainText().strip()
            return ' '.join(text.split())

        if method in [TIM_NEW, TIM_RECOVER]:
            gb = QGroupBox()
            hbox1 = QHBoxLayout()
            gb.setLayout(hbox1)
            # KeepKey recovery doesn't need a word count
            if method == TIM_NEW:
                vbox.addWidget(gb)
            gb.setTitle(_("Select your seed length:"))
            bg = QButtonGroup()
            for i, count in enumerate([12, 18, 24]):
                rb = QRadioButton(gb)
                rb.setText(_("{} words").format(count))
                bg.addButton(rb)
                bg.setId(rb, i)
                hbox1.addWidget(rb)
                rb.setChecked(True)
            cb_pin = QCheckBox(_('Enable PIN protection'))
            cb_pin.setChecked(True)
        else:
            text = QTextEdit()
            text.setMaximumHeight(60)
            if method == TIM_MNEMONIC:
                msg = _("Enter your BIP39 mnemonic:")
            else:
                msg = _("Enter the master private key beginning with xprv:")
                def set_enabled():
                    from electrum.bip32 import is_xprv
                    wizard.next_button.setEnabled(is_xprv(clean_text(text)))
                text.textChanged.connect(set_enabled)
                next_enabled = False

            vbox.addWidget(QLabel(msg))
            vbox.addWidget(text)
            pin = QLineEdit()
            pin.setValidator(QRegExpValidator(QRegExp('[1-9]{0,9}')))
            pin.setMaximumWidth(100)
            hbox_pin = QHBoxLayout()
            hbox_pin.addWidget(QLabel(_("Enter your PIN (digits 1-9):")))
            hbox_pin.addWidget(pin)
            hbox_pin.addStretch(1)

        if method in [TIM_NEW, TIM_RECOVER]:
            vbox.addWidget(WWLabel(RECOMMEND_PIN))
            vbox.addWidget(cb_pin)
        else:
            vbox.addLayout(hbox_pin)

        passphrase_msg = WWLabel(PASSPHRASE_HELP_SHORT)
        passphrase_warning = WWLabel(PASSPHRASE_NOT_PIN)
        passphrase_warning.setStyleSheet("color: red")
        cb_phrase = QCheckBox(_('Enable passphrases'))
        cb_phrase.setChecked(False)
        vbox.addWidget(passphrase_msg)
        vbox.addWidget(passphrase_warning)
        vbox.addWidget(cb_phrase)

        wizard.exec_layout(vbox, next_enabled=next_enabled)

        if method in [TIM_NEW, TIM_RECOVER]:
            item = bg.checkedId()
            pin = cb_pin.isChecked()
        else:
            item = ' '.join(str(clean_text(text)).split())
            pin = str(pin.text())

        return (item, name.text(), pin, cb_phrase.isChecked())


class Plugin(KeepKeyPlugin, QtPlugin):
    icon_paired = "keepkey.png"
    icon_unpaired = "keepkey_unpaired.png"

    @classmethod
    def pin_matrix_widget_class(self):
        from keepkeylib.qt.pinmatrix import PinMatrixWidget
        return PinMatrixWidget


class SettingsDialog(WindowModalDialog):
    '''This dialog doesn't require a device be paired with a wallet.
    We want users to be able to wipe a device even if they've forgotten
    their PIN.'''

    def __init__(self, window, plugin, keystore, device_id):
        title = _("{} Settings").format(plugin.device)
        super(SettingsDialog, self).__init__(window, title)
        self.setMaximumWidth(540)

        devmgr = plugin.device_manager()
        config = devmgr.config
        handler = keystore.handler
        thread = keystore.thread

        def invoke_client(method, *args, **kw_args):
            unpair_after = kw_args.pop('unpair_after', False)

            def task():
                client = devmgr.client_by_id(device_id)
                if not client:
                    raise RuntimeError("Device not connected")
                if method:
                    getattr(client, method)(*args, **kw_args)
                if unpair_after:
                    devmgr.unpair_id(device_id)
                return client.features

            thread.add(task, on_success=update)

        def update(features):
            self.features = features
            set_label_enabled()
            bl_hash = bh2u(features.bootloader_hash)
            bl_hash = "\n".join([bl_hash[:32], bl_hash[32:]])
            noyes = [_("No"), _("Yes")]
            endis = [_("Enable Passphrases"), _("Disable Passphrases")]
            disen = [_("Disabled"), _("Enabled")]
            setchange = [_("Set a PIN"), _("Change PIN")]

            version = "%d.%d.%d" % (features.major_version,
                                    features.minor_version,
                                    features.patch_version)
            coins = ", ".join(coin.coin_name for coin in features.coins)

            device_label.setText(features.label)
            pin_set_label.setText(noyes[features.pin_protection])
            passphrases_label.setText(disen[features.passphrase_protection])
            bl_hash_label.setText(bl_hash)
            label_edit.setText(features.label)
            device_id_label.setText(features.device_id)
            initialized_label.setText(noyes[features.initialized])
            version_label.setText(version)
            coins_label.setText(coins)
            clear_pin_button.setVisible(features.pin_protection)
            clear_pin_warning.setVisible(features.pin_protection)
            pin_button.setText(setchange[features.pin_protection])
            pin_msg.setVisible(not features.pin_protection)
            passphrase_button.setText(endis[features.passphrase_protection])
            language_label.setText(features.language)

        def set_label_enabled():
            label_apply.setEnabled(label_edit.text() != self.features.label)

        def rename():
            invoke_client('change_label', label_edit.text())

        def toggle_passphrase():
            title = _("Confirm Toggle Passphrase Protection")
            currently_enabled = self.features.passphrase_protection
            if currently_enabled:
                msg = _("After disabling passphrases, you can only pair this "
                        "Electrum wallet if it had an empty passphrase.  "
                        "If its passphrase was not empty, you will need to "
                        "create a new wallet with the install wizard.  You "
                        "can use this wallet again at any time by re-enabling "
                        "passphrases and entering its passphrase.")
            else:
                msg = _("Your current Electrum wallet can only be used with "
                        "an empty passphrase.  You must create a separate "
                        "wallet with the install wizard for other passphrases "
                        "as each one generates a new set of addresses.")
            msg += "\n\n" + _("Are you sure you want to proceed?")
            if not self.question(msg, title=title):
                return
            invoke_client('toggle_passphrase', unpair_after=currently_enabled)

        def set_pin():
            invoke_client('set_pin', remove=False)

        def clear_pin():
            invoke_client('set_pin', remove=True)

        def wipe_device():
            wallet = window.wallet
            if wallet and sum(wallet.get_balance()):
                title = _("Confirm Device Wipe")
                msg = _("Are you SURE you want to wipe the device?\n"
                        "Your wallet still has bitcoins in it!")
                if not self.question(msg, title=title,
                                     icon=QMessageBox.Critical):
                    return
            invoke_client('wipe_device', unpair_after=True)

        def slider_moved():
            mins = timeout_slider.sliderPosition()
            timeout_minutes.setText(_("{:2d} minutes").format(mins))

        def slider_released():
            config.set_session_timeout(timeout_slider.sliderPosition() * 60)

        # Information tab
        info_tab = QWidget()
        info_layout = QVBoxLayout(info_tab)
        info_glayout = QGridLayout()
        info_glayout.setColumnStretch(2, 1)
        device_label = QLabel()
        pin_set_label = QLabel()
        passphrases_label = QLabel()
        version_label = QLabel()
        device_id_label = QLabel()
        bl_hash_label = QLabel()
        bl_hash_label.setWordWrap(True)
        coins_label = QLabel()
        coins_label.setWordWrap(True)
        language_label = QLabel()
        initialized_label = QLabel()
        rows = [
            (_("Device Label"), device_label),
            (_("PIN set"), pin_set_label),
            (_("Passphrases"), passphrases_label),
            (_("Firmware Version"), version_label),
            (_("Device ID"), device_id_label),
            (_("Bootloader Hash"), bl_hash_label),
            (_("Supported Coins"), coins_label),
            (_("Language"), language_label),
            (_("Initialized"), initialized_label),
        ]
        for row_num, (label, widget) in enumerate(rows):
            info_glayout.addWidget(QLabel(label), row_num, 0)
            info_glayout.addWidget(widget, row_num, 1)
        info_layout.addLayout(info_glayout)

        # Settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        settings_glayout = QGridLayout()

        # Settings tab - Label
        label_msg = QLabel(_("Name this {}.  If you have multiple devices "
                             "their labels help distinguish them.")
                           .format(plugin.device))
        label_msg.setWordWrap(True)
        label_label = QLabel(_("Device Label"))
        label_edit = QLineEdit()
        label_edit.setMinimumWidth(150)
        label_edit.setMaxLength(plugin.MAX_LABEL_LEN)
        label_apply = QPushButton(_("Apply"))
        label_apply.clicked.connect(rename)
        label_edit.textChanged.connect(set_label_enabled)
        settings_glayout.addWidget(label_label, 0, 0)
        settings_glayout.addWidget(label_edit, 0, 1, 1, 2)
        settings_glayout.addWidget(label_apply, 0, 3)
        settings_glayout.addWidget(label_msg, 1, 1, 1, -1)

        # Settings tab - PIN
        pin_label = QLabel(_("PIN Protection"))
        pin_button = QPushButton()
        pin_button.clicked.connect(set_pin)
        settings_glayout.addWidget(pin_label, 2, 0)
        settings_glayout.addWidget(pin_button, 2, 1)
        pin_msg = QLabel(_("PIN protection is strongly recommended.  "
                           "A PIN is your only protection against someone "
                           "stealing your bitcoins if they obtain physical "
                           "access to your {}.").format(plugin.device))
        pin_msg.setWordWrap(True)
        pin_msg.setStyleSheet("color: red")
        settings_glayout.addWidget(pin_msg, 3, 1, 1, -1)

        # Settings tab - Session Timeout
        timeout_label = QLabel(_("Session Timeout"))
        timeout_minutes = QLabel()
        timeout_slider = QSlider(Qt.Horizontal)
        timeout_slider.setRange(1, 60)
        timeout_slider.setSingleStep(1)
        timeout_slider.setTickInterval(5)
        timeout_slider.setTickPosition(QSlider.TicksBelow)
        timeout_slider.setTracking(True)
        timeout_msg = QLabel(
            _("Clear the session after the specified period "
              "of inactivity.  Once a session has timed out, "
              "your PIN and passphrase (if enabled) must be "
              "re-entered to use the device."))
        timeout_msg.setWordWrap(True)
        timeout_slider.setSliderPosition(config.get_session_timeout() // 60)
        slider_moved()
        timeout_slider.valueChanged.connect(slider_moved)
        timeout_slider.sliderReleased.connect(slider_released)
        settings_glayout.addWidget(timeout_label, 6, 0)
        settings_glayout.addWidget(timeout_slider, 6, 1, 1, 3)
        settings_glayout.addWidget(timeout_minutes, 6, 4)
        settings_glayout.addWidget(timeout_msg, 7, 1, 1, -1)
        settings_layout.addLayout(settings_glayout)
        settings_layout.addStretch(1)

        # Advanced tab
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        advanced_glayout = QGridLayout()

        # Advanced tab - clear PIN
        clear_pin_button = QPushButton(_("Disable PIN"))
        clear_pin_button.clicked.connect(clear_pin)
        clear_pin_warning = QLabel(
            _("If you disable your PIN, anyone with physical access to your "
              "{} device can spend your bitcoins.").format(plugin.device))
        clear_pin_warning.setWordWrap(True)
        clear_pin_warning.setStyleSheet("color: red")
        advanced_glayout.addWidget(clear_pin_button, 0, 2)
        advanced_glayout.addWidget(clear_pin_warning, 1, 0, 1, 5)

        # Advanced tab - toggle passphrase protection
        passphrase_button = QPushButton()
        passphrase_button.clicked.connect(toggle_passphrase)
        passphrase_msg = WWLabel(PASSPHRASE_HELP)
        passphrase_warning = WWLabel(PASSPHRASE_NOT_PIN)
        passphrase_warning.setStyleSheet("color: red")
        advanced_glayout.addWidget(passphrase_button, 3, 2)
        advanced_glayout.addWidget(passphrase_msg, 4, 0, 1, 5)
        advanced_glayout.addWidget(passphrase_warning, 5, 0, 1, 5)

        # Advanced tab - wipe device
        wipe_device_button = QPushButton(_("Wipe Device"))
        wipe_device_button.clicked.connect(wipe_device)
        wipe_device_msg = QLabel(
            _("Wipe the device, removing all data from it.  The firmware "
              "is left unchanged."))
        wipe_device_msg.setWordWrap(True)
        wipe_device_warning = QLabel(
            _("Only wipe a device if you have the recovery seed written down "
              "and the device wallet(s) are empty, otherwise the bitcoins "
              "will be lost forever."))
        wipe_device_warning.setWordWrap(True)
        wipe_device_warning.setStyleSheet("color: red")
        advanced_glayout.addWidget(wipe_device_button, 6, 2)
        advanced_glayout.addWidget(wipe_device_msg, 7, 0, 1, 5)
        advanced_glayout.addWidget(wipe_device_warning, 8, 0, 1, 5)
        advanced_layout.addLayout(advanced_glayout)
        advanced_layout.addStretch(1)

        tabs = QTabWidget(self)
        tabs.addTab(info_tab, _("Information"))
        tabs.addTab(settings_tab, _("Settings"))
        tabs.addTab(advanced_tab, _("Advanced"))
        dialog_vbox = QVBoxLayout(self)
        dialog_vbox.addWidget(tabs)
        dialog_vbox.addLayout(Buttons(CloseButton(self)))

        # Update information
        invoke_client(None)
