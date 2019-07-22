from functools import partial
import threading

from PyQt5.QtCore import Qt, QEventLoop, pyqtSignal
from PyQt5.QtWidgets import (QVBoxLayout, QLabel, QGridLayout, QPushButton,
                             QHBoxLayout, QButtonGroup, QGroupBox, QDialog,
                             QLineEdit, QRadioButton, QCheckBox, QWidget,
                             QMessageBox, QFileDialog, QSlider, QTabWidget)

from electrum.gui.qt.util import (WindowModalDialog, WWLabel, Buttons, CancelButton,
                                  OkButton, CloseButton)
from electrum.i18n import _
from electrum.plugin import hook
from electrum.util import bh2u

from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from ..hw_wallet.plugin import only_hook_if_libraries_available
from .trezor import (TrezorPlugin, TIM_NEW, TIM_RECOVER, TrezorInitSettings,
                     RECOVERY_TYPE_SCRAMBLED_WORDS, RECOVERY_TYPE_MATRIX)


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
MATRIX_RECOVERY = _(
    "Enter the recovery words by pressing the buttons according to what "
    "the device shows on its display.  You can also use your NUMPAD.\n"
    "Press BACKSPACE to go back a choice or word.\n")
SEEDLESS_MODE_WARNING = _(
    "In seedless mode, the mnemonic seed words are never shown to the user.\n"
    "There is no backup, and the user has a proof of this.\n"
    "This is an advanced feature, only suggested to be used in redundant multisig setups.")


class MatrixDialog(WindowModalDialog):

    def __init__(self, parent):
        super(MatrixDialog, self).__init__(parent)
        self.setWindowTitle(_("Trezor Matrix Recovery"))
        self.num = 9
        self.loop = QEventLoop()

        vbox = QVBoxLayout(self)
        vbox.addWidget(WWLabel(MATRIX_RECOVERY))

        grid = QGridLayout()
        grid.setSpacing(0)
        self.char_buttons = []
        for y in range(3):
            for x in range(3):
                button = QPushButton('?')
                button.clicked.connect(partial(self.process_key, ord('1') + y * 3 + x))
                grid.addWidget(button, 3 - y, x)
                self.char_buttons.append(button)
        vbox.addLayout(grid)

        self.backspace_button = QPushButton("<=")
        self.backspace_button.clicked.connect(partial(self.process_key, Qt.Key_Backspace))
        self.cancel_button = QPushButton(_("Cancel"))
        self.cancel_button.clicked.connect(partial(self.process_key, Qt.Key_Escape))
        buttons = Buttons(self.backspace_button, self.cancel_button)
        vbox.addSpacing(40)
        vbox.addLayout(buttons)
        self.refresh()
        self.show()

    def refresh(self):
        for y in range(3):
            self.char_buttons[3 * y + 1].setEnabled(self.num == 9)

    def is_valid(self, key):
        return key >= ord('1') and key <= ord('9')

    def process_key(self, key):
        self.data = None
        if key == Qt.Key_Backspace:
            self.data = '\010'
        elif key == Qt.Key_Escape:
            self.data = 'x'
        elif self.is_valid(key):
            self.char_buttons[key - ord('1')].setFocus()
            self.data = '%c' % key
        if self.data:
            self.loop.exit(0)

    def keyPressEvent(self, event):
        self.process_key(event.key())
        if not self.data:
            QDialog.keyPressEvent(self, event)

    def get_matrix(self, num):
        self.num = num
        self.refresh()
        self.loop.exec_()


class QtHandler(QtHandlerBase):

    pin_signal = pyqtSignal(object)
    matrix_signal = pyqtSignal(object)
    close_matrix_dialog_signal = pyqtSignal()

    def __init__(self, win, pin_matrix_widget_class, device):
        super(QtHandler, self).__init__(win, device)
        self.pin_signal.connect(self.pin_dialog)
        self.matrix_signal.connect(self.matrix_recovery_dialog)
        self.close_matrix_dialog_signal.connect(self._close_matrix_dialog)
        self.pin_matrix_widget_class = pin_matrix_widget_class
        self.matrix_dialog = None

    def get_pin(self, msg):
        self.done.clear()
        self.pin_signal.emit(msg)
        self.done.wait()
        return self.response

    def get_matrix(self, msg):
        self.done.clear()
        self.matrix_signal.emit(msg)
        self.done.wait()
        data = self.matrix_dialog.data
        if data == 'x':
            self.close_matrix_dialog()
        return data

    def _close_matrix_dialog(self):
        if self.matrix_dialog:
            self.matrix_dialog.accept()
            self.matrix_dialog = None

    def close_matrix_dialog(self):
        self.close_matrix_dialog_signal.emit()

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

    def matrix_recovery_dialog(self, msg):
        if not self.matrix_dialog:
            self.matrix_dialog = MatrixDialog(self.top_level_window())
        self.matrix_dialog.get_matrix(msg)
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
                def show_address(keystore=keystore):
                    keystore.thread.add(partial(self.show_address, wallet, addrs[0], keystore))
                device_name = "{} ({})".format(self.device, keystore.label)
                menu.addAction(_("Show on {}").format(device_name), show_address)

    def show_settings_dialog(self, window, keystore):
        device_id = self.choose_device(window, keystore)
        if device_id:
            SettingsDialog(window, self, keystore, device_id).exec_()

    def request_trezor_init_settings(self, wizard, method, device_id):
        vbox = QVBoxLayout()
        next_enabled = True

        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))
        model = client.get_trezor_model()
        fw_version = client.client.version

        # label
        label = QLabel(_("Enter a label to name your device:"))
        name = QLineEdit()
        hl = QHBoxLayout()
        hl.addWidget(label)
        hl.addWidget(name)
        hl.addStretch(1)
        vbox.addLayout(hl)

        # word count
        gb = QGroupBox()
        hbox1 = QHBoxLayout()
        gb.setLayout(hbox1)
        vbox.addWidget(gb)
        gb.setTitle(_("Select your seed length:"))
        bg_numwords = QButtonGroup()
        word_counts = (12, 18, 24)
        for i, count in enumerate(word_counts):
            rb = QRadioButton(gb)
            rb.setText(_("{:d} words").format(count))
            bg_numwords.addButton(rb)
            bg_numwords.setId(rb, i)
            hbox1.addWidget(rb)
            rb.setChecked(True)

        # PIN
        cb_pin = QCheckBox(_('Enable PIN protection'))
        cb_pin.setChecked(True)
        vbox.addWidget(WWLabel(RECOMMEND_PIN))
        vbox.addWidget(cb_pin)

        # "expert settings" button
        expert_vbox = QVBoxLayout()
        expert_widget = QWidget()
        expert_widget.setLayout(expert_vbox)
        expert_widget.setVisible(False)
        expert_button = QPushButton(_("Show expert settings"))
        def show_expert_settings():
            expert_button.setVisible(False)
            expert_widget.setVisible(True)
        expert_button.clicked.connect(show_expert_settings)
        vbox.addWidget(expert_button)

        # passphrase
        passphrase_msg = WWLabel(PASSPHRASE_HELP_SHORT)
        passphrase_warning = WWLabel(PASSPHRASE_NOT_PIN)
        passphrase_warning.setStyleSheet("color: red")
        cb_phrase = QCheckBox(_('Enable passphrases'))
        cb_phrase.setChecked(False)
        expert_vbox.addWidget(passphrase_msg)
        expert_vbox.addWidget(passphrase_warning)
        expert_vbox.addWidget(cb_phrase)

        # ask for recovery type (random word order OR matrix)
        bg_rectype = None
        if method == TIM_RECOVER and not model == 'T':
            gb_rectype = QGroupBox()
            hbox_rectype = QHBoxLayout()
            gb_rectype.setLayout(hbox_rectype)
            expert_vbox.addWidget(gb_rectype)
            gb_rectype.setTitle(_("Select recovery type:"))
            bg_rectype = QButtonGroup()

            rb1 = QRadioButton(gb_rectype)
            rb1.setText(_('Scrambled words'))
            bg_rectype.addButton(rb1)
            bg_rectype.setId(rb1, RECOVERY_TYPE_SCRAMBLED_WORDS)
            hbox_rectype.addWidget(rb1)
            rb1.setChecked(True)

            rb2 = QRadioButton(gb_rectype)
            rb2.setText(_('Matrix'))
            bg_rectype.addButton(rb2)
            bg_rectype.setId(rb2, RECOVERY_TYPE_MATRIX)
            hbox_rectype.addWidget(rb2)

        # no backup
        cb_no_backup = None
        if method == TIM_NEW:
            cb_no_backup = QCheckBox(f'''{_('Enable seedless mode')}''')
            cb_no_backup.setChecked(False)
            if (model == '1' and fw_version >= (1, 7, 1)
                    or model == 'T' and fw_version >= (2, 0, 9)):
                cb_no_backup.setToolTip(SEEDLESS_MODE_WARNING)
            else:
                cb_no_backup.setEnabled(False)
                cb_no_backup.setToolTip(_('Firmware version too old.'))
            expert_vbox.addWidget(cb_no_backup)

        vbox.addWidget(expert_widget)
        wizard.exec_layout(vbox, next_enabled=next_enabled)

        return TrezorInitSettings(
            word_count=word_counts[bg_numwords.checkedId()],
            label=name.text(),
            pin_enabled=cb_pin.isChecked(),
            passphrase_enabled=cb_phrase.isChecked(),
            recovery_type=bg_rectype.checkedId() if bg_rectype else None,
            no_backup=cb_no_backup.isChecked() if cb_no_backup else False,
        )


class Plugin(TrezorPlugin, QtPlugin):
    icon_unpaired = "trezor_unpaired.png"
    icon_paired = "trezor.png"

    @classmethod
    def pin_matrix_widget_class(self):
        from trezorlib.qt.pinmatrix import PinMatrixWidget
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
        hs_cols, hs_rows = (128, 64)

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
            if features.bootloader_hash:
                bl_hash = bh2u(features.bootloader_hash)
                bl_hash = "\n".join([bl_hash[:32], bl_hash[32:]])
            else:
                bl_hash = "N/A"
            noyes = [_("No"), _("Yes")]
            endis = [_("Enable Passphrases"), _("Disable Passphrases")]
            disen = [_("Disabled"), _("Enabled")]
            setchange = [_("Set a PIN"), _("Change PIN")]

            version = "%d.%d.%d" % (features.major_version,
                                    features.minor_version,
                                    features.patch_version)

            device_label.setText(features.label)
            pin_set_label.setText(noyes[features.pin_protection])
            passphrases_label.setText(disen[features.passphrase_protection])
            bl_hash_label.setText(bl_hash)
            label_edit.setText(features.label)
            device_id_label.setText(features.device_id)
            initialized_label.setText(noyes[features.initialized])
            version_label.setText(version)
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

        def change_homescreen():
            dialog = QFileDialog(self, _("Choose Homescreen"))
            filename, __ = dialog.getOpenFileName()
            if not filename:
                return  # user cancelled

            if filename.endswith('.toif'):
                img = open(filename, 'rb').read()
                if img[:8] != b'TOIf\x90\x00\x90\x00':
                    handler.show_error('File is not a TOIF file with size of 144x144')
                    return
            else:
                from PIL import Image # FIXME
                im = Image.open(filename)
                if im.size != (128, 64):
                    handler.show_error('Image must be 128 x 64 pixels')
                    return
                im = im.convert('1')
                pix = im.load()
                img = bytearray(1024)
                for j in range(64):
                    for i in range(128):
                        if pix[i, j]:
                            o = (i + j * 128)
                            img[o // 8] |= (1 << (7 - o % 8))
                img = bytes(img)
            invoke_client('change_homescreen', img)

        def clear_homescreen():
            invoke_client('change_homescreen', b'\x00')

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
        language_label = QLabel()
        initialized_label = QLabel()
        rows = [
            (_("Device Label"), device_label),
            (_("PIN set"), pin_set_label),
            (_("Passphrases"), passphrases_label),
            (_("Firmware Version"), version_label),
            (_("Device ID"), device_id_label),
            (_("Bootloader Hash"), bl_hash_label),
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

        # Settings tab - Homescreen
        homescreen_label = QLabel(_("Homescreen"))
        homescreen_change_button = QPushButton(_("Change..."))
        homescreen_clear_button = QPushButton(_("Reset"))
        homescreen_change_button.clicked.connect(change_homescreen)
        try:
            import PIL
        except ImportError:
            homescreen_change_button.setDisabled(True)
            homescreen_change_button.setToolTip(
                _("Required package 'PIL' is not available - Please install it or use the Trezor website instead.")
            )
        homescreen_clear_button.clicked.connect(clear_homescreen)
        homescreen_msg = QLabel(_("You can set the homescreen on your "
                                  "device to personalize it.  You must "
                                  "choose a {} x {} monochrome black and "
                                  "white image.").format(hs_cols, hs_rows))
        homescreen_msg.setWordWrap(True)
        settings_glayout.addWidget(homescreen_label, 4, 0)
        settings_glayout.addWidget(homescreen_change_button, 4, 1)
        settings_glayout.addWidget(homescreen_clear_button, 4, 2)
        settings_glayout.addWidget(homescreen_msg, 5, 1, 1, -1)

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
