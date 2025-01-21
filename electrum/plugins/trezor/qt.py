from functools import partial
import threading
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QEventLoop, pyqtSignal
from PyQt6.QtWidgets import (QVBoxLayout, QLabel, QGridLayout, QPushButton,
                             QHBoxLayout, QButtonGroup, QGroupBox, QDialog,
                             QLineEdit, QRadioButton, QCheckBox, QWidget,
                             QMessageBox, QSlider, QTabWidget)

from electrum.i18n import _
from electrum.logging import Logger
from electrum.plugin import hook
from electrum.keystore import ScriptTypeNotSupported

from electrum.plugins.hw_wallet.qt import QtHandlerBase, QtPluginBase
from electrum.plugins.hw_wallet.trezor_qt_pinmatrix import PinMatrixWidget
from electrum.plugins.hw_wallet.plugin import only_hook_if_libraries_available, OutdatedHwFirmwareException

from electrum.gui.qt.util import (WindowModalDialog, WWLabel, Buttons, CancelButton,
                                  OkButton, CloseButton, PasswordLineEdit, getOpenFileName, ChoiceWidget)
from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWUnlock, WCHWXPub, WalletWizardComponent

from .trezor import (TrezorPlugin, TIM_NEW, TIM_RECOVER, TrezorInitSettings,
                     PASSPHRASE_ON_DEVICE, Capability, BackupType, RecoveryDeviceInputMethod)

if TYPE_CHECKING:
    from electrum.gui.qt.wizard.wallet import QENewWalletWizard

PASSPHRASE_HELP_SHORT = _(
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
        self.backspace_button.clicked.connect(partial(self.process_key, Qt.Key.Key_Backspace))
        self.cancel_button = QPushButton(_("Cancel"))
        self.cancel_button.clicked.connect(partial(self.process_key, Qt.Key.Key_Escape))
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
        if key == Qt.Key.Key_Backspace:
            self.data = '\010'
        elif key == Qt.Key.Key_Escape:
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
        self.loop.exec()


class QtHandler(QtHandlerBase):

    pin_signal = pyqtSignal(object, object)
    matrix_signal = pyqtSignal(object)
    close_matrix_dialog_signal = pyqtSignal()

    def __init__(self, win, pin_matrix_widget_class, device):
        super(QtHandler, self).__init__(win, device)
        self.pin_signal.connect(self.pin_dialog)
        self.matrix_signal.connect(self.matrix_recovery_dialog)
        self.close_matrix_dialog_signal.connect(self._close_matrix_dialog)
        self.pin_matrix_widget_class = pin_matrix_widget_class
        self.matrix_dialog = None
        self.passphrase_on_device = False

    def get_pin(self, msg, *, show_strength=True):
        self.done.clear()
        self.pin_signal.emit(msg, show_strength)
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

    def pin_dialog(self, msg, show_strength):
        # Needed e.g. when resetting a device
        self.clear_dialog()
        dialog = WindowModalDialog(self.top_level_window(), _("Enter PIN"))
        matrix = self.pin_matrix_widget_class(show_strength)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(msg))
        vbox.addWidget(matrix)
        vbox.addLayout(Buttons(CancelButton(dialog), OkButton(dialog)))
        dialog.setLayout(vbox)
        dialog.exec()
        self.response = str(matrix.get_value())
        self.done.set()

    def matrix_recovery_dialog(self, msg):
        if not self.matrix_dialog:
            self.matrix_dialog = MatrixDialog(self.top_level_window())
        self.matrix_dialog.get_matrix(msg)
        self.done.set()

    def passphrase_dialog(self, msg, confirm):
        # If confirm is true, require the user to enter the passphrase twice
        parent = self.top_level_window()
        d = WindowModalDialog(parent, _('Enter Passphrase'))

        OK_button = OkButton(d, _('Enter Passphrase'))
        OnDevice_button = QPushButton(_('Enter Passphrase on Device'))

        new_pw = PasswordLineEdit()
        conf_pw = PasswordLineEdit()

        vbox = QVBoxLayout()
        label = QLabel(msg + "\n")
        label.setWordWrap(True)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(1,1)

        vbox.addWidget(label)

        grid.addWidget(QLabel(_('Passphrase:')), 0, 0)
        grid.addWidget(new_pw, 0, 1)

        if confirm:
            grid.addWidget(QLabel(_('Confirm Passphrase:')), 1, 0)
            grid.addWidget(conf_pw, 1, 1)

        vbox.addLayout(grid)

        def enable_OK():
            if not confirm:
                ok = True
            else:
                ok = new_pw.text() == conf_pw.text()
            OK_button.setEnabled(ok)

        new_pw.textChanged.connect(enable_OK)
        conf_pw.textChanged.connect(enable_OK)

        vbox.addWidget(OK_button)

        if self.passphrase_on_device:
            vbox.addWidget(OnDevice_button)

        d.setLayout(vbox)

        self.passphrase = None

        def ok_clicked():
            self.passphrase = new_pw.text()

        def on_device_clicked():
            self.passphrase = PASSPHRASE_ON_DEVICE

        OK_button.clicked.connect(ok_clicked)
        OnDevice_button.clicked.connect(on_device_clicked)
        OnDevice_button.clicked.connect(d.accept)

        d.exec()
        self.done.set()


class QtPlugin(QtPluginBase):
    # Derived classes must provide the following class-static variables:
    #   icon_file
    #   pin_matrix_widget_class

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
        def connect():
            device_id = self.choose_device(window, keystore)
            return device_id
        def show_dialog(device_id):
            if device_id:
                SettingsDialog(window, self, keystore, device_id).exec()
        keystore.thread.add(connect, on_success=show_dialog)


class InitSettingsLayout(QVBoxLayout):
    def __init__(self, devmgr, method, device_id) -> QVBoxLayout:
        super().__init__()

        client = devmgr.client_by_id(device_id)
        if not client:
            raise Exception(_("The device was disconnected."))
        model = client.get_trezor_model()
        fw_version = client.client.version
        capabilities = client.client.features.capabilities
        have_shamir = Capability.Shamir in capabilities

        # label
        label = QLabel(_("Enter a label to name your device:"))
        self.name = QLineEdit()
        hl = QHBoxLayout()
        hl.addWidget(label)
        hl.addWidget(self.name)
        hl.addStretch(1)
        self.addLayout(hl)

        # Backup type
        gb_backuptype = QGroupBox()
        hbox_backuptype = QHBoxLayout()
        gb_backuptype.setLayout(hbox_backuptype)
        self.addWidget(gb_backuptype)
        gb_backuptype.setTitle(_('Select backup type:'))
        self.bg_backuptype = QButtonGroup()

        rb_single = QRadioButton(gb_backuptype)
        rb_single.setText(_('Single seed (BIP39)'))
        self.bg_backuptype.addButton(rb_single)
        self.bg_backuptype.setId(rb_single, BackupType.Bip39)
        hbox_backuptype.addWidget(rb_single)
        rb_single.setChecked(True)

        rb_shamir = QRadioButton(gb_backuptype)
        rb_shamir.setText(_('Shamir'))
        self.bg_backuptype.addButton(rb_shamir)
        self.bg_backuptype.setId(rb_shamir, BackupType.Slip39_Basic)
        hbox_backuptype.addWidget(rb_shamir)
        rb_shamir.setEnabled(Capability.Shamir in capabilities)
        rb_shamir.setVisible(False)  # visible with "expert settings"

        rb_shamir_groups = QRadioButton(gb_backuptype)
        rb_shamir_groups.setText(_('Super Shamir'))
        self.bg_backuptype.addButton(rb_shamir_groups)
        self.bg_backuptype.setId(rb_shamir_groups, BackupType.Slip39_Advanced)
        hbox_backuptype.addWidget(rb_shamir_groups)
        rb_shamir_groups.setEnabled(Capability.ShamirGroups in capabilities)
        rb_shamir_groups.setVisible(False)  # visible with "expert settings"

        # word count
        word_count_buttons = {}

        gb_numwords = QGroupBox()
        hbox1 = QHBoxLayout()
        gb_numwords.setLayout(hbox1)
        self.addWidget(gb_numwords)
        gb_numwords.setTitle(_("Select seed/share length:"))
        self.bg_numwords = QButtonGroup()
        for count in (12, 18, 20, 24, 33):
            rb = QRadioButton(gb_numwords)
            word_count_buttons[count] = rb
            rb.setText(_("{:d} words").format(count))
            self.bg_numwords.addButton(rb)
            self.bg_numwords.setId(rb, count)
            hbox1.addWidget(rb)
            rb.setChecked(True)

        def configure_word_counts():
            if model == "1":
                checked_wordcount = 24
            else:
                checked_wordcount = 12

            if method == TIM_RECOVER:
                if have_shamir:
                    valid_word_counts = (12, 18, 20, 24, 33)
                else:
                    valid_word_counts = (12, 18, 24)
            elif rb_single.isChecked():
                valid_word_counts = (12, 18, 24)
                gb_numwords.setTitle(_('Select seed length:'))
            else:
                valid_word_counts = (20, 33)
                checked_wordcount = 20
                gb_numwords.setTitle(_('Select share length:'))

            word_count_buttons[checked_wordcount].setChecked(True)
            for c, btn in word_count_buttons.items():
                btn.setVisible(c in valid_word_counts)

        self.bg_backuptype.buttonClicked.connect(configure_word_counts)
        configure_word_counts()

        # set up conditional visibility:
        # 1. backup_type is only visible when creating new seed
        gb_backuptype.setVisible(method == TIM_NEW)
        # 2. word_count is not visible when recovering on TT
        if method == TIM_RECOVER and model != "1":
            gb_numwords.setVisible(False)

        # PIN
        self.cb_pin = QCheckBox(_('Enable PIN protection'))
        self.cb_pin.setChecked(True)
        self.addWidget(WWLabel(RECOMMEND_PIN))
        self.addWidget(self.cb_pin)

        # "expert settings" button
        expert_vbox = QVBoxLayout()
        expert_widget = QWidget()
        expert_widget.setLayout(expert_vbox)
        expert_widget.setVisible(False)
        expert_button = QPushButton(_("Show expert settings"))
        def show_expert_settings():
            expert_button.setVisible(False)
            expert_widget.setVisible(True)
            rb_shamir.setVisible(True)
            rb_shamir_groups.setVisible(True)
        expert_button.clicked.connect(show_expert_settings)
        self.addWidget(expert_button)

        # passphrase
        passphrase_msg = WWLabel(PASSPHRASE_HELP_SHORT)
        passphrase_warning = WWLabel(PASSPHRASE_NOT_PIN)
        passphrase_warning.setStyleSheet("color: red")
        self.cb_phrase = QCheckBox(_('Enable passphrases'))
        self.cb_phrase.setChecked(False)
        expert_vbox.addWidget(passphrase_msg)
        expert_vbox.addWidget(passphrase_warning)
        expert_vbox.addWidget(self.cb_phrase)

        # ask for recovery type (random word order OR matrix)
        self.bg_rectype = None
        if method == TIM_RECOVER and model == '1':
            gb_rectype = QGroupBox()
            hbox_rectype = QHBoxLayout()
            gb_rectype.setLayout(hbox_rectype)
            expert_vbox.addWidget(gb_rectype)
            gb_rectype.setTitle(_("Select recovery type:"))
            self.bg_rectype = QButtonGroup()

            rb1 = QRadioButton(gb_rectype)
            rb1.setText(_('Scrambled words'))
            self.bg_rectype.addButton(rb1)
            self.bg_rectype.setId(rb1, RecoveryDeviceInputMethod.ScrambledWords)
            hbox_rectype.addWidget(rb1)
            rb1.setChecked(True)

            rb2 = QRadioButton(gb_rectype)
            rb2.setText(_('Matrix'))
            self.bg_rectype.addButton(rb2)
            self.bg_rectype.setId(rb2, RecoveryDeviceInputMethod.Matrix)
            hbox_rectype.addWidget(rb2)

        # no backup
        self.cb_no_backup = None
        if method == TIM_NEW:
            self.cb_no_backup = QCheckBox(_('Enable seedless mode'))
            self.cb_no_backup.setChecked(False)
            supports_no_backup = False
            if model == '1':
                if fw_version >= (1, 7, 1):
                    supports_no_backup = True
            else:
                if fw_version >= (2, 0, 9):
                    supports_no_backup = True
            if supports_no_backup:
                self.cb_no_backup.setEnabled(True)
                self.cb_no_backup.setToolTip(SEEDLESS_MODE_WARNING)
            else:
                self.cb_no_backup.setEnabled(False)
                self.cb_no_backup.setToolTip(_('Firmware version too old.'))
            expert_vbox.addWidget(self.cb_no_backup)

        self.addWidget(expert_widget)

    def get_settings(self):
        return TrezorInitSettings(
            word_count=self.bg_numwords.checkedId(),
            label=self.name.text(),
            pin_enabled=self.cb_pin.isChecked(),
            passphrase_enabled=self.cb_phrase.isChecked(),
            recovery_type=self.bg_rectype.checkedId() if self.bg_rectype else None,
            backup_type=self.bg_backuptype.checkedId(),
            no_backup=self.cb_no_backup.isChecked() if self.cb_no_backup else False,
        )


class Plugin(TrezorPlugin, QtPlugin):
    icon_unpaired = "trezor_unpaired.png"
    icon_paired = "trezor.png"

    def create_handler(self, window):
        return QtHandler(window, self.pin_matrix_widget_class(), self.device)

    @classmethod
    def pin_matrix_widget_class(self):
        return PinMatrixWidget

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    # insert trezor pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'trezor_start': {'gui': WCScriptAndDerivation},
            'trezor_xpub': {'gui': WCTrezorXPub},
            'trezor_not_initialized': {'gui': WCTrezorInitMethod},
            'trezor_choose_new_recover': {'gui': WCTrezorInitParams},
            'trezor_do_init': {'gui': WCTrezorInit},
            'trezor_unlock': {'gui': WCHWUnlock},
        }
        wizard.navmap_merge(views)


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
                bl_hash = features.bootloader_hash.hex()
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
                        "create a new wallet.  You can use this wallet again "
                        "at any time by re-enabling passphrases and entering "
                        "its passphrase.")
            else:
                msg = _("Your current Electrum wallet can only be used with "
                        "an empty passphrase.  You must create a separate "
                        "wallet for other passphrases as each one generates "
                        "a new set of addresses.")
            msg += "\n\n" + _("Are you sure you want to proceed?")
            if not self.question(msg, title=title):
                return
            invoke_client('toggle_passphrase', unpair_after=currently_enabled)

        def change_homescreen():
            filename = getOpenFileName(
                parent=self,
                title=_("Choose Homescreen"),
                config=config,
            )
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
                                     icon=QMessageBox.Icon.Critical):
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
        timeout_slider = QSlider(Qt.Orientation.Horizontal)
        timeout_slider.setRange(1, 60)
        timeout_slider.setSingleStep(1)
        timeout_slider.setTickInterval(5)
        timeout_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
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


class WCTrezorXPub(WCHWXPub):
    def __init__(self, parent, wizard):
        WCHWXPub.__init__(self, parent, wizard)

    def get_xpub_from_client(self, client, derivation, xtype):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        _name, _info = current_cosigner['hardware_device']
        if xtype not in self.plugin.SUPPORTED_XTYPES:
            raise ScriptTypeNotSupported(_('This type of script is not supported with {}').format(_info.model_name))
        if not client.is_uptodate():
            msg = (_('Outdated {} firmware for device labelled {}. Please '
                     'download the updated firmware from {}')
                     .format(_info.model_name, _info.label, self.plugin.firmware_URL))
            raise OutdatedHwFirmwareException(msg)
        return client.get_xpub(derivation, xtype, True)


class WCTrezorInitMethod(WalletWizardComponent, Logger):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Trezor Setup'))
        Logger.__init__(self)
        self.plugins = wizard.plugins
        self.plugin = None

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        _name, _info = current_cosigner['hardware_device']
        self.plugin = self.plugins.get_plugin(_info.plugin_name)
        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        if client.features.bootloader_mode:
            msg = (_("Looks like your device is in bootloader mode. Try reconnecting it.\n"
                     "If you haven't installed a firmware on it yet, you can download it from {}")
                   .format(self.plugin.firmware_URL))
            self.error = msg
            return
        if not client.is_uptodate():
            msg = (_('Outdated {} firmware for device labelled {}. Please '
                     'download the updated firmware from {}')
                     .format(_info.model_name, _info.label, self.plugin.firmware_URL))
            self.error = msg
            return

        message = _('Choose how you want to initialize your {}.').format(_info.model_name)
        choices = [
            # Must be short as QT doesn't word-wrap radio button text
            (TIM_NEW, _("Let the device generate a completely new seed randomly")),
            (TIM_RECOVER, _("Recover from a seed you have previously written down")),
        ]
        self.choice_w = ChoiceWidget(message=message, choices=choices)
        self.layout().addWidget(self.choice_w)
        self.layout().addStretch(1)

        self._valid = True

    def apply(self):
        if not self.valid:
            return
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        current_cosigner['trezor_init'] = self.choice_w.selected_key


class WCTrezorInitParams(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Trezor Setup'))
        self.plugins = wizard.plugins
        self._busy = True

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        _name, _info = current_cosigner['hardware_device']
        self.settings_layout = InitSettingsLayout(self.plugins.device_manager, current_cosigner['trezor_init'], _info.device.id_)
        self.layout().addLayout(self.settings_layout)
        self.layout().addStretch(1)

        self.valid = True
        self.busy = False

    def apply(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        current_cosigner['trezor_settings'] = self.settings_layout.get_settings()


class WCTrezorInit(WalletWizardComponent, Logger):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Trezor Setup'))
        Logger.__init__(self)
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('trezor')

        self.layout().addWidget(WWLabel('Done'))

        self._busy = True

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        settings = current_cosigner['trezor_settings']
        method = current_cosigner['trezor_init']
        _name, _info = current_cosigner['hardware_device']
        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        client.handler = self.plugin.create_handler(self.wizard)

        def initialize_device_task(settings, method, device_id, handler):
            try:
                self.plugin._initialize_device(settings, method, device_id, handler)
                self.logger.info('Done initialize device')
                self.valid = True
                self.wizard.requestNext.emit()  # triggers Next GUI thread from event loop
            except Exception as e:
                self.valid = False
                self.error = repr(e)
                self.logger.exception(repr(e))
            finally:
                self.busy = False

        t = threading.Thread(
            target=initialize_device_task,
            args=(settings, method, device_id, client.handler),
            daemon=True)
        t.start()

    def apply(self):
        pass
