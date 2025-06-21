from typing import TYPE_CHECKING, Optional
from functools import partial
import shutil
import os

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton, QWidget, QScrollArea, \
    QFormLayout, QFileDialog, QMenu, QApplication, QMessageBox
from PyQt6.QtCore import QTimer

from electrum.i18n import _
from electrum.gui import messages
from electrum.logging import get_logger

from .util import (WindowModalDialog, Buttons, CloseButton, WWLabel, insert_spaces, MessageBoxMixin,
                   EnterButton, read_QIcon_from_bytes, IconLabel, RunCoroutineDialog)


if TYPE_CHECKING:
    from . import ElectrumGui
    from electrum_ecc import ECPrivkey
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins


class PluginDialog(WindowModalDialog):

    def __init__(self, name, metadata, status_button: Optional['PluginStatusButton'], window: 'PluginsDialog'):
        display_name = metadata.get('fullname', '')
        author = metadata.get('author', '')
        description = metadata.get('description', '')
        requires = metadata.get('requires')
        version = metadata.get('version')
        zip_hash = metadata.get('zip_hash_sha256', None)
        icon_path = metadata.get('icon')

        WindowModalDialog.__init__(self, window, 'Plugin')
        self.setMinimumSize(400, 250)
        self.window = window
        self.metadata = metadata
        self.plugins = self.window.plugins
        self.name = name
        self.status_button = status_button
        p = self.plugins.get(name)  # is enabled
        vbox = QVBoxLayout(self)
        name_label = IconLabel(text=display_name, reverse=True)
        if icon_path:
            name_label.icon_size = 64
            icon = read_QIcon_from_bytes(self.plugins.read_file(name, icon_path))
            name_label.setIcon(icon)
        vbox.addWidget(name_label)
        vbox.addStretch()
        vbox.addWidget(WWLabel(description))
        vbox.addStretch()
        form = QFormLayout(None)
        if author:
            form.addRow(QLabel(_('Author') + ':'), QLabel(author))
        if version:
            form.addRow(QLabel(_('Version') + ':'), QLabel(version))
        if zip_hash:
            form.addRow(QLabel('Hash [sha256]:'), WWLabel(insert_spaces(zip_hash, 8)))
        if requires:
            msg = '\n'.join(map(lambda x: x[1], requires))
            form.addRow(QLabel(_('Requires') + ':'), WWLabel(msg))
        vbox.addLayout(form)
        vbox.addStretch()
        close_button = CloseButton(self)
        close_button.setText(_('Close'))
        buttons = [close_button]
        p = self.plugins.get(name)
        is_enabled = p and p.is_enabled()
        is_external = self.plugins.is_external(name)
        if is_external:
            is_authorized = self.plugins.is_authorized(name)
            if status_button is not None:
                # status_button is None when called from add_external_plugin
                remove_button = QPushButton('')
                remove_button.clicked.connect(self.do_remove)
                remove_button.setText(_('Remove'))
                buttons.insert(0, remove_button)
            if not is_authorized:
                auth_button = QPushButton('Install')
                auth_button.clicked.connect(self.do_authorize)
                buttons.insert(0, auth_button)
        else:
            toggle_button = QPushButton('')
            toggle_button.setText(_('Disable') if is_enabled else _('Enable'))
            toggle_button.clicked.connect(self.do_toggle)
            buttons.insert(0, toggle_button)
        # add settings button
        if p and p.requires_settings() and p.is_enabled():
            settings_button = EnterButton(
                _('Settings'),
                partial(p.settings_dialog, self))
            buttons.insert(1, settings_button)
        # add buttons
        vbox.addLayout(Buttons(*buttons))

    def do_toggle(self):
        if not self.plugins.is_available(self.name):
            msg = "\n".join([
                _('This plugin requires installation of additional dependencies.'),
                _('For Electrum to recognize external packages, you need to run it from source.')
            ])
            self.window.show_message(msg)
            return

        self.close()
        self.window.do_toggle(self.name, self.status_button)

    def do_remove(self):
        self.window.uninstall_plugin(self.name)
        self.close()

    def do_authorize(self):
        assert not self.plugins.is_authorized(self.name)
        privkey = self.window.get_plugins_privkey()
        if not privkey:
            return
        filename = self.plugins.zip_plugin_path(self.name)
        self.window.plugins.authorize_plugin(self.name, filename, privkey)
        self.window.plugins.enable(self.name)
        d = self.plugins.get_metadata(self.name)
        if details := d.get('registers_keystore'):
            self.plugins.register_keystore(self.name, details)
        if self.status_button:
            self.status_button.update()
        self.accept()


class PluginStatusButton(QPushButton):

    def __init__(self, window: 'PluginsDialog', name: str):
        QPushButton.__init__(self, '')
        self.window = window
        self.plugins = window.plugins
        self.name = name
        self.clicked.connect(self.show_plugin_dialog)
        self.update()

    def show_plugin_dialog(self):
        metadata = self.plugins.descriptions[self.name]
        d = PluginDialog(self.name, metadata, self, self.window)
        d.exec()

    def update(self):
        from .util import ColorScheme
        p = self.plugins.get(self.name)
        plugin_is_loaded = p is not None
        enabled = not plugin_is_loaded or (plugin_is_loaded and p.can_user_disable())
        self.setEnabled(enabled)
        if p is not None and p.is_enabled():
            text, color = _('Enabled'), ColorScheme.BLUE
        else:
            text, color = _('Disabled'), ColorScheme.RED
        self.setStyleSheet(color.as_stylesheet())
        self.setText(text)


class PluginsDialog(WindowModalDialog, MessageBoxMixin):
    _logger = get_logger(__name__)

    def __init__(self, config: 'SimpleConfig', plugins: 'Plugins', *, gui_object: Optional['ElectrumGui'] = None):
        WindowModalDialog.__init__(self, None, _('Electrum Plugins'))
        self.gui_object = gui_object
        self.config = config
        self.plugins = plugins
        vbox = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setEnabled(True)
        scroll.setWidgetResizable(True)
        scroll.setMinimumSize(400, 250)
        scroll_w = QWidget()
        scroll.setWidget(scroll_w)
        self.grid = QGridLayout()
        self.grid.setColumnStretch(0, 1)
        scroll_w.setLayout(self.grid)
        vbox.addWidget(scroll)
        add_button = QPushButton(_('Add'))
        add_button.setMinimumWidth(40)  # looks better on windows, no difference on linux
        add_button.clicked.connect(self.add_plugin_dialog)
        vbox.addLayout(Buttons(add_button, CloseButton(self)))
        self.show_list()

    def get_plugins_privkey(self) -> Optional['ECPrivkey']:
        pubkey, salt = self.plugins.get_pubkey_bytes()
        if not pubkey:
            self.init_plugins_password()
            return None
        # ask for url and password, same window
        pw = self.password_dialog(msg=messages.MSG_THIRD_PARTY_PLUGIN_WARNING)
        if not pw:
            return None
        privkey = self.plugins.derive_privkey(pw, salt)
        if pubkey != privkey.get_public_key_bytes():
            keyfile_path, _keyfile_help = self.plugins.get_keyfile_path(None)

            while True:
                exit_dialog = True
                auto_reset_btn = QPushButton(_('Try Auto-Reset'))
                def on_try_auto_reset_clicked():
                    nonlocal exit_dialog
                    if not self.plugins.try_auto_key_reset():
                        self.show_error(_("Auto-Reset not possible. Delete the file manually."))
                        exit_dialog = False
                    else:
                        self.show_message(_("Auto-Reset successful. You can now setup a new password."))
                auto_reset_btn.clicked.connect(on_try_auto_reset_clicked)

                buttons = [
                    QMessageBox.StandardButton.Ok,
                    (auto_reset_btn, QMessageBox.ButtonRole.ActionRole, 0),
                ]
                if self.show_error(
                    ''.join([
                        _('Incorrect password.'), '\n\n',
                        _('Your plugin authorization password is required to install plugins.'), ' ',
                        _('If you need to reset it, remove the following file:'), '\n\n',
                        keyfile_path
                    ]),
                    buttons=buttons
                ) or exit_dialog:
                    break

            return None
        return privkey

    def init_plugins_password(self):
        from .password_dialog import NewPasswordDialog
        msg = ' '.join([
            _('In order to install third-party plugins, you need to choose a plugin authorization password.'),
            _('Its purpose is to prevent unauthorized users (or malware) from installing plugins.'),
        ])
        d = NewPasswordDialog(self, msg=msg)
        pw = d.run()
        if not pw:
            return
        key_hex = self.plugins.create_new_key(pw)
        keyfile_path, keyfile_help = self.plugins.get_keyfile_path(key_hex)
        msg = '\n\n'.join([
            _('Your plugins key is:'), key_hex,
            _('This key has been copied to your clipboard. Please save it in:'),
            keyfile_path,
            keyfile_help,
            '',
        ])
        clipboard = QApplication.clipboard()
        clipboard.setText(key_hex)

        while True:
            exit_dialog = True
            # the button has to be recreated inside the loop, as qt destroys it when the dialog is closed
            auto_setup_btn = QPushButton(_('Try Auto-Setup'))
            def on_auto_setup_clicked():
                nonlocal exit_dialog
                if not self.plugins.try_auto_key_setup(key_hex):
                    self.show_error(_("Auto-Setup not possible. Try the manual setup."))
                    exit_dialog = False
                else:
                    self.show_message(_("Auto-Setup successful. You can now install plugins."))
            auto_setup_btn.clicked.connect(on_auto_setup_clicked)

            # on windows, the auto-setup button is shown right of the ok button,
            # apparently due to OS conventions
            buttons = [
                (auto_setup_btn, QMessageBox.ButtonRole.ActionRole, 0),
                QMessageBox.StandardButton.Ok,
            ]
            if self.show_message(msg, buttons=buttons) or exit_dialog:
                break

    def add_plugin_dialog(self):
        pubkey, salt = self.plugins.get_pubkey_bytes()
        if not pubkey:
            self.init_plugins_password()
            return
        filename, __ = QFileDialog.getOpenFileName(self, _("Select your plugin zipfile"), "", "*.zip")
        if not filename:
            return
        plugins_dir = self.plugins.get_external_plugin_dir()
        path = os.path.join(plugins_dir, os.path.basename(filename))
        if os.path.exists(path):
            self.show_warning(_('Plugin already installed.'))
            return
        shutil.copyfile(filename, path)
        self._try_add_external_plugin_from_path(path)

    def _try_add_external_plugin_from_path(self, path: str):
        try:
            success = self.add_external_plugin(path)
        except Exception as e:
            self._logger.exception("")
            self.show_error(f"{e}")
            success = False
        if not success:
            try:
                os.unlink(path)
            except FileNotFoundError:
                self._logger.debug("", exc_info=True)

    def add_external_plugin(self, path):
        manifest = self.plugins.read_manifest(path)
        name = manifest['name']
        self.plugins.external_plugin_metadata[name] = manifest
        d = PluginDialog(name, manifest, None, self)
        if not d.exec():
            self.plugins.external_plugin_metadata.pop(name)
            return False
        if self.gui_object:
            self.gui_object.reload_windows()
        self.show_list()
        return True

    def show_list(self):
        descriptions = self.plugins.descriptions
        descriptions = sorted(descriptions.items())
        grid = self.grid
        # clear existing items
        for i in reversed(range(grid.count())):
            grid.itemAt(i).widget().setParent(None)
        # populate
        i = 0
        for name, metadata in descriptions:
            i += 1
            if self.plugins.is_internal(name) and self.plugins.is_auto_loaded(name):
                continue
            display_name = metadata.get('fullname')
            if not display_name:
                continue
            label = IconLabel(text=display_name, reverse=True)
            icon_path = metadata.get('icon')
            if icon_path:
                icon = read_QIcon_from_bytes(self.plugins.read_file(name, icon_path))
                label.setIcon(icon)
            label.status_button = PluginStatusButton(self, name)
            grid.addWidget(label, i, 0)
            grid.addWidget(label.status_button, i, 1)
        # add stretch
        grid.setRowStretch(i + 1, 1)

    def do_toggle(self, name, status_button):
        p = self.plugins.get(name)
        is_enabled = p and p.is_enabled()
        if is_enabled:
            self.plugins.disable(name)
        else:
            self.plugins.enable(name)
        if status_button:
            status_button.update()
        if self.gui_object:
            self.gui_object.reload_windows()
        self.bring_to_front()

    def uninstall_plugin(self, name):
        if not self.question(_('Remove plugin \'{}\'?').format(name)):
            return
        self.plugins.uninstall(name)
        if self.gui_object:
            self.gui_object.reload_windows()
        self.show_list()
        self.bring_to_front()

    def bring_to_front(self):
        def _bring_self_to_front():
            self.activateWindow()
            self.setFocus()
        QTimer.singleShot(100, _bring_self_to_front)
