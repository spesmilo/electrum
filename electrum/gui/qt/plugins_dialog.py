from typing import TYPE_CHECKING, Optional
from functools import partial

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton, QWidget, QScrollArea, QFormLayout

from electrum.i18n import _
from electrum.plugin import run_hook

from .util import WindowModalDialog, Buttons, CloseButton, WWLabel, insert_spaces


if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from electrum_cc import ECPrivkey


class PluginDialog(WindowModalDialog):

    def __init__(self, name, metadata, status_button: Optional['PluginStatusButton'], window: 'ElectrumWindow'):
        display_name = metadata.get('fullname', '')
        author = metadata.get('author', '')
        description = metadata.get('description', '')
        requires = metadata.get('requires')
        version = metadata.get('version', 'n/a')
        zip_hash = metadata.get('zip_hash_sha256', None)

        WindowModalDialog.__init__(self, window, 'Plugin')
        self.setMinimumSize(400, 250)
        self.window = window
        self.metadata = metadata
        self.plugins = self.window.plugins
        self.name = name
        self.status_button = status_button
        p = self.plugins.get(name)  # is enabled
        vbox = QVBoxLayout(self)
        form = QFormLayout(None)
        form.addRow(QLabel(_('Name') + ':'), QLabel(display_name))
        form.addRow(QLabel(_('Author') + ':'), QLabel(author))
        form.addRow(QLabel(_('Description') + ':'), WWLabel(description))
        form.addRow(QLabel(_('Version') + ':'), QLabel(version))
        if zip_hash:
            form.addRow(QLabel('Hash [sha256]:'), WWLabel(insert_spaces(zip_hash, 8)))
        if requires:
            msg = '\n'.join(map(lambda x: x[1], requires))
            form.addRow(QLabel(_('Requires') + ':'), WWLabel(msg))
        vbox.addLayout(form)
        toggle_button = QPushButton('')
        if not self.plugins.is_installed(name):
            toggle_button.setText(_('Install...'))
            toggle_button.clicked.connect(self.accept)
        else:
            text = (_('Disable') if p else _('Enable')) if self.plugins.is_authorized(name) else _('Authorize...')
            toggle_button.setText(text)
            toggle_button.clicked.connect(partial(self.do_toggle, toggle_button, name))
        close_button = CloseButton(self)
        close_button.setText(_('Close'))
        buttons = [toggle_button, close_button]
        # add settings widget
        if p and p.requires_settings() and p.is_enabled():
            widget = p.settings_widget(self)
            buttons.insert(0, widget)
        vbox.addLayout(Buttons(*buttons))

    def do_toggle(self, toggle_button, name):
        toggle_button.setEnabled(False)
        if not self.plugins.is_authorized(name):
            privkey = self.window.get_plugins_privkey()
            if not privkey:
                return
            filename = self.plugins.zip_plugin_path(name)
            self.window.plugins.authorize_plugin(name, filename, privkey)
            self.status_button.update()
            self.close()
            return
        p = self.plugins.get(name)
        if not p:
            self.plugins.enable(name)
        else:
            self.plugins.disable(name)
        self.status_button.update()
        self.close()
        # note: all enabled plugins will receive this hook:
        run_hook('init_qt', self.window.window.gui_object)


class PluginStatusButton(QPushButton):

    def __init__(self, window, name):
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
        enabled = (
            not plugin_is_loaded and self.plugins.is_available(self.name, self.window.wallet)
            or plugin_is_loaded and p.can_user_disable()
        )
        self.setEnabled(enabled)
        text, color = (_('Unauthorized'), ColorScheme.RED) if not self.window.plugins.is_authorized(self.name)\
            else ((_('Enabled'), ColorScheme.BLUE) if p is not None and p.is_enabled() else (_('Disabled'), ColorScheme.DEFAULT))
        self.setStyleSheet(color.as_stylesheet())
        self.setText(text)


class PluginsDialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _('Electrum Plugins'))
        self.window = window
        self.wallet = self.window.wallet
        self.config = window.config
        self.plugins = self.window.gui_object.plugins
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
        add_button.clicked.connect(self.add_plugin_dialog)
        #add_button.clicked.connect(self.download_plugin_dialog)
        vbox.addLayout(Buttons(add_button, CloseButton(self)))
        self.show_list()

    def get_plugins_privkey(self) -> Optional['ECPrivkey']:
        pubkey, salt = self.plugins.get_pubkey_bytes()
        if not pubkey:
            self.init_plugins_password()
            return
        # ask for url and password, same window
        pw = self.window.password_dialog(
            msg=' '.join([
                _('<b>Warning</b>: Third-party plugins are not endorsed by Electrum!'),
                '<br/><br/>',
                _('If you install a third-party plugin, you trust the software not to be malicious.'),
                _('Electrum will not be responsible in case of theft, loss of funds or privacy that might result from third-party plugins.'),
                _('You should at minimum check who the author of the plugin is, and be careful of imposters.'),
                '<br/><br/>',
                _('Please enter your plugin authorization password') + ':'
            ])
        )
        if not pw:
            return
        privkey = self.plugins.derive_privkey(pw, salt)
        if pubkey != privkey.get_public_key_bytes():
            keyfile_path, keyfile_help = self.plugins.get_keyfile_path()
            self.window.show_error(
                ''.join([
                    _('Incorrect password.'), '\n\n',
                    _('Your plugin authorization password is required to install plugins.'), ' ',
                    _('If you need to reset it, remove the following file:'), '\n\n',
                    keyfile_path
                ]))
            return
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
        keyfile_path, keyfile_help = self.plugins.get_keyfile_path()
        msg = ''.join([
            _('Your plugins key is:'), '\n\n', key_hex, '\n\n',
            _('Please save this key in'), '\n\n' + keyfile_path, '\n\n', keyfile_help
        ])
        self.window.do_copy(key_hex, title=_('Plugins key'))
        self.window.show_message(msg)

    def download_plugin_dialog(self):
        import os
        from .util import line_dialog
        from electrum.util import UserCancelled
        pubkey, salt = self.plugins.get_pubkey_bytes()
        if not pubkey:
            self.init_plugins_password()
            return
        url = line_dialog(self, 'url', _('Enter plugin URL'), _('Download'))
        if not url:
            return
        coro = self.plugins.download_external_plugin(url)
        try:
            path = self.window.run_coroutine_dialog(coro, "Downloading plugin...")
        except UserCancelled:
            return
        except Exception as e:
            self.window.show_error(f"{e}")
            return
        try:
            success = self.confirm_add_plugin(path)
        except Exception as e:
            self.window.show_error(f"{e}")
            success = False
        if not success:
            os.unlink(path)

    def add_plugin_dialog(self):
        from PyQt6.QtWidgets import QFileDialog
        import shutil, os
        pubkey, salt = self.plugins.get_pubkey_bytes()
        if not pubkey:
            self.init_plugins_password()
            return
        filename, __ = QFileDialog.getOpenFileName(self, "Select your plugin zipfile", "", "*.zip")
        if not filename:
            return
        plugins_dir = self.plugins.get_external_plugin_dir()
        path = os.path.join(plugins_dir, os.path.basename(filename))
        shutil.copyfile(filename, path)
        try:
            success = self.confirm_add_plugin(path)
        except Exception as e:
            self.window.show_error(f"{e}")
            success = False
        if not success:
            os.unlink(path)

    def confirm_add_plugin(self, path):
        manifest = self.plugins.read_manifest(path)
        name = manifest['name']
        d = PluginDialog(name, manifest, None, self)
        if not d.exec():
            return False
        # ask password once user has approved
        privkey = self.get_plugins_privkey()
        if not privkey:
            return False
        self.plugins.external_plugin_metadata[name] = manifest
        self.plugins.authorize_plugin(name, path, privkey)
        self.window.show_message(_('Plugin installed successfully.'))
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
            if metadata.get('registers_keystore'):
                continue
            display_name = metadata.get('fullname')
            if not display_name:
                continue
            label = QLabel(display_name)
            grid.addWidget(label, i, 0)
            status_button = PluginStatusButton(self, name)
            grid.addWidget(status_button, i, 1)
        # add stretch
        grid.setRowStretch(i + 1, 1)
