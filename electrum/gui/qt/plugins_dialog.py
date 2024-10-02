from typing import TYPE_CHECKING, Optional
from functools import partial

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton, QComboBox, QLineEdit, QSpacerItem, QWidget, QHBoxLayout, QScrollArea, QCheckBox, QFormLayout

from electrum.i18n import _
from electrum.gui import messages
from electrum.plugin import run_hook, BasePlugin

from . import util
from .util import WindowModalDialog, Buttons, CloseButton, HelpButton, WWLabel


if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class PluginDialog(WindowModalDialog):

    def __init__(self, name, metadata, cb: 'QCheckBox', window: 'ElectrumWindow', index:int):
        display_name = metadata.get('display_name', '')
        author = metadata.get('author', '')
        description = metadata.get('description', '')
        requires = metadata.get('requires')
        version = metadata.get('version', 'n/a')

        WindowModalDialog.__init__(self, window, 'Plugin')
        self.setMinimumSize(400,250)
        self.index = index
        self.window = window
        self.metadata = metadata
        self.plugins = self.window.plugins
        self.name = name
        self.cb = cb
        p = self.plugins.get(name) # is installed
        vbox = QVBoxLayout(self)
        form = QFormLayout(None)
        form.addRow(QLabel(_('Name') + ':'), QLabel(display_name))
        form.addRow(QLabel(_('Author') + ':'), QLabel(author))
        form.addRow(QLabel(_('Description') + ':'), WWLabel(description))
        form.addRow(QLabel(_('Version') + ':'), QLabel(version))
        if requires:
            msg = '\n'.join(map(lambda x: x[1], requires))
            form.addRow(QLabel(_('Requires') + ':'), WWLabel(msg))
        vbox.addLayout(form)
        if name in self.plugins.internal_plugin_metadata:
            text = _('Disable') if p else _('Enable')
        else:
            text = _('Remove') if p else _('Install')
        toggle_button = QPushButton(text)
        toggle_button.clicked.connect(partial(self.do_toggle, toggle_button, name))
        close_button = CloseButton(self)
        close_button.setText(_('Cancel'))
        buttons = [toggle_button, close_button]
        vbox.addLayout(Buttons(*buttons))

    def do_toggle(self, button, name):
        button.setEnabled(False)
        if name in self.plugins.internal_plugin_metadata:
            p = self.plugins.toggle(name)
            self.cb.setChecked(bool(p))
        else:
            p = self.plugins.get(name)
            if not p:
                #if not self.window.window.question("Install plugin '%s'?"%name):
                #    return
                coro = self.plugins.download_external_plugin(name)
                def on_success(x):
                    self.plugins.enable(name)
                    p = self.plugins.get(name)
                    self.cb.setChecked(bool(p))
                self.window.window.run_coroutine_from_thread(coro, "Downloading '%s' "%name, on_result=on_success)
            else:
                #if not self.window.window.question("Remove plugin '%s'?"%name):
                #    return
                self.plugins.disable(name)
                self.cb.setChecked(False)
                self.plugins.remove_external_plugin(name)

        self.close()
        self.window.enable_settings_widget(name, self.index)
        # note: all enabled plugins will receive this hook:
        run_hook('init_qt', self.window.window.gui_object)


class PluginsDialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _('Electrum Plugins'))
        self.window = window
        self.wallet = self.window.wallet
        self.config = window.config
        self.plugins = self.window.gui_object.plugins
        self.settings_widgets = {}
        vbox = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setEnabled(True)
        scroll.setWidgetResizable(True)
        scroll.setMinimumSize(400,250)
        scroll_w = QWidget()
        scroll.setWidget(scroll_w)
        self.grid = QGridLayout()
        self.grid.setColumnStretch(0,1)
        scroll_w.setLayout(self.grid)
        vbox.addWidget(scroll)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.show_list()

    def enable_settings_widget(self, name: str, i: int):
        p = self.plugins.get(name)
        widget = self.settings_widgets.get(name)  # type: Optional[QWidget]
        if widget and not p:
            # plugin got disabled, rm widget
            self.grid.removeWidget(widget)
            widget.setParent(None)
            self.settings_widgets.pop(name)
        elif widget is None and p and p.requires_settings() and p.is_enabled():
            # plugin got enabled, add widget
            widget = self.settings_widgets[name] = p.settings_widget(self)
            self.grid.addWidget(widget, i, 1)

    def show_list(self):
        descriptions = self.plugins.descriptions
        descriptions = sorted(descriptions.items())
        grid = self.grid
        i = 0
        for name, metadata in descriptions:
            i += 1
            p = self.plugins.get(name)
            if metadata.get('registers_keystore'):
                continue
            display_name = metadata.get('display_name')
            if not display_name:
                continue
            #try:
            cb = QCheckBox(display_name)
            plugin_is_loaded = p is not None
            cb_enabled = (not plugin_is_loaded and self.plugins.is_available(name, self.wallet)
                          or plugin_is_loaded and p.can_user_disable())
            cb.setEnabled(cb_enabled)
            cb.setChecked(plugin_is_loaded and p.is_enabled())
            grid.addWidget(cb, i, 0)
            self.enable_settings_widget(name, i)
            cb.clicked.connect(partial(self.show_plugin_dialog, name, metadata, cb, i))

        #grid.setRowStretch(len(descriptions), 1)

    def show_plugin_dialog(self, name, metadata, cb, i):
        p = self.plugins.get(name)
        cb.setChecked(p is not None and p.is_enabled())
        d = PluginDialog(name, metadata, cb, self, i)
        d.exec()
