from typing import TYPE_CHECKING, Optional
from functools import partial

from PyQt5.QtWidgets import QLabel, QVBoxLayout, QGridLayout, QPushButton, QComboBox, QLineEdit, QSpacerItem, QWidget, QHBoxLayout, QScrollArea, QCheckBox

from electrum.i18n import _
from electrum.gui import messages
from electrum.plugin import run_hook, BasePlugin

from . import util
from .util import WindowModalDialog, Buttons, CloseButton, HelpButton


if TYPE_CHECKING:
    from .main_window import ElectrumWindow



class PluginsDialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _('Electrum Plugins'))
        self.window = window
        self.wallet = self.window.wallet
        self.config = window.config

        self.plugins = self.window.gui_object.plugins
        vbox = QVBoxLayout(self)

        # plugins
        scroll = QScrollArea()
        scroll.setEnabled(True)
        scroll.setWidgetResizable(True)
        scroll.setMinimumSize(400,250)
        self.scroll_w = QWidget()
        scroll.setWidget(self.scroll_w)
        vbox.addWidget(scroll)

        vbox.addLayout(Buttons(CloseButton(self)))
        self.settings_widgets = {}
        self.grid = QGridLayout()
        self.grid.setColumnStretch(0,1)
        self.scroll_w.setLayout(self.grid)
        self.show_list()

    def enable_settings_widget(self, p: Optional['BasePlugin'], name: str, i: int):
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

    def do_toggle(self, cb, name, i):
        p = self.plugins.toggle(name)
        cb.setChecked(bool(p))
        self.enable_settings_widget(p, name, i)
        # note: all enabled plugins will receive this hook:
        run_hook('init_qt', self.window.gui_object)

    def show_list(self):
        descriptions = self.plugins.descriptions.values()
        for i, descr in enumerate(descriptions):
            full_name = descr['__name__']
            prefix, _separator, name = full_name.rpartition('.')
            p = self.plugins.get(name)
            if descr.get('registers_keystore'):
                continue
            try:
                cb = QCheckBox(descr['fullname'])
                plugin_is_loaded = p is not None
                cb_enabled = (not plugin_is_loaded and self.plugins.is_available(name, self.wallet)
                              or plugin_is_loaded and p.can_user_disable())
                cb.setEnabled(cb_enabled)
                cb.setChecked(plugin_is_loaded and p.is_enabled())
                self.grid.addWidget(cb, i, 0)
                self.enable_settings_widget(p, name, i)
                cb.clicked.connect(partial(self.do_toggle, cb, name, i))
                msg = descr['description']
                if descr.get('requires'):
                    msg += '\n\n' + _('Requires') + ':\n' + '\n'.join(map(lambda x: x[1], descr.get('requires')))
                self.grid.addWidget(HelpButton(msg), i, 2)
            except Exception:
                self.window.logger.exception(f"cannot display plugin {name}")

        self.grid.setRowStretch(len(descriptions), 1)

