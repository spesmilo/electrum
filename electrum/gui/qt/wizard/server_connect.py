from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QCheckBox, QLabel, QHBoxLayout, QVBoxLayout, QWidget

from electrum.i18n import _
from electrum.wizard import ServerConnectWizard
from electrum.gui.qt.network_dialog import ProxyWidget, ServerWidget
from electrum.gui.qt.util import icon_path
from .wizard import QEAbstractWizard, WizardComponent

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins
    from electrum.daemon import Daemon
    from electrum.gui.qt import QElectrumApplication


class QEServerConnectWizard(ServerConnectWizard, QEAbstractWizard):

    def __init__(self, config: 'SimpleConfig', app: 'QElectrumApplication', plugins: 'Plugins', daemon: 'Daemon', parent=None):
        ServerConnectWizard.__init__(self, daemon)
        QEAbstractWizard.__init__(self, config, app)
        self.window_title = _('Network and server configuration')
        self.finish_label = _('Next')

        # attach gui classes
        self.navmap_merge({
            'welcome': {'gui': WCWelcome, 'params': {'icon': ''}},
            'proxy_config': {'gui': WCProxyConfig},
            'server_config': {'gui': WCServerConfig},
        })


class WCWelcome(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title='')
        self.wizard_title = _('Electrum Bitcoin Wallet')
        self.use_advanced_w = QCheckBox(_('Advanced network settings'))
        self.use_advanced_w.setChecked(False)
        self.use_advanced_w.stateChanged.connect(self.on_advanced_changed)

        self.img_label = QLabel()
        pixmap = QPixmap(icon_path('electrum_darkblue_1.png'))
        self.img_label.setPixmap(pixmap)
        self.img_label2 = QLabel()
        pixmap = QPixmap(icon_path('electrum_text.png'))
        self.img_label2.setPixmap(pixmap)
        hbox_img = QHBoxLayout()
        hbox_img.addStretch(1)
        hbox_img.addWidget(self.img_label)
        hbox_img.addWidget(self.img_label2)
        hbox_img.addStretch(1)

        self.config_proxy_w = QCheckBox(_('Configure Proxy'))
        self.config_proxy_w.setChecked(False)
        self.config_proxy_w.setVisible(False)
        self.config_proxy_w.stateChanged.connect(self.on_updated)
        self.config_server_w = QCheckBox(_('Select Server'))
        self.config_server_w.setChecked(False)
        self.config_server_w.setVisible(False)
        self.config_server_w.stateChanged.connect(self.on_updated)
        options_w = QWidget()
        vbox = QVBoxLayout()
        vbox.addWidget(self.config_proxy_w)
        vbox.addWidget(self.config_server_w)
        vbox.addStretch(1)
        options_w.setLayout(vbox)

        self.layout().addLayout(hbox_img)
        self.layout().addSpacing(50)
        self.layout().addWidget(self.use_advanced_w, False, Qt.AlignmentFlag.AlignHCenter)
        self.layout().addWidget(options_w, False, Qt.AlignmentFlag.AlignHCenter)
        self._valid = True

    def on_advanced_changed(self):
        self.config_proxy_w.setVisible(self.use_advanced_w.isChecked())
        self.config_server_w.setVisible(self.use_advanced_w.isChecked())
        self.on_updated()

    def apply(self):
        self.wizard_data['use_defaults'] = not self.use_advanced_w.isChecked()
        self.wizard_data['want_proxy'] = self.use_advanced_w.isChecked() and self.config_proxy_w.isChecked()
        self.wizard_data['autoconnect'] = not self.use_advanced_w.isChecked() or not self.config_server_w.isChecked()


class WCProxyConfig(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Proxy'))
        self.pw = ProxyWidget(self)
        self.pw.proxy_cb.setChecked(True)
        self.pw.proxy_host.setText('localhost')
        self.pw.proxy_port.setText('9050')
        self.layout().addWidget(self.pw)
        self.layout().addStretch(1)
        self._valid = True

    def apply(self):
        self.wizard_data['proxy'] = self.pw.get_proxy_settings()


class WCServerConfig(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Server'))
        self.sw = ServerWidget(wizard._daemon.network, self)
        self.layout().addWidget(self.sw)
        self._valid = True

    def apply(self):
        self.wizard_data['autoconnect'] = self.sw.server_e.text().strip() == ''
        self.wizard_data['server'] = self.sw.server_e.text()
