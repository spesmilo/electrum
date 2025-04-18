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
            'welcome': {'gui': WCWelcome},
            'proxy_config': {'gui': WCProxyConfig},
            'server_config': {'gui': WCServerConfig},
        })


class WCWelcome(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title='Network Configuration')
        self.wizard_title = _('Electrum Bitcoin Wallet')

        self.first_help_label = QLabel()
        self.first_help_label.setText(_("Optional settings to customize your network connection") + ":")
        self.first_help_label.setWordWrap(True)

        self.config_proxy_w = QCheckBox(_('Use Proxy'))
        self.config_proxy_w.setChecked(False)
        self.config_proxy_w.stateChanged.connect(self.on_updated)
        self.config_server_w = QCheckBox(_('Select Electrum Server'))
        self.config_server_w.setChecked(False)
        self.config_server_w.stateChanged.connect(self.on_updated)
        options_w = QWidget()
        vbox = QVBoxLayout()
        vbox.addWidget(self.config_proxy_w)
        vbox.addWidget(self.config_server_w)
        options_w.setLayout(vbox)

        self.second_help_label = QLabel()
        self.second_help_label.setText(
            _("If you are unsure what these options are, leave them unchecked.")
        )
        self.second_help_label.setWordWrap(True)

        self.layout().addWidget(self.first_help_label)
        self.layout().addWidget(options_w)
        self.layout().addWidget(self.second_help_label)
        self.layout().addStretch(1)
        self._valid = True

    def apply(self):
        self.wizard_data['use_defaults'] = not (self.config_server_w.isChecked() or self.config_proxy_w.isChecked())
        self.wizard_data['want_proxy'] = self.config_proxy_w.isChecked()
        self.wizard_data['autoconnect'] = not self.config_server_w.isChecked()


class WCProxyConfig(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Proxy'))
        self.pw = ProxyWidget(wizard._daemon.network, self)
        self.pw.proxy_cb.setChecked(True)
        self.pw.proxy_host.setText('localhost')
        self.pw.proxy_port.setText('9050')
        self.layout().addWidget(self.pw)
        self._valid = True

    def apply(self):
        self.wizard_data['proxy'] = self.pw.get_proxy_settings().to_dict()


class WCServerConfig(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_('Server'))
        self.sw = ServerWidget(wizard._daemon.network, self)
        self.layout().addWidget(self.sw)
        self._valid = True

    def apply(self):
        self.wizard_data['autoconnect'] = self.sw.server_e.text().strip() == ''
        self.wizard_data['server'] = self.sw.server_e.text()
        self.wizard_data['one_server'] = self.wizard.config.NETWORK_ONESERVER
