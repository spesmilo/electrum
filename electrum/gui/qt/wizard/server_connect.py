from typing import TYPE_CHECKING

from electrum.i18n import _
from electrum.wizard import ServerConnectWizard
from electrum.gui.qt.network_dialog import ProxyWidget, ServerWidget
from electrum.gui.qt.util import ChoiceWidget
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

        self.setWindowTitle(_('Network and server configuration'))

        # attach gui classes
        self.navmap_merge({
            'autoconnect': { 'gui': WCAutoConnect },
            'proxy_ask': { 'gui': WCProxyAsk },
            'proxy_config': { 'gui': WCProxyConfig },
            'server_config': { 'gui': WCServerConfig },
        })


class WCAutoConnect(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_("How do you want to connect to a server? "))
        message = _("Electrum communicates with remote servers to get "
                  "information about your transactions and addresses. The "
                  "servers all fulfill the same purpose only differing in "
                  "hardware. In most cases you simply want to let Electrum "
                  "pick one at random.  However if you prefer feel free to "
                  "select a server manually.")
        choices = [('autoconnect', _("Auto connect")),
                   ('select', _("Select server manually"))]
        self.choice_w = ChoiceWidget(message=message, choices=choices, selected='autoconnect')
        self.choice_w.itemSelected.connect(self.on_updated)
        self.layout().addWidget(self.choice_w)
        self.layout().addStretch(1)
        self._valid = True

    def apply(self):
        self.wizard_data['autoconnect'] = (self.choice_w.selected_item[0] == 'autoconnect')


class WCProxyAsk(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_("Proxy"))
        message = _("Do you use a local proxy service such as TOR to reach the internet?")
        choices = [
            ('no', _("No")),
            ('yes', _("Yes")),
        ]
        self.choice_w = ChoiceWidget(message=message, choices=choices, selected='no')
        self.layout().addWidget(self.choice_w)
        self.layout().addStretch(1)
        self._valid = True

    def apply(self):
        self.wizard_data['want_proxy'] = (self.choice_w.selected_item[0] == 'yes')


class WCProxyConfig(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_("Proxy"))
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
        WizardComponent.__init__(self, parent, wizard, title=_("Server"))
        self.sw = ServerWidget(wizard._daemon.network, self)
        self.layout().addWidget(self.sw)
        self._valid = True

    def apply(self):
        self.wizard_data['autoconnect'] = self.sw.autoconnect_cb.isChecked()
        self.wizard_data['server'] = self.sw.server_e.text()
