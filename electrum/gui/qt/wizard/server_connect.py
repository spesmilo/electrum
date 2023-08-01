from typing import TYPE_CHECKING

from PyQt5.QtWidgets import QApplication

from electrum.i18n import _
from .wizard import QEAbstractWizard, WizardComponent
from electrum.wizard import ServerConnectWizard
from ..network_dialog import ProxyWidget, ServerWidget
from ..util import ChoicesLayout

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins
    from electrum.daemon import Daemon
    from electrum.gui.qt import QElectrumApplication


class QEServerConnectWizard(ServerConnectWizard, QEAbstractWizard):

    def __init__(self, config: 'SimpleConfig', app: 'QElectrumApplication', plugins: 'Plugins', daemon: 'Daemon', parent=None):
        ServerConnectWizard.__init__(self, daemon)
        QEAbstractWizard.__init__(self, config, app, plugins, daemon)
        self._daemon = daemon

        # attach view names
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
        choices = [_("Auto connect"), _("Select server manually")]
        self.clayout = ChoicesLayout(message, choices, on_clicked=self.on_updated)
        self.layout().addLayout(self.clayout.layout())
        self._valid = True

    def apply(self):
        r = self.clayout.selected_index()
        self.wizard_data['autoconnect'] = (r == 0)
        # if r == 1:
        #     nlayout = NetworkChoiceLayout(network, self.config, wizard=True)
        #     if self.exec_layout(nlayout.layout()):
        #         nlayout.accept()
        #         self.config.NETWORK_AUTO_CONNECT = network.auto_connect
        # else:
        #     network.auto_connect = True
        #     self.config.NETWORK_AUTO_CONNECT = True


class WCProxyAsk(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_("Proxy"))
        message = _("Do you use a local proxy service such as TOR to reach the internet?")
        choices = [_("Yes"), _("No")]
        self.clayout = ChoicesLayout(message, choices)
        self.layout().addLayout(self.clayout.layout())
        self._valid = True

    def apply(self):
        r = self.clayout.selected_index()
        self.wizard_data['want_proxy'] = (r == 0)


class WCProxyConfig(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_("Proxy"))
        pw = ProxyWidget(self)
        self.layout().addWidget(pw)

    def apply(self):
        # TODO
        pass


class WCServerConfig(WizardComponent):
    def __init__(self, parent, wizard):
        WizardComponent.__init__(self, parent, wizard, title=_("Server"))
        sw = ServerWidget(self)
        self.layout().addWidget(sw)

    def apply(self):
        # TODO
        pass
