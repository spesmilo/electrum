from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtProperty

from electrum.plugin import hook

from electrum.gui.common_qt.plugins import PluginQObject
from electrum.gui.qml.qedaemon import QEDaemon

from .trustedcoin import TrustedCoinPlugin, MOBILE_DISCLAIMER

if TYPE_CHECKING:
    from electrum.gui.qml import ElectrumQmlApplication
    from electrum.gui.qml.qewizard import QENewWalletWizard


class TrustedcoinPluginQObject(PluginQObject):

    @pyqtProperty(str, constant=True)
    def disclaimer(self):
        return '\n\n'.join(MOBILE_DISCLAIMER)


class Plugin(TrustedCoinPlugin):
    def __init__(self, *args):
        super().__init__(*args)
        self.so = None  # type: TrustedcoinPluginQObject

    @hook
    def init_qml(self, app: 'ElectrumQmlApplication'):
        self.logger.debug(f'init_qml hook called, gui={str(type(app))}')
        # important: TrustedcoinPluginQObject needs to be parented, as keeping a ref
        # in the plugin is not enough to avoid gc
        self.so = TrustedcoinPluginQObject(self, app)
        self.extend_wizard(QEDaemon.instance.newWalletWizard)

    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'trustedcoin_start': {
                'gui': '../../../../plugins/trustedcoin/qml/Disclaimer',
            },
            # on mobile, restoring from seed disables two-factor authentication
            'trustedcoin_have_seed': {
                'gui': 'WCHaveSeed',
                'next': lambda d: 'trustedcoin_have_ext' if wizard.wants_ext(d) else 'wallet_password',
                'accept': lambda d: None if wizard.wants_ext(d) else self.recovery_disable(d),
                'last': lambda d: wizard.is_single_password() and not wizard.wants_ext(d),
            },
            'trustedcoin_have_ext': {
                'gui': 'WCEnterExt',
                'next': 'wallet_password',
                'accept': self.recovery_disable,
                'last': lambda d: wizard.is_single_password(),
            },
        }
        wizard.navmap_merge(views)
