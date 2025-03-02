from .nwcserver import NWCServerPlugin
from electrum.plugin import hook

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from electrum.daemon import Daemon
    from electrum.wallet import Abstract_Wallet

class Plugin(NWCServerPlugin):

    def __init__(self, *args):
        NWCServerPlugin.__init__(self, *args)

    @hook
    def daemon_wallet_loaded(self, daemon: 'Daemon', wallet: 'Abstract_Wallet'):
        self.start_plugin(wallet)
