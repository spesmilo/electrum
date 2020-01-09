from electrum.plugin import hook
from .ledger import LedgerPlugin
from ..hw_wallet import CmdLineHandler

class Plugin(LedgerPlugin):
	# print("In kivy .py.................class Plugin ............@7......")
    handler = CmdLineHandler()
    @hook
    def init_keystore(self, keystore):
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler
        self.window = window

    def create_handler(self, window):
        return self.handler

