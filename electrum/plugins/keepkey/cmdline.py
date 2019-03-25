from electrum.plugin import hook
from .keepkey import KeepKeyPlugin
from ..hw_wallet import CmdLineHandler

class Plugin(KeepKeyPlugin):
    handler = CmdLineHandler()
    @hook
    def init_keystore(self, keystore):
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler

    def create_handler(self, window):
        return self.handler
