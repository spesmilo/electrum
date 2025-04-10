from electrum.plugin import hook
from electrum.hw_wallet import CmdLineHandler

from .safe_t import SafeTPlugin

class Plugin(SafeTPlugin):
    handler = CmdLineHandler()
    @hook
    def init_keystore(self, keystore):
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler

    def create_handler(self, window):
        return self.handler
