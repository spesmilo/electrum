from electrum.plugin import hook
from .mirkey import MIRkeyPlugin
from ..hw_wallet import CmdLineHandler


class Plugin(MIRkeyPlugin):
    handler = CmdLineHandler()
    @hook
    def init_keystore(self, keystore):
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler

    def create_handler(self, window):
        return self.handler
