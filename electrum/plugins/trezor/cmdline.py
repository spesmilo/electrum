from electrum.plugin import hook
from electrum.i18n import _
from electrum.util import print_stderr
from .trezor import TrezorPlugin, PASSPHRASE_ON_DEVICE
from ..hw_wallet import CmdLineHandler

class TrezorCmdLineHandler(CmdLineHandler):
    def __init__(self):
        self.passphrase_on_device = False
        super().__init__()

    def get_passphrase(self, msg, confirm):
        import getpass
        print_stderr(msg)
        if self.passphrase_on_device and self.yes_no_question(_('Enter passphrase on device?')):
            return PASSPHRASE_ON_DEVICE
        else:
            return getpass.getpass('')

class Plugin(TrezorPlugin):
    handler = CmdLineHandler()
    @hook
    def init_keystore(self, keystore):
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler

    def create_handler(self, window):
        return self.handler
