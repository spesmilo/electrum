from legder import LedgerPlugin
from electrum.util import print_msg
from electrum.plugins import hook

class BTChipCmdLineHandler:
    def stop(self):
        pass

    def show_message(self, msg):
        print_msg(msg)

    def prompt_auth(self, msg):
        import getpass
        print_msg(msg)
        response = getpass.getpass('')
        if len(response) == 0:
            return None
        return response

class Plugin(LedgerPlugin):
    @hook
    def cmdline_load_wallet(self, wallet):
        self.wallet = wallet
        self.wallet.plugin = self
        if self.handler is None:
            self.handler = BTChipCmdLineHandler()


