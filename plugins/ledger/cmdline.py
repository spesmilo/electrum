from legder import LedgerPlugin
from electrum.util import print_msg

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
    handler = BTChipCmdLineHandler()
