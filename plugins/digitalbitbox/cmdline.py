from digitalbitbox import DigitalBitboxPlugin
from electrum_ltc.util import print_msg

class DigitalBitboxCmdLineHandler:
    def stop(self):
        pass

    def show_message(self, msg):
        print_msg(msg)

    def get_passphrase(self, msg, confirm):
        import getpass
        print_msg(msg)
        return getpass.getpass('')

class Plugin(DigitalBitboxPlugin):
    handler = DigitalBitboxCmdLineHandler()
