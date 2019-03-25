from electrum.plugin import hook
from .coldcard import ColdcardPlugin
from electrum.util import print_msg, print_error, raw_input, print_stderr

class ColdcardCmdLineHandler:

    def get_passphrase(self, msg, confirm):
        raise NotImplementedError

    def get_pin(self, msg):
        raise NotImplementedError

    def prompt_auth(self, msg):
        raise NotImplementedError

    def yes_no_question(self, msg):
        print_msg(msg)
        return raw_input() in 'yY'

    def stop(self):
        pass

    def show_message(self, msg, on_cancel=None):
        print_stderr(msg)

    def show_error(self, msg, blocking=False):
        print_error(msg)

    def update_status(self, b):
        print_error('hw device status', b)

    def finished(self):
        pass

class Plugin(ColdcardPlugin):
    handler = ColdcardCmdLineHandler()

    @hook
    def init_keystore(self, keystore):
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler

    def create_handler(self, window):
        return self.handler

# EOF
