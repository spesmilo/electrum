from electrum.plugin import hook
from electrum.util import print_msg, raw_input, print_stderr
from electrum.logging import get_logger

from .coldcard import ColdcardPlugin


_logger = get_logger(__name__)


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
        print_stderr(msg)

    def update_status(self, b):
        _logger.info(f'hw device status {b}')

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
