from .labels import LabelsPlugin
from electrum_ltc.plugin import hook

class Plugin(LabelsPlugin):

    @hook
    def load_wallet(self, wallet, window):
        self.start_wallet(wallet)

    def on_pulled(self, wallet):
        self.print_error('labels pulled from server')
