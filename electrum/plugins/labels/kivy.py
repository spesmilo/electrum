from .labels import LabelsPlugin
from electrum.plugin import hook

class Plugin(LabelsPlugin):

    @hook
    def load_wallet(self, wallet, window):
        self.window = window
        self.start_wallet(wallet)

    def on_pulled(self, wallet):
        self.logger.info('on pulled')
        self.window._trigger_update_history()

