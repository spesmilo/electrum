from exchange_rate import FxPlugin
from electrum_ltc.plugins import hook

class Plugin(FxPlugin):
    @hook
    def load_wallet(self, wallet, window):
        self.window = window

    def on_quotes(self):
        self.print_error("on quotes", self.ccy)
        self.window.fiat_unit = self.ccy
