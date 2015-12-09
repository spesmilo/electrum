from exchange_rate import FxPlugin
from electrum.plugins import hook

class Plugin(FxPlugin):

    def on_quotes(self):
        self.print_error("on quotes", self.ccy)

    def on_history(self):
        self.print_error("on history")
        self.window.history_screen.update()

    def on_close(self):
        self.print_error("on close")
        self.window.fiat_unit = ''
        self.window.history_screen.update()

    @hook
    def init_kivy(self, window):
        self.window = window
        self.window.fiat_unit = self.ccy
        self.window.history_screen.update()

    @hook
    def load_wallet(self, wallet, window):
        self.window = window
        self.window.fiat_unit = self.ccy
