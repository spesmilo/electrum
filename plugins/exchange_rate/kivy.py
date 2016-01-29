from __future__ import absolute_import

from .exchange_rate import FxPlugin
from electrum.plugins import hook


from kivy.event import EventDispatcher

class MyEventDispatcher(EventDispatcher):

    def __init__(self, **kwargs):
        self.register_event_type('on_quotes')
        self.register_event_type('on_history')
        super(MyEventDispatcher, self).__init__(**kwargs)

    def on_quotes(self, *args):
        pass

    def on_history(self, *args):
        pass


class Plugin(FxPlugin):

    def __init__(self, parent, config, name):
        FxPlugin.__init__(self, parent, config, name)
        self.dispatcher = MyEventDispatcher()

    def on_quotes(self):
        self.print_error("on_quotes", self.ccy)
        self.dispatcher.dispatch('on_quotes')

    def on_history(self):
        self.print_error("on_history", self.ccy)
        self.dispatcher.dispatch('on_history')

    def on_close(self):
        self.print_error("on close")
        self.window.fiat_unit = ''
        self.window.history_screen.update()

    @hook
    def init_kivy(self, window):
        self.print_error("init_kivy")
        self.window = window
        self.dispatcher.bind(on_quotes=window.on_quotes)
        self.dispatcher.bind(on_history=window.on_history)
        self.window.fiat_unit = self.ccy
        self.dispatcher.dispatch('on_history')

    @hook
    def load_wallet(self, wallet, window):
        self.window = window
        self.window.fiat_unit = self.ccy
