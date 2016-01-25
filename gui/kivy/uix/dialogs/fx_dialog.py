from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

Builder.load_string('''
<FxDialog@Popup>
    id: popup
    title: 'Fiat Currency'
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    BoxLayout:
        orientation: 'vertical'
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.1
            Label:
                text: _('Enable')
                height: '48dp'
            CheckBox:
                height: '48dp'
                id: enabled
                on_active: popup.on_active(self.active)

        Widget:
            size_hint: 1, 0.1

        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.1
            Label:
                text: _('Source')
                height: '48dp'
            Spinner:
                height: '48dp'
                id: exchanges
                on_text: popup.on_exchange(self.text)

        Widget:
            size_hint: 1, 0.1

        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.1
            Label:
                text: _('Currency')
                height: '48dp'
            Spinner:
                height: '48dp'
                id: ccy
                on_text: popup.on_currency(self.text)
        Widget:
            size_hint: 1, 0.2

        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.2
            Button:
                text: 'Cancel'
                size_hint: 0.5, None
                height: '48dp'
                on_release: popup.dismiss()
            Button:
                text: 'OK'
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    root.callback()
                    popup.dismiss()
''')


from kivy.uix.label import Label
from kivy.uix.checkbox import CheckBox
from kivy.uix.widget import Widget
from kivy.clock import Clock

from electrum.plugins import run_hook
from functools import partial

class FxDialog(Factory.Popup):

    __events__ = ('on_quotes', )

    def __init__(self, app, plugins, config, callback):
        Factory.Popup.__init__(self)
        self.app = app
        self.config = config
        self.callback = callback
        self.plugins = plugins
        p = self.plugins.get('exchange_rate')
        self.ids.enabled.active = bool(p)
        if p:
            p.dispatcher.bind(on_quotes=self.on_quotes)

    def on_quotes(self, b):
        self.add_currencies()

    def on_active(self, b):
        if b:
            p = self.plugins.get('exchange_rate')
            if p is None:
                p = self.plugins.enable('exchange_rate')
                p.init_kivy(self.app)
                p.dispatcher.bind(on_quotes=self.on_quotes)

            values = sorted(p.exchanges.keys())
            text = p.exchange.name()
        else:
            self.plugins.disable('exchange_rate')
            values = []
            text = ''
        Clock.schedule_once(lambda dt: self.add_exchanges(values, text))
        Clock.schedule_once(lambda dt: self.add_currencies())

    def add_exchanges(self, values, text):
        ex = self.ids.exchanges
        ex.values = values
        ex.text = text

    def on_exchange(self, text):
        if not text:
            return
        p = self.plugins.get('exchange_rate')
        if p and text != p.exchange.name():
            p.set_exchange(text)

    def add_currencies(self):
        p = self.plugins.get('exchange_rate')
        currencies = sorted(p.exchange.quotes.keys()) if p else []
        self.ids.ccy.values = currencies
        my_ccy = p.get_currency() if p else None
        if currencies:
            self.ids.ccy.text = my_ccy if my_ccy in currencies else currencies[0]

    def on_currency(self, ccy):
        if not ccy:
            return
        p = self.plugins.get('exchange_rate')
        if p and ccy != p.get_currency():
            p.set_currency(ccy)
        self.app.fiat_unit = ccy
