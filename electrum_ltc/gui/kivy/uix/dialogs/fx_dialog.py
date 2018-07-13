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

from electrum_ltc.gui.kivy.i18n import _
from functools import partial

class FxDialog(Factory.Popup):

    def __init__(self, app, plugins, config, callback):
        Factory.Popup.__init__(self)
        self.app = app
        self.config = config
        self.callback = callback
        self.fx = self.app.fx
        self.fx.set_history_config(True)
        self.add_currencies()

    def add_exchanges(self):
        exchanges = sorted(self.fx.get_exchanges_by_ccy(self.fx.get_currency(), True)) if self.fx.is_enabled() else []
        mx = self.fx.exchange.name() if self.fx.is_enabled() else ''
        ex = self.ids.exchanges
        ex.values = exchanges
        ex.text = (mx if mx in exchanges else exchanges[0]) if self.fx.is_enabled() else ''

    def on_exchange(self, text):
        if not text:
            return
        if self.fx.is_enabled() and text != self.fx.exchange.name():
            self.fx.set_exchange(text)

    def add_currencies(self):
        currencies = [_('None')] + self.fx.get_currencies(True)
        my_ccy = self.fx.get_currency() if self.fx.is_enabled() else _('None')
        self.ids.ccy.values = currencies
        self.ids.ccy.text = my_ccy

    def on_currency(self, ccy):
        b = (ccy != _('None'))
        self.fx.set_enabled(b)
        if b:
            if ccy != self.fx.get_currency():
                self.fx.set_currency(ccy)
            self.app.fiat_unit = ccy
        else:
            self.app.is_fiat = False
        Clock.schedule_once(lambda dt: self.add_exchanges())
