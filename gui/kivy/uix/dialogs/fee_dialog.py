from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.util import fee_levels
from electrum_gui.kivy.i18n import _

Builder.load_string('''
<FeeDialog@Popup>
    id: popup
    title: _('Transaction Fees')
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    BoxLayout:
        orientation: 'vertical'
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                id: fee_per_kb
                text: ''
        Slider:
            id: slider
            range: 0, 4
            step: 1
            on_value: root.on_slider(self.value)
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Dynamic Fees')
            CheckBox:
                id: dynfees
                on_active: root.on_checkbox(self.active)
        Widget:
            size_hint: 1, 1
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
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
                    root.on_ok()
                    root.dismiss()
''')

class FeeDialog(Factory.Popup):

    def __init__(self, app, config, callback):
        Factory.Popup.__init__(self)
        self.app = app
        self.config = config
        self.fee_step = self.config.max_fee_rate() / 10
        self.fee_rate = self.config.fee_per_kb()
        self.callback = callback
        self.dynfees = self.config.get('dynamic_fees', True)
        self.ids.dynfees.active = self.dynfees
        self.update_slider()
        self.update_text()

    def update_text(self):
        value = int(self.ids.slider.value)
        self.ids.fee_per_kb.text = self.get_fee_text(value)

    def update_slider(self):
        slider = self.ids.slider
        if self.dynfees:
            slider.range = (0, 4)
            slider.step = 1
            slider.value = self.config.get('fee_level', 2)
        else:
            slider.range = (1, 10)
            slider.step = 1
            slider.value = min(self.fee_rate / self.fee_step, 10)

    def get_fee_text(self, value):
        if self.ids.dynfees.active:
            tooltip = fee_levels[value]
            if self.config.has_fee_estimates():
                dynfee = self.config.dynfee(value)
                tooltip += '\n' + (self.app.format_amount_and_units(dynfee)) + '/kB'
        else:
            fee_rate = value * self.fee_step
            tooltip = self.app.format_amount_and_units(fee_rate) + '/kB'
            if self.config.has_fee_estimates():
                i = self.config.reverse_dynfee(fee_rate)
                tooltip += '\n' + (_('low fee') if i < 0 else 'Within %d blocks'%i)
        return tooltip

    def on_ok(self):
        value = int(self.ids.slider.value)
        self.config.set_key('dynamic_fees', self.dynfees, False)
        if self.dynfees:
            self.config.set_key('fee_level', value, True)
        else:
            self.config.set_key('fee_per_kb', value * self.fee_step, True)
        self.callback()

    def on_slider(self, value):
        self.update_text()

    def on_checkbox(self, b):
        self.dynfees = b
        self.update_slider()
        self.update_text()
