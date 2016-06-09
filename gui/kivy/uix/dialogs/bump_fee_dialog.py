from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_ltc.bitcoin import FEE_STEP, RECOMMENDED_FEE
from electrum_ltc.util import fee_levels
from electrum_ltc_gui.kivy.i18n import _

Builder.load_string('''
<BumpFeeDialog@Popup>
    title: _('Bump fee')
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    BoxLayout:
        orientation: 'vertical'

        GridLayout:
            height: self.minimum_height
            size_hint_y: None
            cols: 1
            spacing: '10dp'
            BoxLabel:
                id: old_fee
                text: _('Fee')
                value: ''
            BoxLabel:
                id: new_fee
                text: _('New Fee')
                value: ''
        Label:
            id: tooltip
            text: ''
        Slider:
            id: slider
            range: 0, 4
            step: 1
            on_value: root.on_slider(self.value)
        Widget:
            size_hint: 1, 1
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Button:
                text: 'Cancel'
                size_hint: 0.5, None
                height: '48dp'
                on_release: root.dismiss()
            Button:
                text: 'OK'
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    root.dismiss()
                    root.on_ok()
''')

class BumpFeeDialog(Factory.Popup):

    def __init__(self, app, fee, size, callback):
        Factory.Popup.__init__(self)
        self.app = app
        self.init_fee = fee
        self.tx_size = size
        self.callback = callback
        self.config = app.electrum_config
        self.dynfees = self.config.get('dynamic_fees', True) and self.app.network
        self.ids.old_fee.value = self.app.format_amount_and_units(self.init_fee)
        self.update_slider()
        self.update_text()

    def update_text(self):
        value = int(self.ids.slider.value)
        self.ids.new_fee.value = self.app.format_amount_and_units(self.get_fee())
        if self.dynfees:
            value = int(self.ids.slider.value)
            self.ids.tooltip.text = fee_levels[value]

    def update_slider(self):
        slider = self.ids.slider
        if self.dynfees:
            slider.range = (0, 4)
            slider.step = 1
            slider.value = 0
        else:
            slider.range = (FEE_STEP, 2*RECOMMENDED_FEE)
            slider.step = FEE_STEP
            slider.value = self.init_fee*1.5

    def get_fee(self):
        value = int(self.ids.slider.value)
        if self.dynfees:
            dynfee = self.app.network.dynfee(value)
            if dynfee:
                return dynfee*self.tx_size/1000
        else:
            return value*self.tx_size/1000

    def on_ok(self):
        new_fee = self.get_fee()
        self.callback(self.init_fee, new_fee)

    def on_slider(self, value):
        self.update_text()

    def on_checkbox(self, b):
        self.dynfees = b
        self.update_text()
