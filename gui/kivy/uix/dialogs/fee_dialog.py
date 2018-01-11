from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electroncash.util import fee_levels
from electroncash_gui.kivy.i18n import _

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
        self.fee_rate = self.config.fee_per_kb()
        self.callback = callback
        self.update_slider()
        self.update_text()

    def update_text(self):
        value = int(self.ids.slider.value)
        self.ids.fee_per_kb.text = self.get_fee_text(value)

    def update_slider(self):
        slider = self.ids.slider
        slider.range = (0, 9)
        slider.step = 1
        slider.value = self.config.static_fee_index(self.fee_rate)

    def get_fee_text(self, value):
            fee_rate = self.config.static_fee(value)
            tooltip = self.app.format_amount_and_units_fees(fee_rate) + '/byte'
            return tooltip

    def on_ok(self):
        value = int(self.ids.slider.value)
        self.config.set_key('fee_per_kb', self.config.static_fee(value), True)
        self.callback()

    def on_slider(self, value):
        self.update_text()
 
