from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.bitcoin import RECOMMENDED_FEE
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
            range: 0, 100
            on_value: root.on_slider(self.value)
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Dynamic Fees')
            CheckBox:
                id: dynfees
                on_active: root.on_checkbox(self.active)
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, None
            Label:
                id: reco
                font_size: '6pt'
                text_size: self.size
                text: ''
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
        self.callback = callback

        self.dynfees = self.config.get('dynamic_fees', False)
        self.fee_factor = self.config.get('fee_factor', 50)
        self.static_fee = self.config.get('fee_per_kb', RECOMMENDED_FEE)

        self.ids.dynfees.active = self.dynfees
        self.update_slider()
        self.update_text()

        if self.app.network and self.app.network.fee:
            self.ids.reco.text = _('Recommended fee for inclusion in the next two blocks') + ': ' + self.app.format_amount_and_units(self.app.network.fee) +'/kb' 

    def update_text(self):
        self.ids.fee_per_kb.text = self.get_fee_text()

    def update_slider(self):
        slider = self.ids.slider
        if self.dynfees:
            slider.value = self.fee_factor
            slider.range = (0, 100)
        else:
            slider.value = self.static_fee
            slider.range = (0, 2*RECOMMENDED_FEE)

    def get_fee_text(self):
        if self.ids.dynfees.active:
            return 'Recommendation x %d%%'%(self.fee_factor + 50)
        else:
            return self.app.format_amount_and_units(self.static_fee) + '/kB'

    def on_ok(self):
        self.config.set_key('dynamic_fees', self.dynfees, False)
        if self.dynfees:
            self.config.set_key('fee_factor', self.fee_factor, True)
        else:
            self.config.set_key('fee_per_kb', self.static_fee, True)
        self.callback()

    def on_slider(self, value):
        if self.dynfees:
            self.fee_factor = int(value)
        else:
            self.static_fee = int(value)
        self.update_text()

    def on_checkbox(self, b):
        self.dynfees = b
        self.update_slider()
        self.update_text()
