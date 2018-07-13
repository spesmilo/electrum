from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_ltc.gui.kivy.i18n import _

Builder.load_string('''
<BumpFeeDialog@Popup>
    title: _('Bump fee')
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    BoxLayout:
        orientation: 'vertical'
        padding: '10dp'

        GridLayout:
            height: self.minimum_height
            size_hint_y: None
            cols: 1
            spacing: '10dp'
            BoxLabel:
                id: old_fee
                text: _('Current Fee')
                value: ''
            BoxLabel:
                id: new_fee
                text: _('New Fee')
                value: ''
        Label:
            id: tooltip1
            text: ''
            size_hint_y: None
        Label:
            id: tooltip2
            text: ''
            size_hint_y: None
        Slider:
            id: slider
            range: 0, 4
            step: 1
            on_value: root.on_slider(self.value)
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.2
            Label:
                text: _('Final')
            CheckBox:
                id: final_cb
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
        self.mempool = self.config.use_mempool_fees()
        self.dynfees = self.config.is_dynfee() and bool(self.app.network) and self.config.has_dynamic_fees_ready()
        self.ids.old_fee.value = self.app.format_amount_and_units(self.init_fee)
        self.update_slider()
        self.update_text()

    def update_text(self):
        fee = self.get_fee()
        self.ids.new_fee.value = self.app.format_amount_and_units(fee)
        pos = int(self.ids.slider.value)
        fee_rate = self.get_fee_rate()
        text, tooltip = self.config.get_fee_text(pos, self.dynfees, self.mempool, fee_rate)
        self.ids.tooltip1.text = text
        self.ids.tooltip2.text = tooltip

    def update_slider(self):
        slider = self.ids.slider
        maxp, pos, fee_rate = self.config.get_fee_slider(self.dynfees, self.mempool)
        slider.range = (0, maxp)
        slider.step = 1
        slider.value = pos

    def get_fee_rate(self):
        pos = int(self.ids.slider.value)
        if self.dynfees:
            fee_rate = self.config.depth_to_fee(pos) if self.mempool else self.config.eta_to_fee(pos)
        else:
            fee_rate = self.config.static_fee(pos)
        return fee_rate

    def get_fee(self):
        fee_rate = self.get_fee_rate()
        return int(fee_rate * self.tx_size // 1000)

    def on_ok(self):
        new_fee = self.get_fee()
        is_final = self.ids.final_cb.active
        self.callback(self.init_fee, new_fee, is_final)

    def on_slider(self, value):
        self.update_text()
