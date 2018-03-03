from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_gui.kivy.i18n import _

Builder.load_string('''
<FeeDialog@Popup>
    id: popup
    title: _('Transaction Fees')
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    method: 0
    BoxLayout:
        orientation: 'vertical'
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Method') + ':'
            Button:
                text: _('Mempool based') if root.method == 2 else _('ETA based') if root.method == 1 else _('Static')
                background_color: (0,0,0,0)
                on_release:
                    root.method  = (root.method + 1) % 3
                    root.update_slider()
                    root.update_text()
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Target') + ':'
            Label:
                id: fee_target
                text: ''
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: (_('Current rate') if root.method > 0 else _('Estimate')) + ':'
            Label:
                id: fee_estimate
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
        mempool = self.config.use_mempool_fees()
        dynfees = self.config.is_dynfee()
        self.method = (2 if mempool else 1) if dynfees else 0
        self.update_slider()
        self.update_text()

    def update_text(self):
        value = int(self.ids.slider.value)
        target, estimate = self.get_fee_text(value)
        self.ids.fee_target.text = target
        self.ids.fee_estimate.text = estimate

    def get_method(self):
        dynfees = self.method > 0
        mempool = self.method == 2
        return dynfees, mempool

    def update_slider(self):
        slider = self.ids.slider
        dynfees, mempool = self.get_method()
        maxp, pos, fee_rate = self.config.get_fee_slider(dynfees, mempool)
        slider.range = (0, maxp)
        slider.step = 1
        slider.value = pos

    def get_fee_text(self, pos):
        dynfees, mempool = self.get_method()
        if dynfees:
            fee_rate = self.config.depth_to_fee(pos) if mempool else self.config.eta_to_fee(pos)
        else:
            fee_rate = self.config.static_fee(pos)
        return self.config.get_fee_text(pos, dynfees, mempool, fee_rate)

    def on_ok(self):
        value = int(self.ids.slider.value)
        dynfees, mempool = self.get_method()
        self.config.set_key('dynamic_fees', dynfees, False)
        self.config.set_key('mempool_fees', mempool, False)
        if dynfees:
            if mempool:
                self.config.set_key('depth_level', value, True)
            else:
                self.config.set_key('fee_level', value, True)
        else:
            self.config.set_key('fee_per_kb', self.config.static_fee(value), True)
        self.callback()

    def on_slider(self, value):
        self.update_text()
