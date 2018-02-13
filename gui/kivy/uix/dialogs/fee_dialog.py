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
                text: (_('Target') if dynfees.active else _('Fixed rate')) + ':'
            Label:
                id: fee_target
                text: ''
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: (_('Current rate') if dynfees.active else _('Estimate')) + ':'
            Label:
                id: fee_estimate
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
                on_active: root.on_dynfees(self.active)
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Use mempool')
            CheckBox:
                id: mempool
                on_active: root.on_mempool(self.active)
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
        self.mempool = self.config.use_mempool_fees()
        self.dynfees = self.config.is_dynfee()
        self.ids.mempool.active = self.mempool
        self.ids.dynfees.active = self.dynfees
        self.update_slider()
        self.update_text()

    def update_text(self):
        value = int(self.ids.slider.value)
        target, estimate = self.get_fee_text(value)
        self.ids.fee_target.text = target
        self.ids.fee_estimate.text = estimate

    def update_slider(self):
        slider = self.ids.slider
        maxp, pos, fee_rate = self.config.get_fee_slider(self.dynfees, self.mempool)
        slider.range = (0, maxp)
        slider.step = 1
        slider.value = pos

    def get_fee_text(self, pos):
        dyn = self.dynfees
        mempool = self.mempool
        if dyn:
            fee_rate = self.config.depth_to_fee(pos) if mempool else self.config.eta_to_fee(pos)
        else:
            fee_rate = self.config.static_fee(pos)
        return self.config.get_fee_text(pos, dyn, mempool, fee_rate)

    def on_ok(self):
        value = int(self.ids.slider.value)
        self.config.set_key('dynamic_fees', self.dynfees, False)
        self.config.set_key('mempool_fees', self.mempool, False)
        if self.dynfees:
            if self.mempool:
                self.config.set_key('depth_level', value, True)
            else:
                self.config.set_key('fee_level', value, True)
        else:
            self.config.set_key('fee_per_kb', self.config.static_fee(value), True)
        self.callback()

    def on_slider(self, value):
        self.update_text()

    def on_dynfees(self, b):
        self.dynfees = b
        self.update_slider()
        self.update_text()

    def on_mempool(self, b):
        self.mempool = b
        self.update_slider()
        self.update_text()
