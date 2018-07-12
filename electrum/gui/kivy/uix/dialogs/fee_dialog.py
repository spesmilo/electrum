from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.gui.kivy.i18n import _

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
                text: _('Mempool') if root.method == 2 else _('ETA') if root.method == 1 else _('Static')
                background_color: (0,0,0,0)
                bold: True
                on_release:
                    root.method  = (root.method + 1) % 3
                    root.update_slider()
                    root.update_text()
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: (_('Target') if root.method > 0 else _('Fee')) + ':'
            Label:
                id: fee_target
                text: ''
        Slider:
            id: slider
            range: 0, 4
            step: 1
            on_value: root.on_slider(self.value)
        Widget:
            size_hint: 1, 0.5
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            TopLabel:
                id: fee_estimate
                text: ''
                font_size: '14dp'
        Widget:
            size_hint: 1, 0.5
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
        mempool = self.config.use_mempool_fees()
        dynfees = self.config.is_dynfee()
        self.method = (2 if mempool else 1) if dynfees else 0
        self.update_slider()
        self.update_text()

    def update_text(self):
        pos = int(self.ids.slider.value)
        dynfees, mempool = self.get_method()
        if self.method == 2:
            fee_rate = self.config.depth_to_fee(pos)
            target, estimate = self.config.get_fee_text(pos, dynfees, mempool, fee_rate)
            msg = 'In the current network conditions, in order to be positioned %s, a transaction will require a fee of %s.' % (target, estimate)
        elif self.method == 1:
            fee_rate = self.config.eta_to_fee(pos)
            target, estimate = self.config.get_fee_text(pos, dynfees, mempool, fee_rate)
            msg = 'In the last few days, transactions that confirmed %s usually paid a fee of at least %s.' % (target.lower(), estimate)
        else:
            fee_rate = self.config.static_fee(pos)
            target, estimate = self.config.get_fee_text(pos, dynfees, True, fee_rate)
            msg = 'In the current network conditions, a transaction paying %s would be positioned %s.' % (target, estimate)

        self.ids.fee_target.text = target
        self.ids.fee_estimate.text = msg

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
