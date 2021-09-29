from typing import TYPE_CHECKING

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.gui.kivy.i18n import _

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow

from .fee_dialog import FeeSliderDialog


Builder.load_string('''
<BumpFeeDialog@Popup>
    title: _('Bump fee')
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    method: 0
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
                id: old_feerate
                text: _('Current Fee rate')
                value: ''
            BoxLabel:
                id: new_feerate
                text: _('New Fee rate')
                value: ''
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Target') + ' (%s):' % (_('mempool') if root.method == 2 else _('ETA') if root.method == 1 else _('static'))
            Button:
                id: fee_target
                text: ''
                background_color: (0,0,0,0)
                bold: True
                on_release:
                    root.method  = (root.method + 1) % 3
                    root.update_slider()
                    root.on_slider(root.slider.value)
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

class BumpFeeDialog(FeeSliderDialog, Factory.Popup):

    def __init__(self, app: 'ElectrumWindow', fee, size, callback):
        Factory.Popup.__init__(self)
        FeeSliderDialog.__init__(self, app.electrum_config, self.ids.slider)
        self.app = app
        self.init_fee = fee
        self.tx_size = size
        self.callback = callback
        self.config = app.electrum_config
        self.ids.old_fee.value = self.app.format_amount_and_units(self.init_fee)
        self.ids.old_feerate.value = self.app.format_fee_rate(fee / self.tx_size * 1000)
        self.update_slider()
        self.update_text()

    def update_text(self):
        target, tooltip, dyn = self.config.get_fee_target()
        self.ids.fee_target.text = target
        fee_per_kb = self.config.fee_per_kb()
        if fee_per_kb is None:
            self.ids.new_feerate.value = "unknown"
        else:
            fee_per_byte = fee_per_kb / 1000
            self.ids.new_feerate.value = f'{fee_per_byte:.1f} sat/B'

    def on_ok(self):
        fee_per_kb = self.config.fee_per_kb()
        new_fee_rate = fee_per_kb / 1000 if fee_per_kb is not None else None
        is_final = self.ids.final_cb.active
        self.callback(new_fee_rate, is_final)

    def on_slider(self, value):
        self.save_config()
        self.update_text()
