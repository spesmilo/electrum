from typing import TYPE_CHECKING, Optional

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.gui.kivy.i18n import _

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow

from .fee_dialog import FeeSliderDialog


Builder.load_string('''
<CPFPDialog@Popup>
    title: _('Child Pays for Parent')
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
            TopLabel:
                text:
                    _(\
                    "A CPFP is a transaction that sends an unconfirmed output back to "\
                    "yourself, with a high fee. The goal is to have miners confirm "\
                    "the parent transaction in order to get the fee attached to the "\
                    "child transaction.")
            BoxLabel:
                id: total_size
                text: _('Total Size')
                value: ''
            BoxLabel:
                id: input_amount
                text: _('Input amount')
                value: ''
            BoxLabel:
                id: output_amount
                text: _('Output amount')
                value: ''
            BoxLabel:
                id: fee_for_child
                text: _('Fee for child')
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
        GridLayout:
            height: self.minimum_height
            size_hint_y: None
            cols: 1
            spacing: '10dp'
            BoxLabel:
                id: total_fee
                text: _('Total fee')
                value: ''
            BoxLabel:
                id: total_feerate
                text: _('Total feerate')
                value: ''
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

class CPFPDialog(FeeSliderDialog, Factory.Popup):

    def __init__(self, app: 'ElectrumWindow', parent_fee, total_size, new_tx, callback):
        self.app = app
        self.parent_fee = parent_fee
        self.total_size = total_size
        self.new_tx = new_tx
        self.max_fee = self.new_tx.output_value()
        Factory.Popup.__init__(self)
        FeeSliderDialog.__init__(self, app.electrum_config, self.ids.slider)
        self.callback = callback
        self.config = app.electrum_config
        self.ids.total_size.value = ('%d bytes'% self.total_size)
        self.ids.input_amount.value = self.app.format_amount(self.max_fee) + ' ' + self.app._get_bu()
        self.update_slider()
        self.update_text()

    def get_child_fee_from_total_feerate(self, fee_per_kb: Optional[int]) -> Optional[int]:
        if fee_per_kb is None:
            return None
        fee = fee_per_kb * self.total_size / 1000 - self.parent_fee
        fee = round(fee)
        fee = min(self.max_fee, fee)
        fee = max(self.total_size, fee)  # pay at least 1 sat/byte for combined size
        return fee

    def update_text(self):
        target, tooltip, dyn = self.config.get_fee_target()
        self.ids.fee_target.text = target
        fee_per_kb = self.config.fee_per_kb()
        self.fee = self.get_child_fee_from_total_feerate(fee_per_kb)
        if self.fee is None:
            self.ids.fee_for_child.value = "unknown"
        else:
            comb_fee = self.fee + self.parent_fee
            comb_feerate = 1000 * comb_fee / self.total_size
            self.ids.fee_for_child.value = self.app.format_amount_and_units(self.fee)
            self.ids.output_amount.value = self.app.format_amount_and_units(self.max_fee-self.fee) if self.max_fee > self.fee else ''
            self.ids.total_fee.value = self.app.format_amount_and_units(self.fee+self.parent_fee)
            self.ids.total_feerate.value = self.app.format_fee_rate(comb_feerate)

    def on_ok(self):
        fee = self.fee
        self.callback(fee, self.max_fee)

    def on_slider(self, value):
        self.save_config()
        self.update_text()
