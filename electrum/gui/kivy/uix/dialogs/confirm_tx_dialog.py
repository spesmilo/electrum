from decimal import Decimal
from typing import TYPE_CHECKING

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.uix.checkbox import CheckBox
from kivy.uix.label import Label
from kivy.uix.widget import Widget
from kivy.clock import Clock

from electrum.gui.kivy.i18n import _
from electrum.plugin import run_hook
from electrum.util import NotEnoughFunds

from .fee_dialog import FeeSliderDialog

if TYPE_CHECKING:
    from electrum.gui.kivy.main_window import ElectrumWindow

Builder.load_string('''
<ConfirmTxDialog@Popup>
    id: popup
    title: _('Confirm Payment')
    message: ''
    warning: ''
    extra_fee: ''
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    method: 0
    BoxLayout:
        orientation: 'vertical'
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Amount to be sent:')
            Label:
                id: amount_label
                text: ''
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Mining fee:')
            Label:
                id: fee_label
                text: ''
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, (0.5 if root.extra_fee else 0.01)
            Label:
                text: _('Additional fees') if root.extra_fee else ''
            Label:
                text: root.extra_fee
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Fee rate:')
            Label:
                id: feerate_label
                text: ''
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Target') + ' (%s):' % (_('mempool') if root.method == 2 else _('ETA') if root.method == 1 else _('static'))
            Button:
                id: fee_button
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
        Label:
            text: root.warning
            text_size: self.width, None
        Widget:
            size_hint: 1, 0.5
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Button:
                text: _('Cancel')
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    popup.dismiss()
            Button:
                id: ok_button
                text: _('OK')
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    root.on_pay(root.tx)
                    popup.dismiss()
''')




class ConfirmTxDialog(FeeSliderDialog, Factory.Popup):

    def __init__(self, app: 'ElectrumWindow', amount, make_tx, on_pay):

        Factory.Popup.__init__(self)
        FeeSliderDialog.__init__(self, app.electrum_config, self.ids.slider)
        self.app = app
        self.amount = amount
        self.make_tx = make_tx
        self.on_pay = on_pay
        self.update_slider()
        self.update_text()
        self.update_tx()

    def update_tx(self):
        try:
            # make unsigned transaction
            tx = self.make_tx()
        except NotEnoughFunds:
            self.warning = _("Not enough funds")
            self.ids.ok_button.disabled = True
            return
        except Exception as e:
            self.ids.ok_button.disabled = True
            self.app.logger.exception('')
            self.app.show_error(repr(e))
            return
        self.ids.ok_button.disabled = False
        amount = self.amount if self.amount != '!' else tx.output_value()
        tx_size = tx.estimated_size()
        fee = tx.get_fee()
        self.ids.fee_label.text = self.app.format_amount_and_units(fee)
        feerate = Decimal(fee) / tx_size  # sat/byte
        self.ids.feerate_label.text = f'{feerate:.1f} sat/B'
        self.ids.amount_label.text = self.app.format_amount_and_units(amount)
        x_fee = run_hook('get_tx_extra_fee', self.app.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            self.extra_fee = self.app.format_amount_and_units(x_fee_amount)
        else:
            self.extra_fee = ''
        fee_warning_tuple = self.app.wallet.get_tx_fee_warning(
            invoice_amt=amount, tx_size=tx_size, fee=fee)
        if fee_warning_tuple:
            allow_send, long_warning, short_warning = fee_warning_tuple
            self.warning = long_warning
        else:
            self.warning = ''
        self.tx = tx

    def on_slider(self, value):
        self.save_config()
        self.update_text()
        Clock.schedule_once(lambda dt: self.update_tx())

    def update_text(self):
        target, tooltip, dyn = self.config.get_fee_target()
        self.ids.fee_button.text = target
