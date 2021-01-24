from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.uix.checkbox import CheckBox
from kivy.uix.label import Label
from kivy.uix.widget import Widget
from kivy.clock import Clock

from decimal import Decimal

from electrum_ltc.simple_config import FEERATE_WARNING_HIGH_FEE, FEE_RATIO_HIGH_WARNING
from electrum_ltc.gui.kivy.i18n import _
from electrum_ltc.plugin import run_hook
from electrum_ltc.util import NotEnoughFunds

from .fee_dialog import FeeSliderDialog, FeeDialog

Builder.load_string('''
<ConfirmTxDialog@Popup>
    id: popup
    title: _('Confirm Payment')
    message: ''
    warning: ''
    extra_fee: ''
    show_final: False
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
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
                text: _('Fee target:')
            Button:
                id: fee_button
                text: ''
                background_color: (0,0,0,0)
                bold: True
                on_release:
                    root.on_fee_button()
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
                opacity: int(root.show_final)
            CheckBox:
                id: final_cb
                opacity: int(root.show_final)
                disabled: not root.show_final
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
                text: _('OK')
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    root.pay()
                    popup.dismiss()
''')




class ConfirmTxDialog(FeeSliderDialog, Factory.Popup):

    def __init__(self, app, invoice):

        Factory.Popup.__init__(self)
        FeeSliderDialog.__init__(self, app.electrum_config, self.ids.slider)
        self.app = app
        self.show_final = bool(self.config.get('use_rbf'))
        self.invoice = invoice
        self.update_slider()
        self.update_text()
        self.update_tx()

    def update_tx(self):
        outputs = self.invoice.outputs
        try:
            # make unsigned transaction
            coins = self.app.wallet.get_spendable_coins(None)
            tx = self.app.wallet.make_unsigned_transaction(coins=coins, outputs=outputs)
        except NotEnoughFunds:
            self.warning = _("Not enough funds")
            return
        except Exception as e:
            self.logger.exception('')
            self.app.show_error(repr(e))
            return
        rbf = not bool(self.ids.final_cb.active) if self.show_final else False
        tx.set_rbf(rbf)
        amount = sum(map(lambda x: x.value, outputs)) if '!' not in [x.value for x in outputs] else tx.output_value()
        fee = tx.get_fee()
        feerate = Decimal(fee) / tx.estimated_size()  # sat/byte
        self.ids.fee_label.text = self.app.format_amount_and_units(fee) + f' ({feerate:.1f} sat/B)'
        self.ids.amount_label.text = self.app.format_amount_and_units(amount)
        x_fee = run_hook('get_tx_extra_fee', self.app.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            self.extra_fee = self.app.format_amount_and_units(x_fee_amount)
        else:
            self.extra_fee = ''
        fee_ratio = Decimal(fee) / amount if amount else 1
        if fee_ratio >= FEE_RATIO_HIGH_WARNING:
            self.warning = _('Warning') + ': ' + _("The fee for this transaction seems unusually high.") + f' ({fee_ratio*100:.2f}% of amount)'
        elif feerate > FEERATE_WARNING_HIGH_FEE / 1000:
            self.warning = _('Warning') + ': ' + _("The fee for this transaction seems unusually high.") + f' (feerate: {feerate:.2f} sat/byte)'
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

    def pay(self):
        self.app.protected(_('Send payment?'), self.app.send_screen.send_tx, (self.tx, self.invoice))

    def on_fee_button(self):
        fee_dialog = FeeDialog(self, self.config, self.after_fee_changed)
        fee_dialog.open()

    def after_fee_changed(self):
        self.read_config()
        self.update_slider()
        self.update_text()
        Clock.schedule_once(lambda dt: self.update_tx())
