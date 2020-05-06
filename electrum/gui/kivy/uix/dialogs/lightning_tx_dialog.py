import copy
from datetime import datetime
from decimal import Decimal
from typing import NamedTuple, Callable, TYPE_CHECKING

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.uix.label import Label
from kivy.uix.dropdown import DropDown
from kivy.uix.button import Button

from electrum.gui.kivy.i18n import _


if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string('''

<LightningTxDialog>
    id: popup
    title: _('Lightning Payment')
    preimage: ''
    is_sent: False
    amount_str: ''
    fee_str: ''
    date_str: ''
    payment_hash: ''
    description: ''
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            scroll_type: ['bars', 'content']
            bar_width: '25dp'
            GridLayout:
                height: self.minimum_height
                size_hint_y: None
                cols: 1
                spacing: '10dp'
                padding: '10dp'
                GridLayout:
                    height: self.minimum_height
                    size_hint_y: None
                    cols: 1
                    spacing: '10dp'
                    BoxLabel:
                        text: _('Description') if root.description else ''
                        value: root.description
                    BoxLabel:
                        text: _('Date')
                        value: root.date_str
                    BoxLabel:
                        text: _('Amount sent') if root.is_sent else _('Amount received')
                        value: root.amount_str
                    BoxLabel:
                        text: _('Transaction fee') if root.fee_str else ''
                        value: root.fee_str
                TopLabel:
                    text: _('Payment hash') + ':'
                TxHashLabel:
                    data: root.payment_hash
                    name: _('Payment hash')
                TopLabel:
                    text: _('Preimage')
                TxHashLabel:
                    data: root.preimage
                    name: _('Preimage')

        Widget:
            size_hint: 1, 0.1

        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Widget
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Close')
                on_release: root.dismiss()
''')


class ActionButtonOption(NamedTuple):
    text: str
    func: Callable
    enabled: bool


class LightningTxDialog(Factory.Popup):

    def __init__(self, app, tx_item):
        Factory.Popup.__init__(self)
        self.app = app  # type: ElectrumWindow
        self.wallet = self.app.wallet
        self._action_button_fn = lambda btn: None
        self.description = tx_item['label']
        self.timestamp = tx_item['timestamp']
        self.date_str = datetime.fromtimestamp(self.timestamp).isoformat(' ')[:-3]
        self.amount = Decimal(tx_item['amount_msat']) /1000
        self.payment_hash = tx_item['payment_hash']
        self.preimage = tx_item['preimage']
        format_amount = self.app.format_amount_and_units
        self.is_sent = self.amount < 0
        self.amount_str = format_amount(-self.amount if self.is_sent else self.amount)
        if tx_item.get('fee_msat'):
            self.fee_str = format_amount(Decimal(tx_item['fee_msat']) / 1000)
