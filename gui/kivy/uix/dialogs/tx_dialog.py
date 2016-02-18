from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.uix.label import Label

from electrum_gui.kivy.i18n import _
from datetime import datetime
from electrum.util import InvalidPassword

Builder.load_string('''

<TxDialog>
    id: popup
    title: _('Transaction')
    is_mine: True
    can_sign: False
    can_broadcast: False
    fee_str: ''
    date_str: ''
    amount_str: ''
    tx_hash: ''
    status_str: ''
    description: ''
    outputs_str: ''
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
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
                        text: _('Status')
                        value: root.status_str
                    BoxLabel:
                        text: _('Description') if root.description else ''
                        value: root.description
                    BoxLabel:
                        text: _('Date') if root.date_str else ''
                        value: root.date_str
                    BoxLabel:
                        text: _('Amount sent') if root.is_mine else _('Amount received')
                        value: root.amount_str
                    BoxLabel:
                        text: _('Transaction fee') if root.fee_str else ''
                        value: root.fee_str
                TopLabel:
                    text: _('Outputs') + ':'
                OutputList:
                    height: self.minimum_height
                    size_hint: 1, None
                    id: output_list
                TopLabel:
                    text: _('Transaction ID') + ':' if root.tx_hash else ''
                TxHashLabel:
                    data: root.tx_hash
                    name: _('Transaction ID')
        Widget:
            size_hint: 1, 0.1

        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Sign') if root.can_sign else _('Broadcast') if root.can_broadcast else ''
                opacity: 1 if root.can_sign or root.can_broadcast else 0
                disabled: not( root.can_sign or root.can_broadcast )
                on_release:
                    if root.can_sign: root.do_sign()
                    if root.can_broadcast: root.do_broadcast()
            IconButton:
                size_hint: 0.5, None
                height: '48dp'
                icon: 'atlas://gui/kivy/theming/light/qrcode'
                on_release: root.show_qr()
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Close')
                on_release: popup.dismiss()
''')


class TxDialog(Factory.Popup):

    def __init__(self, app, tx):
        Factory.Popup.__init__(self)
        self.app = app
        self.wallet = self.app.wallet
        self.tx = tx

    def on_open(self):
        self.update()

    def update(self):
        self.can_broadcast = False
        if self.tx.is_complete():
            self.tx_hash = self.tx.hash()
            self.description = self.wallet.get_label(self.tx_hash)
            if self.tx_hash in self.wallet.transactions.keys():
                conf, timestamp = self.wallet.get_confirmations(self.tx_hash)
                self.status_str = _("%d confirmations")%conf if conf else _('Pending')
                if timestamp:
                    self.date_str = datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
            else:
                self.can_broadcast = self.app.network is not None
                self.status_str = _('Signed')
        else:
            s, r = self.tx.signature_count()
            self.status_str = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)

        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(self.tx)
        self.is_mine = is_mine
        if is_relevant:
            if is_mine:
                if fee is not None:
                    self.amount_str = self.app.format_amount_and_units(-v+fee)
                    self.fee_str = self.app.format_amount_and_units(-fee)
                else:
                    self.amount_str = self.app.format_amount_and_units(-v)
                    self.fee_str = _("unknown")
            else:
                self.amount_str = self.app.format_amount_and_units(v)
                self.fee_str = ''
        else:
            self.amount_str = _("Transaction unrelated to your wallet")
            self.fee_str = ''
        self.can_sign = self.wallet.can_sign(self.tx)
        self.ids.output_list.update(self.tx.outputs())

    def do_sign(self):
        self.app.protected(_("Enter your PIN code in order to sign this transaction"), self._do_sign, ())

    def _do_sign(self, password):
        self.status_str = _('Signing') + '...'
        Clock.schedule_once(lambda dt: self.__do_sign(password), 0.1)

    def __do_sign(self, password):
        try:
            self.app.wallet.sign_transaction(self.tx, password)
        except InvalidPassword:
            self.app.show_error(_("Invalid PIN"))
        self.update()

    def do_broadcast(self):
        self.app.broadcast(self.tx)

    def show_qr(self):
        from electrum.bitcoin import base_encode
        text = str(self.tx).decode('hex')
        text = base_encode(text, base=43)
        self.app.qr_dialog(_("Raw Transaction"), text)
