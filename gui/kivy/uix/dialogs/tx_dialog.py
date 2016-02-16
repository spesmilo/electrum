from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.clock import Clock

from electrum_ltc_gui.kivy.i18n import _
from datetime import datetime

Builder.load_string('''
<TxDialog@Popup>
    id: popup
    title: _('Transaction')
    is_mine: True
    can_sign: False
    can_broadcast: False
    fee_str: ''
    date_str: ''
    amount_str: ''
    txid_str: ''
    status_str: ''
    description: ''
    BoxLayout:
        orientation: 'vertical'
        GridLayout:
            cols: 2
            spacing: '10dp'
            TopLabel:
                text: _('Status')
            TopLabel:
                text: root.status_str
            TopLabel:
                text: _('Description') if root.description else ''
            TopLabel:
                text: root.description
            TopLabel:
                text: _('Date') if root.date_str else ''
            TopLabel:
                text: root.date_str
            TopLabel:
                text: _('Amount sent') if root.is_mine else _('Amount received')
            TopLabel:
                text: root.amount_str
            TopLabel:
                text: _('Transaction fee') if root.fee_str else ''
            TopLabel:
                text: root.fee_str

        TopLabel:
            text: root.txid_str

        Widget:
            size_hint: 1, 0.2

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
        self.update()

    def update(self):
        self.can_broadcast = False
        if self.tx.is_complete():
            tx_hash = self.tx.hash()
            self.description = self.wallet.get_label(tx_hash)
            self.txid_str = _('Transaction ID') + ' :\n' + ' '.join(map(''.join, zip(*[iter(tx_hash)]*4)))
            if tx_hash in self.wallet.transactions.keys():
                conf, timestamp = self.wallet.get_confirmations(tx_hash)
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

    def do_sign(self):
        self.app.protected(_("Enter your PIN code in order to sign this transaction"), self._do_sign, ())

    def _do_sign(self, password):
        self.status_str = _('Signing') + '...'
        Clock.schedule_once(lambda dt: self.__do_sign(password), 0.1)

    def __do_sign(self, password):
        self.app.wallet.sign_transaction(self.tx, password)
        self.update()

    def do_broadcast(self):
        self.app.show_info(_('Broadcasting'))
        ok, txid = self.app.wallet.sendtx(self.tx)
        self.app.show_info(txid)

    def show_qr(self):
        from electrum_ltc.bitcoin import base_encode
        text = str(self.tx).decode('hex')
        text = base_encode(text, base=43)
        self.app.qr_dialog(_("Raw Transaction"), text)
