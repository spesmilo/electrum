from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.clock import Clock

from electrum_gui.kivy.i18n import _
from datetime import datetime

Builder.load_string('''
<TxDialog@Popup>
    id: popup
    title: _('Transaction')
    can_sign: False
    can_broadcast: False
    fee_str: ''
    amount_str: ''
    txid_str: ''
    status_str: ''
    time_str: ''
    AnchorLayout:
        anchor_x: 'center'
        BoxLayout:
            orientation: 'vertical'
            Label:
                id: txid_label
                text: root.txid_str
                text_size: self.width, None
                size: self.texture_size
            Label:
                id: status_label
                text: root.status_str
                text_size: self.width, None
                size_hint: 1, 0.3
            Label:
                id: date_label
                text: root.time_str
                text_size: self.width, None
                size_hint: 1, 0.3
            Label:
                id: amount_label
                text: root.amount_str
                text_size: self.width, None
                size_hint: 1, 0.3
            Label:
                id: fee_label
                text: root.fee_str
                text_size: self.width, None
                size_hint: 1, 0.3
            Widget:
                size_hint: 1, 1
            BoxLayout:
                size_hint: 1, None
                height: '48dp'
                Button:
                    size_hint: 0.5, None
                    height: '48dp'
                    text: _('Sign') if root.can_sign else _('Broadcast') if root.can_broadcast else ''
                    #opacity: 1 if root.can_sign or root.can_broadcast else 0
                    disabled: not( root.can_sign or root.can_broadcast )
                    on_release:
                        if root.can_sign: root.do_sign()
                        if root.can_broadcast: root.do_broadcast()
                Button:
                    size_hint: 0.5, None
                    height: '48dp'
                    text: _('QR')
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
            self.txid_str = _('Transaction ID') + ' :\n' + ' '.join(map(''.join, zip(*[iter(tx_hash)]*4)))
            if tx_hash in self.wallet.transactions.keys():
                conf, timestamp = self.wallet.get_confirmations(tx_hash)
                self.status_str = _("%d confirmations")%conf
                if timestamp:
                    self.time_str = datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
                else:
                    self.time_str = _('Pending')
            else:
                self.can_broadcast = self.app.network is not None
        else:
            s, r = self.tx.signature_count()
            self.txid_str = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)

        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(self.tx)
        if is_relevant:
            if is_mine:
                if fee is not None:
                    self.amount_str = _("Amount sent:")+' %s'% self.app.format_amount_and_units(-v+fee)
                    self.fee_str = _("Transaction fee")+': %s'% self.app.format_amount_and_units(-fee)
                else:
                    self.amount_str = _("Amount sent:")+' %s'% self.app.format_amount_and_units(-v)
                    self.fee_str = _("Transaction fee")+': '+ _("unknown")
            else:
                self.amount_str = _("Amount received:")+' %s'% self.app.format_amount_and_units(v)
                self.fee_str = ''
        else:
            self.amount_str = _("Transaction unrelated to your wallet")
            self.fee_str = ''
        self.can_sign = self.wallet.can_sign(self.tx)

    def do_sign(self):
        self.app.protected(_("Enter your PIN code in order to sign this transaction"), self._do_sign, ())

    def _do_sign(self, password):
        self.txid_str = _('Signing') + '...'
        Clock.schedule_once(lambda dt: self.__do_sign(password), 0.1)

    def __do_sign(self, password):
        self.app.wallet.sign_transaction(self.tx, password)
        self.update()

    def do_broadcast(self):
        self.app.show_info(_('Broadcasting'))
        ok, txid = self.app.wallet.sendtx(self.tx)
        self.app.show_info(txid)

    def show_qr(self):
        from electrum.bitcoin import base_encode
        text = str(self.tx).decode('hex')
        text = base_encode(text, base=43)
        self.app.qr_dialog(_("Raw Transaction"), text)
