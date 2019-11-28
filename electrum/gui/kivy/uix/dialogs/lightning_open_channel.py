from typing import TYPE_CHECKING

from kivy.lang import Builder
from kivy.factory import Factory

from electrum.gui.kivy.i18n import _
from electrum.lnaddr import lndecode
from electrum.util import bh2u
from electrum.bitcoin import COIN
import electrum.simple_config as config

from .label_dialog import LabelDialog

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string('''
<LightningOpenChannelDialog@Popup>
    id: s
    name: 'lightning_open_channel'
    title: _('Open Lightning Channel')
    pubkey: ''
    amount: ''
    ipport: ''
    BoxLayout
        spacing: '12dp'
        padding: '12dp'
        orientation: 'vertical'
        SendReceiveBlueBottom:
            id: blue_bottom
            size_hint: 1, None
            height: self.minimum_height
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/globe'
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: s.pubkey if s.pubkey else _('Node ID')
                    shorten: True
            #CardSeparator:
            #    color: blue_bottom.foreground_color
            #BoxLayout:
            #    size_hint: 1, None
            #    height: blue_bottom.item_height
            #    Image:
            #        source: 'atlas://electrum/gui/kivy/theming/light/network'
            #        size_hint: None, None
            #        size: '22dp', '22dp'
            #        pos_hint: {'center_y': .5}
            #    BlueButton:
            #        text: s.ipport if s.ipport else _('host:port')
            #        on_release: s.ipport_dialog()
            CardSeparator:
                color: blue_bottom.foreground_color
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/calculator'
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: s.amount if s.amount else _('Amount')
                    on_release: app.amount_dialog(s, True)
        BoxLayout:
            size_hint: 1, None
            IconButton:
                icon: 'atlas://electrum/gui/kivy/theming/light/copy'
                size_hint: 0.5, None
                height: '48dp'
                on_release: s.do_paste()
            IconButton:
                icon: 'atlas://electrum/gui/kivy/theming/light/camera'
                size_hint: 0.5, None
                height: '48dp'
                on_release: app.scan_qr(on_complete=s.on_qr)
            Button:
                text: _('Suggest')
                size_hint: 1, None
                height: '48dp'
                on_release: s.choose_node()
            Button:
                text: _('Open')
                size_hint: 1, None
                height: '48dp'
                on_release: s.open_channel()
        Widget:
            size_hint: 1, 1
''')

class LightningOpenChannelDialog(Factory.Popup):
    def ipport_dialog(self):
        def callback(text):
            self.ipport = text
        d = LabelDialog(_('IP/port in format:\n[host]:[port]'), self.ipport, callback)
        d.open()

    def choose_node(self):
        suggested = self.app.wallet.lnworker.suggest_peer()
        if suggested:
            self.pubkey = suggested.hex()

    def __init__(self, app, lnaddr=None, msg=None):
        super(LightningOpenChannelDialog, self).__init__()
        self.app = app  # type: ElectrumWindow
        self.lnaddr = lnaddr
        self.msg = msg

    def open(self, *args, **kwargs):
        super(LightningOpenChannelDialog, self).open(*args, **kwargs)
        if self.lnaddr:
            fee = self.app.electrum_config.fee_per_kb()
            if not fee:
                fee = config.FEERATE_FALLBACK_STATIC_FEE
            self.amount = self.app.format_amount_and_units(self.lnaddr.amount * COIN + fee * 2)
            self.pubkey = bh2u(self.lnaddr.pubkey.serialize())
        if self.msg:
            self.app.show_info(self.msg)

    def do_paste(self):
        contents = self.app._clipboard.paste()
        if not contents:
            self.app.show_info(_("Clipboard is empty"))
            return
        self.pubkey = contents

    def on_qr(self, conn_str):
        self.pubkey = conn_str

    # FIXME "max" button in amount_dialog should enforce LN_MAX_FUNDING_SAT
    def open_channel(self):
        if not self.pubkey or not self.amount:
            self.app.show_info(_('All fields must be filled out'))
            return
        conn_str = self.pubkey
        if self.ipport:
            conn_str += '@' + self.ipport.strip()
        amount = self.app.get_amount(self.amount)
        self.app.protected('Enter PIN to create a new channel', self.do_open_channel, (conn_str, amount))
        self.dismiss()

    def do_open_channel(self, conn_str, amount, password):
        coins = self.app.wallet.get_spendable_coins(None, nonlocal_only=True)
        funding_tx = self.app.wallet.lnworker.mktx_for_open_channel(coins=coins, funding_sat=amount)
        try:
            chan, funding_tx = self.app.wallet.lnworker.open_channel(connect_str=conn_str,
                                                                     funding_tx=funding_tx,
                                                                     funding_sat=amount,
                                                                     push_amt_sat=0,
                                                                     password=password)
        except Exception as e:
            self.app.show_error(_('Problem opening channel: ') + '\n' + repr(e))
            return
        n = chan.constraints.funding_txn_minimum_depth
        message = '\n'.join([
            _('Channel established.'),
            _('Remote peer ID') + ':' + chan.node_id.hex(),
            _('This channel will be usable after {} confirmations').format(n)
        ])
        if not funding_tx.is_complete():
            message += '\n\n' + _('Please sign and broadcast the funding transaction')
        self.app.show_info(message)
        if not funding_tx.is_complete():
            self.app.tx_dialog(funding_tx)
