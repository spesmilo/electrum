from kivy.lang import Builder
from kivy.factory import Factory
from electrum.gui.kivy.i18n import _
from electrum.lnaddr import lndecode
from electrum.gui.kivy.uix.dialogs.choice_dialog import ChoiceDialog
from electrum.util import bh2u
from electrum.bitcoin import COIN
import electrum.simple_config as config
from .label_dialog import LabelDialog

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
                    text: s.pubkey if s.pubkey else _('Node ID, [pubkey]@[host]:[port]')
                    shorten: True
                    on_release: s.choose_node()
                IconButton:
                    on_release: app.scan_qr(on_complete=s.on_pubkey)
                    icon: 'atlas://electrum/gui/kivy/theming/light/camera'
                    color: blue_bottom.foreground_color
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                    size_hint: None, None
            CardSeparator:
                color: blue_bottom.foreground_color
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/network'
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: s.ipport if s.ipport else _('Auto-detect IP/port')
                    on_release: s.ipport_dialog()
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
                    text: s.amount if s.amount else _('Channel capacity amount')
                    on_release: app.amount_dialog(s, True)
        Button:
            size_hint: 1, None
            height: blue_bottom.item_height
            text: _('Paste')
            on_release: s.do_paste()
        Button:
            size_hint: 1, None
            height: blue_bottom.item_height
            text: _('Open Channel')
            on_release: s.do_open_channel()
''')

class LightningOpenChannelDialog(Factory.Popup):
    def ipport_dialog(self):
        def callback(text):
            self.ipport = text
        d = LabelDialog(_('IP/port in format:\n[host]:[port]'), self.ipport, callback)
        d.open()

    def on_pubkey(self, data):
        self.pubkey = data.replace('\n', '') # strip newlines if we choose from ChoiseDialog

    def choose_node(self):
        lines = []
        suggested = self.app.wallet.lnworker.suggest_peer()
        if suggested:
            assert len(suggested) == 33
            for i in range(0, 34, 11):
                lines += [bh2u(suggested[i:i+11])]
        servers = ['\n'.join(lines)]
        ChoiceDialog(_('Choose node to connect to'), sorted(servers), self.pubkey, self.on_pubkey).open()

    def __init__(self, app, lnaddr=None, msg=None):
        super(LightningOpenChannelDialog, self).__init__()
        self.app = app
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

    def do_open_channel(self):
        if not self.pubkey or not self.amount:
            self.app.show_info(_('All fields must be filled out'))
            return
        conn_str = self.pubkey
        if self.ipport:
            conn_str += '@' + self.ipport.strip()
        try:
            node_id_hex = self.app.wallet.lnworker.open_channel(conn_str, self.app.get_amount(self.amount), 0)
        except Exception as e:
            self.app.show_error(_('Problem opening channel: ') + '\n' + repr(e))
            return
        self.app.show_info(_('Please wait for confirmation, channel is opening with node ') + node_id_hex[:16])
        self.dismiss()
