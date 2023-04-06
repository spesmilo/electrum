from typing import TYPE_CHECKING

from kivy.lang import Builder
from kivy.factory import Factory

from electrum.gui import messages
from electrum.gui.kivy.i18n import _
from electrum.lnaddr import lndecode
from electrum.bitcoin import COIN
import electrum.simple_config as config
from electrum.logging import Logger
from electrum.lnutil import ln_dummy_address, extract_nodeid, ConnStringFormatError

from .label_dialog import LabelDialog
from .confirm_tx_dialog import ConfirmTxDialog
from .qr_dialog import QRDialog
from .question import Question

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string('''
#:import KIVY_GUI_PATH electrum.gui.kivy.KIVY_GUI_PATH

<LightningOpenChannelDialog@Popup>
    use_gossip: False
    id: s
    name: 'lightning_open_channel'
    title: _('Open Lightning Channel')
    pubkey: ''
    amount: ''
    is_max: False
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
                    source: f'atlas://{KIVY_GUI_PATH}/theming/atlas/light/globe'
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: s.pubkey if s.pubkey else (_('Node ID') if root.use_gossip else _('Trampoline node'))
                    shorten: True
                    on_release: s.suggest_node()
            CardSeparator:
                color: blue_bottom.foreground_color
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                Image:
                    source: f'atlas://{KIVY_GUI_PATH}/theming/atlas/light/calculator'
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: s.amount if s.amount else _('Amount')
                    on_release: app.amount_dialog(s, True)
        TopLabel:
            text: _('Paste or scan a node ID, a connection string or a lightning invoice.') if root.use_gossip else _('Choose a trampoline node and the amount')
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            IconButton:
                icon: f'atlas://{KIVY_GUI_PATH}/theming/atlas/light/copy'
                size_hint: 0.5, None
                height: '48dp'
                on_release: s.do_paste()
                disabled: not app.use_gossip
            IconButton:
                icon: f'atlas://{KIVY_GUI_PATH}/theming/atlas/light/camera'
                size_hint: 0.5, None
                height: '48dp'
                on_release: app.scan_qr(on_complete=s.on_qr)
                disabled: not app.use_gossip
            Button:
                text: _('Suggest')
                size_hint: 1, None
                height: '48dp'
                on_release: s.suggest_node()
            Button:
                text: _('Clear')
                size_hint: 1, None
                height: '48dp'
                on_release: s.do_clear()
        Widget:
            size_hint: 1, 1
        BoxLayout:
            size_hint: 1, None
            Widget:
                size_hint: 2, None
            Button:
                text: _('Open')
                size_hint: 1, None
                height: '48dp'
                on_release: s.open_channel()
                disabled: not root.pubkey or not root.amount
''')

class LightningOpenChannelDialog(Factory.Popup, Logger):
    def ipport_dialog(self):
        def callback(text):
            self.ipport = text
        d = LabelDialog(_('IP/port in format:\n[host]:[port]'), self.ipport, callback)
        d.open()

    def suggest_node(self):
        if self.use_gossip:
            suggested = self.app.wallet.lnworker.suggest_peer()
            if suggested:
                self.pubkey = suggested.hex()
            else:
                _, _, percent = self.app.wallet.network.lngossip.get_sync_progress_estimate()
                if percent is None:
                    percent = "??"
                self.pubkey = f"Please wait, graph is updating ({percent}% / 30% done)."
        else:
            self.trampoline_index += 1
            self.trampoline_index = self.trampoline_index % len(self.trampoline_names)
            self.pubkey = self.trampoline_names[self.trampoline_index]

    def __init__(self, app, lnaddr=None, msg=None):
        Factory.Popup.__init__(self)
        Logger.__init__(self)
        self.app = app  # type: ElectrumWindow
        self.lnaddr = lnaddr
        self.msg = msg
        self.use_gossip = bool(self.app.network.channel_db)
        if not self.use_gossip:
            from electrum.lnworker import hardcoded_trampoline_nodes
            self.trampolines = hardcoded_trampoline_nodes()
            self.trampoline_names = list(self.trampolines.keys())
            self.trampoline_index = 0
            self.pubkey = ''

    def open(self, *args, **kwargs):
        super(LightningOpenChannelDialog, self).open(*args, **kwargs)
        if self.lnaddr:
            fee = self.app.electrum_config.fee_per_kb()
            if not fee:
                fee = config.FEERATE_FALLBACK_STATIC_FEE
            self.amount = self.app.format_amount_and_units(self.lnaddr.amount * COIN + fee * 2)  # FIXME magic number?!
            self.pubkey = self.lnaddr.pubkey.serialize().hex()
        if self.msg:
            self.app.show_info(self.msg)

    def do_clear(self):
        self.pubkey = ''
        self.amount = ''

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
        if self.use_gossip:
            conn_str = self.pubkey
            if self.ipport:
                conn_str += '@' + self.ipport.strip()
        else:
            conn_str = str(self.trampolines[self.pubkey])
        amount = '!' if self.is_max else self.app.get_amount(self.amount)
        self.dismiss()
        lnworker = self.app.wallet.lnworker
        try:
            node_id, rest = extract_nodeid(conn_str)
        except ConnStringFormatError as e:
            self.app.show_error(_('Problem opening channel: ') + '\n' + str(e))
            return
        if lnworker.has_conflicting_backup_with(node_id):
            msg = messages.MGS_CONFLICTING_BACKUP_INSTANCE
            d = Question(msg, lambda x: self._open_channel(x, conn_str, amount))
            d.open()
        else:
            self._open_channel(True, conn_str, amount)

    def _open_channel(self, x, conn_str, amount):
        if not x:
            return
        lnworker = self.app.wallet.lnworker
        coins = self.app.wallet.get_spendable_coins(None, nonlocal_only=True)
        node_id, rest = extract_nodeid(conn_str)
        make_tx = lambda: lnworker.mktx_for_open_channel(
            coins=coins,
            funding_sat=amount,
            node_id=node_id,
            fee_est=None)
        on_pay = lambda tx: self.app.protected('Create a new channel?', self.do_open_channel, (tx, conn_str))
        d = ConfirmTxDialog(
            self.app,
            amount = amount,
            make_tx=make_tx,
            on_pay=on_pay,
        )
        d.open()

    def do_open_channel(self, funding_tx, conn_str, password):
        # read funding_sat from tx; converts '!' to int value
        funding_sat = funding_tx.output_value_for_address(ln_dummy_address())
        lnworker = self.app.wallet.lnworker
        try:
            chan, funding_tx = lnworker.open_channel(
                connect_str=conn_str,
                funding_tx=funding_tx,
                funding_sat=funding_sat,
                push_amt_sat=0,
                password=password)
        except Exception as e:
            self.app.logger.exception("Problem opening channel")
            self.app.show_error(_('Problem opening channel: ') + '\n' + repr(e))
            return
        # TODO: it would be nice to show this before broadcasting
        if chan.has_onchain_backup():
            self.maybe_show_funding_tx(chan, funding_tx)
        else:
            title = _('Save backup')
            help_text = _(messages.MSG_CREATED_NON_RECOVERABLE_CHANNEL)
            data = lnworker.export_channel_backup(chan.channel_id)
            popup = QRDialog(
                title, data,
                show_text=False,
                text_for_clipboard=data,
                help_text=help_text,
                close_button_text=_('OK'),
                on_close=lambda: self.maybe_show_funding_tx(chan, funding_tx))
            popup.open()

    def maybe_show_funding_tx(self, chan, funding_tx):
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
