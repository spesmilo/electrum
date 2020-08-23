import asyncio
import binascii
from typing import TYPE_CHECKING

from kivy.lang import Builder
from kivy.factory import Factory
from kivy.uix.popup import Popup
from kivy.clock import Clock

from electrum.util import bh2u
from electrum.lnutil import LOCAL, REMOTE, format_short_channel_id
from electrum.lnchannel import AbstractChannel, Channel
from electrum.gui.kivy.i18n import _
from .question import Question

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string(r'''
<LightningChannelItem@CardItem>
    details: {}
    active: False
    short_channel_id: '<channelId not set>'
    status: ''
    is_backup: False
    local_balance: ''
    remote_balance: ''
    _chan: None
    BoxLayout:
        size_hint: 0.7, None
        spacing: '8dp'
        height: '32dp'
        orientation: 'vertical'
        Widget
        CardLabel:
            color: (.5,.5,.5,1) if not root.active else (1,1,1,1)
            text: root.short_channel_id
            font_size: '15sp'
        Widget
        CardLabel:
            font_size: '13sp'
            shorten: True
            text: root.status
        Widget
    BoxLayout:
        size_hint: 0.3, None
        spacing: '8dp'
        height: '32dp'
        orientation: 'vertical'
        Widget
        CardLabel:
            text: root.local_balance if not root.is_backup else ''
            font_size: '13sp'
            halign: 'right'
        Widget
        CardLabel:
            text: root.remote_balance if not root.is_backup else ''
            font_size: '13sp'
            halign: 'right'
        Widget

<LightningChannelsDialog@Popup>:
    name: 'lightning_channels'
    title: _('Lightning channels.')
    has_lightning: False
    can_send: ''
    can_receive: ''
    id: popup
    BoxLayout:
        id: box
        orientation: 'vertical'
        spacing: '2dp'
        padding: '12dp'
        BoxLabel:
            text: _('Can send') + ':'
            value: root.can_send
        BoxLabel:
            text: _('Can receive') + ':'
            value: root.can_receive
        ScrollView:
            GridLayout:
                cols: 1
                id: lightning_channels_container
                size_hint: 1, None
                height: self.minimum_height
                spacing: '2dp'
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Widget:
                size_hint: 0.7, None
                height: '48dp'
            Button:
                size_hint: 0.3, None
                height: '48dp'
                text: _('New...')
                disabled: not root.has_lightning
                on_release: popup.app.popup_dialog('lightning_open_channel_dialog')


<ChannelDetailsPopup@Popup>:
    id: popuproot
    data: []
    is_closed: False
    is_redeemed: False
    node_id:''
    short_id:''
    initiator:''
    capacity:''
    funding_txid:''
    closing_txid:''
    state:''
    local_ctn:0
    remote_ctn:0
    local_csv:0
    remote_csv:0
    feerate:0
    can_send:''
    can_receive:''
    is_open:False
    BoxLayout:
        padding: '12dp', '12dp', '12dp', '12dp'
        spacing: '12dp'
        orientation: 'vertical'
        ScrollView:
            scroll_type: ['bars', 'content']
            scroll_wheel_distance: dp(114)
            BoxLayout:
                orientation: 'vertical'
                height: self.minimum_height
                size_hint_y: None
                spacing: '5dp'
                BoxLabel:
                    text: _('Channel ID')
                    value: root.short_id
                BoxLabel:
                    text: _('State')
                    value: root.state
                BoxLabel:
                    text: _('Initiator')
                    value: root.initiator
                BoxLabel:
                    text: _('Capacity')
                    value: root.capacity
                BoxLabel:
                    text: _('Can send')
                    value: root.can_send if root.is_open else 'n/a'
                BoxLabel:
                    text: _('Can receive')
                    value: root.can_receive if root.is_open else 'n/a'
                BoxLabel:
                    text: _('CSV delay')
                    value: 'Local: %d\nRemote: %d' % (root.local_csv, root.remote_csv)
                BoxLabel:
                    text: _('CTN')
                    value: 'Local: %d\nRemote: %d' % (root.local_ctn, root.remote_ctn)
                BoxLabel:
                    text: _('Fee rate')
                    value: '%d sat/kilobyte' % (root.feerate)
                Widget:
                    size_hint: 1, 0.1
                TopLabel:
                    text: _('Remote Node ID')
                TxHashLabel:
                    data: root.node_id
                    name: _('Remote Node ID')
                TopLabel:
                    text: _('Funding Transaction')
                TxHashLabel:
                    data: root.funding_txid
                    name: _('Funding Transaction')
                    touch_callback: lambda: app.show_transaction(root.funding_txid)
                TopLabel:
                    text: _('Closing Transaction')
                    opacity: int(bool(root.closing_txid))
                TxHashLabel:
                    opacity: int(bool(root.closing_txid))
                    data: root.closing_txid
                    name: _('Closing Transaction')
                    touch_callback: lambda: app.show_transaction(root.closing_txid)
                Widget:
                    size_hint: 1, 0.1
        Widget:
            size_hint: 1, 0.05
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Backup')
                on_release: root.export_backup()
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Close')
                on_release: root.close()
                disabled: root.is_closed
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Force-close')
                on_release: root.force_close()
                disabled: root.is_closed
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Delete')
                on_release: root.remove_channel()
                disabled: not root.is_redeemed

<ChannelBackupPopup@Popup>:
    id: popuproot
    data: []
    is_closed: False
    is_redeemed: False
    node_id:''
    short_id:''
    initiator:''
    capacity:''
    funding_txid:''
    closing_txid:''
    state:''
    is_open:False
    BoxLayout:
        padding: '12dp', '12dp', '12dp', '12dp'
        spacing: '12dp'
        orientation: 'vertical'
        ScrollView:
            scroll_type: ['bars', 'content']
            scroll_wheel_distance: dp(114)
            BoxLayout:
                orientation: 'vertical'
                height: self.minimum_height
                size_hint_y: None
                spacing: '5dp'
                BoxLabel:
                    text: _('Channel ID')
                    value: root.short_id
                BoxLabel:
                    text: _('State')
                    value: root.state
                BoxLabel:
                    text: _('Initiator')
                    value: root.initiator
                BoxLabel:
                    text: _('Capacity')
                    value: root.capacity
                Widget:
                    size_hint: 1, 0.1
                TopLabel:
                    text: _('Remote Node ID')
                TxHashLabel:
                    data: root.node_id
                    name: _('Remote Node ID')
                TopLabel:
                    text: _('Funding Transaction')
                TxHashLabel:
                    data: root.funding_txid
                    name: _('Funding Transaction')
                    touch_callback: lambda: app.show_transaction(root.funding_txid)
                TopLabel:
                    text: _('Closing Transaction')
                    opacity: int(bool(root.closing_txid))
                TxHashLabel:
                    opacity: int(bool(root.closing_txid))
                    data: root.closing_txid
                    name: _('Closing Transaction')
                    touch_callback: lambda: app.show_transaction(root.closing_txid)
                Widget:
                    size_hint: 1, 0.1
        Widget:
            size_hint: 1, 0.05
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Request force-close')
                on_release: root.request_force_close()
                disabled: root.is_closed
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Delete')
                on_release: root.remove_backup()
''')


class ChannelBackupPopup(Popup):

    def __init__(self, chan: AbstractChannel, app: 'ElectrumWindow', **kwargs):
        super(ChannelBackupPopup,self).__init__(**kwargs)
        self.chan = chan
        self.app = app
        self.short_id = format_short_channel_id(chan.short_channel_id)
        self.state = chan.get_state_for_GUI()
        self.title = _('Channel Backup')

    def request_force_close(self):
        msg = _('Request force close?')
        Question(msg, self._request_force_close).open()

    def _request_force_close(self, b):
        if not b:
            return
        loop = self.app.wallet.network.asyncio_loop
        coro = asyncio.run_coroutine_threadsafe(self.app.wallet.lnbackups.request_force_close(self.chan.channel_id), loop)
        try:
            coro.result(5)
            self.app.show_info(_('Channel closed'))
        except Exception as e:
            self.app.show_info(_('Could not close channel: ') + repr(e)) # repr because str(Exception()) == ''

    def remove_backup(self):
        msg = _('Delete backup?')
        Question(msg, self._remove_backup).open()

    def _remove_backup(self, b):
        if not b:
            return
        self.app.wallet.lnbackups.remove_channel_backup(self.chan.channel_id)
        self.dismiss()

class ChannelDetailsPopup(Popup):

    def __init__(self, chan: Channel, app: 'ElectrumWindow', **kwargs):
        super(ChannelDetailsPopup,self).__init__(**kwargs)
        self.is_closed = chan.is_closed()
        self.is_redeemed = chan.is_redeemed()
        self.app = app
        self.chan = chan
        self.title = _('Channel details')
        self.node_id = bh2u(chan.node_id)
        self.channel_id = bh2u(chan.channel_id)
        self.funding_txid = chan.funding_outpoint.txid
        self.short_id = format_short_channel_id(chan.short_channel_id)
        self.capacity = self.app.format_amount_and_units(chan.constraints.capacity)
        self.state = chan.get_state_for_GUI()
        self.local_ctn = chan.get_latest_ctn(LOCAL)
        self.remote_ctn = chan.get_latest_ctn(REMOTE)
        self.local_csv = chan.config[LOCAL].to_self_delay
        self.remote_csv = chan.config[REMOTE].to_self_delay
        self.initiator = 'Local' if chan.constraints.is_initiator else 'Remote'
        self.feerate = chan.get_latest_feerate(LOCAL)
        self.can_send = self.app.format_amount_and_units(chan.available_to_spend(LOCAL) // 1000)
        self.can_receive = self.app.format_amount_and_units(chan.available_to_spend(REMOTE) // 1000)
        self.is_open = chan.is_open()
        closed = chan.get_closing_height()
        if closed:
            self.closing_txid, closing_height, closing_timestamp = closed

    def close(self):
        Question(_('Close channel?'), self._close).open()

    def _close(self, b):
        if not b:
            return
        loop = self.app.wallet.network.asyncio_loop
        coro = asyncio.run_coroutine_threadsafe(self.app.wallet.lnworker.close_channel(self.chan.channel_id), loop)
        try:
            coro.result(5)
            self.app.show_info(_('Channel closed'))
        except Exception as e:
            self.app.show_info(_('Could not close channel: ') + repr(e)) # repr because str(Exception()) == ''

    def remove_channel(self):
        msg = _('Are you sure you want to delete this channel? This will purge associated transactions from your wallet history.')
        Question(msg, self._remove_channel).open()

    def _remove_channel(self, b):
        if not b:
            return
        self.app.wallet.lnworker.remove_channel(self.chan.channel_id)
        self.app._trigger_update_history()
        self.dismiss()

    def export_backup(self):
        text = self.app.wallet.lnworker.export_channel_backup(self.chan.channel_id)
        # TODO: some messages are duplicated between Kivy and Qt.
        help_text = ' '.join([
            _("Channel backups can be imported in another instance of the same wallet, by scanning this QR code."),
            _("Please note that channel backups cannot be used to restore your channels."),
            _("If you lose your wallet file, the only thing you can do with a backup is to request your channel to be closed, so that your funds will be sent on-chain."),
        ])
        self.app.qr_dialog(_("Channel Backup " + self.chan.short_id_for_GUI()), text, help_text=help_text)

    def force_close(self):
        Question(_('Force-close channel?'), self._force_close).open()

    def _force_close(self, b):
        if not b:
            return
        if self.chan.is_closed():
            self.app.show_error(_('Channel already closed'))
            return
        loop = self.app.wallet.network.asyncio_loop
        coro = asyncio.run_coroutine_threadsafe(self.app.wallet.lnworker.force_close_channel(self.chan.channel_id), loop)
        try:
            coro.result(1)
            self.app.show_info(_('Channel closed, you may need to wait at least {} blocks, because of CSV delays'.format(self.chan.config[REMOTE].to_self_delay)))
        except Exception as e:
            self.app.show_info(_('Could not force close channel: ') + repr(e)) # repr because str(Exception()) == ''


class LightningChannelsDialog(Factory.Popup):

    def __init__(self, app: 'ElectrumWindow'):
        super(LightningChannelsDialog, self).__init__()
        self.clocks = []
        self.app = app
        self.has_lightning = app.wallet.has_lightning()
        self.update()

    def show_item(self, obj):
        chan = obj._chan
        if chan.is_backup():
            p = ChannelBackupPopup(chan, self.app)
        else:
            p = ChannelDetailsPopup(chan, self.app)
        p.open()

    def format_fields(self, chan):
        labels = {}
        for subject in (REMOTE, LOCAL):
            bal_minus_htlcs = chan.balance_minus_outgoing_htlcs(subject)//1000
            label = self.app.format_amount(bal_minus_htlcs)
            other = subject.inverted()
            bal_other = chan.balance(other)//1000
            bal_minus_htlcs_other = chan.balance_minus_outgoing_htlcs(other)//1000
            if bal_other != bal_minus_htlcs_other:
                label += ' (+' + self.app.format_amount(bal_other - bal_minus_htlcs_other) + ')'
            labels[subject] = label
        closed = chan.is_closed()
        return [
            'n/a' if closed else labels[LOCAL],
            'n/a' if closed else labels[REMOTE],
        ]

    def update_item(self, item):
        chan = item._chan
        item.status = chan.get_state_for_GUI()
        item.short_channel_id = chan.short_id_for_GUI()
        l, r = self.format_fields(chan)
        item.local_balance = _('Local') + ':' + l
        item.remote_balance = _('Remote') + ': ' + r
        self.update_can_send()

    def update(self):
        channel_cards = self.ids.lightning_channels_container
        channel_cards.clear_widgets()
        if not self.app.wallet:
            return
        lnworker = self.app.wallet.lnworker
        channels = list(lnworker.channels.values()) if lnworker else []
        lnbackups = self.app.wallet.lnbackups
        backups = list(lnbackups.channel_backups.values())
        for i in channels + backups:
            item = Factory.LightningChannelItem()
            item.screen = self
            item.active = not i.is_closed()
            item.is_backup = i.is_backup()
            item._chan = i
            self.update_item(item)
            channel_cards.add_widget(item)
        self.update_can_send()

    def update_can_send(self):
        lnworker = self.app.wallet.lnworker
        if not lnworker:
            self.can_send = 'n/a'
            self.can_receive = 'n/a'
            return
        self.can_send = self.app.format_amount_and_units(lnworker.num_sats_can_send())
        self.can_receive = self.app.format_amount_and_units(lnworker.num_sats_can_receive())
