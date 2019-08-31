import asyncio
import binascii
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.uix.popup import Popup
from kivy.clock import Clock
from electrum.util import bh2u
from electrum.lnutil import LOCAL, REMOTE, format_short_channel_id
from electrum.gui.kivy.i18n import _
from .question import Question

Builder.load_string(r'''
<LightningChannelItem@CardItem>
    details: {}
    active: False
    short_channel_id: '<channelId not set>'
    status: ''
    local_balance: ''
    remote_balance: ''
    _chan: None
    BoxLayout:
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
        spacing: '8dp'
        height: '32dp'
        orientation: 'vertical'
        Widget
        CardLabel:
            text: root.local_balance
            font_size: '13sp'
            halign: 'right'
        Widget
        CardLabel:
            text: root.remote_balance
            font_size: '13sp'
            halign: 'right'
        Widget

<LightningChannelsDialog@Popup>:
    name: 'lightning_channels'
    title: _('Lightning channels.')
    id: popup
    BoxLayout:
        id: box
        orientation: 'vertical'
        spacing: '1dp'
        ScrollView:
            GridLayout:
                cols: 1
                id: lightning_channels_container
                size_hint: 1, None
                height: self.minimum_height
                spacing: '2dp'
                padding: '12dp'
        Button:
            size_hint: 1, None
            height: '48dp'
            text: _('New channel...')
            on_press: popup.app.popup_dialog('lightning_open_channel_dialog')

<ChannelDetailsList@RecycleView>:
    scroll_type: ['bars', 'content']
    scroll_wheel_distance: dp(114)
    bar_width: dp(10)
    viewclass: 'BoxLabel'
    RecycleBoxLayout:
        default_size: None, dp(56)
        default_size_hint: 1, None
        size_hint_y: None
        height: self.minimum_height
        orientation: 'vertical'
        spacing: dp(2)

<ChannelDetailsPopup@Popup>:
    id: popuproot
    data: []
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            ChannelDetailsList:
                data: popuproot.data
        Widget:
            size_hint: 1, 0.1
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Close channel')
                on_release: root.close()
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Force-close')
                on_release: root.force_close()
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Dismiss')
                on_release: root.dismiss()
''')


class ChannelDetailsPopup(Popup):

    def __init__(self, chan, app, **kwargs):
        super(ChannelDetailsPopup,self).__init__(**kwargs)
        self.app = app
        self.chan = chan
        self.title = _('Channel details')
        self.data = [{'text': key, 'value': str(value)} for key, value in self.details().items()]

    def details(self):
        chan = self.chan
        return {
            _('Short Chan ID'): format_short_channel_id(chan.short_channel_id),
            _('Initiator'): 'Local' if chan.constraints.is_initiator else 'Remote',
            _('State'): chan.get_state(),
            _('Local CTN'): chan.get_latest_ctn(LOCAL),
            _('Remote CTN'): chan.get_latest_ctn(REMOTE),
            _('Capacity'): self.app.format_amount_and_units(chan.constraints.capacity),
            _('Can send'): self.app.format_amount_and_units(chan.available_to_spend(LOCAL) // 1000),
            _('Current feerate'): str(chan.get_latest_feerate(LOCAL)),
            _('Node ID'): bh2u(chan.node_id),
            _('Channel ID'): bh2u(chan.channel_id),
            _('Funding TXID'): chan.funding_outpoint.txid,
        }

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

    def force_close(self):
        Question(_('Force-close channel?'), self._force_close).open()

    def _force_close(self, b):
        if not b:
            return
        if self.chan.get_state() == 'CLOSED':
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

    def __init__(self, app):
        super(LightningChannelsDialog, self).__init__()
        self.clocks = []
        self.app = app
        self.update()

    def show_item(self, obj):
        p = ChannelDetailsPopup(obj._chan, self.app)
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
        return [
            labels[LOCAL],
            labels[REMOTE],
        ]

    def update_item(self, item):
        chan = item._chan
        item.status = chan.get_state()
        item.short_channel_id = format_short_channel_id(chan.short_channel_id)
        l, r = self.format_fields(chan)
        item.local_balance = _('Local') + ':' + l
        item.remote_balance = _('Remote') + ': ' + r

    def update(self):
        channel_cards = self.ids.lightning_channels_container
        channel_cards.clear_widgets()
        if not self.app.wallet:
            return
        lnworker = self.app.wallet.lnworker
        for i in lnworker.channels.values():
            item = Factory.LightningChannelItem()
            item.screen = self
            item.active = i.node_id in lnworker.peers
            item._chan = i
            self.update_item(item)
            channel_cards.add_widget(item)
