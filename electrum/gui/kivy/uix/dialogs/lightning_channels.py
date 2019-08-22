import asyncio
import binascii
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.uix.popup import Popup
from kivy.clock import Clock
from electrum.gui.kivy.uix.context_menu import ContextMenu
from electrum.util import bh2u
from electrum.lnutil import LOCAL, REMOTE, format_short_channel_id
from electrum.gui.kivy.i18n import _

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

<ChannelDetailsItem@BoxLayout>:
    canvas.before:
        Color:
            rgba: 0.5, 0.5, 0.5, 1
        Rectangle:
            size: self.size
            pos: self.pos
    value: ''
    Label:
        text: root.value
        text_size: self.size # this makes the text not overflow, but wrap

<ChannelDetailsRow@BoxLayout>:
    keyName: ''
    value: ''
    ChannelDetailsItem:
        value: root.keyName
        size_hint_x: 0.5 # this makes the column narrower

    # see https://blog.kivy.org/2014/07/wrapping-text-in-kivys-label/
    ScrollView:
        Label:
            text: root.value
            size_hint_y: None
            text_size: self.width, None
            height: self.texture_size[1]

<ChannelDetailsList@RecycleView>:
    scroll_type: ['bars', 'content']
    scroll_wheel_distance: dp(114)
    bar_width: dp(10)
    viewclass: 'ChannelDetailsRow'
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
    ChannelDetailsList:
        data: popuproot.data
''')

class ChannelDetailsPopup(Popup):
    def __init__(self, data, **kwargs):
        super(ChannelDetailsPopup,self).__init__(**kwargs)
        self.data = data

class LightningChannelsDialog(Factory.Popup):
    def __init__(self, app):
        super(LightningChannelsDialog, self).__init__()
        self.clocks = []
        self.app = app
        self.context_menu = None
        self.app.wallet.network.register_callback(self.on_channels, ['channels'])
        self.app.wallet.network.register_callback(self.on_channel, ['channel'])
        self.update()

    def show_channel_details(self, obj):
        p = Factory.ChannelDetailsPopup()
        p.title = _('Details for channel ') + format_short_channel_id(obj.chan.short_channel_id)
        p.data = [{'keyName': key, 'value': str(obj.details[key])} for key in obj.details.keys()]
        p.open()

    def close_channel(self, obj):
        loop = self.app.wallet.network.asyncio_loop
        coro = asyncio.run_coroutine_threadsafe(self.app.wallet.lnworker.close_channel(obj._chan.channel_id), loop)
        try:
            coro.result(5)
            self.app.show_info(_('Channel closed'))
        except Exception as e:
            self.app.show_info(_('Could not close channel: ') + repr(e)) # repr because str(Exception()) == ''

    def force_close_channel(self, obj):
        if obj._chan.get_state() == 'CLOSED':
            self.app.show_error(_('Channel already closed'))
            return
        loop = self.app.wallet.network.asyncio_loop
        coro = asyncio.run_coroutine_threadsafe(self.app.wallet.lnworker.force_close_channel(obj._chan.channel_id), loop)
        try:
            coro.result(1)
            self.app.show_info(_('Channel closed, you may need to wait at least {} blocks, because of CSV delays'.format(obj._chan.config[REMOTE].to_self_delay)))
        except Exception as e:
            self.app.show_info(_('Could not force close channel: ') + repr(e)) # repr because str(Exception()) == ''

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, [
            (_("Force close"), self.force_close_channel),
            (_("Co-op close"), self.close_channel),
            (_("Details"), self.show_channel_details)])
        self.ids.box.add_widget(self.context_menu)

    def hide_menu(self):
        if self.context_menu is not None:
            self.ids.box.remove_widget(self.context_menu)
            self.context_menu = None

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

    def on_channel(self, evt, chan):
        Clock.schedule_once(lambda dt: self.update())

    def on_channels(self, evt):
        Clock.schedule_once(lambda dt: self.update())

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
            item.details = self.channel_details(i)
            item._chan = i
            self.update_item(item)
            channel_cards.add_widget(item)

    def channel_details(self, chan):
        return {_('Node ID'): bh2u(chan.node_id),
                _('Channel ID'): bh2u(chan.channel_id),
                _('Capacity'): self.app.format_amount_and_units(chan.constraints.capacity),
                _('Funding TXID'): chan.funding_outpoint.txid,
                _('Short Chan ID'): bh2u(chan.short_channel_id) if chan.short_channel_id else _('Not available'),
                _('Available to spend'): self.app.format_amount_and_units(chan.available_to_spend(LOCAL) // 1000),
                _('State'): chan.get_state(),
                _('Initiator'): 'Opened/funded by us' if chan.constraints.is_initiator else 'Opened/funded by remote party',
                _('Current feerate'): chan.get_latest_feerate(LOCAL)}
