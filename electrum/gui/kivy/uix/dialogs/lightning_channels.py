import asyncio
import binascii
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.uix.popup import Popup
from kivy.clock import Clock
from electrum.gui.kivy.uix.context_menu import ContextMenu
from electrum.util import bh2u
from electrum.lnutil import LOCAL, REMOTE

Builder.load_string('''
<LightningChannelItem@CardItem>
    details: {}
    active: False
    channelId: '<channelId not set>'
    Label:
        text: root.channelId

<LightningChannelsDialog@Popup>:
    name: 'lightning_channels'
    title: 'Lightning channels. Tap to select.'
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
        super(ChanenlDetailsPopup,self).__init__(**kwargs)
        self.data = data

class LightningChannelsDialog(Factory.Popup):
    def __init__(self, app):
        super(LightningChannelsDialog, self).__init__()
        self.clocks = []
        self.app = app
        self.context_menu = None
        self.app.wallet.network.register_callback(self.channels_update, ['channels'])
        self.channels_update('bogus evt')

    def show_channel_details(self, obj):
        p = Factory.ChannelDetailsPopup()
        p.title = 'Lightning channels details for ' + self.presentable_chan_id(obj._chan)
        p.data = [{'keyName': key, 'value': str(obj.details[key])} for key in obj.details.keys()]
        p.open()

    def close_channel(self, obj):
        loop = self.app.wallet.network.asyncio_loop
        coro = asyncio.run_coroutine_threadsafe(self.app.wallet.lnworker.close_channel(obj._chan.channel_id), loop)
        try:
            coro.result(5)
            self.app.show_info('Channel closed')
        except Exception as e:
            self.app.show_info('Could not close channel: ' + repr(e)) # repr because str(Exception()) == ''

    def force_close_channel(self, obj):
        loop = self.app.wallet.network.asyncio_loop
        coro = asyncio.run_coroutine_threadsafe(self.app.wallet.lnworker.force_close_channel(obj._chan.channel_id), loop)
        try:
            coro.result(1)
            self.app.show_info('Channel closed, you may need to wait at least ' + str(obj._chan.config[REMOTE].to_self_delay) + ' blocks, because of CSV delays')
        except Exception as e:
            self.app.show_info('Could not force close channel: ' + repr(e)) # repr because str(Exception()) == ''

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, [
            ("Force close", self.force_close_channel),
            ("Co-op close", self.close_channel),
            ("Details", self.show_channel_details)])
        self.ids.box.add_widget(self.context_menu)

    def hide_menu(self):
        if self.context_menu is not None:
            self.ids.box.remove_widget(self.context_menu)
            self.context_menu = None

    def presentable_chan_id(self, i):
        return bh2u(i.short_channel_id) if i.short_channel_id else bh2u(i.channel_id)[:16]

    def channels_update(self, evt):
        channel_cards = self.ids.lightning_channels_container
        channel_cards.clear_widgets()
        lnworker = self.app.wallet.lnworker
        for i in lnworker.channels.values():
            item = Factory.LightningChannelItem()
            item.screen = self
            item.channelId = self.presentable_chan_id(i)
            item.active = i.node_id in lnworker.peers
            item.details = self.channel_details(i)
            item._chan = i
            channel_cards.add_widget(item)

    def channel_details(self, chan):
        return {'Node ID': bh2u(chan.node_id),
                'Channel ID': bh2u(chan.channel_id),
                'Capacity': self.app.format_amount_and_units(chan.constraints.capacity),
                'Funding TXID': chan.funding_outpoint.txid,
                'Short Chan ID': bh2u(chan.short_channel_id) if chan.short_channel_id else 'Not available',
                'Available to spend': self.app.format_amount_and_units(chan.available_to_spend(LOCAL) // 1000),
                'State': chan.get_state()}
