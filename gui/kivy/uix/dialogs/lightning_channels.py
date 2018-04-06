import binascii
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.uix.popup import Popup
from kivy.clock import Clock
import electrum.lightning as lightning
from electrum_gui.kivy.uix.context_menu import ContextMenu

Builder.load_string('''
<LightningChannelItem@CardItem>
    details: {}
    active: False
    channelPoint: '<channelPoint not set>'
    Label:
        text: root.channelPoint

<LightningChannelsDialog@Popup>:
    name: 'lightning_channels'
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

    def show_channel_details(self, obj):
        p = Factory.ChannelDetailsPopup()
        p.data = [{'keyName': key, 'value': str(obj.details[key])} for key in obj.details.keys()]
        p.open()

    def close_channel(self, obj):
        print("asked to close channel", obj.channelPoint)
        lightning.lightningCall(self.app.wallet.network.lightningrpc, "closechannel")(*([obj.channelPoint] + (["--force"] if not obj.active else [])))

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, [("Close", self.close_channel),
            ("Details", self.show_channel_details)])
        self.ids.box.add_widget(self.context_menu)

    def hide_menu(self):
        if self.context_menu is not None:
            self.ids.box.remove_widget(self.context_menu)
            self.context_menu = None

    def open(self, *args, **kwargs):
        super(LightningChannelsDialog, self).open(*args, **kwargs)
        for i in self.clocks: i.cancel()
        self.clocks.append(Clock.schedule_interval(self.fetch_channels, 10))
        self.app.wallet.network.lightningrpc.subscribe(self.rpc_result_handler)

    def dismiss(self, *args, **kwargs):
        self.hide_menu()
        super(LightningChannelsDialog, self).dismiss(*args, **kwargs)
        self.app.wallet.network.lightningrpc.clearSubscribers()

    def fetch_channels(self, dw):
        lightning.lightningCall(self.app.wallet.network.lightningrpc, "listchannels")()

    def rpc_result_handler(self, methodName, res):
        print("got result", methodName)
        if isinstance(res, Exception):
            raise res
        channel_cards = self.ids.lightning_channels_container
        channel_cards.clear_widgets()
        if "channels" in res:
          for i in res["channels"]:
            item = Factory.LightningChannelItem()
            item.screen = self
            print(i)
            item.channelPoint = i["channel_point"].split(":")[0]
            item.active = i["active"]
            item.details = i
            channel_cards.add_widget(item)
        else:
          self.app.show_info(res)
