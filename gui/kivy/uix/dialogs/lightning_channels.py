import binascii
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.clock import Clock
import electrum.lightning as lightning
from electrum_gui.kivy.uix.context_menu import ContextMenu

Builder.load_string('''
<LightningChannelItem@CardItem>
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
''')

class LightningChannelsDialog(Factory.Popup):
    def __init__(self, app):
        super(LightningChannelsDialog, self).__init__()
        self.clocks = []
        self.app = app
        self.context_menu = None

    def close_channel(self, obj):
        print("asked to close channel", obj.channelPoint)
        lightning.lightningCall(self.app.wallet.network.lightningrpc, "closechannel")(obj.channelPoint + (" --force" if not obj.active else ""))

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, [("Close", self.close_channel)])
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
        for i in res["channels"]:
            item = Factory.LightningChannelItem()
            item.screen = self
            print(i)
            item.channelPoint = binascii.hexlify(bytes(reversed(bytes(bytearray.fromhex(i["channel_point"].split(":")[0]))))).decode("ascii")
            item.active = i["active"]
            channel_cards.add_widget(item)
