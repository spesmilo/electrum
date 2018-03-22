from kivy.lang import Builder
from kivy.factory import Factory
from kivy.clock import Clock
import electrum.lightning as lightning

Builder.load_string('''
<LightningChannelItem@CardItem>
    channelId: '<channelId not set>'
    Label:
        text: root.channelId

<LightningChannelsDialog@Popup>:
    name: 'lightning_channels'
    BoxLayout:
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
    def open(self, *args, **kwargs):
        super(LightningChannelsDialog, self).open(*args, **kwargs)
        for i in self.clocks: i.cancel()
        self.clocks.append(Clock.schedule_interval(self.fetch_channels, 10))
        self.app.wallet.network.lightningrpc.subscribe(self.rpc_result_handler)
    def dismiss(self, *args, **kwargs):
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
            item.channelId = i["chan_id"]
            channel_cards.add_widget(item)
