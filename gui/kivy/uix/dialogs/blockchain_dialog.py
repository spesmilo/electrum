from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_ltc.i18n import _

Builder.load_string('''
#:import _ electrum_ltc_gui.kivy.i18n._

<BlockchainDialog@Popup>
    id: popup
    title: _('Blockchain')
    size_hint: 1, 1
    cp_height: 0
    cp_value: ''

    BoxLayout:
        orientation: 'vertical'
        padding: '10dp'
        spacing: '10dp'
        TopLabel:
            height: '48dp'
            id: bc_height
            text: _("Verified headers: %d blocks.")% app.num_blocks
        TopLabel:
            height: '48dp'
            id: bc_status
            text: _("Connected to %d nodes.")% app.num_nodes if app.num_nodes else _("Not connected?")
        Widget:
            size_hint: 1, 0.1
        TopLabel:
            text: _("Electrum connects to several nodes in order to download block headers and find out the longest blockchain.") + _("This blockchain is used to verify the transactions sent by your transaction server.")
            font_size: '6pt'
        Widget:
            size_hint: 1, 0.1
        Widget:
            size_hint: 1, 0.1
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.2
            Button:
                text: _('Cancel')
                size_hint: 0.5, None
                height: '48dp'
                on_release: popup.dismiss()
            Button:
                text: _('OK')
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    root.callback(root.cp_height, root.cp_value)
                    popup.dismiss()
''')

class BlockchainDialog(Factory.Popup):
    def __init__(self, network, callback):
        Factory.Popup.__init__(self)
        self.network = network
        self.callback = callback
        self.is_split = len(self.network.blockchains) > 1

        self.checkpoint_height = network.get_checkpoint()
