from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_ltc.i18n import _

Builder.load_string('''
#:import _ electrum_ltc_gui.kivy.i18n._

<CheckpointDialog@Popup>
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
            text: _("In order to verify the history returned by your main server, Electrum downloads block headers from random nodes. These headers are then used to check that transactions sent by the server really are in the blockchain.")
            font_size: '6pt'
        Widget:
            size_hint: 1, 0.1
        GridLayout:
            orientation: 'horizontal'
            cols: 2
            height: '36dp'
            TopLabel:
                text: _('Checkpoint') + ':'
                height: '36dp'
            TextInput:
                id: height_input
                multiline: False
                input_type: 'number'
                height: '36dp'
                size_hint_y: None
                text: '%d'%root.cp_height
            TopLabel:
                text: _('Block hash') + ':'
            TxHashLabel:
                data: root.cp_value
        Widget:
            size_hint: 1, 0.1
        Label:
            font_size: '6pt'
            text: _('If there is a fork of the blockchain, you need to configure your checkpoint in order to make sure that you are on the correct side of the fork. Enter a block number to fetch a checkpoint from your main server, and check its value from independent sources.')
            halign: 'left'
            text_size: self.width, None
            size: self.texture_size

        Widget:
            size_hint: 1, 0.3
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

class CheckpointDialog(Factory.Popup):
    def __init__(self, network, callback):
        Factory.Popup.__init__(self)
        self.network = network
        self.callback = callback
        self.is_split = len(self.network.blockchains) > 1
