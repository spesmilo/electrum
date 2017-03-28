from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.i18n import _

Builder.load_string('''
#:import _ electrum_gui.kivy.i18n._

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
            text: ''
        TopLabel:
            height: '48dp'
            id: bc_status
            text: ''
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
                on_focus: root.on_height_str()
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
        self.cp_height, self.cp_value = self.network.blockchain.get_checkpoint()
        self.callback = callback

        n_nodes = len(network.get_interfaces())
        n_blocks = network.get_local_height()
        self.ids.bc_height.text = _("Verified headers: %d blocks.")%n_blocks
        self.ids.bc_status.text = _("Connected to %d nodes.")%n_nodes if n_nodes else _("Not connected?")


    def on_height_str(self):
        try:
            new_height = int(self.ids.height_input.text)
        except:
            new_height = 0
        if new_height == self.cp_height:
            return
        try:
            header = self.network.synchronous_get(('blockchain.block.get_header', [new_height]), 5)
            new_value = self.network.blockchain.hash_header(header)
        except BaseException as e:
            self.network.print_error(str(e))
            new_value = ''
        if new_value:
            self.cp_height = new_height
            self.cp_value = new_value
