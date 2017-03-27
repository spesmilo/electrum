from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder



Builder.load_string('''
#:import _ electrum_gui.kivy.i18n._

<CheckpointDialog@Popup>
    id: popup
    cp_height: 0
    cp_value: ''
    title: _('Checkpoint')
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    BoxLayout:
        orientation: 'vertical'
        Label:
            id: description
            text: 'In the event of a blockchain fork, a checkpoint can be used to ensure that you are on the correct blockchain.'
            halign: 'left'
            text_size: self.width, None
            size: self.texture_size
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.2
            Label:
                text: _('Height')
                height: '48dp'
            TextInput:
                id: height_input
                text: '%d'%root.cp_height
                on_focus: root.on_height_str()
        TopLabel:
            text: _('Block hash') + ':'
        TxHashLabel:
            data: root.cp_value
        Label:
            text: 'Edit the height to fetch a checkpoint from your main server, and check its value from independent sources.'
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
