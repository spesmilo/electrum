from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

Builder.load_string('''
<SeedOptionsDialog@Popup>
    id: popup
    title: _('Seed Options')
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    BoxLayout:
        orientation: 'vertical'
        Label:
            id: description
            text: _('You may extend your seed with custom words')
            halign: 'left'
            text_size: self.width, None
            size: self.texture_size
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.2
            Label:
                text: _('Extend Seed')
            CheckBox:
                id:ext
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.2
            Label:
                text: _('BIP39')
                id:bip39_label
            CheckBox:
                id:bip39
        Widget:
            size_hint: 1, 0.1
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.2
            Button:
                text: 'Cancel'
                size_hint: 0.5, None
                height: '48dp'
                on_release: popup.dismiss()
            Button:
                text: 'OK'
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    root.callback(ext.active, bip39.active)
                    popup.dismiss()
''')


class SeedOptionsDialog(Factory.Popup):
    def __init__(self, is_ext, is_bip39, callback):
        Factory.Popup.__init__(self)
        self.ids.ext.active = is_ext
        if is_bip39 is None:
            self.ids.bip39.opacity = 0
            self.ids.bip39_label.opacity = 0
            self.ids.bip39.disabled = True
        else:
            self.ids.bip39.active = is_bip39
        self.callback = callback
