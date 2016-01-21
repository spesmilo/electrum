from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

Builder.load_string('''
<CheckBoxDialog@Popup>
    id: popup
    title: ''
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            size_hint: 1, 1
            Label:
                id: description
                text: ''
                size_hint: 1, None
                halign: 'left'
                text_size: self.width, None
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Enable')
            CheckBox:
                id:cb
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
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
                    root.callback(cb.active)
                    popup.dismiss()
''')

class CheckBoxDialog(Factory.Popup):
    def __init__(self, title, text, status, callback):
        Factory.Popup.__init__(self)
        self.ids.cb.active = status
        self.ids.description.text = text
        self.callback = callback
        self.title = title
