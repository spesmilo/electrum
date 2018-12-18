from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

Builder.load_string('''
<LabelDialog@Popup>
    id: popup
    title: ''
    size_hint: 0.8, 0.3
    pos_hint: {'top':0.9}
    BoxLayout:
        orientation: 'vertical'
        Widget:
            size_hint: 1, 0.2
        TextInput:
            id:input
            padding: '5dp'
            size_hint: 1, None
            height: '27dp'
            pos_hint: {'center_y':.5}
            text:''
            multiline: False
            background_normal: 'atlas://gui/kivy/theming/light/tab_btn'
            background_active: 'atlas://gui/kivy/theming/light/textinput_active'
            hint_text_color: self.foreground_color
            foreground_color: 1, 1, 1, 1
            font_size: '16dp'
            focus: True
        Widget:
            size_hint: 1, 0.2
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
                    root.callback(input.text)
                    popup.dismiss()
''')

class LabelDialog(Factory.Popup):

    def __init__(self, title, text, callback):
        Factory.Popup.__init__(self)
        self.ids.input.text = text
        self.callback = callback
        self.title = title
