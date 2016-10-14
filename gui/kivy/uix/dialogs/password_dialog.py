from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from decimal import Decimal
from kivy.clock import Clock

Builder.load_string('''

<PasswordDialog@Popup>
    id: popup
    title: _('PIN Code')
    message: ''
    size_hint: 0.9, 0.9
    BoxLayout:
        orientation: 'vertical'
        Widget:
            size_hint: 1, 1
        Label:
            text: root.message
            text_size: self.width, None
            size: self.texture_size
        Widget:
            size_hint: 1, 1
        Label:
            id: a
            text: ' * '*len(kb.password) + ' o '*(6-len(kb.password))
        Widget:
            size_hint: 1, 1
        GridLayout:
            id: kb
            update_amount: popup.update_password
            password: ''
            on_password: popup.on_password(self.password)
            size_hint: 1, None
            height: '200dp'
            cols: 3
            KButton:
                text: '1'
            KButton:
                text: '2'
            KButton:
                text: '3'
            KButton:
                text: '4'
            KButton:
                text: '5'
            KButton:
                text: '6'
            KButton:
                text: '7'
            KButton:
                text: '8'
            KButton:
                text: '9'
            KButton:
                text: 'Clear'
            KButton:
                text: '0'
            KButton:
                text: '<'
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Widget:
                size_hint: 0.5, None
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Cancel')
                on_release:
                    popup.dismiss()
''')


class PasswordDialog(Factory.Popup):

    #def __init__(self, message, callback):
    #    Factory.Popup.__init__(self)

    def init(self, message, callback):
        self.message = message
        self.callback = callback
        self.ids.kb.password = ''

    def update_password(self, c):
        kb = self.ids.kb
        text = kb.password
        if c == '<':
            text = text[:-1]
        elif c == 'Clear':
            text = ''
        else:
            text += c
        kb.password = text

    def on_password(self, pw):
        if len(pw) == 6:
            self.dismiss()
            Clock.schedule_once(lambda dt: self.callback(pw), 0.1)
