from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from decimal import Decimal

Builder.load_string('''

<PasswordDialog@Popup>
    id: popup
    title: _('Enter PIN Code')
    size_hint: 0.9, 0.9

    BoxLayout:

        orientation: 'vertical'
        size_hint: 0.8, 1

        Label:
            id: a
            text: ' * '*len(kb.password) + ' o '*(6-len(kb.password))
            size_hint: 1, None
            height: '48dp'

        GridLayout:
            id: kb
            update_amount: popup.update_password
            password: ''
            on_password: popup.on_password(self.password)
            size_hint: 1, None
            height: '300dp'
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

        Widget:
            size_hint: 1, 1
''')


class PasswordDialog(Factory.Popup):

    def __init__(self, title, cb):
        Factory.Popup.__init__(self)
        self.title = title
        self.callback = cb

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
            self.callback(pw)
