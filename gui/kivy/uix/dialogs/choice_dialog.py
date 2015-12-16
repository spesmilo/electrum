from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.uix.checkbox import CheckBox
from kivy.uix.label import Label

Builder.load_string('''
<ChoiceDialog@Popup>
    id: popup
    title: ''
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    BoxLayout:
        orientation: 'vertical'
        Widget:
            size_hint: 1, 0.2
        GridLayout:
            orientation: 'vertical'
            id: choices
            cols: 2
            size_hint: 1, 0.8
        Widget:
            size_hint: 1, 0.8
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
                    root.callback(popup.value)
                    popup.dismiss()
''')

class ChoiceDialog(Factory.Popup):

    def __init__(self, title, choices, value, callback):
        Factory.Popup.__init__(self)
        for k in choices:
            l = Label(text=k)
            l.height = '48dp'
            l.size_hint_y = 1
            cb = CheckBox(group='choices')
            cb.value = k
            cb.size_hint_y = 1
            def f(cb, x):
                if x: self.value = cb.value
            cb.bind(active=f)
            if k == value:
                cb.active = True
            self.ids.choices.add_widget(l)
            self.ids.choices.add_widget(cb)
        self.callback = callback
        self.title = title
        self.value = value
