#!python
#!/usr/bin/env python
from kivy.app import App
from kivy.uix.bubble import Bubble
from kivy.animation import Animation
from kivy.uix.floatlayout import FloatLayout
from kivy.lang import Builder
from kivy.factory import Factory

Builder.load_string('''
<MenuItem@Button>
    background_color: .2, .9, 1, 1
    height: '40dp'
    size_hint: 1, None

<ContextMenu>
    size_hint: 1, None
    height: '32dp'
    #size: 120, 250
    pos: (0, 0)
    show_arrow: False
    padding: 0
    orientation: 'horizontal'
    BoxLayout:
        size_hint: 1, 1
        height: '40dp'
        orientation: 'horizontal'
        id: buttons
''')


class MenuItem(Factory.Button):
    pass

class ContextMenu(Bubble):
    def __init__(self, obj, action_list):
        Bubble.__init__(self)
        self.obj = obj
        for k, v in action_list:
            l = MenuItem()
            l.text = k
            l.on_release = lambda f=v: f(obj)
            self.ids.buttons.add_widget(l)
