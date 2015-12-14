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
    height: '48dp'
    size_hint: 1, None

<ContextMenu>
    size_hint: 1, None
    height: '48dp'
    pos: (0, 0)
    show_arrow: False
    arrow_pos: 'top_mid'
    padding: 0
    orientation: 'horizontal'
    BoxLayout:
        size_hint: 1, 1
        height: '48dp'
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
            def func(f=v):
                f(obj)
                if self.parent: self.parent.hide_menu()
            l.on_release = func
            self.ids.buttons.add_widget(l)
