#!python
#!/usr/bin/env python
from kivy.app import App
from kivy.uix.bubble import Bubble
from kivy.animation import Animation
from kivy.uix.floatlayout import FloatLayout
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.clock import Clock

from electrum_gui.kivy.i18n import _

Builder.load_string('''
<MenuItem@Button>
    background_normal: ''
    background_color: (0.192, .498, 0.745, 1)
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
        padding: '12dp', '0dp'
        spacing: '3dp'
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
            l.text = _(k)
            def func(f=v):
                Clock.schedule_once(lambda dt: self.hide(), 0.1)
                Clock.schedule_once(lambda dt: f(obj), 0.15)
            l.on_release = func
            self.ids.buttons.add_widget(l)

    def hide(self):
        if self.parent:
            self.parent.hide_menu()
