from functools import partial

from kivy.animation import Animation
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.uix.bubble import Bubble, BubbleButton
from kivy.properties import ListProperty
from kivy.uix.widget import Widget

from electrum_gui.i18n import _

class ContextMenuItem(Widget):
    '''abstract class
    '''

class ContextButton(ContextMenuItem, BubbleButton):
    pass

class ContextMenu(Bubble):

    buttons = ListProperty([_('ok'), _('cancel')])
    '''List of Buttons to be displayed at the bottom'''

    __events__ = ('on_press', 'on_release')

    def __init__(self, **kwargs):
        self._old_buttons = self.buttons
        super(ContextMenu, self).__init__(**kwargs)
        self.on_buttons(self, self.buttons)

    def on_touch_down(self, touch):
        if not self.collide_point(*touch.pos):
            self.hide()
            return
        return super(ContextMenu, self).on_touch_down(touch)

    def on_buttons(self, _menu, value):
        if 'menu_content' not in self.ids.keys():
            return
        if value == self._old_buttons:
            return
        blayout = self.ids.menu_content
        blayout.clear_widgets()
        for btn in value:
            ib = ContextButton(text=btn)
            ib.bind(on_press=partial(self.dispatch, 'on_press'))
            ib.bind(on_release=partial(self.dispatch, 'on_release'))
            blayout.add_widget(ib)
        self._old_buttons = value

    def on_press(self, instance):
        pass

    def on_release(self, instance):
        pass

    def show(self, pos, duration=0):
        Window.add_widget(self)
        # wait for the bubble to adjust it's size according to text then animate
        Clock.schedule_once(lambda dt: self._show(pos, duration))

    def _show(self, pos, duration):
        def on_stop(*l):
            if duration:
                Clock.schedule_once(self.hide, duration + .5)

        self.opacity = 0
        arrow_pos = self.arrow_pos
        if arrow_pos[0] in ('l', 'r'):
            pos = pos[0], pos[1] - (self.height/2)
        else:
            pos = pos[0] - (self.width/2), pos[1]

        self.limit_to = Window

        anim = Animation(opacity=1, pos=pos, d=.32)
        anim.bind(on_complete=on_stop)
        anim.cancel_all(self)
        anim.start(self)


    def hide(self, *dt):

        def on_stop(*l):
            Window.remove_widget(self)
        anim = Animation(opacity=0, d=.25)
        anim.bind(on_complete=on_stop)
        anim.cancel_all(self)
        anim.start(self)

    def add_widget(self, widget, index=0):
        if not isinstance(widget, ContextMenuItem):
            super(ContextMenu, self).add_widget(widget, index)
            return
        menu_content.add_widget(widget, index)
