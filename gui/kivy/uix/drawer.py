'''Drawer Widget to hold the main window and the menu/hidden section that
can be swiped in from the left. This Menu would be only hidden in phone mode
and visible in Tablet Mode.

This class is specifically in lined to save on start up speed(minimize i/o).
'''

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import OptionProperty, NumericProperty, ObjectProperty
from kivy.clock import Clock
from kivy.lang import Builder

import gc

# delayed imports
app = None


class Drawer(Factory.RelativeLayout):
    '''Drawer Widget to hold the main window and the menu/hidden section that
    can be swiped in from the left. This Menu would be only hidden in phone mode
    and visible in Tablet Mode.

    '''

    state = OptionProperty('closed',
                            options=('closed', 'open', 'opening', 'closing'))
    '''This indicates the current state the drawer is in.

    :attr:`state` is a `OptionProperty` defaults to `closed`. Can be one of
    `closed`, `open`, `opening`, `closing`.
    '''

    scroll_timeout = NumericProperty(200)
    '''Timeout allowed to trigger the :data:`scroll_distance`,
    in milliseconds. If the user has not moved :data:`scroll_distance`
    within the timeout, the scrolling will be disabled and the touch event
    will go to the children.

    :data:`scroll_timeout` is a :class:`~kivy.properties.NumericProperty`
    and defaults to 200 (milliseconds)
    '''

    scroll_distance = NumericProperty('9dp')
    '''Distance to move before scrolling the :class:`Drawer` in pixels.
    As soon as the distance has been traveled, the :class:`Drawer` will
    start to scroll, and no touch event will go to children.
    It is advisable that you base this value on the dpi of your target
    device's screen.

    :data:`scroll_distance` is a :class:`~kivy.properties.NumericProperty`
    and defaults to 20dp.
    '''

    drag_area = NumericProperty('9dp')
    '''The percentage of area on the left edge that triggers the opening of
    the drawer. from 0-1

    :attr:`drag_area` is a `NumericProperty` defaults to 2
    '''

    hidden_widget = ObjectProperty(None)
    ''' This is the widget that is hidden in phone mode on the left side of
    drawer or displayed on the left of the overlay widget in tablet mode.

    :attr:`hidden_widget` is a `ObjectProperty` defaults to None.
    '''

    overlay_widget = ObjectProperty(None)
    '''This a pointer to the default widget that is overlayed either on top or
    to the right of the hidden widget.
    '''

    def __init__(self, **kwargs):
        super(Drawer, self).__init__(**kwargs)

        self._triigger_gc = Clock.create_trigger(self._re_enable_gc, .2)

    def toggle_drawer(self):
        if app.ui_mode[0] == 't':
            return
        Factory.Animation.cancel_all(self.overlay_widget)
        anim = Factory.Animation(x=self.hidden_widget.width
                            if self.state in ('opening', 'closed') else 0,
                            d=.1, t='linear')
        anim.bind(on_complete = self._complete_drawer_animation)
        anim.start(self.overlay_widget)

    def _re_enable_gc(self, dt):
        global gc
        gc.enable()

    def on_touch_down(self, touch):
        if self.disabled:
            return

        if not self.collide_point(*touch.pos):
            return

        touch.grab(self)

        # disable gc for smooth interaction
        # This is still not enough while wallet is synchronising
        # look into pausing all background tasks while ui interaction like this
        gc.disable()

        global app
        if not app:
            app = App.get_running_app()

        # skip on tablet mode
        if app.ui_mode[0] == 't':
            return super(Drawer, self).on_touch_down(touch)

        state = self.state
        touch.ud['send_touch_down'] = False
        start = 0 #if state[0] == 'c' else self.hidden_widget.right
        drag_area = self.drag_area\
           if self.state[0] == 'c' else\
           (self.overlay_widget.x)

        if touch.x < start or touch.x > drag_area:
            if self.state == 'open':
                self.toggle_drawer()
                return
            return super(Drawer, self).on_touch_down(touch)

        self._touch = touch
        Clock.schedule_once(self._change_touch_mode,
                            self.scroll_timeout/1000.)
        touch.ud['in_drag_area'] = True
        touch.ud['send_touch_down'] = True
        return

    def on_touch_move(self, touch):
        if not touch.grab_current is self:
            return
        self._touch = False
        # skip on tablet mode
        if app.ui_mode[0] == 't':
            return super(Drawer, self).on_touch_move(touch)

        if not touch.ud.get('in_drag_area', None):
            return super(Drawer, self).on_touch_move(touch)

        ov = self.overlay_widget
        ov.x=min(self.hidden_widget.width,
            max(ov.x + touch.dx*2, 0))

        #_anim = Animation(x=x, duration=1/2, t='in_out_quart')
        #_anim.cancel_all(ov)
        #_anim.start(ov)

        if abs(touch.x - touch.ox) < self.scroll_distance:
            return

        touch.ud['send_touch_down'] = False
        Clock.unschedule(self._change_touch_mode)
        self._touch = None
        self.state = 'opening' if touch.dx > 0 else 'closing'
        touch.ox = touch.x
        return

    def _change_touch_mode(self, *args):
        if not self._touch:
            return
        touch = self._touch
        touch.ungrab(self)
        touch.ud['in_drag_area'] = False
        touch.ud['send_touch_down'] = False
        self._touch = None
        super(Drawer, self).on_touch_down(touch)
        return

    def on_touch_up(self, touch):
        if not touch.grab_current is self:
            return

        self._triigger_gc()

        touch.ungrab(self)
        touch.grab_current = None

        # skip on tablet mode
        get  = touch.ud.get
        if app.ui_mode[0] == 't':
            return super(Drawer, self).on_touch_up(touch)

        self.old_x = [1, ] * 10
        self.speed = sum((
            (self.old_x[x + 1] - self.old_x[x]) for x in range(9))) / 9.

        if get('send_touch_down', None):
            # touch up called before moving
            Clock.unschedule(self._change_touch_mode)
            self._touch = None
            Clock.schedule_once(
                lambda dt: super(Drawer, self).on_touch_down(touch))
        if get('in_drag_area', None):
            if abs(touch.x - touch.ox) < self.scroll_distance:
                anim_to = (0 if self.state[0] == 'c'
                      else self.hidden_widget.width)
                Factory.Animation(x=anim_to, d=.1).start(self.overlay_widget)
                return
            touch.ud['in_drag_area'] = False
            if not get('send_touch_down', None):
                self.toggle_drawer()
        Clock.schedule_once(lambda dt: super(Drawer, self).on_touch_up(touch))

    def _complete_drawer_animation(self, *args):
        self.state = 'open' if self.state in ('opening', 'closed') else 'closed'

    def add_widget(self, widget, index=1):
        if not widget:
            return

        iget = self.ids.get
        if not iget('hidden_widget') or not iget('overlay_widget'):
            super(Drawer, self).add_widget(widget)
            return

        if not self.hidden_widget:
            self.hidden_widget = self.ids.hidden_widget
        if not self.overlay_widget:
            self.overlay_widget = self.ids.overlay_widget

        if self.overlay_widget.children and self.hidden_widget.children:
            Logger.debug('Drawer: Accepts only two widgets. discarding rest')
            return

        if not self.hidden_widget.children:
            self.hidden_widget.add_widget(widget)
        else:
            self.overlay_widget.add_widget(widget)
            widget.x = 0

    def remove_widget(self, widget):
        if self.overlay_widget.children[0] == widget:
            self.overlay_widget.clear_widgets()
            return
        if widget == self.hidden_widget.children:
            self.hidden_widget.clear_widgets()
            return

    def clear_widgets(self):
        self.overlay_widget.clear_widgets()
        self.hidden_widget.clear_widgets()

if __name__ == '__main__':
    from kivy.app import runTouchApp
    from kivy.lang import Builder
    runTouchApp(Builder.load_string('''
Drawer:
    Button:
    Button
'''))