
from kivy.uix.stencilview import StencilView
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.image import Image

from kivy.animation import Animation
from kivy.clock import Clock
from kivy.properties import OptionProperty, NumericProperty, ObjectProperty

# delayed import
app = None


class Drawer(StencilView):

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

    drag_area = NumericProperty(.1)
    '''The percentage of area on the left edge that triggers the opening of
    the drawer. from 0-1

    :attr:`drag_area` is a `NumericProperty` defaults to 2
    '''

    _hidden_widget = ObjectProperty(None)
    _overlay_widget = ObjectProperty(None)

    def __init__(self, **kwargs):
        super(Drawer, self).__init__(**kwargs)
        self.bind(pos=self._do_layout,
                    size=self._do_layout,
                    children=self._do_layout)

    def _do_layout(self, instance, value):
        if not self._hidden_widget or not self._overlay_widget:
            return
        self._overlay_widget.height = self._hidden_widget.height =\
            self.height

    def on_touch_down(self, touch):
        if self.disabled:
            return

        if not self.collide_point(*touch.pos):
            return

        touch.grab(self)

        global app
        if not app:
            from kivy.app import App
            app = App.get_running_app()

        # skip on tablet mode
        if app.ui_mode[0] == 't':
            return super(Drawer, self).on_touch_down(touch)

        touch.ud['send_touch_down'] = False
        drag_area = ((self.width * self.drag_area)
                    if self.state[0] == 'c' else
                    self._hidden_widget.width)
        if touch.x > drag_area:
            return super(Drawer, self).on_touch_down(touch)
        self._touch = touch
        Clock.schedule_once(self._change_touch_mode,
                            self.scroll_timeout/1000.)
        touch.ud['in_drag_area'] = True
        touch.ud['send_touch_down'] = True
        return

    def on_touch_move(self, touch):
        if not touch.grab_current:
            return

        # skip on tablet mode
        if app.ui_mode[0] == 't':
            return super(Drawer, self).on_touch_move(touch)

        if not touch.ud.get('in_drag_area', None):
            return super(Drawer, self).on_touch_move(touch)

        self._overlay_widget.x = min(self._hidden_widget.width,
                        max(self._overlay_widget.x + touch.dx*2, 0))
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
        touch.ud['in_drag_area'] = False
        touch.ud['send_touch_down'] = False
        self._touch = None
        super(Drawer, self).on_touch_down(touch)
        return

    def on_touch_up(self, touch):
        if not touch.grab_current:
            return

        # skip on tablet mode
        if app.ui_mode[0] == 't':
            return super(Drawer, self).on_touch_down(touch)

        if touch.ud.get('send_touch_down', None):
            Clock.unschedule(self._change_touch_mode)
            Clock.schedule_once(
                lambda dt: super(Drawer, self).on_touch_down(touch), -1)
        if touch.ud.get('in_drag_area', None):
            touch.ud['in_drag_area'] = False
        Animation.cancel_all(self._overlay_widget)
        anim = Animation(x=self._hidden_widget.width
                            if self.state[0] == 'o' else 0,
                            d=.1, t='linear')
        anim.bind(on_complete = self._complete_drawer_animation)
        anim.start(self._overlay_widget)
        Clock.schedule_once(
            lambda dt: super(Drawer, self).on_touch_up(touch), 0)

    def _complete_drawer_animation(self, *args):
        self.state = 'open' if self.state[0] == 'o' else 'closed'

    def add_widget(self, widget, index=1):
        if not widget:
            return
        children = self.children
        len_children = len(children)
        if len_children == 2:
            Logger.debug('Drawer: No more than two widgets allowed')
            return

        super(Drawer, self).add_widget(widget)
        if len_children == 0:
            # first widget add it to the hidden/drawer section
            self._hidden_widget = widget
            return
        # Second Widget
        self._overlay_widget = widget

    def remove_widget(self, widget):
        super(Drawer, self).remove_widget(self)
        if widget == self._hidden_widget:
            self._hidden_widget = None
            return
        if widget == self._overlay_widget:
            self._overlay_widget = None
            return