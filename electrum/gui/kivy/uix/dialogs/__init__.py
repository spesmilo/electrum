from kivy.app import App
from kivy.clock import Clock
from kivy.factory import Factory
from kivy.properties import NumericProperty, StringProperty, BooleanProperty
from kivy.core.window import Window
from kivy.uix.recycleview import RecycleView
from kivy.uix.boxlayout import BoxLayout

from electrum.gui.kivy.i18n import _



class AnimatedPopup(Factory.Popup):
    ''' An Animated Popup that animates in and out.
    '''

    anim_duration = NumericProperty(.36)
    '''Duration of animation to be used
    '''

    __events__ = ['on_activate', 'on_deactivate']


    def on_activate(self):
        '''Base function to be overridden on inherited classes.
        Called when the popup is done animating.
        '''
        pass

    def on_deactivate(self):
        '''Base function to be overridden on inherited classes.
        Called when the popup is done animating.
        '''
        pass

    def open(self):
        '''Do the initialization of incoming animation here.
        Override to set your custom animation.
        '''
        def on_complete(*l):
            self.dispatch('on_activate')

        self.opacity = 0
        super(AnimatedPopup, self).open()
        anim = Factory.Animation(opacity=1, d=self.anim_duration)
        anim.bind(on_complete=on_complete)
        anim.start(self)

    def dismiss(self):
        '''Do the initialization of incoming animation here.
        Override to set your custom animation.
        '''
        def on_complete(*l):
            super(AnimatedPopup, self).dismiss()
            self.dispatch('on_deactivate')

        anim = Factory.Animation(opacity=0, d=.25)
        anim.bind(on_complete=on_complete)
        anim.start(self)

class EventsDialog(Factory.Popup):
    ''' Abstract Popup that provides the following events
    .. events::
        `on_release`
        `on_press`
    '''

    __events__ = ('on_release', 'on_press')

    def __init__(self, **kwargs):
        super(EventsDialog, self).__init__(**kwargs)

    def on_release(self, instance):
        pass

    def on_press(self, instance):
        pass

    def close(self):
        self.dismiss()


class SelectionDialog(EventsDialog):

    def add_widget(self, widget, index=0):
        if self.content:
            self.content.add_widget(widget, index)
            return
        super(SelectionDialog, self).add_widget(widget)


class InfoBubble(Factory.Bubble):
    '''Bubble to be used to display short Help Information'''

    message = StringProperty(_('Nothing set !'))
    '''Message to be displayed; defaults to "nothing set"'''

    icon = StringProperty('')
    ''' Icon to be displayed along with the message defaults to ''

    :attr:`icon` is a  `StringProperty` defaults to `''`
    '''

    fs = BooleanProperty(False)
    ''' Show Bubble in half screen mode

    :attr:`fs` is a `BooleanProperty` defaults to `False`
    '''

    modal = BooleanProperty(False)
    ''' Allow bubble to be hidden on touch.

    :attr:`modal` is a `BooleanProperty` defauult to `False`.
    '''

    exit = BooleanProperty(False)
    '''Indicates whether to exit app after bubble is closed.

    :attr:`exit` is a `BooleanProperty` defaults to False.
    '''

    dim_background = BooleanProperty(False)
    ''' Indicates Whether to draw a background on the windows behind the bubble.

    :attr:`dim` is a `BooleanProperty` defaults to `False`.
    '''

    def on_touch_down(self, touch):
        if self.modal:
            return True
        self.hide()
        if self.collide_point(*touch.pos):
            return True

    def show(self, pos, duration, width=None, modal=False, exit=False):
        '''Animate the bubble into position'''
        self.modal, self.exit = modal, exit
        if width:
            self.width = width
        if self.modal:
            from kivy.uix.modalview import ModalView
            self._modal_view = m = ModalView(background_color=[.5, .5, .5, .2])
            Window.add_widget(m)
            m.add_widget(self)
        else:
            Window.add_widget(self)

        # wait for the bubble to adjust its size according to text then animate
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

        anim = Factory.Animation(opacity=1, pos=pos, d=.32)
        anim.bind(on_complete=on_stop)
        anim.cancel_all(self)
        anim.start(self)


    def hide(self, now=False):
        ''' Auto fade out the Bubble
        '''
        def on_stop(*l):
            if self.modal:
                m = self._modal_view
                m.remove_widget(self)
                Window.remove_widget(m)
            Window.remove_widget(self)
            if self.exit:
                App.get_running_app().stop()
                import sys
                sys.exit()
            else:
                App.get_running_app().is_exit = False

        if now:
            return on_stop()

        anim = Factory.Animation(opacity=0, d=.25)
        anim.bind(on_complete=on_stop)
        anim.cancel_all(self)
        anim.start(self)



class OutputItem(BoxLayout):
    pass

class OutputList(RecycleView):

    def __init__(self, **kwargs):
        super(OutputList, self).__init__(**kwargs)
        self.app = App.get_running_app()

    def update(self, outputs):
        res = []
        for o in outputs:
            value = self.app.format_amount_and_units(o.value)
            res.append({'address': o.address, 'value': value})
        self.data = res


class TopLabel(Factory.Label):
    pass


class RefLabel(TopLabel):
    pass
