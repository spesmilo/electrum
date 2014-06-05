from kivy.app import App
from kivy.cache import Cache
from kivy.clock import Clock
from kivy.compat import string_types
from kivy.properties import (ObjectProperty, DictProperty, NumericProperty,
                             ListProperty)
from kivy.lang import Builder
from kivy.factory import Factory


# Delayed imports
app = None


class CScreen(Factory.Screen):

    __events__ = ('on_activate', 'on_deactivate', 'on_enter', 'on_leave')

    action_view = ObjectProperty(None)

    def _change_action_view(self):
        app = App.get_running_app()
        action_bar = app.root.manager.current_screen.ids.action_bar
        _action_view = self.action_view

        if (not _action_view) or _action_view.parent:
            return
        action_bar.clear_widgets()
        action_bar.add_widget(_action_view)

    def on_enter(self):
        # FIXME: use a proper event don't use animation time of screen
        Clock.schedule_once(lambda dt: self.dispatch('on_activate'), .25)

    def on_activate(self):
        Clock.schedule_once(lambda dt: self._change_action_view())

    def on_leave(self):
        self.dispatch('on_deactivate')

    def on_deactivate(self):
        Clock.schedule_once(lambda dt: self._change_action_view())

    def load_screen(self, screen_name):
        content = self.content
        if not content:
            Builder.load_file('gui/kivy/uix/ui_screens/{}.kv'.format(screen_name))
            if screen_name.endswith('send'):
                content = Factory.ScreenSendContent()
            elif screen_name.endswith('receive'):
                content = Factory.ScreenReceiveContent()
                content.ids.toggle_qr.state = 'down'
            self.content = content
            self.add_widget(content)
            Factory.Animation(opacity=1, d=.25).start(content)
            return
        if screen_name.endswith('receive'):
            content.mode = 'qr'
        else:
            content.mode = 'address'


class EScreen(Factory.EffectWidget, CScreen):

    background_color = ListProperty((0.929, .929, .929, .929))

    speed = NumericProperty(0)

    effect_flex_scroll = '''
uniform float speed;

vec4 effect(vec4 color, sampler2D texture, vec2 tex_coords, vec2 coords)
{{
    return texture2D(
        texture,
        vec2(tex_coords.x + sin(
            tex_coords.y * 3.1416 / .2 + 3.1416 / .5
        ) * speed, tex_coords.y));
}}
'''
    def __init__(self, **kwargs):
        super(EScreen, self).__init__(**kwargs)
        self.old_x = [1, ] * 10
        self._anim = Factory.Animation(speed=0, d=.22)
        from kivy.uix.effectwidget import AdvancedEffectBase
        self.speed = 0
        self.scrollflex = AdvancedEffectBase(
            glsl=self.effect_flex_scroll,
            uniforms={'speed': self.speed}
        )
        self._trigger_straighten = Clock.create_trigger(
            self.straighten_screen, .15)

    def on_speed(self, *args):
        value = max(-0.05, min(0.05, float("{0:.5f}".format(args[1]))))
        self.scrollflex.uniforms['speed'] = value

    def on_parent(self, instance, value):
        if value:
            value.bind(x=self.screen_moving)

    def screen_moving(self, instance, value):
        self.old_x.append(value/self.width)
        self.old_x.pop(0)
        self.speed = sum(((self.old_x[x + 1] - self.old_x[x]) for x in range(9))) / 9.
        self._anim.cancel_all(self)
        self._trigger_straighten()

    def straighten_screen(self, dt):
        self._anim.start(self)


class ScreenDashboard(EScreen):
    ''' Dashboard screen: Used to display the main dashboard.
    '''

    tab = ObjectProperty(None)

    def __init__(self, **kwargs):
        self.ra_dialog = None
        super(ScreenDashboard, self).__init__(**kwargs)

    def show_tx_details(self, item):
        ra_dialog = Cache.get('electrum_widgets', 'RecentActivityDialog')
        if not ra_dialog:
            Factory.register('RecentActivityDialog',
                             module='electrum_gui.kivy.uix.dialogs.carousel_dialog')
            Factory.register('GridView',
                             module='electrum_gui.kivy.uix.gridview')
            ra_dialog = ra_dialog = Factory.RecentActivityDialog()
            Cache.append('electrum_widgets', 'RecentActivityDialog', ra_dialog)
        ra_dialog.item = item
        ra_dialog.open()


class ScreenAddress(CScreen):
    '''This is the dialog that shows a carousel of the currently available
    addresses.
    '''

    labels  = DictProperty({})
    '''
    '''

    tab =  ObjectProperty(None)
    ''' The tab associated With this Carousel
    '''


class ScreenPassword(Factory.Screen):

    __events__ = ('on_release', 'on_deactivate', 'on_activate')

    def on_activate(self):
        app = App.get_running_app()
        action_bar = app.root.main_screen.ids.action_bar
        action_bar.add_widget(self._action_view)

    def on_deactivate(self):
        self.ids.password.text = ''

    def on_release(self, *args):
        pass


class MainScreen(Factory.Screen):
    pass


class ScreenSend(EScreen):
    pass


class ScreenReceive(EScreen):
    pass


class ScreenContacts(EScreen):

    def add_new_contact(self):
        dlg = Cache.get('electrum_widgets', 'NewContactDialog')
        if not dlg:
            dlg = NewContactDialog()
            Cache.append('electrum_widgets', 'NewContactDialog', dlg)
        dlg.open()


class CSpinner(Factory.Spinner):
    '''CustomDropDown that allows fading out the dropdown
    '''

    def _update_dropdown(self, *largs):
        dp = self._dropdown
        cls = self.option_cls
        if isinstance(cls, string_types):
            cls = Factory.get(cls)
        dp.clear_widgets()
        def do_release(option):
            Clock.schedule_once(lambda dt: dp.select(option.text), .25)
        for value in self.values:
            item = cls(text=value)
            item.bind(on_release=do_release)
            dp.add_widget(item)


class TabbedCarousel(Factory.TabbedPanel):
    '''Custom TabbedOanel using a carousel used in the Main Screen
    '''

    carousel = ObjectProperty(None)

    def animate_tab_to_center(self, value):
        scrlv = self._tab_strip.parent
        if not scrlv:
            return

        idx = self.tab_list.index(value)
        if  idx == 0:
            scroll_x = 1
        elif idx == len(self.tab_list) - 1:
            scroll_x = 0
        else:
            self_center_x = scrlv.center_x
            vcenter_x = value.center_x
            diff_x = (self_center_x - vcenter_x)
            try:
                scroll_x = scrlv.scroll_x - (diff_x / scrlv.width)
            except ZeroDivisionError:
                pass
        mation = Factory.Animation(scroll_x=scroll_x, d=.25)
        mation.cancel_all(scrlv)
        mation.start(scrlv)

    def on_current_tab(self, instance, value):
        if value.text == 'default_tab':
            return
        self.animate_tab_to_center(value)

    def on_index(self, instance, value):
        current_slide = instance.current_slide
        if not hasattr(current_slide, 'tab'):
            return
        tab = current_slide.tab
        ct = self.current_tab
        try:
            if ct.text != tab.text:
                carousel = self.carousel
                carousel.slides[ct.slide].dispatch('on_leave')
                self.switch_to(tab)
                carousel.slides[tab.slide].dispatch('on_enter')
        except AttributeError:
            current_slide.dispatch('on_enter')

    def switch_to(self, header):
        # we have to replace the functionality of the original switch_to
        if not header:
            return
        if not hasattr(header, 'slide'):
            header.content = self.carousel
            super(TabbedCarousel, self).switch_to(header)
            try:
                tab = self.tab_list[-1]
            except IndexError:
                return
            self._current_tab = tab
            tab.state = 'down'
            return

        carousel = self.carousel
        self.current_tab.state = "normal"
        header.state = 'down'
        self._current_tab = header
        # set the carousel to load  the appropriate slide
        # saved in the screen attribute of the tab head
        slide = carousel.slides[header.slide]
        if carousel.current_slide != slide:
            carousel.current_slide.dispatch('on_leave')
            carousel.load_slide(slide)
            slide.dispatch('on_enter')

    def add_widget(self, widget, index=0):
        if isinstance(widget, Factory.CScreen):
            self.carousel.add_widget(widget)
            return
        super(TabbedCarousel, self).add_widget(widget, index=index)


class ELTextInput(Factory.TextInput):
    '''Custom TextInput used in main screens for numeric entry
    '''

    def insert_text(self, substring, from_undo=False):
        if not from_undo:
            if self.input_type == 'numbers':
                numeric_list = map(str, range(10))
                if '.' not in self.text:
                    numeric_list.append('.')
                if substring not in numeric_list:
                    return
        super(ELTextInput, self).insert_text(substring, from_undo=from_undo)
