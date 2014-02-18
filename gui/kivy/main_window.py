import  sys

from electrum import WalletStorage, Wallet
from electrum.i18n import _

from kivy.app import App
from kivy.core.window import Window
from kivy.metrics import inch
from kivy.logger import Logger
from kivy.utils import platform
from kivy.properties import (OptionProperty, AliasProperty, ObjectProperty,
                             StringProperty, ListProperty)

#inclusions for factory so that widgets can be used in kv
from gui.kivy.drawer import Drawer
from gui.kivy.dialog import InfoBubble

class ElectrumWindow(App):

    title = _('Electrum App')

    wallet = ObjectProperty(None)
    '''Holds the electrum wallet

    :attr:`wallet` is a `ObjectProperty` defaults to None.
    '''

    conf = ObjectProperty(None)
    '''Holds the electrum config

    :attr:`conf` is a `ObjectProperty`, defaults to None.
    '''

    status = StringProperty(_('Uninitialised'))
    '''The status of the connection should show the balance when connected

    :attr:`status` is a `StringProperty` defaults to _'uninitialised'
    '''

    base_unit = StringProperty('BTC')
    '''BTC or UBTC or ...

    :attr:`base_unit` is a `StringProperty` defaults to 'BTC'
    '''

    _ui_mode = OptionProperty('phone', options=('tablet', 'phone'))

    def _get_ui_mode(self):
        return self._ui_mode

    ui_mode = AliasProperty(_get_ui_mode,
                            None,
                            bind=('_ui_mode',))
    '''Defines tries to ascertain the kind of device the app is running on.
    Cane be one of `tablet` or `phone`.

    :data:`ui_mode` is a read only `AliasProperty` Defaults to 'phone'
    '''

    _orientation = OptionProperty('landscape',
                                 options=('landscape', 'portrait'))

    def _get_orientation(self):
        return self._orientation

    orientation = AliasProperty(_get_orientation,
                                None,
                                bind=('_orientation',))
    '''Tries to ascertain the kind of device the app is running on.
    Cane be one of `tablet` or `phone`.

    :data:`orientation` is a read only `AliasProperty` Defaults to 'landscape'
    '''

    navigation_higherarchy = ListProperty([])
    '''This is a list of the current navigation higherarchy of the app used to
    navigate using back button.

    :attr:`navigation_higherarchy` is s `ListProperty` defaults to []
    '''

    __events__ = ('on_back', )

    def __init__(self, **kwargs):
        # initialize variables
        self.info_bubble = None
        super(ElectrumWindow, self).__init__(**kwargs)
        self.network = network = kwargs.get('network')
        self.electrum_config = config = kwargs.get('config')

    def load_wallet(self, wallet):
        # TODO
        pass

    def build(self):
        from kivy.lang import Builder
        return Builder.load_file('gui/kivy/main.kv')

    def _pause(self):
        if platform == 'android':
            from jnius import autoclass
            python_act = autoclass('org.renpy.android.PythonActivity')
            mActivity = python_act.mActivity
            mActivity.moveTaskToBack(True)

    def on_start(self):
        Window.bind(size=self.on_size,
                    on_keyboard=self.on_keyboard)
        Window.bind(keyboard_height=self.on_keyboard_height)
        self.on_size(Window, Window.size)
        config = self.electrum_config
        storage = WalletStorage(config)

        Logger.info('Electrum: Check for existing wallet')
        if not storage.file_exists:
            # start installation wizard
            Logger.debug('Electrum: Wallet not found. Launching install wizard')
            import installwizard
            wizard = installwizard.InstallWizard(config, self.network,
                                                 storage)
            wizard.bind(on_wizard_complete=self.on_wizard_complete)
            wizard.run()
        else:
            wallet = Wallet(storage)
            wallet.start_threads(self.network)
            self.on_wizard_complete(None, wallet)

        self.on_resume()

    def on_back(self):
        ''' Manage screen higherarchy
        '''
        try:
            self.navigation_higherarchy.pop()()
        except IndexError:
            # capture back button and pause app.
            self._pause()

    def on_keyboard_height(self, *l):
        from kivy.animation import Animation
        from kivy.uix.popup import Popup
        active_widg = Window.children[0]
        active_widg = active_widg\
            if (active_widg == self.root or\
            issubclass(active_widg.__class__, Popup)) else\
            Window.children[1]
        Animation(y=Window.keyboard_height, d=.1).start(active_widg)

    def on_keyboard(self, instance, key, keycode, codepoint, modifiers):
        # override settings button
        if key in (319, 282):
            self.gui.main_gui.toggle_settings(self)
            return True
        if key == 27:
            self.dispatch('on_back')
            return True

    def on_wizard_complete(self, instance, wallet):
        if not wallet:
            Logger.debug('Electrum: No Wallet set/found. Exiting...')
            self.stop()
            sys.exit()
        return

        # plugins that need to change the GUI do it here
        #run_hook('init')

        self.load_wallet(wallet)

        Clock.schedule_once(update_wallet)

        #self.windows.append(w)
        #if url: w.set_url(url)
        #w.app = self.app
        #w.connect_slots(s)
        #w.update_wallet()

        #self.app.exec_()

        wallet.stop_threads()

    def on_pause(self):
        '''
        '''
        # pause nfc
        # pause qrscanner(Camera) if active
        return True

    def on_resume(self):
        '''
        '''
        # resume nfc
        # resume camera if active
        pass

    def on_size(self, instance, value):
        width, height = value
        self._orientation = 'landscape' if width > height else 'portrait'
        self._ui_mode = 'tablet' if min(width, height) > inch(3.51) else 'phone'
        Logger.debug('orientation: {} ui_mode: {}'.format(self._orientation,
                                                          self._ui_mode))

    def load_screen(self, index=0, direction='left'):
        '''
        '''
        screen = Builder.load_file('data/screens/' + self.screens[index])
        screen.name = self.screens[index]
        root.manager.switch_to(screen, direction=direction)

    def load_next_screen(self):
        '''
        '''
        manager = root.manager
        try:
            self.load_screen(self.screens.index(manager.current_screen.name)+1)
        except IndexError:
            self.load_screen()

    def load_previous_screen(self):
        '''
        '''
        manager = root.manager
        try:
            self.load_screen(self.screens.index(manager.current_screen.name)-1,
                             direction='right')
        except IndexError:
            self.load_screen(-1, direction='right')

    def show_error(self, error,
                   width='200dp',
                   pos=None,
                   arrow_pos=None):
        ''' Show a error Message Bubble.
        '''
        self.show_info_bubble(
                    text=error,
                    icon='atlas://gui/kivy/theming/light/error',
                    width=width,
                    pos=pos or Window.center,
                    arrow_pos=arrow_pos)

    def show_info_bubble(self,
                    text=_('Hello World'),
                    pos=(0, 0),
                    duration=0,
                    arrow_pos='bottom_mid',
                    width=None,
                    icon='',
                    modal=False):
        '''Method to show a Information Bubble

        .. parameters::
            text: Message to be displayed
            pos: position for the bubble
            duration: duration the bubble remains on screen. 0 = click to hide
            width: width of the Bubble
            arrow_pos: arrow position for the bubble
        '''

        info_bubble = self.info_bubble
        if not info_bubble:
            info_bubble = self.info_bubble = InfoBubble()

        if info_bubble.parent:
            info_bubble.hide()
            return

        if not arrow_pos:
            info_bubble.show_arrow = False
        else:
            info_bubble.show_arrow = True
            info_bubble.arrow_pos = arrow_pos
        img = info_bubble.ids.img
        if text == 'texture':
            # icon holds a texture not a source image
            # display the texture in full screen
            text = ''
            img.texture = icon
            info_bubble.fs = True
            info_bubble.show_arrow = False
            img.allow_stretch = True
            info_bubble.dim_background = True
            pos = (Window.center[0], Window.center[1] - info_bubble.center[1])
            info_bubble.background_image = 'atlas://gui/kivy/theming/light/card'
        else:
            info_bubble.fs = False
            info_bubble.icon = icon
            if img.texture and img._coreimage:
                img.reload()
            img.allow_stretch = False
            info_bubble.dim_background = False
            info_bubble.background_image = 'atlas://data/images/defaulttheme/bubble'
        info_bubble.message = text
        info_bubble.show(pos, duration, width, modal=modal)
