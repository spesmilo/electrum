''' Dialogs and widgets Responsible for creation, restoration of accounts are
defined here.

Namely: CreateAccountDialog, CreateRestoreDialog, ChangePasswordDialog,
RestoreSeedDialog
'''

from functools import partial

from kivy.app import App
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.properties import ObjectProperty, StringProperty, OptionProperty
from kivy.core.window import Window

from electrum_gui.kivy.uix.dialogs import EventsDialog

from electrum.i18n import _


Builder.load_string('''
#:import Window kivy.core.window.Window
#:import _ electrum.i18n._


<CreateAccountTextInput@TextInput>
    border: 4, 4, 4, 4
    font_size: '15sp'
    padding: '15dp', '15dp'
    background_color: (1, 1, 1, 1) if self.focus else (0.454, 0.698, 0.909, 1)
    foreground_color: (0.31, 0.31, 0.31, 1) if self.focus else (0.835, 0.909, 0.972, 1)
    hint_text_color: self.foreground_color
    background_active: 'atlas://gui/kivy/theming/light/create_act_text_active'
    background_normal: 'atlas://gui/kivy/theming/light/create_act_text_active'
    size_hint_y: None
    height: '48sp'

<CreateAccountButton@Button>:
    root: None
    size_hint: 1, None
    height: '48sp'
    on_press: if self.root: self.root.dispatch('on_press', self)
    on_release: if self.root: self.root.dispatch('on_release', self)



<-CreateAccountDialog>
    text_color: .854, .925, .984, 1
    auto_dismiss: False
    size_hint: None, None
    canvas.before:
        Color:
            rgba: 0, 0, 0, .9
        Rectangle:
            size: Window.size
        Color:
            rgba: .239, .588, .882, 1
        Rectangle:
            size: Window.size

    crcontent: crcontent
    # add electrum icon
    FloatLayout:
        size_hint: None, None
        size: 0, 0
        IconButton:
            id: but_close
            size_hint: None, None
            size: '27dp', '27dp'
            top: Window.height - dp(10)
            right: Window.width - dp(10)
            source: 'atlas://gui/kivy/theming/light/closebutton'
            on_release: root.dispatch('on_press', self)
            on_release: root.dispatch('on_release', self)
    BoxLayout:
        orientation: 'vertical' if self.width < self.height else 'horizontal'
        padding:
            min(dp(42), self.width/8), min(dp(60), self.height/9.7),\
            min(dp(42), self.width/8), min(dp(72), self.height/8)
        spacing: '27dp'
        GridLayout:
            id: grid_logo
            cols: 1
            pos_hint: {'center_y': .5}
            size_hint: 1, .62
            #height: self.minimum_height
            Image:
                id: logo_img
                mipmap: True
                allow_stretch: True
                size_hint: 1, None
                height: '110dp'
                source: 'atlas://gui/kivy/theming/light/electrum_icon640'
            Widget:
                size_hint: 1, None
                height: 0 if stepper.opacity else dp(15)
            Label:
                color: root.text_color
                opacity: 0 if stepper.opacity else 1
                text: 'ELECTRUM'
                size_hint: 1, None
                height: self.texture_size[1] if self.opacity else 0
                font_size: '33sp'
                font_name: 'data/fonts/tron/Tr2n.ttf'
            Image:
                id: stepper
                allow_stretch: True
                opacity: 0
                source: 'atlas://gui/kivy/theming/light/stepper_left'
                size_hint: 1, None
                height: grid_logo.height/2.5 if self.opacity else 0
        Widget:
            size_hint: None, None
            size: '5dp', '5dp'
        GridLayout:
            cols: 1
            id: crcontent
            spacing: '13dp'


<CreateRestoreDialog>
    Label:
        color: root.text_color
        size_hint: 1, None
        text_size: self.width, None
        height: self.texture_size[1]
        text:
            _("Wallet file not found!!")+"\\n\\n" +\
            _("Do you want to create a new wallet ")+\
            _("or restore an existing one?")
    Widget
        size_hint: 1, None
        height: dp(15)
    GridLayout:
        id: grid
        orientation: 'vertical'
        cols: 1
        spacing: '14dp'
        size_hint: 1, None
        height: self.minimum_height
        CreateAccountButton:
            id: create
            text: _('Create a Wallet')
            root: root
        CreateAccountButton:
            id: restore
            text: _('I already have a wallet')
            root: root


<RestoreSeedDialog>
    GridLayout
        cols: 1
        padding: 0, '12dp'
        orientation: 'vertical'
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        CreateAccountTextInput:
            id: text_input_seed
            size_hint: 1, None
            height: '110dp'
            hint_text:
                _('Enter your seedphrase')
            on_text: root._trigger_check_seed()
        Label:
            font_size: '12sp'
            text_size: self.width, None
            size_hint: 1, None
            height: self.texture_size[1]
            halign: 'justify'
            valign: 'middle'
            text:
                _('If you need additional information, please check '
                '[color=#0000ff][ref=1]'
                'https://electrum.org/faq.html#seed[/ref][/color]')
            on_ref_press:
                import webbrowser
                webbrowser.open('https://electrum.org/faq.html#seed')
    GridLayout:
        rows: 1
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        CreateAccountButton:
            id: back
            text: _('Back')
            root: root
        CreateAccountButton:
            id: next
            text: _('Next')
            root: root


<InitSeedDialog>
    spacing: '12dp'
    GridLayout:
        id: grid
        cols: 1
        pos_hint: {'center_y': .5}
        size_hint_y: None
        height: dp(180)
        orientation: 'vertical'
        Button:
            border: 4, 4, 4, 4
            halign: 'justify'
            valign: 'middle'
            font_size: self.width/21
            text_size: self.width - dp(24), self.height - dp(12)
            #size_hint: 1, None
            #height: self.texture_size[1] + dp(24)
            background_normal: 'atlas://gui/kivy/theming/light/white_bg_round_top'
            background_down: self.background_normal
            text: root.message
        GridLayout:
            rows: 1
            size_hint: 1, .7
            #size_hint_y: None
            #height: but_seed.texture_size[1] + dp(24)
            Button:
                id: but_seed
                border: 4, 4, 4, 4
                halign: 'justify'
                valign: 'middle'
                font_size: self.width/15
                text: root.seed_msg
                text_size: self.width - dp(24), self.height - dp(12)
                background_normal: 'atlas://gui/kivy/theming/light/lightblue_bg_round_lb'
                background_down: self.background_normal
            Button:
                id: bt
                size_hint_x: .25
                background_normal: 'atlas://gui/kivy/theming/light/blue_bg_round_rb'
                background_down: self.background_normal
                Image:
                    mipmap: True
                    source: 'atlas://gui/kivy/theming/light/qrcode'
                    size: bt.size
                    center: bt.center
                 #on_release:
    GridLayout:
        rows: 1
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        CreateAccountButton:
            id: back
            text: _('Back')
            root: root
        CreateAccountButton:
            id: confirm
            text: _('Confirm')
            root: root


<ChangePasswordDialog>
    padding: '7dp'
    GridLayout:
        size_hint_y: None
        height: self.minimum_height
        cols: 1
        CreateAccountTextInput:
            id: ti_wallet_name
            hint_text: 'Your Wallet Name'
            multiline: False
            on_text_validate:
                next = ti_new_password if ti_password.disabled else ti_password
                next.focus = True
        Widget:
            size_hint_y: None
            height: '13dp'
        CreateAccountTextInput:
            id: ti_password
            hint_text: 'Enter old pincode'
            size_hint_y: None
            height: 0 if self.disabled else '38sp'
            password: True
            disabled: True if root.mode in ('new', 'create', 'restore') else False
            opacity: 0 if self.disabled else 1
            multiline: False
            on_text_validate:
                ti_new_password.focus = True
        Widget:
            size_hint_y: None
            height: 0 if ti_password.disabled else '13dp'
        CreateAccountTextInput:
            id: ti_new_password
            hint_text: 'Enter new pincode'
            multiline: False
            password: True
            on_text_validate: ti_confirm_password.focus = True
        Widget:
            size_hint_y: None
            height: '13dp'
        CreateAccountTextInput:
            id: ti_confirm_password
            hint_text: 'Confirm pincode'
            password: True
            multiline: False
            on_text_validate: root.validate_new_password()
    Widget
    GridLayout:
        rows: 1
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        CreateAccountButton:
            id: back
            text: _('Back')
            root: root
            disabled: True if root.mode[0] == 'r' else self.disabled
        CreateAccountButton:
            id: next
            text: _('Confirm') if root.mode[0] == 'r' else _('Next')
            root: root

''')


class CreateAccountDialog(EventsDialog):
    ''' Abstract dialog to be used as the base for all Create Account Dialogs
    '''
    crcontent = ObjectProperty(None)

    def __init__(self, **kwargs):
        super(CreateAccountDialog, self).__init__(**kwargs)
        self.action = kwargs.get('action')
        _trigger_size_dialog = Clock.create_trigger(self._size_dialog)
        Window.bind(size=_trigger_size_dialog,
                    rotation=_trigger_size_dialog)
        _trigger_size_dialog()

    def _size_dialog(self, dt):
        app = App.get_running_app()
        if app.ui_mode[0] == 'p':
            self.size = Window.size
        else:
            #tablet
            if app.orientation[0] == 'p':
                #portrait
                self.size = Window.size[0]/1.67, Window.size[1]/1.4
            else:
                self.size = Window.size[0]/2.5, Window.size[1]

    def add_widget(self, widget, index=0):
        if not self.crcontent:
            super(CreateAccountDialog, self).add_widget(widget)
        else:
            self.crcontent.add_widget(widget, index=index)


class CreateRestoreDialog(CreateAccountDialog):
    ''' Initial Dialog for creating or restoring seed'''

    def on_parent(self, instance, value):
        if value:
            app = App.get_running_app()
            self.ids.but_close.disabled = True
            self.ids.but_close.opacity = 0
            self._back = _back = partial(app.dispatch, 'on_back')
            #app.navigation_higherarchy.append(_back)

    def close(self):
        app = App.get_running_app()
        #if self._back in app.navigation_higherarchy:
        #    app.navigation_higherarchy.pop()
        #    self._back = None
        super(CreateRestoreDialog, self).close()


class ChangePasswordDialog(CreateAccountDialog):

    message = StringProperty(_('Empty Message'))
    '''Message to be displayed.'''

    mode = OptionProperty('new',
                          options=('new', 'confirm', 'create', 'restore'))
    ''' Defines the mode of the password dialog.'''

    def validate_new_password(self):
        self.ids.next.dispatch('on_release')

    def on_parent(self, instance, value):
        if value:
            # change the stepper image used to indicate the current state
            stepper = self.ids.stepper
            stepper.opacity = 1
            t_wallet_name = self.ids.ti_wallet_name
            if self.mode in ('create', 'restore'):
                t_wallet_name.text = 'Default Wallet'
                t_wallet_name.readonly = True
                #self.ids.ti_new_password.focus = True
            else:
                t_wallet_name.text = ''
                t_wallet_name.readonly = False
                #t_wallet_name.focus = True
            stepper.source = 'atlas://gui/kivy/theming/light/stepper_left'
            self._back = _back = partial(self.ids.back.dispatch, 'on_release')
            app = App.get_running_app()
            #app.navigation_higherarchy.append(_back)

    def close(self):
        ids = self.ids
        ids.ti_wallet_name.text = ""
        ids.ti_wallet_name.focus = False
        ids.ti_password.text = ""
        ids.ti_password.focus = False
        ids.ti_new_password.text = ""
        ids.ti_new_password.focus = False
        ids.ti_confirm_password.text = ""
        ids.ti_confirm_password.focus = False
        app = App.get_running_app()
        #if self._back in app.navigation_higherarchy:
        #    app.navigation_higherarchy.pop()
        #    self._back = None
        super(ChangePasswordDialog, self).close()


class InitSeedDialog(CreateAccountDialog):

    mode = StringProperty('create')
    ''' Defines the mode for which to optimize the UX. defaults to 'create'.
        
        Can be one of: 'create', 'restore', 'create_2of2', 'create_2fa'...
    '''

    seed_msg = StringProperty('')
    '''Text to be displayed in the TextInput'''

    message = StringProperty('')
    '''Message to be displayed under seed'''

    seed = ObjectProperty(None)

    def on_parent(self, instance, value):
        if value:
            app = App.get_running_app()
            stepper = self.ids.stepper
            stepper.opacity = 1
            stepper.source = 'atlas://gui/kivy/theming/light/stepper_full'
            self._back = _back = partial(self.ids.back.dispatch, 'on_release')
            #app.navigation_higherarchy.append(_back)

    def close(self):
        app = App.get_running_app()
        #if self._back in app.navigation_higherarchy:
        #    app.navigation_higherarchy.pop()
        #    self._back = None
        super(InitSeedDialog, self).close()


class RestoreSeedDialog(CreateAccountDialog):

    def __init__(self, **kwargs):
        self._wizard = kwargs['wizard']
        super(RestoreSeedDialog, self).__init__(**kwargs)
        self._trigger_check_seed = Clock.create_trigger(self.check_seed)

    def check_seed(self, dt):
        self.ids.next.disabled = not bool(self._wizard.is_any(
                                                    self.ids.text_input_seed))

    def on_parent(self, instance, value):
        if value:
            tis = self.ids.text_input_seed
            tis.focus = True
            tis._keyboard.bind(on_key_down=self.on_key_down)
            stepper = self.ids.stepper
            stepper.opacity = 1
            stepper.source = ('atlas://gui/kivy/theming'
                              '/light/stepper_restore_seed')
            self._back = _back = partial(self.ids.back.dispatch,
                                         'on_release')
            app = App.get_running_app()
            #app.navigation_higherarchy.append(_back)

    def on_key_down(self, keyboard, keycode, key, modifiers):
        if keycode[0] in (13, 271):
            self.on_enter()
            return True

    def on_enter(self):
        #self._remove_keyboard()
        # press next
        next = self.ids.next
        if not next.disabled:
            next.dispatch('on_release')

    def _remove_keyboard(self):
        tis = self.ids.text_input_seed
        if tis._keyboard:
            tis._keyboard.unbind(on_key_down=self.on_key_down)
            tis.focus = False

    def close(self):
        self._remove_keyboard()
        app = App.get_running_app()
        #if self._back in app.navigation_higherarchy:
        #    app.navigation_higherarchy.pop()
        #    self._back = None
        super(RestoreSeedDialog, self).close()
