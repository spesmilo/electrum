''' Dialogs and widgets Responsible for creation, restoration of accounts are
defined here.

Namely: CreateAccountDialog, CreateRestoreDialog, RestoreSeedDialog
'''

from functools import partial

from kivy.app import App
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.properties import ObjectProperty, StringProperty, OptionProperty
from kivy.core.window import Window
from kivy.uix.button import Button

from electrum_gui.kivy.uix.dialogs import EventsDialog
from electrum_gui.kivy.i18n import _


Builder.load_string('''
#:import Window kivy.core.window.Window
#:import _ electrum_gui.kivy.i18n._


<WizardTextInput@TextInput>
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

<WizardButton@Button>:
    root: None
    size_hint: 1, None
    height: '48sp'
    on_press: if self.root: self.root.dispatch('on_press', self)
    on_release: if self.root: self.root.dispatch('on_release', self)


<-WizardDialog>
    text_color: .854, .925, .984, 1
    #auto_dismiss: False
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
    BoxLayout:
        orientation: 'vertical' if self.width < self.height else 'horizontal'
        padding:
            min(dp(27), self.width/32), min(dp(27), self.height/32),\
            min(dp(27), self.width/32), min(dp(27), self.height/32)
        spacing: '10dp'
        GridLayout:
            id: grid_logo
            cols: 1
            pos_hint: {'center_y': .5}
            size_hint: 1, None
            height: self.minimum_height
            Label:
                color: root.text_color
                text: 'ELECTRUM'
                size_hint: 1, None
                height: self.texture_size[1] if self.opacity else 0
                font_size: '33sp'
                font_name: 'gui/kivy/data/fonts/tron/Tr2n.ttf'
        GridLayout:
            cols: 1
            id: crcontent
            spacing: '1dp'


<CreateRestoreDialog>
    Image:
        id: logo_img
        mipmap: True
        allow_stretch: True
        size_hint: 1, None
        height: '110dp'
        source: 'atlas://gui/kivy/theming/light/electrum_icon640'
    Widget:
        size_hint: 1, 1
    Label:
        color: root.text_color
        size_hint: 1, None
        text_size: self.width, None
        height: self.texture_size[1]
        text:
            _("Creating a new wallet.")+" " +\
            _("Do you want to create a new seed, or to restore a wallet using an existing seed?")
    Widget
        size_hint: 1, 1
    GridLayout:
        id: grid
        orientation: 'vertical'
        cols: 1
        spacing: '14dp'
        size_hint: 1, None
        height: self.minimum_height
        WizardButton:
            id: create
            text: _('Create a new seed')
            root: root
        WizardButton:
            id: restore_seed
            text: _('I already have a seed')
            root: root
        WizardButton:
            id: restore_xpub
            text: _('Watching-only wallet')
            root: root


<MButton@Button>:
    size_hint: 1, None
    height: '33dp'
    on_release:
        self.parent.update_amount(self.text)

<WordButton@Button>:
    size_hint: None, None
    padding: '5dp', '5dp'
    text_size: None, self.height
    width: self.texture_size[0]
    height: '30dp'
    on_release:
        self.parent.new_word(self.text)


<SeedButton@Button>:
    height: dp(100)
    border: 4, 4, 4, 4
    halign: 'justify'
    valign: 'top'
    font_size: '18dp'
    text_size: self.width - dp(24), self.height - dp(12)
    color: .1, .1, .1, 1
    background_normal: 'atlas://gui/kivy/theming/light/white_bg_round_top'
    background_down: self.background_normal
    size_hint_y: None


<SeedLabel@Label>:
    font_size: '12sp'
    text_size: self.width, None
    size_hint: 1, None
    height: self.texture_size[1]
    halign: 'justify'
    valign: 'middle'
    border: 4, 4, 4, 4


<RestoreSeedDialog>
    word: ''
    Label:
        color: root.text_color
        size_hint: 1, None
        text_size: self.width, None
        height: self.texture_size[1]
        text: "[b]ENTER YOUR SEED PHRASE[/b]"
    GridLayout
        cols: 1
        padding: 0, '12dp'
        orientation: 'vertical'
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        SeedButton:
            id: text_input_seed
            text: ''
            on_text: Clock.schedule_once(root.on_text)
        SeedLabel:
            text: root.message
        BoxLayout:
            id: suggestions
            height: '35dp'
            size_hint: 1, None
            new_word: root.on_word
        BoxLayout:
            id: line1
            update_amount: root.update_text
            size_hint: 1, None
            height: '30dp'
            MButton:
                text: 'Q'
            MButton:
                text: 'W'
            MButton:
                text: 'E'
            MButton:
                text: 'R'
            MButton:
                text: 'T'
            MButton:
                text: 'Y'
            MButton:
                text: 'U'
            MButton:
                text: 'I'
            MButton:
                text: 'O'
            MButton:
                text: 'P'
        BoxLayout:
            id: line2
            update_amount: root.update_text
            size_hint: 1, None
            height: '30dp'
            Widget:
                size_hint: 0.5, None
                height: '33dp'
            MButton:
                text: 'A'
            MButton:
                text: 'S'
            MButton:
                text: 'D'
            MButton:
                text: 'F'
            MButton:
                text: 'G'
            MButton:
                text: 'H'
            MButton:
                text: 'J'
            MButton:
                text: 'K'
            MButton:
                text: 'L'
            Widget:
                size_hint: 0.5, None
                height: '33dp'
        BoxLayout:
            id: line3
            update_amount: root.update_text
            size_hint: 1, None
            height: '30dp'
            Widget:
                size_hint: 1, None
            MButton:
                text: 'Z'
            MButton:
                text: 'X'
            MButton:
                text: 'C'
            MButton:
                text: 'V'
            MButton:
                text: 'B'
            MButton:
                text: 'N'
            MButton:
                text: 'M'
            MButton:
                text: ' '
            MButton:
                text: '<'
    Widget:
        size_hint: 1, 1

    GridLayout:
        rows: 1
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        WizardButton:
            id: back
            text: _('Back')
            root: root
        WizardButton:
            id: next
            text: _('Next')
            root: root
            disabled: True


<RestoreXpubDialog>
    word: ''
    Label:
        color: root.text_color
        size_hint: 1, None
        text_size: self.width, None
        height: self.texture_size[1]
        text: "[b]MASTER PUBLIC KEY[/b]"
    GridLayout
        cols: 1
        padding: 0, '12dp'
        orientation: 'vertical'
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        SeedButton:
            id: text_input_seed
            text: ''
            on_text: Clock.schedule_once(root.on_text)
        SeedLabel:
            text: root.message

    GridLayout:
        rows: 1
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        IconButton:
            id: scan
            height: '48sp'
            on_release: root.scan_xpub()
            icon: 'atlas://gui/kivy/theming/light/camera'
            size_hint: 1, None
        WizardButton:
            text: _('Paste')
            on_release: root.do_paste()
        WizardButton:
            text: _('Clear')
            on_release: root.do_clear()

    Widget:
        size_hint: 1, 1

    GridLayout:
        rows: 1
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        WizardButton:
            id: back
            text: _('Back')
            root: root
        WizardButton:
            id: next
            text: _('Next')
            root: root
            disabled: True


<ShowSeedDialog>
    spacing: '12dp'
    Label:
        color: root.text_color
        size_hint: 1, None
        text_size: self.width, None
        height: self.texture_size[1]
        text: "[b]PLEASE WRITE DOWN YOUR SEED PHRASE[/b]"
    GridLayout:
        id: grid
        cols: 1
        pos_hint: {'center_y': .5}
        size_hint_y: None
        height: self.minimum_height
        orientation: 'vertical'
        spacing: '12dp'
        SeedButton:
            text: root.seed_text
        SeedLabel:
            text: root.message
    Widget:
        size_hint: 1, 1
    GridLayout:
        rows: 1
        spacing: '12dp'
        size_hint: 1, None
        height: self.minimum_height
        WizardButton:
            id: back
            text: _('Back')
            root: root
        WizardButton:
            id: confirm
            text: _('Confirm')
            root: root
''')


class WizardDialog(EventsDialog):
    ''' Abstract dialog to be used as the base for all Create Account Dialogs
    '''
    crcontent = ObjectProperty(None)

    def __init__(self, **kwargs):
        super(WizardDialog, self).__init__(**kwargs)
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
            super(WizardDialog, self).add_widget(widget)
        else:
            self.crcontent.add_widget(widget, index=index)

    def on_dismiss(self):
        app = App.get_running_app()
        if app.wallet is None and self._on_release is not None:
            app.stop()


class CreateRestoreDialog(WizardDialog):
    ''' Initial Dialog for creating or restoring seed'''

    def on_parent(self, instance, value):
        if value:
            app = App.get_running_app()
            self._back = _back = partial(app.dispatch, 'on_back')


class ShowSeedDialog(WizardDialog):

    seed_text = StringProperty('')
    message = StringProperty('')

    def on_parent(self, instance, value):
        if value:
            app = App.get_running_app()
            self._back = _back = partial(self.ids.back.dispatch, 'on_release')


class WordButton(Button):
    pass

class RestoreSeedDialog(WizardDialog):

    message = StringProperty('')

    def __init__(self, **kwargs):
        super(RestoreSeedDialog, self).__init__(**kwargs)
        self._test = kwargs['test']
        from electrum.mnemonic import Mnemonic
        from electrum.old_mnemonic import words as old_wordlist
        self.words = set(Mnemonic('en').wordlist).union(set(old_wordlist))

    def get_suggestions(self, prefix):
        for w in self.words:
            if w.startswith(prefix):
                yield w

    def on_text(self, dt):
        self.ids.next.disabled = not bool(self._test(self.get_text()))

        text = self.ids.text_input_seed.text
        if not text:
            last_word = ''
        elif text[-1] == ' ':
            last_word = ''
        else:
            last_word = text.split(' ')[-1]

        enable_space = False
        self.ids.suggestions.clear_widgets()
        suggestions = [x for x in self.get_suggestions(last_word)]
        if suggestions and len(suggestions) < 10:
            for w in suggestions:
                if w == last_word:
                    enable_space = True
                else:
                    b = WordButton(text=w)
                    self.ids.suggestions.add_widget(b)

        i = len(last_word)
        p = set()
        for x in suggestions:
            if len(x)>i: p.add(x[i])

        for line in [self.ids.line1, self.ids.line2, self.ids.line3]:
            for c in line.children:
                if isinstance(c, Button):
                    if c.text in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                        c.disabled = (c.text.lower() not in p) and last_word
                    elif c.text == ' ':
                        c.disabled = not enable_space

    def on_word(self, w):
        text = self.get_text()
        words = text.split(' ')
        words[-1] = w
        text = ' '.join(words)
        self.ids.text_input_seed.text = text + ' '
        self.ids.suggestions.clear_widgets()

    def get_text(self):
        ti = self.ids.text_input_seed
        text = unicode(ti.text).strip()
        text = ' '.join(text.split())
        return text

    def update_text(self, c):
        c = c.lower()
        text = self.ids.text_input_seed.text
        if c == '<':
            text = text[:-1]
        else:
            text += c
        self.ids.text_input_seed.text = text

    def on_parent(self, instance, value):
        if value:
            tis = self.ids.text_input_seed
            tis.focus = True
            #tis._keyboard.bind(on_key_down=self.on_key_down)
            self._back = _back = partial(self.ids.back.dispatch,
                                         'on_release')
            app = App.get_running_app()

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

class RestoreXpubDialog(WizardDialog):

    message = StringProperty('')

    def __init__(self, **kwargs):
        super(RestoreXpubDialog, self).__init__(**kwargs)
        self._test = kwargs['test']
        self.app = App.get_running_app()

    def get_text(self):
        ti = self.ids.text_input_seed
        return unicode(ti.text).strip()

    def on_text(self, dt):
        self.ids.next.disabled = not bool(self._test(self.get_text()))

    def scan_xpub(self):
        def on_complete(text):
            self.ids.text_input_seed.text = text
        self.app.scan_qr(on_complete)

    def do_paste(self):
        self.ids.text_input_seed.text = unicode(self.app._clipboard.paste())

    def do_clear(self):
        self.ids.text_input_seed.text = ''
