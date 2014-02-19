from functools import partial

from kivy.app import App
from kivy.factory import Factory
from kivy.uix.button import Button
from kivy.uix.bubble import Bubble
from kivy.uix.popup import Popup
from kivy.uix.widget import Widget
from kivy.uix.carousel import Carousel
from kivy.uix.tabbedpanel import TabbedPanelHeader
from kivy.properties import (NumericProperty, StringProperty, ListProperty,
                             ObjectProperty, AliasProperty, OptionProperty,
                             BooleanProperty)

from kivy.animation import Animation
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.metrics import dp, inch

#from electrum.bitcoin import is_valid
from electrum.i18n import _

# Delayed inits
QRScanner = None
NFCSCanner = None
ScreenAddress = None
decode_uri = None

DEFAULT_PATH = '/tmp/'
app = App.get_running_app()

class CarouselHeader(TabbedPanelHeader):

    slide = NumericProperty(0)
    ''' indicates the link to carousels slide'''

class AnimatedPopup(Popup):

    def open(self):
        self.opacity = 0
        super(AnimatedPopup, self).open()
        anim = Animation(opacity=1, d=.5).start(self)

    def dismiss(self):
        def on_complete(*l):
            super(AnimatedPopup, self).dismiss()
        anim = Animation(opacity=0, d=.5)
        anim.bind(on_complete=on_complete)
        anim.start(self)


class CarouselDialog(AnimatedPopup):
    ''' A Popup dialog with a CarouselIndicator used as the content.
    '''

    carousel_content = ObjectProperty(None)

    def open(self):
        self.opacity = 0
        super(CarouselDialog, self).open()
        anim = Animation(opacity=1, d=.5).start(self)

    def dismiss(self):
        def on_complete(*l):
            super(CarouselDialog, self).dismiss()
        anim = Animation(opacity=0, d=.5)
        anim.bind(on_complete=on_complete)
        anim.start(self)

    def add_widget(self, widget, index=0):
        if isinstance(widget, Carousel):
            super(CarouselDialog, self).add_widget(widget, index)
            return
        if 'carousel_content' not in self.ids.keys():
            super(CarouselDialog, self).add_widget(widget)
            return
        self.carousel_content.add_widget(widget, index)



class NFCTransactionDialog(AnimatedPopup):

    mode = OptionProperty('send', options=('send','receive'))

    scanner = ObjectProperty(None)

    def __init__(self, **kwargs):
        # Delayed Init
        global NFCSCanner
        if NFCSCanner is None:
            from electrum_gui.kivy.nfc_scanner import NFCScanner
        self.scanner = NFCSCanner

        super(NFCTransactionDialog, self).__init__(**kwargs)
        self.scanner.nfc_init()
        self.scanner.bind()

    def on_parent(self, instance, value):
        sctr = self.ids.sctr
        if value:
            def _cmp(*l):
                anim = Animation(rotation=2, scale=1, opacity=1)
                anim.start(sctr)
                anim.bind(on_complete=_start)

            def _start(*l):
                anim = Animation(rotation=350, scale=2, opacity=0)
                anim.start(sctr)
                anim.bind(on_complete=_cmp)
            _start()
            return
        Animation.cancel_all(sctr)


class InfoBubble(Bubble):
    '''Bubble to be used to display short Help Information'''

    message = StringProperty(_('Nothing set !'))
    '''Message to be displayed defaults to "nothing set"'''

    icon = StringProperty('')
    ''' Icon to be displayed along with the message defaults to ''
    '''

    fs = BooleanProperty(False)
    ''' Show Bubble in half screen mode
    '''

    modal = BooleanProperty(False)
    ''' Allow bubble to be hidden on touch.
    '''

    exit = BooleanProperty(False)
    ''' exit app after bubble is closes
    '''

    dim_background = BooleanProperty(False)
    ''' Whether to draw a background on the windows behind the bubble
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
        ''' Auto fade out the Bubble
        '''
        def on_stop(*l):
            Window.remove_widget(self)
            if self.exit:
                App.get_running_app().stop()
                import sys
                sys.exit()

        anim = Animation(opacity=0, d=.25)
        anim.bind(on_complete=on_stop)
        anim.cancel_all(self)
        anim.start(self)


class InfoContent(Widget):
    '''Abstract class to be used to add to content to InfoDialog'''
    pass


class InfoButton(Button):
    '''Button that is auto added to the dialog when setting `buttons:`
    property.
    '''
    pass


class EventsDialog(AnimatedPopup):
    ''' Abstract Popup that provides the following events
    .. events::
        `on_release`
        `on_press`
    '''

    __events__ = ('on_release', 'on_press')

    def __init__(self, **kwargs):
        super(EventsDialog, self).__init__(**kwargs)
        self._on_release = kwargs.get('on_release')
        Window.bind(size=self.on_size,
                    rotation=self.on_size)
        self.on_size(Window, Window.size)

    def on_size(self, instance, value):
        if app.ui_mode[0] == 'p':
            self.size = Window.size
        else:
            #tablet
            if app.orientation[0] == 'p':
                #portrait
                self.size = Window.size[0]/1.67, Window.size[1]/1.4
            else:
                self.size = Window.size[0]/2.5, Window.size[1]

    def on_release(self, instance):
        pass

    def on_press(self, instance):
        pass

    def close(self):
        self._on_release = None
        self.dismiss()


class InfoDialog(EventsDialog):
    ''' A dialog box meant to display info along with buttons at the bottom

    '''

    buttons = ListProperty([_('ok'), _('cancel')])
    '''List of Buttons to be displayed at the bottom'''

    def __init__(self, **kwargs):
        self._old_buttons = self.buttons
        super(InfoDialog, self).__init__(**kwargs)
        self.on_buttons(self, self.buttons)

    def on_buttons(self, instance, value):
        if 'buttons_layout' not in self.ids.keys():
            return
        if value == self._old_buttons:
            return
        blayout = self.ids.buttons_layout
        blayout.clear_widgets()
        for btn in value:
            ib = InfoButton(text=btn)
            ib.bind(on_press=partial(self.dispatch, 'on_press'))
            ib.bind(on_release=partial(self.dispatch, 'on_release'))
            blayout.add_widget(ib)
        self._old_buttons = value
        pass

    def add_widget(self, widget, index=0):
        if isinstance(widget, InfoContent):
            self.ids.info_content.add_widget(widget, index=index)
        else:
            super(InfoDialog, self).add_widget(widget)


class TakeInputDialog(InfoDialog):
    ''' A simple Dialog for displaying a message and taking a input
    using a Textinput
    '''

    text = StringProperty('Nothing set yet')

    readonly = BooleanProperty(False)


class EditLabelDialog(TakeInputDialog):
    pass



class ImportPrivateKeysDialog(TakeInputDialog):
    pass



class ShowMasterPublicKeyDialog(TakeInputDialog):
    pass


class EditDescriptionDialog(TakeInputDialog):

    pass


class PrivateKeyDialog(InfoDialog):

    private_key = StringProperty('')
    ''' private key to be displayed in the TextInput
    '''

    address = StringProperty('')
    ''' address to be displayed in the dialog
    '''


class SignVerifyDialog(InfoDialog):

    address = StringProperty('')
    '''current address being verified'''



class MessageBox(InfoDialog):

    image = StringProperty('atlas://gui/kivy/theming/light/info')
    '''path to image to be displayed on the left'''

    message = StringProperty('Empty Message')
    '''Message to be displayed on the dialog'''

    def __init__(self, **kwargs):
        super(MessageBox, self).__init__(**kwargs)
        self.title = kwargs.get('title', _('Message'))


class MessageBoxExit(MessageBox):

    def __init__(self, **kwargs):
        super(MessageBox, self).__init__(**kwargs)
        self.title = kwargs.get('title', _('Exiting'))

class MessageBoxError(MessageBox):

    def __init__(self, **kwargs):
        super(MessageBox, self).__init__(**kwargs)
        self.title = kwargs.get('title', _('Error'))


class WalletAddressesDialog(CarouselDialog):

    def __init__(self, **kwargs):
        super(WalletAddressesDialog, self).__init__(**kwargs)
        CarouselHeader = Factory.CarouselHeader
        ch = CarouselHeader()
        ch.slide = 0 # idx

        # delayed init
        global ScreenAddress
        if not ScreenAddress:
            from electrum_gui.kivy.screens import ScreenAddress
        slide = ScreenAddress()

        slide.tab=ch

        labels = app.wallet.labels
        addresses = app.wallet.addresses()
        _labels = {}
        for address in addresses:
            _labels[labels.get(address, address)] = address

        slide.labels = _labels

        self.add_widget(slide)
        self.add_widget(ch)
        Clock.schedule_once(lambda dt: self.delayed_init(slide))

    def delayed_init(self, slide):
        # add a tab for each wallet
        # for wallet in wallets
        slide.ids.btn_address.values = values = slide.labels.keys()
        slide.ids.btn_address.text = values[0]



class RecentActivityDialog(CarouselDialog):

    def send_payment(self, address):
        tabs = app.root.main_screen.ids.tabs
        screen_send = tabs.ids.screen_send
        # remove self
        self.dismiss()
        # switch_to the send screen
        tabs.ids.panel.switch_to(tabs.ids.tab_send)
        # populate
        screen_send.ids.payto_e.text = address

    def populate_inputs_outputs(self, app, tx_hash):
        if tx_hash:
            tx = app.wallet.transactions.get(tx_hash)
            self.ids.list_outputs.content_adapter.data = \
                [(address, app.gui.main_gui.format_amount(value))\
                for address, value in tx.outputs]
            self.ids.list_inputs.content_adapter.data = \
                [(input['address'], input['prevout_hash'])\
                for input in tx.inputs]


class CreateAccountDialog(EventsDialog):
    ''' Abstract dialog to be used as the base for all Create Account Dialogs
    '''
    crcontent = ObjectProperty(None)

    def add_widget(self, widget, index=0):
        if not self.crcontent:
            super(CreateAccountDialog, self).add_widget(widget)
        else:
            self.crcontent.add_widget(widget, index=index)


class CreateRestoreDialog(CreateAccountDialog):
    ''' Initial Dialog for creating or restoring seed'''

    def on_parent(self, instance, value):
        if value:
            self.ids.but_close.disabled = True
            self.ids.but_close.opacity = 0
            self._back = _back = partial(app.dispatch, 'on_back')
            app.navigation_higherarchy.append(_back)

    def close(self):
        if self._back in app.navigation_higherarchy:
            app.navigation_higherarchy.pop()
            self._back = None
        super(CreateRestoreDialog, self).close()


class InitSeedDialog(CreateAccountDialog):

    seed_msg = StringProperty('')
    '''Text to be displayed in the TextInput'''

    message = StringProperty('')
    '''Message to be displayed under seed'''

    seed = ObjectProperty(None)

    def on_parent(self, instance, value):
        if value:
            stepper = self.ids.stepper
            stepper.opacity = 1
            stepper.source = 'atlas://gui/kivy/theming/light/stepper_full'
            self._back = _back = partial(self.ids.back.dispatch, 'on_release')
            app.navigation_higherarchy.append(_back)

    def close(self):
        if self._back in app.navigation_higherarchy:
            app.navigation_higherarchy.pop()
            self._back = None
        super(InitSeedDialog, self).close()

class VerifySeedDialog(CreateAccountDialog):

    pass

class RestoreSeedDialog(CreateAccountDialog):

    def on_parent(self, instance, value):
        if value:
            stepper = self.ids.stepper;
            stepper.opacity = 1
            stepper.source = 'atlas://gui/kivy/theming/light/stepper_restore_seed'
            self._back = _back = partial(self.ids.back.dispatch, 'on_release')
            app.navigation_higherarchy.append(_back)

    def close(self):
        if self._back in app.navigation_higherarchy:
            app.navigation_higherarchy.pop()
            self._back = None
        super(RestoreSeedDialog, self).close()

class NewContactDialog(Popup):

    qrscr = ObjectProperty(None)
    _decoder = None

    def load_qr_scanner(self):
        global QRScanner
        if not QRScanner:
            from electrum_gui.kivy.qr_scanner import QRScanner
        qrscr = self.qrscr
        if not qrscr:
            self.qrscr = qrscr = QRScanner(opacity=0)
            #pos=self.pos, size=self.size)
            #self.bind(pos=qrscr.setter('pos'),
            #      size=qrscr.setter('size')
            qrscr.bind(symbols=self.on_symbols)
        bl = self.ids.bl
        bl.clear_widgets()
        bl.add_widget(qrscr)
        qrscr.opacity = 1
        Animation(height=dp(280)).start(self)
        Animation(opacity=1).start(self)
        qrscr.start()

    def on_symbols(self, instance, value):
        instance.stop()
        self.remove_widget(instance)
        self.ids.but_contact.dispatch('on_release')
        global decode_uri
        if not decode_uri:
            from electrum_gui.kivy.qr_scanner import decode_uri
        uri = decode_uri(value[0].data)
        self.ids.ti.text = uri.get('address', 'empty')
        self.ids.ti_lbl.text = uri.get('label', 'empty')
        self.ids.ti_lbl.focus = True


class PasswordRequiredDialog(InfoDialog):

    pass


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
            stepper = self.ids.stepper
            stepper.opacity = 1
            stepper.source = 'atlas://gui/kivy/theming/light/stepper_left'
            self._back = _back = partial(self.ids.back.dispatch, 'on_release')
            app.navigation_higherarchy.append(_back)

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
        if self._back in app.navigation_higherarchy:
            app.navigation_higherarchy.pop()
            self._back = None
        super(ChangePasswordDialog, self).close()



class Dialog(Popup):

    content_padding = NumericProperty('2dp')
    '''Padding for the content area of the dialog defaults to 2dp
    '''

    buttons_padding = NumericProperty('2dp')
    '''Padding for the bottns area of the dialog defaults to 2dp
    '''

    buttons_height = NumericProperty('40dp')
    '''Height to be used for the Buttons at the bottom
    '''

    def close(self):
        self.dismiss()

    def add_content(self, widget, index=0):
        self.ids.layout_content.add_widget(widget, index)

    def add_button(self, widget, index=0):
        self.ids.layout_buttons.add_widget(widget, index)


class SaveDialog(Popup):

    filename = StringProperty('')
    '''The default file name provided
    '''

    filters = ListProperty([])
    ''' list of files to be filtered and displayed defaults to  allow all
    '''

    path = StringProperty(DEFAULT_PATH)
    '''path to be loaded by default in this dialog
    '''

    file_chooser = ObjectProperty(None)
    '''link to the file chooser object inside the dialog
    '''

    text_input = ObjectProperty(None)
    '''
    '''

    cancel_button = ObjectProperty(None)
    '''
    '''

    save_button = ObjectProperty(None)
    '''
    '''

    def close(self):
        self.dismiss()


class LoadDialog(SaveDialog):

    def _get_load_btn(self):
        return self.save_button

    load_button = AliasProperty(_get_load_btn, None, bind=('save_button', ))
    '''Alias to the Save Button to be used as LoadButton
    '''

    def __init__(self, **kwargs):
        super(LoadDialog, self).__init__(**kwargs)
        self.load_button.text=_("Load")
