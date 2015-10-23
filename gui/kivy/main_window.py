import re
import sys
import time
import datetime
import traceback
from decimal import Decimal

import electrum
from electrum import WalletStorage, Wallet
from electrum.i18n import _, set_language
from electrum.contacts import Contacts
from electrum.util import profiler
from electrum.plugins import run_hook

from kivy.app import App
from kivy.core.window import Window
from kivy.logger import Logger
from kivy.utils import platform
from kivy.properties import (OptionProperty, AliasProperty, ObjectProperty,
                             StringProperty, ListProperty, BooleanProperty)
from kivy.cache import Cache
from kivy.clock import Clock
from kivy.factory import Factory
from kivy.metrics import inch, metrics
from kivy.lang import Builder

# lazy imports for factory so that widgets can be used in kv
Factory.register('InstallWizard',
                 module='electrum_gui.kivy.uix.dialogs.installwizard')
Factory.register('InfoBubble', module='electrum_gui.kivy.uix.dialogs')
Factory.register('ELTextInput', module='electrum_gui.kivy.uix.screens')


# delayed imports: for startup speed on android
notification = app = ref = format_satoshis = None
util = False


# register widget cache for keeping memory down timeout to forever to cache
# the data
Cache.register('electrum_widgets', timeout=0)

from kivy.uix.screenmanager import Screen
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.uix.label import Label
from kivy.uix.checkbox import CheckBox

Factory.register('TabbedCarousel', module='electrum_gui.kivy.uix.screens')



base_units = {'BTC':8, 'mBTC':5, 'uBTC':2}

class ElectrumWindow(App):

    electrum_config = ObjectProperty(None)

    def _get_bu(self):
        return self.electrum_config.get('base_unit', 'mBTC')

    def _set_bu(self, value):
        assert value in base_units.keys()
        self.electrum_config.set_key('base_unit', value, True)
        self.update_status()
        if self.history_screen:
            self.history_screen.update()

    base_unit = AliasProperty(_get_bu, _set_bu)

    def _rotate_bu(self):
        keys = sorted(base_units.keys())
        self.base_unit = keys[ (keys.index(self.base_unit) + 1) % len(keys)]

    status = StringProperty(_('Not Connected'))

    def decimal_point(self):
        return base_units[self.base_unit]

    def _get_num_zeros(self):
        try:
            return self.electrum_config.get('num_zeros', 0)
        except AttributeError:
            return 0

    def _set_num_zeros(self):
        try:
            self.electrum_config.set_key('num_zeros', value, True)
        except AttributeError:
            Logger.error('Electrum: Config not available '
                         'While trying to save value to config')

    num_zeros = AliasProperty(_get_num_zeros , _set_num_zeros)
    '''Number of zeros used while representing the value in base_unit.
    '''

    def get_amount(self, amount_str):
        a, u = amount_str.split()
        assert u == self.base_unit
        try:
            x = Decimal(a)
        except:
            return None
        p = pow(10, self.decimal_point())
        return int(p * x)


    hierarchy = ListProperty([])
    '''used to navigate with the back button.
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

    url = StringProperty('', allownone=True)
    '''
    '''

    wallet = ObjectProperty(None)
    '''Holds the electrum wallet

    :attr:`wallet` is a `ObjectProperty` defaults to None.
    '''

    def __init__(self, **kwargs):
        # initialize variables
        self._clipboard = None
        self.info_bubble = None
        self.qrscanner = None
        self.nfcscanner = None
        self.tabs = None

        super(ElectrumWindow, self).__init__(**kwargs)

        title = _('Electrum App')
        self.electrum_config = config = kwargs.get('config', None)
        self.network = network = kwargs.get('network', None)
        self.plugins = kwargs.get('plugins', [])

        self.gui_object = kwargs.get('gui_object', None)

        #self.config = self.gui_object.config
        self.contacts = Contacts(self.electrum_config)

        self.bind(url=self.set_url)
        # were we sent a url?
        url = self.electrum_config.get('url', None)
        if url:
            self.set_url(url)

        # create triggers so as to minimize updation a max of 2 times a sec
        self._trigger_update_wallet =\
            Clock.create_trigger(self.update_wallet, .5)
        self._trigger_update_status =\
            Clock.create_trigger(self.update_status, .5)
        self._trigger_notify_transactions = \
            Clock.create_trigger(self.notify_transactions, 5)

    def set_url(self, url):
        print "set url", url
        url = electrum.util.parse_URI(url)
        self.send_screen.set_qr_data(url)

    def scan_qr(self, on_complete):
        from jnius import autoclass
        from android import activity
        PythonActivity = autoclass('org.renpy.android.PythonActivity')
        Intent = autoclass('android.content.Intent')
        intent = Intent("com.google.zxing.client.android.SCAN")
        intent.putExtra("SCAN_MODE", "QR_CODE_MODE")
        def on_qr_result(requestCode, resultCode, intent):
            if requestCode == 0:
                if resultCode == -1: # RESULT_OK:
                    contents = intent.getStringExtra("SCAN_RESULT")
                    if intent.getStringExtra("SCAN_RESULT_FORMAT") == 'QR_CODE':
                        uri = electrum.util.parse_URI(contents)
                        on_complete(uri)
        activity.bind(on_activity_result=on_qr_result)
        PythonActivity.mActivity.startActivityForResult(intent, 0)

    def show_plugins(self, plugins_list):
        def on_checkbox_active(cb, value):
            self.plugins.toggle_enabled(self.electrum_config, cb.name)
        for item in self.plugins.descriptions:
            if 'kivy' not in item.get('available_for', []):
                continue
            name = item.get('name')
            label = Label(text=item.get('fullname'))
            plugins_list.add_widget(label)
            cb = CheckBox()
            cb.name = name
            p = self.plugins.get(name)
            cb.active = (p is not None) and p.is_enabled()
            cb.bind(active=on_checkbox_active)
            plugins_list.add_widget(cb)

    def build(self):
        return Builder.load_file('gui/kivy/main.kv')

    def _pause(self):
        if platform == 'android':
            # move activity to back
            from jnius import autoclass
            python_act = autoclass('org.renpy.android.PythonActivity')
            mActivity = python_act.mActivity
            mActivity.moveTaskToBack(True)

    def on_start(self):
        ''' This is the start point of the kivy ui
        '''
        Logger.info("dpi: {} {}".format(metrics.dpi, metrics.dpi_rounded))
        win = Window
        win.bind(size=self.on_size,
                    on_keyboard=self.on_keyboard)
        win.bind(on_key_down=self.on_key_down)

        # Register fonts without this you won't be able to use bold/italic...
        # inside markup.
        from kivy.core.text import Label
        Label.register('Roboto',
                   'data/fonts/Roboto.ttf',
                   'data/fonts/Roboto.ttf',
                   'data/fonts/Roboto-Bold.ttf',
                   'data/fonts/Roboto-Bold.ttf')

        if platform == 'android':
            # bind to keyboard height so we can get the window contents to
            # behave the way we want when the keyboard appears.
            win.bind(keyboard_height=self.on_keyboard_height)

        self.on_size(win, win.size)
        config = self.electrum_config
        storage = WalletStorage(config.get_wallet_path())

        Logger.info('Electrum: Check for existing wallet')

        if storage.file_exists:
            wallet = Wallet(storage)
            action = wallet.get_action()
        else:
            action = 'new'

        if action is not None:
            # start installation wizard
            Logger.debug('Electrum: Wallet not found. Launching install wizard')
            wizard = Factory.InstallWizard(config, self.network, storage)
            wizard.bind(on_wizard_complete=self.on_wizard_complete)
            wizard.run(action)
        else:
            wallet.start_threads(self.network)
            self.on_wizard_complete(None, wallet)

        self.on_resume()

    def on_stop(self):
        if self.wallet:
            self.wallet.stop_threads()

    def on_back(self):
        try:
            self.hierarchy.pop()()
        except IndexError:
            # capture back button and pause app.
            self._pause()


    def on_keyboard_height(self, window, height):
        win = window
        active_widg = win.children[0]
        if not issubclass(active_widg.__class__, Factory.Popup):
            try:
                active_widg = self.root.children[0]
            except IndexError:
                return

        try:
            fw = self._focused_widget
        except AttributeError:
            return
        if height > 0 and fw.to_window(*fw.pos)[1] > height:
            return
        Factory.Animation(y=win.keyboard_height, d=.1).start(active_widg)

    def on_key_down(self, instance, key, keycode, codepoint, modifiers):
        if 'ctrl' in modifiers:
            # q=24 w=25
            if keycode in (24, 25):
                self.stop()
            elif keycode == 27:
                # r=27
                # force update wallet
                self.update_wallet()
            elif keycode == 112:
                # pageup
                #TODO move to next tab
                pass
            elif keycode == 117:
                # pagedown
                #TODO move to prev tab
                pass
        #TODO: alt+tab_number to activate the particular tab

    def on_keyboard(self, instance, key, keycode, codepoint, modifiers):
        # override settings button
        if key in (319, 282): #f1/settings button on android
            self.gui.main_gui.toggle_settings(self)
            return True

    def on_wizard_complete(self, instance, wallet):
        if not wallet:
            Logger.debug('Electrum: No Wallet set/found. Exiting...')
            app = App.get_running_app()
            app.show_error('Electrum: No Wallet set/found. Exiting...',
                           exit=True)

        self.init_ui()
        self.load_wallet(wallet)

    def popup_dialog(self, name):
        popup = Builder.load_file('gui/kivy/uix/ui_screens/'+name+'.kv')
        popup.open()



    @profiler
    def init_ui(self):
        ''' Initialize The Ux part of electrum. This function performs the basic
        tasks of setting up the ui.
        '''
        from weakref import ref
        set_language(self.electrum_config.get('language'))

        self.funds_error = False
        # setup UX
        self.screens = {}

        #setup lazy imports for mainscreen
        Factory.register('AnimatedPopup',
                         module='electrum_gui.kivy.uix.dialogs')
        Factory.register('QRCodeWidget',
                         module='electrum_gui.kivy.uix.qrcodewidget')

        # preload widgets. Remove this if you want to load the widgets on demand
        #Cache.append('electrum_widgets', 'AnimatedPopup', Factory.AnimatedPopup())
        #Cache.append('electrum_widgets', 'QRCodeWidget', Factory.QRCodeWidget())

        # load and focus the ui
        self.root.manager = self.root.ids['manager']
        self.recent_activity_card = None
        self.history_screen = None
        self.contacts_screen = None

        self.icon = "icons/electrum.png"

        # connect callbacks
        if self.network:
            self.network.register_callback('updated', self._trigger_update_wallet)
            self.network.register_callback('status', self._trigger_update_status)
            self.network.register_callback('new_transaction', self._trigger_notify_transactions)

        self.wallet = None



    @profiler
    def load_wallet(self, wallet):
        self.wallet = wallet
        self.current_account = self.wallet.storage.get('current_account', None)
        self.update_wallet()
        # Once GUI has been initialized check if we want to announce something
        # since the callback has been called before the GUI was initialized
        self.update_history_tab()
        self.notify_transactions()

    def update_status(self, *dt):
        if not self.wallet:
            return

        unconfirmed = ''
        quote_text = ''

        if self.network is None or not self.network.is_running():
            text = _("Offline")

        elif self.network.is_connected():
            server_height = self.network.get_server_height()
            server_lag = self.network.get_local_height() - server_height
            if not self.wallet.up_to_date or server_height == 0:
                self.status = _("Synchronizing...")
            elif server_lag > 1:
                self.status = _("Server lagging (%d blocks)"%server_lag)
            else:
                c, u, x = self.wallet.get_account_balance(self.current_account)
                text = self.format_amount(c)
                if u:
                    unconfirmed =  " [%s unconfirmed]" %( self.format_amount(u, True).strip())
                if x:
                    unmatured =  " [%s unmatured]"%(self.format_amount(x, True).strip())
                #quote_text = self.create_quote_text(Decimal(c+u+x)/100000000, mode='symbol') or ''
                self.status = text.strip() + ' ' + self.base_unit
        else:
            self.status = _("Not connected")
            
        return

        print self.root.manager.ids

        #try:
        status_card = self.root.main_screen.ids.tabs.ids.\
                      screen_dashboard.ids.status_card
        #except AttributeError:
        #    return

        status_card.quote_text = quote_text.strip()
        status_card.uncomfirmed = unconfirmed.strip()


    def update_amount(self, amount, c):
        if c == '<':
            return amount[:-1]
        try:
            s = amount + c
            amount = s  if Decimal(s)!=0 else ''            
        except:
            pass
        return amount

    def format_amount(self, x, is_diff=False, whitespaces=False):
        from electrum.util import format_satoshis
        return format_satoshis(x, is_diff, self.num_zeros,
                               self.decimal_point(), whitespaces)

    @profiler
    def update_wallet(self, *dt):
        self._trigger_update_status()
        if self.wallet.up_to_date or not self.network or not self.network.is_connected():
            self.update_history_tab()
            self.update_contacts_tab()


    @profiler
    def update_history_tab(self, see_all=False):
        if self.history_screen:
            self.history_screen.update(see_all)

    def update_contacts_tab(self):
        if self.contacts_screen:
            self.contacts_screen.update()


    @profiler
    def notify_transactions(self, *dt):
        '''
        '''
        if not self.network or not self.network.is_connected():
            return
        # temporarily disabled for merge
        return
        iface = self.network
        ptfn = iface.pending_transactions_for_notifications
        if len(ptfn) > 0:
            # Combine the transactions if there are more then three
            tx_amount = len(ptfn)
            if(tx_amount >= 3):
                total_amount = 0
                for tx in ptfn:
                    is_relevant, is_mine, v, fee = self.wallet.get_tx_value(tx)
                    if(v > 0):
                        total_amount += v
                self.notify(_("{txs}s new transactions received. Total amount"
                              "received in the new transactions {amount}s"
                              "{unit}s").format(txs=tx_amount,
                                    amount=self.format_amount(total_amount),
                                    unit=self.base_unit()))

                iface.pending_transactions_for_notifications = []
            else:
              for tx in iface.pending_transactions_for_notifications:
                  if tx:
                      iface.pending_transactions_for_notifications.remove(tx)
                      is_relevant, is_mine, v, fee = self.wallet.get_tx_value(tx)
                      if(v > 0):
                          self.notify(
                              _("{txs} new transaction received. {amount} {unit}").
                              format(txs=tx_amount, amount=self.format_amount(v),
                                     unit=self.base_unit))

    def copy(self, text):
        ''' Copy provided text to clipboard
        '''
        if not self._clipboard:
            from kivy.core.clipboard import Clipboard
            self._clipboard = Clipboard
        self._clipboard.put(text, 'text/plain')

    def notify(self, message):
        try:
            global notification, os
            if not notification:
                from plyer import notification
                import os
            icon = (os.path.dirname(os.path.realpath(__file__))
                    + '/../../' + self.icon)
            notification.notify('Electrum', message,
                            app_icon=icon, app_name='Electrum')
        except ImportError:
            Logger.Error('Notification: needs plyer; `sudo pip install plyer`')

    def on_pause(self):
        '''
        '''
        # pause nfc
        if self.qrscanner:
            self.qrscanner.stop()
        if self.nfcscanner:
            self.nfcscanner.nfc_disable()
        return True

    def on_resume(self):
        '''
        '''
        if self.qrscanner and qrscanner.get_parent_window():
            self.qrscanner.start()
        if self.nfcscanner:
            self.nfcscanner.nfc_enable()

    def on_size(self, instance, value):
        width, height = value
        self._orientation = 'landscape' if width > height else 'portrait'
        self._ui_mode = 'tablet' if min(width, height) > inch(3.51) else 'phone'
        #Logger.info("size: {} {}".format(width, height))
        #Logger.info('orientation: {}'.format(self._orientation))
        #Logger.info('ui_mode: {}'.format(self._ui_mode))

    def save_new_contact(self, address, label):
        address = unicode(address)
        label = unicode(label)
        global is_valid
        if not is_valid:
            from electrum.bitcoin import is_valid

        if is_valid(address):
            if label:
                self.set_label(address, text=label)
            self.wallet.add_contact(address)
            self.update_contacts_tab()
            self.update_history_tab()
        else:
            self.show_error(_('Invalid Address'))

    def send_payment(self, address, amount=0, label='', message=''):
        tabs = self.tabs
        screen_send = tabs.ids.screen_send

        if label and self.wallet.labels.get(address) != label:
            #if self.question('Give label "%s" to address %s ?'%(label,address)):
            if address not in self.wallet.addressbook and not self.wallet.  is_mine(address):
                self.wallet.addressbook.append(address)
            self.wallet.set_label(address, label)

        # switch_to the send screen
        tabs.ids.panel.switch_to(tabs.ids.tab_send)

        label = self.wallet.labels.get(address)
        m_addr = label + '  <'+ address +'>' if label else address

        # populate
        def set_address(*l):
            content = screen_send.ids
            content.payto_e.text = m_addr
            content.message_e.text = message
            if amount:
                content.amount_e.text = amount

        # wait for screen to load
        Clock.schedule_once(set_address, .5)

    def set_send(self, address, amount, label, message):
        self.send_payment(address, amount=amount, label=label, message=message)

    def prepare_for_payment_request(self):
        tabs = self.tabs
        screen_send = tabs.ids.screen_send

        # switch_to the send screen
        tabs.ids.panel.switch_to(tabs.ids.tab_send)

        content = screen_send.ids
        if content:
            self.set_frozen(content, False)
        screen_send.screen_label.text = _("please wait...")
        return True

    def payment_request_ok(self):
        tabs = self.tabs
        screen_send = tabs.ids.screen_send

        # switch_to the send screen
        tabs.ids.panel.switch_to(tabs.ids.tab_send)

        self.set_frozen(content, True)

        screen_send.ids.payto_e.text = self.gui_object.payment_request.domain
        screen_send.ids.amount_e.text = self.format_amount(self.gui_object.payment_request.get_amount())
        screen_send.ids.message_e.text = self.gui_object.payment_request.memo

        # wait for screen to load
        Clock.schedule_once(set_address, .5)

    def set_frozen(self, entry, frozen):
        if frozen:
            entry.disabled = True
            Factory.Animation(opacity=0).start(content)
        else:
            entry.disabled = False
            Factory.Animation(opacity=1).start(content)

    def payment_request_error(self):
        tabs = self.tabs
        screen_send = tabs.ids.screen_send

        # switch_to the send screen
        tabs.ids.panel.switch_to(tabs.ids.tab_send)

        self.do_clear()
        self.show_info(self.gui_object.payment_request.error)

    def show_error(self, error, width='200dp', pos=None, arrow_pos=None,
        exit=False, icon='atlas://gui/kivy/theming/light/error', duration=0,
        modal=False):
        ''' Show a error Message Bubble.
        '''
        self.show_info_bubble( text=error, icon=icon, width=width,
            pos=pos or Window.center, arrow_pos=arrow_pos, exit=exit,
            duration=duration, modal=modal)

    def show_info(self, error, width='200dp', pos=None, arrow_pos=None,
        exit=False, duration=0, modal=False):
        ''' Show a Info Message Bubble.
        '''
        self.show_error(error, icon='atlas://gui/kivy/theming/light/error',
            duration=duration, modal=modal, exit=exit, pos=pos,
            arrow_pos=arrow_pos)

    def show_info_bubble(self, text=_('Hello World'), pos=None, duration=0,
        arrow_pos='bottom_mid', width=None, icon='', modal=False, exit=False):
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
            info_bubble = self.info_bubble = Factory.InfoBubble()

        win = Window
        if info_bubble.parent:
            win.remove_widget(info_bubble
                                 if not info_bubble.modal else
                                 info_bubble._modal_view)

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
            info_bubble.background_image = 'atlas://gui/kivy/theming/light/card'
        else:
            info_bubble.fs = False
            info_bubble.icon = icon
            #if img.texture and img._coreimage:
            #    img.reload()
            img.allow_stretch = False
            info_bubble.dim_background = False
            info_bubble.background_image = 'atlas://data/images/defaulttheme/bubble'
        info_bubble.message = text
        if not pos:
                pos = (win.center[0], win.center[1] - (info_bubble.height/2))
        info_bubble.show(pos, duration, width, modal=modal, exit=exit)

    def tx_dialog(self, tx_hash):
        popup = Builder.load_file('gui/kivy/uix/ui_screens/transaction.kv')
        popup.tx_hash = tx_hash
        popup.open()

    def amount_dialog(self, label, callback):
        popup = Builder.load_file('gui/kivy/uix/ui_screens/amount.kv')
        if label.text != label.default_text:
            a, u = label.text.split()
            assert u == self.base_unit
            popup.ids.a.amount = a
        def cb():
            o = popup.ids.a.text
            label.text = o if o else label.default_text
            if callback:
                callback()
        popup.on_dismiss = cb
        popup.open()

    def password_dialog(self, f, args):
        if self.wallet.use_encryption:
            popup = Builder.load_file('gui/kivy/uix/ui_screens/password.kv')
            def callback():
                pw = popup.ids.text_input.text
                Clock.schedule_once(lambda x: apply(f, args + (pw,)), 0.5)
            popup.on_dismiss = callback
            popup.open()
        else:
            apply(f, args + (None,))



