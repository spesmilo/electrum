import  sys
import datetime

from electrum_ltc import WalletStorage, Wallet
from electrum_ltc.i18n import _, set_language
from electrum_ltc.contacts import Contacts

from kivy.config import Config
Config.set('modules', 'screen', 'droid2')
Config.set('graphics', 'width', '480')
Config.set('graphics', 'height', '840')

from kivy.app import App
from kivy.core.window import Window
from kivy.logger import Logger
from kivy.utils import platform
from kivy.properties import (OptionProperty, AliasProperty, ObjectProperty,
                             StringProperty, ListProperty, BooleanProperty)
from kivy.cache import Cache
from kivy.clock import Clock
from kivy.factory import Factory

from electrum_ltc_gui.kivy.uix.drawer import Drawer

# lazy imports for factory so that widgets can be used in kv
Factory.register('InstallWizard',
                 module='electrum_ltc_gui.kivy.uix.dialogs.installwizard')
Factory.register('InfoBubble', module='electrum_ltc_gui.kivy.uix.dialogs')
Factory.register('ELTextInput', module='electrum_ltc_gui.kivy.uix.screens')
Factory.register('QrScannerDialog', module='electrum_ltc_gui.kivy.uix.dialogs.qr_scanner')


# delayed imports: for startup speed on android
notification = app = Decimal = ref = format_satoshis = bitcoin = Builder = None
inch = None
util = False
re = None

# register widget cache for keeping memory down timeout to forever to cache
# the data
Cache.register('electrum_ltc_widgets', timeout=0)

class ElectrumWindow(App):

    def _get_bu(self):
        assert self.decimal_point in (5,8)
        return "LTC" if self.decimal_point == 8 else "mLTC"

    def _set_bu(self, value):
        try:
            self.electrum_config.set_key('base_unit', value, True)
        except AttributeError:
            Logger.error('Electrum: Config not set '
                         'While trying to save value to config')

    base_unit = AliasProperty(_get_bu, _set_bu, bind=('decimal_point',))
    '''BTC or UBTC or mBTC...

    :attr:`base_unit` is a `AliasProperty` defaults to the unit set in
    electrum config.
    '''

    currencies = ListProperty(['EUR', 'GBP', 'USD'])
    '''List of currencies supported by the current exchanger plugin.

    :attr:`currencies` is a `ListProperty` default to ['Eur', 'GBP'. 'USD'].
    '''

    expert_mode = BooleanProperty(False)
    '''This defines whether expert mode options are available in the ui.

    :attr:`expert_mode` is a `BooleanProperty` defaults to `False`.
    '''

    def _get_decimal(self):
        try:
            return self.electrum_config.get('decimal_point', 8)
        except AttributeError:
            return 8

    def _set_decimal(self, value):
        try:
            self.electrum_config.set_key('decimal_point', value, True)
        except AttributeError:
            Logger.error('Electrum: Config not set '
                         'While trying to save value to config')

    decimal_point = AliasProperty(_get_decimal, _set_decimal)
    '''This defines the decimal point to be used determining the
    :attr:`decimal_point`.

    :attr:`decimal_point` is a `AliasProperty` defaults to the value gotten
    from electrum config.
    '''

    electrum_config = ObjectProperty(None)
    '''Holds the electrum config

    :attr:`electrum_config` is a `ObjectProperty`, defaults to None.
    '''

    status = StringProperty(_('Uninitialised'))
    '''The status of the connection should show the balance when connected

    :attr:`status` is a `StringProperty` defaults to 'uninitialised'
    '''

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

    navigation_higherarchy = ListProperty([])
    '''This is a list of the current navigation higherarchy of the app used to
    navigate using back button.

    :attr:`navigation_higherarchy` is s `ListProperty` defaults to []
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

    __events__ = ('on_back', )

    def __init__(self, **kwargs):
        # initialize variables
        self._clipboard = None
        self.exchanger = None
        self.info_bubble = None
        self.qrscanner = None
        self.nfcscanner = None
        self.tabs = None

        super(ElectrumWindow, self).__init__(**kwargs)

        title = _('Electrum-LTC App')
        self.network = network = kwargs.get('network', None)
        self.electrum_config = config = kwargs.get('config', None)
        self.gui_object = kwargs.get('gui_object', None)

        self.config = self.gui_object.config
        self.contacts = Contacts(self.config)

        self.bind(url=self.set_url)
        # were we sent a url?
        url = kwargs.get('url', None)
        if url:
            self.gui_object.set_url(url)

        # create triggers so as to minimize updation a max of 2 times a sec
        self._trigger_update_wallet =\
            Clock.create_trigger(self.update_wallet, .5)
        self._trigger_update_status =\
            Clock.create_trigger(self.update_status, .5)
        self._trigger_notify_transactions = \
            Clock.create_trigger(self.notify_transactions, 5)

    def set_url(self, instance, url):
        self.gui_object.set_url(url)

    def scan_qr(self, on_complete):
        dlg = Cache.get('electrum_ltc_widgets', 'QrScannerDialog')
        if not dlg:
            dlg = Factory.QrScannerDialog()
            Cache.append('electrum_ltc_widgets', 'QrScannerDialog', dlg)
            dlg.bind(on_complete=on_complete)
        dlg.open()

    def build(self):
        global Builder
        if not Builder:
            from kivy.lang import Builder
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
        ''' Manage screen hierarchy
        '''
        try:
            self.navigation_higherarchy.pop()()
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
        if key == 27:
            self.dispatch('on_back')
            return True

    def on_wizard_complete(self, instance, wallet):
        if not wallet:
            Logger.debug('Electrum: No Wallet set/found. Exiting...')
            app = App.get_running_app()
            app.show_error('Electrum: No Wallet set/found. Exiting...',
                           exit=True)


        self.init_ui()
        # plugins that need to change the GUI do it here
        #run_hook('init')

        self.load_wallet(wallet)

    def init_ui(self):
        ''' Initialize The Ux part of electrum. This function performs the basic
        tasks of setting up the ui.
        '''

        # unused?
        #self._close_electrum = False

        #self._tray_icon = 'icons/" + (electrum_dark_icon.png'\
        #    if platform == 'mac' else 'electrum_light_icon.png')

        #setup tray TODO: use the systray branch
        #self.tray = SystemTrayIcon(self.icon, self)
        #self.tray.setToolTip('Electrum')
        #self.tray.activated.connect(self.tray_activated)

        global ref
        if not ref:
            from weakref import ref

        set_language(self.electrum_config.get('language'))

        self.funds_error = False
        self.completions = []

        # setup UX
        self.screens = ['mainscreen',]

        #setup lazy imports for mainscreen
        Factory.register('AnimatedPopup',
                         module='electrum_ltc_gui.kivy.uix.dialogs')
        Factory.register('TabbedCarousel',
                         module='electrum_ltc_gui.kivy.uix.screens')
        Factory.register('ScreenDashboard',
                         module='electrum_ltc_gui.kivy.uix.screens')
        #Factory.register('EffectWidget',
        #                 module='electrum_ltc_gui.kivy.uix.effectwidget')
        Factory.register('QRCodeWidget',
                         module='electrum_ltc_gui.kivy.uix.qrcodewidget')
        Factory.register('MainScreen',
                         module='electrum_ltc_gui.kivy.uix.screens')
        Factory.register('CSpinner',
                         module='electrum_ltc_gui.kivy.uix.screens')
        # preload widgets. Remove this if you want to load the widgets on demand
        Cache.append('electrum_ltc_widgets', 'AnimatedPopup', Factory.AnimatedPopup())
        Cache.append('electrum_ltc_widgets', 'TabbedCarousel', Factory.TabbedCarousel())
        Cache.append('electrum_ltc_widgets', 'QRCodeWidget', Factory.QRCodeWidget())
        Cache.append('electrum_ltc_widgets', 'CSpinner', Factory.CSpinner())


        # load and focus the ui
        #Load mainscreen
        dr = Builder.load_file('gui/kivy/uix/ui_screens/mainscreen.kv')
        self.root.add_widget(dr)
        self.root.manager = manager = dr.ids.manager
        self.root.main_screen = m = manager.screens[0]
        self.tabs = m.ids.tabs

        #TODO
        # load left_menu

        self.icon = "icons/electrum-ltc.png"

        # connect callbacks
        if self.network:
            self.network.register_callback('updated', self._trigger_update_wallet)
            self.network.register_callback('status', self._trigger_update_status)
            self.network.register_callback('new_transaction', self._trigger_notify_transactions)

        self.wallet = None

    def create_quote_text(self, btc_balance, mode='normal'):
        '''
        '''
        if not self.exchanger:
            return
        quote_currency = self.exchanger.currency
        quote_balance = self.exchanger.exchange(btc_balance, quote_currency)

        if quote_currency and mode == 'symbol':
            quote_currency = self.exchanger.symbols.get(quote_currency,
                                                        quote_currency)

        if quote_balance is None:
            quote_text = u"..."
        else:
            quote_text = u"%s%.2f" % (quote_currency,
                                     quote_balance)
        return quote_text

    def set_currencies(self, quote_currencies):
        self.currencies = sorted(quote_currencies.keys())
        self._trigger_update_status()

    def get_history_rate(self, item, btc_balance, mintime):
        '''Historical rates: currently only using coindesk by default.
        '''
        maxtime = datetime.datetime.now().strftime('%Y-%m-%d')
        rate = self.exchanger.get_history_rate(item, btc_balance, mintime,
                                                maxtime)

        return self.set_history_rate(item, rate)


    def set_history_rate(self, item, rate):
        '''
        '''
        #TODO: fix me allow other currencies to be used for history rates
        quote_currency = self.exchanger.symbols.get('USD', 'USD')
        if rate is None:
            quote_text = "..."
        else:
            quote_text = "{0}{1:.3}".format(quote_currency, rate)
        item = item()
        if item:
            item.quote_text = quote_text
        return quote_text


    def load_wallet(self, wallet):
        self.wallet = wallet
        self.accounts_expanded = self.wallet.storage.get('accounts_expanded', {})
        self.current_account = self.wallet.storage.get('current_account', None)

        title = 'Electrum-LTC ' + self.wallet.electrum_version + ' - '\
            + self.wallet.storage.path
        if wallet.is_watching_only():
            title += ' [{}]'.format(_('watching only'))
        self.title = title
        self.update_wallet()
        # Once GUI has been initialized check if we want to announce something
        # since the callback has been called before the GUI was initialized
        self.update_history_tab()
        self.notify_transactions()
        self.update_account_selector()

        #run_hook('load_wallet', wallet)

    def update_status(self, *dt):
        if not self.wallet:
            return

        global Decimal
        if not Decimal:
            from decimal import Decimal

        unconfirmed = ''
        quote_text = ''

        if self.network is None or not self.network.is_running():
            text = _("Offline")

        elif self.network.is_connected():
            server_height = self.network.get_server_height()
            server_lag = self.network.get_local_height() - server_height
            if not self.wallet.up_to_date or server_height == 0:
                text = _("Synchronizing...")
            elif server_lag > 1:
                text = _("Server is lagging (%d blocks)"%server_lag)
            else:
                c, u, x = self.wallet.get_account_balance(self.current_account)
                text = self.format_amount(c)
                if u:
                    unconfirmed =  " [%s unconfirmed]" %( self.format_amount(u, True).strip())
                if x:
                    unmatured =  " [%s unmatured]"%(self.format_amount(x, True).strip())
                quote_text = self.create_quote_text(Decimal(c+u+x)/100000000, mode='symbol') or ''
        else:
            text = _("Not connected")
        try:
            status_card = self.root.main_screen.ids.tabs.ids.\
                        screen_dashboard.ids.status_card
        except AttributeError:
            return
        self.status = text.strip()
        status_card.quote_text = quote_text.strip()
        status_card.uncomfirmed = unconfirmed.strip()

    def format_amount(self, x, is_diff=False, whitespaces=False):
        '''
        '''
        global format_satoshis
        if not format_satoshis:
            from electrum_ltc.util import format_satoshis
        return format_satoshis(x, is_diff, self.num_zeros,
                               self.decimal_point, whitespaces)

    def update_wallet(self, *dt):
        '''
        '''
        if not self.exchanger:
            from electrum_ltc_gui.kivy.plugins.exchange_rate import Exchanger
            self.exchanger = Exchanger(self)
            self.exchanger.start()
            return
        self._trigger_update_status()
        if self.wallet.up_to_date or not self.network or not self.network.is_connected():
            self.update_history_tab()
            self.update_contacts_tab()

    def update_account_selector(self):
        # account selector
        #TODO
        return
        accounts = self.wallet.get_account_names()
        self.account_selector.clear()
        if len(accounts) > 1:
            self.account_selector.addItems([_("All accounts")] + accounts.values())
            self.account_selector.setCurrentIndex(0)
            self.account_selector.show()
        else:
            self.account_selector.hide()

    def parse_histories(self, items):
        for item in items:
            tx_hash, conf, value, timestamp, balance = item
            time_str = _("unknown")
            if conf > 0:
                try:
                    time_str = datetime.datetime.fromtimestamp(
                                    timestamp).isoformat(' ')[:-3]
                except Exception:
                    time_str = _("error")

            if conf == -1:
                time_str = _('unverified')
                icon = "atlas://gui/kivy/theming/light/close"
            elif conf == 0:
                time_str = _('pending')
                icon = "atlas://gui/kivy/theming/light/unconfirmed"
            elif conf < 6:
                time_str = ''  # add new to fix error when conf < 0
                conf = max(1, conf)
                icon = "atlas://gui/kivy/theming/light/clock{}".format(conf)
            else:
                icon = "atlas://gui/kivy/theming/light/confirmed"

            if value is not None:
                v_str = self.format_amount(value, True).replace(',','.')
            else:
                v_str = '--'

            balance_str = self.format_amount(balance).replace(',','.')

            if tx_hash:
                label, is_default_label = self.wallet.get_label(tx_hash)
            else:
                label = _('Pruned transaction outputs')
                is_default_label = False

            yield (conf, icon, time_str, label, v_str, balance_str, tx_hash)

    def update_history_tab(self, see_all=False):

        try:
            history_card = self.root.main_screen.ids.tabs.ids.\
                        screen_dashboard.ids.recent_activity_card
        except AttributeError:
            return
        histories = self.parse_histories(reversed(
                        self.wallet.get_history(self.current_account)))

        # repopulate History Card
        last_widget = history_card.ids.content.children[-1]
        history_card.ids.content.clear_widgets()
        history_add = history_card.ids.content.add_widget
        history_add(last_widget)
        RecentActivityItem = Factory.RecentActivityItem
        global Decimal, ref
        if not ref:
            from weakref import ref
        if not Decimal:
            from decimal import Decimal

        get_history_rate = self.get_history_rate
        count = 0
        for items in histories:
            count += 1
            conf, icon, date_time, address, amount, balance, tx = items
            ri = RecentActivityItem()
            ri.icon = icon
            ri.date = date_time
            mintimestr = date_time.split()[0]
            ri.address = address
            ri.amount = amount
            ri.quote_text = get_history_rate(ref(ri),
                                             Decimal(amount),
                                             mintimestr)
            ri.balance = balance
            ri.confirmations = conf
            ri.tx_hash = tx
            history_add(ri)
            if count == 8 and not see_all:
                break

        history_card.ids.btn_see_all.opacity = (0 if count < 8 else 1)

    def update_receive_tab(self):
        #TODO move to address managment
        return
        data = []

        if self.current_account is None:
            account_items = self.wallet.accounts.items()
        elif self.current_account != -1:
            account_items = [(self.current_account, self.wallet.accounts.get(self.current_account))]
        else:
            account_items = []

        for k, account in account_items:
            name = account.get('name', str(k))
            c, u = self.wallet.get_account_balance(k)
            data = [(name, '', self.format_amount(c + u), '')]

            for is_change in ([0, 1] if self.expert_mode else [0]):
                if self.expert_mode:
                    name = "Receiving" if not is_change else "Change"
                    seq_item = (name, '', '', '')
                    data.append(seq_item)
                else:
                    seq_item = data
                is_red = False
                gap = 0

                for address in account[is_change]:
                    h = self.wallet.history.get(address, [])

                    if h == []:
                        gap += 1
                        if gap > self.wallet.gap_limit:
                            is_red = True
                    else:
                        gap = 0

                    num_tx = '*' if h == ['*'] else "%d" % len(h)
                    item = (address, self.wallet.labels.get(address, ''), '', num_tx)
                    data.append(item)
                    self.update_receive_item(item)

        if self.wallet.imported_keys and (self.current_account is None
                                          or self.current_account == -1):
            c, u = self.wallet.get_imported_balance()
            data.append((_('Imported'), '', self.format_amount(c + u), ''))
            for address in self.wallet.imported_keys.keys():
                item = (address, self.wallet.labels.get(address, ''), '', '')
                data.append(item)
                self.update_receive_item(item)

        receive_list = app.root.main_screen.ids.tabs.ids\
            .screen_receive.receive_view
        receive_list.content_adapter.data = data

    def update_contacts_tab(self):
        contact_list = self.root.main_screen.ids.tabs.ids.\
            screen_contacts.ids.contact_container
        #contact_list.clear_widgets()

        child = -1
        children = contact_list.children

        for key in sorted(self.contacts.keys()):
            _type, address = self.contacts[key]
            label = self.wallet.labels.get(address, '')
            child += 1
            try:
                if children[child].label == label:
                    continue
            except IndexError:
                pass
            tx = self.wallet.get_num_tx(address)
            ci = Factory.ContactItem()
            ci.address = address
            ci.label = label
            ci.tx_amount = tx
            contact_list.add_widget(ci)

        #self.run_hook('update_contacts_tab')

    def set_pay_from(self, l):
        #TODO
        return
        self.pay_from = l
        self.from_list.clear()
        self.from_label.setHidden(len(self.pay_from) == 0)
        self.from_list.setHidden(len(self.pay_from) == 0)
        for addr in self.pay_from:
            c, u = self.wallet.get_addr_balance(addr)
            balance = self.format_amount(c + u)
            self.from_list.addTopLevelItem(QTreeWidgetItem( [addr, balance] ))


    def protected(func):
        return lambda s, *args, **kwargs: s.do_protect(func, args, **kwargs)

    def do_protect(self, func, **kwargs):
        print kwargs
        instance = kwargs.get('instance', None)
        password = kwargs.get('password', None)
        message = kwargs.get('message', '')

        def run_func(instance=None, password=None):
            args = (self, instance, password)
            apply(func, args)

        if self.wallet.use_encryption:
            return self.password_required_dialog(post_ok=run_func, message=message)

        return run_func()

    def do_send(self):
        app = App.get_running_app()
        screen_send = app.root.main_screen.ids.tabs.ids.screen_send
        scrn = screen_send.ids
        label = unicode(scrn.message_e.text)

        r = unicode(scrn.payto_e.text).strip()

        # label or alias, with address in brackets
        global re
        if not re:
            import re
        m = re.match('(.*?)\s*\<([1-9A-HJ-NP-Za-km-z]{26,})\>', r)
        to_address = m.group(2) if m else r

        global bitcoin
        if not bitcoin:
            from electrum_ltc import bitcoin

        if not bitcoin.is_address(to_address):
            app.show_error(_('Invalid Litecoin Address') +
                                            ':\n' + to_address)
            return

        amount = scrn.amount_e.text
        fee = scrn.fee_e.amt
        if not fee:
            app.show_error(_('Invalid Fee'))
            return

        from pudb import set_trace; set_trace()
        message = 'sending {} {} to {}'.format(\
            app.base_unit, scrn.amount_e.text, r)

        confirm_fee = self.config.get('confirm_amount', 100000)
        if fee >= confirm_fee:
            if not self.question(_("The fee for this transaction seems unusually high.\nAre you really sure you want to pay %(fee)s in fees?")%{ 'fee' : self.format_amount(fee) + ' '+ self.base_unit()}):
                return

        self.send_tx(to_address, amount, fee, label)

    @protected
    def send_tx(self, outputs, fee, label, password):

        # first, create an unsigned tx 
        domain = self.get_payment_sources()
        try:
            tx = self.wallet.make_unsigned_transaction(outputs, fee, None, domain)
            tx.error = None
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.show_info(str(e))
            return

        # call hook to see if plugin needs gui interaction
        #run_hook('send_tx', tx)

        # sign the tx
        def sign_thread():
            time.sleep(0.1)
            keypairs = {}
            self.wallet.add_keypairs_from_wallet(tx, keypairs, password)
            self.wallet.sign_transaction(tx, keypairs, password)
            return tx, fee, label

        def sign_done(tx, fee, label):
            if tx.error:
                self.show_info(tx.error)
                return
            if fee < tx.required_fee(self.wallet.verifier):
                self.show_error(_("This transaction requires a higher fee, or "
                                  "it will not be propagated by the network."))
                return
            if label:
                self.wallet.set_label(tx.hash(), label)

            if not self.gui_object.payment_request:
                if not tx.is_complete() or self.config.get('show_before_broadcast'):
                    self.show_transaction(tx)
                    return

            self.broadcast_transaction(tx)

        WaitingDialog(self, 'Signing..').start(sign_thread, sign_done)

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
            notification.notify('Electrum-LTC', message,
                            app_icon=icon, app_name='Electrum-LTC')
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

        global inch
        if not inch:
            from kivy.metrics import inch

        self._ui_mode = 'tablet' if min(width, height) > inch(3.51) else 'phone'
        Logger.debug('orientation: {} ui_mode: {}'.format(self._orientation,
                                                          self._ui_mode))

    def load_screen(self, index=0, direction='left', manager=None, switch=True):
        ''' Load the appropriate screen as mentioned in the parameters.
        '''
        manager = manager or self.root.manager
        screen = Builder.load_file('gui/kivy/uix/ui_screens/'\
            + self.screens[index] + '.kv')
        screen.name = self.screens[index]
        if switch:
            manager.switch_to(screen, direction=direction)
        return screen

    def load_next_screen(self):
        '''
        '''
        manager = root.manager
        try:
            self.load_screen(self.screens.index(manager.current_screen.name)+1,
                             manager=manager)
        except IndexError:
            self.load_screen()

    def load_previous_screen(self):
        ''' Load the previous screen from disk.
        '''
        manager = root.manager
        try:
            self.load_screen(self.screens.index(manager.current_screen.name)-1,
                             direction='right',
                             manager=manager)
        except IndexError:
            pass

    def save_new_contact(self, address, label):
        address = unicode(address)
        label = unicode(label)
        global is_valid
        if not is_valid:
            from electrum_ltc.bitcoin import is_valid


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

    def do_clear(self):
        tabs = self.tabs
        screen_send = tabs.ids.screen_send
        content = screen_send.ids.content
        cts = content.ids
        cts.payto_e.text = cts.message_e.text = cts.amount_e.text = \
            cts.fee_e.text = ''

        self.set_frozen(content, False)

        self.set_pay_from([])
        self.update_status()

    def set_frozen(self, entry, frozen):
        if frozen:
            entry.disabled = True
            Factory.Animation(opacity=0).start(content)
        else:
            entry.disabled = False
            Factory.Animation(opacity=1).start(content)

    def set_addrs_frozen(self,addrs,freeze):
        for addr in addrs:
            if not addr: continue
            if addr in self.wallet.frozen_addresses and not freeze:
                self.wallet.unfreeze(addr)
            elif addr not in self.wallet.frozen_addresses and freeze:
                self.wallet.freeze(addr)
        self.update_receive_tab()

    def payment_request_error(self):
        tabs = self.tabs
        screen_send = tabs.ids.screen_send

        # switch_to the send screen
        tabs.ids.panel.switch_to(tabs.ids.tab_send)

        self.do_clear()
        self.show_info(self.gui_object.payment_request.error)

    def encode_uri(self, addr, amount=0, label='',
                   message='', size='', currency='ltc'):
        ''' Convert to BIP0021 compatible URI
        '''
        uri = 'litecoin:{}'.format(addr)
        first = True
        if amount:
            uri += '{}amount={}'.format('?' if first else '&', amount)
            first = False
        if label:
            uri += '{}label={}'.format('?' if first else '&', label)
            first = False
        if message:
            uri += '{}?message={}'.format('?' if first else '&', message)
            first = False
        if size:
            uri += '{}size={}'.format('?' if not first else '&', size)
        return uri

    def decode_uri(self, uri):
        if ':' not in uri:
            # It's just an address (not BIP21)
            return {'address': uri}

        if '//' not in uri:
            # Workaround for urlparse, it don't handle bitcoin: URI properly
            uri = uri.replace(':', '://')

        try:
            uri = urlparse(uri)
        except NameError:
            # delayed import
            from urlparse import urlparse, parse_qs
            uri = urlparse(uri)

        result = {'address': uri.netloc}

        if uri.path.startswith('?'):
            params = parse_qs(uri.path[1:])
        else:
            params = parse_qs(uri.path)

        for k,v in params.items():
            if k in ('amount', 'label', 'message', 'size'):
                result[k] = v[0]

        return result

    def delete_imported_key(self, addr):
        self.wallet.delete_imported_key(addr)
        self.update_receive_tab()
        self.update_history_tab()

    def delete_pending_account(self, k):
        self.wallet.delete_pending_account(k)
        self.update_receive_tab()

    def get_sendable_balance(self):
        return sum(sum(self.wallet.get_addr_balance(a))
                   for a in self.get_payment_sources())


    def get_payment_sources(self):
        if self.pay_from:
            return self.pay_from
        else:
            return self.wallet.get_account_addresses(self.current_account)


    def send_from_addresses(self, addrs):
        self.set_pay_from( addrs )
        tabs = self.tabs
        screen_send = tabs.ids.screen_send
        self.tabs.setCurrentIndex(1)


    def payto(self, addr):
        if not addr:
            return
        label = self.wallet.labels.get(addr)
        m_addr = label + '  <' + addr + '>' if label else addr
        self.tabs.setCurrentIndex(1)
        self.payto_e.setText(m_addr)
        self.amount_e.setFocus()


    def delete_contact(self, x):
        if self.question(_("Do you want to remove") +
                         " %s "%x +
                         _("from your list of contacts?")):
            self.wallet.delete_contact(x)
            self.wallet.set_label(x, None)
            self.update_history_tab()
            self.update_contacts_tab()

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
            if img.texture and img._coreimage:
                img.reload()
            img.allow_stretch = False
            info_bubble.dim_background = False
            info_bubble.background_image = 'atlas://data/images/defaulttheme/bubble'
        info_bubble.message = text
        if not pos:
                pos = (win.center[0], win.center[1] - (info_bubble.height/2))
        info_bubble.show(pos, duration, width, modal=modal, exit=exit)
