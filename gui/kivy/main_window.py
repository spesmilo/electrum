import  sys
from decimal import Decimal

from electrum import WalletStorage, Wallet
from electrum.i18n import _, set_language
from electrum.wallet import format_satoshis

from kivy.app import App
from kivy.core.window import Window
from kivy.metrics import inch
from kivy.logger import Logger
from kivy.utils import platform
from kivy.properties import (OptionProperty, AliasProperty, ObjectProperty,
                             StringProperty, ListProperty)
from kivy.clock import Clock

#inclusions for factory so that widgets can be used in kv
from gui.kivy.drawer import Drawer
from gui.kivy.dialog import InfoBubble

# delayed imports
notification = None

class ElectrumWindow(App):

    title = _('Electrum App')

    wallet = ObjectProperty(None)
    '''Holds the electrum wallet

    :attr:`wallet` is a `ObjectProperty` defaults to None.
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
    :attr:`base_unit`.

    :attr:`decimal_point` is a `AliasProperty` defaults to the value gotten
    from electrum config.
    '''

    def _get_bu(self):
        assert self.decimal_point in (5,8)
        return "BTC" if self.decimal_point == 8 else "mBTC"

    def _set_bu(self, value):
        try:
            self.electrum_config.set_key('base_unit', value, True)
        except AttributeError:
            Logger.error('Electrum: Config not set '
                         'While trying to save value to config')

    base_unit = AliasProperty(_get_bu, _set_bu, bind=('decimal_point',))
    '''BTC or UBTC or ...

    :attr:`base_unit` is a `AliasProperty` defaults to the unit set in
    electrum config.
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
        self.console = None
        self.exchanger = None

        super(ElectrumWindow, self).__init__(**kwargs)

        self.network = network = kwargs.get('network')
        self.electrum_config = config = kwargs.get('config')

        # create triggers so as to minimize updation a max of 5 times a sec
        self._trigger_update_status =\
            Clock.create_trigger(self.update_status, .2)
        self._trigger_update_console =\
            Clock.create_trigger(self.update_console, .2)
        self._trigger_notify_transactions = \
            Clock.create_trigger(self.notify_transactions, .2)

    def build(self):
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
        Window.bind(size=self.on_size,
                    on_keyboard=self.on_keyboard)
        Window.bind(on_key_down=self.on_key_down)
        if platform == 'android':
            #
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

    def on_keyboard_height(self, *l):
        from kivy.animation import Animation
        from kivy.uix.popup import Popup
        active_widg = Window.children[0]
        active_widg = active_widg\
            if (active_widg == self.root or\
            issubclass(active_widg.__class__, Popup)) else\
            Window.children[1]
        Animation(y=Window.keyboard_height, d=.1).start(active_widg)

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
            app.show_error('Electrum: No Wallet set/found. Exiting...',
                           exit=True)


        self.init_ui()
        # plugins that need to change the GUI do it here
        #run_hook('init')

        self.load_wallet(wallet)

        # check and remove this load_wallet calls update_wallet no
        # need for this here
        #Clock.schedule_once(update_wallet)

        #self.windows.append(w)
        #if url: w.set_url(url)
        #w.app = self.app
        #w.connect_slots(s)
        #w.update_wallet()

        #self.app.exec_()

    def init_ui(self):
        ''' Initialize The Ux part of electrum. This function performs the basic
        tasks of setting up the ui.
        '''

        # unused?
        #self._close_electrum = False

        #self._tray_icon = 'icons/" + (electrum_dark_icon.png'\
        #    if platform == 'mac' else 'electrum_light_icon.png')

        #setup tray
        #self.tray = SystemTrayIcon(self.icon, self)
        #self.tray.setToolTip('Electrum')
        #self.tray.activated.connect(self.tray_activated)

        set_language(self.electrum_config.get('language'))

        self.funds_error = False
        self.completions = []

        # setup UX
        #self.load_dashboard

        self.icon = "icons/electrum.png"

        # load and focus the ui

        # connect callbacks
        if self.network:
            self.network.register_callback(
                'updated', self._trigger_update_status)
            self.network.register_callback(
                'banner', self._trigger_update_console)
            self.network.register_callback(
                'disconnected', self._trigger_update_status)
            self.network.register_callback(
                'disconnecting', self._trigger_update_status)
            self.network.register_callback('new_transaction',
                self._trigger_notify_transactions)

            # set initial message
            self.update_console()

        self.wallet = None

    def create_quote_text(self, btc_balance, mode='normal'):
        '''
        '''
        if not self.exchanger:
            from electrum_gui.kivy.plugins.exchange_rate import Exchanger
            self.exchanger = Exchanger(self)
            self.exchanger.start()
        quote_currency = self.electrum_config.get("currency", 'EUR')
        quote_balance = self.exchanger.exchange(btc_balance, quote_currency)

        if mode == 'symbol':
            if quote_currency:
                quote_currency = self.exchanger.symbols[quote_currency]

        if quote_balance is None:
            quote_text = ""
        else:
            quote_text = "  (%.2f %s)" % (quote_balance, quote_currency)
        return quote_text

    def set_currencies(self, quote_currencies):
        self._trigger_update_status
        #self.currencies = sorted(quote_currencies.keys())

    def update_console(self, *dt):
        if self.console:
            self.console.showMessage(self.network.banner)

    def load_wallet(self, wallet):
        self.wallet = wallet
        self.accounts_expanded = self.wallet.storage.get('accounts_expanded', {})
        self.current_account = self.wallet.storage.get('current_account', None)

        title = 'Electrum ' + self.wallet.electrum_version + ' - '\
            + self.wallet.storage.path
        if wallet.is_watching_only():
            title += ' [{}]'.format(_('watching only'))
        self.title = title
        self.update_wallet()
        # Once GUI has been initialized check if we want to announce something
        # since the callback has been called before the GUI was initialized
        self.notify_transactions()
        self.update_account_selector()
        #TODO
        #self.new_account.setEnabled(self.wallet.seed_version>4)
        #self.update_lock_icon()
        #self.update_buttons_on_seed()

        #run_hook('load_wallet', wallet)

    def update_status(self, *dt):
        if not self.wallet:
            return
        if self.network is None or not self.network.is_running():
            text = _("Offline")
            #icon = QIcon(":icons/status_disconnected.png")

        elif self.network.is_connected():
            unconfirmed = ''
            quote_text = '.'
            if not self.wallet.up_to_date:
                text = _("Synchronizing...")
                #icon = QIcon(":icons/status_waiting.png")
            elif self.network.server_lag > 1:
                text = _("Server is lagging (%d blocks)"%self.network.server_lag)
                #icon = QIcon(":icons/status_lagging.png")
            else:
                c, u = self.wallet.get_account_balance(self.current_account)
                text =  self.format_amount(c)
                if u:
                    unconfirmed =  " [%s unconfirmed]"\
                        %( self.format_amount(u, True).strip())
                quote_text = self.create_quote_text(Decimal(c+u)/100000000) or '.'

                #r = {}
                #run_hook('set_quote_text', c+u, r)
                #quote = r.get(0)
                #if quote:
                #    text += "  (%s)"%quote

                self.notify(_("Balance: ") + text)
                #icon = QIcon(":icons/status_connected.png")
        else:
            text = _("Not connected")
            #icon = QIcon(":icons/status_disconnected.png")

        #TODO
        #status_card = self.root.main_screen.ids.tabs.ids.\
        #                screen_dashboard.ids.status_card
        self.status = text.strip()
        #status_card.quote_text = quote_text.strip()
        #status_card.uncomfirmed = unconfirmed.strip()
        ##app.base_unit = self.base_unit().strip()

    def format_amount(self, x, is_diff=False, whitespaces=False):
        '''
        '''
        return format_satoshis(x, is_diff, self.num_zeros, self.decimal_point, whitespaces)

    def update_wallet(self):
        '''
        '''
        self.update_status()
        if (self.wallet.up_to_date or
            not self.network or not self.network.is_connected()):
            #TODO
            #self.update_history_tab()
            #self.update_receive_tab()
            #self.update_contacts_tab()
            self.update_completions()

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

    def update_history_tab(self, see_all=False):
        def parse_histories(items):
            results = []
            for item in items:
                tx_hash, conf, is_mine, value, fee, balance, timestamp = item
                if conf > 0:
                    try:
                        time_str = datetime.datetime.fromtimestamp(
                                        timestamp).isoformat(' ')[:-3]
                    except:
                        time_str = _("unknown")

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
                    v_str = self.format_amount(value, True, whitespaces=True)
                else:
                    v_str = '--'

                balance_str = self.format_amount(balance, whitespaces=True)

                if tx_hash:
                    label, is_default_label = self.wallet.get_label(tx_hash)
                else:
                    label = _('Pruned transaction outputs')
                    is_default_label = False

                results.append((
                        conf, icon, time_str, label, v_str, balance_str, tx_hash))

            return results

        history_card = self.root.main_screen.ids.tabs.ids.\
                        screen_dashboard.ids.recent_activity_card
        histories = parse_histories(reversed(
                        self.wallet.get_tx_history(self.current_account)))
        #history_view.content_adapter.data = histories

        # repopulate History Card
        last_widget = history_card.ids.content.children[-1]
        history_card.ids.content.clear_widgets()
        history_add = history_card.ids.content.add_widget
        history_add(last_widget)
        RecentActivityItem = Factory.RecentActivityItem

        history_card.ids.btn_see_all.opacity = (0 if see_all or
                                                len(histories) < 8 else 1)
        if not see_all:
            histories = histories[:8]

        create_quote_text = self.create_quote_text
        for items in histories:
            conf, icon, date_time, address, amount, balance, tx = items
            ri = RecentActivityItem()
            ri.icon = icon
            ri.date = date_time
            ri.address = address
            ri.amount = amount
            ri.quote_text = create_quote_text(
                                Decimal(amount)/100000000, mode='symbol')
            ri.balance = balance
            ri.confirmations = conf
            ri.tx_hash = tx
            history_add(ri)

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
        data = []
        for address in self.wallet.addressbook:
            label = self.wallet.labels.get(address, '')
            item = (address, label, "%d" % self.wallet.get_num_tx(address))
            data.append(item)
            # item.setFont(0, QFont(MONOSPACE_FONT))
            # # 32 = label can be edited (bool)
            # item.setData(0,32, True)
            # # 33 = payto string
            # item.setData(0,33, address)

        self.run_hook('update_contacts_tab')

        contact_list = app.root.main_screen.ids.tabs.ids.\
            screen_contacts.ids.contacts_list
        contact_list.content_adapter.data = data

    def update_completions(self):
        l = []
        for addr, label in self.wallet.labels.items():
            if addr in self.wallet.addressbook:
                l.append(label + '  <' + addr + '>')

        #self.run_hook('update_completions', l)
        self.completions = l

    def notify_transactions(self, *dt):
        '''
        '''
        if not self.network or not self.network.is_connected():
            return

        iface = self.network.interface
        if len(iface.pending_transactions_for_notifications) > 0:
            # Combine the transactions if there are more then three
            tx_amount = len(iface.pending_transactions_for_notifications)
            if(tx_amount >= 3):
                total_amount = 0
                for tx in iface.pending_transactions_for_notifications:
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
                          from pudb import set_trace; set_trace()
                          self.notify(
                              _("New transaction received. {amount}s {unit}s").
                              format( amount=self.format_amount(v),
                                     unit=self.base_unit()))

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
                   arrow_pos=None,
                   exit=False,
                   icon='atlas://gui/kivy/theming/light/error',
                   duration=0,
                   modal=False):
        ''' Show a error Message Bubble.
        '''
        self.show_info_bubble(
                    text=error,
                    icon=icon,
                    width=width,
                    pos=pos or Window.center,
                    arrow_pos=arrow_pos,
                    exit=exit,
                    duration=duration,
                    modal=modal)

    def show_info(self, error,
                   width='200dp',
                   pos=None,
                   arrow_pos=None,
                   exit=False,
                   duration=0,
                   modal=False):
        ''' Show a Info Message Bubble.
        '''
        self.show_error(error, icon='atlas://gui/kivy/theming/light/error',
                        duration=duration,
                        modal=modal,
                        exit=exit,
                        pos=pos,
                        arrow_pos=arrow_pos)

    def show_info_bubble(self,
                    text=_('Hello World'),
                    pos=(0, 0),
                    duration=0,
                    arrow_pos='bottom_mid',
                    width=None,
                    icon='',
                    modal=False,
                    exit=False):
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
            Window.remove_widget(info_bubble
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
        info_bubble.show(pos, duration, width, modal=modal, exit=exit)
