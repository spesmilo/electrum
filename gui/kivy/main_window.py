import re
import os
import sys
import time
import datetime
import traceback
from decimal import Decimal
import threading

import electrum_ltc as electrum
from electrum_ltc.bitcoin import TYPE_ADDRESS
from electrum_ltc import WalletStorage, Wallet
from electrum_ltc_gui.kivy.i18n import _
from electrum_ltc.paymentrequest import InvoiceStore
from electrum_ltc.util import profiler, InvalidPassword
from electrum_ltc.plugins import run_hook
from electrum_ltc.util import format_satoshis, format_satoshis_plain
from electrum_ltc.paymentrequest import PR_UNPAID, PR_PAID, PR_UNKNOWN, PR_EXPIRED

from kivy.app import App
from kivy.core.window import Window
from kivy.logger import Logger
from kivy.utils import platform
from kivy.properties import (OptionProperty, AliasProperty, ObjectProperty,
                             StringProperty, ListProperty, BooleanProperty, NumericProperty)
from kivy.cache import Cache
from kivy.clock import Clock
from kivy.factory import Factory
from kivy.metrics import inch
from kivy.lang import Builder

## lazy imports for factory so that widgets can be used in kv
#Factory.register('InstallWizard', module='electrum_ltc_gui.kivy.uix.dialogs.installwizard')
#Factory.register('InfoBubble', module='electrum_ltc_gui.kivy.uix.dialogs')
#Factory.register('OutputList', module='electrum_ltc_gui.kivy.uix.dialogs')
#Factory.register('OutputItem', module='electrum_ltc_gui.kivy.uix.dialogs')

from .uix.dialogs.installwizard import InstallWizard
from .uix.dialogs import InfoBubble
from .uix.dialogs import OutputList, OutputItem

#from kivy.core.window import Window
#Window.softinput_mode = 'below_target'

# delayed imports: for startup speed on android
notification = app = ref = None
util = False

# register widget cache for keeping memory down timeout to forever to cache
# the data
Cache.register('electrum_ltc_widgets', timeout=0)

from kivy.uix.screenmanager import Screen
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.uix.label import Label
from kivy.core.clipboard import Clipboard

Factory.register('TabbedCarousel', module='electrum_ltc_gui.kivy.uix.screens')

# Register fonts without this you won't be able to use bold/italic...
# inside markup.
from kivy.core.text import Label
Label.register('Roboto',
               'gui/kivy/data/fonts/Roboto.ttf',
               'gui/kivy/data/fonts/Roboto.ttf',
               'gui/kivy/data/fonts/Roboto-Bold.ttf',
               'gui/kivy/data/fonts/Roboto-Bold.ttf')


from electrum_ltc.util import base_units


class ElectrumWindow(App):

    electrum_config = ObjectProperty(None)
    language = StringProperty('en')

    # properties might be updated by the network
    num_blocks = NumericProperty(0)
    num_nodes = NumericProperty(0)
    server_host = StringProperty('')
    server_port = StringProperty('')
    num_chains = NumericProperty(0)
    blockchain_name = StringProperty('')
    blockchain_checkpoint = NumericProperty(0)

    auto_connect = BooleanProperty(False)
    def on_auto_connect(self, instance, x):
        host, port, protocol, proxy, auto_connect = self.network.get_parameters()
        self.network.set_parameters(host, port, protocol, proxy, self.auto_connect)
    def toggle_auto_connect(self, x):
        self.auto_connect = not self.auto_connect

    def choose_server_dialog(self, popup):
        from .uix.dialogs.choice_dialog import ChoiceDialog
        protocol = 's'
        def cb2(host):
            from electrum_ltc.bitcoin import NetworkConstants
            pp = servers.get(host, NetworkConstants.DEFAULT_PORTS)
            port = pp.get(protocol, '')
            popup.ids.host.text = host
            popup.ids.port.text = port
        servers = self.network.get_servers()
        ChoiceDialog(_('Choose a server'), sorted(servers), popup.ids.host.text, cb2).open()

    def choose_blockchain_dialog(self, dt):
        from .uix.dialogs.choice_dialog import ChoiceDialog
        chains = self.network.get_blockchains()
        def cb(name):
            for index, b in self.network.blockchains.items():
                if name == self.network.get_blockchain_name(b):
                    self.network.follow_chain(index)
                    #self.block
        names = [self.network.blockchains[b].get_name() for b in chains]
        if len(names) >1:
            ChoiceDialog(_('Choose your chain'), names, '', cb).open()

    use_rbf = BooleanProperty(False)
    def on_use_rbf(self, instance, x):
        self.electrum_config.set_key('use_rbf', self.use_rbf, True)

    use_change = BooleanProperty(False)
    def on_use_change(self, instance, x):
        self.electrum_config.set_key('use_change', self.use_change, True)

    use_unconfirmed = BooleanProperty(False)
    def on_use_unconfirmed(self, instance, x):
        self.electrum_config.set_key('confirmed_only', not self.use_unconfirmed, True)

    def set_URI(self, uri):
        self.switch_to('send')
        self.send_screen.set_URI(uri)

    def on_new_intent(self, intent):
        if intent.getScheme() != 'litecoin':
            return
        uri = intent.getDataString()
        self.set_URI(uri)

    def on_language(self, instance, language):
        Logger.info('language: {}'.format(language))
        _.switch_lang(language)

    def update_history(self, *dt):
        if self.history_screen:
            self.history_screen.update()

    def on_quotes(self, d):
        Logger.info("on_quotes")
        self._trigger_update_history()

    def on_history(self, d):
        Logger.info("on_history")
        self._trigger_update_history()

    def _get_bu(self):
        return self.electrum_config.get('base_unit', 'LTC')

    def _set_bu(self, value):
        assert value in base_units.keys()
        self.electrum_config.set_key('base_unit', value, True)
        self._trigger_update_status()
        self._trigger_update_history()

    base_unit = AliasProperty(_get_bu, _set_bu)
    status = StringProperty('')
    fiat_unit = StringProperty('')

    def on_fiat_unit(self, a, b):
        self._trigger_update_history()

    def decimal_point(self):
        return base_units[self.base_unit]

    def btc_to_fiat(self, amount_str):
        if not amount_str:
            return ''
        rate = self.fx.exchange_rate()
        if not rate:
            return ''
        fiat_amount = self.get_amount(amount_str + ' ' + self.base_unit) * rate / pow(10, 8)
        return "{:.2f}".format(fiat_amount).rstrip('0').rstrip('.')

    def fiat_to_btc(self, fiat_amount):
        if not fiat_amount:
            return ''
        rate = self.fx.exchange_rate()
        if not rate:
            return ''
        satoshis = int(pow(10,8) * Decimal(fiat_amount) / Decimal(rate))
        return format_satoshis_plain(satoshis, self.decimal_point())

    def get_amount(self, amount_str):
        a, u = amount_str.split()
        assert u == self.base_unit
        try:
            x = Decimal(a)
        except:
            return None
        p = pow(10, self.decimal_point())
        return int(p * x)


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

    def __init__(self, **kwargs):
        # initialize variables
        self._clipboard = Clipboard
        self.info_bubble = None
        self.nfcscanner = None
        self.tabs = None
        self.is_exit = False
        self.wallet = None

        App.__init__(self)#, **kwargs)

        title = _('Electrum-LTC App')
        self.electrum_config = config = kwargs.get('config', None)
        self.language = config.get('language', 'en')
        self.network = network = kwargs.get('network', None)
        if self.network:
            self.num_blocks = self.network.get_local_height()
            self.num_nodes = len(self.network.get_interfaces())
            host, port, protocol, proxy_config, auto_connect = self.network.get_parameters()
            self.server_host = host
            self.server_port = port
            self.auto_connect = auto_connect
            self.proxy_config = proxy_config if proxy_config else {}

        self.plugins = kwargs.get('plugins', [])
        self.gui_object = kwargs.get('gui_object', None)
        self.daemon = self.gui_object.daemon
        self.fx = self.daemon.fx

        self.use_rbf = config.get('use_rbf', False)
        self.use_change = config.get('use_change', True)
        self.use_unconfirmed = not config.get('confirmed_only', False)

        # create triggers so as to minimize updation a max of 2 times a sec
        self._trigger_update_wallet = Clock.create_trigger(self.update_wallet, .5)
        self._trigger_update_status = Clock.create_trigger(self.update_status, .5)
        self._trigger_update_history = Clock.create_trigger(self.update_history, .5)
        self._trigger_update_interfaces = Clock.create_trigger(self.update_interfaces, .5)
        # cached dialogs
        self._settings_dialog = None
        self._password_dialog = None

    def wallet_name(self):
        return os.path.basename(self.wallet.storage.path) if self.wallet else ' '

    def on_pr(self, pr):
        if pr.verify(self.wallet.contacts):
            key = self.wallet.invoices.add(pr)
            if self.invoices_screen:
                self.invoices_screen.update()
            status = self.wallet.invoices.get_status(key)
            if status == PR_PAID:
                self.show_error("invoice already paid")
                self.send_screen.do_clear()
            else:
                if pr.has_expired():
                    self.show_error(_('Payment request has expired'))
                else:
                    self.switch_to('send')
                    self.send_screen.set_request(pr)
        else:
            self.show_error("invoice error:" + pr.error)
            self.send_screen.do_clear()

    def on_qr(self, data):
        from electrum_ltc.bitcoin import base_decode, is_address
        data = data.strip()
        if is_address(data):
            self.set_URI(data)
            return
        if data.startswith('litecoin:'):
            self.set_URI(data)
            return
        # try to decode transaction
        from electrum_ltc.transaction import Transaction
        from electrum_ltc.util import bh2u
        try:
            text = bh2u(base_decode(data, None, base=43))
            tx = Transaction(text)
            tx.deserialize()
        except:
            tx = None
        if tx:
            self.tx_dialog(tx)
            return
        # show error
        self.show_error("Unable to decode QR data")

    def update_tab(self, name):
        s = getattr(self, name + '_screen', None)
        if s:
            s.update()

    @profiler
    def update_tabs(self):
        for tab in ['invoices', 'send', 'history', 'receive', 'requests']:
            self.update_tab(tab)

    def switch_to(self, name):
        s = getattr(self, name + '_screen', None)
        if s is None:
            s = self.tabs.ids[name + '_screen']
            s.load_screen()
        panel = self.tabs.ids.panel
        tab = self.tabs.ids[name + '_tab']
        panel.switch_to(tab)

    def show_request(self, addr):
        self.switch_to('receive')
        self.receive_screen.screen.address = addr

    def show_pr_details(self, req, status, is_invoice):
        from electrum_ltc.util import format_time
        requestor = req.get('requestor')
        exp = req.get('exp')
        memo = req.get('memo')
        amount = req.get('amount')
        fund = req.get('fund')
        popup = Builder.load_file('gui/kivy/uix/ui_screens/invoice.kv')
        popup.is_invoice = is_invoice
        popup.amount = amount
        popup.requestor = requestor if is_invoice else req.get('address')
        popup.exp = format_time(exp) if exp else ''
        popup.description = memo if memo else ''
        popup.signature = req.get('signature', '')
        popup.status = status
        popup.fund = fund if fund else 0
        txid = req.get('txid')
        popup.tx_hash = txid or ''
        popup.on_open = lambda: popup.ids.output_list.update(req.get('outputs', []))
        popup.export = self.export_private_keys
        popup.open()

    def show_addr_details(self, req, status):
        from electrum_ltc.util import format_time
        fund = req.get('fund')
        isaddr = 'y'
        popup = Builder.load_file('gui/kivy/uix/ui_screens/invoice.kv')
        popup.isaddr = isaddr
        popup.is_invoice = False
        popup.status = status
        popup.requestor = req.get('address')
        popup.fund = fund if fund else 0
        popup.export = self.export_private_keys
        popup.open()

    def qr_dialog(self, title, data, show_text=False):
        from .uix.dialogs.qr_dialog import QRDialog
        popup = QRDialog(title, data, show_text)
        popup.open()

    def scan_qr(self, on_complete):
        if platform != 'android':
            return
        from jnius import autoclass
        from android import activity
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        Intent = autoclass('android.content.Intent')
        intent = Intent("com.google.zxing.client.android.SCAN")
        intent.putExtra("SCAN_MODE", "QR_CODE_MODE")
        def on_qr_result(requestCode, resultCode, intent):
            if requestCode == 0:
                if resultCode == -1: # RESULT_OK:
                    contents = intent.getStringExtra("SCAN_RESULT")
                    if intent.getStringExtra("SCAN_RESULT_FORMAT") == 'QR_CODE':
                        on_complete(contents)
                    else:
                        self.show_error("wrong format " + intent.getStringExtra("SCAN_RESULT_FORMAT"))
        activity.bind(on_activity_result=on_qr_result)
        try:
            PythonActivity.mActivity.startActivityForResult(intent, 0)
        except:
            self.show_error(_('Could not start Barcode Scanner.') + ' ' + _('Please install the Barcode Scanner app from ZXing'))

    def scan_qr_zxing(self, on_complete):
        # uses zxing embedded lib
        if platform != 'android':
            return
        from jnius import autoclass
        from android import activity
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        IntentIntegrator = autoclass('com.google.zxing.integration.android.IntentIntegrator')
        integrator = IntentIntegrator(PythonActivity.mActivity)
        def on_qr_result(requestCode, resultCode, intent):
            if requestCode == 0:
                if resultCode == -1: # RESULT_OK:
                    contents = intent.getStringExtra("SCAN_RESULT")
                    if intent.getStringExtra("SCAN_RESULT_FORMAT") == 'QR_CODE':
                        on_complete(contents)
                    else:
                        self.show_error("wrong format " + intent.getStringExtra("SCAN_RESULT_FORMAT"))
        activity.bind(on_activity_result=on_qr_result)
        integrator.initiateScan()

    def do_share(self, data, title):
        if platform != 'android':
            return
        from jnius import autoclass, cast
        JS = autoclass('java.lang.String')
        Intent = autoclass('android.content.Intent')
        sendIntent = Intent()
        sendIntent.setAction(Intent.ACTION_SEND)
        sendIntent.setType("text/plain")
        sendIntent.putExtra(Intent.EXTRA_TEXT, JS(data))
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        currentActivity = cast('android.app.Activity', PythonActivity.mActivity)
        it = Intent.createChooser(sendIntent, cast('java.lang.CharSequence', JS(title)))
        currentActivity.startActivity(it)

    def build(self):
        return Builder.load_file('gui/kivy/main.kv')

    def _pause(self):
        if platform == 'android':
            # move activity to back
            from jnius import autoclass
            python_act = autoclass('org.kivy.android.PythonActivity')
            mActivity = python_act.mActivity
            mActivity.moveTaskToBack(True)

    def on_start(self):
        ''' This is the start point of the kivy ui
        '''
        import time
        Logger.info('Time to on_start: {} <<<<<<<<'.format(time.clock()))
        win = Window
        win.bind(size=self.on_size, on_keyboard=self.on_keyboard)
        win.bind(on_key_down=self.on_key_down)
        #win.softinput_mode = 'below_target'
        self.on_size(win, win.size)
        self.init_ui()
        self.load_wallet_by_name(self.electrum_config.get_wallet_path())
        # init plugins
        run_hook('init_kivy', self)
        # fiat currency
        self.fiat_unit = self.fx.ccy if self.fx.is_enabled() else ''
        # default tab
        self.switch_to('history')
        # bind intent for bitcoin: URI scheme
        if platform == 'android':
            from android import activity
            from jnius import autoclass
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            mactivity = PythonActivity.mActivity
            self.on_new_intent(mactivity.getIntent())
            activity.bind(on_new_intent=self.on_new_intent)
        # connect callbacks
        if self.network:
            interests = ['updated', 'status', 'new_transaction', 'verified', 'interfaces']
            self.network.register_callback(self.on_network_event, interests)
            self.network.register_callback(self.on_quotes, ['on_quotes'])
            self.network.register_callback(self.on_history, ['on_history'])
        # URI passed in config
        uri = self.electrum_config.get('url')
        if uri:
            self.set_URI(uri)


    def get_wallet_path(self):
        if self.wallet:
            return self.wallet.storage.path
        else:
            return ''

    def on_wizard_complete(self, instance, wallet):
        if wallet:
            wallet.start_threads(self.daemon.network)
            self.daemon.add_wallet(wallet)
            self.load_wallet(wallet)
        self.on_resume()

    def load_wallet_by_name(self, path):
        if not path:
            return
        wallet = self.daemon.load_wallet(path, None)
        if wallet:
            if wallet != self.wallet:
                self.stop_wallet()
                self.load_wallet(wallet)
                self.on_resume()
        else:
            Logger.debug('Electrum: Wallet not found. Launching install wizard')
            storage = WalletStorage(path)
            wizard = Factory.InstallWizard(self.electrum_config, storage)
            wizard.bind(on_wizard_complete=self.on_wizard_complete)
            action = wizard.storage.get_action()
            wizard.run(action)

    def on_stop(self):
        self.stop_wallet()

    def stop_wallet(self):
        if self.wallet:
            self.daemon.stop_wallet(self.wallet.storage.path)
            self.wallet = None

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
        if key == 27 and self.is_exit is False:
            self.is_exit = True
            self.show_info(_('Press again to exit'))
            return True
        # override settings button
        if key in (319, 282): #f1/settings button on android
            #self.gui.main_gui.toggle_settings(self)
            return True

    def settings_dialog(self):
        from .uix.dialogs.settings import SettingsDialog
        if self._settings_dialog is None:
            self._settings_dialog = SettingsDialog(self)
        self._settings_dialog.update()
        self._settings_dialog.open()

    def popup_dialog(self, name):
        if name == 'settings':
            self.settings_dialog()
        elif name == 'wallets':
            from .uix.dialogs.wallets import WalletDialog
            d = WalletDialog()
            d.open()
        else:
            popup = Builder.load_file('gui/kivy/uix/ui_screens/'+name+'.kv')
            popup.open()

    @profiler
    def init_ui(self):
        ''' Initialize The Ux part of electrum. This function performs the basic
        tasks of setting up the ui.
        '''
        #from weakref import ref

        self.funds_error = False
        # setup UX
        self.screens = {}

        #setup lazy imports for mainscreen
        Factory.register('AnimatedPopup',
                         module='electrum_ltc_gui.kivy.uix.dialogs')
        Factory.register('QRCodeWidget',
                         module='electrum_ltc_gui.kivy.uix.qrcodewidget')

        # preload widgets. Remove this if you want to load the widgets on demand
        #Cache.append('electrum_ltc_widgets', 'AnimatedPopup', Factory.AnimatedPopup())
        #Cache.append('electrum_ltc_widgets', 'QRCodeWidget', Factory.QRCodeWidget())

        # load and focus the ui
        self.root.manager = self.root.ids['manager']

        self.history_screen = None
        self.contacts_screen = None
        self.send_screen = None
        self.invoices_screen = None
        self.receive_screen = None
        self.requests_screen = None
        self.address_screen = None
        self.icon = "icons/electrum-ltc.png"
        self.tabs = self.root.ids['tabs']

    def update_interfaces(self, dt):
        self.num_nodes = len(self.network.get_interfaces())
        self.num_chains = len(self.network.get_blockchains())
        chain = self.network.blockchain()
        self.blockchain_checkpoint = chain.get_checkpoint()
        self.blockchain_name = chain.get_name()
        if self.network.interface:
            self.server_host = self.network.interface.host

    def on_network_event(self, event, *args):
        Logger.info('network event: '+ event)
        if event == 'interfaces':
            self._trigger_update_interfaces()
        elif event == 'updated':
            self._trigger_update_wallet()
            self._trigger_update_status()
        elif event == 'status':
            self._trigger_update_status()
        elif event == 'new_transaction':
            self._trigger_update_wallet()
        elif event == 'verified':
            self._trigger_update_wallet()

    @profiler
    def load_wallet(self, wallet):
        self.wallet = wallet
        self.update_wallet()
        # Once GUI has been initialized check if we want to announce something
        # since the callback has been called before the GUI was initialized
        if self.receive_screen:
            self.receive_screen.clear()
        self.update_tabs()
        run_hook('load_wallet', wallet, self)

    def update_status(self, *dt):
        self.num_blocks = self.network.get_local_height()
        if not self.wallet:
            self.status = _("No Wallet")
            return
        if self.network is None or not self.network.is_running():
            status = _("Offline")
        elif self.network.is_connected():
            server_height = self.network.get_server_height()
            server_lag = self.network.get_local_height() - server_height
            if not self.wallet.up_to_date or server_height == 0:
                status = _("Synchronizing...")
            elif server_lag > 1:
                status = _("Server lagging (%d blocks)"%server_lag)
            else:
                c, u, x = self.wallet.get_balance()
                text = self.format_amount(c+x+u)
                status = str(text.strip() + ' ' + self.base_unit)
        else:
            status = _("Disconnected")

        n = self.wallet.basename()
        self.status = '[size=15dp]%s[/size]\n%s' %(n, status)
        #fiat_balance = self.fx.format_amount_and_units(c+u+x) or ''

    def get_max_amount(self):
        inputs = self.wallet.get_spendable_coins(None, self.electrum_config)
        addr = str(self.send_screen.screen.address) or self.wallet.dummy_address()
        outputs = [(TYPE_ADDRESS, addr, '!')]
        tx = self.wallet.make_unsigned_transaction(inputs, outputs, self.electrum_config)
        amount = tx.output_value()
        return format_satoshis_plain(amount, self.decimal_point())

    def format_amount(self, x, is_diff=False, whitespaces=False):
        return format_satoshis(x, is_diff, 0, self.decimal_point(), whitespaces)

    def format_amount_and_units(self, x):
        return format_satoshis_plain(x, self.decimal_point()) + ' ' + self.base_unit

    #@profiler
    def update_wallet(self, *dt):
        self._trigger_update_status()
        if self.wallet and (self.wallet.up_to_date or not self.network or not self.network.is_connected()):
            self.update_tabs()

    def notify(self, message):
        try:
            global notification, os
            if not notification:
                from plyer import notification
            icon = (os.path.dirname(os.path.realpath(__file__))
                    + '/../../' + self.icon)
            notification.notify('Electrum-LTC', message,
                            app_icon=icon, app_name='Electrum-LTC')
        except ImportError:
            Logger.Error('Notification: needs plyer; `sudo pip install plyer`')

    def on_pause(self):
        # pause nfc
        if self.nfcscanner:
            self.nfcscanner.nfc_disable()
        return True

    def on_resume(self):
        if self.nfcscanner:
            self.nfcscanner.nfc_enable()
        # workaround p4a bug:
        # show an empty info bubble, to refresh the display
        self.show_info_bubble('', duration=0.1, pos=(0,0), width=1, arrow_pos=None)

    def on_size(self, instance, value):
        width, height = value
        self._orientation = 'landscape' if width > height else 'portrait'
        self._ui_mode = 'tablet' if min(width, height) > inch(3.51) else 'phone'

    def on_ref_label(self, label, touch):
        if label.touched:
            label.touched = False
            self.qr_dialog(label.name, label.data, True)
        else:
            label.touched = True
            self._clipboard.copy(label.data)
            Clock.schedule_once(lambda dt: self.show_info(_('Text copied to clipboard.\nTap again to display it as QR code.')))

    def set_send(self, address, amount, label, message):
        self.send_payment(address, amount=amount, label=label, message=message)

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
        self.show_error(error, icon='atlas://gui/kivy/theming/light/important',
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

    def tx_dialog(self, tx):
        from .uix.dialogs.tx_dialog import TxDialog
        d = TxDialog(self, tx)
        d.open()

    def sign_tx(self, *args):
        threading.Thread(target=self._sign_tx, args=args).start()

    def _sign_tx(self, tx, password, on_success, on_failure):
        try:
            self.wallet.sign_transaction(tx, password)
        except InvalidPassword:
            Clock.schedule_once(lambda dt: on_failure(_("Invalid PIN")))
            return
        Clock.schedule_once(lambda dt: on_success(tx))

    def _broadcast_thread(self, tx, on_complete):
        ok, txid = self.network.broadcast(tx)
        Clock.schedule_once(lambda dt: on_complete(ok, txid))

    def broadcast(self, tx, pr=None):
        def on_complete(ok, msg):
            if ok:
                self.show_info(_('Payment sent.'))
                if self.send_screen:
                    self.send_screen.do_clear()
                if pr:
                    self.wallet.invoices.set_paid(pr, tx.txid())
                    self.wallet.invoices.save()
                    self.update_tab('invoices')
            else:
                self.show_error(msg)

        if self.network and self.network.is_connected():
            self.show_info(_('Sending'))
            threading.Thread(target=self._broadcast_thread, args=(tx, on_complete)).start()
        else:
            self.show_info(_('Cannot broadcast transaction') + ':\n' + _('Not connected'))

    def description_dialog(self, screen):
        from .uix.dialogs.label_dialog import LabelDialog
        text = screen.message
        def callback(text):
            screen.message = text
        d = LabelDialog(_('Enter description'), text, callback)
        d.open()

    @profiler
    def amount_dialog(self, screen, show_max):
        from .uix.dialogs.amount_dialog import AmountDialog
        amount = screen.amount
        if amount:
            amount, u = str(amount).split()
            assert u == self.base_unit
        def cb(amount):
            screen.amount = amount
        popup = AmountDialog(show_max, amount, cb)
        popup.open()

    def protected(self, msg, f, args):
        if self.wallet.has_password():
            self.password_dialog(msg, f, args)
        else:
            f(*(args + (None,)))

    def delete_wallet(self):
        from .uix.dialogs.question import Question
        basename = os.path.basename(self.wallet.storage.path)
        d = Question(_('Delete wallet?') + '\n' + basename, self._delete_wallet)
        d.open()

    def _delete_wallet(self, b):
        if b:
            basename = os.path.basename(self.wallet.storage.path)
            self.protected(_("Enter your PIN code to confirm deletion of %s") % basename, self.__delete_wallet, ())

    def __delete_wallet(self, pw):
        wallet_path = self.get_wallet_path()
        dirname = os.path.dirname(wallet_path)
        basename = os.path.basename(wallet_path)
        if self.wallet.has_password():
            try:
                self.wallet.check_password(pw)
            except:
                self.show_error("Invalid PIN")
                return
        self.stop_wallet()
        os.unlink(wallet_path)
        self.show_error("Wallet removed:" + basename)
        d = os.listdir(dirname)
        name = 'default_wallet'
        new_path = os.path.join(dirname, name)
        self.load_wallet_by_name(new_path)

    def show_seed(self, label):
        self.protected(_("Enter your PIN code in order to decrypt your seed"), self._show_seed, (label,))

    def _show_seed(self, label, password):
        if self.wallet.has_password() and password is None:
            return
        keystore = self.wallet.keystore
        try:
            seed = keystore.get_seed(password)
            passphrase = keystore.get_passphrase(password)
        except:
            self.show_error("Invalid PIN")
            return
        label.text = _('Seed') + ':\n' + seed
        if passphrase:
            label.text += '\n\n' + _('Passphrase') + ': ' + passphrase

    def change_password(self, cb):
        if self.wallet.has_password():
            self.protected(_("Changing PIN code.") + '\n' + _("Enter your current PIN:"), self._change_password, (cb,))
        else:
            self._change_password(cb, None)

    def _change_password(self, cb, old_password):
        if self.wallet.has_password():
            if old_password is None:
                return
            try:
                self.wallet.check_password(old_password)
            except InvalidPassword:
                self.show_error("Invalid PIN")
                return
        self.password_dialog(_('Enter new PIN'), self._change_password2, (cb, old_password,))

    def _change_password2(self, cb, old_password, new_password):
        self.password_dialog(_('Confirm new PIN'), self._change_password3, (cb, old_password, new_password))

    def _change_password3(self, cb, old_password, new_password, confirmed_password):
        if new_password == confirmed_password:
            self.wallet.update_password(old_password, new_password)
            cb()
        else:
            self.show_error("PIN numbers do not match")

    def password_dialog(self, msg, f, args):
        from .uix.dialogs.password_dialog import PasswordDialog
        def callback(pw):
            Clock.schedule_once(lambda x: f(*(args + (pw,))), 0.1)
        if self._password_dialog is None:
            self._password_dialog = PasswordDialog()
        self._password_dialog.init(msg, callback)
        self._password_dialog.open()

    def export_private_keys(self, pk_label, addr):
        if self.wallet.is_watching_only():
            self.show_info(_('This is a watching-only wallet. It does not contain private keys.'))
            return
        def show_private_key(addr, pk_label, password):
            if self.wallet.has_password() and password is None:
                return
            if not self.wallet.can_export():
                return
            key = str(self.wallet.export_private_key(addr, password)[0])
            pk_label.data = key
        self.protected(_("Enter your PIN code in order to decrypt your private key"), show_private_key, (addr, pk_label))
