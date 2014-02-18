from functools import partial
import os, datetime, json, csv

from kivy.app import App
from kivy.animation import Animation
from kivy.core.clipboard import Clipboard
from kivy.clock import Clock
from kivy.factory import Factory
from kivy.metrics import dp
from kivy.properties import (ObjectProperty, StringProperty, ListProperty,
                            DictProperty)

from kivy.uix.button import Button
from kivy.uix.bubble import Bubble, BubbleButton
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.screenmanager import Screen as Screen, ScreenManager
from kivy.uix.tabbedpanel import TabbedPanel


from electrum_gui.kivy.dialog import (NewContactDialog, TakeInputDialog,
        PrivateKeyDialog, SignVerifyDialog, MessageBox, MessageBoxError,
        SaveDialog, LoadDialog, InfoDialog, ImportPrivateKeysDialog, Dialog,
        EditLabelDialog, EditDescriptionDialog, ShowMasterPublicKeyDialog,
        RecentActivityDialog)

from electrum_gui.i18n import _, languages
from electrum_gui.kivy.menus import ContextMenu
from electrum.interface import DEFAULT_PORTS
from electrum.verifier import WalletVerifier
from electrum.wallet import Wallet, WalletSynchronizer
from electrum.bitcoin import is_valid

DEFAULT_PATH = '/tmp/'

# Delayed imports
encode_uri = None


class CScreen(Screen):

    __events__ = ('on_activate', 'on_deactivate')

    action_view = ObjectProperty(None)

    def _change_action_view(self):
        app = App.get_running_app()
        action_bar = app.root.main_screen.ids.action_bar
        _action_view = self.action_view

        if (not _action_view) or _action_view.parent:
            return
        action_bar.clear_widgets()
        action_bar.add_widget(_action_view)

    def on_activate(self):
        Clock.schedule_once(lambda dt: self._change_action_view())

    def on_deactivate(self):
        Clock.schedule_once(lambda dt: self._change_action_view())


class RootManager(ScreenManager):
    '''Main Root Widget of the app'''

    # initialize properties that will be updted in kv
    main_screen = ObjectProperty(None)
    '''Object holding the reference to main screen'''

    screen_preferences = ObjectProperty(None)
    '''Object holding the reference to preferences screen'''

    screen_seed = ObjectProperty(None)
    ''''''

    screen_network = ObjectProperty(None)
    '''Object holding the Network screen'''


class MainScreen(Screen):

    pass


class ScreenSend(CScreen):

    pass


class ScreenDashboard(CScreen):

    tab = ObjectProperty(None)

    def show_tx_details(
        self, date, address, amount, amount_color, balance,
        tx_hash, conf, quote_text):

        ra_dialog = RecentActivityDialog()

        ra_dialog.address = address
        ra_dialog.amount = amount
        ra_dialog.amount_color = amount_color
        ra_dialog.confirmations = conf
        ra_dialog.quote_text = quote_text
        date_time = date.split()
        if len(date_time) == 2:
            ra_dialog.date = date_time[0]
            ra_dialog.time = date_time[1]
            ra_dialog.status = 'Validated'
        else:
            ra_dialog.date = date_time
            ra_dialog.status = 'Pending'
        ra_dialog.tx_hash = tx_hash

        app = App.get_running_app()
        main_gui = app.gui.main_gui
        tx_hash = tx_hash
        tx = app.wallet.transactions.get(tx_hash)

        if tx_hash in app.wallet.transactions.keys():
            is_relevant, is_mine, v, fee = app.wallet.get_tx_value(tx)
            conf, timestamp = app.wallet.verifier.get_confirmations(tx_hash)
            #if timestamp:
            #    time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
            #else:
            #    time_str = 'pending'
        else:
            is_mine = False

        ra_dialog.is_mine = is_mine

        if is_mine:
            if fee is not None: 
                ra_dialog.fee = main_gui.format_amount(fee)
            else:
                ra_dialog.fee = 'unknown'

        ra_dialog.open()


class ScreenPassword(Screen):

    __events__ = ('on_release', 'on_deactivate', 'on_activate')

    def on_activate(self):
        app = App.get_running_app()
        action_bar = app.root.main_screen.ids.action_bar
        action_bar.add_widget(self._action_view)

    def on_deactivate(self):
        self.ids.password.text = ''

    def on_release(self, *args):
        pass


class SettingsScreen(Screen):

    def __init__(self, **kwargs):
        super(SettingsScreen, self).__init__(**kwargs)
        Clock.schedule_once(self.delayed_init)
        self.app = App.get_running_app()

    def on_enter(self, *args):
        self.delayed_init()

    def delayed_init(self, *dt):
        app = self.app
        try:
            main_gui = app.gui.main_gui
        except AttributeError:
            # wait for main gui to start
            Clock.schedule_once(self.delayed_init, 1)
            return
        ids = self.ids

        ids.st_unit_combo.key = main_gui.base_unit()
        ids.st_fee_e.text = main_gui.format_amount(app.wallet.fee).strip()
        ids.st_expert_cb.active = main_gui.expert_mode

        currencies = main_gui.exchanger.get_currencies()
        currencies.insert(0, "None")
        currencies = zip(currencies, currencies)
        key = app.conf.get('currency', 'None')
        ids.st_cur_combo.text = ids.st_cur_combo.key = key
        ids.st_cur_combo.items = currencies

        ids.st_lang_combo.key = key = app.conf.get("language", '')
        ids.st_lang_combo.items = languages.items()
        x, y = zip(*ids.st_lang_combo.items)
        ids.st_lang_combo.text = y[x.index(key)]

    def do_callback(self, instance):
        ids = self.ids
        app = self.app
        wallet = app.wallet
        main_gui = app.gui.main_gui

        if instance == ids.export_labels:
            title = _("Select file to save your labels")
            path = DEFAULT_PATH
            filename = "electrum_labels.dat"
            filters = ["*.dat"]

            def save(instance):
                path = dialog.file_chooser.path
                filename = dialog.text_input.text.strip()
                labels = wallet.labels
                try:
                    with open(os.path.join(path, filename), 'w+') as stream:
                        json.dump(labels, stream)
                    MessageBox(title="Labels exported",
                               message=_("Your labels were exported to")\
                                   + " '%s'" % str(filename),
                               size=('320dp', '320dp')).open()
                except (IOError, os.error), reason:
                    MessageBoxError(
                        title="Unable to export labels",
                        message=_("Electrum was unable to export your labels.")+
                            "\n" + str(reason), size=('320dp', '320dp')).open()
                dialog.close()

            dialog = SaveDialog(title=title,
                                path=path,
                                filename=filename,
                                filters=filters)
            dialog.save_button.bind(on_release=save)
            dialog.open()

        elif instance == ids.import_labels:
            title = _("Open labels file")
            path = DEFAULT_PATH
            filename = ""
            filters = ["*.dat"]

            def load(instance):
                path = dialog.file_chooser.path
                filename = dialog.text_input.text.strip()

                labels = wallet.labels
                try:
                    with open(os.path.join(path, filename), 'r') as stream:
                        for key, value in json.loads(stream.read()).items():
                            wallet.labels[key] = value
                        wallet.save()
                    MessageBox(title="Labels imported",
                               message=_("Your labels were imported from") + " '%s'" % str(filename),
                               size=('320dp', '320dp')).open()
                except (IOError, os.error), reason:
                    MessageBoxError(title="Unable to import labels",
                                    message=_("Electrum was unable to import your labels.") + "\n" + str(reason),
                                    size=('320dp', '320dp')).open()

                dialog.close()

            dialog = LoadDialog(title=title, path=path, filename=filename, filters=filters)
            dialog.load_button.bind(on_press=load)
            dialog.open()

        elif instance == ids.export_history:
            title = _("Select file to export your wallet transactions to")
            path = os.path.expanduser('~')
            filename = "electrum-history.csv"
            filters = ["*.csv"]

            def save(instance):
                path = dialog.file_chooser.path
                filename = dialog.text_input.text.strip()
                # extracted from gui_lite.csv_transaction
                wallet = wallet
                try:
                    with open(os.path.join(path, filename), "w+") as stream:
                        transaction = csv.writer(stream)
                        transaction.writerow(["transaction_hash", "label", "confirmations", "value", "fee", "balance", "timestamp"])
                        for item in wallet.get_tx_history():
                            tx_hash, confirmations, is_mine, value, fee, balance, timestamp = item
                            if confirmations:
                                if timestamp is not None:
                                    try:
                                        time_string = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
                                    except [RuntimeError, TypeError, NameError] as reason:
                                        time_string = "unknown"
                                        pass
                                else:
                                    time_string = "unknown"
                            else:
                                time_string = "pending"

                            if value is not None:
                                value_string = format_satoshis(value, True, wallet.num_zeros)
                            else:
                                value_string = '--'

                            if fee is not None:
                                fee_string = format_satoshis(fee, True, wallet.num_zeros)
                            else:
                                fee_string = '0'

                            if tx_hash:
                                label, is_default_label = wallet.get_label(tx_hash)
                            else:
                                label = ""

                            balance_string = format_satoshis(balance, False, wallet.num_zeros)
                            transaction.writerow([tx_hash, label, confirmations, value_string, fee_string, balance_string, time_string])
                        MessageBox(title="CSV Export created",
                                   message="Your CSV export has been successfully created.",
                                   size=('320dp', '320dp')).open()
                except (IOError, os.error), reason:
                    export_error_label = _("Electrum was unable to produce a transaction export.")
                    MessageBoxError(title="Unable to create csv",
                                    message=export_error_label + "\n" + str(reason),
                                    size=('320dp', '320dp')).open()
                dialog.close()

            dialog = SaveDialog(title=title, path=path, filename=filename, filters=filters)
            dialog.save_button.bind(on_press=save)
            dialog.open()

        elif instance == ids.export_privkey:
            # NOTE: equivalent to @protected
            def protected_save_dialog(instance=None, password=None):
                def show_save_dialog(_dlg, instance):
                    _dlg.close()
                    title = _("Select file to export your private keys to")
                    path = DEFAULT_PATH
                    filename = "electrum-private-keys.csv"
                    filters = ["*.csv"]

                    def save(instance):
                        path = dialog.file_chooser.path
                        filename = dialog.text_input.text.strip()
                        try:
                            with open(os.path.join(path, filename), "w+") as csvfile:
                                transaction = csv.writer(csvfile)
                                transaction.writerow(["address", "private_key"])
                                for addr, pk in wallet.get_private_keys(wallet.addresses(True), password).items():
                                    transaction.writerow(["%34s" % addr, pk])
                                MesageBox(message=_("Private keys exported."),
                                          size=('320dp', '320dp')).open()
                        except (IOError, os.error), reason:
                            export_error_label = _("Electrum was unable to produce a private key-export.")
                            return MessageBoxError(message="Unable to create csv", content_text=export_error_label + "\n" + str(reason),
                                            size=('320dp', '320dp')).open()
                        except BaseException, e:
                            return app.show_info_bubble(text=str(e))

                        dialog.close()

                    dialog = SaveDialog(title=title, path=path, filename=filename, filters=filters)
                    dialog.save_button.bind(on_press=save)
                    dialog.open()

                mb = MessageBox(message="%s\n%s\n%s" % (
                                _("[color=ff0000ff][b]WARNING[/b][/color]: ALL your private keys are secret."),
                                _("Exposing a single private key can compromise your entire wallet!") + '\n\n',
                                _("In particular, [color=ff0000ff]DO NOT[/color] use 'redeem private key' services proposed by third parties.")),
                                on_release=show_save_dialog,
                                size = ('350dp', '320dp')).open()

            if wallet.use_encryption:
                return main_gui.password_required_dialog(post_ok=protected_save_dialog)
            return protected_save_dialog()

        elif instance == ids.import_privkey:
            # NOTE: equivalent to @protected
            def protected_load_dialog(_instance=None, password=None):
                def show_privkey_dialog(__instance=None):

                    def on_release(_dlg, _btn):
                        if _btn.text == _('Cancel'):
                            _dlg.close()
                            confirm_dialog.close()
                            return

                        text = _dlg.ids.ti.text.split()
                        badkeys = []
                        addrlist = []
                        for key in text:
                            try:
                                addr = wallet.import_key(key, password)
                            except BaseException as e:
                                badkeys.append(key)
                                continue
                            if not addr:
                                badkeys.append(key)
                            else:
                                addrlist.append(addr)
                        if addrlist:
                            MessageBox(title=_('Information'),
                                       message=_("The following addresses were added") + ':\n' + '\n'.join(addrlist),
                                       size=('320dp', '320dp')).open()
                        if badkeys:
                            MessageBoxError(title=_('Error'),
                                            message=_("The following inputs could not be imported") + ':\n' + '\n'.join(badkeys),
                                            size=('320dp', '320dp')).open()
                        main_gui.update_receive_tab()
                        main_gui.update_history_tab()

                        if _instance is not None:  # called via callback
                            _dlg.close()

                    ImportPrivateKeysDialog(on_release=on_release).open()

                if not wallet.imported_keys:

                    def on_release(_dlg, _btn):
                        _dlg.close
                        if _btn.text == _('No'):
                            return
                        show_privkey_dialog()

                    confirm_dialog = MessageBoxError(title=_('Warning'),
                        message=_('Imported keys are not recoverable from seed.') + ' ' \
                        + _('If you ever need to restore your wallet from its seed, these keys will be lost.') + '\n\n' \
                        + _('Are you sure you understand what you are doing?'),
                        size=('320dp', '320dp'),
                        on_release=on_release)
                    confirm_dialog.buttons = [_('No'), _('Yes')]
                    confirm_dialog.open()
                else:
                    show_privkey_dialog()

            if wallet.use_encryption:
                return main_gui.password_required_dialog(
                    post_ok=protected_load_dialog)
            return protected_load_dialog()

        elif instance == ids.show_pubkey:
            # NOTE: Kivy TextInput doesn't wrap long text. So must handle it manually
            pub_key = wallet.get_master_public_key()
            pub_key = '%s\n%s\n%s\n%s' % (pub_key[0:31], pub_key[32:63], pub_key[64:95], pub_key[96:127])
            ShowMasterPublicKeyDialog(text=pub_key).open()

        elif instance == ids.from_file:
            title = _("Select your transaction file")
            path = DEFAULT_PATH
            filename = ""
            filters = ["*.txn"]

            def load(instance):
                path = dialog.file_chooser.path
                filename = dialog.text_input.text.strip()

                if not filename:
                    return
                try:
                    with open(os.path.join(path, filename), "r") as f:
                        file_content = f.read()
                except (ValueError, IOError, os.error), reason:
                    MessageBoxError(title="Unable to read file or no transaction found",
                                    message=_("Electrum was unable to open your transaction file") + "\n" + str(reason),
                                    size=('320dp', '320dp')).open()

                tx_dict = main_gui.tx_dict_from_text(file_content)
                if tx_dict:
                    main_gui.create_process_transaction_window(tx_dict)

                dialog.close()

            dialog = LoadDialog(title=title, path=path, filename=filename, filters=filters)
            dialog.load_button.bind(on_press=load)
            dialog.open()

        elif instance == ids.from_text:
            def load_transaction(_dlg, _btn):
                if _btn.text == _('Cancel'):
                    _dlg.close
                    return
                text = _dlg.ids.ti.text
                if not text:
                    return
                tx_dict = main_gui.tx_dict_from_text(text)
                if tx_dict:
                    main_gui.create_process_transaction_window(tx_dict)
                _dlg.close()

            dialog = TakeInputDialog(on_release=load_transaction)
            dialog.title = title=_("Input raw transaction")
            dialog.open()

        # End of do_callback() #

    def on_ok(self, instance):
        ##########
        app = self.app
        main_gui = app.gui.main_gui

        fee = unicode(self.ids.st_fee_e.text)
        try:
            fee = main_gui.read_amount(fee)
        except:
            return MessageBoxError(message=_('Invalid value') + ': %s' % fee).open()

        app.wallet.set_fee(fee)

        ##########
        nz = unicode(self.ids.st_nz_e.text)
        try:
            nz = int(nz)
            if nz > 8: nz = 8
        except:
            return MessageBoxError(message=_('Invalid value') + ':%s' % nz).open()

        if app.wallet.num_zeros != nz:
            app.wallet.num_zeros = nz
            app.conf.set_key('num_zeros', nz, True)
            main_gui.update_history_tab()
            main_gui.update_receive_tab()

        usechange_result = self.ids.st_usechange_cb.active
        if app.wallet.use_change != usechange_result:
            app.wallet.use_change = usechange_result
            app.conf.set_key('use_change', app.wallet.use_change, True)

        unit_result = self.ids.st_unit_combo.text
        if main_gui.base_unit() != unit_result:
            main_gui.decimal_point = 8 if unit_result == 'BTC' else 5
            app.conf.set_key('decimal_point', main_gui.decimal_point, True)
            main_gui.update_history_tab()
            main_gui.update_status()

        try:
            n = int(self.ids.st_gap_e.text)
        except:
            return MessageBoxError(message=_('Invalid value')).open()

        if app.wallet.gap_limit != n:
            if app.wallet.change_gap_limit(n):
                main_gui.update_receive_tab()
                app.conf.set_key('gap_limit', app.wallet.gap_limit, True)
            else:
                MessageBoxError(Message=_('Invalid value')).open()
                # TODO: no return???

        need_restart = False

        lang_request = str(self.ids.st_lang_combo.key)
        if lang_request != app.conf.get('language'):
            app.conf.set_key("language", lang_request, True)  # TODO: why can't save unicode
            need_restart = True

        cur_request = str(self.ids.st_cur_combo.text)
        if cur_request != app.conf.get('currency', "None"):
            app.conf.set_key('currency', cur_request, True)  # TODO: why can't save unicode
            main_gui.update_wallet()

        main_gui.run_hook('close_settings_dialog')

        if need_restart:
            MessageBox(message=_('Please restart Electrum to activate the new GUI settings')).open()

        # from receive_tab_set_mode()
        main_gui.save_column_widths()
        main_gui.expert_mode = self.ids.st_expert_cb.active
        app.conf.set_key('classic_expert_mode', main_gui.expert_mode, True)
        main_gui.update_receive_tab()

        # close
        app.root.current = 'main_screen'


class NetworkScreen(Screen):

    status = StringProperty(_('Uninitialized'))
    '''status message displayed on top of screen'''

    server = StringProperty('')

    #servers = ListProperty([])

    servers_view = ObjectProperty(None)

    server_host = ObjectProperty(None)

    server_port = ObjectProperty(None)

    server_protocol = ObjectProperty(None)

    proxy_host = ObjectProperty(None)

    proxy_port = ObjectProperty(None)

    proxy_mode = ObjectProperty(None)

    protocol_names = ListProperty(['TCP', 'HTTP', 'SSL', 'HTTPS'])

    protocol_letters = StringProperty('thsg')

    proxy_names = ListProperty(['NONE', 'SOCKS4', 'SOCKS5', 'HTTP'])

    proxy_keys = ListProperty(['none', 'socks4', 'socks5', 'http'])

    autocycle_cb = ObjectProperty(None)

    interface = ObjectProperty(None)

    def __init__(self, **kwargs):
        self.initialized = True
        super(NetworkScreen, self).__init__(**kwargs)
        Clock.schedule_once(self._delayed_init)

    def _delayed_init(self, dt):
        self.protocol = None
        self.app = app = App.get_running_app()
        self.conf = conf = app.conf
        self.wallet = wallet = app.wallet
        self.interface = interface = wallet.interface

        if not self.initialized:
            if interface.is_connected:
                self.status = _("Connected to") + " %s" % (interface.host) + "\n%d " % (wallet.verifier.height) + _("blocks")
            else:
                self.status = _("Not connected")
        else:
            self.status = _("Please choose a server.") + "\n" + _("Select 'Cancel' if you are offline.")
        self.server = server = interface.server

        self.servers = interface.get_servers()

        self.servers_view.content_adapter.bind(on_selection_change=self.server_changed)

        ########################
        if server:
            host, port, protocol = server.split(':')
            self.set_protocol(protocol)
            self.change_server(host, protocol)
        else:
            self.set_protocol('s')

        ########################
        # TODO: review it
        # if not config.is_modifiable('server'):
        #    for w in [self.server_host, self.server_port, self.server_protocol, self.servers_list_widget]: w.setEnabled(False)

        self.check_for_disable(None, 'none')

        # if not wallet.config.is_modifiable('proxy'):
        #    for w in [proxy_host, proxy_port, proxy_mode]: w.setEnabled(False)

        proxy_config = interface.proxy\
                if interface.proxy else\
                { "mode":"none", "host":"localhost", "port":"8080"}
        self.proxy_mode.key = proxy_config.get("mode")
        self.proxy_host.text = proxy_config.get("host")
        self.proxy_port.text = proxy_config.get("port")

        # server = unicode( server_host.text ) + ':' + unicode( server_port.text ) + ':' + (protocol_letters[server_protocol.currentIndex()])
        # if proxy_mode.currentText() != 'NONE':
        #    proxy = { u'mode':unicode(proxy_mode.currenttext).lower(), u'host':unicode(proxy_host.text), u'port':unicode(proxy_port.text) }
        # else:
        #    proxy = None

        self.autocycle_cb.active = conf.get('auto_cycle', True)
        if not conf.is_modifiable('auto_cycle'):
            self.autocycle_cb.active = False

    def check_for_disable(self, instance, proxy_mode_key):
        if proxy_mode_key != 'none':
            self.proxy_host.disabled = False
            self.proxy_port.disabled = False
        else:
            self.proxy_host.disabled = True
            self.proxy_port.disabled = True

    def on_cancel(self, *args):
        self.manager.current = 'main_screen'

        # TODO: RuntimeError: threads can only be started once
        # interface.start(wait=False)
        # interface.send([('server.peers.subscribe', [])])

        # generate the first addresses, in case we are offline
        self.wallet.synchronize()

        verifier = WalletVerifier(self.interface, self.conf)
        verifier.start()
        self.wallet.set_verifier(verifier)
        synchronizer = WalletSynchronizer(self.wallet, self.conf)
        synchronizer.start()

        if not self.initialized:
            self.app.gui.main_gui.change_password_dialog()

    def on_ok(self, *args):
        self.manager.current = 'main_screen'

        ################
        server = ':'.join([str(self.server_host.text),
                            str(self.server_port.text),
                            str(self.server_protocol.key)])

        if self.proxy_mode.key != 'none':
            proxy = { 'mode':str(self.proxy_mode.key),
                        'host':str(self.proxy_host.text),
                        'port':str(self.proxy_port.text) }
        else:
            proxy = None

        app = self.app
        conf = self.conf
        wallet = self.wallet
        interface = self.interface
        conf.set_key("proxy", proxy, True)
        conf.set_key("server", server, True)
        interface.set_server(server, proxy)
        conf.set_key('auto_cycle', self.autocycle_cb.active, True)

        # generate the first addresses, in case we are offline
        if app.gui.action == 'create':
            app.wallet.synchronize()
            app.gui.change_password_dialog()

        verifier = WalletVerifier(interface, conf)
        verifier.start()
        wallet.set_verifier(verifier)
        synchronizer = WalletSynchronizer(wallet, conf)
        synchronizer.start()

        if app.gui.action == 'restore':
            initialized = self.initialized
            try:
                def on_complete(keep_it=False):
                    wallet.fill_addressbook()
                    #if not keep_it:
                    #    app.stop()
                    #    return
                    if not initialized:
                        app.gui.change_password_dialog()

                app.gui.restore_wallet(on_complete=on_complete)
            except:
                import traceback, sys
                traceback.print_exc(file=sys.stdout)
                app.stop()
        if not interface.isAlive():
            interface.start(wait=False)
        interface.send([('server.peers.subscribe', [])])


    def init_servers_list(self):
        data = []
        for _host, d in self.servers.items():
            if d.get(self.protocol):
                pruning_level = d.get('pruning', '')
                data.append((_host, pruning_level))
        self.servers_view.content_adapter.data = data

    def set_protocol(self, protocol):
        if protocol != self.protocol:
            self.protocol = protocol
            self.init_servers_list()

    def on_change_protocol(self, instance, protocol_key):
        p = protocol_key
        host = unicode(self.server_host.text)
        pp = self.servers.get(host)
        if not pp:
            return
        if p not in pp.keys():
            p = pp.keys()[0]
        port = pp[p]
        self.server_host.text = host
        self.server_port.text = port
        self.set_protocol(p)

    def server_changed(self, instance):
        try:
            index = instance.selection[0].index
        except (AttributeError, IndexError):
            return
        item = instance.get_data_item(index)
        self.change_server(item[0], self.protocol)

    def change_server(self, host, protocol):
        pp = self.servers.get(host, DEFAULT_PORTS)
        if protocol:
            port = pp.get(protocol)
            if not port: protocol = None

        if not protocol:
            if 's' in pp.keys():
                protocol = 's'
                port = pp.get(protocol)
            else:
                protocol = pp.keys()[0]
                port = pp.get(protocol)

        self.server_host.text = host
        self.server_port.text = port
        self.server_protocol.text = self.protocol_names[self.protocol_letters.index(protocol)]

        if not self.servers: return
        # TODO: what's this?
        # for p in protocol_letters:
        #    i = protocol_letters.index(p)
        #    j = self.server_protocol.model().index(i,0)
        #    #if p not in pp.keys(): # and self.interface.is_connected:
        #    #    self.server_protocol.model().setData(j, QVariant(0), Qt.UserRole-1)
        #    #else:
        #    #    self.server_protocol.model().setData(j, QVariant(33), Qt.UserRole-1)

class ScreenAddress(CScreen):

    labels  = DictProperty({})
    '''
    '''

    tab =  ObjectProperty(None)
    ''' The tab associated With this Carousel
    '''

class ScreenConsole(CScreen):

    pass


class ScreenReceive(CScreen):

    pass

#TODO: move to wallet management
class ScreenReceive2(CScreen):

    receive_view = ObjectProperty(None)

    def __init__(self, **kwargs):
        self.context_menu = None
        super(ScreenReceive, self).__init__(**kwargs)
        self.app = App.get_running_app()

    def on_receive_view(self, instance, value):
        if not value:
            return
        value.on_context_menu = self.on_context_menu

    def on_menu_item_selected(self, instance, _menu, _btn):
        '''Called when any one of the bubble menu items is selected
        '''
        app = self.app
        main_gui = app.gui.main_gui

        def delete_imported_key():
            def on_release(_dlg, _dlg_btn):
                if _dlg_btn.text == _('Cancel'):
                    _dlg.close()
                    return
                app.wallet.delete_imported_key(address)
                main_gui.update_receive_tab()
                main_gui.update_history_tab()

            MessageBox(title=_('Delete imported key'),
                            message=_("Do you want to remove")
                                +" %s "%addr +_("from your wallet?"),
                            buttons=[_('Cancel'), _('OK')],
                            on_release=on_release).open()

        def edit_label_dialog():
            # Show dialog to edit the label
            def save_label(_dlg, _dlg_btn):
                if _dlg_btn.text != _('Ok'):
                    return
                txt = _dlg.ids.ti.text
                if txt:
                    instance.parent.children[2].text = txt
                _dlg.close()

            text = instance.parent.children[2].text
            dialog = EditLabelDialog(text=text,
                                     on_release=save_label).open()

        def show_private_key_dialog():
            # NOTE: equivalent to @protected
            def protected_show_private_key(_instance=None, password=None):
                try:
                    pk = app.wallet.get_private_key(address, password)
                except BaseException, e:
                    app.show_info_bubble(text=str(e))
                    return

                PrivateKeyDialog(address=address,
                                 private_key=pk).open()

            if app.wallet.use_encryption:
                return main_gui.password_required_dialog(
                                            post_ok=protected_show_private_key)
            protected_show_private_key()

        def show_sign_verify_dialog():
            def on_release(_dlg, _dlg_btn):
                if _dlg_btn.text != _('Ok'):
                    return
                if _dlg.ids.tabs.current_tab.text == _('Sign'):
                    # NOTE: equivalent to @protected
                    def protected_do_sign_message(instance=None, password=None):
                        try:
                            sig = app.wallet.sign_message(
                                    _dlg.ids.sign_address.text,
                                    _dlg.ids.sign_message.text,
                                    password)
                            _dlg.ids.sign_signature.text = sig
                        except BaseException, e:
                            app.show_info_bubble(text=str(e.message))

                    if app.wallet.use_encryption:
                        return main_gui.password_required_dialog(
                                post_ok=protected_do_sign_message)
                    return protected_do_sign_message()

                else:  # _('Verify')
                    if app.wallet.verify_message(
                            _dlg.ids.verify_address.text,
                            _dlg.ids.verify_signature.text,
                            _dlg.ids.verify_message.text):
                        app.show_info_bubble(text=_("Signature verified"))
                    else:
                        app.show_info_bubble(
                            text=_("Error: wrong signature"))
            SignVerifyDialog(on_release=on_release, address=address).open()

        def toggle_freeze():
            if address in app.wallet.frozen_addresses:
                app.wallet.unfreeze(address)
            else:
                app.wallet.freeze(address)
            main_gui.update_receive_tab()

        def toggle_priority(_dlg, _dlg_btn):
            if address in app.wallet.prioritized_addresses:
                app.wallet.unprioritize(address)
            else:
                app.wallet.prioritize(address)
            main_gui.update_receive_tab()

        _menu.hide()
        address = instance.parent.children[3].text

        if _btn.text == _('Copy to clipboard'):
            # copy data to clipboard
            Clipboard.put(instance.parent.children[3].text, 'UTF8_STRING')
        elif _btn.text == _('Edit label'):
            edit_label_dialog()
        elif _btn.text == _('Private key'):
            show_private_key_dialog()
        elif _btn.text == _('Sign message'):
            # sign message
            show_sign_verify_dialog()
        elif _btn.text == _('Remove_from_wallet'):
            delete_imported_key()
        elif _btn.text in (_('Freeze'), _('Unfreeze')):
            toggle_freeze()
        elif _btn.text in (_('Prioritize'), _('Unprioritize')):
            toggle_priority(_menu, _btn)


    def on_context_menu(self, instance):
        '''Called when list item is clicked.
        Objective: show bubble menu
        '''
        app = self.app
        address = instance.parent.children[3].text
        if not address or not is_valid(address): return

        context_menu = ContextMenu(size_hint=(None, None),
                                size=('160dp', '160dp'),
                                orientation='vertical',
                                arrow_pos='left_mid',
                                buttons=[_('Copy to clipboard'),
                                        _('Edit label'),
                                        _('Private key'),
                                        _('Sign message')],
                                on_release=partial(self.on_menu_item_selected,
                                                   instance))
        if address in app.wallet.imported_keys:
            context_menu.buttons = context_menu.buttons +\
                                [_('Remove from wallet')]
            # TODO: test more this feature

        if app.gui.main_gui.expert_mode:
            # TODO: show frozen, prioritized rows in different color
            # as original code

            t = _("Unfreeze")\
                 if address in app.wallet.frozen_addresses else\
                 _("Freeze")
            context_menu.buttons = context_menu.buttons + [t]
            t = _("Unprioritize")\
                if address in app.wallet.prioritized_addresses else\
                _("Prioritize")
            context_menu.buttons = context_menu.buttons + [t]
        context_menu.show(pos=(instance.right, instance.top))


class ScreenContacts(CScreen):

    def add_new_contact(self):
        NewContactDialog().open()



class TabbedCarousel(TabbedPanel):

    carousel = ObjectProperty(None)

    def animate_tab_to_center(self, value):
        scrlv = self._tab_strip.parent
        if not scrlv:
            return
        self_center_x = scrlv.center_x
        vcenter_x = value.center_x
        diff_x = (self_center_x - vcenter_x)
        try:
            scroll_x = scrlv.scroll_x - (diff_x / scrlv.width)
        except ZeroDivisionError:
            pass
        mation = Animation(scroll_x=max(0, min(scroll_x, 1)), d=.25)
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
                carousel.slides[ct.slide].dispatch('on_deactivate')
                self.switch_to(tab)
                carousel.slides[tab.slide].dispatch('on_activate')
        except AttributeError:
            current_slide.dispatch('on_activate')

    def switch_to(self, header):
        # we have to replace the functionality of the original switch_to
        if not header:
            return
        if not hasattr(header, 'slide'):
            header.content = self.carousel
            super(TabbedCarousel, self).switch_to(header)
            tab = self.tab_list[-1]
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
            carousel.current_slide.dispatch('on_deactivate')
            carousel.load_slide(slide)
            slide.dispatch('on_activate')

    def add_widget(self, widget, index=0):
        if isinstance(widget, Screen):
            self.carousel.add_widget(widget)
            return
        super(TabbedCarousel, self).add_widget(widget, index=index)


class TabbedScreens(TabbedPanel):

    manager = ObjectProperty(None)
    '''Linked to the screen manager in kv'''

    def switch_to(self, header):
        # we don't use default tab so skip
        if not hasattr(header, 'screen'):
            header.content = self.manager
            super(TabbedScreens, self).switch_to(header)
            return
        if not header.screen:
            return
        panel = self
        panel.current_tab.state = "normal"
        header.state = 'down'
        panel._current_tab = header
        self.manager.current = header.screen

    def add_widget(self, widget, index=0):
        if isinstance(widget, Screen):
            self.manager.add_widget(widget)
            return
        super(TabbedScreens, self).add_widget(widget, index=index)
