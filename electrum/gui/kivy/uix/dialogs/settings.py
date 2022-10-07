from typing import TYPE_CHECKING

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.util import base_units_list
from electrum.i18n import languages
from electrum.gui.kivy.i18n import _
from electrum.plugin import run_hook
from electrum import coinchooser

from electrum.gui import messages
from electrum.gui.kivy import KIVY_GUI_PATH

from .choice_dialog import ChoiceDialog

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string('''
#:import partial functools.partial
#:import _ electrum.gui.kivy.i18n._
#:import messages electrum.gui.messages

<SettingsDialog@Popup>
    id: settings
    title: _('Electrum Settings')
    has_pin_code: False
    use_encryption: False
    enable_toggle_use_recoverable_channels: False
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            GridLayout:
                id: scrollviewlayout
                cols:1
                size_hint: 1, None
                height: self.minimum_height
                padding: '10dp'
                SettingsItem:
                    lang: settings.get_language_name()
                    title: 'Language' + ': ' + str(self.lang)
                    description: _('Language')
                    action: partial(root.language_dialog, self)
                CardSeparator
                SettingsItem:
                    status: 'ON' if root.has_pin_code else 'OFF'
                    title: _('PIN code') + ': ' + self.status
                    description: _("Change your PIN code.") if root.has_pin_code else _("Add PIN code")
                    action: partial(root.change_pin_code, self)
                CardSeparator
                SettingsItem:
                    bu: app.base_unit
                    title: _('Denomination') + ': ' + self.bu
                    description: _("Base unit for Bitcoin amounts.")
                    action: partial(root.unit_dialog, self)
                CardSeparator
                SettingsItem:
                    status: root.fx_status()
                    title: _('Fiat Currency') + ': ' + self.status
                    description: _("Display amounts in fiat currency.")
                    action: partial(root.fx_dialog, self)
                CardSeparator
                SettingsItem:
                    status: 'ON' if bool(app.plugins.get('labels')) else 'OFF'
                    title: _('Labels Sync') + ': ' + self.status
                    description: _("Save and synchronize your labels.")
                    action: partial(root.plugin_dialog, 'labels', self)
                CardSeparator
                SettingsItem:
                    status: _('Yes') if app.use_unconfirmed else _('No')
                    title: _('Spend unconfirmed') + ': ' + self.status
                    description: _("Use unconfirmed coins in transactions.")
                    message: _('Spend unconfirmed coins')
                    action: partial(root.boolean_dialog, 'use_unconfirmed', _('Use unconfirmed'), self.message)
                CardSeparator
                SettingsItem:
                    status: _('Yes') if app.use_change else _('No')
                    title: _('Use change addresses') + ': ' + self.status
                    description: _("Send your change to separate addresses.")
                    message: _('Send excess coins to change addresses')
                    action: partial(root.boolean_dialog, 'use_change', _('Use change addresses'), self.message)
                CardSeparator
                SettingsItem:
                    title: _('Password')
                    description: _('Change your password') if app._use_single_password else _("Change your password for this wallet.")
                    action: root.change_password
                CardSeparator
                SettingsItem:
                    disabled: not root.enable_toggle_use_recoverable_channels
                    status: _('Yes') if (app.use_recoverable_channels and not self.disabled) else _('No')
                    title: _('Create recoverable channels') + ': ' + self.status
                    description: _("Add channel recovery data to funding transaction.")
                    message: _(messages.MSG_RECOVERABLE_CHANNELS)
                    action: partial(root.boolean_dialog, 'use_recoverable_channels', _('Create recoverable channels'), self.message)
                CardSeparator
                SettingsItem:
                    status: _('Trampoline') if not app.use_gossip else _('Gossip')
                    title: _('Lightning Routing') + ': ' + self.status
                    description: _("Use trampoline routing or gossip.")
                    action: partial(root.routing_dialog, self)
                CardSeparator
                SettingsItem:
                    disabled: bool(app.electrum_config.get('verbosity')) and not app.enable_debug_logs
                    status: 'ON' if (bool(app.electrum_config.get('verbosity')) or app.enable_debug_logs) else 'OFF'
                    title: _('Enable debug logs') + ': ' + self.status
                    description: "(developer) Log to stderr, to inspect with logcat."
                    action: partial(root.boolean_dialog, 'enable_debug_logs', _('Debug Logs'), self.description)

                # disabled: there is currently only one coin selection policy
                #CardSeparator
                #SettingsItem:
                #    status: root.coinselect_status()
                #    title: _('Coin selection') + ': ' + self.status
                #    description: "Coin selection method"
                #    action: partial(root.coinselect_dialog, self)
''')



class SettingsDialog(Factory.Popup):

    def __init__(self, app: 'ElectrumWindow'):
        self.app = app
        self.plugins = self.app.plugins
        self.config = self.app.electrum_config
        Factory.Popup.__init__(self)
        layout = self.ids.scrollviewlayout
        layout.bind(minimum_height=layout.setter('height'))
        # cached dialogs
        self._fx_dialog = None
        self._proxy_dialog = None
        self._language_dialog = None
        self._unit_dialog = None
        self._coinselect_dialog = None

        self.update()

    def update(self):
        self.wallet = self.app.wallet
        self.use_encryption = self.wallet.has_password() if self.wallet else False
        self.has_pin_code = self.app.has_pin_code()
        self.enable_toggle_use_recoverable_channels = bool(self.wallet.lnworker and self.wallet.lnworker.can_have_recoverable_channels())

    def get_language_name(self) -> str:
        lang = self.config.get('language') or ''
        return languages.get(lang) or languages.get('') or ''

    def change_password(self, dt):
        self.app.change_password(self.update)

    def change_pin_code(self, label, dt):
        self.app.pin_code_dialog(self.update)

    def language_dialog(self, item, dt):
        if self._language_dialog is None:
            l = self.config.get('language') or ''
            def cb(key):
                self.config.set_key("language", key, True)
                item.lang = self.get_language_name()
                self.app.language = key
            self._language_dialog = ChoiceDialog(_('Language'), languages, l, cb)
        self._language_dialog.open()

    def unit_dialog(self, item, dt):
        if self._unit_dialog is None:
            def cb(text):
                self.app._set_bu(text)
                item.bu = self.app.base_unit
            self._unit_dialog = ChoiceDialog(_('Denomination'), base_units_list,
                                             self.app.base_unit, cb, keep_choice_order=True)
        self._unit_dialog.open()

    def routing_dialog(self, item, dt):
        description = _(messages.MSG_HELP_TRAMPOLINE)
        def cb(text):
            self.app.use_gossip = (text == 'Gossip')
        dialog = ChoiceDialog(
            _('Lightning Routing'),
            ['Trampoline', 'Gossip'],
            'Gossip' if self.app.use_gossip else 'Trampoline',
            cb, description=description,
            keep_choice_order=True)
        dialog.open()

    def coinselect_status(self):
        return coinchooser.get_name(self.app.electrum_config)

    def coinselect_dialog(self, item, dt):
        if self._coinselect_dialog is None:
            choosers = sorted(coinchooser.COIN_CHOOSERS.keys())
            chooser_name = coinchooser.get_name(self.config)
            def cb(text):
                self.config.set_key('coin_chooser', text)
                item.status = text
            self._coinselect_dialog = ChoiceDialog(_('Coin selection'), choosers, chooser_name, cb)
        self._coinselect_dialog.open()

    def proxy_status(self):
        net_params = self.app.network.get_parameters()
        proxy = net_params.proxy
        return proxy.get('host') +':' + proxy.get('port') if proxy else _('None')

    def proxy_dialog(self, item, dt):
        network = self.app.network
        if self._proxy_dialog is None:
            net_params = network.get_parameters()
            proxy = net_params.proxy
            def callback(popup):
                nonlocal net_params
                if popup.ids.mode.text != 'None':
                    proxy = {
                        'mode':popup.ids.mode.text,
                        'host':popup.ids.host.text,
                        'port':popup.ids.port.text,
                        'user':popup.ids.user.text,
                        'password':popup.ids.password.text
                    }
                else:
                    proxy = None
                net_params = net_params._replace(proxy=proxy)
                network.run_from_another_thread(network.set_parameters(net_params))
                item.status = self.proxy_status()
            popup = Builder.load_file(KIVY_GUI_PATH + '/uix/ui_screens/proxy.kv')
            popup.ids.mode.text = proxy.get('mode') if proxy else 'None'
            popup.ids.host.text = proxy.get('host') if proxy else ''
            popup.ids.port.text = proxy.get('port') if proxy else ''
            popup.ids.user.text = proxy.get('user') if proxy else ''
            popup.ids.password.text = proxy.get('password') if proxy else ''
            popup.on_dismiss = lambda: callback(popup)
            self._proxy_dialog = popup
        self._proxy_dialog.open()

    def plugin_dialog(self, name, label, dt):
        from .checkbox_dialog import CheckBoxDialog
        def callback(status):
            self.plugins.enable(name) if status else self.plugins.disable(name)
            label.status = 'ON' if status else 'OFF'
        status = bool(self.plugins.get(name))
        dd = self.plugins.descriptions.get(name)
        descr = dd.get('description')
        fullname = dd.get('fullname')
        d = CheckBoxDialog(fullname, descr, status, callback)
        d.open()

    def boolean_dialog(self, name, title, message, dt):
        from .checkbox_dialog import CheckBoxDialog
        CheckBoxDialog(title, message, getattr(self.app, name), lambda x: setattr(self.app, name, x)).open()

    def fx_status(self):
        fx = self.app.fx
        if fx.is_enabled():
            source = fx.exchange.name()
            ccy = fx.get_currency()
            return '%s [%s]' %(ccy, source)
        else:
            return _('None')

    def fx_dialog(self, label, dt):
        if self._fx_dialog is None:
            from .fx_dialog import FxDialog
            def cb():
                label.status = self.fx_status()
            self._fx_dialog = FxDialog(self.app, self.plugins, self.config, cb)
        self._fx_dialog.open()
