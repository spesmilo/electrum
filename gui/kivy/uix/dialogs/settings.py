from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_ltc.i18n import _
from electrum_ltc.util import base_units
from electrum_ltc.i18n import languages, set_language
from electrum_ltc.plugins import run_hook

Builder.load_string('''
<SettingsItem@ButtonBehavior+BoxLayout>
    orientation: 'vertical'
    title: ''
    description: ''
    size_hint: 1, None
    Label:
        id: title
        text: self.parent.title
        bold: True
        halign: 'left'
        size_hint: 1, 1
        text_size: self.width, None
    Label:
        text: self.parent.description
        color: 0.8, 0.8, 0.8, 1
        size_hint: 1, 1
        halign: 'left'
        text_size: self.width, None
    CardSeparator


<SettingsDialog@Popup>
    id: settings
    title: _('Electrum Settings')
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            size_hint: 1, 0.8
            GridLayout:
                row_default_height: '68dp'
                cols:1
                id: scrollviewlayout
                size_hint: 1, None
                SettingsItem:
                    lang: settings.get_language_name()
                    title: _('Language') + ': %s'%self.lang
                    description: _("Language")
                    on_release:
                        settings.language_dialog(self)
                    height: '48dp'
                SettingsItem:
                    status: 'ON' if app.wallet.use_encryption else 'OFF'
                    title: _('PIN code') + ': ' + self.status
                    description: _("Change your PIN code.")
                    on_release:
                        app.change_password()
                        self.status = 'ON' if app.wallet.use_encryption else 'OFF'
                SettingsItem:
                    bu: app.base_unit
                    title: _('Denomination') + ': ' + self.bu
                    description: _("Base unit for Litecoin amounts.")
                    on_release:
                        settings.unit_dialog(self)
                SettingsItem:
                    status: 'ON' if bool(app.plugins.get('exchange_rate')) else 'OFF'
                    title: _('Fiat Exchange rates') + ': ' + self.status
                    description: _("Display amounts in fiat currency.")
                    on_release:
                        settings.plugin_dialog('exchange_rate', self)
                SettingsItem:
                    status: app.fiat_unit
                    title: _('Fiat Currency') + ': ' + self.status
                    description: _("Select the local fiat currency.")
                    on_release:
                        settings.fiat_currency_dialog(self)
                SettingsItem:
                    status: root.fiat_source()
                    title: _('Fiat source') + ': ' + self.status
                    description: _("Source for fiat currency exchange rate.")
                    on_release:
                        settings.fiat_source_dialog(self)
                SettingsItem:
                    status: 'ON' if bool(app.plugins.get('labels')) else 'OFF'
                    title: _('Labels Sync') + ': ' + self.status
                    description: "Synchronize labels."
                    on_release:
                        settings.plugin_dialog('labels', self)
                SettingsItem:
                    title: _('OpenAlias')
                    description: "DNS record that stores one of your Litecoin addresses."
                    on_release:
                        settings.openalias_dialog()
        BoxLayout:
            size_hint: 1, 0.1
            Widget:
                size_hint: 0.5, None
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('OK')
                on_release:
                    settings.dismiss()
''')

class SettingsDialog(Factory.Popup):

    def __init__(self, app):
        self.app = app
        self.plugins = self.app.plugins
        self.config = self.app.electrum_config
        Factory.Popup.__init__(self)
        layout = self.ids.scrollviewlayout
        layout.bind(minimum_height=layout.setter('height'))

    def get_language_name(self):
        return languages.get(self.config.get('language', 'en_UK'), '')

    def language_dialog(self, item):
        from choice_dialog import ChoiceDialog
        l = self.config.get('language', 'en_UK')
        def cb(key):
            self.config.set_key("language", key, True)
            item.lang = self.get_language_name()
            set_language(key)
        d = ChoiceDialog(_('Language'), languages, l, cb)
        d.open()

    def unit_dialog(self, item):
        from choice_dialog import ChoiceDialog
        def cb(text):
            self.app._set_bu(text)
            item.bu = self.app.base_unit
        d = ChoiceDialog(_('Denomination'), base_units.keys(), self.app.base_unit, cb)
        d.open()

    def fiat_currency_dialog(self, item):
        from choice_dialog import ChoiceDialog
        p = self.app.plugins.get('exchange_rate')
        if not p:
            return
        def cb(text):
            p.set_currency(text)
            item.status = text
            self.app.fiat_unit = text
        l = sorted(p.exchange.quotes.keys()) if p else []
        d = ChoiceDialog(_('Fiat Currency'), l, p.get_currency(), cb)
        d.open()

    def fiat_source(self):
        p = self.app.plugins.get('exchange_rate')
        return p.exchange.name() if p else 'None'

    def fiat_source_dialog(self, item):
        from choice_dialog import ChoiceDialog
        p = self.plugins.get('exchange_rate')
        if not p:
            return
        def cb(text):
            p.set_exchange(text)
            item.status = text
        l = sorted(p.exchanges.keys())
        d = ChoiceDialog(_('Exchange rate source'), l, self.fiat_source(), cb)
        d.open()

    def openalias_dialog(self):
        from label_dialog import LabelDialog
        def callback(text):
            pass
        d = LabelDialog(_('OpenAlias'), '', callback)
        d.open()

    def plugin_dialog(self, name, label):
        from checkbox_dialog import CheckBoxDialog
        def callback(status):
            self.plugins.enable(name) if status else self.plugins.disable(name)
            label.status = 'ON' if status else 'OFF'
        status = bool(self.plugins.get(name))
        dd = self.plugins.descriptions.get(name)
        descr = dd.get('description')
        fullname = dd.get('fullname')
        d = CheckBoxDialog(fullname, descr, status, callback)
        d.open()
