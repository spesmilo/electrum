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
    size_hint: 1, 1
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

<PluginItem@ButtonBehavior+BoxLayout>
    orientation: 'vertical'
    title: ''
    description: ''
    size_hint: 1, 1
    BoxLayout:
        orientation: 'horizontal'
        Label:
            id: title
            text: self.parent.title
            size_hint: 1, 1
            bold: True
            text_size: self.size
            halign: 'left'
        Switch:
            id: sw
            name: ''
    Label:
        text: self.parent.description
        size_hint: 1, 1
        text_size: self.width, None
        color: 0.8, 0.8, 0.8, 1
        halign: 'left'

<SettingsDialog@Popup>
    id: settings
    title: _('Electrum Settings')
    BoxLayout:
        orientation: 'vertical'
        SettingsItem:
            lang: settings.get_language_name()
            title: _('Language') + ': %s'%self.lang
            description: _("Language")
            on_release:
                settings.language_dialog(self)
        CardSeparator
        SettingsItem:
            status: 'ON' if app.wallet.use_encryption else 'OFF'
            title: _('PIN code') + ': ' + self.status
            description: _("Change your PIN code.")
            on_release:
                app.change_password()
                self.status = 'ON' if app.wallet.use_encryption else 'OFF'
        CardSeparator
        SettingsItem:
            bu: app.base_unit
            title: _('Denomination') + ': ' + self.bu
            description: _("Base unit for Litecoin amounts.")
            on_release:
                settings.unit_dialog(self)
        CardSeparator
        SettingsItem:
            title: _('Fiat Currency') + ': ' + app.fiat_unit
            description: "Select the local fiat currency."
            on_release:
                settings.fiat_dialog(self)
        CardSeparator
        SettingsItem:
            status: 'ON' if bool(app.plugins.get('labels')) else 'OFF'
            title: _('Labels Sync') + ': ' + self.status
            description: "Synchronize labels."
            on_release:
                settings.labelsync_dialog(self)
        CardSeparator
        SettingsItem:
            title: _('OpenAlias')
            description: "DNS record that stores one of your Litecoin addresses."
            on_release:
                settings.openalias_dialog()
        Widget:
            size_hint: 1, 1
        BoxLayout:
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
        d = ChoiceDialog(_('Denomination'), dict(map(lambda x: (x,x), base_units)), self.app.base_unit, cb)
        d.open()

    def fiat_dialog(self, item):
        from choice_dialog import ChoiceDialog
        def cb(text):
            if text == 'None':
                self.plugins.disable('exchange_rate')
            else:
                self.config.set_key('currency', text, True)
                p = self.app.plugins.enable('exchange_rate')
                p.init_kivy(self.app)

        d = ChoiceDialog(_('Fiat Currency'), { 'None': 'None', 'USD':'USD', 'EUR':'EUR'}, '', cb)
        d.open()

    def openalias_dialog(self):
        from label_dialog import LabelDialog
        def callback(text):
            pass
        d = LabelDialog(_('OpenAlias'), '', callback)
        d.open()

    def labelsync_dialog(self, label):
        from checkbox_dialog import CheckBoxDialog
        def callback(status):
            self.plugins.enable('labels') if status else self.plugins.disable('labels')
            status = bool(self.plugins.get('labels'))
            label.status = 'ON' if status else 'OFF'
        status = bool(self.plugins.get('labels'))
        descr = _('Save your labels on a remote server, and synchronizes them between various instances of your wallet.')
        d = CheckBoxDialog(_('Labels Sync'), descr, status, callback)
        d.open()


class PluginItem():
    def __init__(self, name):
        p = self.plugins.get(name)
        sw.active = (p is not None) and p.is_enabled()
        sw.bind(active=on_active)
        plugins_list.add_widget(sw)
        
