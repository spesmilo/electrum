from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_ltc.i18n import _
from electrum_ltc.util import base_units
from electrum_ltc.i18n import languages, set_language

Builder.load_string('''
<SettingsDialog@Popup>
    id: settings
    title: _('Settings')
    BoxLayout:
        orientation: 'vertical'
        SettingsItem:
            lang: settings.get_language_name()
            title: _('Language') + ' (%s)'%self.lang
            description: _("Language")
            on_release:
                settings.language_dialog(self)
        CardSeparator
        SettingsItem:
            title: _('PIN Code') + ' (%s)'%('ON' if app.wallet.use_encryption else 'OFF')
            description: _("Your PIN code will be required in order to spend litecoins.")
            on_release:
                app.change_password()
                self.title = _('PIN Code') + ' (%s)'%('ON' if app.wallet.use_encryption else 'OFF')
        CardSeparator
        SettingsItem:
            bu: app.base_unit
            title: _('Denomination') + ' (' + self.bu + ')'
            description: _("Base unit for Litecoin amounts.")
            on_release:
                settings.unit_dialog(self)
        CardSeparator
        SettingsItem:
            title: _('Fiat Currency')
            description: "Select the local fiat currency."
            on_release:
                settings.fiat_dialog(self)
        CardSeparator
        SettingsItem:
            title: _('OpenAlias')
            description: "Email-like address."
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
        Factory.Popup.__init__(self)

    def get_language_name(self):
        return languages.get(self.app.electrum_config.get('language', 'en_UK'), '')

    def language_dialog(self, item):
        from choice_dialog import ChoiceDialog
        l = self.app.electrum_config.get('language', 'en_UK')
        def cb(key):
            set_language(key)
            self.app.electrum_config.set_key("language", key, True)
            item.lang = self.get_language_name()
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
            pass
        d = ChoiceDialog(_('Fiat Currency'), {}, '', cb)
        d.open()

    def openalias_dialog(self):
        from label_dialog import LabelDialog
        def callback(text):
            pass
        d = LabelDialog(_('OpenAlias'), '', callback)
        d.open()
