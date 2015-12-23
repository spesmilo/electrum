from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.i18n import _
from electrum.util import base_units
from electrum.i18n import languages, set_language

Builder.load_string('''
<SettingsItem@ButtonBehavior+BoxLayout>
    orientation: 'vertical'
    title: ''
    description: ''
    size_hint: 1, 1
    Label:
        id: title
        text: self.parent.title
        size_hint: 1, 1
        bold: True
        text_size: self.size
        halign: 'left'
    Label:
        text: self.parent.description
        size_hint: 1, 1
        text_size: self.width, None
        color: 0.8, 0.8, 0.8, 1
        halign: 'left'

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
    title: _('Settings')
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
            title: _('PIN Code') + ': %s'%('ON' if app.wallet.use_encryption else 'OFF')
            description: _("Your PIN code will be required in order to spend bitcoins.")
            on_release:
                app.change_password()
                self.title = _('PIN Code') + ' (%s)'%('ON' if app.wallet.use_encryption else 'OFF')
        CardSeparator
        SettingsItem:
            bu: app.base_unit
            title: _('Denomination') + ': ' + self.bu
            description: _("Base unit for Bitcoin amounts.")
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
            self.app.electrum_config.set_key("language", key, True)
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
            pass
        d = ChoiceDialog(_('Fiat Currency'), {}, '', cb)
        d.open()

    def openalias_dialog(self):
        from label_dialog import LabelDialog
        def callback(text):
            pass
        d = LabelDialog(_('OpenAlias'), '', callback)
        d.open()


    def show_plugins(self, plugins_list):

        def on_active(sw, value):
            self.plugins.toggle_enabled(self.electrum_config, sw.name)
            run_hook('init_kivy', self)

        for item in self.plugins.descriptions:
            if 'kivy' not in item.get('available_for', []):
                continue
            name = item.get('__name__')
            label = Label(text=item.get('fullname'), height='48db', size_hint=(1, None))
            plugins_list.add_widget(label)
            sw = Switch()
            sw.name = name
            p = self.plugins.get(name)
            sw.active = (p is not None) and p.is_enabled()
            sw.bind(active=on_active)
            plugins_list.add_widget(sw)

class PluginItem():
    def __init__(self, name):
        p = self.plugins.get(name)
        sw.active = (p is not None) and p.is_enabled()
        sw.bind(active=on_active)
        plugins_list.add_widget(sw)
        
