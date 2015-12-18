from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.i18n import _
from electrum.util import base_units

import os
from label_dialog import LabelDialog

Builder.load_string('''
#:import os os
<WalletDialog@Popup>:
    title: _('Wallets')
    id: popup
    path: app.wallet.storage.path
    on_path:
        button.text = _('Open') if os.path.exists(popup.path) else _('Create')
    BoxLayout:
        orientation: 'vertical'
        BoxLayout:
            height: '48dp'
            size_hint_y: None
            orientation: 'horizontal'
            Label:
                text: _('Wallet') + ': '
                height: '48dp'
                size_hint_y: None
            Button:
                id: wallet_name
                height: '48dp'
                size_hint_y: None
                text: os.path.basename(app.wallet.storage.path)
                on_release:
                    root.name_dialog()
                on_text:
                    popup.path = os.path.join(wallet_selector.path, self.text)
        Widget
            size_hint_y: None
        FileChooserListView:
            id: wallet_selector
            path: os.path.dirname(app.wallet.storage.path)
            on_selection:
                wallet_name.text = os.path.basename(self.selection[0]) if self.selection else ''
            size_hint_y: 0.5
        Widget
            size_hint_y: 0.1

        GridLayout:
            cols: 2
            size_hint_y: None
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Cancel')
                on_release:
                    popup.dismiss()
            Button:
                id: button
                size_hint: 0.5, None
                height: '48dp'
                text: _('Open') if os.path.exists(popup.path) else _('Create')
                on_release:
                    popup.dismiss()
                    app.load_wallet_by_name(popup.path)
''')

class WalletDialog(Factory.Popup):
    def name_dialog(self):
        def cb(text):
            if text:
                self.ids.wallet_name.text = text
        d = LabelDialog(_('Enter wallet name'), '', cb)
        d.open()

