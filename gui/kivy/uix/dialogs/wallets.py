from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_gui.kivy.i18n import _
from electrum.util import base_units

import os
from label_dialog import LabelDialog

Builder.load_string('''
#:import os os
<WalletDialog@Popup>:
    title: _('Wallets')
    id: popup
    path: ''
    BoxLayout:
        orientation: 'vertical'
        padding: '10dp'
        FileChooserListView:
            id: wallet_selector
            dirselect: False
            filter_dirs: True
            filter: '*.*'
            path: os.path.dirname(app.get_wallet_path())
            size_hint_y: 0.6
        Widget
            size_hint_y: 0.1
        GridLayout:
            cols: 2
            size_hint_y: 0.1
            Button:
                size_hint: 0.1, None
                height: '48dp'
                text: _('Cancel')
                on_release:
                    popup.dismiss()
            Button:
                id: open_button
                size_hint: 0.1, None
                height: '48dp'
                text: _('Open') if wallet_selector.selection else _('New Wallet')
                on_release:
                    popup.dismiss()
                    root.new_wallet(app, wallet_selector.path)
''')

class WalletDialog(Factory.Popup):
    def new_wallet(self, app, dirname):
        def cb(text):
            if text:
                app.load_wallet_by_name(os.path.join(dirname, text))
        if self.ids.wallet_selector.selection:
            app.load_wallet_by_name(self.ids.wallet_selector.selection[0])
        else:
            d = LabelDialog(_('Enter wallet name'), '', cb)
            d.open()
