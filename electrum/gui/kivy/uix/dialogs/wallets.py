import os

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum.util import base_units
from electrum.storage import StorageReadWriteError

from ...i18n import _
from .label_dialog import LabelDialog

Builder.load_string('''
#:import os os
<WalletDialog@Popup>:
    title: _('Wallets')
    id: popup
    path: os.path.dirname(app.get_wallet_path())
    BoxLayout:
        orientation: 'vertical'
        padding: '10dp'
        FileChooserListView:
            id: wallet_selector
            dirselect: False
            filter_dirs: True
            filter: '*.*'
            path: root.path
            rootpath: root.path
            size_hint_y: 0.6
        Widget
            size_hint_y: 0.1
        GridLayout:
            cols: 3
            size_hint_y: 0.1
            Button:
                id: open_button
                size_hint: 0.1, None
                height: '48dp'
                text: _('New')
                on_release:
                    popup.dismiss()
                    root.new_wallet(app, wallet_selector.path)
            Button:
                id: open_button
                size_hint: 0.1, None
                height: '48dp'
                text: _('Open')
                disabled: not wallet_selector.selection
                on_release:
                    popup.dismiss()
                    root.open_wallet(app)
''')

class WalletDialog(Factory.Popup):

    def new_wallet(self, app, dirname):
        def cb(filename):
            if not filename:
                return
            # FIXME? "filename" might contain ".." (etc) and hence sketchy path traversals are possible
            try:
                app.load_wallet_by_name(os.path.join(dirname, filename))
            except StorageReadWriteError:
                app.show_error(_("R/W error accessing path"))
        d = LabelDialog(_('Enter wallet name'), '', cb)
        d.open()

    def open_wallet(self, app):
        try:
            app.load_wallet_by_name(self.ids.wallet_selector.selection[0])
        except StorageReadWriteError:
            app.show_error(_("R/W error accessing path"))

