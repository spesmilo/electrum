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
<WalletDialog@Popup>:
    title: _('Wallets')
    id: popup
    path: ''
    disable_new: True
    BoxLayout:
        orientation: 'vertical'
        padding: '10dp'
        FileChooserIconView:
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
                id: new_button
                disabled: root.disable_new
                size_hint: 0.1, None
                height: '48dp'
                text: _('New')
                on_release:
                    popup.dismiss()
                    root.new_wallet(wallet_selector.path)
            Button:
                id: open_button
                size_hint: 0.1, None
                height: '48dp'
                text: _('Open')
                disabled: not wallet_selector.selection
                on_release:
                    popup.dismiss()
                    root.callback(wallet_selector.selection[0])
''')

class WalletDialog(Factory.Popup):

    def __init__(self, path, callback, disable_new):
        Factory.Popup.__init__(self)
        self.path = path
        self.callback = callback
        self.disable_new = disable_new

    def new_wallet(self, dirname):
        assert self.disable_new is False
        def cb(filename):
            if not filename:
                return
            # FIXME? "filename" might contain ".." (etc) and hence sketchy path traversals are possible
            self.callback(os.path.join(dirname, filename))
        d = LabelDialog(_('Enter wallet name'), '', cb)
        d.open()
