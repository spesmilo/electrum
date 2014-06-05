from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.cache import Cache

Factory.register('QrScannerDialog', module='electrum_gui.kivy.uix.dialogs.qr_scanner')

class NewContactDialog(Factory.AnimatedPopup):

    def load_qr_scanner(self):
        self.dismiss()
        dlg = Cache.get('electrum_widgets', 'QrScannerDialog')
        if not dlg:
            dlg = Factory.QrScannerDialog()
            Cache.append('electrum_widgets', 'QrScannerDialog', dlg)
            dlg.bind(on_release=self.on_release)
        dlg.open()

    def on_release(self, instance, uri):
        self.new_contact(uri=uri)

    def new_contact(self, uri={}):
        # load NewContactScreen
        app = App.get_running_app()
        #app.root.
        # set contents of uri in the new contact screen
