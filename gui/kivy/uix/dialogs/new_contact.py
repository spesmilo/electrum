from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty

Factory.register('QrScannerDialog', module='electrum_gui.kivy.uix.dialogs.qr_scanner')

class NewContactDialog(Factory.AnimatedPopup):

    def load_qr_scanner(self):
        self.dismiss()
        App.get_running_app().scan_qr(on_complete=self.on_complete)

    def on_complete(self, instance, uri):
        self.new_contact(uri=uri)

    def new_contact(self, uri={}):
        # load NewContactScreen
        app = App.get_running_app()
        #app.root.
        # set contents of uri in the new contact screen
