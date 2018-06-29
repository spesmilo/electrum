import binascii
from kivy.lang import Builder
from kivy.factory import Factory
from electrum_gui.kivy.i18n import _
from kivy.clock import mainthread
from electrum.lnaddr import lndecode

Builder.load_string('''
<LightningPayerDialog@Popup>
    id: s
    name: 'lightning_payer'
    invoice_data: ''
    BoxLayout:
        orientation: "vertical"
        BlueButton:
            text: s.invoice_data if s.invoice_data else _('Lightning invoice')
            shorten: True
            on_release: Clock.schedule_once(lambda dt: app.show_info(_('Copy and paste the lightning invoice using the Paste button, or use the camera to scan a QR code.')))
        GridLayout:
            cols: 4
            size_hint: 1, None
            height: '48dp'
            IconButton:
                id: qr
                on_release: Clock.schedule_once(lambda dt: app.scan_qr(on_complete=s.on_lightning_qr))
                icon: 'atlas://gui/kivy/theming/light/camera'
            Button:
                text: _('Paste')
                on_release: s.do_paste()
            Button:
                text: _('Paste using xclip')
                on_release: s.do_paste_xclip()
            Button:
                text: _('Clear')
                on_release: s.do_clear()
        Button:
            size_hint: 1, None
            height: '48dp'
            text: _('Open channel to pubkey in invoice')
            on_release: s.do_open_channel()
        Button:
            size_hint: 1, None
            height: '48dp'
            text: _('Pay pasted/scanned invoice')
            on_release: s.do_pay()
''')

class LightningPayerDialog(Factory.Popup):
    def __init__(self, app):
        super(LightningPayerDialog, self).__init__()
        self.app = app

    #def open(self, *args, **kwargs):
    #    super(LightningPayerDialog, self).open(*args, **kwargs)
    #def dismiss(self, *args, **kwargs):
    #    super(LightningPayerDialog, self).dismiss(*args, **kwargs)

    def do_paste_xclip(self):
        import subprocess
        proc = subprocess.run(["xclip","-sel","clipboard","-o"], stdout=subprocess.PIPE)
        self.invoice_data = proc.stdout.decode("ascii")

    def do_paste(self):
        contents = self.app._clipboard.paste()
        if not contents:
            self.app.show_info(_("Clipboard is empty"))
            return
        self.invoice_data = contents

    def do_clear(self):
        self.invoice_data = ""

    def do_open_channel(self):
        compressed_pubkey_bytes = lndecode(self.invoice_data).pubkey.serialize()
        hexpubkey = binascii.hexlify(compressed_pubkey_bytes).decode("ascii")
        local_amt = 200000
        push_amt = 100000

        def on_success(pw):
            # node_id, local_amt, push_amt, emit_function, get_password
            self.app.wallet.lnworker.open_channel_from_other_thread(hexpubkey, local_amt, push_amt, mainthread(lambda parent: self.app.show_info(_("Channel open, waiting for locking..."))), lambda: pw)

        if self.app.wallet.has_keystore_encryption():
            # wallet, msg, on_success (Tuple[str, str] -> ()), on_failure (() -> ())
            self.app.password_dialog(self.app.wallet, _("Password needed for opening channel"), on_success, lambda: self.app.show_error(_("Failed getting password from you")))
        else:
            on_success("")

    def do_pay(self):
        self.app.wallet.lnworker.pay_invoice_from_other_thread(self.invoice_data)

    def on_lightning_qr(self, data):
        self.invoice_data = str(data)
