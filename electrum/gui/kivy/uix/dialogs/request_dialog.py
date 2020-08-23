from typing import TYPE_CHECKING

from kivy.factory import Factory
from kivy.lang import Builder
from kivy.core.clipboard import Clipboard
from kivy.app import App
from kivy.clock import Clock

from electrum.gui.kivy.i18n import _
from electrum.invoices import pr_tooltips, pr_color
from electrum.invoices import PR_UNKNOWN, PR_UNPAID, PR_FAILED, PR_TYPE_LN

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string('''
<RequestDialog@Popup>
    id: popup
    amount_str: ''
    title: ''
    description:''
    is_lightning: False
    key:''
    warning: ''
    status_str: ''
    status_color: 1,1,1,1
    shaded: False
    show_text: False
    AnchorLayout:
        anchor_x: 'center'
        BoxLayout:
            orientation: 'vertical'
            size_hint: 1, 1
            padding: '10dp'
            spacing: '10dp'
            QRCodeWidget:
                id: qr
                shaded: False
                foreground_color: (0, 0, 0, 0.5) if self.shaded else (0, 0, 0, 0)
                on_touch_down:
                    touch = args[1]
                    if self.collide_point(*touch.pos): self.shaded = not self.shaded
            TopLabel:
                text: _('Description') + ': ' + root.description or _('None')
            TopLabel:
                text: _('Amount') + ': ' + root.amount_str
            TopLabel:
                text: (_('Address') if not root.is_lightning else _('Payment hash')) + ': '
            RefLabel:
                text: root.key
            TopLabel:
                text: _('Status') + ': ' + root.status_str
                color: root.status_color
            TopLabel:
                text: root.warning
                color: (0.9, 0.6, 0.3, 1)
            Widget:
                size_hint: 1, 0.2
            BoxLayout:
                size_hint: 1, None
                height: '48dp'
                Button:
                    size_hint: 1, None
                    height: '48dp'
                    text: _('Delete')
                    on_release: root.delete_dialog()
                IconButton:
                    icon: 'atlas://electrum/gui/kivy/theming/light/copy'
                    size_hint: 0.5, None
                    height: '48dp'
                    on_release: root.copy_to_clipboard()
                IconButton:
                    icon: 'atlas://electrum/gui/kivy/theming/light/share'
                    size_hint: 0.5, None
                    height: '48dp'
                    on_release: root.do_share()
                Button:
                    size_hint: 1, None
                    height: '48dp'
                    text: _('Close')
                    on_release: popup.dismiss()
''')

class RequestDialog(Factory.Popup):

    def __init__(self, title, key):
        self.status = PR_UNKNOWN
        Factory.Popup.__init__(self)
        self.app = App.get_running_app()  # type: ElectrumWindow
        self.title = title
        self.key = key
        r = self.app.wallet.get_request(key)
        self.is_lightning = r.is_lightning()
        self.data = r.invoice if self.is_lightning else self.app.wallet.get_request_URI(r)
        self.amount_sat = r.get_amount_sat()
        self.amount_str = self.app.format_amount_and_units(self.amount_sat)
        self.description = r.message
        self.update_status()

    def on_open(self):
        data = self.data
        if self.is_lightning:
            # encode lightning invoices as uppercase so QR encoding can use
            # alphanumeric mode; resulting in smaller QR codes
            data = data.upper()
        self.ids.qr.set_data(data)

    def update_status(self):
        req = self.app.wallet.get_request(self.key)
        self.status = self.app.wallet.get_request_status(self.key)
        self.status_str = req.get_status_str(self.status)
        self.status_color = pr_color[self.status]
        if self.status == PR_UNPAID and self.is_lightning and self.app.wallet.lnworker:
            if self.amount_sat and self.amount_sat > self.app.wallet.lnworker.num_sats_can_receive():
                self.warning = _('Warning') + ': ' + _('This amount exceeds the maximum you can currently receive with your channels')

    def on_dismiss(self):
        self.app.request_popup = None

    def copy_to_clipboard(self):
        Clipboard.copy(self.data)
        msg = _('Text copied to clipboard.')
        Clock.schedule_once(lambda dt: self.app.show_info(msg))

    def do_share(self):
        self.app.do_share(self.data, _("Share Bitcoin Request"))
        self.dismiss()

    def delete_dialog(self):
        from .question import Question
        def cb(result):
            if result:
                self.app.wallet.delete_request(self.key)
                self.dismiss()
                self.app.receive_screen.update()
        d = Question(_('Delete request?'), cb)
        d.open()
