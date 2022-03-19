from typing import TYPE_CHECKING

from kivy.factory import Factory
from kivy.lang import Builder
from kivy.core.clipboard import Clipboard
from kivy.app import App
from kivy.clock import Clock
from kivy.properties import NumericProperty, StringProperty

from electrum.gui.kivy.i18n import _
from electrum.invoices import pr_tooltips, pr_color
from electrum.invoices import PR_UNKNOWN, PR_UNPAID, PR_FAILED

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow



MODE_ADDRESS = 0
MODE_URI = 1
MODE_LIGHTNING = 2


Builder.load_string('''
#:import KIVY_GUI_PATH electrum.gui.kivy.KIVY_GUI_PATH

<RequestDialog@Popup>
    id: popup
    amount_str: ''
    title: ''
    description:''
    mode:0
    key:''
    data:''
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
                text: root.data[0:70] + ('...' if len(root.data)>70 else '')
            BoxLayout:
                size_hint: 1, None
                height: '48dp'
                ToggleButton:
                    id: b0
                    group:'g'
                    size_hint: 1, None
                    height: '48dp'
                    text: _('Address')
                    on_release: root.mode = 0
                ToggleButton:
                    id: b1
                    group:'g'
                    size_hint: 1, None
                    height: '48dp'
                    text: _('URI')
                    on_release: root.mode = 1
                    state: 'down'
                ToggleButton:
                    id: b2
                    group:'g'
                    size_hint: 1, None
                    height: '48dp'
                    text: _('Lightning')
                    on_release: root.mode = 2
            TopLabel:
                text: _('Description') + ': ' + root.description or _('None')
            TopLabel:
                text: _('Amount') + ': ' + root.amount_str
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
                    icon: f'atlas://{KIVY_GUI_PATH}/theming/atlas/light/copy'
                    size_hint: 0.5, None
                    height: '48dp'
                    on_release: root.copy_to_clipboard()
                IconButton:
                    icon: f'atlas://{KIVY_GUI_PATH}/theming/atlas/light/share'
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

    mode = NumericProperty(0)
    data = StringProperty('')

    def __init__(self, title, key):
        self.status = PR_UNKNOWN
        Factory.Popup.__init__(self)
        self.app = App.get_running_app()  # type: ElectrumWindow
        self.title = title
        self.key = key
        r = self.app.wallet.get_request(key)
        self.amount_sat = r.get_amount_sat()
        self.amount_str = self.app.format_amount_and_units(self.amount_sat)
        self.description = r.message
        self.mode = 1
        self.on_mode(0, 0)
        self.ids.b0.pressed = True
        self.update_status()

    def on_mode(self, instance, x):
        r = self.app.wallet.get_request(self.key)
        if self.mode == MODE_ADDRESS:
            self.data = r.get_address() or ''
        elif self.mode == MODE_URI:
            self.data = self.app.wallet.get_request_URI(r) or ''
        else:
            self.data = r.lightning_invoice or ''
        qr_data = self.data
        if self.mode == MODE_LIGHTNING:
            # encode lightning invoices as uppercase so QR encoding can use
            # alphanumeric mode; resulting in smaller QR codes
            qr_data = qr_data.upper()
        if qr_data:
            self.ids.qr.set_data(qr_data)
            self.ids.qr.opacity = 1
        else:
            self.ids.qr.opacity = 0
        self.update_status()

    def update_status(self):
        req = self.app.wallet.get_request(self.key)
        self.status = self.app.wallet.get_request_status(self.key)
        self.status_str = req.get_status_str(self.status)
        self.status_color = pr_color[self.status]
        warning = ''
        if self.status == PR_UNPAID and self.mode == MODE_LIGHTNING and self.app.wallet.lnworker:
            if self.amount_sat and self.amount_sat > self.app.wallet.lnworker.num_sats_can_receive():
                warning = _('Warning') + ': ' + _('This amount exceeds the maximum you can currently receive with your channels')
        if not self.mode == MODE_LIGHTNING:
            address = req.get_address()
            if not address:
                warning = _('Warning') + ': ' + _('This request cannot be paid on-chain')
            elif self.app.wallet.is_used(address):
                warning = _('Warning') + ': ' + _('This address is being reused')
        self.warning = warning

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
