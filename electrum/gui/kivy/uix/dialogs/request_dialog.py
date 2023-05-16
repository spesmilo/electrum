from typing import TYPE_CHECKING

from kivy.factory import Factory
from kivy.lang import Builder
from kivy.core.clipboard import Clipboard
from kivy.app import App
from kivy.clock import Clock
from kivy.properties import NumericProperty, StringProperty, BooleanProperty
from kivy.uix.tabbedpanel import TabbedPanel

from electrum.gui.kivy.i18n import _
from electrum.invoices import pr_tooltips, pr_color
from electrum.invoices import PR_UNKNOWN, PR_UNPAID, PR_FAILED

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string('''
#:import KIVY_GUI_PATH electrum.gui.kivy.KIVY_GUI_PATH

<TabbedPanelWithHiddenHeader@TabbedPanel>:
    tab_height: "0dp"
    tab_width: "1dp"

<RequestDialog@Popup>
    id: popup
    amount_str: ''
    title: ''
    description:''
    mode:0
    key:''
    data:''
    warning: ''
    error_text: ''
    status_str: ''
    status_color: 1,1,1,1
    shaded: False
    show_text: False
    has_lightning: False
    AnchorLayout:
        anchor_x: 'center'
        BoxLayout:
            orientation: 'vertical'
            size_hint: 1, 1
            padding: '10dp'
            spacing: '10dp'
            TabbedPanelWithHiddenHeader:
                id: qrdata_tabs
                do_default_tab: False
                on_touch_down:
                    root.show_text = True if root.error_text else not root.show_text
                TabbedPanelItem:
                    id: qrdata_tab_qr
                    border: 0,0,0,0  # to hide visual artifact around hidden tab header
                    QRCodeWidget:
                        id: qr
                TabbedPanelItem:
                    id: qrdata_tab_text
                    border: 0,0,0,0  # to hide visual artifact around hidden tab header
                    BoxLayout:
                        padding: '20dp'
                        TopLabel:
                            text: root.error_text if root.error_text else root.data
                            pos_hint: {'center_x': .5, 'center_y': .5}
                            halign: "center"
            BoxLayout:
                size_hint: 1, None
                height: '48dp'
                ToggleButton:
                    id: b0
                    group:'g'
                    size_hint: 1, None
                    height: '48dp'
                    text: _('Address')
                    on_release: self.state = 'down'; root.mode = root.MODE_ADDRESS
                ToggleButton:
                    id: b1
                    group:'g'
                    size_hint: 1, None
                    height: '48dp'
                    text: _('URI')
                    on_release: self.state = 'down'; root.mode = root.MODE_URI
                ToggleButton:
                    id: b2
                    group:'g'
                    size_hint: 1, None
                    height: '48dp'
                    text: _('Lightning')
                    on_release: self.state = 'down'; root.mode = root.MODE_LIGHTNING
                    disabled: not root.has_lightning
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


class TabbedPanelWithHiddenHeader(TabbedPanel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._tab_strip.opacity = 0


class RequestDialog(Factory.Popup):

    MODE_ADDRESS = 0
    MODE_URI = 1
    MODE_LIGHTNING = 2

    mode = NumericProperty(0)
    data = StringProperty('')
    show_text = BooleanProperty(False)

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
        if not self.app.wallet.get_request_URI(r) and r.is_lightning():
            self.mode = self.MODE_LIGHTNING
            self.ids.b2.state = 'down'  # FIXME magic number b2
        else:
            self.mode = self.MODE_URI
            self.ids.b1.state = 'down'  # FIXME magic number b1
        self.on_mode(0, 0)
        self.ids.b0.pressed = True
        self.update_status()

    def on_mode(self, instance, x):
        self.update_status()
        qr_data = self.data
        if self.mode == self.MODE_LIGHTNING:
            # encode lightning invoices as uppercase so QR encoding can use
            # alphanumeric mode; resulting in smaller QR codes
            qr_data = qr_data.upper()
        if qr_data:
            self.ids.qr.set_data(qr_data)
        if not qr_data and self.error_text:
            self.show_text = True
        else:
            self.show_text = False

    def on_show_text(self, instance, b):
        tab = self.ids.qrdata_tab_text if self.show_text else self.ids.qrdata_tab_qr
        Clock.schedule_once(lambda dt: self.ids.qrdata_tabs.switch_to(tab))

    def update_status(self):
        req = self.app.wallet.get_request(self.key)
        help_texts = self.app.wallet.get_help_texts_for_receive_request(req)
        address = req.get_address() or ''
        URI = self.app.wallet.get_request_URI(req) or ''
        lnaddr = ""
        if req.is_lightning():
            lnaddr = self.app.wallet.get_bolt11_invoice(req)
        self.status = self.app.wallet.get_invoice_status(req)
        self.status_str = req.get_status_str(self.status)
        self.status_color = pr_color[self.status]
        self.has_lightning = req.is_lightning()

        warning = ''
        error_text = ''
        self.data = ''
        if self.mode == self.MODE_ADDRESS:
            if help_texts.address_is_error:
                error_text = help_texts.address_help
            else:
                self.data = address
                warning = help_texts.address_help
        elif self.mode == self.MODE_URI:
            if help_texts.URI_is_error:
                error_text = help_texts.URI_help
            else:
                self.data = URI
                warning = help_texts.URI_help
        elif self.mode == self.MODE_LIGHTNING:
            if help_texts.ln_is_error:
                error_text = help_texts.ln_help
            else:
                self.data = lnaddr
                warning = help_texts.ln_help
        else:
            raise Exception(f"unexpected {self.mode=!r}")
        self.warning = (_('Warning') + ': ' + warning) if warning else ''
        self.error_text = error_text

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
