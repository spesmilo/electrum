from typing import TYPE_CHECKING

from kivy.factory import Factory
from kivy.lang import Builder
from kivy.core.clipboard import Clipboard
from kivy.app import App
from kivy.clock import Clock

from electrum.gui.kivy.i18n import _
from electrum.util import pr_tooltips, pr_color, get_request_status
from electrum.util import PR_UNKNOWN, PR_UNPAID, PR_FAILED, PR_TYPE_LN

if TYPE_CHECKING:
    from electrum.gui.kivy.main_window import ElectrumWindow


Builder.load_string('''
<InvoiceDialog@Popup>
    id: popup
    amount: 0
    title: ''
    data: ''
    status_color: 1,1,1,1
    status_str:''
    warning: ''
    can_pay: True
    shaded: False
    show_text: False
    AnchorLayout:
        anchor_x: 'center'
        BoxLayout:
            orientation: 'vertical'
            size_hint: 1, 1
            padding: '10dp'
            spacing: '10dp'
            TopLabel:
                text: root.data
            TopLabel:
                text: _('Amount') + ': ' + app.format_amount_and_units(root.amount)
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
                    text: _('Pay')
                    on_release: root.do_pay()
                    disabled: not root.can_pay
''')

class InvoiceDialog(Factory.Popup):

    def __init__(self, title, data, key):
        self.status = PR_UNKNOWN
        Factory.Popup.__init__(self)
        self.app = App.get_running_app()  # type: ElectrumWindow
        self.title = title
        self.data = data
        self.key = key
        r = self.app.wallet.get_invoice(key)
        self.amount = r.get('amount')
        self.is_lightning = r.get('type') == PR_TYPE_LN
        self.update_status()

    def update_status(self):
        req = self.app.wallet.get_invoice(self.key)
        self.status, self.status_str = get_request_status(req)
        self.status_color = pr_color[self.status]
        self.can_pay = self.status in [PR_UNPAID, PR_FAILED]
        if self.can_pay and self.is_lightning and self.app.wallet.lnworker:
            if self.amount and self.amount > self.app.wallet.lnworker.can_send():
                self.warning = _('Warning') + ': ' + _('This amount exceeds the maximum you can currently send with your channels')

    def on_dismiss(self):
        self.app.request_popup = None

    def copy_to_clipboard(self):
        Clipboard.copy(self.data)
        msg = _('Text copied to clipboard.')
        Clock.schedule_once(lambda dt: self.app.show_info(msg))

    def do_share(self):
        self.app.do_share(self.data, _("Share Invoice"))
        self.dismiss()

    def do_pay(self):
        invoice = self.app.wallet.get_invoice(self.key)
        self.app.send_screen.do_pay_invoice(invoice)
        self.dismiss()

    def delete_dialog(self):
        from .question import Question
        def cb(result):
            if result:
                self.app.wallet.delete_invoice(self.key)
                self.dismiss()
                self.app.send_screen.update()
        d = Question(_('Delete invoice?'), cb)
        d.open()
