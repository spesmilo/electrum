from typing import TYPE_CHECKING

from kivy.factory import Factory
from kivy.lang import Builder
from kivy.core.clipboard import Clipboard
from kivy.app import App
from kivy.clock import Clock

from electrum.gui.kivy.i18n import _
from electrum.util import pr_tooltips, pr_color
from electrum.util import PR_UNKNOWN, PR_UNPAID

if TYPE_CHECKING:
    from electrum.gui.kivy.main_window import ElectrumWindow


Builder.load_string('''
<InvoiceDialog@Popup>
    id: popup
    title: ''
    data: ''
    status_color: 1,1,1,1
    status_str:''
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
                text: _('Status') + ': ' + root.status_str
                color: root.status_color
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

    def set_status(self, status):
        self.status = status
        self.status_str = pr_tooltips[status]
        self.status_color = pr_color[status]
        self.can_pay = self.status == PR_UNPAID

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
