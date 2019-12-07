from kivy.factory import Factory
from kivy.lang import Builder
from kivy.core.clipboard import Clipboard
from kivy.app import App
from kivy.clock import Clock

from electrum.gui.kivy.i18n import _
from electrum.util import pr_tooltips, pr_color
from electrum.util import PR_UNKNOWN


Builder.load_string('''
<RequestDialog@Popup>
    id: popup
    title: ''
    data: ''
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
                    text: _('Close')
                    on_release: popup.dismiss()
''')

class RequestDialog(Factory.Popup):

    def __init__(self, title, data, key, *, is_lightning=False):
        self.status = PR_UNKNOWN
        Factory.Popup.__init__(self)
        self.app = App.get_running_app()
        self.title = title
        self.data = data
        self.key = key
        self.is_lightning = is_lightning

    def on_open(self):
        data = self.data
        if self.is_lightning:
            # encode lightning invoices as uppercase so QR encoding can use
            # alphanumeric mode; resulting in smaller QR codes
            data = data.upper()
        self.ids.qr.set_data(data)

    def set_status(self, status):
        self.status = status
        self.status_str = pr_tooltips[status]
        self.status_color = pr_color[status]

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
