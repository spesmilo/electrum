from typing import TYPE_CHECKING

from kivy.factory import Factory
from kivy.lang import Builder
from kivy.core.clipboard import Clipboard
from kivy.app import App
from kivy.clock import Clock

from electrum.gui.kivy.i18n import _

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string('''
<QRDialog@Popup>
    id: popup
    title: ''
    data: ''
    shaded: False
    help_text: ''
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
                text: root.help_text
            Widget:
                size_hint: 1, 0.2
            BoxLayout:
                size_hint: 1, None
                height: '48dp'
                Button:
                    size_hint: 1, None
                    height: '48dp'
                    text: _('Copy')
                    on_release:
                        root.copy_to_clipboard()
                IconButton:
                    icon: 'atlas://electrum/gui/kivy/theming/light/share'
                    size_hint: 0.6, None
                    height: '48dp'
                    on_release: root.do_share()
                Button:
                    size_hint: 1, None
                    height: '48dp'
                    text: _('Close')
                    on_release:
                        popup.dismiss()
''')

class QRDialog(Factory.Popup):
    def __init__(self, title, data, show_text, *,
                 failure_cb=None, text_for_clipboard=None, help_text=None):
        Factory.Popup.__init__(self)
        self.app = App.get_running_app()  # type: ElectrumWindow
        self.title = title
        self.data = data
        self.help_text = (data if show_text else help_text) or ''
        self.failure_cb = failure_cb
        self.text_for_clipboard = text_for_clipboard if text_for_clipboard else data

    def on_open(self):
        self.ids.qr.set_data(self.data, self.failure_cb)

    def copy_to_clipboard(self):
        Clipboard.copy(self.text_for_clipboard)
        msg = _('Text copied to clipboard.')
        Clock.schedule_once(lambda dt: self.app.show_info(msg))

    def do_share(self):
        self.app.do_share(self.text_for_clipboard, self.title)
        self.dismiss()
