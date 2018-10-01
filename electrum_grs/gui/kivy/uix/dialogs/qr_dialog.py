from kivy.factory import Factory
from kivy.lang import Builder

Builder.load_string('''
<QRDialog@Popup>
    id: popup
    title: ''
    data: ''
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
            TopLabel:
                text: root.data if root.show_text else ''
            Widget:
                size_hint: 1, 0.2
            BoxLayout:
                size_hint: 1, None
                height: '48dp'
                Widget:
                    size_hint: 1, None
                    height: '48dp'
                Button:
                    size_hint: 1, None
                    height: '48dp'
                    text: _('Close')
                    on_release:
                        popup.dismiss()
''')

class QRDialog(Factory.Popup):
    def __init__(self, title, data, show_text, failure_cb=None):
        Factory.Popup.__init__(self)
        self.title = title
        self.data = data
        self.show_text = show_text
        self.failure_cb = failure_cb

    def on_open(self):
        self.ids.qr.set_data(self.data, self.failure_cb)
