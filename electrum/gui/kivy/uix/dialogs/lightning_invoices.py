from kivy.factory import Factory
from kivy.lang import Builder
from electrum.gui.kivy.i18n import _
from kivy.uix.recycleview import RecycleView
from electrum.gui.kivy.uix.context_menu import ContextMenu

Builder.load_string('''
<Item@CardItem>
    addr: ''
    desc: ''
    screen: None
    BoxLayout:
        orientation: 'vertical'
        Label
            text: root.addr
            text_size: self.width, None
            shorten: True
        Label
            text: root.desc if root.desc else _('No description')
            text_size: self.width, None
            shorten: True
            font_size: '10dp'

<LightningInvoicesDialog@Popup>
    id: popup
    title: _('Lightning Invoices')
    BoxLayout:
        orientation: 'vertical'
        id: box
        RecycleView:
            viewclass: 'Item'
            id: recycleview
            data: []
            RecycleBoxLayout:
                default_size: None, dp(56)
                default_size_hint: 1, None
                size_hint_y: None
                height: self.minimum_height
                orientation: 'vertical'
''')

class LightningInvoicesDialog(Factory.Popup):

    def __init__(self, report, callback):
        super().__init__()
        self.context_menu = None
        self.callback = callback
        self.menu_actions = [(_('Show'), self.do_show)]
        for addr, preimage, pay_req in report['unsettled']:
            self.ids.recycleview.data.append({'screen': self, 'addr': pay_req, 'desc': dict(addr.tags).get('d', '')})

    def do_show(self, obj):
        self.hide_menu()
        self.dismiss()
        self.callback(obj.addr)

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, self.menu_actions)
        self.ids.box.add_widget(self.context_menu)

    def hide_menu(self):
        if self.context_menu is not None:
            self.ids.box.remove_widget(self.context_menu)
            self.context_menu = None
