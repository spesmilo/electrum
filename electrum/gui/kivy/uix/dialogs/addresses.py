from typing import TYPE_CHECKING

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from decimal import Decimal
from kivy.uix.popup import Popup

from electrum.gui.kivy.i18n import _

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow


Builder.load_string('''
<AddressLabel@Label>
    text_size: self.width, None
    halign: 'left'
    valign: 'top'

<AddressItem@CardItem>
    address: ''
    memo: ''
    amount: ''
    status: ''
    BoxLayout:
        spacing: '8dp'
        height: '32dp'
        orientation: 'vertical'
        Widget
        AddressLabel:
            text: root.address
            shorten: True
        Widget
        AddressLabel:
            text: (root.amount if root.status == 'Funded' else root.status) + '     ' + root.memo
            color: .699, .699, .699, 1
            font_size: '13sp'
            shorten: True
        Widget

<AddressesDialog@Popup>
    id: popup
    title: _('Addresses')
    message: ''
    pr_status: 'Pending'
    show_change: 0
    show_used: 0
    on_message:
        self.update()
    BoxLayout:
        id:box
        padding: '12dp', '70dp', '12dp', '12dp'
        spacing: '12dp'
        orientation: 'vertical'
        size_hint: 1, 1.1
        BoxLayout:
            spacing: '6dp'
            size_hint: 1, None
            orientation: 'horizontal'
            AddressFilter:
                opacity: 1
                size_hint: 1, None
                height: self.minimum_height
                spacing: '5dp'
                AddressButton:
                    id: search
                    text: {0:_('Receiving'), 1:_('Change'), 2:_('All')}[root.show_change]
                    on_release:
                        root.show_change = (root.show_change + 1) % 3
                        Clock.schedule_once(lambda dt: root.update())
            AddressFilter:
                opacity: 1
                size_hint: 1, None
                height: self.minimum_height
                spacing: '5dp'
                AddressButton:
                    id: search
                    text: {0:_('All'), 1:_('Unused'), 2:_('Funded'), 3:_('Used')}[root.show_used]
                    on_release:
                        root.show_used = (root.show_used + 1) % 4
                        Clock.schedule_once(lambda dt: root.update())
            AddressFilter:
                opacity: 1
                size_hint: 1, None
                height: self.minimum_height
                spacing: '5dp'
                canvas.before:
                    Color:
                        rgba: 0.9, 0.9, 0.9, 1
                AddressButton:
                    id: change
                    text: root.message if root.message else _('Search')
                    on_release: Clock.schedule_once(lambda dt: app.description_dialog(popup))
        RecycleView:
            scroll_type: ['bars', 'content']
            bar_width: '15dp'
            viewclass: 'AddressItem'
            id: search_container
            RecycleBoxLayout:
                orientation: 'vertical'
                default_size: None, dp(56)
                default_size_hint: 1, None
                size_hint_y: None
                height: self.minimum_height

<AddressPopup@Popup>:
    address: ''
    balance: ''
    status: ''
    script_type: ''
    pk: ''
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            GridLayout:
                cols: 1
                height: self.minimum_height
                size_hint_y: None
                padding: '10dp'
                spacing: '10dp'
                TopLabel:
                    text: _('Address')
                RefLabel:
                    data: root.address
                    name: _('Address')
                GridLayout:
                    cols: 1
                    size_hint_y: None
                    height: self.minimum_height
                    spacing: '10dp'
                    BoxLabel:
                        text: _('Balance')
                        value: root.balance
                    BoxLabel:
                        text: _('Script type')
                        value: root.script_type
                    BoxLabel:
                        text: _('Status')
                        value: root.status
                TopLabel:
                    text: _('Private Key')
                RefLabel:
                    data: root.pk
                    name: _('Private key')
                    on_touched: if not self.data: root.do_export(self)
        Widget:
            size_hint: 1, 0.1
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Receive')
                on_release: root.receive_at()
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Close')
                on_release: root.dismiss()
''')



class AddressPopup(Popup):

    def __init__(self, parent, address, balance, status, **kwargs):
        super(AddressPopup, self).__init__(**kwargs)
        self.title = _('Address Details')
        self.parent_dialog = parent
        self.app = parent.app
        self.address = address
        self.status = status
        self.script_type = self.app.wallet.get_txin_type(self.address)
        self.balance = self.app.format_amount_and_units(balance)

    def receive_at(self):
        self.dismiss()
        self.parent_dialog.dismiss()
        self.app.switch_to('receive')
        self.app.receive_screen.set_address(self.address)

    def do_export(self, pk_label):
        self.app.export_private_keys(pk_label, self.address)


class AddressesDialog(Factory.Popup):

    def __init__(self, app):
        Factory.Popup.__init__(self)
        self.app = app  # type: ElectrumWindow

    def get_card(self, addr, balance, is_used, label):
        ci = {}
        ci['screen'] = self
        ci['address'] = addr
        ci['memo'] = label
        ci['amount'] = self.app.format_amount_and_units(balance)
        ci['status'] = _('Used') if is_used else _('Funded') if balance > 0 else _('Unused')
        return ci

    def update(self):
        wallet = self.app.wallet
        if self.show_change == 0:
            _list = wallet.get_receiving_addresses()
        elif self.show_change == 1:
            _list = wallet.get_change_addresses()
        else:
            _list = wallet.get_addresses()
        search = self.message
        container = self.ids.search_container
        n = 0
        cards = []
        for address in _list:
            label = wallet.labels.get(address, '')
            balance = sum(wallet.get_addr_balance(address))
            is_used_and_empty = wallet.is_used(address) and balance == 0
            if self.show_used == 1 and (balance or is_used_and_empty):
                continue
            if self.show_used == 2 and balance == 0:
                continue
            if self.show_used == 3 and not is_used_and_empty:
                continue
            card = self.get_card(address, balance, is_used_and_empty, label)
            if search and not self.ext_search(card, search):
                continue
            cards.append(card)
            n += 1
        container.data = cards
        if not n:
            self.app.show_error('No address matching your search')

    def show_item(self, obj):
        address = obj.address
        c, u, x = self.app.wallet.get_addr_balance(address)
        balance = c + u + x
        d = AddressPopup(self, address, balance, obj.status)
        d.open()

    def ext_search(self, card, search):
        return card['memo'].find(search) >= 0 or card['amount'].find(search) >= 0
