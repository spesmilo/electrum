from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from decimal import Decimal

Builder.load_string('''
<RequestLabel@Label>
    #color: .305, .309, .309, 1
    text_size: self.width, None
    halign: 'left'
    valign: 'top'

<RequestItem@CardItem>
    address: ''
    memo: ''
    amount: ''
    status: ''
    date: ''
    icon: 'atlas://electrum_ltc/gui/kivy/theming/light/important'
    Image:
        id: icon
        source: root.icon
        size_hint: None, 1
        width: self.height *.54
        mipmap: True
    BoxLayout:
        spacing: '8dp'
        height: '32dp'
        orientation: 'vertical'
        Widget
        RequestLabel:
            text: root.address
            shorten: True
        Widget
        RequestLabel:
            text: root.memo
            color: .699, .699, .699, 1
            font_size: '13sp'
            shorten: True
        Widget
    BoxLayout:
        spacing: '8dp'
        height: '32dp'
        orientation: 'vertical'
        Widget
        RequestLabel:
            text: root.amount
            halign: 'right'
            font_size: '15sp'
        Widget
        RequestLabel:
            text: root.status
            halign: 'right'
            font_size: '13sp'
            color: .699, .699, .699, 1
        Widget

<RequestsDialog@Popup>
    id: popup
    title: _('Requests')
    BoxLayout:
        id:box
        orientation: 'vertical'
        spacing: '1dp'
        ScrollView:
            GridLayout:
                cols: 1
                id: requests_container
                size_hint: 1, None
                height: self.minimum_height
                spacing: '2dp'
                padding: '12dp'
''')

from kivy.properties import BooleanProperty
from electrum_ltc.gui.kivy.i18n import _
from electrum_ltc.util import format_time
from electrum_ltc.paymentrequest import PR_UNPAID, PR_PAID, PR_UNKNOWN, PR_EXPIRED
from electrum_ltc.gui.kivy.uix.context_menu import ContextMenu

pr_icon = {
    PR_UNPAID: 'atlas://electrum_ltc/gui/kivy/theming/light/important',
    PR_UNKNOWN: 'atlas://electrum_ltc/gui/kivy/theming/light/important',
    PR_PAID: 'atlas://electrum_ltc/gui/kivy/theming/light/confirmed',
    PR_EXPIRED: 'atlas://electrum_ltc/gui/kivy/theming/light/close'
}
request_text = {
    PR_UNPAID: _('Pending'),
    PR_UNKNOWN: _('Unknown'),
    PR_PAID: _('Received'),
    PR_EXPIRED: _('Expired')
}


class RequestsDialog(Factory.Popup):

    def __init__(self, app, screen, callback):
        Factory.Popup.__init__(self)
        self.app = app
        self.screen = screen
        self.callback = callback
        self.cards = {}
        self.context_menu = None

    def get_card(self, req):
        address = req['address']
        ci = self.cards.get(address)
        if ci is None:
            ci = Factory.RequestItem()
            ci.address = address
            ci.screen = self
            self.cards[address] = ci

        amount = req.get('amount')
        ci.amount = self.app.format_amount_and_units(amount) if amount else ''
        ci.memo = req.get('memo', '')
        status, conf = self.app.wallet.get_request_status(address)
        ci.status = request_text[status]
        ci.icon = pr_icon[status]
        #exp = pr.get_expiration_date()
        #ci.date = format_time(exp) if exp else _('Never')
        return ci

    def update(self):
        self.menu_actions = [(_('Show'), self.do_show), (_('Delete'), self.do_delete)]
        requests_list = self.ids.requests_container
        requests_list.clear_widgets()
        _list = self.app.wallet.get_sorted_requests(self.app.electrum_config)
        for pr in _list:
            ci = self.get_card(pr)
            requests_list.add_widget(ci)

    def do_show(self, obj):
        self.hide_menu()
        self.dismiss()
        self.app.show_request(obj.address)

    def do_delete(self, req):
        from .question import Question
        def cb(result):
            if result:
                self.app.wallet.remove_payment_request(req.address, self.app.electrum_config)
                self.hide_menu()
                self.update()
        d = Question(_('Delete request'), cb)
        d.open()

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, self.menu_actions)
        self.ids.box.add_widget(self.context_menu)

    def hide_menu(self):
        if self.context_menu is not None:
            self.ids.box.remove_widget(self.context_menu)
            self.context_menu = None
