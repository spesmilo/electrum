from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from decimal import Decimal

Builder.load_string('''
<InvoicesLabel@Label>
    #color: .305, .309, .309, 1
    text_size: self.width, None
    halign: 'left'
    valign: 'top'

<InvoiceItem@CardItem>
    requestor: ''
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
        InvoicesLabel:
            text: root.requestor
            shorten: True
        Widget
        InvoicesLabel:
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
        InvoicesLabel:
            text: root.amount
            font_size: '15sp'
            halign: 'right'
            width: '110sp'
        Widget
        InvoicesLabel:
            text: root.status
            font_size: '13sp'
            halign: 'right'
            color: .699, .699, .699, 1
        Widget


<InvoicesDialog@Popup>
    id: popup
    title: _('Invoices')
    BoxLayout:
        id: box
        orientation: 'vertical'
        spacing: '1dp'
        ScrollView:
            GridLayout:
                cols: 1
                id: invoices_container
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

invoice_text = {
    PR_UNPAID:_('Pending'),
    PR_UNKNOWN:_('Unknown'),
    PR_PAID:_('Paid'),
    PR_EXPIRED:_('Expired')
}
pr_icon = {
    PR_UNPAID: 'atlas://electrum_ltc/gui/kivy/theming/light/important',
    PR_UNKNOWN: 'atlas://electrum_ltc/gui/kivy/theming/light/important',
    PR_PAID: 'atlas://electrum_ltc/gui/kivy/theming/light/confirmed',
    PR_EXPIRED: 'atlas://electrum_ltc/gui/kivy/theming/light/close'
}


class InvoicesDialog(Factory.Popup):

    def __init__(self, app, screen, callback):
        Factory.Popup.__init__(self)
        self.app = app
        self.screen = screen
        self.callback = callback
        self.cards = {}
        self.context_menu = None

    def get_card(self, pr):
        key = pr.get_id()
        ci = self.cards.get(key)
        if ci is None:
            ci = Factory.InvoiceItem()
            ci.key = key
            ci.screen = self
            self.cards[key] = ci
        ci.requestor = pr.get_requestor()
        ci.memo = pr.get_memo()
        amount = pr.get_amount()
        if amount:
            ci.amount = self.app.format_amount_and_units(amount)
            status = self.app.wallet.invoices.get_status(ci.key)
            ci.status = invoice_text[status]
            ci.icon = pr_icon[status]
        else:
            ci.amount = _('No Amount')
            ci.status = ''
        exp = pr.get_expiration_date()
        ci.date = format_time(exp) if exp else _('Never')
        return ci

    def update(self):
        self.menu_actions = [('Pay', self.do_pay), ('Details', self.do_view), ('Delete', self.do_delete)]
        invoices_list = self.ids.invoices_container
        invoices_list.clear_widgets()
        _list = self.app.wallet.invoices.sorted_list()
        for pr in _list:
            ci = self.get_card(pr)
            invoices_list.add_widget(ci)

    def do_pay(self, obj):
        self.hide_menu()
        self.dismiss()
        pr = self.app.wallet.invoices.get(obj.key)
        self.app.on_pr(pr)

    def do_view(self, obj):
        pr = self.app.wallet.invoices.get(obj.key)
        pr.verify(self.app.wallet.contacts)
        self.app.show_pr_details(pr.get_dict(), obj.status, True)

    def do_delete(self, obj):
        from .question import Question
        def cb(result):
            if result:
                self.app.wallet.invoices.remove(obj.key)
            self.hide_menu()
            self.update()
        d = Question(_('Delete invoice?'), cb)
        d.open()

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, self.menu_actions)
        self.ids.box.add_widget(self.context_menu)

    def hide_menu(self):
        if self.context_menu is not None:
            self.ids.box.remove_widget(self.context_menu)
            self.context_menu = None
