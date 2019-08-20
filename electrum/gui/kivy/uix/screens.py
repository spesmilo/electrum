import asyncio
from weakref import ref
from decimal import Decimal
import re
import datetime
import threading
import traceback, sys
from enum import Enum, auto

from kivy.app import App
from kivy.cache import Cache
from kivy.clock import Clock
from kivy.compat import string_types
from kivy.properties import (ObjectProperty, DictProperty, NumericProperty,
                             ListProperty, StringProperty)

from kivy.uix.recycleview import RecycleView
from kivy.uix.label import Label
from kivy.uix.behaviors import ToggleButtonBehavior
from kivy.uix.image import Image

from kivy.lang import Builder
from kivy.factory import Factory
from kivy.utils import platform

from electrum.util import profiler, parse_URI, format_time, InvalidPassword, NotEnoughFunds, Fiat
from electrum import bitcoin, constants
from electrum.transaction import TxOutput, Transaction, tx_from_str
from electrum.util import send_exception_to_crash_reporter, parse_URI, InvalidBitcoinURI
from electrum.util import PR_UNPAID, PR_PAID, PR_UNKNOWN, PR_EXPIRED, TxMinedInfo, age
from electrum.plugin import run_hook
from electrum.wallet import InternalAddressCorruption
from electrum import simple_config
from electrum.lnaddr import lndecode
from electrum.lnutil import RECEIVED, SENT, PaymentFailure

from .context_menu import ContextMenu
from .dialogs.lightning_open_channel import LightningOpenChannelDialog

from electrum.gui.kivy.i18n import _

class Destination(Enum):
    Address = auto()
    PR = auto()
    LN = auto()

class HistoryRecycleView(RecycleView):
    pass

class RequestRecycleView(RecycleView):
    pass

class CScreen(Factory.Screen):
    __events__ = ('on_activate', 'on_deactivate', 'on_enter', 'on_leave')
    action_view = ObjectProperty(None)
    loaded = False
    kvname = None
    context_menu = None
    menu_actions = []
    app = App.get_running_app()

    def _change_action_view(self):
        app = App.get_running_app()
        action_bar = app.root.manager.current_screen.ids.action_bar
        _action_view = self.action_view

        if (not _action_view) or _action_view.parent:
            return
        action_bar.clear_widgets()
        action_bar.add_widget(_action_view)

    def on_enter(self):
        # FIXME: use a proper event don't use animation time of screen
        Clock.schedule_once(lambda dt: self.dispatch('on_activate'), .25)
        pass

    def update(self):
        pass

    @profiler
    def load_screen(self):
        self.screen = Builder.load_file('electrum/gui/kivy/uix/ui_screens/' + self.kvname + '.kv')
        self.add_widget(self.screen)
        self.loaded = True
        self.update()
        setattr(self.app, self.kvname + '_screen', self)

    def on_activate(self):
        if self.kvname and not self.loaded:
            self.load_screen()
        #Clock.schedule_once(lambda dt: self._change_action_view())

    def on_leave(self):
        self.dispatch('on_deactivate')

    def on_deactivate(self):
        self.hide_menu()

    def hide_menu(self):
        if self.context_menu is not None:
            self.remove_widget(self.context_menu)
            self.context_menu = None

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, self.menu_actions)
        self.add_widget(self.context_menu)


# note: this list needs to be kept in sync with another in qt
TX_ICONS = [
    "unconfirmed",
    "close",
    "unconfirmed",
    "close",
    "clock1",
    "clock2",
    "clock3",
    "clock4",
    "clock5",
    "confirmed",
]

class HistoryScreen(CScreen):

    tab = ObjectProperty(None)
    kvname = 'history'
    cards = {}

    def __init__(self, **kwargs):
        self.ra_dialog = None
        super(HistoryScreen, self).__init__(**kwargs)
        self.menu_actions = [ ('Label', self.label_dialog), ('Details', self.show_tx)]

    def show_tx(self, obj):
        tx_hash = obj.tx_hash
        tx = self.app.wallet.db.get_transaction(tx_hash)
        if not tx:
            return
        self.app.tx_dialog(tx)

    def label_dialog(self, obj):
        from .dialogs.label_dialog import LabelDialog
        key = obj.tx_hash
        text = self.app.wallet.get_label(key)
        def callback(text):
            self.app.wallet.set_label(key, text)
            self.update()
        d = LabelDialog(_('Enter Transaction Label'), text, callback)
        d.open()

    def get_card(self, tx_item): #tx_hash, tx_mined_status, value, balance):
        is_lightning = tx_item.get('lightning', False)
        timestamp = tx_item['timestamp']
        if is_lightning:
            status = 0
            txpos = tx_item['txpos']
            if timestamp is None:
                status_str = 'unconfirmed'
            else:
                status_str = format_time(int(timestamp))
            icon = "atlas://electrum/gui/kivy/theming/light/lightning"
        else:
            tx_hash = tx_item['txid']
            conf = tx_item['confirmations']
            txpos = tx_item['txpos_in_block'] or 0
            height = tx_item['height']
            tx_mined_info = TxMinedInfo(height=tx_item['height'],
                                        conf=tx_item['confirmations'],
                                        timestamp=tx_item['timestamp'])
            status, status_str = self.app.wallet.get_tx_status(tx_hash, tx_mined_info)
            icon = "atlas://electrum/gui/kivy/theming/light/" + TX_ICONS[status]
        ri = {}
        ri['screen'] = self
        ri['icon'] = icon
        ri['date'] = status_str
        ri['message'] = tx_item['label']
        value = tx_item['value'].value
        if value is not None:
            ri['is_mine'] = value < 0
            if value < 0: value = - value
            ri['amount'] = self.app.format_amount_and_units(value)
            if 'fiat_value' in tx_item:
                ri['quote_text'] = tx_item['fiat_value'].to_ui_string()
        return ri

    def update(self, see_all=False):
        import operator
        wallet = self.app.wallet
        if wallet is None:
            return
        history = sorted(wallet.get_full_history(self.app.fx).values(), key=lambda x: x.get('timestamp') or float('inf'), reverse=True)
        history_card = self.screen.ids.history_container
        history_card.data = [self.get_card(item) for item in history]


class SendScreen(CScreen):

    kvname = 'send'
    payment_request = None
    payment_request_queued = None

    def set_URI(self, text):
        if not self.app.wallet:
            self.payment_request_queued = text
            return
        try:
            uri = parse_URI(text, self.app.on_pr, loop=self.app.asyncio_loop)
        except InvalidBitcoinURI as e:
            self.app.show_info(_("Error parsing URI") + f":\n{e}")
            return
        amount = uri.get('amount')
        self.screen.address = uri.get('address', '')
        self.screen.message = uri.get('message', '')
        self.screen.amount = self.app.format_amount_and_units(amount) if amount else ''
        self.payment_request = None
        self.screen.destinationtype = Destination.Address

    def set_ln_invoice(self, invoice):
        try:
            lnaddr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        except Exception as e:
            self.app.show_info(invoice + _(" is not a valid Lightning invoice: ") + repr(e)) # repr because str(Exception()) == ''
            return
        self.screen.address = invoice
        self.screen.message = dict(lnaddr.tags).get('d', None)
        self.screen.amount = self.app.format_amount_and_units(lnaddr.amount * bitcoin.COIN) if lnaddr.amount else ''
        self.payment_request = None
        self.screen.destinationtype = Destination.LN

    def update(self):
        if self.app.wallet and self.payment_request_queued:
            self.set_URI(self.payment_request_queued)
            self.payment_request_queued = None

    def do_clear(self):
        self.screen.amount = ''
        self.screen.message = ''
        self.screen.address = ''
        self.payment_request = None
        self.screen.destinationtype = Destination.Address

    def set_request(self, pr):
        self.screen.address = pr.get_requestor()
        amount = pr.get_amount()
        self.screen.amount = self.app.format_amount_and_units(amount) if amount else ''
        self.screen.message = pr.get_memo()
        if pr.is_pr():
            self.screen.destinationtype = Destination.PR
            self.payment_request = pr
        else:
            self.screen.destinationtype = Destination.Address
            self.payment_request = None

    def save_invoice(self):
        if not self.screen.address:
            return
        if self.screen.destinationtype == Destination.PR:
            # it should be already saved
            return
        # save address as invoice
        from electrum.paymentrequest import make_unsigned_request, PaymentRequest
        req = {'address':self.screen.address, 'memo':self.screen.message}
        amount = self.app.get_amount(self.screen.amount) if self.screen.amount else 0
        req['amount'] = amount
        pr = make_unsigned_request(req).SerializeToString()
        pr = PaymentRequest(pr)
        self.app.wallet.invoices.add(pr)
        #self.app.show_info(_("Invoice saved"))
        if pr.is_pr():
            self.screen.destinationtype = Destination.PR
            self.payment_request = pr
        else:
            self.screen.destinationtype = Destination.Address
            self.payment_request = None

    def do_paste(self):
        data = self.app._clipboard.paste()
        if not data:
            self.app.show_info(_("Clipboard is empty"))
            return
        # try to decode as transaction
        try:
            raw_tx = tx_from_str(data)
            tx = Transaction(raw_tx)
            tx.deserialize()
        except:
            tx = None
        if tx:
            self.app.tx_dialog(tx)
            return
        # try to decode as URI/address
        if data.startswith('ln'):
            self.set_ln_invoice(data.rstrip())
        else:
            self.set_URI(data)
            # save automatically
            self.save_invoice()

    def _do_send_lightning(self):
        if not self.screen.amount:
            self.app.show_error(_('Since the invoice contained no amount, you must enter one'))
            return
        invoice = self.screen.address
        amount_sat = self.app.get_amount(self.screen.amount)
        threading.Thread(target=self._lnpay_thread, args=(invoice, amount_sat)).start()

    def _lnpay_thread(self, invoice, amount_sat):
        self.do_clear()
        self.app.show_info(_('Payment in progress..'))
        try:
            success = self.app.wallet.lnworker.pay(invoice, attempts=10, amount_sat=amount_sat, timeout=60)
        except PaymentFailure as e:
            self.app.show_error(_('Payment failure') + '\n' + str(e))
            return
        if success:
            self.app.show_info(_('Payment was sent'))
            self.app._trigger_update_history()
        else:
            self.app.show_error(_('Payment failed'))

    def do_send(self):
        if self.screen.destinationtype == Destination.LN:
            self._do_send_lightning()
            return
        elif self.screen.destinationtype == Destination.PR:
            if self.payment_request.has_expired():
                self.app.show_error(_('Payment request has expired'))
                return
            outputs = self.payment_request.get_outputs()
        else:
            address = str(self.screen.address)
            if not address:
                self.app.show_error(_('Recipient not specified.') + ' ' + _('Please scan a Bitcoin address or a payment request'))
                return
            if not bitcoin.is_address(address):
                self.app.show_error(_('Invalid Bitcoin Address') + ':\n' + address)
                return
            try:
                amount = self.app.get_amount(self.screen.amount)
            except:
                self.app.show_error(_('Invalid amount') + ':\n' + self.screen.amount)
                return
            outputs = [TxOutput(bitcoin.TYPE_ADDRESS, address, amount)]
        message = self.screen.message
        amount = sum(map(lambda x:x[2], outputs))
        if self.app.electrum_config.get('use_rbf'):
            from .dialogs.question import Question
            d = Question(_('Should this transaction be replaceable?'), lambda b: self._do_send(amount, message, outputs, b))
            d.open()
        else:
            self._do_send(amount, message, outputs, False)

    def _do_send(self, amount, message, outputs, rbf):
        # make unsigned transaction
        config = self.app.electrum_config
        coins = self.app.wallet.get_spendable_coins(None, config)
        try:
            tx = self.app.wallet.make_unsigned_transaction(coins, outputs, config, None)
        except NotEnoughFunds:
            self.app.show_error(_("Not enough funds"))
            return
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.app.show_error(repr(e))
            return
        if rbf:
            tx.set_rbf(True)
        fee = tx.get_fee()
        msg = [
            _("Amount to be sent") + ": " + self.app.format_amount_and_units(amount),
            _("Mining fee") + ": " + self.app.format_amount_and_units(fee),
        ]
        x_fee = run_hook('get_tx_extra_fee', self.app.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            msg.append(_("Additional fees") + ": " + self.app.format_amount_and_units(x_fee_amount))

        feerate_warning = simple_config.FEERATE_WARNING_HIGH_FEE
        if fee > feerate_warning * tx.estimated_size() / 1000:
            msg.append(_('Warning') + ': ' + _("The fee for this transaction seems unusually high."))
        msg.append(_("Enter your PIN code to proceed"))
        self.app.protected('\n'.join(msg), self.send_tx, (tx, message))

    def send_tx(self, tx, message, password):
        if self.app.wallet.has_password() and password is None:
            return
        def on_success(tx):
            if tx.is_complete():
                self.app.broadcast(tx, self.payment_request)
                self.app.wallet.set_label(tx.txid(), message)
            else:
                self.app.tx_dialog(tx)
        def on_failure(error):
            self.app.show_error(error)
        if self.app.wallet.can_sign(tx):
            self.app.show_info("Signing...")
            self.app.sign_tx(tx, password, on_success, on_failure)
        else:
            self.app.tx_dialog(tx)



class ReceiveScreen(CScreen):

    kvname = 'receive'
    cards = {}

    def __init__(self, **kwargs):
        super(ReceiveScreen, self).__init__(**kwargs)
        self.menu_actions = [(_('Show'), self.do_show), (_('Delete'), self.do_delete)]
        self.expiration = self.app.electrum_config.get('request_expiration', 3600) # 1 hour

    def clear(self):
        self.screen.address = ''
        self.screen.amount = ''
        self.screen.message = ''
        self.screen.lnaddr = ''

    def set_address(self, addr):
        self.screen.address = addr

    def on_address(self, addr):
        req = self.app.wallet.get_payment_request(addr, self.app.electrum_config)
        self.screen.status = ''
        if req:
            self.screen.message = req.get('memo', '')
            amount = req.get('amount')
            self.screen.amount = self.app.format_amount_and_units(amount) if amount else ''
            status = req.get('status', PR_UNKNOWN)
            self.screen.status = _('Payment received') if status == PR_PAID else ''

    def get_URI(self):
        from electrum.util import create_bip21_uri
        amount = self.screen.amount
        if amount:
            a, u = self.screen.amount.split()
            assert u == self.app.base_unit
            amount = Decimal(a) * pow(10, self.app.decimal_point())
        return create_bip21_uri(self.screen.address, amount, self.screen.message)

    def do_share(self):
        uri = self.get_URI()
        self.app.do_share(uri, _("Share Bitcoin Request"))

    def do_copy(self):
        uri = self.get_URI()
        self.app._clipboard.copy(uri)
        self.app.show_info(_('Request copied to clipboard'))

    def new_request(self, lightning):
        amount = self.screen.amount
        amount = self.app.get_amount(amount) if amount else 0
        message = self.screen.message
        expiration = self.expiration
        if lightning:
            payment_hash = self.app.wallet.lnworker.add_invoice(amount, message)
            request, direction, is_paid = self.app.wallet.lnworker.invoices.get(payment_hash.hex())
            key = payment_hash.hex()
        else:
            addr = self.screen.address or self.app.wallet.get_unused_address()
            if not addr:
                self.app.show_info(_('No address available. Please remove some of your pending requests.'))
                return
            self.screen.address = addr
            req = self.app.wallet.make_payment_request(addr, amount, message, expiration)
            self.app.wallet.add_payment_request(req, self.app.electrum_config)
            key = addr
        self.update()
        self.app.show_request(lightning, key)

    def get_card(self, req):
        is_lightning = req.get('lightning', False)
        status = req['status']
        #if status != PR_UNPAID:
        #    continue
        if not is_lightning:
            address = req['address']
            key = address
        else:
            key = req['rhash']
            address = req['invoice']
        timestamp = req.get('time', 0)
        amount = req.get('amount')
        description = req.get('memo', '')
        ci = self.cards.get(key)
        if ci is None:
            ci = {}
            ci['address'] = address
            ci['is_lightning'] = is_lightning
            ci['key'] = key
            ci['screen'] = self
            self.cards[key] = ci
        ci['amount'] = self.app.format_amount_and_units(amount) if amount else ''
        ci['memo'] = description
        ci['status'] = age(timestamp)
        return ci

    def update(self):
        _list = self.app.wallet.get_sorted_requests(self.app.electrum_config)
        requests_container = self.screen.ids.requests_container
        requests_container.data = [self.get_card(item) for item in _list if item.get('status') != PR_PAID]

    def do_show(self, obj):
        self.hide_menu()
        self.app.show_request(obj.is_lightning, obj.key)

    def expiration_dialog(self, obj):
        from .dialogs.choice_dialog import ChoiceDialog
        choices = {
            10*60: _('10 minutes'),
            60*60: _('1 hour'),
            24*60*60: _('1 day'),
            7*24*60*60: _('1 week')
        }
        def callback(c):
            self.expiration = c
            self.app.electrum_config.set_key('request_expiration', c)
        d = ChoiceDialog(_('Expiration date'), choices, self.expiration, callback)
        d.open()

    def do_delete(self, req):
        from .dialogs.question import Question
        def cb(result):
            if result:
                if req.is_lightning:
                    self.app.wallet.lnworker.delete_invoice(req.key)
                else:
                    self.app.wallet.remove_payment_request(req.key, self.app.electrum_config)
                self.hide_menu()
                self.update()
        d = Question(_('Delete request'), cb)
        d.open()

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, self.menu_actions)
        self.add_widget(self.context_menu)

    def hide_menu(self):
        if self.context_menu is not None:
            self.remove_widget(self.context_menu)
            self.context_menu = None

class TabbedCarousel(Factory.TabbedPanel):
    '''Custom TabbedPanel using a carousel used in the Main Screen
    '''

    carousel = ObjectProperty(None)

    def animate_tab_to_center(self, value):
        scrlv = self._tab_strip.parent
        if not scrlv:
            return
        idx = self.tab_list.index(value)
        n = len(self.tab_list)
        if idx in [0, 1]:
            scroll_x = 1
        elif idx in [n-1, n-2]:
            scroll_x = 0
        else:
            scroll_x = 1. * (n - idx - 1) / (n - 1)
        mation = Factory.Animation(scroll_x=scroll_x, d=.25)
        mation.cancel_all(scrlv)
        mation.start(scrlv)

    def on_current_tab(self, instance, value):
        self.animate_tab_to_center(value)

    def on_index(self, instance, value):
        current_slide = instance.current_slide
        if not hasattr(current_slide, 'tab'):
            return
        tab = current_slide.tab
        ct = self.current_tab
        try:
            if ct.text != tab.text:
                carousel = self.carousel
                carousel.slides[ct.slide].dispatch('on_leave')
                self.switch_to(tab)
                carousel.slides[tab.slide].dispatch('on_enter')
        except AttributeError:
            current_slide.dispatch('on_enter')

    def switch_to(self, header):
        # we have to replace the functionality of the original switch_to
        if not header:
            return
        if not hasattr(header, 'slide'):
            header.content = self.carousel
            super(TabbedCarousel, self).switch_to(header)
            try:
                tab = self.tab_list[-1]
            except IndexError:
                return
            self._current_tab = tab
            tab.state = 'down'
            return

        carousel = self.carousel
        self.current_tab.state = "normal"
        header.state = 'down'
        self._current_tab = header
        # set the carousel to load the appropriate slide
        # saved in the screen attribute of the tab head
        slide = carousel.slides[header.slide]
        if carousel.current_slide != slide:
            carousel.current_slide.dispatch('on_leave')
            carousel.load_slide(slide)
            slide.dispatch('on_enter')

    def add_widget(self, widget, index=0):
        if isinstance(widget, Factory.CScreen):
            self.carousel.add_widget(widget)
            return
        super(TabbedCarousel, self).add_widget(widget, index=index)
