import asyncio
from weakref import ref
from decimal import Decimal
import re
import threading
import traceback, sys
from typing import TYPE_CHECKING, List, Optional, Dict, Any

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
from kivy.logger import Logger

from electrum.util import profiler, parse_URI, format_time, InvalidPassword, NotEnoughFunds, Fiat
from electrum.invoices import (PR_TYPE_ONCHAIN, PR_TYPE_LN, PR_DEFAULT_EXPIRATION_WHEN_CREATING,
                               PR_PAID, PR_UNKNOWN, PR_EXPIRED, PR_INFLIGHT,
                               LNInvoice, pr_expiration_values, Invoice, OnchainInvoice)
from electrum import bitcoin, constants
from electrum.transaction import Transaction, tx_from_any, PartialTransaction, PartialTxOutput
from electrum.util import parse_URI, InvalidBitcoinURI, TxMinedInfo, maybe_extract_bolt11_invoice
from electrum.plugin import run_hook
from electrum.wallet import InternalAddressCorruption
from electrum import simple_config
from electrum.simple_config import FEERATE_WARNING_HIGH_FEE, FEE_RATIO_HIGH_WARNING
from electrum.lnaddr import lndecode
from electrum.lnutil import RECEIVED, SENT, PaymentFailure

from .dialogs.question import Question
from .dialogs.lightning_open_channel import LightningOpenChannelDialog

from electrum.gui.kivy.i18n import _

if TYPE_CHECKING:
    from electrum.gui.kivy.main_window import ElectrumWindow
    from electrum.paymentrequest import PaymentRequest


class HistoryRecycleView(RecycleView):
    pass

class RequestRecycleView(RecycleView):
    pass

class PaymentRecycleView(RecycleView):
    pass

class CScreen(Factory.Screen):
    __events__ = ('on_activate', 'on_deactivate', 'on_enter', 'on_leave')
    action_view = ObjectProperty(None)
    kvname = None
    app = App.get_running_app()  # type: ElectrumWindow

    def on_enter(self):
        # FIXME: use a proper event don't use animation time of screen
        Clock.schedule_once(lambda dt: self.dispatch('on_activate'), .25)
        pass

    def update(self):
        pass

    def on_activate(self):
        setattr(self.app, self.kvname + '_screen', self)
        self.update()

    def on_leave(self):
        self.dispatch('on_deactivate')

    def on_deactivate(self):
        pass


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


Builder.load_file('electrum/gui/kivy/uix/ui_screens/history.kv')
Builder.load_file('electrum/gui/kivy/uix/ui_screens/send.kv')
Builder.load_file('electrum/gui/kivy/uix/ui_screens/receive.kv')


class HistoryScreen(CScreen):

    tab = ObjectProperty(None)
    kvname = 'history'
    cards = {}

    def __init__(self, **kwargs):
        self.ra_dialog = None
        super(HistoryScreen, self).__init__(**kwargs)

    def show_item(self, obj):
        key = obj.key
        tx_item = self.history.get(key)
        if tx_item.get('lightning') and tx_item['type'] == 'payment':
            self.app.lightning_tx_dialog(tx_item)
            return
        if tx_item.get('lightning'):
            tx = self.app.wallet.lnworker.lnwatcher.db.get_transaction(key)
        else:
            tx = self.app.wallet.db.get_transaction(key)
        if not tx:
            return
        self.app.tx_dialog(tx)

    def get_card(self, tx_item): #tx_hash, tx_mined_status, value, balance):
        is_lightning = tx_item.get('lightning', False)
        timestamp = tx_item['timestamp']
        key = tx_item.get('txid') or tx_item['payment_hash']
        if is_lightning:
            status = 0
            status_str = 'unconfirmed' if timestamp is None else format_time(int(timestamp))
            icon = "atlas://electrum/gui/kivy/theming/light/lightning"
            message = tx_item['label']
            fee_msat = tx_item['fee_msat']
            fee = int(fee_msat/1000) if fee_msat else None
            fee_text = '' if fee is None else 'fee: %d sat'%fee
        else:
            tx_hash = tx_item['txid']
            conf = tx_item['confirmations']
            tx_mined_info = TxMinedInfo(height=tx_item['height'],
                                        conf=tx_item['confirmations'],
                                        timestamp=tx_item['timestamp'])
            status, status_str = self.app.wallet.get_tx_status(tx_hash, tx_mined_info)
            icon = "atlas://electrum/gui/kivy/theming/light/" + TX_ICONS[status]
            message = tx_item['label'] or tx_hash
            fee = tx_item['fee_sat']
            fee_text = '' if fee is None else 'fee: %d sat'%fee
        ri = {}
        ri['screen'] = self
        ri['key'] = key
        ri['icon'] = icon
        ri['date'] = status_str
        ri['message'] = message
        ri['fee_text'] = fee_text
        value = tx_item['value'].value
        if value is not None:
            ri['is_mine'] = value <= 0
            ri['amount'] = self.app.format_amount(value, is_diff = True)
            if 'fiat_value' in tx_item:
                ri['quote_text'] = str(tx_item['fiat_value'])
        return ri

    def update(self, see_all=False):
        wallet = self.app.wallet
        if wallet is None:
            return
        self.history = wallet.get_full_history(self.app.fx)
        history = reversed(self.history.values())
        history_card = self.ids.history_container
        history_card.data = [self.get_card(item) for item in history]


class SendScreen(CScreen):

    kvname = 'send'
    payment_request = None  # type: Optional[PaymentRequest]
    parsed_URI = None

    def set_URI(self, text: str):
        if not self.app.wallet:
            return
        try:
            uri = parse_URI(text, self.app.on_pr, loop=self.app.asyncio_loop)
        except InvalidBitcoinURI as e:
            self.app.show_info(_("Error parsing URI") + f":\n{e}")
            return
        self.parsed_URI = uri
        amount = uri.get('amount')
        self.address = uri.get('address', '')
        self.message = uri.get('message', '')
        self.amount = self.app.format_amount_and_units(amount) if amount else ''
        self.payment_request = None
        self.is_lightning = False

    def set_ln_invoice(self, invoice: str):
        try:
            invoice = str(invoice).lower()
            lnaddr = lndecode(invoice, expected_hrp=constants.net.SEGWIT_HRP)
        except Exception as e:
            self.app.show_info(invoice + _(" is not a valid Lightning invoice: ") + repr(e)) # repr because str(Exception()) == ''
            return
        self.address = invoice
        self.message = dict(lnaddr.tags).get('d', None)
        self.amount = self.app.format_amount_and_units(lnaddr.amount * bitcoin.COIN) if lnaddr.amount else ''
        self.payment_request = None
        self.is_lightning = True

    def update(self):
        if self.app.wallet is None:
            return
        _list = self.app.wallet.get_invoices()
        _list.reverse()
        payments_container = self.ids.payments_container
        payments_container.data = [self.get_card(item) for item in _list]

    def show_item(self, obj):
        self.app.show_invoice(obj.is_lightning, obj.key)

    def get_card(self, item: Invoice):
        status = self.app.wallet.get_invoice_status(item)
        status_str = item.get_status_str(status)
        is_lightning = item.type == PR_TYPE_LN
        if is_lightning:
            assert isinstance(item, LNInvoice)
            key = item.rhash
            log = self.app.wallet.lnworker.logs.get(key)
            if status == PR_INFLIGHT and log:
                status_str += '... (%d)'%len(log)
            is_bip70 = False
        else:
            assert isinstance(item, OnchainInvoice)
            key = item.id
            is_bip70 = bool(item.bip70)
        return {
            'is_lightning': is_lightning,
            'is_bip70': is_bip70,
            'screen': self,
            'status': status,
            'status_str': status_str,
            'key': key,
            'memo': item.message,
            'amount': self.app.format_amount_and_units(item.get_amount_sat() or 0),
        }

    def do_clear(self):
        self.amount = ''
        self.message = ''
        self.address = ''
        self.payment_request = None
        self.is_lightning = False
        self.is_bip70 = False
        self.parsed_URI = None

    def set_request(self, pr: 'PaymentRequest'):
        self.address = pr.get_requestor()
        amount = pr.get_amount()
        self.amount = self.app.format_amount_and_units(amount) if amount else ''
        self.message = pr.get_memo()
        self.locked = True
        self.payment_request = pr

    def do_paste(self):
        data = self.app._clipboard.paste().strip()
        if not data:
            self.app.show_info(_("Clipboard is empty"))
            return
        # try to decode as transaction
        try:
            tx = tx_from_any(data)
            tx.deserialize()
        except:
            tx = None
        if tx:
            self.app.tx_dialog(tx)
            return
        # try to decode as URI/address
        bolt11_invoice = maybe_extract_bolt11_invoice(data)
        if bolt11_invoice is not None:
            self.set_ln_invoice(bolt11_invoice)
        else:
            self.set_URI(data)

    def read_invoice(self):
        address = str(self.address)
        if not address:
            self.app.show_error(_('Recipient not specified.') + ' ' + _('Please scan a Bitcoin address or a payment request'))
            return
        if not self.amount:
            self.app.show_error(_('Please enter an amount'))
            return
        try:
            amount = self.app.get_amount(self.amount)
        except:
            self.app.show_error(_('Invalid amount') + ':\n' + self.amount)
            return
        message = self.message
        if self.is_lightning:
            return LNInvoice.from_bech32(address)
        else:  # on-chain
            if self.payment_request:
                outputs = self.payment_request.get_outputs()
            else:
                if not bitcoin.is_address(address):
                    self.app.show_error(_('Invalid Bitcoin Address') + ':\n' + address)
                    return
                outputs = [PartialTxOutput.from_address_and_value(address, amount)]
            return self.app.wallet.create_invoice(
                outputs=outputs,
                message=message,
                pr=self.payment_request,
                URI=self.parsed_URI)

    def do_save(self):
        invoice = self.read_invoice()
        if not invoice:
            return
        self.app.wallet.save_invoice(invoice)
        self.do_clear()
        self.update()

    def do_pay(self):
        invoice = self.read_invoice()
        if not invoice:
            return
        self.app.wallet.save_invoice(invoice)
        self.do_clear()
        self.update()
        self.do_pay_invoice(invoice)

    def do_pay_invoice(self, invoice):
        if invoice.is_lightning():
            self._do_pay_lightning(invoice)
            return
        else:
            do_pay = lambda rbf: self._do_pay_onchain(invoice, rbf)
            if self.app.electrum_config.get('use_rbf'):
                d = Question(_('Should this transaction be replaceable?'), do_pay)
                d.open()
            else:
                do_pay(False)

    def _do_pay_lightning(self, invoice: LNInvoice) -> None:
        threading.Thread(
            target=self.app.wallet.lnworker.pay,
            args=(invoice.invoice,),
            kwargs={
                'attempts': 10,
            },
        ).start()

    def _do_pay_onchain(self, invoice: OnchainInvoice, rbf: bool) -> None:
        # make unsigned transaction
        outputs = invoice.outputs
        coins = self.app.wallet.get_spendable_coins(None)
        try:
            tx = self.app.wallet.make_unsigned_transaction(coins=coins, outputs=outputs)
        except NotEnoughFunds:
            self.app.show_error(_("Not enough funds"))
            return
        except Exception as e:
            Logger.exception('')
            self.app.show_error(repr(e))
            return
        if rbf:
            tx.set_rbf(True)
        fee = tx.get_fee()
        amount = sum(map(lambda x: x.value, outputs)) if '!' not in [x.value for x in outputs] else tx.output_value()
        msg = [
            _("Amount to be sent") + ": " + self.app.format_amount_and_units(amount),
            _("Mining fee") + ": " + self.app.format_amount_and_units(fee),
        ]
        x_fee = run_hook('get_tx_extra_fee', self.app.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            msg.append(_("Additional fees") + ": " + self.app.format_amount_and_units(x_fee_amount))

        feerate = Decimal(fee) / tx.estimated_size()  # sat/byte
        fee_ratio = Decimal(fee) / amount if amount else 1
        if fee_ratio >= FEE_RATIO_HIGH_WARNING:
            msg.append(_('Warning') + ': ' + _("The fee for this transaction seems unusually high.")
                       + f' ({fee_ratio*100:.2f}% of amount)')
        elif feerate > FEERATE_WARNING_HIGH_FEE / 1000:
            msg.append(_('Warning') + ': ' + _("The fee for this transaction seems unusually high.")
                       + f' (feerate: {feerate:.2f} sat/byte)')
        self.app.protected('\n'.join(msg), self.send_tx, (tx,))

    def send_tx(self, tx, password):
        if self.app.wallet.has_password() and password is None:
            return
        def on_success(tx):
            if tx.is_complete():
                self.app.broadcast(tx)
            else:
                self.app.tx_dialog(tx)
        def on_failure(error):
            self.app.show_error(error)
        if self.app.wallet.can_sign(tx):
            self.app.show_info("Signing...")
            self.app.sign_tx(tx, password, on_success, on_failure)
        else:
            self.app.tx_dialog(tx)

    def clear_invoices_dialog(self):
        invoices = self.app.wallet.get_invoices()
        if not invoices:
            return
        def callback(c):
            if c:
                for req in invoices:
                    key = req.rhash if req.is_lightning() else req.get_address()
                    self.app.wallet.delete_invoice(key)
                self.update()
        n = len(invoices)
        d = Question(_('Delete {} invoices?').format(n), callback)
        d.open()


class ReceiveScreen(CScreen):

    kvname = 'receive'

    def __init__(self, **kwargs):
        super(ReceiveScreen, self).__init__(**kwargs)
        Clock.schedule_interval(lambda dt: self.update(), 5)

    def expiry(self):
        return self.app.electrum_config.get('request_expiry', PR_DEFAULT_EXPIRATION_WHEN_CREATING)

    def clear(self):
        self.address = ''
        self.amount = ''
        self.message = ''
        self.lnaddr = ''

    def set_address(self, addr):
        self.address = addr

    def on_address(self, addr):
        req = self.app.wallet.get_request(addr)
        self.status = ''
        if req:
            self.message = req.get('memo', '')
            amount = req.get('amount')
            self.amount = self.app.format_amount_and_units(amount) if amount else ''
            status = req.get('status', PR_UNKNOWN)
            self.status = _('Payment received') if status == PR_PAID else ''

    def get_URI(self):
        from electrum.util import create_bip21_uri
        amount = self.amount
        if amount:
            a, u = self.amount.split()
            assert u == self.app.base_unit
            amount = Decimal(a) * pow(10, self.app.decimal_point())
        return create_bip21_uri(self.address, amount, self.message)

    def do_copy(self):
        uri = self.get_URI()
        self.app._clipboard.copy(uri)
        self.app.show_info(_('Request copied to clipboard'))

    def new_request(self, lightning):
        amount = self.amount
        amount = self.app.get_amount(amount) if amount else 0
        message = self.message
        if lightning:
            key = self.app.wallet.lnworker.add_request(amount, message, self.expiry())
        else:
            addr = self.address or self.app.wallet.get_unused_address()
            if not addr:
                self.app.show_info(_('No address available. Please remove some of your pending requests.'))
                return
            self.address = addr
            req = self.app.wallet.make_payment_request(addr, amount, message, self.expiry())
            self.app.wallet.add_payment_request(req)
            key = addr
        self.clear()
        self.update()
        self.app.show_request(lightning, key)

    def get_card(self, req: Invoice) -> Dict[str, Any]:
        is_lightning = req.is_lightning()
        if not is_lightning:
            assert isinstance(req, OnchainInvoice)
            address = req.get_address()
            key = address
        else:
            assert isinstance(req, LNInvoice)
            key = req.rhash
            address = req.invoice
        amount = req.get_amount_sat()
        description = req.message
        status = self.app.wallet.get_request_status(key)
        status_str = req.get_status_str(status)
        ci = {}
        ci['screen'] = self
        ci['address'] = address
        ci['is_lightning'] = is_lightning
        ci['key'] = key
        ci['amount'] = self.app.format_amount_and_units(amount) if amount else ''
        ci['memo'] = description
        ci['status'] = status
        ci['status_str'] = status_str
        return ci

    def update(self):
        if self.app.wallet is None:
            return
        _list = self.app.wallet.get_sorted_requests()
        _list.reverse()
        requests_container = self.ids.requests_container
        requests_container.data = [self.get_card(item) for item in _list]

    def show_item(self, obj):
        self.app.show_request(obj.is_lightning, obj.key)

    def expiration_dialog(self, obj):
        from .dialogs.choice_dialog import ChoiceDialog
        def callback(c):
            self.app.electrum_config.set_key('request_expiry', c)
        d = ChoiceDialog(_('Expiration date'), pr_expiration_values, self.expiry(), callback)
        d.open()

    def clear_requests_dialog(self):
        requests = self.app.wallet.get_sorted_requests()
        if not requests:
            return
        def callback(c):
            if c:
                self.app.wallet.clear_requests()
                self.update()
        n = len(requests)
        d = Question(_('Delete {} requests?').format(n), callback)
        d.open()



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
