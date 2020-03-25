import asyncio
from weakref import ref
from decimal import Decimal
import re
import threading
import traceback, sys
import copy
from typing import TYPE_CHECKING, List, Optional

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
from electrum.util import PR_TYPE_ONCHAIN, PR_TYPE_ONCHAIN_ASSET, PR_TYPE_LN, PR_DEFAULT_EXPIRATION_WHEN_CREATING
from electrum import bitcoin, constants
from electrum.transaction import Transaction, tx_from_any, PartialTransaction, PartialTxOutput
from electrum.util import (parse_URI, InvalidBitcoinURI, PR_PAID, PR_UNKNOWN, PR_EXPIRED,
                           PR_INFLIGHT, TxMinedInfo, get_request_status, pr_expiration_values,
                           maybe_extract_bolt11_invoice)
from electrum.plugin import run_hook
from electrum.wallet import InternalAddressCorruption
from electrum import simple_config
from electrum.lnaddr import lndecode
from electrum.lnutil import RECEIVED, SENT, PaymentFailure

from .dialogs.question import Question
from .dialogs.lightning_open_channel import LightningOpenChannelDialog

from electrum.gui.kivy.i18n import _
from electrum.asset_synchronizer import AssetItem
from .combobox import ComboBox
if TYPE_CHECKING:
    from electrum.gui.kivy.main_window import ElectrumWindow
    from electrum.paymentrequest import PaymentRequest


class HistoryRecycleView(RecycleView):
    pass

class AssetHistoryRecycleView(RecycleView):
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
Builder.load_file('electrum/gui/kivy/uix/ui_screens/assethistory.kv')

class AssetKey():
    def __init__(self, asset, address):
        self.asset = asset
        self.address = address

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

class AssetHistoryScreen(CScreen):

    tab = ObjectProperty(None)
    kvname = 'assethistory'
    cards = {}

    def __init__(self, **kwargs):
        self.ra_dialog = None
        super(AssetHistoryScreen, self).__init__(**kwargs)

    def show_item(self, obj):
        key = obj.key
        tx_item = self.assethistory.get(key)
        if tx_item.get('lightning') and tx_item['type'] == 'payment':
            self.app.lightning_tx_dialog(tx_item)
            return

    def get_card(self, tx_item): #tx_hash, tx_mined_status, value, balance):
        is_lightning = tx_item.get('lightning', False)
        timestamp = tx_item['timestamp']
        key = tx_item.get('txid') or tx_item['payment_hash']
        asset_guid = ''
        asset_address = ''
        transfer_type = ''
        symbol = ''
        precision = '8'
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
            if 'asset' in tx_item:
                asset_guid = tx_item['asset']
                asset_address = tx_item['address']
                transfer_type = tx_item['transfer_type']
                symbol = tx_item['symbol']
                precision = tx_item['precision']
        ri = {}
        ri['screen'] = self
        ri['key'] = key
        ri['icon'] = icon
        ri['date'] = status_str
        ri['message'] = message
        ri['asset'] = asset_guid
        ri['address'] = asset_address
        ri['transfer_type'] = transfer_type
        ri['symbol'] = symbol
        ri['precision'] = precision
        value = tx_item['value'].value
        if value is not None:
            ri['is_mine'] = value <= 0
            ri['amount'] = self.app.format_amount(value, is_diff = True, decimal=precision)
            if 'fiat_value' in tx_item:
                ri['quote_text'] = str(tx_item['fiat_value'])
        return ri

    def update(self, see_all=False):
        wallet = self.app.wallet
        if wallet is None:
            return
        self.assethistory = wallet.get_full_assethistory(self.app.fx)
        assethistory = reversed(self.assethistory.values())
        assethistory_card = self.ids.assethistory_container
        assethistory_card.data = [self.get_card(item) for item in assethistory]


class SendScreen(CScreen):

    kvname = 'send'
    payment_request = None  # type: Optional[PaymentRequest]
    payment_request_queued = None  # type: Optional[str]
    parsed_URI = None
    asset_e = None

    def set_URI(self, text: str):
        if not self.app.wallet:
            self.payment_request_queued = text
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
        self.asset = uri.get('asset', '')
        precision = 8
        asset_symbol = None
        if amount and self.asset is not '':
            assetObj = self.app.wallet.asset_synchronizer.get_asset(self.asset)
            if assetObj is not None:
                self.amount = self.app.format_amount_and_units(None, asset_amount=amount, asset_symbol=assetObj.symbol, asset_precision=assetObj.precision)
            else:
                self.amount = self.app.format_amount_and_units(amount)
        else:
            self.amount = self.app.format_amount_and_units(amount) if amount else ''
        self.payment_request = None
        self.is_lightning = False

    def set_ln_invoice(self, invoice):
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

    def get_asset(self, asset):
        balance = self.app.format_amount(asset.balance, is_diff=False, decimal=asset.precision)
        if asset.asset is 0:
            return [AssetKey(0, ''), balance + ' SYS']
        else:
            return [AssetKey(asset.asset, asset.address), asset.address + ' (' + str(asset.asset) + ':' + asset.symbol + ') ' + balance]
    
    def update(self):
        if self.app.wallet is None:
            return
        if self.payment_request_queued:
            self.set_URI(self.payment_request_queued)
            self.payment_request_queued = None
        _list = self.app.wallet.get_invoices()
        _list.reverse()
        payments_container = self.ids.payments_container
        payments_container.data = [self.get_card(item) for item in _list]

        self.assets = copy.deepcopy(self.app.wallet.asset_synchronizer.get_assets())
        c, u, x = self.app.wallet.get_balance()
        self.assets.insert(0, AssetItem(asset=0,address='',
                    symbol='',
                    balance=c,
                    precision=self.app.decimal_point()))
        self.asset_e = self.ids.asset_e
        self.asset_e.items = [self.get_asset(asset) for asset in self.assets]

    def show_item(self, obj):
        self.app.show_invoice(obj.is_lightning, obj.key)

    def get_card(self, item):
        invoice_type = item['type']
        status, status_str = get_request_status(item) # convert to str
        if invoice_type == PR_TYPE_LN:
            key = item['rhash']
            log = self.app.wallet.lnworker.logs.get(key)
            if item['status'] == PR_INFLIGHT and log:
                status_str += '... (%d)'%len(log)
        elif invoice_type == PR_TYPE_ONCHAIN or invoice_type == PR_TYPE_ONCHAIN_ASSET:
            key = item['id']
        else:
            raise Exception('unknown invoice type')
        amount = '0'
        if item['amount'] and 'asset' in item and item['asset'] is not '':
            asset = self.app.wallet.asset_synchronizer.get_asset(item['asset'])
            if asset is not None:
                amount = self.app.format_amount_and_units(None, asset_amount=item['amount'], asset_symbol=asset.symbol, asset_precision=asset.precision)
            else:
                amount = self.app.format_amount_and_units(item['amount'])
        else:
            amount = self.app.format_amount_and_units(item['amount'] or 0)
        return {
            'is_lightning': invoice_type == PR_TYPE_LN,
            'asset': item['asset'] if 'asset' in item else '',
            'asset_address': item['asset_address'] if 'asset_address' in item else '',
            'is_bip70': 'bip70' in item,
            'screen': self,
            'status': status,
            'status_str': status_str,
            'key': key,
            'memo': item['message'],
            'amount': amount,
        }

    def do_clear(self):
        self.amount = ''
        self.asset = ''
        self.message = ''
        self.address = ''
        self.payment_request = None
        self.is_lightning = False
        self.is_bip70 = False
        self.parsed_URI = None

    def set_request(self, pr: 'PaymentRequest'):
        self.address = pr.get_requestor()
        amount = pr.get_amount()
        asset_guid = pr.get_asset_guid()
        if amount and asset_guid is not None and asset_guid is not '':
            asset = self.app.wallet.asset_synchronizer.get_asset(asset_guid)
            if asset is not None:
                self.amount = self.app.format_amount_and_units(None, asset_amount=amount, asset_symbol=asset.symbol, asset_precision=asset.precision)
            else:
                self.amount = self.app.format_amount_and_units(amount)
        else:
            self.amount = self.app.format_amount_and_units(amount) if amount else ''              
        self.message = pr.get_memo()
        
        #if asset is not None:
        #    self.selected_asset = AssetKey(asset=asset_guid, address= None)
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
            self.app.show_error(_('Recipient not specified.') + ' ' + _('Please scan a Syscoin address or a payment request'))
            return
        if not self.amount:
            self.app.show_error(_('Please enter an amount'))
            return
        asset = None
        precision = 8
        if self.asset_e.key is not None and self.asset_e.key.asset != 0:
            asset = self.app.wallet.asset_synchronizer.get_asset(self.asset_e.key.asset, self.asset_e.key.address)
            precision = asset.precision
        try:
            amount = self.app.get_amount(self.amount, decimal=precision)
        except:
            self.app.show_error(_('Invalid amount') + ':\n' + self.amount)
            return
        message = self.message
        if self.is_lightning:
            return self.app.wallet.lnworker.parse_bech32_invoice(address)
        else:  # on-chain
            if self.payment_request:
                outputs = self.payment_request.get_outputs()
            else:
                if not bitcoin.is_address(address):
                    self.app.show_error(_('invalid syscoin address') + ':\n' + address)
                    return
                outputs = [PartialTxOutput.from_address_and_value(address, amount)]
            return self.app.wallet.create_invoice(asset, outputs, message, self.payment_request, self.parsed_URI)

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
        if invoice['type'] == PR_TYPE_LN:
            self._do_pay_lightning(invoice)
            return
        elif invoice['type'] == PR_TYPE_ONCHAIN or invoice['type'] == PR_TYPE_ONCHAIN_ASSET:
            do_pay = lambda rbf: self._do_pay_onchain(invoice, rbf)
            if self.app.electrum_config.get('use_rbf'):
                d = Question(_('Should this transaction be replaceable?'), do_pay)
                d.open()
            else:
                do_pay(False)
        else:
            raise Exception('unknown invoice type')

    def _do_pay_lightning(self, invoice):
        attempts = 10
        threading.Thread(target=self.app.wallet.lnworker.pay, args=(invoice['invoice'], invoice['amount'], attempts)).start()

    def _do_pay_onchain(self, invoice, rbf):
        # make unsigned transaction
        outputs = invoice['outputs']  # type: List[PartialTxOutput]
        amount = sum(map(lambda x: x.value, outputs))
        coins = self.app.wallet.get_spendable_coins(None)
        asset_symbol = None
        asset_precision = None
        from_address = None
        asset_guid = None
        if 'asset' in invoice:
            asset_guid = invoice['asset']
            from_address = invoice['asset_address'] or None
        if asset_guid is not None:
            if from_address is None:
                assets = self.app.wallet.asset_synchronizer.get_asset(asset_guid, all_allocations = True)
                for asset in assets:
                    asset_precision = asset.precision
                    asset_symbol = asset.symbol
                    if asset.balance >= amount:
                        from_address = asset.address
                        break
            else:
                asset = self.app.wallet.asset_synchronizer.get_asset(asset_guid, asset_address=from_address)
                if asset is not None:
                    asset_precision = asset.precision
                    asset_symbol = asset.symbol

            if from_address is None or asset_precision is None:
                self.app.show_error(_("Not enough funds in asset"))
                return
        try:
            tx = self.app.wallet.make_unsigned_transaction(coins=coins, outputs=outputs, asset_guid=asset_guid, asset_address=from_address)
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


        msg = [
            _("Amount to be sent") + ": " + self.app.format_amount_and_units(tx.output_value(), amount, asset_symbol, asset_precision),
            _("Mining fee") + ": " + self.app.format_amount_and_units(fee),
        ]
        x_fee = run_hook('get_tx_extra_fee', self.app.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            msg.append(_("Additional fees") + ": " + self.app.format_amount_and_units(x_fee_amount))

        feerate_warning = constants.net.FEERATE_WARNING_HIGH_FEE
        if fee > feerate_warning * tx.estimated_size() / 1000:
            msg.append(_('Warning') + ': ' + _("The fee for this transaction seems unusually high."))
        msg.append(_("Enter your PIN code to proceed"))
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
                    key = req['key']
                    self.app.wallet.delete_invoice(key)
                self.update()
        n = len(invoices)
        d = Question(_(f'Delete {n} invoices?'), callback)
        d.open()

class ReceiveScreen(CScreen):

    kvname = 'receive'
    asset_e = None

    def __init__(self, **kwargs):
        super(ReceiveScreen, self).__init__(**kwargs)
        Clock.schedule_interval(lambda dt: self.update(), 5)
        
    def expiry(self):
        return self.app.electrum_config.get('request_expiry', PR_DEFAULT_EXPIRATION_WHEN_CREATING)

    def clear(self):
        self.address = ''
        self.asset = ''
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
        precision = 8
        asset_guid = None
        if self.asset_e.key is not None and self.asset_e.key.asset != 0:
            asset_guid = self.asset_e.key.asset
        if asset_guid is not None:
            asset = self.app.wallet.asset_synchronizer.get_asset(asset_guid)
            if asset is not None:
                precision = asset.precision      
        return create_bip21_uri(asset_guid, self.address, amount, self.message, decimal_point=precision)

    def do_copy(self):
        uri = self.get_URI()
        self.app._clipboard.copy(uri)
        self.app.show_info(_('Request copied to clipboard'))

    def new_request(self, lightning):
        asset_guid = None
        precision = 8
        if self.asset_e.key is not None and self.asset_e.key.asset != 0:
            asset = self.app.wallet.asset_synchronizer.get_asset(self.asset_e.key.asset)
            if asset is not None:
                asset_guid = asset.asset
                precision = asset.precision
        amount = self.amount
        amount = self.app.get_amount(amount, decimal=precision) if amount else 0
        message = self.message
        if lightning:
            key = self.app.wallet.lnworker.add_request(amount, message, self.expiry())
        else:
            addr = self.address or self.app.wallet.get_unused_address()
            if not addr:
                self.app.show_info(_('No address available. Please remove some of your pending requests.'))
                return
            self.address = addr
            req = self.app.wallet.make_payment_request(asset_guid, addr, amount, message, self.expiry())
            self.app.wallet.add_payment_request(req)
            key = addr
        self.clear()
        self.update()
        self.app.show_request(lightning, key)

    def get_card(self, req):
        is_lightning = req.get('type') == PR_TYPE_LN
        if not is_lightning:
            address = req['address']
            key = address
        else:
            key = req['rhash']
            address = req['invoice']
        amount = req.get('amount')
        amountci = ''
        if amount and req.get('type') == PR_TYPE_ONCHAIN_ASSET:
            asset = self.app.wallet.asset_synchronizer.get_asset(req.get('asset'))
            if asset is not None:
                amountci = self.app.format_amount_and_units(None, asset_amount=amount, asset_symbol=asset.symbol, asset_precision=asset.precision)
            else:
                amountci = self.app.format_amount_and_units(amount)
        else:
            amountci = self.app.format_amount_and_units(amount) if amount else ''               
        description = req.get('message') or req.get('memo', '')  # TODO: a db upgrade would be needed to simplify that.
        status, status_str = get_request_status(req)
        ci = {}
        ci['screen'] = self
        ci['address'] = address
        ci['is_lightning'] = is_lightning
        ci['key'] = key
        ci['amount'] = amountci
        ci['memo'] = description
        ci['status'] = status
        ci['status_str'] = status_str
        ci['asset']: req.get('asset')
        return ci

    def get_asset(self, asset):
        balance = self.app.format_amount(asset.balance, is_diff=False, decimal=asset.precision)
        if asset.asset is 0:
            return [AssetKey(0, ''), balance + ' SYS']
        else:
            return [AssetKey(asset.asset, asset.address), asset.address + ' (' + str(asset.asset) + ':' + asset.symbol + ') ' + balance]
    
    def update(self):
        if self.app.wallet is None:
            return
        _list = self.app.wallet.get_sorted_requests()
        _list.reverse()
        requests_container = self.ids.requests_container
        requests_container.data = [self.get_card(item) for item in _list]

        self.assets = copy.deepcopy(self.app.wallet.asset_synchronizer.get_assets())
        c, u, x = self.app.wallet.get_balance()
        self.assets.insert(0, AssetItem(asset=0,address='',
                    symbol='',
                    balance=c,
                    precision=self.app.decimal_point()))
        self.asset_e = self.ids.asset_e
        self.asset_e.items = [self.get_asset(asset) for asset in self.assets]

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
                for req in requests:
                    key = req.get('rhash') or req['address']
                    self.app.wallet.delete_request(key)
                self.update()
        n = len(requests)
        d = Question(_(f'Delete {n} requests?'), callback)
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
