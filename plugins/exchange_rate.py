from PyQt4.QtGui import *
from PyQt4.QtCore import *

import datetime
import inspect
import requests
import sys
import threading
import time
from decimal import Decimal

from electrum.bitcoin import COIN
from electrum.plugins import BasePlugin, hook
from electrum.i18n import _
from electrum.util import ThreadJob
from electrum_gui.qt.util import *
from electrum_gui.qt.amountedit import AmountEdit

class ExchangeBase:
    def get_json(self, site, get_string):
        response = requests.request('GET', 'https://' + site + get_string,
                                    headers={'User-Agent' : 'Electrum'})
        return response.json()

    def name(self):
        return self.__class__.__name__

    def update(self, ccy):
        return {}

    def history_ccys(self):
        return []

    def historical_rates(self, ccy, minstr, maxstr):
        return {}

class BitcoinAverage(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('api.bitcoinaverage.com', '/ticker/global/all')
        return dict([(r, Decimal(jsonresp[r]['last']))
                     for r in json if r != 'timestamp'])

class BitcoinVenezuela(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('api.bitcoinvenezuela.com', '/')
        return dict([(r, Decimal(json['BTC'][r]))
                     for r in json['BTC']])

    def history_ccys(self):
        return ['ARS', 'VEF']

    def historical_rates(self, ccy, minstr, maxstr):
        return self.get_json('api.bitcoinvenezuela.com',
                             "/historical/index.php?coin=BTC")[ccy +'_BTC']

class BTCParalelo(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('btcparalelo.com', '/api/price')
        return {'VEF': Decimal(json['price'])}

class Bitcurex(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('pln.bitcurex.com', '/data/ticker.json')
        pln_price = json['last']
        return {'PLN': Decimal(pln_price)}

class Bitmarket(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('www.bitmarket.pl', '/json/BTCPLN/ticker.json')
        return {'PLN': Decimal(json['last'])}

class BitPay(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('bitpay.com', '/api/rates')
        return dict([(r['code'], Decimal(r['rate'])) for r in json])

class Blockchain(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('blockchain.info', '/ticker')
        return dict([(r, Decimal(json[r]['15m'])) for r in json])

class BTCChina(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('data.btcchina.com', '/data/ticker')
        return {'CNY': Decimal(json['ticker']['last'])}

class CaVirtEx(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('www.cavirtex.com', '/api/CAD/ticker.json')
        return {'CAD': Decimal(json['last'])}

class Coinbase(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('coinbase.com',
                             '/api/v1/currencies/exchange_rates')
        return dict([(r[7:].upper(), Decimal(json[r]))
                     for r in json if r.startswith('btc_to_')])

class CoinDesk(ExchangeBase):
    def update(self, ccy):
        dicts = self.get_json('api.coindesk.com',
                              '/v1/bpi/supported-currencies.json')
        json = self.get_json('api.coindesk.com',
                             '/v1/bpi/currentprice/%s.json' % ccy)
        ccys = [d['currency'] for d in dicts]
        result = dict.fromkeys(ccys)
        result[ccy] = Decimal(json['bpi'][ccy]['rate'])
        return result

    def history_ccys(self):
        return ['USD']

    def historical_rates(self, ccy, minstr, maxstr):
        return self.get_json('api.coindesk.com',
                             "/v1/bpi/historical/close.json?start="
                             + minstr + "&end=" + maxstr)

class itBit(ExchangeBase):
    def update(self, ccy):
        ccys = ['USD', 'EUR', 'SGD']
        json = self.get_json('api.itbit.com', '/v1/markets/XBT%s/ticker' % ccy)
        result = dict.fromkeys(ccys)
        result[ccy] = Decimal(json['lastPrice'])
        return result

class LocalBitcoins(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('localbitcoins.com',
                             '/bitcoinaverage/ticker-all-currencies/')
        return dict([(r, Decimal(json[r]['rates']['last'])) for r in json])

class Winkdex(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('winkdex.com', '/api/v0/price')
        return {'USD': Decimal(json['price'] / 100.0)}

    def history_ccys(self):
        return ['USD']

    def historical_rates(self, ccy, minstr, maxstr):
        json = self.get_json('winkdex.com',
                             "/api/v0/series?start_time=1342915200")
        return json['series'][0]['results']


class Exchanger(ThreadJob):

    def __init__(self, parent):
        self.parent = parent
        self.quotes = {}
        self.timeout = 0

    def get_json(self, site, get_string):
        resp = requests.request('GET', 'https://' + site + get_string,
                                headers={"User-Agent":"Electrum"})
        return resp.json()

    def update_rate(self):
        try:
            rates = self.parent.exchange.update(self.parent.fiat_unit())
        except Exception as e:
            self.parent.print_error(e)
            rates = {}
        self.quotes = rates
        self.parent.set_currencies(rates)
        self.parent.refresh_fields()

    def run(self):
        if self.parent.parent.windows and self.timeout <= time.time():
            self.update_rate()
            self.timeout = time.time() + 150

class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        is_exchange = lambda obj: (inspect.isclass(obj)
                                   and issubclass(obj, ExchangeBase))
        self.exchanges = dict(inspect.getmembers(sys.modules[__name__],
                                                 is_exchange))
        self.network = None
        self.set_exchange(self.config_exchange())
        self.currencies = [self.fiat_unit()]
        self.exchanger = Exchanger(self)
        self.resp_hist = {}
        self.btc_rate = Decimal("0.0")
        self.wallet_tx_list = {}

    def config_exchange(self):
        return self.config.get('use_exchange', 'Blockchain')

    def config_history(self):
        return self.config.get('history_rates', 'unchecked') != 'unchecked'

    def set_exchange(self, name):
        class_ = self.exchanges.get(name) or self.exchanges.values()[0]
        name = class_.__name__
        self.print_error("using exchange", name)
        if self.config_exchange() != name:
            self.config.set_key('use_exchange', name, True)
        self.exchange = class_()

    @hook
    def set_network(self, network):
        if network != self.network:
            if self.network:
                self.network.remove_job(self.exchanger)
            self.network = network
            if network:
                network.add_job(self.exchanger)

    def on_new_window(self, window):
        window.connect(window, SIGNAL("refresh_currencies()"),
                       window.update_status)
        window.fx_fields = {}
        self.add_send_edit(window)
        self.add_receive_edit(window)
        window.update_status()
        self.new_wallets([window.wallet])

    def close(self):
        BasePlugin.close(self)
        self.set_network(None)
        self.exchanger = None
        for window in self.parent.windows:
            window.send_fiat_e.hide()
            window.receive_fiat_e.hide()
            window.update_status()

    def set_currencies(self, currency_options):
        self.currencies = sorted(currency_options)
        for window in self.parent.windows:
            window.emit(SIGNAL("refresh_currencies()"))
            window.emit(SIGNAL("refresh_currencies_combo()"))

    def exchange_rate(self):
        '''Returns None, or the exchange rate as a Decimal'''
        rate = self.exchanger.quotes.get(self.fiat_unit())
        if rate:
            return Decimal(rate)

    @hook
    def get_fiat_balance_text(self, btc_balance, r):
        # return balance as: 1.23 USD
        r[0] = self.create_fiat_balance_text(Decimal(btc_balance) / COIN)

    def get_fiat_price_text(self, r):
        # return BTC price as: 123.45 USD
        r[0] = self.create_fiat_balance_text(1)
        quote = r[0]
        if quote:
            r[0] = "%s"%quote

    @hook
    def get_fiat_status_text(self, btc_balance, r2):
        # return status as:   (1.23 USD)    1 BTC~123.45 USD
        text = ""
        r = {}
        self.get_fiat_price_text(r)
        quote = r.get(0)
        if quote:
            price_text = "1 BTC~%s"%quote
            fiat_currency = quote[-3:]
            btc_price = self.btc_rate
            fiat_balance = Decimal(btc_price) * Decimal(btc_balance) / COIN
            balance_text = "(%.2f %s)" % (fiat_balance,fiat_currency)
            text = "  " + balance_text + "     " + price_text + " "
        r2[0] = text

    def create_fiat_balance_text(self, btc_balance):
        cur_rate = self.exchange_rate()
        if cur_rate is None:
            quote_text = ""
        else:
            quote_balance = btc_balance * Decimal(cur_rate)
            self.btc_rate = cur_rate
            quote_text = "%.2f %s" % (quote_balance, self.fiat_unit())
        return quote_text

    @hook
    def load_wallet(self, wallet, window):
        self.new_wallets([wallet])

    def new_wallets(self, wallets):
        if wallets:
            # For mid-session plugin loads
            self.set_network(wallets[0].network)
            for wallet in wallets:
                if wallet not in self.wallet_tx_list:
                    self.wallet_tx_list[wallet] = None
            self.get_historical_rates()

    def get_historical_rates(self):
        '''Request historic rates for all wallets for which they haven't yet
        been requested
        '''
        if not self.config_history():
            return
        all_txs = {}
        new = False
        for wallet in self.wallet_tx_list:
            if self.wallet_tx_list[wallet] is None:
                new = True
                tx_list = {}
                for item in wallet.get_history(wallet.storage.get("current_account", None)):
                    tx_hash, conf, value, timestamp, balance = item
                    tx_list[tx_hash] = {'value': value, 'timestamp': timestamp }
                    # FIXME: not robust to request failure
                self.wallet_tx_list[wallet] = tx_list
            all_txs.update(self.wallet_tx_list[wallet])
        if new:
            self.print_error("requesting historical FX rates")
            t = threading.Thread(target=self.request_historical_rates,
                                 args=(all_txs,))
            t.setDaemon(True)
            t.start()

    def request_historical_rates(self, tx_list):
        try:
            mintimestr = datetime.datetime.fromtimestamp(int(min(tx_list.items(), key=lambda x: x[1]['timestamp'])[1]['timestamp'])).strftime('%Y-%m-%d')
            maxtimestr = datetime.datetime.now().strftime('%Y-%m-%d')
            self.resp_hist = self.exchange.historical_rates(
                self.fiat_unit(), mintimestr, maxtimestr)
        except Exception:
            return
        for window in self.parent.windows:
            window.need_update.set()

    def requires_settings(self):
        return True

    @hook
    def history_tab_update(self, window):
        if self.config.get('history_rates') != "checked":
            return
        if not self.resp_hist:
            return
        wallet = window.wallet
        tx_list = self.wallet_tx_list.get(wallet)
        if not wallet or not tx_list:
            return
        window.is_edit = True
        window.history_list.setColumnCount(7)
        window.history_list.setHeaderLabels([ '', '', _('Date'), _('Description') , _('Amount'), _('Balance'), _('Fiat Amount')] )
        root = window.history_list.invisibleRootItem()
        childcount = root.childCount()
        exchange = self.exchange.name()
        for i in range(childcount):
            item = root.child(i)
            try:
                tx_info = tx_list[str(item.data(0, Qt.UserRole).toPyObject())]
            except Exception:
                newtx = wallet.get_history()
                v = newtx[[x[0] for x in newtx].index(str(item.data(0, Qt.UserRole).toPyObject()))][2]
                tx_info = {'timestamp':int(time.time()), 'value': v}
                pass
            tx_time = int(tx_info['timestamp'])
            tx_value = Decimal(str(tx_info['value'])) / COIN
            if exchange == "CoinDesk":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                try:
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(self.resp_hist['bpi'][tx_time_str]), "USD")
                except KeyError:
                    tx_fiat_val = "%.2f %s" % (self.btc_rate * Decimal(str(tx_info['value']))/COIN , "USD")
            elif exchange == "Winkdex":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d') + "T16:00:00-04:00"
                try:
                    tx_rate = self.resp_hist[[x['timestamp'] for x in self.resp_hist].index(tx_time_str)]['price']
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(tx_rate)/Decimal("100.0"), "USD")
                except ValueError:
                    tx_fiat_val = "%.2f %s" % (self.btc_rate * Decimal(tx_info['value'])/COIN , "USD")
                except KeyError:
                    tx_fiat_val = _("No data")
            elif exchange == "BitcoinVenezuela":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                try:
                    num = self.resp_hist[tx_time_str].replace(',','')
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(num), self.fiat_unit())
                except KeyError:
                    tx_fiat_val = _("No data")

            tx_fiat_val = " "*(12-len(tx_fiat_val)) + tx_fiat_val
            item.setText(6, tx_fiat_val)
            item.setFont(6, QFont(MONOSPACE_FONT))
            if Decimal(str(tx_info['value'])) < 0:
                item.setForeground(6, QBrush(QColor("#BC1E1E")))

            # We autosize but in some cases QT doesn't handle that
            # properly for new columns it seems
            window.history_list.setColumnWidth(6, 120)
            window.is_edit = False


    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        d = QDialog()
        d.setWindowTitle("Settings")
        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('Exchange rate API: ')), 0, 0)
        layout.addWidget(QLabel(_('Currency: ')), 1, 0)
        layout.addWidget(QLabel(_('History Rates: ')), 2, 0)
        combo = QComboBox()
        combo_ex = QComboBox()
        combo_ex.addItems(sorted(self.exchanges.keys()))
        combo_ex.setCurrentIndex(combo_ex.findText(self.config_exchange()))

        hist_checkbox = QCheckBox()
        ok_button = QPushButton(_("OK"))

        def hist_checkbox_update():
            hist_checkbox.setEnabled(self.fiat_unit() in
                                     self.exchange.history_ccys())
            hist_checkbox.setChecked(self.config_history())

        def on_change(x):
            try:
                ccy = str(self.currencies[x])
            except Exception:
                return
            if ccy != self.fiat_unit():
                self.config.set_key('currency', ccy, True)
                hist_checkbox_update()
                for window in self.parent.windows:
                    window.update_status()

        def on_change_ex(idx):
            exchange = str(combo_ex.currentText())
            if exchange != self.exchange.name():
                self.set_exchange(exchange)
                self.currencies = []
                combo.clear()
                self.exchanger.timeout = 0
                hist_checkbox_update()
                set_currencies(combo)
                for window in self.parent.windows:
                    window.update_status()

        def on_change_hist(checked):
            if checked:
                self.config.set_key('history_rates', 'checked')
                self.get_historical_rates()
            else:
                self.config.set_key('history_rates', 'unchecked')
                for window in self.parent.windows:
                    window.history_list.setHeaderLabels( [ '', '', _('Date'), _('Description') , _('Amount'), _('Balance')] )
                    window.history_list.setColumnCount(6)

        def set_currencies(combo):
            try:
                combo.blockSignals(True)
                current_currency = self.fiat_unit()
                combo.clear()
            except Exception:
                return
            combo.addItems(self.currencies)
            try:
                index = self.currencies.index(current_currency)
            except Exception:
                index = 0
            combo.blockSignals(False)
            combo.setCurrentIndex(index)

        def ok_clicked():
            if self.exchange in ["CoinDesk", "itBit"]:
                self.timeout = 0
            d.accept();

        hist_checkbox_update()
        set_currencies(combo)
        combo.currentIndexChanged.connect(on_change)
        combo_ex.currentIndexChanged.connect(on_change_ex)
        hist_checkbox.stateChanged.connect(on_change_hist)
        for window in self.parent.windows:
            combo.connect(window, SIGNAL('refresh_currencies_combo()'), lambda: set_currencies(combo))
        combo_ex.connect(d, SIGNAL('refresh_exchanges_combo()'), lambda: set_exchanges(combo_ex))
        ok_button.clicked.connect(lambda: ok_clicked())
        layout.addWidget(combo,1,1)
        layout.addWidget(combo_ex,0,1)
        layout.addWidget(hist_checkbox,2,1)
        layout.addWidget(ok_button,3,1)

        if d.exec_():
            return True
        else:
            return False

    def fiat_unit(self):
        return self.config.get("currency", "EUR")

    def refresh_fields(self):
        '''Update the display at the new rate'''
        for window in self.parent.windows:
            for field in window.fx_fields.values():
                field.textEdited.emit(field.text())

    def add_send_edit(self, window):
        window.send_fiat_e = AmountEdit(self.fiat_unit)
        self.connect_fields(window, True)
        window.send_grid.addWidget(window.send_fiat_e, 4, 3, Qt.AlignHCenter)
        window.amount_e.frozen.connect(lambda: window.send_fiat_e.setFrozen(window.amount_e.isReadOnly()))

    def add_receive_edit(self, window):
        window.receive_fiat_e = AmountEdit(self.fiat_unit)
        self.connect_fields(window, False)
        window.receive_grid.addWidget(window.receive_fiat_e, 2, 3, Qt.AlignHCenter)

    def connect_fields(self, window, send):
        if send:
            btc_e, fiat_e, fee_e = (window.amount_e, window.send_fiat_e,
                                    window.fee_e)
        else:
            btc_e, fiat_e, fee_e = (window.receive_amount_e,
                                    window.receive_fiat_e, None)
        def fiat_changed():
            fiat_e.setStyleSheet(BLACK_FG)
            window.fx_fields[(fiat_e, btc_e)] = fiat_e
            try:
                fiat_amount = Decimal(str(fiat_e.text()))
            except:
                btc_e.setText("")
                if fee_e: fee_e.setText("")
                return
            exchange_rate = self.exchange_rate()
            if exchange_rate is not None:
                btc_amount = fiat_amount/exchange_rate
                btc_e.setAmount(int(btc_amount*Decimal(COIN)))
                btc_e.setStyleSheet(BLUE_FG)
                if fee_e: window.update_fee()
        fiat_e.textEdited.connect(fiat_changed)
        def btc_changed():
            btc_e.setStyleSheet(BLACK_FG)
            window.fx_fields[(fiat_e, btc_e)] = btc_e
            btc_amount = btc_e.get_amount()
            rate = self.exchange_rate()
            if rate is None or btc_amount is None:
                fiat_e.setText("")
            else:
                fiat_amount = rate * Decimal(btc_amount) / Decimal(COIN)
                pos = fiat_e.cursorPosition()
                fiat_e.setText("%.2f"%fiat_amount)
                fiat_e.setCursorPosition(pos)
                fiat_e.setStyleSheet(BLUE_FG)
        btc_e.textEdited.connect(btc_changed)
        window.fx_fields[(fiat_e, btc_e)] = btc_e

    @hook
    def do_clear(self, window):
        window.send_fiat_e.setText('')
