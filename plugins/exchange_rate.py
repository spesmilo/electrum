from PyQt4.QtGui import *
from PyQt4.QtCore import *

from datetime import datetime
import inspect
import requests
import sys
from threading import Thread
import time
import traceback
from decimal import Decimal

from electrum.bitcoin import COIN
from electrum.plugins import BasePlugin, hook
from electrum.i18n import _
from electrum.util import print_error, ThreadJob, timestamp_to_datetime
from electrum.util import format_satoshis
from electrum_gui.qt.util import *
from electrum_gui.qt.amountedit import AmountEdit

class ExchangeBase:
    def __init__(self, sig):
        self.history = {}
        self.quotes = {}
        self.sig = sig

    def get_json(self, site, get_string):
        response = requests.request('GET', 'https://' + site + get_string,
                                    headers={'User-Agent' : 'Electrum'})
        return response.json()

    def print_error(self, *msg):
        print_error("[%s]" % self.name(), *msg)

    def name(self):
        return self.__class__.__name__

    def update(self, ccy):
        self.quotes = self.get_rates(ccy)
        self.sig.emit(SIGNAL('fx_quotes'))
        return self.quotes

    def history_ccys(self):
        return []

    def set_history(self, ccy, history):
        '''History is a map of "%Y-%m-%d" strings to values'''
        self.history[ccy] = history
        self.sig.emit(SIGNAL("fx_history"))

    def get_historical_rates(self, ccy):
        result = self.history.get(ccy)
        if not result and ccy in self.history_ccys():
            self.print_error("requesting historical rates for", ccy)
            t = Thread(target=self.historical_rates, args=(ccy,))
            t.setDaemon(True)
            t.start()
        return result

    def historical_rate(self, ccy, d_t):
        return self.history.get(ccy, {}).get(d_t.strftime('%Y-%m-%d'))


class BitcoinAverage(ExchangeBase):
    def update(self, ccy):
        json = self.get_json('api.bitcoinaverage.com', '/ticker/global/all')
        return dict([(r, Decimal(jsonresp[r]['last']))
                     for r in json if r != 'timestamp'])

class BitcoinVenezuela(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('api.bitcoinvenezuela.com', '/')
        return dict([(r, Decimal(json['BTC'][r]))
                     for r in json['BTC']])

    def history_ccys(self):
        return ['ARS', 'EUR', 'USD', 'VEF']

    def historical_rates(self, ccy):
        return self.get_json('api.bitcoinvenezuela.com',
                             "/historical/index.php?coin=BTC")[ccy +'_BTC']

class BTCParalelo(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('btcparalelo.com', '/api/price')
        return {'VEF': Decimal(json['price'])}

class Bitcurex(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('pln.bitcurex.com', '/data/ticker.json')
        pln_price = json['last']
        return {'PLN': Decimal(pln_price)}

class Bitmarket(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('www.bitmarket.pl', '/json/BTCPLN/ticker.json')
        return {'PLN': Decimal(json['last'])}

class BitPay(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('bitpay.com', '/api/rates')
        return dict([(r['code'], Decimal(r['rate'])) for r in json])

class Blockchain(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('blockchain.info', '/ticker')
        return dict([(r, Decimal(json[r]['15m'])) for r in json])

class BTCChina(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('data.btcchina.com', '/data/ticker')
        return {'CNY': Decimal(json['ticker']['last'])}

class CaVirtEx(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('www.cavirtex.com', '/api/CAD/ticker.json')
        return {'CAD': Decimal(json['last'])}

class Coinbase(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('coinbase.com',
                             '/api/v1/currencies/exchange_rates')
        return dict([(r[7:].upper(), Decimal(json[r]))
                     for r in json if r.startswith('btc_to_')])

class CoinDesk(ExchangeBase):
    def get_rates(self, ccy):
        dicts = self.get_json('api.coindesk.com',
                              '/v1/bpi/supported-currencies.json')
        json = self.get_json('api.coindesk.com',
                             '/v1/bpi/currentprice/%s.json' % ccy)
        ccys = [d['currency'] for d in dicts]
        result = dict.fromkeys(ccys)
        result[ccy] = Decimal(json['bpi'][ccy]['rate'])
        return result

    def history_starts(self):
        return { 'USD': '2012-11-30' }

    def history_ccys(self):
        return self.history_starts().keys()

    def historical_rates(self, ccy):
        start = self.history_starts()[ccy]
        end = datetime.today().strftime('%Y-%m-%d')
        # Note ?currency and ?index don't work as documented.  Sigh.
        query = ('/v1/bpi/historical/close.json?start=%s&end=%s'
                 % (start, end))
        json = self.get_json('api.coindesk.com', query)
        self.set_history(ccy, json['bpi'])

class itBit(ExchangeBase):
    def get_rates(self, ccy):
        ccys = ['USD', 'EUR', 'SGD']
        json = self.get_json('api.itbit.com', '/v1/markets/XBT%s/ticker' % ccy)
        result = dict.fromkeys(ccys)
        result[ccy] = Decimal(json['lastPrice'])
        return result

class LocalBitcoins(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('localbitcoins.com',
                             '/bitcoinaverage/ticker-all-currencies/')
        return dict([(r, Decimal(json[r]['rates']['last'])) for r in json])

class Winkdex(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('winkdex.com', '/api/v0/price')
        return {'USD': Decimal(json['price'] / 100.0)}

    def history_ccys(self):
        return ['USD']

    def historical_rates(self, ccy):
        json = self.get_json('winkdex.com',
                             "/api/v0/series?start_time=1342915200")
        history = json['series'][0]['results']
        self.set_history(ccy, dict([(h['timestamp'][:10], h['price'] / 100.0)
                                    for h in history]))


class Plugin(BasePlugin, ThreadJob):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        # Signal object first
        self.sig = QObject()
        self.sig.connect(self.sig, SIGNAL('fx_quotes'), self.on_fx_quotes)
        self.sig.connect(self.sig, SIGNAL('fx_history'), self.on_fx_history)
        self.ccy = self.config_ccy()
        self.history_used_spot = False
        self.ccy_combo = None
        self.hist_checkbox = None

        is_exchange = lambda obj: (inspect.isclass(obj)
                                   and issubclass(obj, ExchangeBase))
        self.exchanges = dict(inspect.getmembers(sys.modules[__name__],
                                                 is_exchange))
        self.set_exchange(self.config_exchange())
        # FIXME: kill this
        self.btc_rate = Decimal("0.0")

    def thread_jobs(self):
        return [self]

    def run(self):
        # This runs from the network thread which catches exceptions
        if self.parent.windows and self.timeout <= time.time():
            self.timeout = time.time() + 150
            rates = self.exchange.update(self.ccy)
            self.refresh_fields()

    def config_ccy(self):
        '''Use when dynamic fetching is needed'''
        return self.config.get("currency", "EUR")

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
        self.exchange = class_(self.sig)
        # A new exchange means new fx quotes, initially empty.  Force
        # a quote refresh
        self.timeout = 0
        self.get_historical_rates()
        self.on_fx_quotes()

    def update_status_bars(self):
        '''Update status bar fiat balance in all windows'''
        for window in self.parent.windows:
            window.update_status()

    def on_new_window(self, window):
        window.fx_fields = {}
        self.add_send_edit(window)
        self.add_receive_edit(window)
        window.update_status()

    def on_fx_history(self):
        '''Called when historical fx quotes are updated'''
        for window in self.parent.windows:
            window.update_history_tab()

    def on_fx_quotes(self):
        '''Called when fresh spot fx quotes come in'''
        self.update_status_bars()
        self.populate_ccy_combo()
        # History tab needs updating if it used spot
        if self.history_used_spot:
            self.on_fx_history()

    def on_ccy_combo_change(self):
        '''Called when the chosen currency changes'''
        ccy = str(self.ccy_combo.currentText())
        if ccy and ccy != self.ccy:
            print "Setting:", ccy
            self.ccy = ccy
            self.config.set_key('currency', ccy, True)
            self.update_status_bars()
            self.get_historical_rates() # Because self.ccy changes
            self.hist_checkbox_update()

    def hist_checkbox_update(self):
        if self.hist_checkbox:
            self.hist_checkbox.setEnabled(self.ccy in self.exchange.history_ccys())
            self.hist_checkbox.setChecked(self.config_history())

    def populate_ccy_combo(self):
        # There should be at most one instance of the settings dialog
        combo = self.ccy_combo
        # NOTE: bool(combo) is False if it is empty.  Nuts.
        if combo is not None:
            combo.blockSignals(True)
            combo.clear()
            combo.addItems(sorted(self.exchange.quotes.keys()))
            combo.blockSignals(False)
            combo.setCurrentIndex(combo.findText(self.ccy))

    def close(self):
        BasePlugin.close(self)
        for window in self.parent.windows:
            window.send_fiat_e.hide()
            window.receive_fiat_e.hide()
            window.update_history_tab()
            window.update_status()

    def exchange_rate(self):
        '''Returns None, or the exchange rate as a Decimal'''
        rate = self.exchange.quotes.get(self.ccy)
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
            quote_text = "%.2f %s" % (quote_balance, self.ccy)
        return quote_text

    def get_historical_rates(self):
        if self.config_history():
            self.exchange.get_historical_rates(self.ccy)

    def requires_settings(self):
        return True

    def historical_value_str(self, ccy, satoshis, d_t):
        rate = self.exchange.historical_rate(ccy, d_t)
        # Frequently there is no rate for today, until tomorrow :)
        # Use spot quotes in that case
        if rate is None and d_t.date() == datetime.today().date():
            rate = self.exchange.quotes.get(ccy)
            if rate is not None:
                self.history_used_spot = True
        if rate:
             value = round(Decimal(satoshis) / COIN * Decimal(rate), 2)
             return " ".join(["{:,.2f}".format(value), ccy])
        return _("No data")

    @hook
    def history_tab_headers(self, headers):
        headers.extend([_('Fiat Amount'), _('Fiat Balance')])

    @hook
    def history_tab_update(self):
        self.history_used_spot = False

    @hook
    def history_tab_update(self, tx, entry):
        if not self.config_history():
            return
        tx_hash, conf, value, timestamp, balance = tx
        date = timestamp_to_datetime(timestamp)
        if not date:
            date = timestamp_to_datetime(0)
        for amount in [value, balance]:
            text = self.historical_value_str(self.ccy, amount, date)
            entry.append("%16s" % text)

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        d = QDialog()
        d.setWindowTitle("Settings")
        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('Exchange rate API: ')), 0, 0)
        layout.addWidget(QLabel(_('Currency: ')), 1, 0)
        layout.addWidget(QLabel(_('History Rates: ')), 2, 0)

        # Currency list
        self.ccy_combo = QComboBox()
        self.ccy_combo.currentIndexChanged.connect(self.on_ccy_combo_change)
        self.populate_ccy_combo()

        def on_change_ex(idx):
            exchange = str(combo_ex.currentText())
            if exchange != self.exchange.name():
                self.set_exchange(exchange)
                self.hist_checkbox_update()

        def on_change_hist(checked):
            if checked:
                self.config.set_key('history_rates', 'checked')
                self.get_historical_rates()
            else:
                self.config.set_key('history_rates', 'unchecked')

        def ok_clicked():
            if self.exchange in ["CoinDesk", "itBit"]:
                self.timeout = 0
            d.accept();

        combo_ex = QComboBox()
        combo_ex.addItems(sorted(self.exchanges.keys()))
        combo_ex.setCurrentIndex(combo_ex.findText(self.config_exchange()))
        combo_ex.currentIndexChanged.connect(on_change_ex)

        self.hist_checkbox = QCheckBox()
        self.hist_checkbox.stateChanged.connect(on_change_hist)
        self.hist_checkbox_update()

        ok_button = QPushButton(_("OK"))
        ok_button.clicked.connect(lambda: ok_clicked())

        layout.addWidget(self.ccy_combo,1,1)
        layout.addWidget(combo_ex,0,1)
        layout.addWidget(self.hist_checkbox,2,1)
        layout.addWidget(ok_button,3,1)

        result = d.exec_()
        self.ccy_combo = None
        return result

    def refresh_fields(self):
        '''Update the display at the new rate'''
        for window in self.parent.windows:
            for field in window.fx_fields.values():
                field.textEdited.emit(field.text())

    def add_send_edit(self, window):
        window.send_fiat_e = AmountEdit(self.config_ccy)
        self.connect_fields(window, True)
        window.send_grid.addWidget(window.send_fiat_e, 4, 3, Qt.AlignHCenter)
        window.amount_e.frozen.connect(lambda: window.send_fiat_e.setFrozen(window.amount_e.isReadOnly()))

    def add_receive_edit(self, window):
        window.receive_fiat_e = AmountEdit(self.config_ccy)
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
