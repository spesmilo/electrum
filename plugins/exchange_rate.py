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
from functools import partial

from electrum_ltc.bitcoin import COIN
from electrum_ltc.plugins import BasePlugin, hook
from electrum_ltc.i18n import _
from electrum_ltc.util import PrintError, ThreadJob, timestamp_to_datetime
from electrum_ltc.util import format_satoshis
from electrum_ltc_gui.qt.util import *
from electrum_ltc_gui.qt.amountedit import AmountEdit

# See https://en.wikipedia.org/wiki/ISO_4217
CCY_PRECISIONS = {'BHD': 3, 'BIF': 0, 'BYR': 0, 'CLF': 4, 'CLP': 0,
                  'CVE': 0, 'DJF': 0, 'GNF': 0, 'IQD': 3, 'ISK': 0,
                  'JOD': 3, 'JPY': 0, 'KMF': 0, 'KRW': 0, 'KWD': 3,
                  'LYD': 3, 'MGA': 1, 'MRO': 1, 'OMR': 3, 'PYG': 0,
                  'RWF': 0, 'TND': 3, 'UGX': 0, 'UYI': 0, 'VND': 0,
                  'VUV': 0, 'XAF': 0, 'XAG': 2, 'XAU': 4, 'XOF': 0,
                  'XPF': 0}

class ExchangeBase(PrintError):
    def __init__(self, sig):
        self.history = {}
        self.quotes = {}
        self.sig = sig

    def protocol(self):
        return "https"

    def get_json(self, site, get_string):
        url = "".join([self.protocol(), '://', site, get_string])
        response = requests.request('GET', url,
                                    headers={'User-Agent' : 'Electrum'})
        return response.json()

    def name(self):
        return self.__class__.__name__

    def update_safe(self, ccy):
        try:
            self.print_error("getting fx quotes for", ccy)
            self.quotes = self.get_rates(ccy)
            self.print_error("received fx quotes")
            self.sig.emit(SIGNAL('fx_quotes'))
        except Exception, e:
            self.print_error("failed fx quotes:", e)

    def update(self, ccy):
        t = Thread(target=self.update_safe, args=(ccy,))
        t.setDaemon(True)
        t.start()

    def get_historical_rates_safe(self, ccy):
        try:
            self.print_error("requesting fx history for", ccy)
            self.history[ccy] = self.historical_rates(ccy)
            self.print_error("received fx history for", ccy)
            self.sig.emit(SIGNAL("fx_history"))
        except Exception, e:
            self.print_error("failed fx history:", e)

    def get_historical_rates(self, ccy):
        result = self.history.get(ccy)
        if not result and ccy in self.history_ccys():
            t = Thread(target=self.get_historical_rates_safe, args=(ccy,))
            t.setDaemon(True)
            t.start()
        return result

    def history_ccys(self):
        return []

    def historical_rate(self, ccy, d_t):
        return self.history.get(ccy, {}).get(d_t.strftime('%Y-%m-%d'))


class Bit2C(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('www.bit2c.co.il', '/Exchanges/LTCNIS/Ticker.json')
        return {'NIS': Decimal(json['ll'])}

class BitcoinVenezuela(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('api.bitcoinvenezuela.com', '/')
        return dict([(r, Decimal(json['LTC'][r]))
                     for r in json['LTC']])

    def protocol(self):
        return "http"

    def history_ccys(self):
        return ['ARS', 'EUR', 'USD', 'VEF']

    def historical_rates(self, ccy):
        json = self.get_json('api.bitcoinvenezuela.com',
                             '/historical/index.php?coin=LTC')
        return json[ccy +'_LTC']

class Bitfinex(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('api.bitfinex.com', '/v1/pubticker/ltcusd')
        return {'USD': Decimal(json['last_price'])}

class BTCChina(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('data.btcchina.com', '/data/ticker?market=ltccny')
        return {'CNY': Decimal(json['ticker']['last'])}

class BTCe(ExchangeBase):
    def get_rates(self, ccy):
        ccys = ['EUR', 'RUR', 'USD']
        ccy_str = '-'.join(['ltc_%s' % c.lower() for c in ccys])
        json = self.get_json('btc-e.com', '/api/3/ticker/%s' % ccy_str)
        result = dict.fromkeys(ccys)
        for ccy in ccys:
            result[ccy] = Decimal(json['ltc_%s' % ccy.lower()]['last'])
        return result

class CaVirtEx(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('www.cavirtex.com', '/api2/ticker.json?currencypair=LTCCAD')
        return {'CAD': Decimal(json['ticker']['LTCCAD']['last'])}

class GoCoin(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('x.g0cn.com', '/prices')
        ltc_prices = json['prices']['LTC']
        return dict([(r, Decimal(ltc_prices[r])) for r in ltc_prices])

class HitBTC(ExchangeBase):
    def get_rates(self, ccy):
        ccys = ['EUR', 'USD']
        json = self.get_json('api.hitbtc.com', '/api/1/public/LTC%s/ticker' % ccy)
        result = dict.fromkeys(ccys)
        if ccy in ccys:
            result[ccy] = Decimal(json['last'])
        return result

class Kraken(ExchangeBase):
    def get_rates(self, ccy):
        dicts = self.get_json('api.kraken.com', '/0/public/AssetPairs')
        pairs = [k for k in dicts['result'] if k.startswith('XLTCZ')]
        json = self.get_json('api.kraken.com',
                             '/0/public/Ticker?pair=%s' % ','.join(pairs))
        ccys = [p[5:] for p in pairs]
        result = dict.fromkeys(ccys)
        result[ccy] = Decimal(json['result']['XLTCZ'+ccy]['c'][0])
        return result

    def history_ccys(self):
        return ['EUR', 'USD']

    def historical_rates(self, ccy):
        query = '/0/public/OHLC?pair=LTC%s&interval=1440' % ccy
        json = self.get_json('api.kraken.com', query)
        history = json['result']['XLTCZ'+ccy]
        return dict([(time.strftime('%Y-%m-%d', time.localtime(t[0])), t[4])
                                    for t in history])

class OKCoin(ExchangeBase):
    def get_rates(self, ccy):
        json = self.get_json('www.okcoin.cn', '/api/ticker.do?symbol=ltc_cny')
        return {'CNY': Decimal(json['ticker']['last'])}


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
        self.windows = dict()

        is_exchange = lambda obj: (inspect.isclass(obj)
                                   and issubclass(obj, ExchangeBase)
                                   and obj != ExchangeBase)
        self.exchanges = dict(inspect.getmembers(sys.modules[__name__],
                                                 is_exchange))
        self.set_exchange(self.config_exchange())

    def ccy_amount_str(self, amount, commas):
        prec = CCY_PRECISIONS.get(self.ccy, 2)
        fmt_str = "{:%s.%df}" % ("," if commas else "", max(0, prec))
        return fmt_str.format(round(amount, prec))

    def thread_jobs(self):
        return [self]

    def run(self):
        # This runs from the network thread which catches exceptions
        if self.windows and self.timeout <= time.time():
            self.timeout = time.time() + 150
            self.exchange.update(self.ccy)

    def config_ccy(self):
        '''Use when dynamic fetching is needed'''
        return self.config.get("currency", "EUR")

    def config_exchange(self):
        return self.config.get('use_exchange', 'BTCe')

    def config_history(self):
        return self.config.get('history_rates', 'unchecked') != 'unchecked'

    def show_history(self):
        return self.config_history() and self.exchange.history_ccys()

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
        for window in self.windows:
            window.update_status()

    def on_new_window(self, window):
        # Additional send and receive edit boxes
        send_e = AmountEdit(self.config_ccy)
        window.send_grid.addWidget(send_e, 4, 3, Qt.AlignHCenter)
        window.amount_e.frozen.connect(
            lambda: send_e.setFrozen(window.amount_e.isReadOnly()))
        receive_e = AmountEdit(self.config_ccy)
        window.receive_grid.addWidget(receive_e, 2, 3, Qt.AlignHCenter)

        self.windows[window] = {'edits': (send_e, receive_e),
                                'last_edited': {}}
        self.connect_fields(window, window.amount_e, send_e, window.fee_e)
        self.connect_fields(window, window.receive_amount_e, receive_e, None)
        window.history_list.refresh_headers()
        window.update_status()

    def connect_fields(self, window, btc_e, fiat_e, fee_e):
        last_edited = self.windows[window]['last_edited']

        def edit_changed(edit):
            edit.setStyleSheet(BLACK_FG)
            last_edited[(fiat_e, btc_e)] = edit
            amount = edit.get_amount()
            rate = self.exchange_rate()
            if rate is None or amount is None:
                if edit is fiat_e:
                    btc_e.setText("")
                    if fee_e:
                        fee_e.setText("")
                else:
                    fiat_e.setText("")
            else:
                if edit is fiat_e:
                    btc_e.setAmount(int(amount / Decimal(rate) * COIN))
                    if fee_e: window.update_fee()
                    btc_e.setStyleSheet(BLUE_FG)
                else:
                    fiat_e.setText(self.ccy_amount_str(
                        amount * Decimal(rate) / COIN, False))
                    fiat_e.setStyleSheet(BLUE_FG)

        fiat_e.textEdited.connect(partial(edit_changed, fiat_e))
        btc_e.textEdited.connect(partial(edit_changed, btc_e))
        last_edited[(fiat_e, btc_e)] = btc_e

    @hook
    def do_clear(self, window):
        self.windows[window]['edits'][0].setText('')

    def on_close_window(self, window):
        self.windows.pop(window)

    def close(self):
        # Get rid of hooks before updating status bars.
        BasePlugin.close(self)
        self.update_status_bars()
        self.refresh_headers()
        for window, data in self.windows.items():
            for edit in data['edits']:
                edit.hide()
            window.update_status()

    def refresh_headers(self):
        for window in self.windows:
            window.history_list.refresh_headers()

    def on_fx_history(self):
        '''Called when historical fx quotes are updated'''
        for window in self.windows:
            window.update_history_tab()

    def on_fx_quotes(self):
        '''Called when fresh spot fx quotes come in'''
        self.update_status_bars()
        self.populate_ccy_combo()
        # Refresh edits with the new rate
        for window, data in self.windows.items():
            for edit in data['last_edited'].values():
                edit.textEdited.emit(edit.text())
        # History tab needs updating if it used spot
        if self.history_used_spot:
            self.on_fx_history()

    def on_ccy_combo_change(self):
        '''Called when the chosen currency changes'''
        ccy = str(self.ccy_combo.currentText())
        if ccy and ccy != self.ccy:
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

    def exchange_rate(self):
        '''Returns None, or the exchange rate as a Decimal'''
        rate = self.exchange.quotes.get(self.ccy)
        if rate:
            return Decimal(rate)

    @hook
    def get_fiat_status_text(self, btc_balance, result):
        # return status as:   (1.23 USD)    1 BTC~123.45 USD
        rate = self.exchange_rate()
        if rate is None:
            text = _("  (No FX rate available)")
        else:
            text =  "  (%s)    1 LTC~%s" % (self.value_str(btc_balance, rate),
                                            self.value_str(COIN, rate))
        result['text'] = text

    def get_historical_rates(self):
        if self.show_history():
            self.exchange.get_historical_rates(self.ccy)

    def requires_settings(self):
        return True

    def value_str(self, satoshis, rate):
        if rate:
            value = Decimal(satoshis) / COIN * Decimal(rate)
            return "%s %s" % (self.ccy_amount_str(value, True), self.ccy)
        return _("No data")

    def historical_value_str(self, satoshis, d_t):
        rate = self.exchange.historical_rate(self.ccy, d_t)
        # Frequently there is no rate for today, until tomorrow :)
        # Use spot quotes in that case
        if rate is None and (datetime.today().date() - d_t.date()).days <= 2:
            rate = self.exchange.quotes.get(self.ccy)
            self.history_used_spot = True
        return self.value_str(satoshis, rate)

    @hook
    def history_tab_headers(self, headers):
        if self.show_history():
            headers.extend([_('Fiat Amount'), _('Fiat Balance')])

    @hook
    def history_tab_update_begin(self):
        self.history_used_spot = False

    @hook
    def history_tab_update(self, tx, entry):
        if not self.show_history():
            return
        tx_hash, conf, value, timestamp, balance = tx
        date = timestamp_to_datetime(timestamp)
        if not date:
            date = timestamp_to_datetime(0)
        for amount in [value, balance]:
            text = self.historical_value_str(amount, date)
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
            self.refresh_headers()

        def ok_clicked():
            self.timeout = 0
            self.ccy_combo = None
            d.accept()

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

        return d.exec_()
