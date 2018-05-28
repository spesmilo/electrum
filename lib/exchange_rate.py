from datetime import datetime
import inspect
import requests
import sys
import os
import json
from threading import Thread
import time
import csv
import decimal
from decimal import Decimal

from .bitcoin import COIN
from .i18n import _
from .util import PrintError, ThreadJob, make_dir


# See https://en.wikipedia.org/wiki/ISO_4217
CCY_PRECISIONS = {'BHD': 3, 'BIF': 0, 'BYR': 0, 'CLF': 4, 'CLP': 0,
                  'CVE': 0, 'DJF': 0, 'GNF': 0, 'IQD': 3, 'ISK': 0,
                  'JOD': 3, 'JPY': 0, 'KMF': 0, 'KRW': 0, 'KWD': 3,
                  'LYD': 3, 'MGA': 1, 'MRO': 1, 'OMR': 3, 'PYG': 0,
                  'RWF': 0, 'TND': 3, 'UGX': 0, 'UYI': 0, 'VND': 0,
                  'VUV': 0, 'XAF': 0, 'XAU': 4, 'XOF': 0, 'XPF': 0}


class ExchangeBase(PrintError):

    def __init__(self, on_quotes, on_history):
        self.history = {}
        self.quotes = {}
        self.on_quotes = on_quotes
        self.on_history = on_history

    def get_json(self, site, get_string):
        # APIs must have https
        url = ''.join(['https://', site, get_string])
        response = requests.request('GET', url, headers={'User-Agent' : 'Electrum'}, timeout=10)
        return response.json()

    def get_csv(self, site, get_string):
        url = ''.join(['https://', site, get_string])
        response = requests.request('GET', url, headers={'User-Agent' : 'Electrum'})
        reader = csv.DictReader(response.content.decode().split('\n'))
        return list(reader)

    def name(self):
        return self.__class__.__name__

    def update_safe(self, ccy):
        try:
            self.print_error("getting fx quotes for", ccy)
            self.quotes = self.get_rates(ccy)
            self.print_error("received fx quotes")
        except BaseException as e:
            self.print_error("failed fx quotes:", e)
        self.on_quotes()

    def update(self, ccy):
        t = Thread(target=self.update_safe, args=(ccy,))
        t.setDaemon(True)
        t.start()

    def read_historical_rates(self, ccy, cache_dir):
        filename = os.path.join(cache_dir, self.name() + '_'+ ccy)
        if os.path.exists(filename):
            timestamp = os.stat(filename).st_mtime
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    h = json.loads(f.read())
                h['timestamp'] = timestamp
            except:
                h = None
        else:
            h = None
        if h:
            self.history[ccy] = h
            self.on_history()
        return h

    def get_historical_rates_safe(self, ccy, cache_dir):
        try:
            self.print_error("requesting fx history for", ccy)
            h = self.request_history(ccy)
            self.print_error("received fx history for", ccy)
        except BaseException as e:
            self.print_error("failed fx history:", e)
            return
        filename = os.path.join(cache_dir, self.name() + '_' + ccy)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(json.dumps(h))
        h['timestamp'] = time.time()
        self.history[ccy] = h
        self.on_history()

    def get_historical_rates(self, ccy, cache_dir):
        if ccy not in self.history_ccys():
            return
        h = self.history.get(ccy)
        if h is None:
            h = self.read_historical_rates(ccy, cache_dir)
        if h is None or h['timestamp'] < time.time() - 24*3600:
            t = Thread(target=self.get_historical_rates_safe, args=(ccy, cache_dir))
            t.setDaemon(True)
            t.start()

    def history_ccys(self):
        return []

    def historical_rate(self, ccy, d_t):
        return self.history.get(ccy, {}).get(d_t.strftime('%Y-%m-%d'), 'NaN')

    def get_currencies(self):
        rates = self.get_rates('')
        return sorted([str(a) for (a, b) in rates.items() if b is not None and len(a)==3])


class Bit2C(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('www.bit2c.co.il', '/Exchanges/LTCNIS/Ticker.json')
        return {'NIS': Decimal(json['ll'])}


class BitcoinAverage(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('apiv2.bitcoinaverage.com', '/indices/global/ticker/short')
        return dict([(r.replace("LTC", ""), Decimal(json[r]['last']))
                     for r in json if r != 'timestamp'])

    def history_ccys(self):
        return ['AUD', 'BRL', 'CAD', 'CHF', 'CNY', 'EUR', 'GBP', 'IDR', 'ILS',
                'MXN', 'NOK', 'NZD', 'PLN', 'RON', 'RUB', 'SEK', 'SGD', 'USD',
                'ZAR']

    def request_history(self, ccy):
        history = self.get_csv('apiv2.bitcoinaverage.com',
                               "/indices/global/history/LTC%s?period=alltime&format=csv" % ccy)
        return dict([(h['DateTime'][:10], h['Average'])
                     for h in history])


class BitcoinVenezuela(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.bitcoinvenezuela.com', '/')
        rates = [(r, json['LTC'][r]) for r in json['LTC']
                 if json['LTC'][r] is not None]  # Giving NULL sometimes
        return dict(rates)

    def history_ccys(self):
        return ['ARS', 'EUR', 'USD', 'VEF']

    def request_history(self, ccy):
        return self.get_json('api.bitcoinvenezuela.com',
                             "/historical/index.php?coin=LTC")[ccy +'_LTC']

class Bitfinex(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.bitfinex.com', '/v1/pubticker/ltcusd')
        return {'USD': Decimal(json['last_price'])}


class Bitso(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.bitso.com', '/v3/ticker/?book=ltc_mxn')
        return {'MXN': Decimal(json['payload']['last'])}


class BitStamp(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('www.bitstamp.net', '/api/v2/ticker/ltcusd/')
        return {'USD': Decimal(json['last'])}


class Coinbase(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.coinbase.com',
                             '/v2/exchange-rates?currency=LTC')
        rates = json['data']['rates']
        return dict([(k, Decimal(rates[k])) for k in rates])


class CoinSpot(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('www.coinspot.com.au', '/pubapi/latest')
        return {'AUD': Decimal(json['prices']['ltc']['last'])}


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

    def request_history(self, ccy):
        query = '/0/public/OHLC?pair=LTC%s&interval=1440' % ccy
        json = self.get_json('api.kraken.com', query)
        history = json['result']['XLTCZ'+ccy]
        return dict([(time.strftime('%Y-%m-%d', time.localtime(t[0])), t[4])
                                    for t in history])


class OKCoin(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('www.okcoin.com', '/api/v1/ticker.do?symbol=ltc_usd')
        return {'USD': Decimal(json['ticker']['last'])}


class MercadoBitcoin(ExchangeBase):

    def get_rates(self,ccy):
        json = self.get_json('www.mercadobitcoin.net', '/api/ltc/ticker/')
        return {'BRL': Decimal(json['ticker']['last'])}

class TheRockTrading(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.therocktrading.com', 
                             '/v1/funds/LTCEUR/ticker')
        return {'EUR': Decimal(json['last'])}

class QuadrigaCX(ExchangeBase):

    def get_rates(self,ccy):
        json = self.get_json('api.quadrigacx.com', '/v2/ticker?book=ltc_cad')
        return {'CAD': Decimal(json['last'])}


class WEX(ExchangeBase):

    def get_rates(self, ccy):
        json_eur = self.get_json('wex.nz', '/api/3/ticker/ltc_eur')
        json_rub = self.get_json('wex.nz', '/api/3/ticker/ltc_rur')
        json_usd = self.get_json('wex.nz', '/api/3/ticker/ltc_usd')
        return {'EUR': Decimal(json_eur['ltc_eur']['last']),
                'RUB': Decimal(json_rub['ltc_rur']['last']),
                'USD': Decimal(json_usd['ltc_usd']['last'])}


def dictinvert(d):
    inv = {}
    for k, vlist in d.items():
        for v in vlist:
            keys = inv.setdefault(v, [])
            keys.append(k)
    return inv

def get_exchanges_and_currencies():
    import os, json
    path = os.path.join(os.path.dirname(__file__), 'currencies.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.loads(f.read())
    except:
        pass
    d = {}
    is_exchange = lambda obj: (inspect.isclass(obj)
                               and issubclass(obj, ExchangeBase)
                               and obj != ExchangeBase)
    exchanges = dict(inspect.getmembers(sys.modules[__name__], is_exchange))
    for name, klass in exchanges.items():
        exchange = klass(None, None)
        try:
            d[name] = exchange.get_currencies()
            print(name, "ok")
        except:
            print(name, "error")
            continue
    with open(path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(d, indent=4, sort_keys=True))
    return d


CURRENCIES = get_exchanges_and_currencies()


def get_exchanges_by_ccy(history=True):
    if not history:
        return dictinvert(CURRENCIES)
    d = {}
    exchanges = CURRENCIES.keys()
    for name in exchanges:
        klass = globals()[name]
        exchange = klass(None, None)
        d[name] = exchange.history_ccys()
    return dictinvert(d)


class FxThread(ThreadJob):

    def __init__(self, config, network):
        self.config = config
        self.network = network
        self.ccy = self.get_currency()
        self.history_used_spot = False
        self.ccy_combo = None
        self.hist_checkbox = None
        self.cache_dir = os.path.join(config.path, 'cache')
        self.set_exchange(self.config_exchange())
        make_dir(self.cache_dir)

    def get_currencies(self, h):
        d = get_exchanges_by_ccy(h)
        return sorted(d.keys())

    def get_exchanges_by_ccy(self, ccy, h):
        d = get_exchanges_by_ccy(h)
        return d.get(ccy, [])

    def ccy_amount_str(self, amount, commas):
        prec = CCY_PRECISIONS.get(self.ccy, 2)
        fmt_str = "{:%s.%df}" % ("," if commas else "", max(0, prec))
        try:
            rounded_amount = round(amount, prec)
        except decimal.InvalidOperation:
            rounded_amount = amount
        return fmt_str.format(rounded_amount)

    def run(self):
        # This runs from the plugins thread which catches exceptions
        if self.is_enabled():
            if self.timeout ==0 and self.show_history():
                self.exchange.get_historical_rates(self.ccy, self.cache_dir)
            if self.timeout <= time.time():
                self.timeout = time.time() + 150
                self.exchange.update(self.ccy)

    def is_enabled(self):
        return bool(self.config.get('use_exchange_rate'))

    def set_enabled(self, b):
        return self.config.set_key('use_exchange_rate', bool(b))

    def get_history_config(self):
        return bool(self.config.get('history_rates'))

    def set_history_config(self, b):
        self.config.set_key('history_rates', bool(b))

    def get_history_capital_gains_config(self):
        return bool(self.config.get('history_rates_capital_gains', False))

    def set_history_capital_gains_config(self, b):
        self.config.set_key('history_rates_capital_gains', bool(b))

    def get_fiat_address_config(self):
        return bool(self.config.get('fiat_address'))

    def set_fiat_address_config(self, b):
        self.config.set_key('fiat_address', bool(b))

    def get_currency(self):
        '''Use when dynamic fetching is needed'''
        return self.config.get("currency", "EUR")

    def config_exchange(self):
        return self.config.get('use_exchange', 'BitcoinAverage')

    def show_history(self):
        return self.is_enabled() and self.get_history_config() and self.ccy in self.exchange.history_ccys()

    def set_currency(self, ccy):
        self.ccy = ccy
        self.config.set_key('currency', ccy, True)
        self.timeout = 0 # Because self.ccy changes
        self.on_quotes()

    def set_exchange(self, name):
        class_ = globals().get(name, BitcoinAverage)
        self.print_error("using exchange", name)
        if self.config_exchange() != name:
            self.config.set_key('use_exchange', name, True)
        self.exchange = class_(self.on_quotes, self.on_history)
        # A new exchange means new fx quotes, initially empty.  Force
        # a quote refresh
        self.timeout = 0
        self.exchange.read_historical_rates(self.ccy, self.cache_dir)

    def on_quotes(self):
        if self.network:
            self.network.trigger_callback('on_quotes')

    def on_history(self):
        if self.network:
            self.network.trigger_callback('on_history')

    def exchange_rate(self):
        '''Returns None, or the exchange rate as a Decimal'''
        rate = self.exchange.quotes.get(self.ccy)
        if rate is None:
            return Decimal('NaN')
        return Decimal(rate)

    def format_amount(self, btc_balance):
        rate = self.exchange_rate()
        return '' if rate.is_nan() else "%s" % self.value_str(btc_balance, rate)

    def format_amount_and_units(self, btc_balance):
        rate = self.exchange_rate()
        return '' if rate.is_nan() else "%s %s" % (self.value_str(btc_balance, rate), self.ccy)

    def get_fiat_status_text(self, btc_balance, base_unit, decimal_point):
        rate = self.exchange_rate()
        return _("  (No FX rate available)") if rate.is_nan() else " 1 %s~%s %s" % (base_unit,
            self.value_str(COIN / (10**(8 - decimal_point)), rate), self.ccy)

    def fiat_value(self, satoshis, rate):
        return Decimal('NaN') if satoshis is None else Decimal(satoshis) / COIN * Decimal(rate)

    def value_str(self, satoshis, rate):
        return self.format_fiat(self.fiat_value(satoshis, rate))

    def format_fiat(self, value):
        if value.is_nan():
            return _("No data")
        return "%s" % (self.ccy_amount_str(value, True))

    def history_rate(self, d_t):
        if d_t is None:
            return Decimal('NaN')
        rate = self.exchange.historical_rate(self.ccy, d_t)
        # Frequently there is no rate for today, until tomorrow :)
        # Use spot quotes in that case
        if rate == 'NaN' and (datetime.today().date() - d_t.date()).days <= 2:
            rate = self.exchange.quotes.get(self.ccy, 'NaN')
            self.history_used_spot = True
        return Decimal(rate)

    def historical_value_str(self, satoshis, d_t):
        return self.format_fiat(self.historical_value(satoshis, d_t))

    def historical_value(self, satoshis, d_t):
        return self.fiat_value(satoshis, self.history_rate(d_t))

    def timestamp_rate(self, timestamp):
        from .util import timestamp_to_datetime
        date = timestamp_to_datetime(timestamp)
        return self.history_rate(date)
