from datetime import datetime
import inspect
import requests
import sys
import os
import json
import pkgutil
from threading import Thread
import time
import csv
import decimal
from decimal import Decimal

from .bitcoin import COIN
from .i18n import _
from .util import PrintError, ThreadJob, print_error


DEFAULT_ENABLED = False
DEFAULT_CURRENCY = "EUR"
DEFAULT_EXCHANGE = "Kraken"

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
        response = requests.request('GET', url, headers={'User-Agent' : 'Electron Cash'}, timeout=10)
        return response.json()

    def get_csv(self, site, get_string):
        url = ''.join(['https://', site, get_string])
        response = requests.request('GET', url, headers={'User-Agent' : 'Electron-Cash'})
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
            except:
                h = None
        else:
            h = None
            timestamp = False
        if h:
            self.history[ccy] = h
            self.on_history()
        return h, timestamp

    def get_historical_rates_safe(self, ccy, cache_dir):
        h, timestamp = self.read_historical_rates(ccy, cache_dir)
        if h is None or time.time() - timestamp < 24*3600:
            try:
                self.print_error("requesting fx history for", ccy)
                h = self.request_history(ccy)
                self.print_error("received fx history for", ccy)
                self.on_history()
            except BaseException as e:
                self.print_error("failed fx history:", e)
                return
            filename = os.path.join(cache_dir, self.name() + '_' + ccy)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(json.dumps(h))
        self.history[ccy] = h
        self.on_history()

    def get_historical_rates(self, ccy, cache_dir):
        result = self.history.get(ccy)
        if not result and ccy in self.history_ccys():
            t = Thread(target=self.get_historical_rates_safe, args=(ccy, cache_dir))
            t.setDaemon(True)
            t.start()
        return result

    def history_ccys(self):
        return []

    def historical_rate(self, ccy, d_t):
        return self.history.get(ccy, {}).get(d_t.strftime('%Y-%m-%d'))

    def get_currencies(self):
        rates = self.get_rates('')
        return sorted([str(a) for (a, b) in rates.items() if b is not None and len(a)==3])


class BitcoinAverage(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('apiv2.bitcoinaverage.com', '/indices/global/ticker/short')
        return dict([(r.replace("BCH", ""), Decimal(json[r]['last']))
                     for r in json if r != 'timestamp'])

    def history_ccys(self):
        return ['AUD', 'BRL', 'CAD', 'CHF', 'CNY', 'EUR', 'GBP', 'IDR', 'ILS',
                'MXN', 'NOK', 'NZD', 'PLN', 'RON', 'RUB', 'SEK', 'SGD', 'USD',
                'ZAR']

    def request_history(self, ccy):
        history = self.get_csv('apiv2.bitcoinaverage.com',
                               "/indices/global/history/BCH%s?period=alltime&format=csv" % ccy)
        return dict([(h['DateTime'][:10], h['Average'])
                     for h in history])


class Bitmarket(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('www.bitmarket.pl', '/json/BCCPLN/ticker.json')
        return {'PLN': Decimal(json['last'])}


class BitPay(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('bitpay.com', '/api/rates/BCH')
        return dict([(r['code'], Decimal(r['rate'])) for r in json])


class Bitso(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.bitso.com', '/v2/ticker/?book=bch_btc')
        return {'BTC': Decimal(json['last'])}


class BitStamp(ExchangeBase):

    def get_rates(self, ccy):
        json_usd = self.get_json('www.bitstamp.net', '/api/v2/ticker/bchusd')
        json_eur = self.get_json('www.bitstamp.net', '/api/v2/ticker/bcheur')
        json_btc = self.get_json('www.bitstamp.net', '/api/v2/ticker/bchbtc')
        return {
            'USD': Decimal(json_usd['last']),
            'EUR': Decimal(json_eur['last']),
            'BTC': Decimal(json_btc['last'])}


class Coinbase(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('coinbase.com',
                             '/api/v1/currencies/exchange_rates')
        return dict([(r[7:].upper(), Decimal(json[r]))
                     for r in json if r.startswith('bch_to_')])

class Kraken(ExchangeBase):

    def get_rates(self, ccy):
        ccys = ['EUR', 'USD']
        pairs = ['BCH%s' % c for c in ccys]
        json = self.get_json('api.kraken.com',
                             '/0/public/Ticker?pair=%s' % ','.join(pairs))
        return dict((k[-3:], Decimal(float(v['c'][0])))
                     for k, v in json['result'].items())


class CoinFloor(ExchangeBase):
    # CoinFloor API only supports GBP on public API
    def get_rates(self, ccy):
        json = self.get_json('webapi.coinfloor.co.uk:8090/bist/BCH/GBP', '/ticker/')
        return {'GBP': Decimal(json['last'])}


class WEX(ExchangeBase):

    def get_rates(self, ccy):
        json_eur = self.get_json('wex.nz', '/api/3/ticker/bch_eur')
        json_rub = self.get_json('wex.nz', '/api/3/ticker/bch_rur')
        json_usd = self.get_json('wex.nz', '/api/3/ticker/bch_usd')
        json_btc = self.get_json('wex.nz', '/api/3/ticker/bch_btc')
        json_ltc = self.get_json('wex.nz', '/api/3/ticker/bch_ltc')
        json_eth = self.get_json('wex.nz', '/api/3/ticker/bch_eth')
        json_dsh = self.get_json('wex.nz', '/api/3/ticker/bch_dsh')
        return {'EUR': Decimal(json_eur['bch_eur']['last']),
                'RUB': Decimal(json_rub['bch_rur']['last']),
                'USD': Decimal(json_usd['bch_usd']['last']),
                'BTC': Decimal(json_btc['bch_btc']['last']),
                'LTC': Decimal(json_ltc['bch_ltc']['last']),
                'ETH': Decimal(json_eth['bch_eth']['last']),
                'DSH': Decimal(json_dsh['bch_dsh']['last'])}


class CoinCap(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.coincap.io', '/v2/rates/bitcoin-cash/')
        return {'USD': Decimal(json['data']['rateUsd'])}

    def history_ccys(self):
        return ['USD']

    def request_history(self, ccy):
        from datetime import datetime as dt
        # Currently 2000 days is the maximum in 1 API call which needs to be fixed
        # sometime before the year 2023...
        history = self.get_json('api.coincap.io',
                               "/v2/assets/bitcoin-cash/history?interval=d1&limit=2000")
        return dict([(dt.utcfromtimestamp(h['time']/1000).strftime('%Y-%m-%d'),
                        h['priceUsd'])
                     for h in history['data']])


class CoinGecko(ExchangeBase):

    def get_rates(self, ccy):
        json = self.get_json('api.coingecko.com', '/api/v3/coins/bitcoin-cash?localization=False&sparkline=false')
        prices = json["market_data"]["current_price"]
        return dict([(a[0].upper(),Decimal(a[1])) for a in prices.items()])

    def history_ccys(self):
        return ['AED', 'ARS', 'AUD', 'BTD', 'BHD', 'BMD', 'BRL', 'BTC',
                'CAD', 'CHF', 'CLP', 'CNY', 'CZK', 'DKK', 'ETH', 'EUR',
                'GBP', 'HKD', 'HUF', 'IDR', 'ILS', 'INR', 'JPY', 'KRW',
                'KWD', 'LKR', 'LTC', 'MMK', 'MXH', 'MYR', 'NOK', 'NZD',
                'PHP', 'PKR', 'PLN', 'RUB', 'SAR', 'SEK', 'SGD', 'THB',
                'TRY', 'TWD', 'USD', 'VEF', 'XAG', 'XAU', 'XDR', 'ZAR']

    def request_history(self, ccy):
        history = self.get_json('api.coingecko.com', '/api/v3/coins/bitcoin-cash/market_chart?vs_currency=%s&days=max' % ccy)

        from datetime import datetime as dt
        return dict([(dt.utcfromtimestamp(h[0]/1000).strftime('%Y-%m-%d'), h[1])
                     for h in history['prices']])


def dictinvert(d):
    inv = {}
    for k, vlist in d.items():
        for v in vlist:
            keys = inv.setdefault(v, [])
            keys.append(k)
    return inv

def get_exchanges_and_currencies():
    try:
        data = pkgutil.get_data(__name__, 'currencies.json')
        return json.loads(data.decode('utf-8'))
    except:
        pass

    path = os.path.join(os.path.dirname(__file__), 'currencies.json')
    d = {}
    is_exchange = lambda obj: (inspect.isclass(obj)
                               and issubclass(obj, ExchangeBase)
                               and obj != ExchangeBase)
    exchanges = dict(inspect.getmembers(sys.modules[__name__], is_exchange))
    for name, klass in exchanges.items():
        exchange = klass(None, None)
        try:
            d[name] = exchange.get_currencies()
            print_error(name, "ok")
        except:
            print_error(name, "error")
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
        if not os.path.exists(self.cache_dir):
            os.mkdir(self.cache_dir)

    def get_currencies(self, h):
        d = get_exchanges_by_ccy(h)
        return sorted(d.keys())

    def get_exchanges_by_ccy(self, ccy, h):
        d = get_exchanges_by_ccy(h)
        return d.get(ccy, [])

    def ccy_amount_str(self, amount, commas,default_prec = 2):
        prec = CCY_PRECISIONS.get(self.ccy, default_prec)
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
        return self.config.get('use_exchange_rate', DEFAULT_ENABLED)

    def set_enabled(self, b):
        return self.config.set_key('use_exchange_rate', bool(b))

    def get_history_config(self):
        return bool(self.config.get('history_rates'))

    def set_history_config(self, b):
        self.config.set_key('history_rates', bool(b))

    def get_fiat_address_config(self):
        return bool(self.config.get('fiat_address'))

    def set_fiat_address_config(self, b):
        self.config.set_key('fiat_address', bool(b))

    def get_currency(self):
        '''Use when dynamic fetching is needed'''
        return self.config.get("currency", DEFAULT_CURRENCY)

    def config_exchange(self):
        return self.config.get('use_exchange', DEFAULT_EXCHANGE)

    def show_history(self):
        return self.is_enabled() and self.get_history_config() and self.ccy in self.exchange.history_ccys()

    def set_currency(self, ccy):
        self.ccy = ccy
        if self.get_currency() != ccy:
            self.config.set_key('currency', ccy, True)
        self.timeout = 0 # Because self.ccy changes
        self.on_quotes()

    def set_exchange(self, name):
        class_ = globals().get(name, Kraken)
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
        if rate:
            return Decimal(rate)

    def format_amount_and_units(self, btc_balance):
        amount_str = self.format_amount(btc_balance)
        return '' if not amount_str else "%s %s" % (amount_str, self.ccy)

    def format_amount(self, btc_balance):
        rate = self.exchange_rate()
        return '' if rate is None else self.value_str(btc_balance, rate)

    def get_fiat_status_text(self, btc_balance, base_unit, decimal_point):
        rate = self.exchange_rate()
        default_prec = 2
        if (base_unit == "cash"):
            default_prec = 4
        return _("  (No FX rate available)") if rate is None else " 1 %s~%s %s" % (base_unit,
            self.value_str(COIN / (10**(8 - decimal_point)), rate, default_prec ), self.ccy )

    def value_str(self, satoshis, rate, default_prec = 2 ):
        if satoshis is None:  # Can happen with incomplete history
            return _("Unknown")
        if rate:
            value = Decimal(satoshis) / COIN * Decimal(rate)
            return "%s" % (self.ccy_amount_str(value, True, default_prec))
        return _("No data")

    def history_rate(self, d_t):
        rate = self.exchange.historical_rate(self.ccy, d_t)
        # Frequently there is no rate for today, until tomorrow :)
        # Use spot quotes in that case
        if rate is None and (datetime.today().date() - d_t.date()).days <= 2:
            rate = self.exchange.quotes.get(self.ccy)
            self.history_used_spot = True
        return Decimal(rate) if rate is not None else None

    def historical_value_str(self, satoshis, d_t):
        rate = self.history_rate(d_t)
        return self.value_str(satoshis, rate)

    def historical_value(self, satoshis, d_t):
        rate = self.history_rate(d_t)
        if rate:
            return Decimal(satoshis) / COIN * Decimal(rate)

    def timestamp_rate(self, timestamp):
        from .util import timestamp_to_datetime
        date = timestamp_to_datetime(timestamp)
        return self.history_rate(date)
