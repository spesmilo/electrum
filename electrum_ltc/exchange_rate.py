import asyncio
from datetime import datetime
import inspect
import sys
import os
import json
import time
import csv
import decimal
from decimal import Decimal
import concurrent.futures
import traceback
from typing import Sequence

from .bitcoin import COIN
from .i18n import _
from .util import PrintError, ThreadJob, make_dir, log_exceptions
from .util import make_aiohttp_session
from .network import Network
from .simple_config import SimpleConfig


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

    async def get_raw(self, site, get_string):
        # APIs must have https
        url = ''.join(['https://', site, get_string])
        async with make_aiohttp_session(Network.get_instance().proxy) as session:
            async with session.get(url) as response:
                return await response.text()

    async def get_json(self, site, get_string):
        # APIs must have https
        url = ''.join(['https://', site, get_string])
        async with make_aiohttp_session(Network.get_instance().proxy) as session:
            async with session.get(url) as response:
                # set content_type to None to disable checking MIME type
                return await response.json(content_type=None)

    async def get_csv(self, site, get_string):
        raw = await self.get_raw(site, get_string)
        reader = csv.DictReader(raw.split('\n'))
        return list(reader)

    def name(self):
        return self.__class__.__name__

    @log_exceptions
    async def update_safe(self, ccy):
        try:
            self.print_error("getting fx quotes for", ccy)
            self.quotes = await self.get_rates(ccy)
            self.print_error("received fx quotes")
        except BaseException as e:
            self.print_error("failed fx quotes:", repr(e))
            self.quotes = {}
        self.on_quotes()

    def update(self, ccy):
        asyncio.get_event_loop().create_task(self.update_safe(ccy))

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

    @log_exceptions
    async def get_historical_rates_safe(self, ccy, cache_dir):
        try:
            self.print_error("requesting fx history for", ccy)
            h = await self.request_history(ccy)
            self.print_error("received fx history for", ccy)
        except BaseException as e:
            self.print_error("failed fx history:", e)
            #traceback.print_exc()
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
            asyncio.get_event_loop().create_task(self.get_historical_rates_safe(ccy, cache_dir))

    def history_ccys(self):
        return []

    def historical_rate(self, ccy, d_t):
        return self.history.get(ccy, {}).get(d_t.strftime('%Y-%m-%d'), 'NaN')

    def get_currencies(self):
        rates = self.get_rates('')
        return sorted([str(a) for (a, b) in rates.items() if b is not None and len(a)==3])


class Bit2C(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('www.bit2c.co.il', '/Exchanges/LTCNIS/Ticker.json')
        return {'NIS': Decimal(json['ll'])}


class BitcoinAverage(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('apiv2.bitcoinaverage.com', '/indices/global/ticker/short')
        return dict([(r.replace("LTC", ""), Decimal(json[r]['last']))
                     for r in json if r != 'timestamp'])

    def history_ccys(self):
        return ['AUD', 'BRL', 'CAD', 'CHF', 'CNY', 'EUR', 'GBP', 'IDR', 'ILS',
                'MXN', 'NOK', 'NZD', 'PLN', 'RON', 'RUB', 'SEK', 'SGD', 'USD',
                'ZAR']

    async def request_history(self, ccy):
        history = await self.get_csv('apiv2.bitcoinaverage.com',
                               "/indices/global/history/LTC%s?period=alltime&format=csv" % ccy)
        return dict([(h['DateTime'][:10], h['Average'])
                     for h in history])


class BitcoinVenezuela(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.bitcoinvenezuela.com', '/')
        rates = [(r, json['LTC'][r]) for r in json['LTC']
                 if json['LTC'][r] is not None]  # Giving NULL sometimes
        return dict(rates)

    def history_ccys(self):
        return ['ARS', 'EUR', 'USD', 'VEF']

    async def request_history(self, ccy):
        json = await self.get_json('api.bitcoinvenezuela.com',
                             "/historical/index.php?coin=LTC")
        return json[ccy +'_LTC']


class Bitfinex(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.bitfinex.com', '/v1/pubticker/ltcusd')
        return {'USD': Decimal(json['last_price'])}


class Bitso(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.bitso.com', '/v3/ticker/?book=ltc_mxn')
        return {'MXN': Decimal(json['payload']['last'])}


class BitStamp(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('www.bitstamp.net', '/api/v2/ticker/ltcusd/')
        return {'USD': Decimal(json['last'])}


class Coinbase(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.coinbase.com',
                             '/v2/exchange-rates?currency=LTC')
        return {ccy: Decimal(rate) for (ccy, rate) in json["data"]["rates"].items()}



class CoinSpot(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('www.coinspot.com.au', '/pubapi/latest')
        return {'AUD': Decimal(json['prices']['ltc']['last'])}


class GoCoin(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('x.g0cn.com', '/prices')
        ltc_prices = json['prices']['LTC']
        return dict([(r, Decimal(ltc_prices[r])) for r in ltc_prices])


class HitBTC(ExchangeBase):

    async def get_rates(self, ccy):
        ccys = ['USD']
        json = await self.get_json('api.hitbtc.com', '/api/2/public/ticker/LTC%s' % ccy)
        result = dict.fromkeys(ccys)
        if ccy in ccys:
            result[ccy] = Decimal(json['last'])
        return result


class Kraken(ExchangeBase):

    async def get_rates(self, ccy):
        dicts = await self.get_json('api.kraken.com', '/0/public/AssetPairs')
        pairs = [k for k in dicts['result'] if k.startswith('XLTCZ')]
        json = await self.get_json('api.kraken.com',
                             '/0/public/Ticker?pair=%s' % ','.join(pairs))
        ccys = [p[5:] for p in pairs]
        result = dict.fromkeys(ccys)
        result[ccy] = Decimal(json['result']['XLTCZ'+ccy]['c'][0])
        return result

    def history_ccys(self):
        return ['EUR', 'USD']

    async def request_history(self, ccy):
        query = '/0/public/OHLC?pair=LTC%s&interval=1440' % ccy
        json = await self.get_json('api.kraken.com', query)
        history = json['result']['XLTCZ'+ccy]
        return dict([(time.strftime('%Y-%m-%d', time.localtime(t[0])), t[4])
                                    for t in history])


class OKCoin(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('www.okcoin.com', '/api/v1/ticker.do?symbol=ltc_usd')
        return {'USD': Decimal(json['ticker']['last'])}


class MercadoBitcoin(ExchangeBase):

    async def get_rates(self,ccy):
        json = await self.get_json('www.mercadobitcoin.net', '/api/ltc/ticker/')
        return {'BRL': Decimal(json['ticker']['last'])}


class TheRockTrading(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.therocktrading.com',
                                   '/v1/funds/LTCEUR/ticker')
        return {'EUR': Decimal(json['last'])}

class QuadrigaCX(ExchangeBase):

    async def get_rates(self,ccy):
        json = await self.get_json('api.quadrigacx.com', '/v2/ticker?book=ltc_cad')
        return {'CAD': Decimal(json['last'])}


class WEX(ExchangeBase):

    async def get_rates(self, ccy):
        json_eur = await self.get_json('wex.nz', '/api/3/ticker/ltc_eur')
        json_rub = await self.get_json('wex.nz', '/api/3/ticker/ltc_rur')
        json_usd = await self.get_json('wex.nz', '/api/3/ticker/ltc_usd')
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

    def __init__(self, config: SimpleConfig, network: Network):
        self.config = config
        self.network = network
        if self.network:
            self.network.register_callback(self.set_proxy, ['proxy_set'])
        self.ccy = self.get_currency()
        self.history_used_spot = False
        self.ccy_combo = None
        self.hist_checkbox = None
        self.cache_dir = os.path.join(config.path, 'cache')
        self._trigger = asyncio.Event()
        self._trigger.set()
        self.set_exchange(self.config_exchange())
        make_dir(self.cache_dir)

    def set_proxy(self, trigger_name, *args):
        self._trigger.set()

    @staticmethod
    def get_currencies(history: bool) -> Sequence[str]:
        d = get_exchanges_by_ccy(history)
        return sorted(d.keys())

    @staticmethod
    def get_exchanges_by_ccy(ccy: str, history: bool) -> Sequence[str]:
        d = get_exchanges_by_ccy(history)
        return d.get(ccy, [])

    @staticmethod
    def remove_thousands_separator(text):
        return text.replace(',', '') # FIXME use THOUSAND_SEPARATOR in util

    def ccy_amount_str(self, amount, commas):
        prec = CCY_PRECISIONS.get(self.ccy, 2)
        fmt_str = "{:%s.%df}" % ("," if commas else "", max(0, prec)) # FIXME use util.THOUSAND_SEPARATOR and util.DECIMAL_POINT
        try:
            rounded_amount = round(amount, prec)
        except decimal.InvalidOperation:
            rounded_amount = amount
        return fmt_str.format(rounded_amount)

    async def run(self):
        while True:
            try:
                await asyncio.wait_for(self._trigger.wait(), 150)
            except concurrent.futures.TimeoutError:
                pass
            else:
                self._trigger.clear()
                if self.is_enabled():
                    if self.show_history():
                        self.exchange.get_historical_rates(self.ccy, self.cache_dir)
            if self.is_enabled():
                self.exchange.update(self.ccy)

    def is_enabled(self):
        return bool(self.config.get('use_exchange_rate'))

    def set_enabled(self, b):
        self.config.set_key('use_exchange_rate', bool(b))
        self.trigger_update()

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
        self.trigger_update()
        self.on_quotes()

    def trigger_update(self):
        if self.network:
            self.network.asyncio_loop.call_soon_threadsafe(self._trigger.set)

    def set_exchange(self, name):
        class_ = globals().get(name, BitcoinAverage)
        self.print_error("using exchange", name)
        if self.config_exchange() != name:
            self.config.set_key('use_exchange', name, True)
        self.exchange = class_(self.on_quotes, self.on_history)
        # A new exchange means new fx quotes, initially empty.  Force
        # a quote refresh
        self.trigger_update()
        self.exchange.read_historical_rates(self.ccy, self.cache_dir)

    def on_quotes(self):
        if self.network:
            self.network.trigger_callback('on_quotes')

    def on_history(self):
        if self.network:
            self.network.trigger_callback('on_history')

    def exchange_rate(self) -> Decimal:
        """Returns the exchange rate as a Decimal"""
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
