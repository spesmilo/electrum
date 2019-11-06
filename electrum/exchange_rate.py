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
from typing import Sequence, Optional

from aiorpcx.curio import timeout_after, TaskTimeout, TaskGroup

from .bitcoin import COIN
from .i18n import _
from .util import (ThreadJob, make_dir, log_exceptions,
                   make_aiohttp_session, resource_path)
from .network import Network
from .simple_config import SimpleConfig
from .logging import Logger


DEFAULT_ENABLED = False
DEFAULT_CURRENCY = "EUR"
DEFAULT_EXCHANGE = "CoinGecko"  # default exchange should ideally provide historical rates


# See https://en.wikipedia.org/wiki/ISO_4217
CCY_PRECISIONS = {'BHD': 3, 'BIF': 0, 'BYR': 0, 'CLF': 4, 'CLP': 0,
                  'CVE': 0, 'DJF': 0, 'GNF': 0, 'IQD': 3, 'ISK': 0,
                  'JOD': 3, 'JPY': 0, 'KMF': 0, 'KRW': 0, 'KWD': 3,
                  'LYD': 3, 'MGA': 1, 'MRO': 1, 'OMR': 3, 'PYG': 0,
                  'RWF': 0, 'TND': 3, 'UGX': 0, 'UYI': 0, 'VND': 0,
                  'VUV': 0, 'XAF': 0, 'XAU': 4, 'XOF': 0, 'XPF': 0}


class ExchangeBase(Logger):

    def __init__(self, on_quotes, on_history):
        Logger.__init__(self)
        self.history = {}
        self.quotes = {}
        self.on_quotes = on_quotes
        self.on_history = on_history

    async def get_raw(self, site, get_string):
        # APIs must have https
        url = ''.join(['https://', site, get_string])
        network = Network.get_instance()
        proxy = network.proxy if network else None
        async with make_aiohttp_session(proxy) as session:
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.text()

    async def get_json(self, site, get_string):
        # APIs must have https
        url = ''.join(['https://', site, get_string])
        network = Network.get_instance()
        proxy = network.proxy if network else None
        async with make_aiohttp_session(proxy) as session:
            async with session.get(url) as response:
                response.raise_for_status()
                # set content_type to None to disable checking MIME type
                return await response.json(content_type=None)

    async def get_csv(self, site, get_string):
        raw = await self.get_raw(site, get_string)
        reader = csv.DictReader(raw.split('\n'))
        return list(reader)

    def name(self):
        return self.__class__.__name__

    async def update_safe(self, ccy):
        try:
            self.logger.info(f"getting fx quotes for {ccy}")
            self.quotes = await self.get_rates(ccy)
            self.logger.info("received fx quotes")
        except BaseException as e:
            self.logger.info(f"failed fx quotes: {repr(e)}")
            self.quotes = {}
        self.on_quotes()

    def read_historical_rates(self, ccy, cache_dir) -> Optional[dict]:
        filename = os.path.join(cache_dir, self.name() + '_'+ ccy)
        if not os.path.exists(filename):
            return None
        timestamp = os.stat(filename).st_mtime
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                h = json.loads(f.read())
        except:
            return None
        if not h:  # e.g. empty dict
            return None
        h['timestamp'] = timestamp
        self.history[ccy] = h
        self.on_history()
        return h

    @log_exceptions
    async def get_historical_rates_safe(self, ccy, cache_dir):
        try:
            self.logger.info(f"requesting fx history for {ccy}")
            h = await self.request_history(ccy)
            self.logger.info(f"received fx history for {ccy}")
        except BaseException as e:
            self.logger.info(f"failed fx history: {repr(e)}")
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

    async def request_history(self, ccy):
        raise NotImplementedError()  # implemented by subclasses

    async def get_rates(self, ccy):
        raise NotImplementedError()  # implemented by subclasses

    async def get_currencies(self):
        rates = await self.get_rates('')
        return sorted([str(a) for (a, b) in rates.items() if b is not None and len(a)==3])


class BitcoinAverage(ExchangeBase):
    # note: historical rates used to be freely available
    # but this is no longer the case. see #5188

    async def get_rates(self, ccy):
        json = await self.get_json('apiv2.bitcoinaverage.com', '/indices/global/ticker/short')
        return dict([(r.replace("BTC", ""), Decimal(json[r]['last']))
                     for r in json if r != 'timestamp'])


class Bitcointoyou(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('bitcointoyou.com', "/API/ticker.aspx")
        return {'BRL': Decimal(json['ticker']['last'])}


class BitcoinVenezuela(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.bitcoinvenezuela.com', '/')
        rates = [(r, json['BTC'][r]) for r in json['BTC']
                 if json['BTC'][r] is not None]  # Giving NULL for LTC
        return dict(rates)

    def history_ccys(self):
        return ['ARS', 'EUR', 'USD', 'VEF']

    async def request_history(self, ccy):
        json = await self.get_json('api.bitcoinvenezuela.com',
                             "/historical/index.php?coin=BTC")
        return json[ccy +'_BTC']


class Bitbank(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('public.bitbank.cc', '/btc_jpy/ticker')
        return {'JPY': Decimal(json['data']['last'])}


class BitFlyer(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('bitflyer.jp', '/api/echo/price')
        return {'JPY': Decimal(json['mid'])}


class Bitmarket(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('www.bitmarket.pl', '/json/BTCPLN/ticker.json')
        return {'PLN': Decimal(json['last'])}


class BitPay(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('bitpay.com', '/api/rates')
        return dict([(r['code'], Decimal(r['rate'])) for r in json])


class Bitso(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.bitso.com', '/v2/ticker')
        return {'MXN': Decimal(json['last'])}


class BitStamp(ExchangeBase):

    async def get_currencies(self):
        return ['USD', 'EUR']

    async def get_rates(self, ccy):
        if ccy in CURRENCIES[self.name()]:
            json = await self.get_json('www.bitstamp.net', f'/api/v2/ticker/btc{ccy.lower()}/')
            return {ccy: Decimal(json['last'])}
        return {}


class Bitvalor(ExchangeBase):

    async def get_rates(self,ccy):
        json = await self.get_json('api.bitvalor.com', '/v1/ticker.json')
        return {'BRL': Decimal(json['ticker_1h']['total']['last'])}


class BlockchainInfo(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('blockchain.info', '/ticker')
        return dict([(r, Decimal(json[r]['15m'])) for r in json])


class Bylls(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('bylls.com', '/api/price?from_currency=BTC&to_currency=CAD')
        return {'CAD': Decimal(json['public_price']['to_price'])}


class Coinbase(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.coinbase.com',
                             '/v2/exchange-rates?currency=BTC')
        return {ccy: Decimal(rate) for (ccy, rate) in json["data"]["rates"].items()}


class CoinCap(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.coincap.io', '/v2/rates/bitcoin/')
        return {'USD': Decimal(json['data']['rateUsd'])}

    def history_ccys(self):
        return ['USD']

    async def request_history(self, ccy):
        # Currently 2000 days is the maximum in 1 API call
        # (and history starts on 2017-03-23)
        history = await self.get_json('api.coincap.io',
                                      '/v2/assets/bitcoin/history?interval=d1&limit=2000')
        return dict([(datetime.utcfromtimestamp(h['time']/1000).strftime('%Y-%m-%d'), h['priceUsd'])
                     for h in history['data']])


class CoinDesk(ExchangeBase):

    async def get_currencies(self):
        dicts = await self.get_json('api.coindesk.com',
                              '/v1/bpi/supported-currencies.json')
        return [d['currency'] for d in dicts]

    async def get_rates(self, ccy):
        json = await self.get_json('api.coindesk.com',
                             '/v1/bpi/currentprice/%s.json' % ccy)
        result = {ccy: Decimal(json['bpi'][ccy]['rate_float'])}
        return result

    def history_starts(self):
        return { 'USD': '2012-11-30', 'EUR': '2013-09-01' }

    def history_ccys(self):
        return self.history_starts().keys()

    async def request_history(self, ccy):
        start = self.history_starts()[ccy]
        end = datetime.today().strftime('%Y-%m-%d')
        # Note ?currency and ?index don't work as documented.  Sigh.
        query = ('/v1/bpi/historical/close.json?start=%s&end=%s'
                 % (start, end))
        json = await self.get_json('api.coindesk.com', query)
        return json['bpi']


class CoinGecko(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.coingecko.com', '/api/v3/exchange_rates')
        return dict([(ccy.upper(), Decimal(d['value']))
                     for ccy, d in json['rates'].items()])

    def history_ccys(self):
        # CoinGecko seems to have historical data for all ccys it supports
        return CURRENCIES[self.name()]

    async def request_history(self, ccy):
        history = await self.get_json('api.coingecko.com',
                                      '/api/v3/coins/bitcoin/market_chart?vs_currency=%s&days=max' % ccy)

        return dict([(datetime.utcfromtimestamp(h[0]/1000).strftime('%Y-%m-%d'), h[1])
                     for h in history['prices']])


class itBit(ExchangeBase):

    async def get_rates(self, ccy):
        ccys = ['USD', 'EUR', 'SGD']
        json = await self.get_json('api.itbit.com', '/v1/markets/XBT%s/ticker' % ccy)
        result = dict.fromkeys(ccys)
        if ccy in ccys:
            result[ccy] = Decimal(json['lastPrice'])
        return result


class Kraken(ExchangeBase):

    async def get_rates(self, ccy):
        ccys = ['EUR', 'USD', 'CAD', 'GBP', 'JPY']
        pairs = ['XBT%s' % c for c in ccys]
        json = await self.get_json('api.kraken.com',
                             '/0/public/Ticker?pair=%s' % ','.join(pairs))
        return dict((k[-3:], Decimal(float(v['c'][0])))
                     for k, v in json['result'].items())


class LocalBitcoins(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('localbitcoins.com',
                             '/bitcoinaverage/ticker-all-currencies/')
        return dict([(r, Decimal(json[r]['rates']['last'])) for r in json])


class MercadoBitcoin(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.bitvalor.com', '/v1/ticker.json')
        return {'BRL': Decimal(json['ticker_1h']['exchanges']['MBT']['last'])}


class NegocieCoins(ExchangeBase):

    async def get_rates(self,ccy):
        json = await self.get_json('api.bitvalor.com', '/v1/ticker.json')
        return {'BRL': Decimal(json['ticker_1h']['exchanges']['NEG']['last'])}

class TheRockTrading(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.therocktrading.com',
                             '/v1/funds/BTCEUR/ticker')
        return {'EUR': Decimal(json['last'])}


class Winkdex(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('winkdex.com', '/api/v0/price')
        return {'USD': Decimal(json['price'] / 100.0)}

    def history_ccys(self):
        return ['USD']

    async def request_history(self, ccy):
        json = await self.get_json('winkdex.com',
                             "/api/v0/series?start_time=1342915200")
        history = json['series'][0]['results']
        return dict([(h['timestamp'][:10], h['price'] / 100.0)
                     for h in history])


class Zaif(ExchangeBase):
    async def get_rates(self, ccy):
        json = await self.get_json('api.zaif.jp', '/api/1/last_price/btc_jpy')
        return {'JPY': Decimal(json['last_price'])}


def dictinvert(d):
    inv = {}
    for k, vlist in d.items():
        for v in vlist:
            keys = inv.setdefault(v, [])
            keys.append(k)
    return inv

def get_exchanges_and_currencies():
    # load currencies.json from disk
    path = resource_path('currencies.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.loads(f.read())
    except:
        pass
    # or if not present, generate it now.
    print("cannot find currencies.json. will regenerate it now.")
    d = {}
    is_exchange = lambda obj: (inspect.isclass(obj)
                               and issubclass(obj, ExchangeBase)
                               and obj != ExchangeBase)
    exchanges = dict(inspect.getmembers(sys.modules[__name__], is_exchange))

    async def get_currencies_safe(name, exchange):
        try:
            d[name] = await exchange.get_currencies()
            print(name, "ok")
        except:
            print(name, "error")

    async def query_all_exchanges_for_their_ccys_over_network():
        async with timeout_after(10):
            async with TaskGroup() as group:
                for name, klass in exchanges.items():
                    exchange = klass(None, None)
                    await group.spawn(get_currencies_safe(name, exchange))
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(query_all_exchanges_for_their_ccys_over_network())
    except Exception as e:
        pass
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
        ThreadJob.__init__(self)
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
            # approx. every 2.5 minutes, refresh spot price
            try:
                async with timeout_after(150):
                    await self._trigger.wait()
                    self._trigger.clear()
                # we were manually triggered, so get historical rates
                if self.is_enabled() and self.show_history():
                    self.exchange.get_historical_rates(self.ccy, self.cache_dir)
            except TaskTimeout:
                pass
            if self.is_enabled():
                await self.exchange.update_safe(self.ccy)

    def is_enabled(self):
        return bool(self.config.get('use_exchange_rate', DEFAULT_ENABLED))

    def set_enabled(self, b):
        self.config.set_key('use_exchange_rate', bool(b))
        self.trigger_update()

    def get_history_config(self, *, default=False):
        return bool(self.config.get('history_rates', default))

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
        return self.config.get("currency", DEFAULT_CURRENCY)

    def config_exchange(self):
        return self.config.get('use_exchange', DEFAULT_EXCHANGE)

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
        class_ = globals().get(name) or globals().get(DEFAULT_EXCHANGE)
        self.logger.info(f"using exchange {name}")
        if self.config_exchange() != name:
            self.config.set_key('use_exchange', name, True)
        assert issubclass(class_, ExchangeBase), f"unexpected type {class_} for {name}"
        self.exchange = class_(self.on_quotes, self.on_history)  # type: ExchangeBase
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
            if rate is None:
                rate = 'NaN'
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


assert globals().get(DEFAULT_EXCHANGE), f"default exchange {DEFAULT_EXCHANGE} does not exist"
