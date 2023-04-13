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
from typing import Sequence, Optional, Mapping, Dict, Union, Any

from aiorpcx.curio import timeout_after, TaskTimeout
import aiohttp

from . import util
from .bitcoin import COIN
from .i18n import _
from .util import (ThreadJob, make_dir, log_exceptions, OldTaskGroup,
                   make_aiohttp_session, resource_path, EventListener, event_listener, to_decimal)
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
                  'VUV': 0, 'XAF': 0, 'XAU': 4, 'XOF': 0, 'XPF': 0,
                  # Cryptocurrencies
                  'BTC': 8, 'LTC': 8, 'XRP': 6, 'ETH': 18,
                  }

POLL_PERIOD_SPOT_RATE = 150  # approx. every 2.5 minutes, try to refresh spot price
EXPIRY_SPOT_RATE = 600       # spot price becomes stale after 10 minutes


class ExchangeBase(Logger):

    def __init__(self, on_quotes, on_history):
        Logger.__init__(self)
        self._history = {}  # type: Dict[str, Dict[str, str]]
        self._quotes = {}  # type: Dict[str, Optional[Decimal]]
        self._quotes_timestamp = 0  # type: Union[int, float]
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

    async def update_safe(self, ccy: str) -> None:
        try:
            self.logger.info(f"getting fx quotes for {ccy}")
            self._quotes = await self.get_rates(ccy)
            assert all(isinstance(rate, (Decimal, type(None))) for rate in self._quotes.values()), \
                f"fx rate must be Decimal, got {self._quotes}"
            self._quotes_timestamp = time.time()
            self.logger.info("received fx quotes")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.logger.info(f"failed fx quotes: {repr(e)}")
        except Exception as e:
            self.logger.exception(f"failed fx quotes: {repr(e)}")
        self.on_quotes()

    def read_historical_rates(self, ccy: str, cache_dir: str) -> Optional[dict]:
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
        # cast rates to str
        h = {date_str: str(rate) for (date_str, rate) in h.items()}
        h['timestamp'] = timestamp
        self._history[ccy] = h
        self.on_history()
        return h

    @log_exceptions
    async def get_historical_rates_safe(self, ccy: str, cache_dir: str) -> None:
        try:
            self.logger.info(f"requesting fx history for {ccy}")
            h = await self.request_history(ccy)
            self.logger.info(f"received fx history for {ccy}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.logger.info(f"failed fx history: {repr(e)}")
            return
        except Exception as e:
            self.logger.exception(f"failed fx history: {repr(e)}")
            return
        # cast rates to str
        h = {date_str: str(rate) for (date_str, rate) in h.items()}
        filename = os.path.join(cache_dir, self.name() + '_' + ccy)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(json.dumps(h))
        h['timestamp'] = time.time()
        self._history[ccy] = h
        self.on_history()

    def get_historical_rates(self, ccy: str, cache_dir: str) -> None:
        if ccy not in self.history_ccys():
            return
        h = self._history.get(ccy)
        if h is None:
            h = self.read_historical_rates(ccy, cache_dir)
        if h is None or h['timestamp'] < time.time() - 24*3600:
            util.get_asyncio_loop().create_task(self.get_historical_rates_safe(ccy, cache_dir))

    def history_ccys(self) -> Sequence[str]:
        return []

    def historical_rate(self, ccy: str, d_t: datetime) -> Decimal:
        date_str = d_t.strftime('%Y-%m-%d')
        rate = self._history.get(ccy, {}).get(date_str) or 'NaN'
        try:
            return Decimal(rate)
        except Exception:  # guard against garbage coming from exchange
            #self.logger.debug(f"found corrupted historical_rate: {rate=!r}. for {ccy=} at {date_str}")
            return Decimal('NaN')

    async def request_history(self, ccy: str) -> Dict[str, Union[str, float]]:
        raise NotImplementedError()  # implemented by subclasses

    async def get_rates(self, ccy: str) -> Mapping[str, Optional[Decimal]]:
        raise NotImplementedError()  # implemented by subclasses

    async def get_currencies(self) -> Sequence[str]:
        rates = await self.get_rates('')
        return sorted([str(a) for (a, b) in rates.items() if b is not None and len(a)==3])

    def get_cached_spot_quote(self, ccy: str) -> Decimal:
        """Returns the cached exchange rate as a Decimal"""
        if ccy == 'BTC':
            return Decimal(1)
        rate = self._quotes.get(ccy)
        if rate is None:
            return Decimal('NaN')
        if self._quotes_timestamp + EXPIRY_SPOT_RATE < time.time():
            # Our rate is stale. Probably better to return no rate than an incorrect one.
            return Decimal('NaN')
        return Decimal(rate)

class Yadio(ExchangeBase):

    async def get_currencies(self):
        dicts = await self.get_json('api.yadio.io', '/currencies')
        return list(dicts.keys())

    async def get_rates(self, ccy: str) -> Mapping[str, Optional[Decimal]]:
        json = await self.get_json('api.yadio.io', '/rate/%s/BTC' % ccy)
        return {ccy: to_decimal(json['rate'])}

class BitcoinAverage(ExchangeBase):
    # note: historical rates used to be freely available
    # but this is no longer the case. see #5188

    async def get_rates(self, ccy):
        json = await self.get_json('apiv2.bitcoinaverage.com', '/indices/global/ticker/short')
        return dict([(r.replace("BTC", ""), to_decimal(json[r]['last']))
                     for r in json if r != 'timestamp'])


class Bitcointoyou(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('bitcointoyou.com', "/API/ticker.aspx")
        return {'BRL': to_decimal(json['ticker']['last'])}


class BitcoinVenezuela(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.bitcoinvenezuela.com', '/')
        rates = [(r, to_decimal(json['BTC'][r])) for r in json['BTC']
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
        return {'JPY': to_decimal(json['data']['last'])}


class BitFlyer(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('bitflyer.jp', '/api/echo/price')
        return {'JPY': to_decimal(json['mid'])}


class BitPay(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('bitpay.com', '/api/rates')
        return dict([(r['code'], to_decimal(r['rate'])) for r in json])


class Bitso(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.bitso.com', '/v2/ticker')
        return {'MXN': to_decimal(json['last'])}


class BitStamp(ExchangeBase):

    async def get_currencies(self):
        return ['USD', 'EUR']

    async def get_rates(self, ccy):
        if ccy in CURRENCIES[self.name()]:
            json = await self.get_json('www.bitstamp.net', f'/api/v2/ticker/btc{ccy.lower()}/')
            return {ccy: to_decimal(json['last'])}
        return {}


class Bitvalor(ExchangeBase):

    async def get_rates(self,ccy):
        json = await self.get_json('api.bitvalor.com', '/v1/ticker.json')
        return {'BRL': to_decimal(json['ticker_1h']['total']['last'])}


class BlockchainInfo(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('blockchain.info', '/ticker')
        return dict([(r, to_decimal(json[r]['15m'])) for r in json])


class Bylls(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('bylls.com', '/api/price?from_currency=BTC&to_currency=CAD')
        return {'CAD': to_decimal(json['public_price']['to_price'])}


class Coinbase(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.coinbase.com',
                             '/v2/exchange-rates?currency=BTC')
        return {ccy: to_decimal(rate) for (ccy, rate) in json["data"]["rates"].items()}


class CoinCap(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.coincap.io', '/v2/rates/bitcoin/')
        return {'USD': to_decimal(json['data']['rateUsd'])}

    def history_ccys(self):
        return ['USD']

    async def request_history(self, ccy):
        # Currently 2000 days is the maximum in 1 API call
        # (and history starts on 2017-03-23)
        history = await self.get_json('api.coincap.io',
                                      '/v2/assets/bitcoin/history?interval=d1&limit=2000')
        return dict([(datetime.utcfromtimestamp(h['time']/1000).strftime('%Y-%m-%d'), str(h['priceUsd']))
                     for h in history['data']])


class CoinDesk(ExchangeBase):

    async def get_currencies(self):
        dicts = await self.get_json('api.coindesk.com',
                              '/v1/bpi/supported-currencies.json')
        return [d['currency'] for d in dicts]

    async def get_rates(self, ccy):
        json = await self.get_json('api.coindesk.com',
                             '/v1/bpi/currentprice/%s.json' % ccy)
        result = {ccy: to_decimal(json['bpi'][ccy]['rate_float'])}
        return result

    def history_starts(self):
        return {'USD': '2012-11-30', 'EUR': '2013-09-01'}

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
        return dict([(ccy.upper(), to_decimal(d['value']))
                     for ccy, d in json['rates'].items()])

    def history_ccys(self):
        # CoinGecko seems to have historical data for all ccys it supports
        return CURRENCIES[self.name()]

    async def request_history(self, ccy):
        history = await self.get_json('api.coingecko.com',
                                      '/api/v3/coins/bitcoin/market_chart?vs_currency=%s&days=max' % ccy)

        return dict([(datetime.utcfromtimestamp(h[0]/1000).strftime('%Y-%m-%d'), str(h[1]))
                     for h in history['prices']])


class CointraderMonitor(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('cointradermonitor.com', '/api/pbb/v1/ticker')
        return {'BRL': to_decimal(json['last'])}


class itBit(ExchangeBase):

    async def get_rates(self, ccy):
        ccys = ['USD', 'EUR', 'SGD']
        json = await self.get_json('api.itbit.com', '/v1/markets/XBT%s/ticker' % ccy)
        result = dict.fromkeys(ccys)
        if ccy in ccys:
            result[ccy] = to_decimal(json['lastPrice'])
        return result


class Kraken(ExchangeBase):

    async def get_rates(self, ccy):
        ccys = ['EUR', 'USD', 'CAD', 'GBP', 'JPY']
        pairs = ['XBT%s' % c for c in ccys]
        json = await self.get_json('api.kraken.com',
                             '/0/public/Ticker?pair=%s' % ','.join(pairs))
        return dict((k[-3:], to_decimal(v['c'][0]))
                     for k, v in json['result'].items())


class LocalBitcoins(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('localbitcoins.com',
                             '/bitcoinaverage/ticker-all-currencies/')
        return dict([(r, to_decimal(json[r]['rates']['last'])) for r in json])


class MercadoBitcoin(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.bitvalor.com', '/v1/ticker.json')
        return {'BRL': to_decimal(json['ticker_1h']['exchanges']['MBT']['last'])}


class TheRockTrading(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('api.therocktrading.com',
                             '/v1/funds/BTCEUR/ticker')
        return {'EUR': to_decimal(json['last'])}


class Winkdex(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('winkdex.com', '/api/v0/price')
        return {'USD': to_decimal(json['price']) / 100}

    def history_ccys(self):
        return ['USD']

    async def request_history(self, ccy):
        json = await self.get_json('winkdex.com',
                             "/api/v0/series?start_time=1342915200")
        history = json['series'][0]['results']
        return dict([(h['timestamp'][:10], str(to_decimal(h['price']) / 100))
                     for h in history])


class Zaif(ExchangeBase):
    async def get_rates(self, ccy):
        json = await self.get_json('api.zaif.jp', '/api/1/last_price/btc_jpy')
        return {'JPY': to_decimal(json['last_price'])}


class Bitragem(ExchangeBase):

    async def get_rates(self,ccy):
        json = await self.get_json('api.bitragem.com', '/v1/index?asset=BTC&market=BRL')
        return {'BRL': to_decimal(json['response']['index'])}


class Biscoint(ExchangeBase):

    async def get_rates(self,ccy):
        json = await self.get_json('api.biscoint.io', '/v1/ticker?base=BTC&quote=BRL')
        return {'BRL': to_decimal(json['data']['last'])}


class Walltime(ExchangeBase):

    async def get_rates(self, ccy):
        json = await self.get_json('s3.amazonaws.com',
                             '/data-production-walltime-info/production/dynamic/walltime-info.json')
        return {'BRL': to_decimal(json['BRL_XBT']['last_inexact'])}


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
            async with OldTaskGroup() as group:
                for name, klass in exchanges.items():
                    exchange = klass(None, None)
                    await group.spawn(get_currencies_safe(name, exchange))
    loop = util.get_asyncio_loop()
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


class FxThread(ThreadJob, EventListener):

    def __init__(self, *, config: SimpleConfig):
        ThreadJob.__init__(self)
        self.config = config
        self.register_callbacks()
        self.ccy = self.get_currency()
        self.history_used_spot = False
        self.ccy_combo = None
        self.hist_checkbox = None
        self.cache_dir = os.path.join(config.path, 'cache')  # type: str
        self._trigger = asyncio.Event()
        self._trigger.set()
        self.set_exchange(self.config_exchange())
        make_dir(self.cache_dir)

    @event_listener
    def on_event_proxy_set(self, *args):
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
    def remove_thousands_separator(text: str) -> str:
        return text.replace(util.THOUSANDS_SEP, "")

    def ccy_amount_str(self, amount, *, add_thousands_sep: bool = False, ccy=None) -> str:
        prec = CCY_PRECISIONS.get(self.ccy if ccy is None else ccy, 2)
        fmt_str = "{:%s.%df}" % ("," if add_thousands_sep else "", max(0, prec))
        try:
            rounded_amount = round(amount, prec)
        except decimal.InvalidOperation:
            rounded_amount = amount
        text = fmt_str.format(rounded_amount)
        # replace "," -> THOUSANDS_SEP
        # replace "." -> DECIMAL_POINT
        dp_loc = text.find(".")
        text = text.replace(",", util.THOUSANDS_SEP)
        if dp_loc == -1:
            return text
        return text[:dp_loc] + util.DECIMAL_POINT + text[dp_loc+1:]

    async def run(self):
        while True:
            # every few minutes, refresh spot price
            try:
                async with timeout_after(POLL_PERIOD_SPOT_RATE):
                    await self._trigger.wait()
                    self._trigger.clear()
                # we were manually triggered, so get historical rates
                if self.is_enabled() and self.has_history():
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

    def can_have_history(self):
        return self.is_enabled() and self.ccy in self.exchange.history_ccys()

    def has_history(self):
        return self.can_have_history() and self.config.get('history_rates', False)

    def get_currency(self) -> str:
        '''Use when dynamic fetching is needed'''
        return self.config.get("currency", DEFAULT_CURRENCY)

    def config_exchange(self):
        return self.config.get('use_exchange', DEFAULT_EXCHANGE)

    def set_currency(self, ccy: str):
        self.ccy = ccy
        self.config.set_key('currency', ccy, True)
        self.trigger_update()
        self.on_quotes()

    def trigger_update(self):
        loop = util.get_asyncio_loop()
        loop.call_soon_threadsafe(self._trigger.set)

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
        util.trigger_callback('on_quotes')

    def on_history(self):
        util.trigger_callback('on_history')

    def exchange_rate(self) -> Decimal:
        """Returns the exchange rate as a Decimal"""
        if not self.is_enabled():
            return Decimal('NaN')
        return self.exchange.get_cached_spot_quote(self.ccy)

    def format_amount(self, btc_balance, *, timestamp: int = None) -> str:
        if timestamp is None:
            rate = self.exchange_rate()
        else:
            rate = self.timestamp_rate(timestamp)
        return '' if rate.is_nan() else "%s" % self.value_str(btc_balance, rate)

    def format_amount_and_units(self, btc_balance, *, timestamp: int = None) -> str:
        if timestamp is None:
            rate = self.exchange_rate()
        else:
            rate = self.timestamp_rate(timestamp)
        return '' if rate.is_nan() else "%s %s" % (self.value_str(btc_balance, rate), self.ccy)

    def get_fiat_status_text(self, btc_balance, base_unit, decimal_point):
        rate = self.exchange_rate()
        if rate.is_nan():
            return _("  (No FX rate available)")
        amount = 1000 if decimal_point == 0 else 1
        value = self.value_str(amount * COIN / (10**(8 - decimal_point)), rate)
        return " %d %s~%s %s" % (amount, base_unit, value, self.ccy)

    def fiat_value(self, satoshis, rate) -> Decimal:
        return Decimal('NaN') if satoshis is None else Decimal(satoshis) / COIN * Decimal(rate)

    def value_str(self, satoshis, rate) -> str:
        return self.format_fiat(self.fiat_value(satoshis, rate))

    def format_fiat(self, value: Decimal) -> str:
        if value.is_nan():
            return _("No data")
        return self.ccy_amount_str(value, add_thousands_sep=True)

    def history_rate(self, d_t: Optional[datetime]) -> Decimal:
        if d_t is None:
            return Decimal('NaN')
        rate = self.exchange.historical_rate(self.ccy, d_t)
        # Frequently there is no rate for today, until tomorrow :)
        # Use spot quotes in that case
        if rate.is_nan() and (datetime.today().date() - d_t.date()).days <= 2:
            rate = self.exchange.get_cached_spot_quote(self.ccy)
            self.history_used_spot = True
        if rate is None:
            rate = 'NaN'
        return Decimal(rate)

    def historical_value_str(self, satoshis, d_t: Optional[datetime]) -> str:
        return self.format_fiat(self.historical_value(satoshis, d_t))

    def historical_value(self, satoshis, d_t: Optional[datetime]) -> Decimal:
        return self.fiat_value(satoshis, self.history_rate(d_t))

    def timestamp_rate(self, timestamp: Optional[int]) -> Decimal:
        from .util import timestamp_to_datetime
        date = timestamp_to_datetime(timestamp)
        return self.history_rate(date)


assert globals().get(DEFAULT_EXCHANGE), f"default exchange {DEFAULT_EXCHANGE} does not exist"
