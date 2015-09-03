# -*- encoding: utf8 -*-

'''Module exchange_rate:

This module is responsible for getting the conversion rates from different
bitcoin exchanges.
'''

import decimal
import json

from kivy.network.urlrequest import UrlRequest
from kivy.event import EventDispatcher
from kivy.properties import (OptionProperty, StringProperty, AliasProperty,
    ListProperty)
from kivy.clock import Clock
from kivy.cache import Cache

# Register local cache
Cache.register('history_rate', timeout=220)

EXCHANGES = ["BitcoinAverage",
             "BitcoinVenezuela",
             "BitPay",
             "Blockchain",
             "BTCChina",
             "CaVirtEx",
             "Coinbase",
             "CoinDesk",
             "LocalBitcoins",
             "Winkdex"]

HISTORY_EXCHNAGES = ['Coindesk',
                     'Winkdex',
                     'BitcoinVenezuela']


class Exchanger(EventDispatcher):
    ''' Provide exchanges rate between crypto and different national
    currencies. See Module Documentation for details.
    '''

    symbols = {'ALL': u'Lek', 'AED': u'د.إ', 'AFN':u'؋', 'ARS': u'$',
        'AMD': u'֏', 'AWG': u'ƒ', 'ANG': u'ƒ', 'AOA': u'Kz', 'BDT': u'৳',
        'BHD': u'BD', 'BIF': u'FBu', 'BTC': u'BTC', 'BTN': u'Nu', 'CDF': u'FC',
        'CHF': u'CHF', 'CLF': u'UF', 'CLP':u'$', 'CVE': u'$', 'DJF':u'Fdj',
        'DZD': u'دج', 'AUD': u'$', 'AZN': u'ман', 'BSD': u'$', 'BBD': u'$',
        'BYR': u'p', 'CRC': u'₡', 'BZD': u'BZ$', 'BMD': u'$', 'BOB': u'$b',
        'BAM': u'KM', 'BWP': u'P', 'BGN': 'uлв', 'BRL': u'R$', 'BND': u'$',
        'KHR': u'៛', 'CAD': u'$', 'ERN': u'Nfk', 'ETB': u'Br', 'KYD': u'$',
        'USD': u'$', 'CLP': u'$', 'HRK': u'kn', 'CUP': u'₱', 'CZK': u'Kč',
        'DKK': u'kr', 'DOP': u'RD$', 'XCD': u'$', 'EGP': u'£', 'SVC': u'$' ,
        'EEK': u'kr', 'EUR': u'€', u'FKP': u'£', 'FJD': u'$', 'GHC': u'¢',
        'GIP': u'£', 'GTQ': u'Q', 'GBP': u'£', 'GYD': u'$', 'HNL': u'L',
        'HKD': u'$', 'HUF': u'Ft', 'ISK': u'kr', 'INR': u'₹', 'IDR': u'Rp',
        'IRR': u'﷼', 'IMP': '£', 'ILS': '₪', 'COP': '$', 'JMD': u'J$',
        'JPY': u'¥', 'JEP': u'£', 'KZT': u'лв', 'KPW': u'₩', 'KRW': u'₩',
        'KGS': u'лв', 'LAK': u'₭', 'LVL': u'Ls', 'CNY': u'¥'}

    _use_exchange = OptionProperty('Blockchain', options=EXCHANGES)
    '''This is the exchange to be used for getting the currency exchange rates
    '''

    _currency = StringProperty('EUR')
    '''internal use only
    '''

    def _set_currency(self, value):
        value = str(value)
        if self.use_exchange == 'CoinDesk':
            self._update_cd_currency(self.currency)
            return
        self._currency = value
        self.parent.electrum_config.set_key('currency', value, True)

    def _get_currency(self):
        self._currency = self.parent.electrum_config.get('currency', 'EUR')
        return self._currency

    currency = AliasProperty(_get_currency, _set_currency, bind=('_currency',))

    currencies = ListProperty(['EUR', 'GBP', 'USD'])
    '''List of currencies supported by the current exchanger plugin.

    :attr:`currencies` is a `ListProperty` default to ['Eur', 'GBP'. 'USD'].
    '''

    def _get_useex(self):
        if not self.parent:
            return self._use_exchange

        self._use_exchange = self.parent.electrum_config.get('use_exchange',
                                                             'Blockchain')
        return self._use_exchange

    def _set_useex(self, value):
        if not self.parent:
            return self._use_exchange
        self.parent.electrum_config.set_key('use_exchange', value, True)
        self._use_exchange = value

    use_exchange = AliasProperty(_get_useex, _set_useex,
                                 bind=('_use_exchange', ))

    def __init__(self, parent):
        super(Exchanger, self).__init__()
        self.parent = parent
        self.quote_currencies = None
        self.exchanges = EXCHANGES
        self.history_exchanges = HISTORY_EXCHNAGES

    def exchange(self, btc_amount, quote_currency):
        if self.quote_currencies is None:
            return None

        quote_currencies = self.quote_currencies.copy()
        if quote_currency not in quote_currencies:
            return None

        return btc_amount * decimal.Decimal(quote_currencies[quote_currency])

    def get_history_rate(self, item, btc_amt, mintime, maxtime):
        def on_success(request, response):
            response = json.loads(response)

            try:
                hrate = response['bpi'][mintime]
                hrate = abs(btc_amt) * decimal.Decimal(hrate)
                Cache.append('history_rate', uid, hrate)
            except KeyError:
                hrate = 'not found'

            self.parent.set_history_rate(item, hrate)

        # Check local cache before getting data from remote
        exchange = 'coindesk'
        uid = '{}:{}'.format(exchange, mintime)
        hrate = Cache.get('history_rate', uid)

        if hrate:
            return hrate

        req = UrlRequest(url='https://api.coindesk.com/v1/bpi/historical'
                         '/close.json?start={}&end={}'
                         .format(mintime, maxtime)
            ,on_success=on_success, timeout=15)
        return None

    def update_rate(self, dt):
        ''' This is called from :method:`start` every X seconds; to update the
        rates for currencies for the currently selected exchange.
        '''
        if not self.parent.network or not self.parent.network.is_connected():
            return

        # temporarily disabled
        return

        update_rates = {
            "BitcoinAverage": self.update_ba,
            "BitcoinVenezuela": self.update_bv,
            "BitPay": self.update_bp,
            "Blockchain": self.update_bc,
            "BTCChina": self.update_CNY,
            "CaVirtEx": self.update_cv,
            "CoinDesk": self.update_cd,
            "Coinbase": self.update_cb,
            "LocalBitcoins": self.update_lb,
            "Winkdex": self.update_wd,
        }
        try:
            update_rates[self.use_exchange]()
        except KeyError:
            return

    def update_wd(self):

        def on_success(request, response):
            response = json.loads(response)
            quote_currencies = {'USD': 0.0}
            lenprices = len(response["prices"])
            usdprice = response['prices'][lenprices-1]['y']

            try:
                quote_currencies["USD"] = decimal.Decimal(usdprice)
            except KeyError:
                pass

            self.quote_currencies = quote_currencies
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(
            url='https://winkdex.com/static/data/0_600_288.json',
                        on_success=on_success,
                        timeout=5)

    def update_cd_currency(self, currency):

        def on_success(request, response):
            response = json.loads(response)
            quote_currencies = self.quote_currencies
            quote_currencies[currency] =\
                str(response['bpi'][str(currency)]['rate_float'])
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(
            url='https://api.coindesk.com/v1/bpi/currentprice/'\
                + str(currency) + '.json',on_success=on_success, timeout=5)

    def update_cd(self):

        def on_success(request, response):
            quote_currencies = {}
            response = json.loads(response)

            for cur in response:
                quote_currencies[str(cur["currency"])] = 0.0

            self.quote_currencies = quote_currencies
            self.update_cd_currency(self.currency)

        req = UrlRequest(
            url='https://api.coindesk.com/v1/bpi/supported-currencies.json',
                        on_success=on_success,
                        timeout=5)

    def update_cv(self):
        def on_success(request, response):
            response = json.loads(response)
            quote_currencies = {"CAD": 0.0}
            cadprice = response["last"]
            try:
                quote_currencies["CAD"] = decimal.Decimal(cadprice)
                self.quote_currencies = quote_currencies
            except KeyError:
                pass
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(url='https://www.cavirtex.com/api/CAD/ticker.json',
                        on_success=on_success,
                        timeout=5)

    def update_CNY(self):

        def on_success(request, response):
            quote_currencies = {"CNY": 0.0}
            cnyprice = response["ticker"]["last"]
            try:
                quote_currencies["CNY"] = decimal.Decimal(cnyprice)
                self.quote_currencies = quote_currencies
            except KeyError:
                pass
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(url='https://data.btcchina.com/data/ticker',
                        on_success=on_success,
                        timeout=5)

    def update_bp(self):

        def on_success(request, response):
            quote_currencies = {}
            try:
                for r in response:
                    quote_currencies[str(r['code'])] = decimal.Decimal(r['rate'])
                self.quote_currencies = quote_currencies
            except KeyError:
                pass
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(url='https://bitpay.com/api/rates',
                        on_success=on_success,
                        timeout=5)

    def update_cb(self):

        def _lookup_rate(response, quote_id):
            return decimal.Decimal(str(response[str(quote_id)]))

        def on_success(request, response):
            quote_currencies = {}
            try:
                for r in response:
                    if r[:7] == "btc_to_":
                        quote_currencies[r[7:].upper()] =\
                            _lookup_rate(response, r)
                self.quote_currencies = quote_currencies
            except KeyError:
                pass
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(
            url='https://coinbase.com/api/v1/currencies/exchange_rates',
            on_success=on_success,
            timeout=5)

    def update_bc(self):

        def _lookup_rate(response, quote_id):
            return decimal.Decimal(str(response[str(quote_id)]["15m"]))

        def on_success(request, response):
            quote_currencies = {}
            try:
                for r in response:
                    quote_currencies[r] = _lookup_rate(response, r)
                self.quote_currencies = quote_currencies
            except KeyError, TypeError:
                pass
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(url='https://blockchain.info/ticker',
                        on_success=on_success,
                        timeout=5)

    def update_lb(self):
        def _lookup_rate(response, quote_id):
            return decimal.Decimal(response[str(quote_id)]["rates"]["last"])

        def on_success(request, response):
            quote_currencies = {}
            try:
                for r in response:
                    quote_currencies[r] = _lookup_rate(response, r)
                self.quote_currencies = quote_currencies
            except KeyError:
                pass
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(
            url='https://localbitcoins.com/bitcoinaverage/ticker-all-currencies/',
            on_success=on_success,
            timeout=5)


    def update_ba(self):

        def on_success(request, response):
            quote_currencies = {}
            try:
                for r in response:
                    quote_currencies[r] = decimal.Decimal(response[r][u'last'])
                self.quote_currencies = quote_currencies
            except TypeError:
                pass
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(url='https://api.bitcoinaverage.com/ticker/global/all',
                        on_success=on_success,
                        timeout=5)

    def update_bv(self):

        def on_success(request, response):
            quote_currencies = {}
            try:
                for r in response["BTC"]:
                    quote_currencies[r] = decimal.Decimal(response['BTC'][r])
                self.quote_currencies = quote_currencies
            except KeyError:
                pass
            self.parent.set_currencies(quote_currencies)

        req = UrlRequest(url='https://api.bitcoinvenezuela.com/',
                        on_success=on_success,
                        timeout=5)

    def start(self):
        self.update_rate(0)
        # check every 20 seconds
        Clock.unschedule(self.update_rate)
        Clock.schedule_interval(self.update_rate, 20)

    def stop(self):
        Clock.unschedule(self.update_rate)

