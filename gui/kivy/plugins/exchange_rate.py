# -*- encoding: utf8 -*-

'''Module exchange_rate:

This module is responsible for getting the conversion rates from different
bitcoin exchanges.
'''

from kivy.network.urlrequest import UrlRequest
from kivy.event import EventDispatcher
from kivy.properties import (OptionProperty, StringProperty, AliasProperty,
    ListProperty)
from kivy.clock import Clock
import decimal
import json

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


class Exchanger(EventDispatcher):
    ''' Provide exchanges rate between crypto and different national
    currencies. See Module Documentation for details.
    '''

    symbols = {'ALL': 'Lek', 'AED': 'د.إ', 'AFN':'؋', 'ARS': '$', 'AMD': '֏',
        'AWG': 'ƒ', 'ANG': 'ƒ', 'AOA': 'Kz', 'BDT': '৳', 'BHD': 'BD',
        'BIF': 'FBu', 'BTC': 'BTC', 'BTN': 'Nu', 'CDF': 'FC', 'CHF': 'CHF',
        'CLF': 'UF', 'CLP':'$', 'CVE': '$', 'DJF':'Fdj', 'DZD': 'دج',
        'AUD': '$', 'AZN': 'ман', 'BSD': '$', 'BBD': '$', 'BYR': 'p', 'CRC': '₡',
        'BZD': 'BZ$', 'BMD': '$', 'BOB': '$b', 'BAM': 'KM', 'BWP': 'P',
        'BGN': 'лв', 'BRL': 'R$', 'BND': '$', 'KHR': '៛', 'CAD': '$',
        'ERN': 'Nfk', 'ETB': 'Br', 'KYD': '$', 'USD': '$', 'CLP': '$',
        'HRK': 'kn', 'CUP':'₱', 'CZK': 'Kč', 'DKK': 'kr', 'DOP': 'RD$',
        'XCD': '$', 'EGP': '£', 'SVC': '$' , 'EEK': 'kr', 'EUR': '€',
        'FKP': '£', 'FJD': '$', 'GHC': '¢', 'GIP': '£', 'GTQ': 'Q', 'GBP': '£',
        'GYD': '$', 'HNL': 'L', 'HKD': '$', 'HUF': 'Ft', 'ISK': 'kr',
        'INR': '₹', 'IDR': 'Rp', 'IRR': '﷼', 'IMP': '£', 'ILS': '₪', 'COP': '$',
        'JMD': 'J$', 'JPY': '¥', 'JEP': '£', 'KZT': 'лв', 'KPW': '₩',
        'KRW': '₩', 'KGS': 'лв', 'LAK': '₭', 'LVL': 'Ls', 'CNY': '¥'}

    _use_exchange = OptionProperty('Blockchain', options=EXCHANGES)
    '''This is the exchange to be used for getting the currency exchange rates
    '''

    _currency = StringProperty('EUR')
    '''internal use only
    '''

    def _set_currency(self, value):
        exchanger = self.exchanger
        if self.use_exchange == 'CoinDesk':
            self._update_cd_currency(self.currency)
            return
        try:
            self._currency = value
            self.electrum_cinfig.set_key('currency', value, True)
        except AttributeError:
            self._currency = 'EUR'

    def _get_currency(self):
        try:
            self._currency = self.electrum_config.get('currency', 'EUR')
        except AttributeError:
            pass
        finally:
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

    def exchange(self, btc_amount, quote_currency):
        if self.quote_currencies is None:
            return None

        quote_currencies = self.quote_currencies.copy()
        if quote_currency not in quote_currencies:
            return None

        return btc_amount * decimal.Decimal(quote_currencies[quote_currency])

    def update_rate(self, dt):
        ''' This is called from :method:`start` every X seconds; to update the
        rates for currencies for the currently selected exchange.
        '''
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
            except KeyError:
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
        # check rates every few seconds
        self.update_rate(0)
        # check every few seconds
        Clock.unschedule(self.update_rate)
        Clock.schedule_interval(self.update_rate, 20)

    def stop(self):
        Clock.unschedule(self.update_rate)

