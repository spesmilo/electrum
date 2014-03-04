# -*- encoding: utf8 -*-

'''Module exchange_rate:

This module is responsible for getting the conversion rates between different
currencies.
'''

from kivy.network.urlrequest import UrlRequest
#kivy.event import EventDispatcher
from kivy.clock import Clock
import decimal
import json

class Exchanger(object):
    '''
    '''

    symbols = {'ALL': 'Lek', 'AED': 'د.إ', 'AFN':'؋', 'ARS': '$', 'AMD': '֏',
        'AWG': 'ƒ', 'ANG': 'ƒ', 'AOA': 'Kz', 'BDT': '৳', 'BHD': 'BD',
        'BIF': 'FBu', 'BTC': 'BTC', 'BTN': 'Nu',
        'AUD': '$', 'AZN': 'ман', 'BSD': '$', 'BBD': '$', 'BYR': 'p',
        'BZD': 'BZ$', 'BMD': '$', 'BOB': '$b', 'BAM': 'KM', 'BWP': 'P',
        'BGN': 'лв', 'BRL': 'R$', 'BND': '$', 'KHR': '៛', 'CAD': '$',
        'KYD': '$', 'USD': '$', 'CLP': '$', 'CNY': '¥', 'COP': '$', 'CRC': '₡',
        'HRK': 'kn', 'CUP':'₱', 'CZK': 'Kč', 'DKK': 'kr', 'DOP': 'RD$',
        'XCD': '$', 'EGP': '£', 'SVC': '$' , 'EEK': 'kr', 'EUR': '€',
        'FKP': '£', 'FJD': '$', 'GHC': '¢', 'GIP': '£', 'GTQ': 'Q', 'GBP': '£',
        'GYD': '$', 'HNL': 'L', 'HKD': '$', 'HUF': 'Ft', 'ISK': 'kr',
        'INR': '₹', 'IDR': 'Rp', 'IRR': '﷼', 'IMP': '£', 'ILS': '₪',
        'JMD': 'J$', 'JPY': '¥', 'JEP': '£', 'KZT': 'лв', 'KPW': '₩',
        'KRW': '₩', 'KGS': 'лв', 'LAK': '₭', 'LVL': 'Ls'}

    def __init__(self, parent):
        self.parent = parent
        self.quote_currencies = None
        self.exchanges = ('BlockChain', 'Coinbase', 'CoinDesk')
        try:
            self.use_exchange =  parent.electrum_config.get('use_exchange',
                                                            'BlockChain')
        except AttributeError:
            self.use_exchange = 'BlockChain'
        self.currencies = self.symbols.keys()

    def exchange(self, btc_amount, quote_currency):
        if self.quote_currencies is None:
            return None
        quote_currencies = self.quote_currencies.copy()
        if quote_currency not in quote_currencies:
            return None
        if self.use_exchange == "CoinDesk":
            try:
                connection = httplib.HTTPSConnection('api.coindesk.com')
                connection.request("GET", "/v1/bpi/currentprice/" + str(quote_currency) + ".json")
            except Exception:
                return
            resp = connection.getresponse()
            if resp.reason == httplib.responses[httplib.NOT_FOUND]:
                return
            try:
                resp_rate = json.loads(resp.read())
            except Exception:
                return
            return btc_amount * decimal.Decimal(str(resp_rate["bpi"][str(quote_currency)]["rate_float"]))
        return btc_amount * decimal.Decimal(quote_currencies[quote_currency])

    def check_rates(self, dt):
        if self.use_exchange == 'BlockChain':
            self.check_blockchain()
        elif self.use_exchange == 'CoinDesk':
            self.check_coindesk()
        elif self.use_exchange == 'Coinbase':
            self.check_coinbase()

    def check_coindesk(self):

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

        def on_failure(*args):
            pass

        def on_error(*args):
            pass

        def on_redirect(*args):
            pass

        req = UrlRequest(
            url='https://api.coindesk.com/v1/bpi/supported-currencies.json',
                        on_success=on_success,
                        on_failure=on_failure,
                        on_error=on_error,
                        on_redirect=on_redirect,
                        timeout=5)

    def check_coinbase(self):

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

        def on_failure(*args):
            pass

        def on_error(*args):
            pass

        def on_redirect(*args):
            pass

        req = UrlRequest(
            url='https://coinbase.com/api/v1/currencies/exchange_rates',
            on_success=on_success,
            on_failure=on_failure,
            on_error=on_error,
            on_redirect=on_redirect,
            timeout=5)

    def check_blockchain(self):

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

        def on_failure(*args):
            pass

        def on_error(*args):
            pass

        def on_redirect(*args):
            pass

        req = UrlRequest(url='https://blockchain.info/ticker',
                        on_success=on_success,
                        on_failure=on_failure,
                        on_error=on_error,
                        on_redirect=on_redirect,
                        timeout=5)

    def start(self):
        # check every 5 seconds
        self.check_rates(0)
        Clock.schedule_interval(self.check_rates, 5)

    def stop(self):
        Clock.unschedule(self.check_rates)

