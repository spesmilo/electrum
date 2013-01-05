from PyQt4.QtCore import SIGNAL
import decimal
import httplib
import json
import threading

class Exchanger(threading.Thread):

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.daemon = True
        self.parent = parent
        self.quote_currencies = None
        self.lock = threading.Lock()
        # Do price discovery
        self.start()

    def exchange(self, btc_amount, quote_currency):
        with self.lock:
            if self.quote_currencies is None:
                return None
            quote_currencies = self.quote_currencies.copy()
        if quote_currency not in quote_currencies:
            return None
        return btc_amount * quote_currencies[quote_currency]

    def run(self):
        self.discovery()

    def discovery(self):
        try:
            connection = httplib.HTTPSConnection('blockchain.info')
            connection.request("GET", "/ticker")
        except:
            return
        response = connection.getresponse()
        if response.reason == httplib.responses[httplib.NOT_FOUND]:
            return
        response = json.loads(response.read())
        quote_currencies = {}
        try:
            for r in response:
                quote_currencies[r] = self._lookup_rate(response, r)
            with self.lock:
                self.quote_currencies = quote_currencies
            self.parent.emit(SIGNAL("refresh_balance()"))
        except KeyError:
            pass
            
    def get_currencies(self):
        return [] if self.quote_currencies == None else sorted(self.quote_currencies.keys())

    def _lookup_rate(self, response, quote_id):
        return decimal.Decimal(str(response[str(quote_id)]["15m"]))

if __name__ == "__main__":
    exch = Exchanger(("BRL", "CNY", "EUR", "GBP", "RUB", "USD"))
    print exch.exchange(1, "EUR")

