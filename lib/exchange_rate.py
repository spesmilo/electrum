import decimal
import httplib
import json

class Exchanger:

    def __init__(self, quote_currencies, refresh_balance):
        self.refresh_balance = refresh_balance
        self.quote_currencies = {}

    def exchange(self, btc_amount, quote_currency):
        return btc_amount * self.quote_currencies[quote_currency]

    def discovery(self):
        connection = httplib.HTTPSConnection('intersango.com')
        connection.request("GET", "/api/ticker.php")
        response = connection.getresponse()
        if response.status == 404:
            return
        response = json.loads(response.read())
        # 1 = BTC:GBP
        # 2 = BTC:EUR
        # 3 = BTC:USD
        # 4 = BTC:PLN
        try:
            self.quote_currencies["GBP"] = self.lookup_rate(response, 1)
            self.quote_currencies["EUR"] = self.lookup_rate(response, 2)
            self.quote_currencies["USD"] = self.lookup_rate(response, 3)
            self.refresh_balance()
        except KeyError:
            pass

    def lookup_rate(self, response, quote_id):
        return decimal.Decimal(response[str(quote_id)]["last"])

if __name__ == "__main__":
    exch = Exchanger(("EUR", "USD", "GBP"))
    print exch.exchange(1, "EUR")

