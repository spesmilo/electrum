class Exchanger:

    def __init__(self, quote_currencies):
        self.quote_currencies = quote_currencies

    def exchange(self, btc_amount, quote_currency):
        assert quote_currency in self.quote_currencies

        return btc_amount * 6

if __name__ == "__main__":
    exch = Exchanger(("EUR", "USD", "GBP"))
    print exch.exchange(1, "EUR")

