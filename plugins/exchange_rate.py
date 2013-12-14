from PyQt4.QtGui import *
from PyQt4.QtCore import *

import decimal
import httplib
import json
import threading
import re
from decimal import Decimal
from electrum.plugins import BasePlugin
from electrum.i18n import _
from electrum_gui.qt.util import *


class Exchanger(threading.Thread):

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.daemon = True
        self.parent = parent
        self.quote_currencies = None
        self.lock = threading.Lock()
        self.is_running = False

    def exchange(self, btc_amount, quote_currency):
        with self.lock:
            if self.quote_currencies is None:
                return None
            quote_currencies = self.quote_currencies.copy()
        if quote_currency not in quote_currencies:
            return None
        return btc_amount * quote_currencies[quote_currency]

    def stop(self):
        self.is_running = False

    def run(self):
        self.is_running = True
        while self.is_running:
            self.update()
            time.sleep(120)

    def update(self):
        try:
            connection = httplib.HTTPConnection('blockchain.info')
            connection.request("GET", "/ticker")
        except Exception:
            return
        response = connection.getresponse()
        if response.reason == httplib.responses[httplib.NOT_FOUND]:
            return
        try:
            response = json.loads(response.read())
        except Exception:
            return
        quote_currencies = {}
        try:
            for r in response:
                quote_currencies[r] = self._lookup_rate(response, r)
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)
        # print "updating exchange rate", self.quote_currencies["USD"]

            
    def get_currencies(self):
        return [] if self.quote_currencies == None else sorted(self.quote_currencies.keys())

    def _lookup_rate(self, response, quote_id):
        return decimal.Decimal(str(response[str(quote_id)]["15m"]))


class Plugin(BasePlugin):

    def fullname(self):
        return "Exchange rates"

    def description(self):
        return """exchange rates, retrieved from blockchain.info"""


    def __init__(self,a,b):
        BasePlugin.__init__(self,a,b)
        self.currencies = [self.config.get('currency', "EUR")]

    def init(self):
        self.win = self.gui.main_window
        self.win.connect(self.win, SIGNAL("refresh_currencies()"), self.win.update_status)
        # Do price discovery
        self.exchanger = Exchanger(self)
        self.exchanger.start()
        self.gui.exchanger = self.exchanger #

    def set_currencies(self, quote_currencies):
        self.currencies = sorted(quote_currencies.keys())
        self.win.emit(SIGNAL("refresh_currencies()"))
        self.win.emit(SIGNAL("refresh_currencies_combo()"))

    def set_quote_text(self, btc_balance, r):
        r[0] = self.create_quote_text(Decimal(btc_balance) / 100000000)

    def create_quote_text(self, btc_balance):
        quote_currency = self.config.get("currency", "EUR")
        quote_balance = self.exchanger.exchange(btc_balance, quote_currency)
        if quote_balance is None:
            quote_text = ""
        else:
            quote_text = "%.2f %s" % (quote_balance, quote_currency)
        return quote_text


    def requires_settings(self):
        return True


    def toggle(self):
        out = BasePlugin.toggle(self)
        self.win.update_status()
        return out


    def close(self):
        self.exchanger.stop()


    def settings_widget(self, window):
        combo = QComboBox()

        def on_change(x):
            cur_request = str(self.currencies[x])
            if cur_request != self.config.get('currency', "EUR"):
                self.config.set_key('currency', cur_request, True)
                self.win.update_status()

        def set_currencies(combo):
            try:
                combo.clear()
            except Exception:
                return
            combo.addItems(self.currencies)
            try:
                index = self.currencies.index(self.config.get('currency', "EUR"))
            except Exception:
                index = 0
            combo.setCurrentIndex(index)

        set_currencies(combo)
        combo.currentIndexChanged.connect(on_change)
        combo.connect(window, SIGNAL('refresh_currencies_combo()'), lambda: set_currencies(combo))
        return combo


        
