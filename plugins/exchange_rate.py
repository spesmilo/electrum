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
        self.use_exchange = self.parent.config.get('use_exchange', "CoinDesk")
        self.parent.exchanges = ["CoinDesk", "Blockchain"]
        self.parent.currencies = ["EUR","GBP","USD"]
        self.parent.win.emit(SIGNAL("refresh_exchanges_combo()"))
        self.parent.win.emit(SIGNAL("refresh_currencies_combo()"))
        self.is_running = False

    def exchange(self, btc_amount, quote_currency):
        with self.lock:
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

    def stop(self):
        self.is_running = False

    def run(self):
        self.is_running = True
        while self.is_running:
            self.use_exchange = self.parent.config.get('use_exchange', "Blockchain")
            if self.use_exchange == "Blockchain":
                self.update_bc()
            elif self.use_exchange == "CoinDesk":
                self.update_cd()
            time.sleep(150)

    def update_cd(self):
        try:
            connection = httplib.HTTPSConnection('api.coindesk.com')
            connection.request("GET", "/v1/bpi/supported-currencies.json")
        except Exception:
            return
        response = connection.getresponse()
        if response.reason == httplib.responses[httplib.NOT_FOUND]:
            return
        try:
            resp_currencies = json.loads(response.read())
        except Exception:
            return

        quote_currencies = {}
        for cur in resp_currencies:
            quote_currencies[str(cur["currency"])] = 0.0
        with self.lock:
            self.quote_currencies = quote_currencies
        self.parent.set_currencies(quote_currencies)


    def update_bc(self):
        try:
            connection = httplib.HTTPSConnection('blockchain.info')
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
        self.exchanges = [self.config.get('use_exchange', "CoinDesk")]

    def init(self):
        self.win = self.gui.main_window
        self.win.connect(self.win, SIGNAL("refresh_currencies()"), self.win.update_status)
        # Do price discovery
        self.exchanger = Exchanger(self)
        self.exchanger.start()
        self.gui.exchanger = self.exchanger #

    def set_currencies(self, currency_options):
        self.currencies = sorted(currency_options)
        self.win.emit(SIGNAL("refresh_currencies()"))
        self.win.emit(SIGNAL("refresh_currencies_combo()"))


    def set_quote_text(self, btc_balance, r):
        r[0] = self.create_quote_text(Decimal(btc_balance) / 100000000)

    def create_quote_text(self, btc_balance):
        quote_currency = self.config.get("currency", "EUR")
        self.exchanger.use_exchange = self.config.get("use_exchange", "Blockchain")
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
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        d = QDialog()
        layout = QGridLayout(d)
        layout.addWidget(QLabel("Exchange rate API: "), 0, 0)
        layout.addWidget(QLabel("Currency: "), 1, 0)
        combo = QComboBox()
        combo_ex = QComboBox()

        def on_change(x):
            cur_request = str(self.currencies[x])
            if cur_request != self.config.get('currency', "EUR"):
                self.config.set_key('currency', cur_request, True)
                self.win.update_status()

        def on_change_ex(x):
            cur_request = str(self.exchanges[x])
            if cur_request != self.config.get('use_exchange', "Blockchain"):
                self.config.set_key('use_exchange', cur_request, True)
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

        def set_exchanges(combo_ex):
            try:
                combo_ex.clear()
            except Exception:
                return
            combo_ex.addItems(self.exchanges)
            try:
                index = self.exchanges.index(self.config.get('use_exchange', "Blockchain"))
            except Exception:
                index = 0
            combo_ex.setCurrentIndex(index)

        set_exchanges(combo_ex)
        set_currencies(combo)
        combo.currentIndexChanged.connect(on_change)
        combo_ex.currentIndexChanged.connect(on_change_ex)
        combo.connect(d, SIGNAL('refresh_currencies_combo()'), lambda: set_currencies(combo))
        combo_ex.connect(d, SIGNAL('refresh_exchanges_combo()'), lambda: set_exchanges(combo_ex))
        layout.addWidget(combo,1,1)
        layout.addWidget(combo_ex,0,1)
        
        if d.exec_():
            return True
        else:
            return False


        
