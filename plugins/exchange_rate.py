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

    def exchange(self, btc_amount, quote_currency):
        with self.lock:
            if self.quote_currencies is None:
                return None
            quote_currencies = self.quote_currencies.copy()
        if quote_currency not in quote_currencies:
            return None
        return btc_amount * quote_currencies[quote_currency]

    def run(self):
        try:
            connection = httplib.HTTPConnection('blockchain.info')
            connection.request("GET", "/ticker")
        except:
            return
        response = connection.getresponse()
        if response.reason == httplib.responses[httplib.NOT_FOUND]:
            return
        try:
            response = json.loads(response.read())
        except:
            return
        quote_currencies = {}
        try:
            for r in response:
                quote_currencies[r] = self._lookup_rate(response, r)
            with self.lock:
                self.quote_currencies = quote_currencies
            self.parent.emit(SIGNAL("refresh_balance()"))
        except KeyError:
            pass

        print self.quote_currencies
            
    def get_currencies(self):
        return [] if self.quote_currencies == None else sorted(self.quote_currencies.keys())

    def _lookup_rate(self, response, quote_id):
        return decimal.Decimal(str(response[str(quote_id)]["15m"]))


class Plugin(BasePlugin):

    def fullname(self):
        return "Exchange rates"

    def description(self):
        return """exchange rates"""

    def init(self):
        self.win = self.gui.main_window
        self.exchanger = Exchanger(self.win)
        self.win.connect(self.win, SIGNAL("refresh_balance()"), self.win.update_wallet)
        # Do price discovery
        self.exchanger.start()
        self.gui.exchanger = self.exchanger

    def set_status_text(self, text):
        m = re.match( _( "Balance" ) + ": (\d.+) " + self.win.base_unit(), str(text))
        if m:
            amount = Decimal(m.group(1))
            text += self.create_quote_text(amount)
            self.win.balance_label.setText(text)

    def create_quote_text(self, btc_balance):
        quote_currency = self.config.get("currency", "None")
        quote_balance = self.exchanger.exchange(btc_balance, quote_currency)
        if quote_balance is None:
            quote_text = ""
        else:
            quote_text = "  (%.2f %s)" % (quote_balance, quote_currency)
        return quote_text


    def requires_settings(self):
        return True


    def settings_dialog(self):
        d = QDialog(self.win)

        vbox = QVBoxLayout(d)

        grid = QGridLayout()
        vbox.addLayout(grid)

        currencies = self.exchanger.get_currencies()
        currencies.insert(0, "None")

        cur_label=QLabel(_('Currency') + ':')
        grid.addWidget(cur_label , 2, 0)
        cur_combo = QComboBox()
        cur_combo.addItems(currencies)
        try:
            index = currencies.index(self.config.get('currency', "None"))
        except:
            index = 0
        cur_combo.setCurrentIndex(index)
        grid.addWidget(cur_combo, 2, 1)
        grid.addWidget(HelpButton(_('Select which currency is used for quotes.') + ' '), 2, 2)

        vbox.addLayout(ok_cancel_buttons(d))

        if d.exec_():

            cur_request = str(currencies[cur_combo.currentIndex()])
            if cur_request != self.config.get('currency', "None"):
                self.config.set_key('currency', cur_request, True)
                self.win.update_wallet()


        
