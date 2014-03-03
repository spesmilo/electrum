from PyQt4.QtGui import *
from PyQt4.QtCore import *

import datetime
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
        self.use_exchange = self.parent.config.get('use_exchange', "Blockchain")
        self.parent.exchanges = ["Blockchain", "Coinbase", "CoinDesk"]
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
            elif self.use_exchange == "Coinbase":
                self.update_cb()
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

    def update_cb(self):
        try:
            connection = httplib.HTTPSConnection('coinbase.com')
            connection.request("GET", "/api/v1/currencies/exchange_rates")
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
                if r[:7] == "btc_to_":
                    quote_currencies[r[7:].upper()] = self._lookup_rate_cb(response, r)
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
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
    def _lookup_rate_cb(self, response, quote_id):
        return decimal.Decimal(str(response[str(quote_id)]))



class Plugin(BasePlugin):

    def fullname(self):
        return "Exchange rates"

    def description(self):
        return """exchange rates, retrieved from blockchain.info, CoinDesk, or Coinbase"""


    def __init__(self,a,b):
        BasePlugin.__init__(self,a,b)
        self.currencies = [self.config.get('currency', "EUR")]
        self.exchanges = [self.config.get('use_exchange', "Blockchain")]

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

    def load_wallet(self, wallet):
        self.wallet = wallet
        tx_list = {}
        for item in self.wallet.get_tx_history(self.wallet.storage.get("current_account", None)):
            tx_hash, conf, is_mine, value, fee, balance, timestamp = item
            tx_list[tx_hash] = {'value': value, 'timestamp': timestamp, 'balance': balance}
            
        self.tx_list = tx_list
        

    def requires_settings(self):
        return True


    def toggle(self):
        out = BasePlugin.toggle(self)
        self.win.update_status()
        return out


    def close(self):
        self.exchanger.stop()

    def history_tab_update(self):
        if self.config.get('history_rates', 'unchecked') == "checked":
            tx_list = self.tx_list
            
            mintimestr = datetime.datetime.fromtimestamp(int(min(tx_list.items(), key=lambda x: x[1]['timestamp'])[1]['timestamp'])).strftime('%Y-%m-%d')
            maxtimestr = datetime.datetime.now().strftime('%Y-%m-%d')
            try:
                connection = httplib.HTTPSConnection('api.coindesk.com')
                connection.request("GET", "/v1/bpi/historical/close.json?start=" + mintimestr + "&end=" + maxtimestr)
            except Exception:
                return
            resp = connection.getresponse()
            if resp.reason == httplib.responses[httplib.NOT_FOUND]:
                return
            try:
                resp_hist = json.loads(resp.read())
            except Exception:
                return

            self.gui.main_window.is_edit = True
            self.gui.main_window.history_list.setColumnCount(6)
            self.gui.main_window.history_list.setHeaderLabels( [ '', _('Date'), _('Description') , _('Amount'), _('Balance'), _('Fiat Amount')] )
            root = self.gui.main_window.history_list.invisibleRootItem()
            childcount = root.childCount()
            for i in range(childcount):
                item = root.child(i)
                try:
                    tx_info = tx_list[str(item.data(0, Qt.UserRole).toPyObject())]
                except Exception:
                    newtx = self.wallet.get_tx_history()
                    v = newtx[[x[0] for x in newtx].index(str(item.data(0, Qt.UserRole).toPyObject()))][3]
                   
                    tx_info = {'timestamp':int(datetime.datetime.now().strftime("%s")), 'value': v }
                    pass
                tx_time = int(tx_info['timestamp'])
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                tx_USD_val = "%.2f %s" % (Decimal(tx_info['value']) / 100000000 * Decimal(resp_hist['bpi'][tx_time_str]), "USD")


                item.setText(5, tx_USD_val)
            
            for i, width in enumerate(self.gui.main_window.column_widths['history']):
                self.gui.main_window.history_list.setColumnWidth(i, width)
            self.gui.main_window.history_list.setColumnWidth(4, 140)
            self.gui.main_window.history_list.setColumnWidth(5, 120)
            self.gui.main_window.is_edit = False
       

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        d = QDialog()
        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('Exchange rate API: ')), 0, 0)
        layout.addWidget(QLabel(_('Currency: ')), 1, 0)
        layout.addWidget(QLabel(_('History Rates: ')), 2, 0)
        combo = QComboBox()
        combo_ex = QComboBox()
        hist_checkbox = QCheckBox()
        hist_checkbox.setEnabled(False)
        if self.config.get('history_rates', 'unchecked') == 'unchecked':
            hist_checkbox.setChecked(False)
        else:
            hist_checkbox.setChecked(True)
        ok_button = QPushButton(_("OK"))

        def on_change(x):
            cur_request = str(self.currencies[x])
            if cur_request != self.config.get('currency', "EUR"):
                self.config.set_key('currency', cur_request, True)
                if cur_request == "USD" and self.config.get('use_exchange', "Blockchain") == "CoinDesk":
                    hist_checkbox.setEnabled(True)
                else:
                    hist_checkbox.setChecked(False)
                    hist_checkbox.setEnabled(False)
                self.win.update_status()

        def on_change_ex(x):
            cur_request = str(self.exchanges[x])
            if cur_request != self.config.get('use_exchange', "Blockchain"):
                self.config.set_key('use_exchange', cur_request, True)
                if cur_request == "Blockchain":
                    self.exchanger.update_bc()
                    hist_checkbox.setChecked(False)
                    hist_checkbox.setEnabled(False)
                elif cur_request == "CoinDesk":
                    self.exchanger.update_cd()
                    if self.config.get('currency', "EUR") == "USD":
                        hist_checkbox.setEnabled(True)
                    else:
                        hist_checkbox.setChecked(False)
                        hist_checkbox.setEnabled(False)
                elif cur_request == "Coinbase":
                    self.exchanger.update_cb()
                    hist_checkbox.setChecked(False)
                    hist_checkbox.setEnabled(False)
                set_currencies(combo)
                self.win.update_status()

        def on_change_hist(checked):
            if checked:
                self.config.set_key('history_rates', 'checked')
                self.history_tab_update()
            else:
                self.config.set_key('history_rates', 'unchecked')
                self.gui.main_window.history_list.setHeaderLabels( [ '', _('Date'), _('Description') , _('Amount'), _('Balance')] )
                self.gui.main_window.history_list.setColumnCount(5)
                for i,width in enumerate(self.gui.main_window.column_widths['history']):
                    self.gui.main_window.history_list.setColumnWidth(i, width)

        def set_hist_check(hist_checkbox):
            if self.config.get('use_exchange', "Blockchain") == "CoinDesk":
                hist_checkbox.setEnabled(True)
            else:
                hist_checkbox.setEnabled(False) 
        
        def set_currencies(combo):
            current_currency = self.config.get('currency', "EUR")
            try:
                combo.clear()
            except Exception:
                return
            combo.addItems(self.currencies)
            try:
                index = self.currencies.index(current_currency)
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

        def ok_clicked():
            d.accept();

        set_exchanges(combo_ex)
        set_currencies(combo)
        set_hist_check(hist_checkbox)
        combo.currentIndexChanged.connect(on_change)
        combo_ex.currentIndexChanged.connect(on_change_ex)
        hist_checkbox.stateChanged.connect(on_change_hist)
        combo.connect(d, SIGNAL('refresh_currencies_combo()'), lambda: set_currencies(combo))
        combo_ex.connect(d, SIGNAL('refresh_exchanges_combo()'), lambda: set_exchanges(combo_ex))
        ok_button.clicked.connect(lambda: ok_clicked())
        layout.addWidget(combo,1,1)
        layout.addWidget(combo_ex,0,1)
        layout.addWidget(hist_checkbox,2,1)
        layout.addWidget(ok_button,3,1)
        
        if d.exec_():
            return True
        else:
            return False


        
