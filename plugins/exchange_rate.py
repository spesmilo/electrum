from PyQt4.QtGui import *
from PyQt4.QtCore import *

import datetime
import decimal
import httplib
import json
import threading
import time
import re
from ssl import SSLError
from decimal import Decimal
from ssl import SSLError

from electrum.plugins import BasePlugin, hook
from electrum.i18n import _
from electrum_gui.qt.util import *
from electrum_gui.qt.amountedit import AmountEdit


EXCHANGES = ["BitcoinAverage",
             "BitcoinVenezuela",
             "BTCParalelo",
             "Bitcurex",
             "Bitmarket",
             "BitPay",
             "Blockchain",
             "BTCChina",
             "CaVirtEx",
             "Coinbase",
             "CoinDesk",
             "itBit",
             "LocalBitcoins",
             "Winkdex"]

EXCH_SUPPORT_HIST = [("CoinDesk", "USD"),
                     ("Winkdex", "USD"),
                     ("BitcoinVenezuela", "ARS"),
                     ("BitcoinVenezuela", "VEF")]

class Exchanger(threading.Thread):

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.daemon = True
        self.parent = parent
        self.quote_currencies = None
        self.lock = threading.Lock()
        self.query_rates = threading.Event()
        self.use_exchange = self.parent.config.get('use_exchange', "Blockchain")
        self.parent.exchanges = EXCHANGES
        self.parent.win.emit(SIGNAL("refresh_exchanges_combo()"))
        self.parent.win.emit(SIGNAL("refresh_currencies_combo()"))
        self.is_running = False

    def get_json(self, site, get_string):
        try:
            connection = httplib.HTTPSConnection(site)
            connection.request("GET", get_string, headers={"User-Agent":"Electrum"})
        except Exception:
            raise
        resp = connection.getresponse()
        if resp.reason == httplib.responses[httplib.NOT_FOUND]:
            raise
        try:
            json_resp = json.loads(resp.read())
        except Exception:
            raise
        return json_resp
        
    def get_json_insecure(self, site, get_string):
        """ get_json_insecure shouldn't be used in production releases
        It doesn't use SSL, and so prices could be manipulated by a middle man
        This should be used ONLY when developing plugins when you don't have a
        SSL certificate that validates against HTTPSConnection
        """
        try:
            connection = httplib.HTTPConnection(site)
            connection.request("GET", get_string, headers={"User-Agent":"Electrum"})
        except Exception:
            raise
        resp = connection.getresponse()
        if resp.reason == httplib.responses[httplib.NOT_FOUND]:
            raise
        try:
            json_resp = json.loads(resp.read())
        except Exception:
            raise
        return json_resp


    def exchange(self, btc_amount, quote_currency):
        with self.lock:
            if self.quote_currencies is None:
                return None
            quote_currencies = self.quote_currencies.copy()
        if quote_currency not in quote_currencies:
            return None
        return btc_amount * decimal.Decimal(str(quote_currencies[quote_currency]))

    def stop(self):
        self.is_running = False

    def update_rate(self):
        self.use_exchange = self.parent.config.get('use_exchange', "Blockchain")
        update_rates = {
            "BitcoinAverage": self.update_ba,
            "BitcoinVenezuela": self.update_bv,
            "BTCParalelo": self.update_bpl,
            "Bitcurex": self.update_bx,
            "Bitmarket": self.update_bm,
            "BitPay": self.update_bp,
            "Blockchain": self.update_bc,
            "BTCChina": self.update_CNY,
            "CaVirtEx": self.update_cv,
            "CoinDesk": self.update_cd,
            "Coinbase": self.update_cb,
            "itBit": self.update_ib,
            "LocalBitcoins": self.update_lb,
            "Winkdex": self.update_wd,
        }
        try:
            update_rates[self.use_exchange]()
        except KeyError:
            return

    def run(self):
        self.is_running = True
        while self.is_running:
            self.query_rates.clear()
            self.update_rate()
            self.query_rates.wait(150)


    def update_cd(self):
        try:
            resp_currencies = self.get_json('api.coindesk.com', "/v1/bpi/supported-currencies.json")
        except SSLError:
            print("SSL Error when accesing coindesk")
            return
        except Exception:
            return

        quote_currencies = {}
        for cur in resp_currencies:
            quote_currencies[str(cur["currency"])] = 0.0

        current_cur = self.parent.config.get("currency", "EUR")
        if current_cur in quote_currencies:
            try:
                resp_rate = self.get_json('api.coindesk.com', "/v1/bpi/currentprice/" + str(current_cur) + ".json")
                quote_currencies[str(current_cur)] = decimal.Decimal(str(resp_rate["bpi"][str(current_cur)]["rate_float"]))
            except Exception:
                return
        with self.lock:
            self.quote_currencies = quote_currencies
        self.parent.set_currencies(quote_currencies)

    def update_ib(self):
        available_currencies = ["USD", "EUR", "SGD"]
        quote_currencies = {}
        for cur in available_currencies:
            quote_currencies[cur] = 0.0
        current_cur = self.parent.config.get("currency", "EUR")
        if current_cur in available_currencies:
            try:
                resp_rate = self.get_json('api.itbit.com', "/v1/markets/XBT" + str(current_cur) + "/ticker")
                quote_currencies[str(current_cur)] = decimal.Decimal(str(resp_rate["lastPrice"]))
            except SSLError:
                print("SSL Error when accesing itbit")
                return
            except Exception:
                return
        with self.lock:
            self.quote_currencies = quote_currencies
        self.parent.set_currencies(quote_currencies)

    def update_wd(self):
        try:
            winkresp = self.get_json('winkdex.com', "/api/v0/price")
        except SSLError:
            print("SSL Error when accesing winkdex")
            return
        except Exception:
            return
        quote_currencies = {"USD": 0.0}
        usdprice = decimal.Decimal(str(winkresp["price"]))/decimal.Decimal("100.0")
        try:
            quote_currencies["USD"] = usdprice
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)

    def update_cv(self):
        try:
            jsonresp = self.get_json('www.cavirtex.com', "/api/CAD/ticker.json")
        except SSLError:
            print("SSL Error when accesing cavirtex")
            return
        except Exception:
            return
        quote_currencies = {"CAD": 0.0}
        cadprice = jsonresp["last"]
        try:
            quote_currencies["CAD"] = decimal.Decimal(str(cadprice))
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)

    def update_bm(self):
        try:
            jsonresp = self.get_json('www.bitmarket.pl', "/json/BTCPLN/ticker.json")
        except SSLError:
            print("SSL Error when accesing bitmarket")
            return
        except Exception:
            return
        quote_currencies = {"PLN": 0.0}
        pln_price = jsonresp["last"]
        try:
            quote_currencies["PLN"] = decimal.Decimal(str(pln_price))
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)

    def update_bx(self):
        try:
            jsonresp = self.get_json('pln.bitcurex.com', "/data/ticker.json")
        except SSLError:
            print("SSL Error when accesing bitcurex")
            return
        except Exception:
            return
        quote_currencies = {"PLN": 0.0}
        pln_price = jsonresp["last"]
        try:
            quote_currencies["PLN"] = decimal.Decimal(str(pln_price))
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)

    def update_CNY(self):
        try:
            jsonresp = self.get_json('data.btcchina.com', "/data/ticker")
        except SSLError:
            print("SSL Error when accesing btcchina")
            return
        except Exception:
            return
        quote_currencies = {"CNY": 0.0}
        cnyprice = jsonresp["ticker"]["last"]
        try:
            quote_currencies["CNY"] = decimal.Decimal(str(cnyprice))
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)

    def update_bp(self):
        try:
            jsonresp = self.get_json('bitpay.com', "/api/rates")
        except SSLError:
            print("SSL Error when accesing bitpay")
            return
        except Exception:
            return
        quote_currencies = {}
        try:
            for r in jsonresp:
                quote_currencies[str(r["code"])] = decimal.Decimal(r["rate"])
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)

    def update_cb(self):
        try:
            jsonresp = self.get_json('coinbase.com', "/api/v1/currencies/exchange_rates")
        except SSLError:
            print("SSL Error when accesing coinbase")
            return
        except Exception:
            return

        quote_currencies = {}
        try:
            for r in jsonresp:
                if r[:7] == "btc_to_":
                    quote_currencies[r[7:].upper()] = self._lookup_rate_cb(jsonresp, r)
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)


    def update_bc(self):
        try:
            jsonresp = self.get_json('blockchain.info', "/ticker")
        except SSLError:
            print("SSL Error when accesing blockchain")
            return
        except Exception:
            return
        quote_currencies = {}
        try:
            for r in jsonresp:
                quote_currencies[r] = self._lookup_rate(jsonresp, r)
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)

    def update_lb(self):
        try:
            jsonresp = self.get_json('localbitcoins.com', "/bitcoinaverage/ticker-all-currencies/")
        except SSLError:
            print("SSL Error when accesing localbitcoins")
            return
        except Exception:
            return
        quote_currencies = {}
        try:
            for r in jsonresp:
                quote_currencies[r] = self._lookup_rate_lb(jsonresp, r)
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)


    def update_bv(self):
        try:
            jsonresp = self.get_json_insecure('api.bitcoinvenezuela.com', "/")
            print("**WARNING**: update_bv is using an insecure connection, shouldn't be used on production")
        except SSLError:
            print("SSL Error when accesing bitcoinvenezuela")
            return
        except Exception:
            return
        
        quote_currencies = {}
        try:
            for r in jsonresp["BTC"]:
                quote_currencies[r] = Decimal(jsonresp["BTC"][r])
            
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            print ("KeyError")
        self.parent.set_currencies(quote_currencies)

        
    def update_bpl(self):
        try:
            jsonresp = self.get_json_insecure('btcparalelo.com', "/api/price")
            print("**WARNING**: update_bpl is using an insecure connection, shouldn't be used on production")
        except SSLError:
            print("SSL Error when accesing btcparalelo")
            return
        except Exception:
            return
        
        
        quote_currencies = {}
        try:
            quote_currencies = {"VEF": Decimal(jsonresp["price"])}
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            print ("KeyError")
        self.parent.set_currencies(quote_currencies)
        
    def update_ba(self):
        try:
            jsonresp = self.get_json('api.bitcoinaverage.com', "/ticker/global/all")
        except SSLError:
            print("SSL Error when accesing bitcoinaverage")
            return
        except Exception:
            return
        quote_currencies = {}
        try:
            for r in jsonresp:
                if not r == "timestamp":
                    quote_currencies[r] = self._lookup_rate_ba(jsonresp, r)
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)


    def _lookup_rate(self, response, quote_id):
        return decimal.Decimal(str(response[str(quote_id)]["15m"]))
    def _lookup_rate_cb(self, response, quote_id):
        return decimal.Decimal(str(response[str(quote_id)]))
    def _lookup_rate_ba(self, response, quote_id):
        return decimal.Decimal(response[str(quote_id)]["last"])
    def _lookup_rate_lb(self, response, quote_id):
        return decimal.Decimal(response[str(quote_id)]["rates"]["last"])


class Plugin(BasePlugin):

    def fullname(self):
        return "Exchange rates"

    def description(self):
        return """exchange rates, retrieved from blockchain.info, CoinDesk, or Coinbase"""


    def __init__(self,a,b):
        BasePlugin.__init__(self,a,b)
        self.currencies = [self.fiat_unit()]
        self.exchanges = [self.config.get('use_exchange', "Blockchain")]
        self.exchanger = None

    @hook
    def init_qt(self, gui):
        self.gui = gui
        self.win = self.gui.main_window
        self.win.connect(self.win, SIGNAL("refresh_currencies()"), self.win.update_status)
        self.btc_rate = Decimal("0.0")
        self.resp_hist = {}
        self.tx_list = {}
        if self.exchanger is None:
            # Do price discovery
            self.exchanger = Exchanger(self)
            self.exchanger.start()
            self.gui.exchanger = self.exchanger #
            self.add_send_edit()
            self.add_receive_edit()
            self.win.update_status()

    def close(self):
        self.exchanger.stop()
        self.exchanger = None
        self.send_fiat_e.hide()
        self.receive_fiat_e.hide()
        self.win.update_status()

    def set_currencies(self, currency_options):
        self.currencies = sorted(currency_options)
        self.win.emit(SIGNAL("refresh_currencies()"))
        self.win.emit(SIGNAL("refresh_currencies_combo()"))

    @hook
    def get_fiat_balance_text(self, btc_balance, r):
        # return balance as: 1.23 USD
        r[0] = self.create_fiat_balance_text(Decimal(btc_balance) / 100000000)

    def get_fiat_price_text(self, r):
        # return BTC price as: 123.45 USD
        r[0] = self.create_fiat_balance_text(1)
        quote = r[0]
        if quote:
            r[0] = "%s"%quote

    @hook
    def get_fiat_status_text(self, btc_balance, r2):
        # return status as:   (1.23 USD)    1 BTC~123.45 USD
        text = ""
        r = {}
        self.get_fiat_price_text(r)
        quote = r.get(0)
        if quote:
            price_text = "1 BTC~%s"%quote
            fiat_currency = quote[-3:]
            btc_price = self.btc_rate
            fiat_balance = Decimal(btc_price) * (Decimal(btc_balance)/100000000)
            balance_text = "(%.2f %s)" % (fiat_balance,fiat_currency)
            text = "  " + balance_text + "     " + price_text + " "
        r2[0] = text

    def create_fiat_balance_text(self, btc_balance):
        quote_currency = self.fiat_unit()
        self.exchanger.use_exchange = self.config.get("use_exchange", "Blockchain")
        cur_rate = self.exchanger.exchange(Decimal("1.0"), quote_currency)
        if cur_rate is None:
            quote_text = ""
        else:
            quote_balance = btc_balance * Decimal(cur_rate)
            self.btc_rate = cur_rate
            quote_text = "%.2f %s" % (quote_balance, quote_currency)
        return quote_text

    @hook
    def load_wallet(self, wallet):
        tx_list = {}
        for item in self.wallet.get_history(self.wallet.storage.get("current_account", None)):
            tx_hash, conf, value, timestamp, balance = item
            tx_list[tx_hash] = {'value': value, 'timestamp': timestamp }

        self.tx_list = tx_list
        self.cur_exchange = self.config.get('use_exchange', "Blockchain")
        threading.Thread(target=self.request_history_rates, args=()).start()


    def requires_settings(self):
        return True


    def request_history_rates(self):
        if self.config.get('history_rates') != "checked":
            return
        if not self.tx_list:
            return

        try:
            mintimestr = datetime.datetime.fromtimestamp(int(min(self.tx_list.items(), key=lambda x: x[1]['timestamp'])[1]['timestamp'])).strftime('%Y-%m-%d')
        except Exception:
            return
        maxtimestr = datetime.datetime.now().strftime('%Y-%m-%d')

        if self.cur_exchange == "CoinDesk":
            try:
                self.resp_hist = self.exchanger.get_json('api.coindesk.com', "/v1/bpi/historical/close.json?start=" + mintimestr + "&end=" + maxtimestr)
            except Exception:
                return
        elif self.cur_exchange == "Winkdex":
            try:
                self.resp_hist = self.exchanger.get_json('winkdex.com', "/api/v0/series?start_time=1342915200")['series'][0]['results']
            except Exception:
                return
        elif self.cur_exchange == "BitcoinVenezuela":
            cur_currency = self.fiat_unit()
            if cur_currency == "VEF":
                try:
                    self.resp_hist = self.exchanger.get_json('api.bitcoinvenezuela.com', "/historical/index.php?coin=BTC")['VEF_BTC']
                except Exception:
                    return
            elif cur_currency == "ARS":
                try:
                    self.resp_hist = self.exchanger.get_json('api.bitcoinvenezuela.com', "/historical/index.php?coin=BTC")['ARS_BTC']
                except Exception:
                    return
            else:
                return

        self.win.need_update.set()

    @hook
    def history_tab_update(self):
        if self.config.get('history_rates') != "checked":
            return
        if not self.resp_hist:
            return
        if not self.wallet:
            return

        self.win.is_edit = True
        self.win.history_list.setColumnCount(6)
        self.win.history_list.setHeaderLabels( [ '', _('Date'), _('Description') , _('Amount'), _('Balance'), _('Fiat Amount')] )
        root = self.win.history_list.invisibleRootItem()
        childcount = root.childCount()
        for i in range(childcount):
            item = root.child(i)
            try:
                tx_info = self.tx_list[str(item.data(0, Qt.UserRole).toPyObject())]
            except Exception:
                newtx = self.wallet.get_tx_history()
                v = newtx[[x[0] for x in newtx].index(str(item.data(0, Qt.UserRole).toPyObject()))][3]
                tx_info = {'timestamp':int(time.time()), 'value': v}
                pass
            tx_time = int(tx_info['timestamp'])
            tx_value = Decimal(str(tx_info['value'])) / 100000000
            if self.cur_exchange == "CoinDesk":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                try:
                    tx_fiat_val = "%.2f %s" % (value * Decimal(self.resp_hist['bpi'][tx_time_str]), "USD")
                except KeyError:
                    tx_fiat_val = "%.2f %s" % (self.btc_rate * Decimal(str(tx_info['value']))/100000000 , "USD")
            elif self.cur_exchange == "Winkdex":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d') + "T16:00:00-04:00"
                try:
                    tx_rate = self.resp_hist[[x['timestamp'] for x in self.resp_hist].index(tx_time_str)]['price']
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(tx_rate)/Decimal("100.0"), "USD")
                except ValueError:
                    tx_fiat_val = "%.2f %s" % (self.btc_rate * Decimal(tx_info['value'])/100000000 , "USD")
                except KeyError:
                    tx_fiat_val = _("No data")
            elif self.cur_exchange == "BitcoinVenezuela":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                try:
                    num = self.resp_hist[tx_time_str].replace(',','')
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(num), self.fiat_unit())
                except KeyError:
                    tx_fiat_val = _("No data")

            tx_fiat_val = " "*(12-len(tx_fiat_val)) + tx_fiat_val
            item.setText(5, tx_fiat_val)
            item.setFont(5, QFont(MONOSPACE_FONT))
            if Decimal(str(tx_info['value'])) < 0:
                item.setForeground(5, QBrush(QColor("#BC1E1E")))

        self.win.history_list.setColumnWidth(5, 120)
        self.win.is_edit = False


    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        d = QDialog()
        d.setWindowTitle("Settings")
        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('Exchange rate API: ')), 0, 0)
        layout.addWidget(QLabel(_('Currency: ')), 1, 0)
        layout.addWidget(QLabel(_('History Rates: ')), 2, 0)
        combo = QComboBox()
        combo_ex = QComboBox()
        hist_checkbox = QCheckBox()
        hist_checkbox.setEnabled(False)
        hist_checkbox.setChecked(self.config.get('history_rates', 'unchecked') != 'unchecked')
        ok_button = QPushButton(_("OK"))

        def on_change(x):
            try:
                cur_request = str(self.currencies[x])
            except Exception:
                return
            if cur_request != self.fiat_unit():
                self.config.set_key('currency', cur_request, True)
                cur_exchange = self.config.get('use_exchange', "Blockchain")
                if (cur_exchange, cur_request) in EXCH_SUPPORT_HIST:
                    hist_checkbox.setEnabled(True)
                else:
                    disable_check()
                self.win.update_status()
                try:
                    self.fiat_button
                except:
                    pass
                else:
                    self.fiat_button.setText(cur_request)

        def disable_check():
            hist_checkbox.setChecked(False)
            hist_checkbox.setEnabled(False)

        def on_change_ex(x):
            cur_request = str(self.exchanges[x])
            if cur_request != self.config.get('use_exchange', "Blockchain"):
                self.config.set_key('use_exchange', cur_request, True)
                self.currencies = []
                combo.clear()
                self.exchanger.query_rates.set()
                cur_currency = self.fiat_unit()
                if (cur_request, cur_currency) in EXCH_SUPPORT_HIST:
                    hist_checkbox.setEnabled(True)
                else:
                    disable_check()
                set_currencies(combo)
                self.win.update_status()

        def on_change_hist(checked):
            if checked:
                self.config.set_key('history_rates', 'checked')
                self.request_history_rates()
            else:
                self.config.set_key('history_rates', 'unchecked')
                self.win.history_list.setHeaderLabels( [ '', _('Date'), _('Description') , _('Amount'), _('Balance')] )
                self.win.history_list.setColumnCount(5)
                for i,width in enumerate(self.win.column_widths['history']):
                    self.win.history_list.setColumnWidth(i, width)

        def set_hist_check(hist_checkbox):
            cur_exchange = self.config.get('use_exchange', "Blockchain")
            hist_checkbox.setEnabled(cur_exchange in ["CoinDesk", "Winkdex", "BitcoinVenezuela"])

        def set_currencies(combo):
            try:
                combo.blockSignals(True)
                current_currency = self.fiat_unit()
                combo.clear()
            except Exception:
                return
            combo.addItems(self.currencies)
            try:
                index = self.currencies.index(current_currency)
            except Exception:
                index = 0
            combo.blockSignals(False)
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
            if self.config.get('use_exchange', "Blockchain") in ["CoinDesk", "itBit"]:
                self.exchanger.query_rates.set()
            d.accept();

        set_exchanges(combo_ex)
        set_currencies(combo)
        set_hist_check(hist_checkbox)
        combo.currentIndexChanged.connect(on_change)
        combo_ex.currentIndexChanged.connect(on_change_ex)
        hist_checkbox.stateChanged.connect(on_change_hist)
        combo.connect(self.win, SIGNAL('refresh_currencies_combo()'), lambda: set_currencies(combo))
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

    def fiat_unit(self):
        return self.config.get("currency", "EUR")

    def add_send_edit(self):
        self.send_fiat_e = AmountEdit(self.fiat_unit)
        btc_e = self.win.amount_e
        fee_e = self.win.fee_e
        self.connect_fields(btc_e, self.send_fiat_e, fee_e)
        self.win.send_grid.addWidget(self.send_fiat_e, 4, 3, Qt.AlignHCenter)
        btc_e.frozen.connect(lambda: self.send_fiat_e.setFrozen(btc_e.isReadOnly()))

    def add_receive_edit(self):
        self.receive_fiat_e = AmountEdit(self.fiat_unit)
        btc_e = self.win.receive_amount_e
        self.connect_fields(btc_e, self.receive_fiat_e, None)
        self.win.receive_grid.addWidget(self.receive_fiat_e, 2, 3, Qt.AlignHCenter)

    def connect_fields(self, btc_e, fiat_e, fee_e):
        def fiat_changed():
            try:
                fiat_amount = Decimal(str(fiat_e.text()))
            except:
                btc_e.setText("")
                if fee_e: fee_e.setText("")
                return
            exchange_rate = self.exchanger.exchange(Decimal("1.0"), self.fiat_unit())
            if exchange_rate is not None:
                btc_amount = fiat_amount/exchange_rate
                btc_e.setAmount(int(btc_amount*Decimal(100000000)))
                if fee_e: self.win.update_fee(False)
        fiat_e.textEdited.connect(fiat_changed)
        def btc_changed():
            if self.exchanger is None:
                return
            btc_amount = btc_e.get_amount()
            if btc_amount is None:
                fiat_e.setText("")
                return
            fiat_amount = self.exchanger.exchange(Decimal(btc_amount)/Decimal(100000000), self.fiat_unit())
            if fiat_amount is not None:
                pos = fiat_e.cursorPosition()
                fiat_e.setText("%.2f"%fiat_amount)
                fiat_e.setCursorPosition(pos)
        btc_e.textEdited.connect(btc_changed)
