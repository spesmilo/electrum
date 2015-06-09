from PyQt4.QtGui import *
from PyQt4.QtCore import *

import datetime
import decimal
import requests
import json
import threading
import time
import re
from ssl import SSLError
from decimal import Decimal

from electrum.bitcoin import COIN
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
        #self.parent.win.emit(SIGNAL("refresh_exchanges_combo()"))
        #self.parent.win.emit(SIGNAL("refresh_currencies_combo()"))
        self.is_running = False

    def get_json(self, site, get_string):
        resp = requests.request('GET', 'https://' + site + get_string, headers={"User-Agent":"Electrum"})
        return resp.json()
        
    def exchange(self, btc_amount, quote_currency):
        with self.lock:
            if self.quote_currencies is None:
                return None
            quote_currencies = self.quote_currencies.copy()
        if quote_currency not in quote_currencies:
            return None
        return btc_amount * Decimal(str(quote_currencies[quote_currency]))

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
            rates = update_rates[self.use_exchange]()
        except Exception as e:
            self.parent.print_error(e)
            rates = {}
        with self.lock:
            self.quote_currencies = rates
            self.parent.set_currencies(rates)

    def run(self):
        self.is_running = True
        while self.is_running:
            self.query_rates.clear()
            self.update_rate()
            self.query_rates.wait(150)


    def update_cd(self):
        resp_currencies = self.get_json('api.coindesk.com', "/v1/bpi/supported-currencies.json")
        quote_currencies = {}
        for cur in resp_currencies:
            quote_currencies[str(cur["currency"])] = 0.0
        current_cur = self.parent.config.get("currency", "EUR")
        if current_cur in quote_currencies:
            resp_rate = self.get_json('api.coindesk.com', "/v1/bpi/currentprice/" + str(current_cur) + ".json")
            quote_currencies[str(current_cur)] = Decimal(str(resp_rate["bpi"][str(current_cur)]["rate_float"]))
        return quote_currencies

    def update_ib(self):
        available_currencies = ["USD", "EUR", "SGD"]
        quote_currencies = {}
        for cur in available_currencies:
            quote_currencies[cur] = 0.0
        current_cur = self.parent.config.get("currency", "EUR")
        if current_cur in available_currencies:
            resp_rate = self.get_json('api.itbit.com', "/v1/markets/XBT" + str(current_cur) + "/ticker")
            quote_currencies[str(current_cur)] = Decimal(str(resp_rate["lastPrice"]))
        return quote_currencies

    def update_wd(self):
        winkresp = self.get_json('winkdex.com', "/api/v0/price")
        return {"USD": Decimal(str(winkresp["price"]))/Decimal("100.0")}

    def update_cv(self):
        jsonresp = self.get_json('www.cavirtex.com', "/api/CAD/ticker.json")
        cadprice = jsonresp["last"]
        return {"CAD": Decimal(str(cadprice))}

    def update_bm(self):
        jsonresp = self.get_json('www.bitmarket.pl', "/json/BTCPLN/ticker.json")
        pln_price = jsonresp["last"]
        return {"PLN": Decimal(str(pln_price))}

    def update_bx(self):
        jsonresp = self.get_json('pln.bitcurex.com', "/data/ticker.json")
        pln_price = jsonresp["last"]
        return {"PLN": Decimal(str(pln_price))}

    def update_CNY(self):
        jsonresp = self.get_json('data.btcchina.com', "/data/ticker")
        cnyprice = jsonresp["ticker"]["last"]
        return {"CNY": Decimal(str(cnyprice))}

    def update_bp(self):
        jsonresp = self.get_json('bitpay.com', "/api/rates")
        return dict([(str(r["code"]), Decimal(r["rate"])) for r in jsonresp])

    def update_cb(self):
        jsonresp = self.get_json('coinbase.com', "/api/v1/currencies/exchange_rates")
        return dict([(r[7:].upper(), Decimal(str(jsonresp[r]))) for r in jsonresp if r.startswith("btc_to_")])

    def update_bc(self):
        jsonresp = self.get_json('blockchain.info', "/ticker")
        return dict([(r, Decimal(str(jsonresp[r]["15m"]))) for r in jsonresp])

    def update_lb(self):
        jsonresp = self.get_json('localbitcoins.com', "/bitcoinaverage/ticker-all-currencies/")
        return dict([(r, Decimal(jsonresp[r]["rates"]["last"])) for r in jsonresp])

    def update_bv(self):
        jsonresp = self.get_json('api.bitcoinvenezuela.com', "/")
        return dict([(r, Decimal(jsonresp["BTC"][r])) for r in jsonresp["BTC"]])

    def update_bpl(self):
        jsonresp = self.get_json('btcparalelo.com', "/api/price")
        return {"VEF": Decimal(jsonresp["price"])}

    def update_ba(self):
        jsonresp = self.get_json('api.bitcoinaverage.com', "/ticker/global/all")
        return dict([(r, Decimal(jsonresp[r]["last"])) for r in jsonresp if not r == "timestamp"])


class Plugin(BasePlugin):

    def __init__(self,a,b):
        BasePlugin.__init__(self,a,b)
        self.currencies = [self.fiat_unit()]
        self.exchanges = [self.config.get('use_exchange', "Blockchain")]
        # Do price discovery
        self.exchanger = Exchanger(self)
        self.exchanger.start()
        self.win = None

    @hook
    def init_qt(self, gui):
        self.gui = gui
        self.win = self.gui.main_window
        self.win.connect(self.win, SIGNAL("refresh_currencies()"), self.win.update_status)
        self.btc_rate = Decimal("0.0")
        self.resp_hist = {}
        self.tx_list = {}
        self.gui.exchanger = self.exchanger #
        self.add_send_edit()
        self.add_receive_edit()
        self.win.update_status()

    def close(self):
        BasePlugin.close(self)
        self.exchanger.stop()
        self.exchanger = None
        self.gui.exchanger = None
        self.send_fiat_e.hide()
        self.receive_fiat_e.hide()
        self.win.update_status()

    def set_currencies(self, currency_options):
        self.currencies = sorted(currency_options)
        if self.win:
            self.win.emit(SIGNAL("refresh_currencies()"))
            self.win.emit(SIGNAL("refresh_currencies_combo()"))

    @hook
    def get_fiat_balance_text(self, btc_balance, r):
        # return balance as: 1.23 USD
        r[0] = self.create_fiat_balance_text(Decimal(btc_balance) / COIN)

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
            fiat_balance = Decimal(btc_price) * Decimal(btc_balance) / COIN
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
    def load_wallet(self, wallet, window):
        tx_list = {}
        for item in self.wallet.get_history(self.wallet.storage.get("current_account", None)):
            tx_hash, conf, value, timestamp, balance = item
            tx_list[tx_hash] = {'value': value, 'timestamp': timestamp }

        self.tx_list = tx_list
        self.cur_exchange = self.config.get('use_exchange', "Blockchain")
        t = threading.Thread(target=self.request_history_rates, args=())
        t.setDaemon(True)
        t.start()


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
                newtx = self.wallet.get_history()
                v = newtx[[x[0] for x in newtx].index(str(item.data(0, Qt.UserRole).toPyObject()))][2]
                tx_info = {'timestamp':int(time.time()), 'value': v}
                pass
            tx_time = int(tx_info['timestamp'])
            tx_value = Decimal(str(tx_info['value'])) / COIN
            if self.cur_exchange == "CoinDesk":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                try:
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(self.resp_hist['bpi'][tx_time_str]), "USD")
                except KeyError:
                    tx_fiat_val = "%.2f %s" % (self.btc_rate * Decimal(str(tx_info['value']))/COIN , "USD")
            elif self.cur_exchange == "Winkdex":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d') + "T16:00:00-04:00"
                try:
                    tx_rate = self.resp_hist[[x['timestamp'] for x in self.resp_hist].index(tx_time_str)]['price']
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(tx_rate)/Decimal("100.0"), "USD")
                except ValueError:
                    tx_fiat_val = "%.2f %s" % (self.btc_rate * Decimal(tx_info['value'])/COIN , "USD")
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
                btc_e.setAmount(int(btc_amount*Decimal(COIN)))
                if fee_e: self.win.update_fee(False)
        fiat_e.textEdited.connect(fiat_changed)
        def btc_changed():
            if self.exchanger is None:
                return
            btc_amount = btc_e.get_amount()
            if btc_amount is None:
                fiat_e.setText("")
                return
            fiat_amount = self.exchanger.exchange(Decimal(btc_amount)/Decimal(COIN), self.fiat_unit())
            if fiat_amount is not None:
                pos = fiat_e.cursorPosition()
                fiat_e.setText("%.2f"%fiat_amount)
                fiat_e.setCursorPosition(pos)
        btc_e.textEdited.connect(btc_changed)
