from PyQt4.QtGui import *
from PyQt4.QtCore import *

import datetime
import decimal
import httplib
import json
import threading
import time
import re
from decimal import Decimal
from electrum_ltc.plugins import BasePlugin
from electrum_ltc.i18n import _
from electrum_ltc_gui.qt.util import *
from electrum_ltc_gui.qt.amountedit import AmountEdit


EXCHANGES = ["Bit2C",
             "BitcoinVenezuela",
             "Bitfinex",
             "BTC-e",
             "BTCChina",
             "Crypto-Trade",
             "Kraken",
             "OKCoin",
             "Vault of Satoshi"]


class Exchanger(threading.Thread):

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.daemon = True
        self.parent = parent
        self.quote_currencies = None
        self.lock = threading.Lock()
        self.query_rates = threading.Event()
        self.use_exchange = self.parent.config.get('use_exchange', "BTC-e")
        self.parent.exchanges = EXCHANGES
        self.parent.currencies = ["EUR","GBP","USD"]
        self.parent.win.emit(SIGNAL("refresh_exchanges_combo()"))
        self.parent.win.emit(SIGNAL("refresh_currencies_combo()"))
        self.is_running = False

    def get_json(self, site, get_string):
        try:
            connection = httplib.HTTPSConnection(site)
            connection.request("GET", get_string)
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
        self.use_exchange = self.parent.config.get('use_exchange', "BTC-e")
        update_rates = {
            "Bit2C": self.update_b2c,
            "BitcoinVenezuela": self.update_bv,
            "Bitfinex": self.update_bf,
            "BTC-e": self.update_be,
            "BTCChina": self.update_CNY,
            "Crypto-Trade": self.update_ct,
            "Kraken": self.update_kk,
            "OKCoin": self.update_ok,
            "Vault of Satoshi": self.update_vs,
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


    def update_b2c(self):
        quote_currencies = {"NIS": 0.0}
        for cur in quote_currencies:
            try:
                quote_currencies[cur] = self.get_json('www.bit2c.co.il', "/Exchanges/LTC" + cur + "/Ticker.json")["ll"]
            except Exception:
                pass
        with self.lock:
            self.quote_currencies = quote_currencies
        self.parent.set_currencies(quote_currencies)

    def update_bv(self):
        try:
            jsonresp = self.get_json('api.bitcoinvenezuela.com', "/")
        except Exception:
            return
        quote_currencies = {}
        try:
            for r in jsonresp["LTC"]:
                quote_currencies[r] = Decimal(jsonresp["LTC"][r])
            with self.lock:
                self.quote_currencies = quote_currencies
        except KeyError:
            pass
        self.parent.set_currencies(quote_currencies)

    def update_bf(self):
        quote_currencies = {"USD": 0.0}
        for cur in quote_currencies:
            try:
                quote_currencies[cur] = self.get_json('api.bitfinex.com', "/v1/pubticker/ltc" + cur.lower())["last_price"]
            except Exception:
                pass
        with self.lock:
            self.quote_currencies = quote_currencies
        self.parent.set_currencies(quote_currencies)

    def update_be(self):
        quote_currencies = {"CNH": 0.0, "EUR": 0.0, "GBP": 0.0, "RUR": 0.0, "USD": 0.0}
        for cur in quote_currencies:
            try:
                quote_currencies[cur] = self.get_json('btc-e.com', "/api/2/ltc_" + cur.lower() + "/ticker")["ticker"]["last"]
            except Exception:
                pass
        with self.lock:
            self.quote_currencies = quote_currencies
        self.parent.set_currencies(quote_currencies)

    def update_CNY(self):
        try:
            jsonresp = self.get_json('data.btcchina.com', "/data/ticker?market=ltccny")
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

    def update_ct(self):
        quote_currencies = {"EUR": 0.0, "USD": 0.0}
        for cur in quote_currencies:
            try:
                quote_currencies[cur] = self.get_json('www.crypto-trade.com', "/api/1/ticker/ltc_" + cur.lower())["data"]["last"]
            except Exception:
                pass
        with self.lock:
            self.quote_currencies = quote_currencies
        self.parent.set_currencies(quote_currencies)

    def update_kk(self):
        try:
            resp_currencies = self.get_json('api.kraken.com', "/0/public/AssetPairs")["result"]
            pairs = ','.join([k for k in resp_currencies if k.startswith("XLTCZ")])
            resp_rate = self.get_json('api.kraken.com', "/0/public/Ticker?pair=" + pairs)["result"]
        except Exception:
            return
        quote_currencies = {}
        for cur in resp_rate:
            quote_currencies[cur[5:]] = resp_rate[cur]["c"][0]
        with self.lock:
            self.quote_currencies = quote_currencies
        self.parent.set_currencies(quote_currencies)

    def update_ok(self):
        try:
            jsonresp = self.get_json('www.okcoin.com', "/api/ticker.do?symbol=ltc_cny")
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

    def update_vs(self):
        quote_currencies = {"CAD": 0.0, "USD": 0.0}
        for cur in quote_currencies:
            try:
                quote_currencies[cur] = self.get_json('api.vaultofsatoshi.com', "/public/ticker?order_currency=LTC&payment_currency=" + cur)["data"]["closing_price"]["value"]
            except Exception:
                pass
        with self.lock:
            self.quote_currencies = quote_currencies
        self.parent.set_currencies(quote_currencies)


    def get_currencies(self):
        return [] if self.quote_currencies == None else sorted(self.quote_currencies.keys())


class Plugin(BasePlugin):

    def fullname(self):
        return "Exchange rates"

    def description(self):
        return """exchange rates, retrieved from BTC-e and other market exchanges"""


    def __init__(self,a,b):
        BasePlugin.__init__(self,a,b)
        self.currencies = [self.config.get('currency', "EUR")]
        self.exchanges = [self.config.get('use_exchange', "BTC-e")]

    def init(self):
        self.win = self.gui.main_window
        self.win.connect(self.win, SIGNAL("refresh_currencies()"), self.win.update_status)
        self.btc_rate = Decimal("0.0")
        # Do price discovery
        self.exchanger = Exchanger(self)
        self.exchanger.start()
        self.gui.exchanger = self.exchanger #

    def set_currencies(self, currency_options):
        self.currencies = sorted(currency_options)
        self.win.emit(SIGNAL("refresh_currencies()"))
        self.win.emit(SIGNAL("refresh_currencies_combo()"))

    def get_fiat_balance_text(self, btc_balance, r):
        # return balance as: 1.23 USD
        r[0] = self.create_fiat_balance_text(Decimal(btc_balance) / 100000000)

    def get_fiat_price_text(self, r):
        # return BTC price as: 123.45 USD
        r[0] = self.create_fiat_balance_text(1)
        quote = r[0]
        if quote:
            r[0] = "%s"%quote

    def get_fiat_status_text(self, btc_balance, r2):
        # return status as:   (1.23 USD)    1 BTC~123.45 USD
        text = ""
        r = {}
        self.get_fiat_price_text(r)
        quote = r.get(0)
        if quote:
            price_text = "1 LTC~%s"%quote
            fiat_currency = quote[-3:]
            btc_price = quote[:-4]
            fiat_balance = Decimal(btc_price) * (Decimal(btc_balance)/100000000)
            balance_text = "(%.2f %s)" % (fiat_balance,fiat_currency)
            text = "  " + balance_text + "     " + price_text + " "
        r2[0] = text

    def create_fiat_balance_text(self, btc_balance):
        quote_currency = self.config.get("currency", "EUR")
        self.exchanger.use_exchange = self.config.get("use_exchange", "BTC-e")
        cur_rate = self.exchanger.exchange(Decimal("1.0"), quote_currency)
        if cur_rate is None:
            quote_text = ""
        else:
            quote_balance = btc_balance * Decimal(cur_rate)
            self.btc_rate = cur_rate
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
        if self.config.get('use_exchange_rate'):
            try:
                self.fiat_button
            except:
                self.gui.main_window.show_message(_("To see fiat amount when sending bitcoin, please restart Electrum to activate the new GUI settings."))
        return out


    def close(self):
        self.exchanger.stop()

    def history_tab_update(self):
        if self.config.get('history_rates', 'unchecked') == "checked":
            cur_exchange = self.config.get('use_exchange', "BTC-e")
            try:
                tx_list = self.tx_list
            except Exception:
                return

            try:
                mintimestr = datetime.datetime.fromtimestamp(int(min(tx_list.items(), key=lambda x: x[1]['timestamp'])[1]['timestamp'])).strftime('%Y-%m-%d')
            except Exception:
                return
            maxtimestr = datetime.datetime.now().strftime('%Y-%m-%d')

            if cur_exchange == "CoinDesk":
                try:
                    resp_hist = self.exchanger.get_json('api.coindesk.com', "/v1/bpi/historical/close.json?start=" + mintimestr + "&end=" + maxtimestr)
                except Exception:
                    return
            elif cur_exchange == "Winkdex":
                try:
                    resp_hist = self.exchanger.get_json('winkdex.com', "/static/data/0_86400_730.json")['prices']
                except Exception:
                    return
            elif cur_exchange == "BitcoinVenezuela":
                cur_currency = self.config.get('currency', "EUR")
                if cur_currency in ("ARS", "EUR", "USD", "VEF"):
                    try:
                        resp_hist = self.exchanger.get_json('api.bitcoinvenezuela.com', "/historical/index.php?coin=LTC")[cur_currency + '_LTC']
                    except Exception:
                        return
                else:
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

                    tx_info = {'timestamp':int(time.time()), 'value': v }
                    pass
                tx_time = int(tx_info['timestamp'])
                if cur_exchange == "CoinDesk":
                    tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                    try:
                        tx_USD_val = "%.2f %s" % (Decimal(str(tx_info['value'])) / 100000000 * Decimal(resp_hist['bpi'][tx_time_str]), "USD")
                    except KeyError:
                        tx_USD_val = "%.2f %s" % (self.btc_rate * Decimal(str(tx_info['value']))/100000000 , "USD")
                elif cur_exchange == "Winkdex":
                    tx_time_str = int(tx_time) - (int(tx_time) % (60 * 60 * 24))
                    try:
                        tx_rate = resp_hist[[x['x'] for x in resp_hist].index(tx_time_str)]['y']
                        tx_USD_val = "%.2f %s" % (Decimal(tx_info['value']) / 100000000 * Decimal(tx_rate), "USD")
                    except ValueError:
                        tx_USD_val = "%.2f %s" % (self.btc_rate * Decimal(tx_info['value'])/100000000 , "USD")
                elif cur_exchange == "BitcoinVenezuela":
                    tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                    try:
                        num = resp_hist[tx_time_str].replace(',','')
                        tx_BTCVEN_val = "%.2f %s" % (Decimal(str(tx_info['value'])) / 100000000 * Decimal(num), cur_currency)
                    except KeyError:
                        tx_BTCVEN_val = _("No data")

                if cur_exchange == "CoinDesk" or cur_exchange == "Winkdex":
                    item.setText(5, tx_USD_val)
                elif cur_exchange == "BitcoinVenezuela":
                    item.setText(5, tx_BTCVEN_val)
                if Decimal(str(tx_info['value'])) < 0:
                    item.setForeground(5, QBrush(QColor("#BC1E1E")))

            for i, width in enumerate(self.gui.main_window.column_widths['history']):
                self.gui.main_window.history_list.setColumnWidth(i, width)
            self.gui.main_window.history_list.setColumnWidth(4, 140)
            self.gui.main_window.history_list.setColumnWidth(5, 120)
            self.gui.main_window.is_edit = False


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
        if self.config.get('history_rates', 'unchecked') == 'unchecked':
            hist_checkbox.setChecked(False)
        else:
            hist_checkbox.setChecked(True)
        ok_button = QPushButton(_("OK"))

        def on_change(x):
            try:
                cur_request = str(self.currencies[x])
            except Exception:
                return
            if cur_request != self.config.get('currency', "EUR"):
                self.config.set_key('currency', cur_request, True)
                cur_exchange = self.config.get('use_exchange', "BTC-e")
                if cur_request == "USD" and (cur_exchange == "CoinDesk" or cur_exchange == "Winkdex"):
                    hist_checkbox.setEnabled(True)
                elif cur_request in ("ARS", "EUR", "USD", "VEF") and (cur_exchange == "BitcoinVenezuela"):
                    hist_checkbox.setEnabled(True)
                else:
                    hist_checkbox.setChecked(False)
                    hist_checkbox.setEnabled(False)
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
            if cur_request != self.config.get('use_exchange', "BTC-e"):
                self.config.set_key('use_exchange', cur_request, True)
                self.currencies = []
                combo.clear()
                self.exchanger.query_rates.set()
                cur_currency = self.config.get('currency', "EUR")
                if cur_request == "CoinDesk" or cur_request == "Winkdex":
                    if cur_currency == "USD":
                        hist_checkbox.setEnabled(True)
                    else:
                        disable_check()
                elif cur_request == "BitcoinVenezuela":
                    if cur_currency in ("ARS", "EUR", "USD", "VEF"):
                        hist_checkbox.setEnabled(True)
                    else:
                        disable_check()
                else:
                    disable_check()
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
            cur_exchange = self.config.get('use_exchange', "BTC-e")
            if cur_exchange == "CoinDesk" or cur_exchange == "Winkdex":
                hist_checkbox.setEnabled(True)
            elif cur_exchange == "BitcoinVenezuela":
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
                index = self.exchanges.index(self.config.get('use_exchange', "BTC-e"))
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
        quote_currency = self.config.get("currency", "???")
        return quote_currency

    def fiat_dialog(self):
        if not self.config.get('use_exchange_rate'):
          self.gui.main_window.show_message(_("To use this feature, first enable the exchange rate plugin."))
          return

        if not self.gui.main_window.network.is_connected():
          self.gui.main_window.show_message(_("To use this feature, you must have a network connection."))
          return

        quote_currency = self.fiat_unit()

        d = QDialog(self.gui.main_window)
        d.setWindowTitle("Fiat")
        vbox = QVBoxLayout(d)
        text = "Amount to Send in " + quote_currency
        vbox.addWidget(QLabel(_(text)+':'))

        grid = QGridLayout()
        fiat_e = AmountEdit(self.fiat_unit)
        grid.addWidget(fiat_e, 1, 0)

        r = {}
        self.get_fiat_price_text(r)
        quote = r.get(0)
        if quote:
          text = "1 LTC~%s"%quote
          grid.addWidget(QLabel(_(text)), 4, 0, 3, 0)
        else:
            self.gui.main_window.show_message(_("Exchange rate not available.  Please check your network connection."))
            return

        vbox.addLayout(grid)
        vbox.addLayout(ok_cancel_buttons(d))

        if not d.exec_():
            return

        fiat = str(fiat_e.text())

        if str(fiat) == "" or str(fiat) == ".":
            fiat = "0"

        quote = quote[:-4]
        btcamount = Decimal(fiat) / Decimal(quote)
        if str(self.gui.main_window.base_unit()) == "mLTC":
            btcamount = btcamount * 1000
        quote = "%.8f"%btcamount
        self.gui.main_window.amount_e.setText( quote )

    def exchange_rate_button(self, grid):
        quote_currency = self.config.get("currency", "EUR")
        self.fiat_button = EnterButton(_(quote_currency), self.fiat_dialog)
        grid.addWidget(self.fiat_button, 4, 3, Qt.AlignHCenter)
