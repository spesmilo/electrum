from PyQt4.QtGui import *
from PyQt4.QtCore import *

import datetime
import requests
import threading
import time
from decimal import Decimal

from electrum.bitcoin import COIN
from electrum.plugins import BasePlugin, hook
from electrum.i18n import _
from electrum.util import ThreadJob
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

class Exchanger(ThreadJob):

    def __init__(self, parent):
        self.parent = parent
        self.quote_currencies = None
        self.timeout = 0

    def get_json(self, site, get_string):
        resp = requests.request('GET', 'https://' + site + get_string, headers={"User-Agent":"Electrum"})
        return resp.json()

    def exchange(self, btc_amount, quote_currency):
        if self.quote_currencies is None:
            return None
        quote_currencies = self.quote_currencies.copy()
        if quote_currency not in quote_currencies:
            return None
        return btc_amount * Decimal(str(quote_currencies[quote_currency]))

    def update_rate(self):
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
            rates = update_rates[self.parent.exchange]()
        except Exception as e:
            self.parent.print_error(e)
            rates = {}
        self.quote_currencies = rates
        self.parent.set_currencies(rates)
        self.parent.refresh_fields()

    def run(self):
        if self.parent.gui and self.timeout <= time.time():
            self.update_rate()
            self.timeout = time.time() + 150

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
        self.exchange = self.config.get('use_exchange', "Blockchain")
        self.currencies = [self.fiat_unit()]
        self.exchanger = Exchanger(self)
        self.resp_hist = {}
        self.btc_rate = Decimal("0.0")
        self.network = None
        self.gui = None
        self.wallet_tx_list = {}

    @hook
    def set_network(self, network):
        if network != self.network:
            if self.network:
                self.network.remove_job(self.exchanger)
            self.network = network
            if network:
                network.add_job(self.exchanger)

    @hook
    def init_qt(self, gui):
        self.gui = gui
        # For mid-session plugin loads
        for window in gui.windows:
            self.new_window(window)
        self.new_wallets([window.wallet for window in gui.windows])

    @hook
    def new_window(self, window):
        window.connect(window, SIGNAL("refresh_currencies()"),
                       window.update_status)
        window.fx_fields = {}
        self.add_send_edit(window)
        self.add_receive_edit(window)
        window.update_status()

    def close(self):
        BasePlugin.close(self)
        self.set_network(None)
        self.exchanger = None
        for window in self.gui.windows:
            window.send_fiat_e.hide()
            window.receive_fiat_e.hide()
            window.update_status()

    def set_currencies(self, currency_options):
        self.currencies = sorted(currency_options)
        for window in self.gui.windows:
            window.emit(SIGNAL("refresh_currencies()"))
            window.emit(SIGNAL("refresh_currencies_combo()"))

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
        self.new_wallets([wallet])

    def new_wallets(self, wallets):
        if wallets:
            # For mid-session plugin loads
            self.set_network(wallets[0].network)
            for wallet in wallets:
                if wallet not in self.wallet_tx_list:
                    self.wallet_tx_list[wallet] = None
            self.get_historical_rates()

    def get_historical_rates(self):
        '''Request historic rates for all wallets for which they haven't yet
        been requested
        '''
        if self.config.get('history_rates') != "checked":
            return
        all_txs = {}
        new = False
        for wallet in self.wallet_tx_list:
            if self.wallet_tx_list[wallet] is None:
                new = True
                self.print_error("New wallet:", wallet)
                tx_list = {}
                for item in wallet.get_history(wallet.storage.get("current_account", None)):
                    tx_hash, conf, value, timestamp, balance = item
                    tx_list[tx_hash] = {'value': value, 'timestamp': timestamp }
                    # FIXME: not robust to request failure
                self.wallet_tx_list[wallet] = tx_list
            all_txs.update(self.wallet_tx_list[wallet])
        if new:
            self.print_error("requesting historical FX rates")
            t = threading.Thread(target=self.request_historical_rates,
                                 args=(all_txs,))
            t.setDaemon(True)
            t.start()

    def request_historical_rates(self, tx_list):
        try:
            mintimestr = datetime.datetime.fromtimestamp(int(min(tx_list.items(), key=lambda x: x[1]['timestamp'])[1]['timestamp'])).strftime('%Y-%m-%d')
        except Exception:
            return
        maxtimestr = datetime.datetime.now().strftime('%Y-%m-%d')

        if self.exchange == "CoinDesk":
            try:
                self.resp_hist = self.exchanger.get_json('api.coindesk.com', "/v1/bpi/historical/close.json?start=" + mintimestr + "&end=" + maxtimestr)
            except Exception:
                return
        elif self.exchange == "Winkdex":
            try:
                self.resp_hist = self.exchanger.get_json('winkdex.com', "/api/v0/series?start_time=1342915200")['series'][0]['results']
            except Exception:
                return
        elif self.exchange == "BitcoinVenezuela":
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

        for window in self.gui.windows:
            window.need_update.set()

    def requires_settings(self):
        return True

    @hook
    def history_tab_update(self, window):
        if self.config.get('history_rates') != "checked":
            return
        if not self.resp_hist:
            return
        wallet = window.wallet
        tx_list = self.wallet_tx_list.get(wallet)
        if not wallet or not tx_list:
            return
        window.is_edit = True
        window.history_list.setColumnCount(7)
        window.history_list.setHeaderLabels([ '', '', _('Date'), _('Description') , _('Amount'), _('Balance'), _('Fiat Amount')] )
        root = window.history_list.invisibleRootItem()
        childcount = root.childCount()
        for i in range(childcount):
            item = root.child(i)
            try:
                tx_info = tx_list[str(item.data(0, Qt.UserRole).toPyObject())]
            except Exception:
                newtx = wallet.get_history()
                v = newtx[[x[0] for x in newtx].index(str(item.data(0, Qt.UserRole).toPyObject()))][2]
                tx_info = {'timestamp':int(time.time()), 'value': v}
                pass
            tx_time = int(tx_info['timestamp'])
            tx_value = Decimal(str(tx_info['value'])) / COIN
            if self.exchange == "CoinDesk":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                try:
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(self.resp_hist['bpi'][tx_time_str]), "USD")
                except KeyError:
                    tx_fiat_val = "%.2f %s" % (self.btc_rate * Decimal(str(tx_info['value']))/COIN , "USD")
            elif self.exchange == "Winkdex":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d') + "T16:00:00-04:00"
                try:
                    tx_rate = self.resp_hist[[x['timestamp'] for x in self.resp_hist].index(tx_time_str)]['price']
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(tx_rate)/Decimal("100.0"), "USD")
                except ValueError:
                    tx_fiat_val = "%.2f %s" % (self.btc_rate * Decimal(tx_info['value'])/COIN , "USD")
                except KeyError:
                    tx_fiat_val = _("No data")
            elif self.exchange == "BitcoinVenezuela":
                tx_time_str = datetime.datetime.fromtimestamp(tx_time).strftime('%Y-%m-%d')
                try:
                    num = self.resp_hist[tx_time_str].replace(',','')
                    tx_fiat_val = "%.2f %s" % (tx_value * Decimal(num), self.fiat_unit())
                except KeyError:
                    tx_fiat_val = _("No data")

            tx_fiat_val = " "*(12-len(tx_fiat_val)) + tx_fiat_val
            item.setText(6, tx_fiat_val)
            item.setFont(6, QFont(MONOSPACE_FONT))
            if Decimal(str(tx_info['value'])) < 0:
                item.setForeground(6, QBrush(QColor("#BC1E1E")))

            # We autosize but in some cases QT doesn't handle that
            # properly for new columns it seems
            window.history_list.setColumnWidth(6, 120)
            window.is_edit = False


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
        combo_ex.addItems(EXCHANGES)
        combo_ex.setCurrentIndex(combo_ex.findText(self.exchange))
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
                if (self.exchange, cur_request) in EXCH_SUPPORT_HIST:
                    hist_checkbox.setEnabled(True)
                else:
                    disable_check()
                for window in self.gui.windows:
                    window.update_status()
                try:
                    self.fiat_button
                except:
                    pass
                else:
                    self.fiat_button.setText(cur_request)

        def disable_check():
            hist_checkbox.setChecked(False)
            hist_checkbox.setEnabled(False)

        def on_change_ex(exchange):
            exchange = str(exchange)
            if exchange != self.exchange:
                self.exchange = exchange
                self.config.set_key('use_exchange', exchange, True)
                self.currencies = []
                combo.clear()
                self.timeout = 0
                cur_currency = self.fiat_unit()
                if (exchange, cur_currency) in EXCH_SUPPORT_HIST:
                    hist_checkbox.setEnabled(True)
                else:
                    disable_check()
                set_currencies(combo)
                for window in self.gui.windows:
                    window.update_status()

        def on_change_hist(checked):
            if checked:
                self.config.set_key('history_rates', 'checked')
                self.get_historical_rates()
            else:
                self.config.set_key('history_rates', 'unchecked')
                for window in self.gui.windows:
                    window.history_list.setHeaderLabels( [ '', '', _('Date'), _('Description') , _('Amount'), _('Balance')] )
                    window.history_list.setColumnCount(6)

        def set_hist_check(hist_checkbox):
            hist_checkbox.setEnabled(self.exchange in ["CoinDesk", "Winkdex", "BitcoinVenezuela"])

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

        def ok_clicked():
            if self.exchange in ["CoinDesk", "itBit"]:
                self.timeout = 0
            d.accept();

        set_currencies(combo)
        set_hist_check(hist_checkbox)
        combo.currentIndexChanged.connect(on_change)
        combo_ex.currentIndexChanged.connect(on_change_ex)
        hist_checkbox.stateChanged.connect(on_change_hist)
        for window in self.gui.windows:
            combo.connect(window, SIGNAL('refresh_currencies_combo()'), lambda: set_currencies(combo))
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

    def refresh_fields(self):
        '''Update the display at the new rate'''
        for window in self.gui.windows:
            for field in window.fx_fields.values():
                field.textEdited.emit(field.text())

    def add_send_edit(self, window):
        window.send_fiat_e = AmountEdit(self.fiat_unit)
        self.connect_fields(window, True)
        window.send_grid.addWidget(window.send_fiat_e, 4, 3, Qt.AlignHCenter)
        window.amount_e.frozen.connect(lambda: window.send_fiat_e.setFrozen(window.amount_e.isReadOnly()))

    def add_receive_edit(self, window):
        window.receive_fiat_e = AmountEdit(self.fiat_unit)
        self.connect_fields(window, False)
        window.receive_grid.addWidget(window.receive_fiat_e, 2, 3, Qt.AlignHCenter)

    def connect_fields(self, window, send):
        if send:
            btc_e, fiat_e, fee_e = (window.amount_e, window.send_fiat_e,
                                    window.fee_e)
        else:
            btc_e, fiat_e, fee_e = (window.receive_amount_e,
                                    window.receive_fiat_e, None)
        def fiat_changed():
            fiat_e.setStyleSheet(BLACK_FG)
            window.fx_fields[(fiat_e, btc_e)] = fiat_e
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
                btc_e.setStyleSheet(BLUE_FG)
                if fee_e: window.update_fee()
        fiat_e.textEdited.connect(fiat_changed)
        def btc_changed():
            btc_e.setStyleSheet(BLACK_FG)
            window.fx_fields[(fiat_e, btc_e)] = btc_e
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
                fiat_e.setStyleSheet(BLUE_FG)
        btc_e.textEdited.connect(btc_changed)
        window.fx_fields[(fiat_e, btc_e)] = btc_e

    @hook
    def do_clear(self, window):
        window.send_fiat_e.setText('')
