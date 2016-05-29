import time
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from electrum_gui.qt.util import *
from electrum_gui.qt.amountedit import AmountEdit


from electrum.bitcoin import COIN
from electrum.i18n import _
from decimal import Decimal
from functools import partial
from electrum.plugins import hook
from exchange_rate import FxPlugin
from electrum.util import timestamp_to_datetime

class Plugin(FxPlugin, QObject):

    def __init__(self, parent, config, name):
        FxPlugin.__init__(self, parent, config, name)
        QObject.__init__(self)

    def connect_fields(self, window, btc_e, fiat_e, fee_e):

        def edit_changed(edit):
            if edit.follows:
                return
            edit.setStyleSheet(BLACK_FG)
            fiat_e.is_last_edited = (edit == fiat_e)
            amount = edit.get_amount()
            rate = self.exchange_rate()
            if rate is None or amount is None:
                if edit is fiat_e:
                    btc_e.setText("")
                    if fee_e:
                        fee_e.setText("")
                else:
                    fiat_e.setText("")
            else:
                if edit is fiat_e:
                    btc_e.follows = True
                    btc_e.setAmount(int(amount / Decimal(rate) * COIN))
                    btc_e.setStyleSheet(BLUE_FG)
                    btc_e.follows = False
                    if fee_e:
                        window.update_fee()
                else:
                    fiat_e.follows = True
                    fiat_e.setText(self.ccy_amount_str(
                        amount * Decimal(rate) / COIN, False))
                    fiat_e.setStyleSheet(BLUE_FG)
                    fiat_e.follows = False

        btc_e.follows = False
        fiat_e.follows = False
        fiat_e.textChanged.connect(partial(edit_changed, fiat_e))
        btc_e.textChanged.connect(partial(edit_changed, btc_e))
        fiat_e.is_last_edited = False

    @hook
    def init_qt(self, gui):
        for window in gui.windows:
            self.on_new_window(window)

    @hook
    def do_clear(self, window):
        window.fiat_send_e.setText('')

    def on_close(self):
        self.emit(SIGNAL('close_fx_plugin'))

    def restore_window(self, window):
        window.update_status()
        window.history_list.refresh_headers()
        window.fiat_send_e.hide()
        window.fiat_receive_e.hide()

    def on_quotes(self):
        self.emit(SIGNAL('new_fx_quotes'))

    def on_history(self):
        self.emit(SIGNAL('new_fx_history'))

    def on_fx_history(self, window):
        '''Called when historical fx quotes are updated'''
        window.history_list.update()

    def on_fx_quotes(self, window):
        '''Called when fresh spot fx quotes come in'''
        window.update_status()
        self.populate_ccy_combo()
        # Refresh edits with the new rate
        edit = window.fiat_send_e if window.fiat_send_e.is_last_edited else window.amount_e
        edit.textEdited.emit(edit.text())
        edit = window.fiat_receive_e if window.fiat_receive_e.is_last_edited else window.receive_amount_e
        edit.textEdited.emit(edit.text())
        # History tab needs updating if it used spot
        if self.history_used_spot:
            self.on_fx_history(window)

    def on_ccy_combo_change(self):
        '''Called when the chosen currency changes'''
        ccy = str(self.ccy_combo.currentText())
        if ccy and ccy != self.ccy:
            self.set_currency(ccy)
            self.hist_checkbox_update()

    def hist_checkbox_update(self):
        if self.hist_checkbox:
            self.hist_checkbox.setEnabled(self.ccy in self.exchange.history_ccys())
            self.hist_checkbox.setChecked(self.config_history())

    def populate_ccy_combo(self):
        # There should be at most one instance of the settings dialog
        combo = self.ccy_combo
        # NOTE: bool(combo) is False if it is empty.  Nuts.
        if combo is not None:
            combo.blockSignals(True)
            combo.clear()
            combo.addItems(sorted(self.exchange.quotes.keys()))
            combo.blockSignals(False)
            combo.setCurrentIndex(combo.findText(self.ccy))

    @hook
    def on_new_window(self, window):
        # Additional send and receive edit boxes
        if not hasattr(window, 'fiat_send_e'):
            send_e = AmountEdit(self.get_currency)
            window.send_grid.addWidget(send_e, 4, 2, Qt.AlignLeft)
            window.amount_e.frozen.connect(
                lambda: send_e.setFrozen(window.amount_e.isReadOnly()))
            receive_e = AmountEdit(self.get_currency)
            window.receive_grid.addWidget(receive_e, 2, 2, Qt.AlignLeft)
            window.fiat_send_e = send_e
            window.fiat_receive_e = receive_e
            self.connect_fields(window, window.amount_e, send_e, window.fee_e)
            self.connect_fields(window, window.receive_amount_e, receive_e, None)
        else:
            window.fiat_send_e.show()
            window.fiat_receive_e.show()
        window.history_list.refresh_headers()
        window.update_status()
        window.connect(self, SIGNAL('new_fx_quotes'), lambda: self.on_fx_quotes(window))
        window.connect(self, SIGNAL('new_fx_history'), lambda: self.on_fx_history(window))
        window.connect(self, SIGNAL('close_fx_plugin'), lambda: self.restore_window(window))
        window.connect(self, SIGNAL('refresh_headers'), window.history_list.refresh_headers)

    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        d = WindowModalDialog(window, _("Exchange Rate Settings"))
        layout = QGridLayout(d)
        layout.addWidget(QLabel(_('Exchange rate API: ')), 0, 0)
        layout.addWidget(QLabel(_('Currency: ')), 1, 0)
        layout.addWidget(QLabel(_('History Rates: ')), 2, 0)

        # Currency list
        self.ccy_combo = QComboBox()
        self.ccy_combo.currentIndexChanged.connect(self.on_ccy_combo_change)
        self.populate_ccy_combo()

        def on_change_ex(idx):
            exchange = str(combo_ex.currentText())
            if exchange != self.exchange.name():
                self.set_exchange(exchange)
                self.hist_checkbox_update()

        def on_change_hist(checked):
            if checked:
                self.config.set_key('history_rates', 'checked')
                self.get_historical_rates()
            else:
                self.config.set_key('history_rates', 'unchecked')
            self.emit(SIGNAL('refresh_headers'))

        def ok_clicked():
            self.timeout = 0
            self.ccy_combo = None
            d.accept()

        combo_ex = QComboBox()
        combo_ex.addItems(sorted(self.exchanges.keys()))
        combo_ex.setCurrentIndex(combo_ex.findText(self.config_exchange()))
        combo_ex.currentIndexChanged.connect(on_change_ex)

        self.hist_checkbox = QCheckBox()
        self.hist_checkbox.stateChanged.connect(on_change_hist)
        self.hist_checkbox_update()

        ok_button = QPushButton(_("OK"))
        ok_button.clicked.connect(lambda: ok_clicked())

        layout.addWidget(self.ccy_combo,1,1)
        layout.addWidget(combo_ex,0,1)
        layout.addWidget(self.hist_checkbox,2,1)
        layout.addWidget(ok_button,3,1)

        return d.exec_()


    def config_history(self):
        return self.config.get('history_rates', 'unchecked') != 'unchecked'

    def show_history(self):
        return self.config_history() and self.ccy in self.exchange.history_ccys()

    @hook
    def history_tab_headers(self, headers):
        if self.show_history():
            headers.extend(['%s '%self.ccy + _('Amount'), '%s '%self.ccy + _('Balance')])

    @hook
    def history_tab_update_begin(self):
        self.history_used_spot = False

    @hook
    def history_tab_update(self, tx, entry):
        if not self.show_history():
            return
        tx_hash, height, conf, timestamp, value, balance = tx
        if conf <= 0:
            date = timestamp_to_datetime(time.time())
        else:
            date = timestamp_to_datetime(timestamp)
        for amount in [value, balance]:
            text = self.historical_value_str(amount, date)
            entry.append(text)
