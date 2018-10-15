
#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import

import time
import threading
import base64
from functools import partial

from PyQt5.QtGui import *
from PyQt5.QtCore import *
import PyQt5.QtCore as QtCore
import PyQt5.QtGui as QtGui
from PyQt5.QtWidgets import (QVBoxLayout, QLabel, QGridLayout, QLineEdit, QHBoxLayout, QWidget, QCheckBox, QMenu)

from electroncash.plugins import BasePlugin, hook
from electroncash.i18n import _
from electroncash_gui.qt.util import EnterButton, Buttons, CloseButton
from electroncash_gui.qt.util import OkButton, WindowModalDialog
from electroncash.address import Address
from .shuffle import ChangeAdressWidget, OutputAdressWidget, ConsoleOutput, AmountSelect, ServersList, ExternalOutput, ConsoleLogger, InputAddressesWidget
from .client import bot_job, BotThread
from .coin import Coin

class SimpleLogger(object):

    def __init__(self, logchan = None):
        self.pThread = None
        self.logchan = logchan

    def send(self, message):
        if not self.logchan == None:
            self.logchan.send(message)
        if message.startswith("Error"):
            self.pThread.done.set()
        elif message.startswith("Blame"):
            if "insufficient" in message:
                pass
            elif "wrong hash" in message:
                pass
            else:
                self.pThread.done.set()


class ShuffleWidget(QWidget):

    def __init__(self, window):
        QWidget.__init__(self)
        self.window = window
        self.timer = QtCore.QTimer()
        self.update_inputs_timer = QtCore.QTimer()
        self.waiting_timeout = 180
        self.timer.timeout.connect(self.tick)
        self.update_inputs_timer.timeout.connect(self.update_inputs)
        self.update_inputs_timer.start(15000)
        self.coinshuffle_fee_constant = 1000
        self.bot_thread = None
        self.bot_limit_value = 1
        self.bot_maximum_value = 3
        self.bot_period_value = 1
        self.bot_stopper = False
        # This is for debug
        # self.coinshuffle_fee_constant = 10
        #
        # self.coinshuffle_amounts = [1e7, 1e6]
        # Use this in test mode
        self.coinshuffle_amounts = [1e5, 1e6, 1e7]
        self.shuffle_grid = QGridLayout()
        self.shuffle_grid.setSpacing(8)
        self.shuffle_grid.setColumnStretch(3, 1)

        self.coinshuffle_servers = ServersList()
        self.coinshuffle_enable_bot = QCheckBox(_('Use bot'))
        self.coinshuffle_inputs_label = QLabel(_('Shuffle input address '))
        self.coinshuffle_inputs_total_label = QLabel(_('Total amount in selected coins'))
        self.coinshuffle_inputs_total_output = QLabel()
        self.coinshuffle_changes = ChangeAdressWidget()
        self.coinshuffle_changes_label = QLabel(_('Shuffle change address'))
        self.coinshuffle_fresh_changes = QCheckBox(_('Show only fresh change addresses'))
        self.coinshuffle_use_external_output = QCheckBox(_('Use external output address'))
        self.coinshuffle_outputs = OutputAdressWidget()
        self.coinshuffle_outputs_label = QLabel(_('Shuffle output address'))
        self.coinshuffle_external_output = ExternalOutput(testnet=self.window.config.get("testnet", False))
        self.coinshuffle_amount_radio = AmountSelect(self.coinshuffle_amounts, window = self.window)
        self.coinshuffle_fee = QLabel(_(self.window.format_amount_and_units(self.coinshuffle_fee_constant)))
        self.coinshuffle_amount_label = QLabel(_('Amount'))
        self.coinshuffle_text_output = ConsoleOutput()
        self.coinshuffle_timer_output = QLabel()

        self.coinshuffle_inputs_list = InputAddressesWidget(decimal_point = self.window.get_decimal_point, parent = self.window)

        self.coinshuffle_bot_limit = QLineEdit()
        self.coinshuffle_bot_limit.setValidator(QIntValidator(1,100))
        self.coinshuffle_bot_limit.setText(str(self.bot_limit_value))
        self.coinshuffle_bot_limit_label = QLabel(_('Minimal number of players in pool'))
        self.coinshuffle_bot_maximum = QLineEdit()
        self.coinshuffle_bot_maximum.setValidator(QIntValidator(1,100))
        self.coinshuffle_bot_maximum.setText(str(self.bot_maximum_value))
        self.coinshuffle_bot_maximum_label = QLabel(_('Maximum players to support pool'))
        self.coinshuffle_bot_period = QLineEdit()
        self.coinshuffle_bot_period.setValidator(QIntValidator(1,1000))
        self.coinshuffle_bot_period.setText(str(self.bot_period_value))
        self.coinshuffle_bot_period_label = QLabel(_('Lookup period in minutes'))

        self.coinshuffle_bot_start_button = EnterButton(_("Run bot"),lambda :self.start_bot())
        self.coinshuffle_bot_stop_button = EnterButton(_("Stop bot"),lambda :self.cancel_bot())
        self.coinshuffle_bot_start_button.setEnabled(True)
        self.coinshuffle_bot_stop_button.setEnabled(False)

        self.coinshuffle_bot_limit.hide()
        self.coinshuffle_bot_maximum.hide()
        self.coinshuffle_bot_period.hide()
        self.coinshuffle_bot_limit_label.hide()
        self.coinshuffle_bot_maximum_label.hide()
        self.coinshuffle_bot_period_label.hide()
        self.coinshuffle_bot_start_button.hide()
        self.coinshuffle_bot_stop_button.hide()

        self.coinshuffle_inputs_list.clicked.connect(self.check_sufficient_ammount)
        self.coinshuffle_amount_radio.button_group.buttonClicked.connect(self.check_sufficient_ammount)
        self.coinshuffle_fresh_changes.stateChanged.connect(lambda: self.coinshuffle_changes.update(self.window.wallet, fresh_only = self.coinshuffle_fresh_changes.isChecked()))
        self.coinshuffle_use_external_output.stateChanged.connect(lambda: self.coinshuffle_change_outputs(self.coinshuffle_use_external_output.isChecked()))
        self.coinshuffle_external_output.textChanged.connect(self.check_sufficient_ammount)
        self.coinshuffle_enable_bot.stateChanged.connect(self.switch_bot)


        self.coinshuffle_start_button = EnterButton(_("Shuffle"),lambda :self.start_coinshuffle_protocol())
        self.coinshuffle_cancel_button = EnterButton(_("Cancel"),lambda :self.cancel_coinshuffle_protocol())
        self.coinshuffle_start_button.setEnabled(False)
        self.coinshuffle_cancel_button.setEnabled(False)

        self.shuffle_grid.addWidget(QLabel(_('Shuffle server')), 1, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_inputs_label, 2, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_inputs_total_label , 3, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_inputs_total_output , 3, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_changes_label, 4, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_outputs_label, 6, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_amount_label, 9, 0)
        self.shuffle_grid.addWidget(QLabel(_('Fee')), 10, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_servers, 1, 1, 1, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_enable_bot, 1, 2, 1, -1)
        self.shuffle_grid.addWidget(self.coinshuffle_fresh_changes, 5, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_use_external_output, 7, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_external_output, 8, 1, 1, -1)
        self.shuffle_grid.addWidget(self.coinshuffle_inputs_list, 2, 1, 1, -1)
        self.shuffle_grid.addWidget(self.coinshuffle_changes, 4,1,1,-1)
        self.shuffle_grid.addWidget(self.coinshuffle_outputs, 6,1,1,-1)
        self.shuffle_grid.addWidget(self.coinshuffle_amount_radio, 9,1)
        self.shuffle_grid.addWidget(self.coinshuffle_fee, 10, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_start_button, 11, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_cancel_button, 11, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_timer_output, 11, 2)
        self.shuffle_grid.addWidget(self.coinshuffle_text_output, 12, 0, 1, -1)

        self.shuffle_grid.addWidget(self.coinshuffle_bot_limit, 2, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_bot_maximum, 4, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_bot_period, 5, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_bot_limit_label, 2, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_bot_maximum_label, 4, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_bot_period_label, 5, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_bot_start_button, 6, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_bot_stop_button, 6, 1)

        self.shuffle_grid.addWidget(self.coinshuffle_inputs_list, 13, 1, 1, -1)

        self.window.cashaddr_toggled_signal.connect(lambda: self.update_inputs(force_update=True))

        self.check_sufficient_ammount()

        vbox0 = QVBoxLayout()
        vbox0.addLayout(self.shuffle_grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)
        vbox = QVBoxLayout(self)
        vbox.addLayout(hbox)
        vbox.addStretch(1)

    def disable_bot_settings(self):
        self.coinshuffle_servers.setEnabled(False)
        self.coinshuffle_enable_bot.setEnabled(False)
        self.coinshuffle_bot_limit.setEnabled(False)
        self.coinshuffle_bot_maximum.setEnabled(False)
        self.coinshuffle_bot_period.setEnabled(False)

    def enable_bot_settings(self):
        self.coinshuffle_servers.setEnabled(True)
        self.coinshuffle_enable_bot.setEnabled(True)
        self.coinshuffle_bot_limit.setEnabled(True)
        self.coinshuffle_bot_maximum.setEnabled(True)
        self.coinshuffle_bot_period.setEnabled(True)


    def start_bot(self):
        server_params = self.coinshuffle_servers.get_current_server()
        server = server_params['server']
        port = server_params['port']
        info = server_params['info']
        ssl = server_params.get('ssl', False)
        stat_endpoint = "http{}://{}:{}/stats".format("s" if ssl else "", server, info)
        limit_value = self.coinshuffle_bot_limit.text()
        limit = int(limit_value) if not limit_value == "" else self.bot_limit_value
        maximum_value = self.coinshuffle_bot_maximum.text()
        maximum = int(maximum_value) if not maximum_value == "" else self.bot_maximum_value
        period_value = self.coinshuffle_bot_period.text()
        period = int(period_value) if not period_value == "" else self.bot_period_value
        basic_logger = SimpleLogger(logchan=self.coinshuffle_text_output)
        coin = Coin(self.window.network)
        fee = self.coinshuffle_fee_constant
        password = None
        parent = self.window.top_level_window()
        while self.window.wallet.has_password():
            password = self.window.password_dialog(parent=parent)
            if password is None:
                # User cancelled password input
                return
            try:
                self.window.wallet.check_password(password)
                break
            except Exception as e:
                self.window.show_error(str(e), parent=parent)
                continue
        bot_logger = ConsoleLogger()
        bot_logger.logUpdater.connect(lambda x: self.coinshuffle_text_output.append(x))
        self.bot_thread = BotThread(stat_endpoint, server, port, self.window.network, ssl,
                               limit, maximum, SimpleLogger, self.window.wallet, password,
                               fee, bot_logger, True, period)
        self.bot_thread.start()
        self.disable_bot_settings()
        self.coinshuffle_bot_start_button.setEnabled(False)
        self.coinshuffle_bot_stop_button.setEnabled(True)

    def cancel_bot(self):
        self.coinshuffle_bot_stop_button.setEnabled(False)
        if self.bot_thread:
            self.bot_thread.join()
        self.coinshuffle_bot_start_button.setEnabled(True)
        self.enable_bot_settings()

    def switch_bot(self, checked):
        if checked:
            self.coinshuffle_inputs_list.hide()
            self.coinshuffle_inputs_label.hide()
            self.coinshuffle_inputs_total_label.hide()
            self.coinshuffle_inputs_total_output.hide()
            self.coinshuffle_changes.hide()
            self.coinshuffle_changes_label.hide()
            self.coinshuffle_fresh_changes.hide()
            self.coinshuffle_outputs_label.hide()
            self.coinshuffle_outputs.hide()
            self.coinshuffle_use_external_output.hide()
            self.coinshuffle_external_output.hide()
            self.coinshuffle_amount_label.hide()
            self.coinshuffle_amount_radio.hide()
            self.coinshuffle_start_button.hide()
            self.coinshuffle_cancel_button.hide()
            self.coinshuffle_timer_output.hide()

            self.coinshuffle_bot_limit.show()
            self.coinshuffle_bot_maximum.show()
            self.coinshuffle_bot_period.show()
            self.coinshuffle_bot_limit_label.show()
            self.coinshuffle_bot_maximum_label.show()
            self.coinshuffle_bot_period_label.show()
            self.coinshuffle_bot_start_button.show()
            self.coinshuffle_bot_stop_button.show()


        else:
            self.coinshuffle_bot_limit.hide()
            self.coinshuffle_bot_maximum.hide()
            self.coinshuffle_bot_period.hide()
            self.coinshuffle_bot_limit_label.hide()
            self.coinshuffle_bot_maximum_label.hide()
            self.coinshuffle_bot_period_label.hide()
            self.coinshuffle_bot_start_button.hide()
            self.coinshuffle_bot_stop_button.hide()

            self.coinshuffle_inputs_list.show()
            self.coinshuffle_inputs_label.show()
            self.coinshuffle_inputs_total_label.show()
            self.coinshuffle_inputs_total_output.show()
            self.coinshuffle_changes.show()
            self.coinshuffle_changes_label.show()
            self.coinshuffle_fresh_changes.show()
            self.coinshuffle_outputs_label.show()
            self.coinshuffle_outputs.show()
            self.coinshuffle_use_external_output.show()
            self.coinshuffle_external_output.show()
            self.coinshuffle_amount_label.show()
            self.coinshuffle_amount_radio.show()
            self.coinshuffle_start_button.show()
            self.coinshuffle_cancel_button.show()
            self.coinshuffle_timer_output.show()


    def coinshuffle_change_outputs(self, checked):
        if checked:
            self.coinshuffle_external_output.setEnabled(True)
            self.coinshuffle_outputs.setEnabled(False)
        else:
            self.coinshuffle_external_output.setEnabled(False)
            self.coinshuffle_outputs.setEnabled(True)
        self.check_sufficient_ammount()

    def update_inputs(self, force_update=False):
        if not self.coinshuffle_cancel_button.isEnabled():
            self.coinshuffle_inputs_list.update(self.window.wallet, force_update=force_update)
            self.coinshuffle_outputs.update(self.window.wallet)
            self.coinshuffle_changes.update(self.window.wallet, fresh_only=self.coinshuffle_fresh_changes.isChecked())

    def tick(self):
        self.waiting_timeout -= 1
        if self.waiting_timeout > 0:
            self.coinshuffle_timer_output.setText("{} s to break".format(self.waiting_timeout))
        else:
            self.logger.send("Error: timeout waiting for another players")

    def set_coinshuffle_addrs(self):
        self.coinshuffle_servers.setItems()
        self.coinshufle_input_addrs = map(lambda x: x.get('address'),self.window.wallet.get_utxos())
        self.coinshuffle_outputs_addrs = map(lambda x: x.get('address'),self.window.wallet.get_utxos())
        self.coinshuffle_inputs_list.setItems(self.window.wallet)
        self.coinshuffle_changes.setItems(self.window.wallet, fresh_only=self.coinshuffle_fresh_changes.isChecked())
        self.coinshuffle_outputs.setItems(self.window.wallet)

    def get_sufficient_amount(self):
        return self.coinshuffle_amount_radio.get_amount() + self.coinshuffle_fee_constant

    def check_sufficient_ammount(self):
        coin_amount = self.coinshuffle_inputs_list.get_selected_amount()
        self.coinshuffle_inputs_total_output.setText(self.window.format_amount_and_units(coin_amount))
        shuffle_amount = self.coinshuffle_amount_radio.get_amount()
        fee = self.coinshuffle_fee_constant
        if shuffle_amount and fee:
            if coin_amount > (fee + shuffle_amount):
                self.coinshuffle_start_button.setEnabled(True)
                if self.coinshuffle_use_external_output.isChecked():
                    if not Address.is_valid(self.coinshuffle_external_output.text()):
                        self.coinshuffle_start_button.setEnabled(False)
            else:
                self.coinshuffle_start_button.setEnabled(False)
        else:
            self.coinshuffle_start_button.setEnabled(False)

    def enable_coinshuffle_settings(self):
        # self.check_sufficient_ammount()
        self.coinshuffle_servers.setEnabled(True)
        self.coinshuffle_start_button.setEnabled(True)
        self.coinshuffle_inputs_list.setEnabled(True)
        self.coinshuffle_changes.setEnabled(True)
        self.coinshuffle_outputs.setEnabled(True)
        self.coinshuffle_amount_radio.setEnabled(True)
        self.waiting_timeout = 180
        self.coinshuffle_timer_output.setText("")
        self.coinshuffle_use_external_output.setEnabled(True)
        self.coinshuffle_external_output.setEnabled(True)
        self.coinshuffle_fresh_changes.setEnabled(True)
        self.coinshuffle_enable_bot.setEnabled(True)

    def disable_coinshuffle_settings(self):
        self.coinshuffle_servers.setEnabled(False)
        self.coinshuffle_start_button.setEnabled(False)
        self.coinshuffle_inputs_list.setEnabled(False)
        self.coinshuffle_changes.setEnabled(False)
        self.coinshuffle_outputs.setEnabled(False)
        self.coinshuffle_amount_radio.setEnabled(False)
        self.coinshuffle_use_external_output.setEnabled(False)
        self.coinshuffle_external_output.setEnabled(False)
        self.coinshuffle_fresh_changes.setEnabled(False)
        self.coinshuffle_enable_bot.setEnabled(False)


    def process_protocol_messages(self, message):
        if message.startswith("Error"):
            self.pThread.join()
            self.coinshuffle_text_output.setTextColor(QColor('red'))
            self.coinshuffle_text_output.append(message)
            self.enable_coinshuffle_settings()
            self.coinshuffle_cancel_button.setEnabled(False)
            self.coinshuffle_inputs_list.update(self.window.wallet)
            self.coinshuffle_outputs.update(self.window.wallet)
            self.timer.stop()
        elif message[-17:] == "complete protocol":
            self.coinshuffle_text_output.append(message)
            self.pThread.done.set()
            tx = self.pThread.protocol.tx
            if tx:
                self.pThread.join()
            else:
                print("No tx: " + str(tx.raw))
            self.enable_coinshuffle_settings()
            self.coinshuffle_cancel_button.setEnabled(False)
            self.coinshuffle_inputs_list.update(self.window.wallet)
            self.coinshuffle_outputs.update(self.window.wallet)
        elif "begins" in message:
            self.timer.stop()
            self.coinshuffle_timer_output.setText("")
            self.waiting_timeout = 180
        else:
            header = message[:6]
            if header == 'Player':
                self.coinshuffle_text_output.setTextColor(QColor('green'))
            if header[:5] == 'Blame':
                self.coinshuffle_text_output.setTextColor(QColor('red'))
                if "insufficient" in message:
                    pass
                elif "wrong hash" in message:
                    pass
                else:
                    self.pThread.join()
                    self.enable_coinshuffle_settings()
                    self.coinshuffle_text_output.append(str(self.pThread.isAlive()))
            self.coinshuffle_text_output.append(message)
            self.coinshuffle_text_output.setTextColor(QColor('black'))


    def start_coinshuffle_protocol(self):
        from .client import ProtocolThread
        from electroncash.bitcoin import (regenerate_key, deserialize_privkey)
        from .shuffle import ConsoleLogger
        parent = self.window.top_level_window()
        password = None
        while self.window.wallet.has_password():
            password = self.window.password_dialog(parent=parent)
            if password is None:
                # User cancelled password input
                return
            try:
                self.window.wallet.check_password(password)
                break
            except Exception as e:
                self.window.show_error(str(e), parent=parent)
                continue
        try:
            server_params = self.coinshuffle_servers.get_current_server()
            server = server_params['server']
            port = server_params['port']
            ssl = server_params.get('ssl', False)
        except:
            self.coinshuffle_text_output.setText('Wrong server connection string')
            return

        inputs_utxos = self.coinshuffle_inputs_list.get_checked_utxos()
        possible_change_address = self.coinshuffle_changes.get_change_address()
        if possible_change_address:
            change_address = possible_change_address
        else:
            change_address = inputs_utxos[0]['address'].to_string(Address.FMT_LEGACY)
        if self.coinshuffle_use_external_output.isChecked():
            output_address = self.coinshuffle_external_output.text()
        else:
            output_address = self.coinshuffle_outputs.get_output_address()
        #disable inputs
        self.disable_coinshuffle_settings()
        self.coinshuffle_cancel_button.setEnabled(True)
        #
        amount = self.coinshuffle_amount_radio.get_amount()
        fee = self.coinshuffle_fee_constant
        self.logger = ConsoleLogger()
        self.logger.logUpdater.connect(lambda x: self.process_protocol_messages(x))
        sks = {}
        inputs = {}
        for utxo in inputs_utxos:
            public_key = self.window.wallet.get_public_key(utxo['address'])
            priv_key = self.window.wallet.export_private_key(utxo['address'], password)
            sks[public_key] = regenerate_key(deserialize_privkey(priv_key)[1])
            if not public_key in inputs:
                inputs[public_key] = []
            inputs[public_key].append(utxo['prevout_hash']+ ":" + str(utxo['prevout_n']))
        pub_key = list(inputs.keys())[0]
        sk = sks[pub_key]
        self.pThread = ProtocolThread(server, port, self.window.network,
                                      amount, fee, sk, sks, inputs, pub_key,
                                      output_address, change_address,
                                      logger = self.logger, ssl = ssl)
        self.pThread.start()
        self.timer.start(1000)

    def cancel_coinshuffle_protocol(self):
        if self.pThread.is_alive():
            self.pThread.join()
            while self.pThread.is_alive():
                time.sleep(0.1)
            self.coinshuffle_cancel_button.setEnabled(False)
            self.timer.stop()
            self.enable_coinshuffle_settings()


def set_coins(win, selected):
    checked_utxos = [utxo.replace(":","") for utxo in selected]
    win.parent.cs_tab.coinshuffle_inputs_list.setItems(win.wallet, checked_utxos=checked_utxos)
    win.parent.cs_tab.check_sufficient_ammount()
    win.parent.tabs.setCurrentWidget(win.parent.cs_tab)


def create_coins_menu(win, position):
    selected = [x.data(0, Qt.UserRole) for x in win.selectedItems()]
    if not selected:
        return
    menu = QMenu()
    coins = filter(lambda x: win.get_name(x) in selected, win.utxos)

    menu.addAction(_("Spend"), lambda: win.parent.spend_coins(coins))
    if len(selected) == 1:
        txid = selected[0].split(':')[0]
        tx = win.wallet.transactions.get(txid)
        menu.addAction(_("Details"), lambda: win.parent.show_transaction(tx))

    if len(selected) > 0:
        selected_coins = [utxo for utxo in win.wallet.get_utxos()
                          if "{}:{}".format(utxo['prevout_hash'],utxo['prevout_n']) in selected]
        selected_amount = sum(utxo['value'] for utxo in selected_coins)
        is_enough_for_shuffling = selected_amount >= win.parent.cs_tab.get_sufficient_amount()
        is_not_shuffle_now = not win.parent.cs_tab.coinshuffle_cancel_button.isEnabled()
        if is_enough_for_shuffling and is_not_shuffle_now:
            menu.addAction(_("Shuffle"), lambda : set_coins(win, selected))

    menu.exec_(win.viewport().mapToGlobal(position))

class Plugin(BasePlugin):

    def fullname(self):
        return 'CashShuffle'

    def description(self):
        return _("Configure CashShuffle Protocol")

    def is_available(self):
        return True

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.windows = []

    @hook
    def init_qt(self, gui):
        for window in gui.windows:
            tab_names = [window.tabs.tabText(i) for i in range(window.tabs.count())]
            if "Shuffle" not in tab_names:
                self.on_new_window(window)

    @hook
    def on_new_window(self, window):
        self.utxo_list_menu_backup = window.utxo_list.create_menu
        window.cs_tab = None
        self.update(window)
        window.utxo_list.customContextMenuRequested.disconnect()
        window.utxo_list.customContextMenuRequested.connect(lambda x: create_coins_menu(window.utxo_list, x))

    @hook
    def on_close_window(self, window):
        self.update(window)

    def on_close(self):
        for window in self.windows:
            tabIndex= window.tabs.indexOf(window.cs_tab)
            window.tabs.removeTab(tabIndex)
            del window.cs_tab
            window.utxo_list.customContextMenuRequested.disconnect()
            window.utxo_list.customContextMenuRequested.connect(self.utxo_list_menu_backup)

    def update(self, window):
        window.cs_tab = ShuffleWidget(window)
        window.cs_tab.set_coinshuffle_addrs()
        # icon = QIcon(":icons/tab_coins.png")
        icon = QIcon(":shuffle_tab_ico.png")
        description =  _("Shuffle")
        name = "shuffle"
        window.cs_tab.tab_icon = icon
        window.cs_tab.tab_description = description
        window.cs_tab.tab_pos = len(window.tabs)
        window.cs_tab.tab_name = name
        window.tabs.addTab(window.cs_tab, icon, description.replace("&", ""))
        self.windows.append(window)

    def requires_settings(self):
        return False
