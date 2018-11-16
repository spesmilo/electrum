
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

import os
import json
from functools import partial

from PyQt5.QtGui import *
from PyQt5.QtCore import *
import PyQt5.QtCore as QtCore
import PyQt5.QtGui as QtGui
from PyQt5.QtWidgets import QVBoxLayout, QLabel, QGridLayout, QLineEdit, QHBoxLayout, QWidget, QCheckBox, QMenu, QComboBox, QMessageBox

from electroncash.plugins import BasePlugin, hook
from electroncash.i18n import _
from electroncash_gui.qt.util import EnterButton, Buttons, CloseButton
from electroncash_gui.qt.util import OkButton, WindowModalDialog
from electroncash.address import Address
from electroncash.transaction import Transaction
from electroncash_plugins.shuffle.client import BackgroundShufflingThread

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


def set_coins(win, selected):
    checked_utxos = [utxo.replace(":","") for utxo in selected]
    win.parent.cs_tab.coinshuffle_inputs_list.setItems(win.wallet, checked_utxos=checked_utxos)
    win.parent.cs_tab.check_sufficient_ammount()
    win.parent.tabs.setCurrentWidget(win.parent.cs_tab)


def is_coin_shuffled(wallet, coin):
    txs = wallet.storage.get("transactions", {})
    coin_out_n = coin['prevout_n']
    if coin['prevout_hash'] in txs:
        tx = Transaction(txs[coin['prevout_hash']])
        outputs = tx.outputs()
        inputs_len = len(tx.inputs())
        outputs_groups = {}
        for out_n, output in enumerate(outputs):
            amount = output[2]
            if outputs_groups.get(amount):
                outputs_groups[amount].append(out_n)
            else:
                outputs_groups[amount] = [out_n]
        for amount in outputs_groups:
            group_len = len(outputs_groups[amount])
            if group_len > 2 and amount in [10000, 100000, 1000000, 10000000, 100000000]:
                if coin_out_n in outputs_groups[amount] and inputs_len >= group_len:
                    return True
        return False
    else:
        return None

def get_shuffled_coins(wallet):
    utxos = wallet.get_utxos()
    transactions = wallet.storage.get("transactions")
    return [utxo for utxo in utxos if wallet.is_coin_shuffled(utxo)]

def on_utxo_list_update(utxo_list):
    utxo_list.on_update_backup()
    utxo_labels = {}
    queued_labels = {}
    in_progress = {}
    wait_for_others = {}
    too_big_labels = {}
    dust_labels = {}
    not_confirmed = {}
    for utxo in utxo_list.utxos:
        name = utxo_list.get_name(utxo)
        short_name = name[0:10] + '...' + name[-2:]
        utxo_labels[short_name] = utxo_list.wallet.is_coin_shuffled(utxo) # is it optimal to do so?
        in_progress[short_name] = utxo_list.in_progress.get(name) == 'in progress'
        wait_for_others[short_name] = utxo_list.in_progress.get(name) == "wait for others"
        queued_labels[short_name] = utxo['value'] > 10000 and utxo['value']<1000000000
        too_big_labels[short_name] = utxo['value'] >= 1000000000
        dust_labels[short_name] = utxo['value'] <= 10000
        not_confirmed[short_name] = utxo['height'] <= 0
    # shuffle_icon = QIcon(":shuffle_tab_ico.png")
    for index in range(utxo_list.topLevelItemCount()):
        item = utxo_list.topLevelItem(index)
        label = item.data(4, Qt.DisplayRole)
        if utxo_labels[label]:
            item.setData(5, Qt.DisplayRole, "shuffled")
        elif not_confirmed[label]:
            item.setData(5, Qt.DisplayRole, "not confirmed")
        elif queued_labels[label]:
            item.setData(5, Qt.DisplayRole, "in queue")
        elif too_big_labels[label]:
            item.setData(5, Qt.DisplayRole, "too big coin")
        elif dust_labels[label]:
            item.setData(5, Qt.DisplayRole, "too small coin")
        else:
            item.setData(5, Qt.DisplayRole, "DEFAULT NONBLANK VALUE")
        if in_progress[label]:
            item.setData(5, Qt.DisplayRole, "in progress")
        if wait_for_others[label]:
            item.setData(5, Qt.DisplayRole, "wait for others")


def update_coin_status(window, coin_name, msg):
    if coin_name not in ["MAINLOG", "PROTOCOL"]:
        if msg.startswith("Player") and coin_name not in window.utxo_list.in_progress:
            if "get session number" in msg:
                window.utxo_list.in_progress[coin_name] = 'wait for others'
                window.utxo_list.on_update()
        elif msg.startswith("Player"):
            if "begins CoinShuffle protocol" in msg:
                window.utxo_list.in_progress[coin_name] = 'in progress'
                window.utxo_list.on_update()
        elif msg.startswith("Error"):
            if coin_name in window.utxo_list.in_progress:
                del window.utxo_list.in_progress[coin_name]
                window.utxo_list.on_update()
        elif msg.endswith("complete protocol"):
            if coin_name in window.utxo_list.in_progress:
                del window.utxo_list.in_progress[coin_name]
                window.utxo_list.on_update()
        elif msg.startswith("Blame") and "insufficient" not in message and "wrong hash" not in message:
            if coin_name in window.utxo_list.in_progress:
                del window.utxo_list.in_progress[coin_name]
                window.utxo_list.on_update()
    else:
        if msg == "stopped":
            window.utxo_list.in_progress = {}
            window.utxo_list.on_update()


class ServersList(QComboBox):

    def __init__(self, parent=None):
        QComboBox.__init__(self, parent)
        self.servers_path = "servers.json"
        self.servers_list = None
        self.load_servers_list()

    def load_servers_list(self):
        r = {}
        try:
            zips = __file__.find(".zip")
            if zips == -1:
                with open(os.path.join(os.path.dirname(__file__), self.servers_path), 'r') as f:
                    r = json.loads(f.read())
            else:
                from zipfile import ZipFile
                zip_file = ZipFile(__file__[: zips + 4])
                with zip_file.open("shuffle/" + self.servers_path) as f:
                    r = json.loads(f.read().decode())
        except:
            pass
        self.servers_list = r

    def setItems(self):
        for server in self.servers_list:
            ssl = self.servers_list[server].get('ssl')
            item = server + ('   [ssl enabled]' if ssl else '   [ssl disabled]')
            self.addItem(item)

    def get_current_server(self):
        current_server = self.currentText().split(' ')[0]
        server = self.servers_list.get(current_server)
        server["server"] = current_server
        return server



class electrum_console_logger(QObject):

    gotMessage = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super(QObject, self).__init__(parent)
        self.parent = parent

    def send(self, msg, sender):
        self.gotMessage.emit(msg, sender)


def start_background_shuffling(window, network_settings, period = 1, password=None):
    logger = electrum_console_logger()
    # logger.gotMessage.connect(lambda msg, sender: window.console.showMessage("{}: {}".format(sender, msg)))
    logger.gotMessage.connect(lambda msg, sender: update_coin_status(window, sender, msg))

    window.background_process = BackgroundShufflingThread(window.wallet, network_settings,
                                                          logger=logger,
                                                          period=period,
                                                          password=password)
    window.background_process.start()

def modify_utxo_list(window):
    header = window.utxo_list.headerItem()
    header_labels = [header.text(i) for i in range(header.columnCount())]
    header_labels.append("Shuffling status")
    window.utxo_list.setColumnCount(6)
    window.utxo_list.setHeaderLabels(header_labels)
    window.utxo_list.on_update_backup = window.utxo_list.on_update
    window.utxo_list.on_update = lambda: on_utxo_list_update(window.utxo_list)
    window.utxo_list.in_progress = {}

def restore_utxo_list(window):
    header = window.utxo_list.headerItem()
    header_labels = [header.text(i) for i in range(header.columnCount())]
    del header_labels[-1]
    window.utxo_list.setColumnCount(5)
    window.utxo_list.setHeaderLabels(header_labels)
    window.utxo_list.on_update = window.utxo_list.on_update_backup
    window.utxo_list.in_progress = None
    delattr(window.utxo_list, "in_progress")
    delattr(window.utxo_list, "on_update_backup")


def unfreeze_frozen_by_shuffling(wallet):
    coins_frozen_by_shuffling = wallet.storage.get("coins_frozen_by_shuffling", [])
    if coins_frozen_by_shuffling:
        wallet.set_frozen_coin_state(coins_frozen_by_shuffling, False)
    wallet.storage.put("coins_frozen_by_shuffling", None)

def modify_wallet(wallet):
    wallet.is_coin_shuffled = lambda coin: is_coin_shuffled(wallet, coin)
    wallet.get_shuffled_coins = lambda: get_shuffled_coins(wallet)
    unfreeze_frozen_by_shuffling(wallet)

def restore_wallet(wallet):
    if getattr(wallet, "is_coin_shuffled", None):
        delattr(wallet, "is_coin_shuffled")
    if getattr(wallet, "get_shuffled_coins", None):
        delattr(wallet, "get_shuffled_coins")
    unfreeze_frozen_by_shuffling(wallet)


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
            self.on_new_window(window)

    @hook
    def on_new_window(self, window):
        password = None
        while window.wallet.has_password():
            password = window.password_dialog(parent=window, msg = "Enter password to allow\nCashShuffle do the job")
            if password is None:
                # User cancelled password input
                msgBox = QMessageBox(parent=window)
                msgBox.setText("Can't get password. Closing the pluging")
                msgBox.exec_()
                window.gui_object.plugins.toggle_internal_plugin('shuffle')
                return
            try:
                window.wallet.check_password(password)
                break
            except Exception as e:
                window.show_error(str(e), parent=window)
                continue
        window.update_cashshuffle_icon()
        window.cs_tab = None
        self.windows.append(window)
        modify_utxo_list(window)
        modify_wallet(window.wallet)
        # console modification
        window.console.updateNamespace({"start_background_shuffling": lambda *args, **kwargs: start_background_shuffling(window, *args, **kwargs)})
        window.utxo_list.on_update()
        network_settings = window.wallet.storage.get("cashshuffle_server", None)
        if not network_settings:
            network_settings = self.settings_dialog(window, msg="Choose the server, please")
        if not network_settings:
            msgBox = QMessageBox(parent=window)
            msgBox.setText("Can't get network. Closing the pluging")
            msgBox.exec_()
            window.gui_object.plugins.toggle_internal_plugin('shuffle')
            return
        network_settings['host'] = network_settings.pop('server')
        network_settings["network"] = window.network
        start_background_shuffling(window, network_settings, period = 10, password=password)


    def on_close(self):
        for window in self.windows:
            if getattr(window, "background_process", None):
                window.background_process.join()
                while window.background_process.is_alive():
                    pass
                window.background_process = None
            restore_utxo_list(window)
            restore_wallet(window.wallet)
            if window.console.namespace.get("start_background_shuffling", None):
                del window.console.namespace["start_background_shuffling"]
            window.utxo_list.on_update()
            window.update_cashshuffle_icon()


    def update(self, window):
        self.windows.append(window)

    def settings_dialog(self, window, msg=None):

        d = WindowModalDialog(window, _("CashShuffle settings"))
        d.setMinimumSize(500, 200)

        vbox = QVBoxLayout(d)
        if not msg:
            msg = "Choose CashShuffle Server from List\nChanges will take effect after restarting the plugin"
        vbox.addWidget(QLabel(_(msg)))
        grid = QGridLayout()
        vbox.addLayout(grid)

        serverList=ServersList(parent=d)
        serverList.setItems()

        grid.addWidget(QLabel('Servers'), 0, 0)
        grid.addWidget(serverList, 0, 1)

        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))


        if not d.exec_():
            return
        else:
            network_settings = serverList.get_current_server()
            for wdw in self.windows:
                wdw.wallet.storage.put("cashshuffle_server", network_settings)
            return network_settings


    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def requires_settings(self):
        return True
