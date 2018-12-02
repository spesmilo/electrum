
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

import os, sys
import json
import copy
from functools import partial

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electroncash.plugins import BasePlugin, hook
from electroncash.i18n import _
from electroncash_gui.qt.util import EnterButton, Buttons, CloseButton
from electroncash_gui.qt.util import OkButton, WindowModalDialog
from electroncash_gui.qt.password_dialog import PasswordDialog
from electroncash.address import Address
from electroncash.transaction import Transaction
from electroncash_plugins.shuffle.client import BackgroundShufflingThread

# class SimpleLogger(object):
#
#     def __init__(self, logchan = None):
#         self.pThread = None
#         self.logchan = logchan
#
#     def send(self, message):
#         if not self.logchan == None:
#             self.logchan.send(message)
#         if message.startswith("Error"):
#             self.pThread.done.set()t

#         elif message.startswith("Blame"):
#             if "insufficient" in message:
#                 pass
#             elif "wrong hash" in message:
#                 pass
#             else:
#                 self.pThread.done.set()


# def set_coins(win, selected):
#     checked_utxos = [utxo.replace(":","") for utxo in selected]
#     win.parent.cs_tab.coinshuffle_inputs_list.setItems(win.wallet, checked_utxos=checked_utxos)
#     win.parent.cs_tab.check_sufficient_ammount()
#     win.parent.tabs.setCurrentWidget(win.parent.cs_tab)


def is_coin_shuffled(wallet, coin, txs=None):
    txs = txs or wallet.storage.get("transactions", {})
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
    with self.wallet.transaction_lock:
        utxos = wallet.get_utxos()
    txs = self.wallet.storage.get("transactions", {})
    return [utxo for utxo in utxos if wallet.is_coin_shuffled(utxo, txs)]

def my_custom_item_setup(utxo_list, utxo, name, item):
    if not hasattr(utxo_list.wallet, 'is_coin_shuffled'):
        return
    frozenstring = item.data(0, Qt.UserRole+1) or ""
    if utxo_list.wallet.is_coin_shuffled(utxo):  # already shuffled
        item.setText(5, "shuffled")
        item.setData(5, Qt.UserRole+1, "shuffled")
    elif frozenstring.find("a") > -1 or frozenstring.find("c") > -1:
        item.setText(5, "user frozen")
        item.setData(5, Qt.UserRole+1, "user frozen")
    elif utxo['height'] <= 0: # not_confirmed
        item.setText(5, "not confirmed")
        item.setData(5, Qt.UserRole+1, "not confirmed")
    elif utxo['value'] > 10000 and utxo['value']<1000000000: # queued_labels
        item.setText(5, "in queue")
        item.setData(5, Qt.UserRole+1, "in queue")
    elif utxo['value'] >= 1000000000: # too big
        item.setText(5, "too big coin")
        item.setData(5, Qt.UserRole+1, "too big coin")
    elif utxo['value'] <= 10000: # dust
        item.setText(5, "too small coin")
        item.setData(5, Qt.UserRole+1, "too small coin")

    if utxo_list.in_progress.get(name) == 'in progress': # in progress
        item.setText(5, "in progress")
        item.setData(5, Qt.UserRole+1, "in progress")
    if utxo_list.in_progress.get(name) == "wait for others": # wait for others
        item.setText(5, "wait for others")
        item.setData(5, Qt.UserRole+1, "wait for others")


def update_coin_status(window, coin_name, msg):
    if getattr(window.utxo_list, "in_progress", None) == None:
        return
    if coin_name not in ["MAINLOG", "PROTOCOL"]:
        if msg.startswith("Player") and coin_name not in window.utxo_list.in_progress:
            if "get session number" in msg:
                window.utxo_list.in_progress[coin_name] = 'wait for others'
                window.utxo_list.update()
        elif msg.startswith("Player"):
            if "begins CoinShuffle protocol" in msg:
                window.utxo_list.in_progress[coin_name] = 'in progress'
                window.utxo_list.update()
        elif msg.startswith("Error"):
            if coin_name in window.utxo_list.in_progress:
                del window.utxo_list.in_progress[coin_name]
                window.utxo_list.update()
        elif msg.endswith("complete protocol"):
            if coin_name in window.utxo_list.in_progress:
                del window.utxo_list.in_progress[coin_name]
                window.utxo_list.update()
        elif msg.startswith("Blame") and "insufficient" not in message and "wrong hash" not in message:
            if coin_name in window.utxo_list.in_progress:
                del window.utxo_list.in_progress[coin_name]
                window.utxo_list.update()
    else:
        if msg == "stopped":
            window.utxo_list.in_progress = {}



class electrum_console_logger(QObject):

    gotMessage = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super(QObject, self).__init__(parent)
        self.parent = parent

    def send(self, msg, sender):
        self.gotMessage.emit(msg, sender)


def start_background_shuffling(window, network_settings, period = 1, password=None):
    logger = electrum_console_logger()
    logger.gotMessage.connect(lambda msg, sender: update_coin_status(window, sender, msg))

    window.background_process = BackgroundShufflingThread(window.wallet, network_settings,
                                                          logger=logger,
                                                          period=period,
                                                          password=password)
    window.background_process.start()

def modify_utxo_list(window):
    header = window.utxo_list.headerItem()
    header_labels = [header.text(i) for i in range(header.columnCount())]
    header_labels.append(_("Shuffle status"))
    window.utxo_list.update_headers(header_labels)
    window.utxo_list.in_progress = {}

def restore_utxo_list(window):
    header = window.utxo_list.headerItem()
    header_labels = [header.text(i) for i in range(header.columnCount())]
    del header_labels[-1]
    window.utxo_list.update_headers(header_labels)
    window.utxo_list.in_progress = None
    delattr(window.utxo_list, "in_progress")


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
        self.initted = False

    @hook
    def init_qt(self, gui):
        if self.initted:
            return
        self.print_error("Initializing...")
        ct = 0
        for window in gui.windows:
            self.on_new_window(window)
            ct += 1
        self.initted = True
        self.print_error("Initialized (had {} extant windows).".format(ct))

    def window_has_cashshuffle(self, window):
        return window in self.windows

    def window_wants_cashshuffle(self, window):
        return window.wallet.storage.get("cashshuffle_enabled", False)

    def window_set_wants_cashshuffle(self, window, b):
        window.wallet.storage.put("cashshuffle_enabled", bool(b))

    def window_set_cashshuffle(self, window, b):
        if not b and self.window_has_cashshuffle(window):
            self.on_close_window(window)
        elif b and not self.window_has_cashshuffle(window):
            self._enable_for_window(window)
        self.window_set_wants_cashshuffle(window, b)

    @hook
    def on_new_window(self, window):
        if window.wallet and not self.window_has_cashshuffle(window) and self.window_wants_cashshuffle(window):
            self._enable_for_window(window)

    def _enable_for_window(self, window):
        if not window.is_wallet_cashshuffle_compatible():
            # wallet is watching-only, multisig, or hardware so.. mark it permanently for no cashshuffle
            self.window_set_cashshuffle(window, False)
            return
        title = window.windowTitle() if window and window.windowTitle() else "UNKNOWN WINDOW"
        self.print_error("Window '{}' registered, performing window-specific startup code".format(title))
        password = None
        name = window.wallet.basename()
        while window.wallet.has_password():
            msg = _("CashShuffle requires access to '{}'.").format(name) + "\n" +  _('Please enter your password')
            dlgParent = None if sys.platform == 'darwin' else window
            password = PasswordDialog(parent=dlgParent, msg=msg).run()
            if password is None:
                # User cancelled password input
                self.window_set_cashshuffle(window, False)
                window.show_error(_("Can't get password, disabling for this wallet."), parent=window)
                return
            try:
                window.wallet.check_password(password)
                break
            except Exception as e:
                window.show_error(str(e), parent=window)
                continue
        network_settings = copy.deepcopy(window.config.get("cashshuffle_server", None))
        if not network_settings:
            network_settings = self.settings_dialog(None, msg=_("Please choose a CashShuffle server"))
        if not network_settings:
            self.window_set_cashshuffle(window, False)
            window.show_error(_("Can't get network, disabling CashShuffle."), parent=window)
            return
        ns_in = copy.deepcopy(network_settings)
        network_settings['host'] = network_settings.pop('server')
        network_settings["network"] = window.network
        window.update_cashshuffle_icon()
        window.cs_tab = None
        modify_utxo_list(window)
        modify_wallet(window.wallet)
        self.windows.append(window)
        self.save_network_settings(ns_in) # nb this needs to be called after the window is added
        window.update_status()
        # console modification
        window.console.updateNamespace({"start_background_shuffling": lambda *args, **kwargs: start_background_shuffling(window, *args, **kwargs)})
        window.utxo_list.update()
        start_background_shuffling(window, network_settings, period = 10, password=password)

    @hook
    def utxo_list_item_setup(self, utxo_list, x, name, item):
        return my_custom_item_setup(utxo_list, x, name, item)


    def on_close(self):
        for window in self.windows.copy():
            self.on_close_window(window)
            window.update_status()
        self.initted = False
        self.print_error("Plugin closed")

    @hook
    def on_close_window(self, window):
        if window not in self.windows:
            return
        title = window.windowTitle() if window and window.windowTitle() else "UNKNOWN WINDOW"
        if getattr(window, "background_process", None):
            window.background_process.join()
            while window.background_process.is_alive():
                # this code should never be reached.
                self.print_error("INFINITE LOOP!! FIXME!")
                pass
            window.background_process = None
            self.print_error("Window '{}' closed, ended shuffling for its wallet".format(title))
        restore_utxo_list(window)
        restore_wallet(window.wallet)
        if window.console.namespace.get("start_background_shuffling", None):
            del window.console.namespace["start_background_shuffling"]
        window.utxo_list.update()
        window.update_status()
        self.windows.remove(window)
        self.print_error("Window '{}' removed".format(title))

    @hook
    def on_new_password(self, window, old, new):
        if getattr(window, 'background_process', None):
            self.print_error("Got new password for wallet {} informing background process...".format(window.wallet.basename() if window.wallet else 'UNKNOWN'))
            window.background_process.set_password(new)

    # def update(self, window):
    #     self.windows.append(window)

    def settings_dialog(self, window, msg=None):
        def setup_combo_box(cb, selected = {}):
            #
            def load_servers(servers_path):
                r = {}
                try:
                    zips = __file__.find(".zip")
                    if zips == -1:
                        with open(os.path.join(os.path.dirname(__file__), servers_path), 'r') as f:
                            r = json.loads(f.read())
                    else:
                        from zipfile import ZipFile
                        zip_file = ZipFile(__file__[: zips + 4])
                        with zip_file.open("shuffle/" + servers_path) as f:
                            r = json.loads(f.read().decode())
                except:
                    self.print_error("Error loading server list from {}: {}", servers_path, sys.exc_info()[1])
                return r
            # /
            servers = load_servers("servers.json")
            selIdx = -1
            for host, d0 in sorted(servers.items()):
                d = d0.copy()
                d['server'] = host
                item = host + (' [ssl]' if d['ssl'] else '')
                cb.addItem(item, d)
                if selected and selected == d:
                    selIdx = cb.count()-1
            if selIdx > -1:
                cb.setCurrentIndex(selIdx)
            elif selected and len(selected) == 4:
                cb.addItem(_("(Custom)"), selected.copy())
                cb.setCurrentIndex(cb.count()-1)
        # /
        def from_combobox(cb, le, sb1, sb2, chk):
            d = cb.currentData()
            if not isinstance(d, dict): return
            host, port, info, ssl = d.get('server'), d.get('port'), d.get('info'), d.get('ssl')
            le.setText(host)
            sb1.setValue(port)
            sb2.setValue(info)
            chk.setChecked(ssl)
        def get_form(le, sb1, sb2, chk):
            return {
                'server': le.text(),
                'port'  : sb1.value(),
                'info'  : sb2.value(),
                'ssl'   : chk.isChecked()
            }

        dlgParent = None if sys.platform == 'darwin' else window

        d = WindowModalDialog(dlgParent, _("CashShuffle settings"))
        d.setMinimumSize(500, 200)

        vbox = QVBoxLayout(d)
        if not msg:
            msg = _("Choose a CashShuffle server from the list.\nChanges will take effect after restarting the plugin.")
        vbox.addWidget(QLabel(msg))
        grid = QGridLayout()
        vbox.addLayout(grid)

        serverCB = QComboBox()
        srv, port, info, ssl = "", 8080, 8081, False
        selected = dict()
        if self.windows:
            try:
                # try and pre-populate from config
                current = self.windows[0].config.get("cashshuffle_server", dict())
                srv = current["server"]
                port = current["port"]
                info = current["info"]
                ssl = current["ssl"]
                selected = current
            except KeyError:
                pass
            
        setup_combo_box(serverCB, selected = selected)

        grid.addWidget(QLabel('Servers'), 0, 0)
        grid.addWidget(serverCB, 0, 1)

        grid.addWidget(QLabel(_("Host")), 1, 0)

        hbox = QHBoxLayout()
        grid.addLayout(hbox, 1, 1, 1, 2)
        grid.setColumnStretch(2, 1)
        srvLe = QLineEdit(srv)
        hbox.addWidget(srvLe)
        hbox.addWidget(QLabel(_("P:")))
        portSb = QSpinBox(); portSb.setRange(1, 65534); #portSb.setPrefix("P: ")
        portSb.setValue(port)
        hbox.addWidget(portSb)
        hbox.addWidget(QLabel(_("I:")))
        infoSb = QSpinBox(); infoSb.setRange(1, 65534); #infoSb.setPrefix("I: ")
        infoSb.setValue(info)
        hbox.addWidget(infoSb)
        sslChk = QCheckBox(_("SSL"))
        sslChk.setChecked(ssl)
        hbox.addWidget(sslChk)

        serverCB.currentIndexChanged.connect(lambda x: from_combobox(serverCB, srvLe, portSb, infoSb, sslChk))
        if not srv: from_combobox(serverCB, srvLe, portSb, infoSb, sslChk) # had no config'd server, just take whatever the current combo box is for form fields
        
        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))


        if not d.exec_():
            return
        else:
            network_settings = get_form(srvLe, portSb, infoSb, sslChk)
            self.print_error("Saving network settings: {}".format(network_settings))
            self.save_network_settings(network_settings)
            return network_settings


    def save_network_settings(self, network_settings):
        ns = copy.deepcopy(network_settings)
        saved = set()
        for wdw in self.windows:
            if wdw.config not in saved: # paranoia
                wdw.config.set_key("cashshuffle_server", ns)
                saved.add(wdw.config)


    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def requires_settings(self):
        return True
