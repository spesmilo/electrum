#!/usr/bin/env python
#
# Cash Shuffle - CoinJoin for Bitcoin Cash
# Copyright (C) 2018 Electron Cash LLC
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

import os, sys, json, copy, socket, time

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electroncash.plugins import BasePlugin, hook
from electroncash.i18n import _
from electroncash.util import print_error, profiler, PrintError, Weak
from electroncash.network import Network
from electroncash_gui.qt.util import EnterButton, Buttons, CloseButton, HelpLabel, OkButton, WindowModalDialog, rate_limited
from electroncash_gui.qt.password_dialog import PasswordDialog
from electroncash_gui.qt.main_window import ElectrumWindow
from electroncash.address import Address
from electroncash.bitcoin import COINBASE_MATURITY
from electroncash.transaction import Transaction
from electroncash_plugins.shuffle.client import BackgroundShufflingThread, ERR_SERVER_CONNECT, ERR_BAD_SERVER_PREFIX, MSG_SERVER_OK, PrintErrorThread, get_name, unfreeze_frozen_by_shuffling
from electroncash_plugins.shuffle.comms import query_server_for_stats, verify_ssl_socket

FEE = 300
SORTED_SCALES = sorted(BackgroundShufflingThread.scales)
SCALE_ARROWS = ('→','⇢','➟','➝','➡')
assert len(SORTED_SCALES) == len(SCALE_ARROWS), "Please add a scale arrow if you modify the scales!"
SCALE_ARROW_DICT = dict(zip(SORTED_SCALES, SCALE_ARROWS))
SCALE_0 = SORTED_SCALES[0]
SCALE_N = SORTED_SCALES[-1]
UPPER_BOUND = SCALE_N*10 + FEE
LOWER_BOUND = SCALE_0 + FEE


def is_coin_shuffled(wallet, coin, txs_in=None):
    cache = getattr(wallet, "_is_shuffled_cache", dict())
    tx_id, n = coin['prevout_hash'], coin['prevout_n']
    name = "{}:{}".format(tx_id, n)
    answer = cache.get(name, None)
    if answer is not None:
        # check cache, if cache hit, return answer and avoid the lookup below
        return answer
    def doChk():
        if txs_in:
            txs = txs_in
        else:
            with wallet.lock:
                with wallet.transaction_lock:
                    txs = wallet.transactions
        if tx_id in txs:
            tx = txs[tx_id]
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
                if group_len > 2 and amount in BackgroundShufflingThread.scales:
                    if n in outputs_groups[amount] and inputs_len >= group_len:
                        return True
            return False
        else:
            return None
    # /doChk
    answer = doChk()
    if answer is not None:
        # cache the answer iff it's a definitive answer True/False only
        cache[name] = answer
    return answer


def get_shuffled_and_unshuffled_coin_totals(wallet, exclude_frozen = False, mature = False, confirmed_only = False):
    ''' Returns a 3-tuple of tuples of (amount_total, num_utxos) that are 'shuffled', 'unshuffled' and 'unshuffled_but_in_progress', respectively. '''
    shuf, unshuf, uprog = wallet.get_shuffled_and_unshuffled_coins(exclude_frozen, mature, confirmed_only)
    ret, lists = [(0,0),(0,0),(0,0)], ( shuf, unshuf, uprog )
    i = 0
    for l in lists:
        tot = 0
        n = 0
        for c in l:
            tot += c['value']
            n += 1
        ret[i] = (tot, n)
        i += 1
    return tuple(ret)

# Called from either the wallet code or the shufflethread.
# The wallet code calls this when spending either shuffled-only or unshuffled-only coins in a tx.
def cashshuffle_get_new_change_address(wallet, for_shufflethread=False):
    with wallet.lock:
        with wallet.transaction_lock:
            if not for_shufflethread and wallet._last_change and not wallet.get_address_history(wallet._last_change):
                # if they keep hitting preview on the same tx, give them the same change each time
                return wallet._last_change
            change = None
            for address in wallet.get_change_addresses():
                if address not in wallet._addresses_cashshuffle_reserved and not wallet.get_address_history(address):
                    change = address
                    break
            while not change:
                address = wallet.create_new_address(for_change = True)
                if address not in wallet._addresses_cashshuffle_reserved:
                    change = address
            wallet._addresses_cashshuffle_reserved.add(change)
            if not for_shufflethread:
                # new change address generated for code outside the shuffle threads. cache and return it next time.
                wallet._last_change = change
            return change

@profiler
def get_shuffled_and_unshuffled_coins(wallet, exclude_frozen = False, mature = False, confirmed_only = False):
    ''' Returns a 3-tupe of mutually exclusive lists: shuffled_utxos, unshuffled_utxos, and unshuffled_but_in_progress '''
    shuf, unshuf, uprog = [], [], []
    if hasattr(wallet, 'is_coin_shuffled'):
        with wallet.lock:
            with wallet.transaction_lock:
                coins_frozen_by_shuffling = set(wallet.storage.get("coins_frozen_by_shuffling", list()))
                utxos = wallet.get_utxos(exclude_frozen = exclude_frozen, mature = mature, confirmed_only = confirmed_only)
                txs = wallet.transactions
                for utxo in utxos:
                    state = wallet.is_coin_shuffled(utxo, txs)
                    if state:
                        shuf.append(utxo)
                    else:
                        name = get_name(utxo)
                        if state is not None:
                            if name not in coins_frozen_by_shuffling:
                                unshuf.append(utxo)
                            else:
                                uprog.append(utxo)
                        else:
                            wallet.print_error("Warning: get_shuffled_and_unshuffled_coins got an 'unknown' utxo: {}",name)
    return shuf, unshuf, uprog


def my_custom_item_setup(utxo_list, utxo, name, item):
    if not hasattr(utxo_list.wallet, 'is_coin_shuffled'):
        return

    prog = utxo_list.in_progress.get(name, "")
    frozenstring = item.data(0, Qt.UserRole+1) or ""

    if utxo_list.wallet.is_coin_shuffled(utxo):  # already shuffled
        item.setText(5, _("Shuffled"))
    elif not prog and ("a" in frozenstring or "c" in frozenstring):
        item.setText(5, _("Frozen"))
    elif utxo['height'] <= 0: # not_confirmed
        item.setText(5, _("Unconfirmed"))
    elif utxo['coinbase'] and (utxo['height'] + COINBASE_MATURITY > utxo_list.wallet.get_local_height()): # maturity check
        item.setText(5, _("Not mature"))
    elif utxo['value'] >= LOWER_BOUND and utxo['value'] < UPPER_BOUND: # queued_labels
        if utxo_list.wallet.network and utxo_list.wallet.network.is_connected():
            item.setText(5, _("In queue"))
        else:
            item.setText(5, _("Offline"))
    elif utxo['value'] >= UPPER_BOUND: # too big
        item.setText(5, _("Too big"))
    elif utxo['value'] < LOWER_BOUND: # dust
        item.setText(5, _("Too small"))

    if prog == 'in progress': # in progress
        item.setText(5, _("In progress"))
    elif prog.startswith('phase '):
        item.setText(5, _("Phase {}").format(prog.split()[-1]))
    elif prog == "wait for others": # wait for others
        item.setText(5, _("Wait for others"))
    elif prog == "completed":
        item.setText(5, _("Done"))

def update_coin_status(window, coin_name, msg):
    if getattr(window.utxo_list, "in_progress", None) is None:
        return
    #print_error("[shuffle] wallet={}; Coin {} Message '{}'".format(window.wallet.basename(), coin_name, msg.strip()))
    prev_in_progress = window.utxo_list.in_progress.get(coin_name)
    new_in_progress = prev_in_progress
    msg = msg or '' # force str
    coin_name = coin_name or '' # force str

    if coin_name not in ("MAINLOG", "PROTOCOL"):
        if msg.startswith("Player"):
            if "get session number" in msg:
                new_in_progress = 'wait for others'
            elif "begins CoinShuffle protocol" in msg:
                new_in_progress = 'in progress'
            elif "reaches phase" in msg:
                pos = msg.find("reaches phase")
                parts = msg[pos:].split(' ', 2)
                try:
                    phase = int(parts[2])
                    new_in_progress = 'phase {}'.format(phase)
                except (IndexError, ValueError):
                    pass
            elif msg.endswith("complete protocol"):
                new_in_progress = "completed"  # NB: this means we "leak" statuses as this final status never gets cleaned up. FIXME. there is a race condition anyway between code that picks up UTXOs for shuffling and the wallet code
        elif msg.startswith("Error"):
            new_in_progress = None # flag to remove from progress list
            if ERR_SERVER_CONNECT in msg or ERR_BAD_SERVER_PREFIX in msg:
                window.cashshuffle_set_flag(1) # 1 means server connection issue
        elif msg.startswith("Blame") and "insufficient" not in msg and "wrong hash" not in msg:
            new_in_progress = None
        elif msg.startswith("shuffle_txid:"): # TXID message -- call "set_label"
            words = msg.split()
            if len(words) >= 2:
                txid = words[1]
                try:
                    tot, scale_orig, chg, fee = [int(w) for w in words[2:6]] # parse satoshis
                    # satoshis -> display format
                    tot, scale, chg = window.format_amount(tot), window.format_amount(scale_orig), window.format_amount(chg)
                    window.wallet.set_label(txid, _("Shuffle")
                                            + (" {} {} {} {} + {} (-{} sats {})"
                                               .format(tot, window.base_unit(),
                                                       SCALE_ARROW_DICT.get(scale_orig, '⇒'),
                                                       scale, chg, fee, _("fee"))
                                               ))
                except (IndexError, ValueError, TypeError):
                    # Hmm. Some sort of parse error. Just label it 'CashShuffle'
                    window.wallet.set_label(txid, _("CashShuffle"))
                window.update_wallet()

        if not msg.startswith("Error") and not msg.startswith("Exit"):
            window.cashshuffle_set_flag(0) # 0 means ok
        elif new_in_progress != 'completed' and prev_in_progress == new_in_progress: # "Exit" or "Error"
            # thread exit or error without completing protocol, set status back to 'in queue'
            # -- fixes wrong status of 'in progress' and 'waiting for others' being shown in UI for dead threads
            new_in_progress = None

    else:
        if msg == "stopped":
            window.utxo_list.in_progress.clear(); new_in_progress = prev_in_progress = None
        elif msg.startswith("forget "):
            words = msg.strip().split()
            prev_in_progress = 1; new_in_progress = None; coin_name = words[-1] # force the code below to pop the coin that we were asked to forget from the status dict
        elif ERR_SERVER_CONNECT in msg:
            new_in_progress = None # flag to remove from progress list
            window.cashshuffle_set_flag(1) # 1 means server connection issue
        elif MSG_SERVER_OK in msg:
            new_in_progress = None
            window.cashshuffle_set_flag(0) # server is ok now.



    if prev_in_progress != new_in_progress:
        if new_in_progress is None:
            window.utxo_list.in_progress.pop(coin_name, None)
        else:
            window.utxo_list.in_progress[coin_name] = new_in_progress
        window.utxo_list.update()

class electrum_console_logger(QObject):

    gotMessage = pyqtSignal(str, str)

    def __init__(self, window):
        super().__init__(None)
        self.window = window
        self.gotMessage.connect(self.gotMsgSlot)

    def send(self, msg, sender):
        self.gotMessage.emit(msg, sender)

    def gotMsgSlot(self, msg, sender):
        update_coin_status(self.window, sender, msg)

    def disconnectAll(self):
        try:
            self.gotMessage.disconnect()
        except:
            pass

def start_background_shuffling(window, network_settings, period = 10.0, password = None, timeout = 60.0):
    logger = electrum_console_logger(window)

    window.background_process = BackgroundShufflingThread(window,
                                                          window.wallet,
                                                          network_settings,
                                                          logger = logger,
                                                          fee = FEE,
                                                          period = period,
                                                          password = password,
                                                          timeout = timeout)
    window.background_process.start()

def monkey_patches_apply(window):
    def patch_window(window):
        if getattr(window, '_shuffle_patched_', None):
            return
        window.background_process = None
        window._shuffle_patched_ = True
        window.send_tab_shuffle_extra = SendTabExtra(window)
        print_error("[shuffle] Patched window")

    def patch_utxo_list(utxo_list):
        if getattr(utxo_list, '_shuffle_patched_', None):
            return
        header = utxo_list.headerItem()
        header_labels = [header.text(i) for i in range(header.columnCount())]
        header_labels.append(_("Shuffle status"))
        utxo_list.update_headers(header_labels)
        utxo_list.in_progress = dict()
        utxo_list._shuffle_patched_ = True
        print_error("[shuffle] Patched utxo_list")

    def patch_wallet(wallet):
        if getattr(wallet, '_shuffle_patched_', None):
            return
        wallet.is_coin_shuffled = lambda coin, txs=None: is_coin_shuffled(wallet, coin, txs)
        wallet.get_shuffled_and_unshuffled_coins = lambda *args, **kwargs: get_shuffled_and_unshuffled_coins(wallet, *args, **kwargs)
        wallet.cashshuffle_get_new_change_address = lambda for_shufflethread=False: cashshuffle_get_new_change_address(wallet,for_shufflethread = for_shufflethread)
        wallet._is_shuffled_cache = dict()
        wallet._addresses_cashshuffle_reserved = set()
        wallet._last_change = None
        unfreeze_frozen_by_shuffling(wallet)
        wallet._shuffle_patched_ = True
        print_error("[shuffle] Patched wallet")

    patch_wallet(window.wallet)
    patch_utxo_list(window.utxo_list)
    patch_window(window)

def monkey_patches_remove(window):
    def restore_window(window):
        if not getattr(window, '_shuffle_patched_', None):
            return
        window.send_tab_shuffle_extra.setParent(None); window.send_tab_shuffle_extra.deleteLater();
        delattr(window, 'send_tab_shuffle_extra')
        delattr(window, 'background_process')
        delattr(window, '_shuffle_patched_')
        print_error("[shuffle] Unpatched window")
        # Note that at this point an additional monkey patch: 'window.__disabled_sendtab_extra__' may stick around until the plugin is unloaded altogether

    def restore_utxo_list(utxo_list):
        if not getattr(utxo_list, '_shuffle_patched_', None):
            return
        header = utxo_list.headerItem()
        header_labels = [header.text(i) for i in range(header.columnCount())]
        del header_labels[-1]
        utxo_list.update_headers(header_labels)
        utxo_list.in_progress = None
        delattr(window.utxo_list, "in_progress")
        delattr(window.utxo_list, '_shuffle_patched_')
        print_error("[shuffle] Unpatched utxo_list")

    def restore_wallet(wallet):
        if not getattr(wallet, '_shuffle_patched_', None):
            return
        delattr(wallet, '_addresses_cashshuffle_reserved')
        delattr(wallet, 'cashshuffle_get_new_change_address')
        delattr(wallet, "is_coin_shuffled")
        delattr(wallet, "get_shuffled_and_unshuffled_coins")
        delattr(wallet, "_is_shuffled_cache")
        delattr(wallet, '_shuffle_patched_')
        delattr(wallet, "_last_change")
        unfreeze_frozen_by_shuffling(wallet)
        print_error("[shuffle] Unpatched wallet")

    restore_window(window)
    restore_utxo_list(window.utxo_list)
    restore_wallet(window.wallet)


class Plugin(BasePlugin):

    instance = None       # The extant instance singleton, if any. Variable is cleared on plugin stop.
    gui = None            # The "gui object" singleton (ElectrumGui) -- a useful refrence to keep around.
    network_dialog = None # The NetworkDialog window singleton (managed by the ElectrumGui singleton).

    def fullname(self):
        return 'CashShuffle'

    def description(self):
        return _("CashShuffle Protocol")

    def is_available(self):
        return True

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.windows = []
        self.disabled_windows = [] # this is to manage the "cashshuffle disabled" xtra gui element in the send tab
        self.initted = False

    @hook
    def init_qt(self, gui):
        if self.initted:
            return
        self.print_error("Initializing...")
        Plugin.instance = self
        Plugin.gui = gui
        if Plugin.network_dialog != gui.nd:
            Plugin.network_dialog = gui.nd # each time we are stopped, our module gets re-imported and we lose globals... so try and recapture this singleton
        ct = 0
        for window in gui.windows:
            self.on_new_window(window)
            ct += 1
        self.on_network_dialog(Plugin.network_dialog) # If we have a network dialgog, add self to network dialog
        self.initted = True
        self.print_error("Initialized (had {} extant windows).".format(ct))

    @hook
    def on_network_dialog(self, nd):
        self.print_error("OnNetworkDialog", str(nd))
        Plugin.network_dialog = nd
        if not nd: return
        if not hasattr(nd, "__shuffle_settings__") or not nd.__shuffle_settings__:
            nd.__shuffle_settings__ = st = SettingsTab(nd.nlayout.tabs, None, nd.nlayout.config)
            nd.nlayout.tabs.addTab(st, _("CashShuffle"))
            st.applyChanges.connect(Plugin.try_to_apply_network_dialog_settings)
        elif nd.__shuffle_settings__:
            # they may have a fake view if they didn't apply the last settings, refresh the view
            st = nd.__shuffle_settings__
            st.refreshFromSettings()

    def del_network_dialog_tab(self):
        # delete the shuffle settings widget
        if Plugin.network_dialog and hasattr(Plugin.network_dialog, '__shuffle_settings__'):
            nd = Plugin.network_dialog
            st = Plugin.network_dialog.__shuffle_settings__
            if st:
                idx = nd.nlayout.tabs.indexOf(st)
                if idx > -1:
                    if nd.nlayout.tabs.currentIndex() == idx:
                        nd.nlayout.tabs.setCurrentIndex(0)
                    nd.nlayout.tabs.removeTab(idx)
                st.stopNetworkChecker()
                st.setParent(None)
                st = None
            Plugin.network_dialog.__shuffle_settings__ = None
            self.print_error("Removed CashShuffle network settings tab")

    def window_has_cashshuffle(self, window):
        return window in self.windows

    def window_wants_cashshuffle(self, window):
        return window.wallet.storage.get("cashshuffle_enabled", False)

    def window_set_wants_cashshuffle(self, window, b):
        window.wallet.storage.put("cashshuffle_enabled", bool(b))

    def window_set_cashshuffle(self, window, b):
        if not b and self.window_has_cashshuffle(window):
            self._disable_for_window(window)
        elif b and not self.window_has_cashshuffle(window):
            self._enable_for_window(window)
        self.window_set_wants_cashshuffle(window, b)

    def _window_set_disabled_extra(self, window):
        self._window_clear_disabled_extra(window)
        window.__disabled_sendtab_extra__ = SendTabExtraDisabled(window)

    def _window_clear_disabled_extra(self, window):
        extra = getattr(window, "__disabled_sendtab_extra__", None)
        if extra:
            extra.setParent(None) # python will gc this badboy
            delattr(window, "__disabled_sendtab_extra__")
            del extra # hopefully object refct goes immediately to 0 and this widget dies quickly.
            return True

    @hook
    def on_new_window(self, window):
        if not window.is_wallet_cashshuffle_compatible():
            # wallet is watching-only, multisig, or hardware so.. mark it permanently for no cashshuffle
            self.window_set_cashshuffle(window, False)
            return
        if window.wallet and not self.window_has_cashshuffle(window):
            if self.window_wants_cashshuffle(window):
                self._enable_for_window(window) or self._window_add_to_disabled(window)
            else:
                self._window_add_to_disabled(window)

    def _enable_for_window(self, window):
        name = window.wallet.basename()
        self.print_error("Window '{}' registered, performing window-specific startup code".format(name))
        password = None
        while window.wallet.has_password():
            msg = _("CashShuffle requires access to '{}'.").format(name) + "\n" +  _('Please enter your password')
            dlgParent = None if sys.platform == 'darwin' else window
            password = PasswordDialog(parent=dlgParent, msg=msg).run()
            if password is None:
                # User cancelled password input
                self.window_set_cashshuffle(window, False)
                window.show_error(_("CashShuffle didn't get the password, disabling for this wallet."), parent=window)
                return
            try:
                window.wallet.check_password(password)
                break
            except Exception as e:
                window.show_error(str(e), parent=window)
                continue
        network_settings = Plugin.get_network_settings(window.config)
        if not network_settings:
            network_settings = self.settings_dialog(window, msg=_("Please choose a CashShuffle server"), restart_ask = False)
        if not network_settings:
            self.window_set_cashshuffle(window, False)
            window.show_error(_("Can't get network, disabling CashShuffle."), parent=window)
            return
        self._window_remove_from_disabled(window)
        network_settings = copy.deepcopy(network_settings)
        network_settings['host'] = network_settings.pop('server')
        monkey_patches_apply(window)
        self.windows.append(window)
        window.update_status()
        window.utxo_list.update()
        start_background_shuffling(window, network_settings, password=password)
        return True

    @hook
    def utxo_list_item_setup(self, utxo_list, x, name, item):
        return my_custom_item_setup(utxo_list, x, name, item)


    def on_close(self):
        self.del_network_dialog_tab()
        for window in self.windows.copy():
            self.on_close_window(window)
            window.update_status()
        for window in self.disabled_windows.copy():
            self.on_close_window(window)
            window.update_status()
        self.initted = False
        Plugin.instance = None
        self.print_error("Plugin closed")
        assert len(self.windows) == 0 and len(self.disabled_windows) == 0, (self.windows, self.disabled_windows)

    @hook
    def on_close_window(self, window):
        def didRemove(window):
            self.print_error("Window '{}' removed".format(window.wallet.basename()))
        if self._window_remove_from_disabled(window):
            didRemove(window)
            return
        if self._disable_for_window(window, add_to_disabled = False):
            didRemove(window)
            return

    def _disable_for_window(self, window, add_to_disabled = True):
        if window not in self.windows:
            return
        name = window.wallet.basename()
        if window.background_process:
            self.print_error("Joining background_process...")
            window.background_process.join()
            window.background_process.logger.disconnectAll(); window.background_process.logger.deleteLater()
            window.background_process = None
            self.print_error("Window '{}' closed, ended shuffling for its wallet".format(name))
        self.windows.remove(window)
        monkey_patches_remove(window)
        window.utxo_list.update()
        window.update_status()
        self.print_error("Window '{}' disabled".format(name))
        if add_to_disabled:
            self._window_add_to_disabled(window)
        else:
            self._window_remove_from_disabled(window)
        return True
    
    def _window_add_to_disabled(self, window):
        if window not in self.disabled_windows:
            self._window_set_disabled_extra(window)
            self.disabled_windows.append(window)
            return True

    def _window_remove_from_disabled(self, window):
        self._window_clear_disabled_extra(window)
        if window in self.disabled_windows:
            self.disabled_windows.remove(window)
            return True

    @hook
    def on_new_password(self, window, old, new):
        if getattr(window, 'background_process', None):
            self.print_error("Got new password for wallet {} informing background process...".format(window.wallet.basename() if window.wallet else 'UNKNOWN'))
            window.background_process.set_password(new)

    @hook
    def spendable_coin_filter(self, window, coins):
        if not coins or window not in self.windows:
            return

        extra = window.send_tab_shuffle_extra
        spend_mode = extra.spendingMode()

        if spend_mode == extra.SpendingModeShuffled:
            # in Cash-Shuffle mode + shuffled spending we can ONLY spend shuffled coins!
            for coin in coins.copy():
                if not is_coin_shuffled(window.wallet, coin):
                    coins.remove(coin)
        elif spend_mode == extra.SpendingModeUnshuffled:
            # in Cash-Shuffle mode + unshuffled spending we can ONLY spend unshuffled coins!
            for coin in coins.copy():
                if is_coin_shuffled(window.wallet, coin):
                    coins.remove(coin)


    @hook
    def balance_label_extra(self, window):
        if window not in self.windows:
            return
        shuf, unshuf, uprog = get_shuffled_and_unshuffled_coin_totals(window.wallet)
        totShuf, nShuf = shuf
        window.send_tab_shuffle_extra.refresh(shuf, unshuf, uprog)
        if nShuf:
            return _('Shuffled: {} {} in {} Coins').format(window.format_amount(totShuf).strip(), window.base_unit(), nShuf)
        return None

    @hook
    def not_enough_funds_extra(self, window):
        if window not in self.windows:
            return

        shuf, unshuf, uprog = get_shuffled_and_unshuffled_coin_totals(window.wallet)
        totShuf, nShuf, totUnshuf, nUnshuf, totInProg, nInProg = *shuf, *unshuf, *uprog

        extra = window.send_tab_shuffle_extra
        extra.refresh(shuf, unshuf, uprog)

        spend_mode = extra.spendingMode()

        rets = []
        if spend_mode == extra.SpendingModeShuffled:
            if totUnshuf:
                rets += [_("{} {} are unshuffled").format(window.format_amount(totUnshuf).strip(), window.base_unit())]
        elif spend_mode == extra.SpendingModeUnshuffled:
            if totShuf:
                rets += [_("{} {} are shuffled").format(window.format_amount(totShuf).strip(), window.base_unit())]
        if totInProg:
            rets += [_("{} {} are busy shuffling").format(window.format_amount(totInProg).strip(), window.base_unit())]

        return ') ('.join(rets) or None

    @hook
    def get_change_addrs(self, wallet):
        for window in self.windows:
            if wallet == window.wallet:
                change_addrs = [wallet.cashshuffle_get_new_change_address()]
                wallet.print_error("CashShuffle: reserving change address",change_addrs[0].to_ui_string())
                return change_addrs

    @hook
    def do_clear(self, w):
        for window in self.windows:
            if w is window:
                extra = getattr(w, 'send_tab_shuffle_extra', None)
                if extra:
                    extra.do_clear()
                return

    def restart_all(self):
        for window in self.windows:
            bp = window.background_process
            if bp:
                password = bp.get_password()
                network_settings = Plugin.get_network_settings(window.config)
                if network_settings:
                    bp.join()
                    # kill the extant console logger as its existence can cause subtle bugs
                    bp.logger.disconnectAll(); bp.logger.deleteLater(); bp.logger = None
                    network_settings['host'] = network_settings.pop('server')
                    window.background_process = None; del bp
                    start_background_shuffling(window, network_settings, password=password)
                    window.print_error("CashShuffle restarted for wallet")
                    nd = Plugin.network_dialog
                    # force network settings tab to also refresh itself on restart to keep it in synch with other possible settings dialogs
                    if nd:
                        st = getattr(nd, "__shuffle_settings__", None)
                        if st: st.refreshFromSettings()
                else:
                    window.print_error("ERROR: could not load network settings, FIXME!")
            else:
                window.print_error("WARNING: Window lacks a BackgroundProcess, FIXME!")

    def settings_dialog(self, window, msg=None, restart_ask = True):
        def window_parent(w):
            # this is needed because WindowModalDialog overrides window.parent
            if callable(w.parent): return w.parent()
            return w.parent
        while not isinstance(window, ElectrumWindow) and window and window_parent(window):
            # MacOS fixups -- we can get into a situation where we are created without the ElectrumWindow being an immediate parent or grandparent
            window = window_parent(window)
        assert window and isinstance(window, ElectrumWindow)

        d = SettingsDialog(None, _("CashShuffle Settings"), window.config, msg)
        try:
            server_ok = False
            ns = None
            while not server_ok:
                if not d.exec_():
                    return
                else:
                    ns = d.get_form()
                    server_ok = d.serverOk
                    if not server_ok:
                        server_ok = Plugin.show_bad_server_box()

            if ns:
                Plugin.save_network_settings(window.config, ns)
                if restart_ask:
                    window.restart_cashshuffle(msg = _("CashShuffle must be restarted for the server change to take effect."))
            return ns
        finally:
            d.deleteLater()
            del d

    @staticmethod
    def show_bad_server_box():
        return bool(QMessageBox.critical(None, _("Error"), _("Unable to connect to the specified server."), QMessageBox.Retry|QMessageBox.Ignore, QMessageBox.Retry) == QMessageBox.Ignore)

    @staticmethod
    def try_to_apply_network_dialog_settings(settings_tab):
        ns = settings_tab.get_form()
        if ns and (settings_tab.serverOk or Plugin.show_bad_server_box()):
            Plugin.save_network_settings(settings_tab.config, ns) # save settings first.
            gui = Plugin.gui
            instance = Plugin.instance
            window = None
            # Next, try and get a wallet window to query user for plugin restart. If no window found, that's ok. Restart won't be necessary. :)
            if instance and instance.windows:
                # first try and get a window that actually has cashshuffle running, as that's only polite
                window = instance.windows[-1]
            elif instance and instance.disabled_windows:
                # ok, no enabled windows -- next, get a window that is cashshuffle compatible, if any exist
                window = instance.disabled_windows[-1]
            elif gui and gui.windows:
                # If that fails, get any old window...
                window = gui.windows[-1]
            # NB: if no window at this point, settings will take effect next time CashShuffle is enabled for a window
            if window:
                # window will raise itself.
                window.restart_cashshuffle(msg = _("CashShuffle must be restarted for the server change to take effect."))

    @staticmethod
    def save_network_settings(config, network_settings):
        ns = copy.deepcopy(network_settings)
        print_error("Saving network settings: {}".format(ns))
        config.set_key("cashshuffle_server_v1", ns)
        
    @staticmethod
    def get_network_settings(config):
        return copy.deepcopy(config.get("cashshuffle_server_v1", None))

    def settings_widget(self, window):
        weakMeth = Weak(self.settings_dialog)
        weakWindow = Weak(window)
        return EnterButton(_('Settings'), lambda: weakMeth(weakWindow))

    def requires_settings(self):
        return True

class SendTabExtraDisabled(QFrame, PrintError):
    ''' Implements a Widget that appears in the main_window 'send tab' to inform the user CashShuffle was disabled for this wallet '''

    pixmap_cached = None # singleton gets initialized first time an instance of this class is constructed. Contains the cashshuffle_icon5_grayed.png scaled to 100px width

    def __init__(self, window):
        self.send_tab = window.send_tab
        self.send_grid = window.send_grid
        self.wallet = window.wallet
        self.window = window
        super().__init__(window.send_tab)
        self.send_grid.addWidget(self, 0, 0, 1, self.send_grid.columnCount()) # just our luck. row 0 is free!
        self.setup()

    def setup(self):
        self.setFrameStyle(QFrame.Panel|QFrame.Sunken)
        l = QGridLayout(self)
        l.setVerticalSpacing(6)
        l.setHorizontalSpacing(30)
        l.setContentsMargins(6, 6, 6, 6)
        self.txt = "<big><b>{}</b></big> &nbsp;&nbsp; {}".format(_("CashShuffle Disabled"), _("Your shuffled and unshuffled coins can be mixed and spent together."))

        self.msg = "{}\n\n{}\n\n{}".format(_("When CashShuffle is disabled, your privacy on the blockchain is reduced to traditional levels, and 'chainalysis' becomes easier (your transactions can be associated with one another)."),
                                           _("This spending mode is the same as previous versions of Electron Cash, which did not offer CashShuffle."),
                                           _("You may toggle CashShuffle back on at any time using the 'CashShuffle' icon in the status bar."))
        self.titleLabel = HelpLabel(self.txt, self.msg)

        self.titleLabel.setParent(self)
        l.addWidget(self.titleLabel, 0, 1, 1, 4)

        l.setAlignment(self.titleLabel, Qt.AlignLeft|Qt.AlignVCenter)
        l.addItem(QSpacerItem(1, 1, QSizePolicy.MinimumExpanding, QSizePolicy.Fixed), 1, 5)


        icon = QLabel(self)
        if not SendTabExtraDisabled.pixmap_cached:
            SendTabExtraDisabled.pixmap_cached = QPixmap(":/icons/cash_shuffle5_grayed.png").scaledToWidth(75,Qt.SmoothTransformation)
        icon.setPixmap(SendTabExtraDisabled.pixmap_cached)
        icon.setToolTip(_("CashShuffle Disabled"))
        l.addWidget(icon, 0, 0, l.rowCount(), 1)

        l.setSizeConstraint(QLayout.SetNoConstraint)



class SendTabExtra(QFrame, PrintError):
    ''' Implements a Widget that appears in the main_window 'send tab' to inform the user of shuffled coin status & totals '''

    needRefreshSignal = pyqtSignal() # protocol thread uses this signal to tell us that amounts have changed
    pixmap_cached = None # singleton gets initialized first time an instance of this class is constructed. Contains the cashshuffle_icon5.png scaled to 100px width

    def __init__(self, window):
        self.send_tab = window.send_tab
        self.send_grid = window.send_grid
        self.wallet = window.wallet
        self.window = window
        super().__init__(window.send_tab)
        self.send_grid.addWidget(self, 0, 0, 1, self.send_grid.columnCount()) # just our luck. row 0 is free!
        self.setup()

    def setup(self):
        self.setFrameStyle(QFrame.Panel|QFrame.Sunken)
        l = QGridLayout(self)
        l.setVerticalSpacing(6)
        l.setHorizontalSpacing(30)
        l.setContentsMargins(6, 12, 6, 12)
        self.msg = "{}\n\n{}\n\n{}".format(_("For improved privacy, shuffled coins and unshuffled coins cannot be sent together in the same transaction when CashShuffle is enabled."),
                                                 _("You may switch between shuffled and unshuffled spending using the radio buttons on the right."),
                                                 _("If insufficient shuffled funds are available, you can wait a few minutes as coins are shuffled in the background."))
        self.msg2 = "{}\n\n{}\n\n{}".format(_("For improved privacy, shuffled coins and unshuffled coins cannot be sent together in the same transaction when CashShuffle is enabled."),
                                            _("You may switch between shuffled and unshuffled spending using the radio buttons on the right."),
                                            _("Some of your unshuffled funds may be temporarily locked while the shuffle operation is performed. If you want to unlock these funds immediately, you can use the 'Pause Shuffling' button to do so."))
        self.titleLabel = HelpLabel("", "") # Will be initialized by self.onSpendRadio() below
        self.titleLabel.setParent(self)
        l.addWidget(self.titleLabel, 0, 1, 1, 4)
        self.spendButtons = QButtonGroup(self)
        spend_mode = self.wallet.storage.get('shuffle_spend_mode', self.SpendingModeUnknown)
        # Shuffled
        self.shufLabel = HelpLabel("Shuffled available:", self.msg)
        m = _("Shuffled (private) funds")
        self.shufLabel.setToolTip(m)
        self.shufLabel.setParent(self)
        l.addWidget(self.shufLabel, 1, 1)
        self.amountLabel = QLabel("", self); self.amountLabel.setToolTip(m)
        l.addWidget(self.amountLabel, 1, 2)
        self.numCoinsLabel = QLabel("", self); self.numCoinsLabel.setToolTip(m)
        l.addWidget(self.numCoinsLabel, 1, 3)
        self.spendShuffled = QRadioButton(_("Spend Shuffled"), self); self.spendShuffled.setToolTip(_("Spend only your shuffled (private) coins"))
        l.addWidget(self.spendShuffled, 1, 4)
        self.spendButtons.addButton(self.spendShuffled)
        if spend_mode != self.SpendingModeUnshuffled:
            self.spendShuffled.setChecked(True)
        # Unshuffled
        self.unshufLabel = HelpLabel("Unshuffled available:", self.msg2)
        m = _("Funds that are not yet shuffled")
        self.unshufLabel.setToolTip(m)
        self.unshufLabel.setParent(self)
        l.addWidget(self.unshufLabel, 2, 1)
        self.amountLabelUnshuf = QLabel("", self); self.amountLabelUnshuf.setToolTip(m)
        l.addWidget(self.amountLabelUnshuf, 2, 2)
        self.numCoinsLabelUnshuf = QLabel("", self); self.numCoinsLabelUnshuf.setToolTip(m)
        l.addWidget(self.numCoinsLabelUnshuf, 2, 3)
        self.spendUnshuffled = QRadioButton(_("Spend Unshuffled"), self); self.spendUnshuffled.setToolTip(_("Spend only your unshuffled coins"))
        l.addWidget(self.spendUnshuffled, 2, 4)
        self.spendButtons.addButton(self.spendUnshuffled)
        if spend_mode == self.SpendingModeUnshuffled:
            self.spendUnshuffled.setChecked(True)

        # In Progress
        self.msg3 = _("Funds that are busy being shuffled are not available for spending until they are shuffled. To spend these funds immediately, use the 'Pause Shuffling' button to temporarily suspend CashShuffle.")
        self.busyLbl = HelpLabel(_("Busy shuffling:"), self.msg3)
        self.busyLbl.setParent(self)
        m = _("Funds currently being shuffled")
        self.busyLbl.setToolTip(m)
        l.addWidget(self.busyLbl, 3, 1)
        self.amountLabelBusy = QLabel("", self); self.amountLabelBusy.setToolTip(m)
        l.addWidget(self.amountLabelBusy, 3, 2)
        self.numCoinsLabelBusy = QLabel("", self); self.numCoinsLabelBusy.setToolTip(m)
        l.addWidget(self.numCoinsLabelBusy, 3, 3)
        self.pauseBut = QPushButton("", self) # Button text filled in by refresh() call
        self.pauseBut.setDefault(False); self.pauseBut.setAutoDefault(False); self.pauseBut.setCheckable(True)
        self.pauseBut.setToolTip(_("Pause/Unpause the background shuffle process (frees up 'busy' coins for spending)"))
        l.addWidget(self.pauseBut, 3, 4)

        l.setAlignment(self.titleLabel, Qt.AlignLeft)
        l.setAlignment(self.numCoinsLabel, Qt.AlignLeft)
        l.setAlignment(self.numCoinsLabelUnshuf, Qt.AlignLeft)
        l.setAlignment(self.numCoinsLabelBusy, Qt.AlignLeft)
        l.addItem(QSpacerItem(1, 1, QSizePolicy.MinimumExpanding, QSizePolicy.Fixed), 1, 5)


        icon = QLabel(self)
        if not SendTabExtra.pixmap_cached:
            # cache it and keep it around, since scaling this pixmap wastes CPU cycles each time
            SendTabExtra.pixmap_cached = QPixmap(":/icons/cash_shuffle5.png").scaledToWidth(125,Qt.SmoothTransformation)
        icon.setPixmap(SendTabExtra.pixmap_cached)
        l.addWidget(icon, 0, 0, l.rowCount(), 1)

        l.setSizeConstraint(QLayout.SetNoConstraint)


        self.onSpendRadio() # sets up the title label
        self.spendButtons.buttonClicked.connect(self.onSpendRadio)
        self.window.history_updated_signal.connect(self.refresh)
        self.needRefreshSignal.connect(self.refresh)
        self.needRefreshSignal.connect(self.window.update_fee)
        self.spendButtons.buttonClicked.connect(lambda x="ignored": self.refresh())
        self.pauseBut.clicked.connect(self.onClickedPause)

    def onSpendRadio(self, ignored = None):
        which = self.spendingMode()
        self.wallet.storage.put("shuffle_spend_mode", which)
        if which == self.SpendingModeShuffled:
            self.titleLabel.setText("<big><b>{}</b></big> &nbsp;&nbsp; ({})"
                                    .format(_("CashShuffle Enabled"), _("Only <b>shuffled</b> funds will be sent")))
            self.titleLabel.help_text = self.msg
            self.forceUnpause()
            self.pauseBut.setDisabled(True)
        elif which == self.SpendingModeUnshuffled:
            self.titleLabel.setText("<big><b>{}</b></big> &nbsp;&nbsp; ({})"
                                    .format(_("CashShuffle Enabled"), _("Only <i>unshuffled</i> funds will be sent")))
            self.titleLabel.help_text = self.msg2
            self.pauseBut.setEnabled(bool(self.window.background_process))

        self.window.update_fee()

    def onClickedPause(self, b):
        if self.window.background_process:
            self.window.background_process.set_paused(b)
            # Note: GUI refresh() wil later also set this string but we set it immediately here so UI feel peppier
            self.pauseBut.setText(_("Pause Shuffling") if not b else _("Shuffling Paused"))

    def do_clear(self): # called by plugin hook do_clear()
        self.forceUnpause()
        self.refresh()

    def forceUnpause(self):
        if self.window.background_process:
            self.window.background_process.set_paused(False)
        self.pauseBut.setChecked(False)
        self.pauseBut.setText(_("Pause Shuffling"))


    def showEvent(self, e):
        super().showEvent(e)
        self.refresh()

    @rate_limited(0.250)
    def refresh(self, shuf=None, unshuf=None, inprog=None):
        if not hasattr(self.window.wallet, '_shuffle_patched_'):
            # this can happen if this timer fires after the wallet was "un-monkey-patched". It's the price we pay for @rate_limied. :)
            return
        if shuf is None or unshuf is None or inprog is None:
            shuf, unshuf, inprog = get_shuffled_and_unshuffled_coin_totals(self.window.wallet)
        amount, n, amountUnshuf, nUnshuf, amountInProg, nInProg = *shuf, *unshuf, *inprog
        bt = ( "<b>{}</b> {}", ("<b>{}</b> %s <small>(%s)</small>"%(_("Coins"),_("UTXOs"))) ) # bold text template
        nt = ( "{} {}", ("{} %s <small>(%s)</small>"%(_("Coins"),_("UTXOs"))) ) # normal text template
        mode = self.spendingMode()
        tshuf = bt if mode == self.SpendingModeShuffled else nt # select a template based on mode
        tunshuf = bt if mode == self.SpendingModeUnshuffled else nt # select a template based on mode
        self.amountLabel.setText(tshuf[0].format(self.window.format_amount(amount).strip(), self.window.base_unit()))
        self.numCoinsLabel.setText(tshuf[1].format(n))
        self.amountLabelUnshuf.setText(tunshuf[0].format(self.window.format_amount(amountUnshuf).strip(), self.window.base_unit()))
        self.numCoinsLabelUnshuf.setText(tunshuf[1].format(nUnshuf))
        self.amountLabelBusy.setText(nt[0].format(self.window.format_amount(amountInProg).strip(), self.window.base_unit()))
        self.numCoinsLabelBusy.setText(nt[1].format(nInProg))

        f = self.spendShuffled.font()
        f.setBold(bool(mode == self.SpendingModeShuffled))
        self.spendShuffled.setFont(f)

        f = self.spendUnshuffled.font()
        f.setBold(bool(mode == self.SpendingModeUnshuffled))
        self.spendUnshuffled.setFont(f)

        if self.window.background_process:
            is_paused = self.window.background_process.get_paused()
            self.pauseBut.setChecked(is_paused)
        else:
            self.pauseBut.setChecked(False)
        self.pauseBut.setText(_("Pause Shuffling") if not self.pauseBut.isChecked() else _("Shuffling Paused"))

        self.pauseBut.setEnabled(bool(self.window.background_process and mode == self.SpendingModeUnshuffled))


    SpendingModeShuffled = 1
    SpendingModeUnshuffled = 2
    SpendingModeUnknown = 0

    def spendingMode(self):
        ''' Returns one o the SpendingMode* class constants above '''
        if hasattr(self.wallet, "_shuffle_patched_"):
            which = self.spendButtons.checkedButton()
            if which is self.spendShuffled: return self.SpendingModeShuffled
            elif which is self.spendUnshuffled: return self.SpendingModeUnshuffled
        return self.SpendingModeUnknown



class SettingsDialog(WindowModalDialog, PrintErrorThread):
    settingsChanged = pyqtSignal(dict)
    statusChanged = pyqtSignal(dict)
    formChanged = pyqtSignal()

    def __init__(self, parent, title, config, message=None):
        super().__init__(parent, title)
        self.config = config
        self.networkChecker = None
        self.serverOk = None
        if not isinstance(self, SettingsTab):
            self.setWindowModality(Qt.ApplicationModal)
            self.setMinimumSize(500, 200)
        self.setup(message)
        # NB: don't enable this as it may cause crashes
        #self.destroyed.connect(lambda x: self.print_error("Destroyed"))

    #def __del__(self):
    #    self.print_error("(Instance deleted)")

    def showEvent(self, e):
        super().showEvent(e)
        self.startNetworkChecker()
    def hideEvent(self, e):
        super().hideEvent(e)
        self.stopNetworkChecker()
    def closeEvent(self, e):
        super().closeEvent(e)
    def from_combobox(self):
        d = self.cb.currentData()
        if isinstance(d, dict):
            host, info, ssl = d.get('server'), d.get('info'), d.get('ssl')
            self.le.setText(host)
            self.sb.setValue(info)
            self.chk.setChecked(ssl)
        en = self.cb.currentIndex() == self.cb.count()-1
        self.le.setEnabled(en); self.sb.setEnabled(en); self.chk.setEnabled(en)
        self.formChanged.emit()
    def get_form(self):
        ret = {
            'server': self.le.text(),
            'info'  : self.sb.value(),
            'ssl'   : self.chk.isChecked()
        }
        if self.isVisible():
            customIdx = self.cb.count()-1
            if self.cb.currentIndex() == customIdx:
                # "remember" what they typed into the custom area..
                d = self.cb.itemData(customIdx)
                if ret != d:
                    self.cb.setItemData(customIdx, ret)
        return ret
    def setup_combo_box(self, selected = {}):
        def load_servers(fname):
            r = {}
            try:
                zips = __file__.find(".zip")
                if zips == -1:
                    with open(os.path.join(os.path.dirname(__file__), fname), 'r') as f:
                        r = json.loads(f.read())
                else:
                    from zipfile import ZipFile
                    zip_file = ZipFile(__file__[: zips + 4])
                    with zip_file.open("shuffle/" + fname) as f:
                        r = json.loads(f.read().decode())
            except:
                self.print_error("Error loading server list from {}: {}", fname, str(sys.exc_info()[1]))
            return r
        # /
        servers = load_servers("servers.json")
        selIdx = -1
        self.cb.clear()
        for host, d0 in sorted(servers.items()):
            d = d0.copy()
            d['server'] = host
            item = host + (' [ssl]' if d['ssl'] else '')
            self.cb.addItem(item, d)
            if selected and selected == d:
                selIdx = self.cb.count()-1

        self.cb.addItem(_("(Custom)"))
        if selIdx > -1:
            self.cb.setCurrentIndex(selIdx)
        elif selected and len(selected) == 3:
            custIdx = self.cb.count()-1
            self.cb.setItemData(custIdx, selected.copy())
            self.cb.setCurrentIndex(custIdx)
            return True
        return False
    def refreshFromSettings(self):
        selected = dict()
        try:
            # try and pre-populate from config
            current = self.config.get("cashshuffle_server_v1", dict())
            dummy = (current["server"], current["info"], current["ssl"]); del dummy;
            selected = current
        except KeyError:
            pass

        self.setup_combo_box(selected = selected)
        return selected
    def setup(self, msg):
        vbox = QVBoxLayout(self)
        if not msg:
            msg = _("Choose a CashShuffle server or enter a custom server.\nChanges will require the CashShuffle plugin to restart.")
        l = QLabel(msg + "\n")
        l.setAlignment(Qt.AlignHCenter|Qt.AlignTop)
        vbox.addWidget(l)
        grid = QGridLayout()
        vbox.addLayout(grid)

        self.cb = QComboBox(self)
        self.refreshFromSettings()

        grid.addWidget(QLabel(_('Servers'), self), 0, 0)
        grid.addWidget(self.cb, 0, 1)

        grid.addWidget(QLabel(_("Host"), self), 1, 0)

        hbox = QHBoxLayout(); grid.addLayout(hbox, 1, 1, 1, 2); grid.setColumnStretch(2, 1)
        self.le = QLineEdit(self); hbox.addWidget(self.le)
        self.le.textEdited.connect(lambda x='ignored': self.formChanged.emit())
        hbox.addWidget(QLabel(_("P:"), self))
        self.sb = QSpinBox(self); self.sb.setRange(1, 65535); hbox.addWidget(self.sb)
        self.sb.valueChanged.connect(lambda x='ignored': self.formChanged.emit())
        self.chk = QCheckBox(_("SSL"), self); hbox.addWidget(self.chk)
        self.chk.toggled.connect(lambda x='ignored': self.formChanged.emit())

        self.cb.currentIndexChanged.connect(lambda x='ignored': self.from_combobox())
        self.from_combobox()

        hbox2 = QHBoxLayout()
        vbox.addLayout(hbox2)
        self.statusGB = QGroupBox(_("Status"), self)
        hbox2.addWidget(self.statusGB)
        hbox3 = QHBoxLayout(self.statusGB)
        self.statusLabel = QLabel("", self.statusGB)
        self.statusLabel.setMinimumHeight(50)
        self.statusLabel.setAlignment(Qt.AlignAbsolute|Qt.AlignTop)
        hbox3.addWidget(self.statusLabel)

        self.vbox = vbox

        if not isinstance(self, SettingsTab):
            vbox.addStretch()
            buttons = Buttons(CloseButton(self), OkButton(self))
            vbox.addLayout(buttons)

    def startNetworkChecker(self):
        if self.networkChecker: return

        def onStatusChanged(d):
            #self.print_error("status changed", d)
            if not d: # Empty dict means we are connecting
                self.serverOk = None
                self.statusLabel.setText("<font color=\"blue\"><i>" + _("Checking server...") + "</i></font>")
                return
            if d.get('failed'): # Dict with only 1 key, 'failed' means connecton failed
                reason = d['failed']
                if reason == 'offline_mode':
                    reason = _("Electron Cash is in offline mode.")
                elif reason == 'bad':
                    reason = _("Server is misconfigured")
                elif reason == 'ssl':
                    reason = _("Failed to verify SSL certificate")
                else:
                    reason = _("Connection failure")
                self.statusLabel.setText("<b>" + _("Status") + ":</b> <font color=\"red\">{}</font>".format(reason))
                self.serverOk = False
                return

            # any other case has all the below keys defined

            self.serverOk = d['status'] == _('Ok')

            self.statusLabel.setText(
                '''
                <b>{}:</b> <i>{}</i><br>
                <b>{}:</b> <font color="green">{}</font> &nbsp;&nbsp;&nbsp;
                <small>{}: {} &nbsp;&nbsp;&nbsp; {}: {} &nbsp;&nbsp;&nbsp; {}: {}</small>
                '''
                .format(_('Server'), d['host'],
                        _('Status'), d['status'],
                        _('Pool size'), d['poolSize'],
                        _('Connections'),
                        d['connections'],
                        _('Active pools'), d['pools'])
            )

        class NetworkChecker(QThread, PrintErrorThread):
            ''' Runs in a separate thread, checks the server automatically when the settings form changes
                and publishes results to GUI thread. '''
            def __init__(self, parent):
                assert isinstance(parent, SettingsDialog), "Parent to NetworkChecker must be a settings dialog"
                super().__init__(parent)
                self.parent = parent
                self.timer = None # delay checking server in case user is typing in a new one in the custom box
                self.timerCon = None
                #self.destroyed.connect(lambda x: self.print_error("Destroyed"))
            #def __del__(self):
            #    self.print_error("(Instance deleted)")
            def run(self): # overrides QThread
                try:
                    self.print_error("Started thread.")
                    def updateStatus(d):
                        #self.print_error("updateStatus", d) # XXX
                        is_bad_server, is_bad_ssl, is_offline_mode = False, False, False
                        try:
                            if not Network.get_instance():
                                is_offline_mode = True
                                raise RuntimeError("No network")
                                
                            port, poolSize, connections, pools = query_server_for_stats(d['server'], d['info'], d['ssl'])
                            if poolSize < 3:
                                # hard-coded -- do not accept servers with poolSize < 3
                                is_bad_server = True
                                raise RuntimeError("PoolSize must be >=3, got: {}".format(poolSize))
                            if d['ssl'] and not verify_ssl_socket(d['server'], int(port), timeout=7.5):
                                is_bad_ssl = True
                                raise RuntimeError("Could not verify SSL server certificate.")
                                
                            socket.create_connection((d['server'], port), 5.0).close() # test connectivity to port
                            self.parent.statusChanged.emit({
                                'host'   : d['server'],
                                'status' : _('Ok'),
                                'poolSize' : str(poolSize),
                                'connections' : str(connections),
                                'pools' : str(len(pools))
                            })
                        except BaseException as e:
                            #import traceback
                            #traceback.print_exc()
                            self.print_error("exception on connect:",str(e))
                            if is_offline_mode:
                                self.parent.statusChanged.emit({'failed' : 'offline_mode'})
                            elif is_bad_ssl:
                                self.parent.statusChanged.emit({'failed' : 'ssl'})
                            elif is_bad_server:
                                self.parent.statusChanged.emit({'failed' : 'bad'})
                            else:
                                self.parent.statusChanged.emit({'failed' : 'failed'})
                    def onSettingsChange(d):
                        #self.print_error("onSettingsChange",d) # XXX
                        self.parent.statusChanged.emit(dict())
                        updateStatus(d)
                    def onTimer(t, d):
                        #self.print_error("onTimer",t.objectName()) # XXX
                        if t.objectName() == "Virgin Timer":
                            t.setObjectName("Nonvirgin Timer")
                            t.setSingleShot(False)
                            t.start(15000) # fire every 15 seconds to update stats
                            onSettingsChange(d)
                        else:
                            updateStatus(d)
                    def killTimer():
                        if self.timer:
                            #self.print_error("killTimer") # XXX
                            self.timer.stop()
                            if self.timerCon:
                                self.timer.timeout.disconnect(self.timerCon)
                            self.timeCon = None
                            self.timer.deleteLater()
                            self.timer = None
                    def startTimer(d):
                        #self.print_error("startTimer",d) # XXX
                        d = d.copy()
                        killTimer()
                        class MyTimer(QTimer, PrintErrorThread):
                            def __init__(self, parent=None):
                                QTimer.__init__(self, parent)
                                #self.destroyed.connect(lambda x: self.print_error("Destroyed"))
                            #def __del__(self):
                            #    self.print_error("(Instance deleted)")
                        self.timer = MyTimer(); self.timer.setObjectName("Virgin Timer")
                        self.timerCon = self.timer.timeout.connect(lambda: onTimer(self.timer,d))
                        self.timer.start(250)

                    c = self.parent.settingsChanged.connect(lambda d: startTimer(d))
                    super().exec_() # Process thread event loop
                    killTimer()
                    self.print_error("Exiting thread...")
                finally:
                    if c:
                        self.parent.settingsChanged.disconnect(c)
                    del c
            # / run
        # / NetworkChecker

        self.networkChecker = NetworkChecker(self)
        self.networkChecker.conn1 = self.statusChanged.connect(lambda d: onStatusChanged(d))
        def onFormChange():
            #self.print_error("onFormChange")
            d = self.get_form()
            self.settingsChanged.emit(d)
        self.networkChecker.conn2 = self.formChanged.connect(lambda: onFormChange())
        self.print_error("Starting network checker...")
        self.networkChecker.start()
        QTimer.singleShot(100, lambda: onFormChange())

    def stopNetworkChecker(self):
        if self.networkChecker:
            if self.networkChecker.conn1:
                self.statusChanged.disconnect(self.networkChecker.conn1)
                self.networkChecker.conn1 = None
            if self.networkChecker.conn2:
                self.statusChanged.disconnect(self.networkChecker.conn2)
                self.networkChecker.conn2 = None
            self.networkChecker.quit()
            self.networkChecker.wait()
            self.networkChecker.deleteLater()
            self.networkChecker = None
            self.print_error("Stopped network checker.")
    # /
# /SettingsDialog

class SettingsTab(SettingsDialog):
    applyChanges = pyqtSignal(object)

    def __init__(self, parent, title, config, message=None):
        super().__init__(parent, title, config, message)
        self.setWindowModality(Qt.NonModal)
        self.setWindowFlags(Qt.Widget) # force non-dialog
        self.apply = QPushButton(_("Apply"), self)
        hbox = QHBoxLayout()
        self.vbox.addLayout(hbox)
        self.vbox.addStretch()
        hbox.addStretch(1)
        hbox.addWidget(self.apply)
        self.apply.clicked.connect(lambda: self.applyChanges.emit(self))
# /SettingsTab
