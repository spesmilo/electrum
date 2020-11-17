#!/usr/bin/env python3
#
# Cash Shuffle - CoinJoin for Bitcoin Cash
# Copyright (C) 2018-2019 Electron Cash LLC
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
import os
import sys
import json
import copy
import socket
import time
import threading
import queue

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electroncash import networks
from electroncash.plugins import BasePlugin, hook
from electroncash.i18n import _
from electroncash.util import print_error, profiler, PrintError, Weak, format_satoshis_plain, finalization_print_error
from electroncash.network import Network
from electroncash.address import Address
from electroncash.transaction import Transaction
from electroncash.simple_config import SimpleConfig, get_config
from electroncash.wallet import Abstract_Wallet
from electroncash_gui.qt.util import EnterButton, CancelButton, Buttons, CloseButton, HelpLabel, OkButton, rate_limited, ColorScheme, destroyed_print_error, AppModalDialog
from electroncash_gui.qt.password_dialog import PasswordDialog
from electroncash_gui.qt.main_window import ElectrumWindow
from electroncash_gui.qt.amountedit import BTCAmountEdit
from electroncash_gui.qt.utils import FixedAspectRatioSvgWidget
from .client import BackgroundShufflingThread, ERR_SERVER_CONNECT, ERR_BAD_SERVER_PREFIX, MSG_SERVER_OK
from .comms import query_server_for_stats, verify_ssl_socket
from .conf_keys import ConfKeys  # config keys per wallet and global
from .coin_utils import CoinUtils

def is_coin_busy_shuffling(window, utxo_or_name):
    ''' Convenience wrapper for BackgroundShufflingThread.is_coin_busy_shuffling '''
    bp = getattr(window, 'background_process', None)
    return bool(bp and bp.is_coin_busy_shuffling(utxo_or_name))

def network_callback(window, event, *args):
    ''' This gets called in the network thread. It should just emit signals to GUI
    if it is to do any GUI work. '''
    if event == 'new_transaction':
        if len(args) == 2 and hasattr(window, 'wallet') and args[1] is window.wallet and args[0]:
            window._shuffle_sigs.tx.emit(window, args[0])

def my_custom_item_setup(utxo_list, item, utxo, name):
    if not hasattr(utxo_list.wallet, 'is_coin_shuffled'):
        return

    prog = utxo_list.in_progress.get(name, "")
    frozenstring = item.data(0, utxo_list.DataRoles.frozen_flags) or ""
    is_reshuffle = name in utxo_list.wallet._reshuffles
    is_slp = 's' in frozenstring

    u_value = utxo['value']

    if is_slp:
        item.setText(5, _("SLP Token"))
    elif not is_reshuffle and utxo_list.wallet.is_coin_shuffled(utxo):  # already shuffled
        item.setText(5, _("Shuffled"))
    elif not is_reshuffle and utxo['address'] in utxo_list.wallet._shuffled_address_cache:  # we hit the cache directly as a performance hack. we don't really need a super-accurate reply as this is for UI and the cache will eventually be accurate
        item.setText(5, _("Shuffled Addr"))
    elif not prog and ("a" in frozenstring or "c" in frozenstring):
        item.setText(5, _("Frozen"))
    elif u_value >= BackgroundShufflingThread.UPPER_BOUND: # too big
        item.setText(5, _("Too big"))
    elif u_value < BackgroundShufflingThread.LOWER_BOUND: # too small
        item.setText(5, _("Too small"))
    elif utxo['height'] <= 0: # not_confirmed
        if is_reshuffle:
            item.setText(5, _("Unconfirmed (reshuf)"))
        else:
            item.setText(5, _("Unconfirmed"))
    elif utxo['coinbase']:  # we disallow coinbase coins unconditionally -- due to miner feedback (they don't like shuffling these)
        item.setText(5, _("Coinbase"))
    elif (u_value >= BackgroundShufflingThread.LOWER_BOUND
              and u_value < BackgroundShufflingThread.UPPER_BOUND): # queued_labels
        window = utxo_list.parent
        if (window and window.background_process and utxo_list.wallet.network
                and utxo_list.wallet.network.is_connected()):
            if window.background_process.get_paused():
                item.setText(5, _("Paused"))
            else:
                if is_reshuffle:
                    item.setText(5, _("In queue (reshuf)"))
                else:
                    item.setText(5, _("In queue"))
        else:
            item.setText(5, _("Offline"))

    if prog == 'in progress': # in progress
        item.setText(5, _("In progress"))
    elif prog.startswith('phase '):
        item.setText(5, _("Phase {}").format(prog.split()[-1]))
    elif prog == 'wait for others': # wait for others
        item.setText(5, _("Wait for others"))
    elif prog.startswith("got players"): # got players > 1
        num, tot = (int(x) for x in prog.rsplit(' ', 2)[-2:])
        txt = "{} ({}/{})".format(_("Players"), num, tot)
        item.setText(5, txt)
    elif prog == "completed":
        item.setText(5, _("Done"))

def my_custom_utxo_context_menu_setup(window, utxo_list, menu, selected):
    ''' Adds CashShuffle related actions to the utxo_list context (right-click)
    menu '''
    wallet = window.wallet
    shuffled_selected = [name for name,flags in selected.items()
                         if (not flags
                             and wallet.is_coin_shuffled(CoinUtils.coin_name_to_dict(name))
                             and name not in wallet._reshuffles)]
    reshuffles_selected = [name for name in selected if name in wallet._reshuffles]
    menu.addSection(_('CashShuffle'))
    def on_reshuffle():
        wallet._reshuffles.update(set(shuffled_selected))
        utxo_list.update()

    def on_cancel_reshuffles():
        wallet._reshuffles.difference_update(set(reshuffles_selected))
        utxo_list.update()

    len_shufs, len_reshufs = len(shuffled_selected), len(reshuffles_selected)
    if len_shufs:
        if len_shufs == 1:
            action = menu.addAction(_('Reshuffle Coin'), on_reshuffle)
        else:
            action = menu.addAction(_('Reshuffle {} Shuffled').format(len_shufs), on_reshuffle)
    if len_reshufs:
        if len_reshufs == 1:
            action = menu.addAction(_('Cancel Reshuffle'), on_cancel_reshuffles)
        else:
            action = menu.addAction(_('Cancel {} Reshuffles').format(len_reshufs), on_cancel_reshuffles)

def _make_label(window, tot, shufamt, chg, fee, scale):
    is_dusty_fee = not chg and fee - BackgroundShufflingThread.FEE > 0
    # satoshis -> display format
    tot, shufamt, chg = window.format_amount(tot), window.format_amount(shufamt), window.format_amount(chg) if chg else ''
    chgtxt = " + {} ".format(chg) if chg else " "
    # Note it's important that the "Shuffle" prefix not be translated because we use it elsewhere
    # in the filter shuffle history callback... and it's also a "proper name" :)
    return ( "Shuffle" + (" {} {} {} {}{}(-{} sats {})"
                          .format(tot, window.base_unit(),
                                  BackgroundShufflingThread.SCALE_ARROW_DICT.get(scale, BackgroundShufflingThread.SCALE_ARROW_UNKNOWN),
                                  shufamt, chgtxt, fee, _("fee") if not is_dusty_fee else _("dusty fee")
                                 )
                         )
           )

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
            elif 'joined the pool' in msg:
                try:
                    num = int(msg.split(' ', 2)[1])
                    if num > 1:
                        # got more players than just self
                        new_in_progress = 'got players {} {}'.format(num, window.background_process.poolSize)
                except (ValueError, IndexError):
                    pass
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
                new_in_progress = "completed"  # NB: these don't leak. they eventually get cleaned up by the 'forget ' command from the background thread after some time
        elif msg.startswith("Error"):
            new_in_progress = None # flag to remove from progress list
            if ERR_SERVER_CONNECT in msg or ERR_BAD_SERVER_PREFIX in msg:
                window.cashshuffle_set_flag(1) # 1 means server connection issue
        elif msg.startswith("Blame") and "insufficient" not in msg and "wrong hash" not in msg:
            new_in_progress = None
        elif msg.startswith("shuffle_txid:"): # TXID message -- call "set_label"
            words = msg.split()
            label = _("CashShuffle")  # fallback on parse error
            if len(words) >= 2:
                txid = words[1]
                try:
                    tot, shufamt, chg, fee, scale = [int(w) for w in words[2:7]] # parse satoshis
                    label = _make_label(window, tot, shufamt, chg, fee, scale)
                except (IndexError, ValueError, TypeError) as e:
                    # Hmm. Some sort of parse error. We'll label it 'CashShuffle'
                    window.print_error("*** WARNING: Could not parse shuffle_txid message:", str(e), msg)
            window.wallet.set_label(txid, label)
            Plugin._increment_shuffle_counter(window)
            window.update_wallet()
        elif msg.startswith("add_tentative_shuffle:"):
            # add_tentative_shuffle: utxo outaddr tot scale chg fee
            # This is a mechanism as a workaround for issue #70 -- it's possible for last player to delay and cause other players to miss the txid.
            try:
                words = msg.split()
                utxo, addr = words[1:3]
                tot, shufamt, chg, fee, scale = [int(x) for x in words[3:8]] # parse satoshis
                window._shuffle_tentative[utxo] = (addr, tot, shufamt, chg, fee, scale) # remember this tentative shuffle so we can generate a label for it if we see a matching tx come in later
            except (IndexError, ValueError, TypeError) as e:
                # Some sort of parse error...
                window.print_error("*** WARNING: Could not parse add_tentative_shuffle message:", str(e), msg)
        elif msg.startswith("del_tentative_shuffle:"):
            try:
                utxo = msg.split()[1]
                window._shuffle_tentative.pop(utxo, None)  # tolerate del commands for missing values from dict
            except IndexError as e:
                # Some sort of parse error...
                window.print_error("*** WARNING: Could not parse del_tentative_shuffle message:", str(e), msg)


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

def _got_tx_check_tentative_shuffles(window, tx):
    ''' GUI thread: Got a new transaction for a window, so see if we should
    apply the shuffle_tentative label to it. The below mechanism is a
    workaround for bug #70. '''
    t = getattr(window, '_shuffle_tentative', None)
    if not t:
        # Most of the time this code path is taken as the dict is usually empty.
        # It only ever has entries when a shuffle failed at phase 4.
        return
    inputs, outputs = tx.inputs(), tx.outputs()
    for utxo, info in t.copy().items():
        # loop through all of the "tentative tx's" we have. this dict should be very small,
        # it only contains entries for shuffles that timed out in phase 4 where last player took too long (bug #70)
        addr, tot, amt, chg, fee, scale = info
        for txin in inputs:
            if CoinUtils.get_name(txin) == utxo:
                # found the coin in the incoming tx. Now make sure it's our anticipated shuffle tx that failed and not some other tx, so we apply the correct label only when it's the phase-4-failed shuffle tx.
                for n, txout in enumerate(outputs):
                    # Search the outputs of this tx to make sure they match what we expected for scale, out_addr...
                    typ, _addr, amount = txout
                    # the below checks make sure it matches what we expected from the failed shuffle, and also that the coin is shuffled (paranoia check).
                    if isinstance(_addr, Address) and amount == amt and _addr.to_storage_string() == addr:
                        txid = tx.txid()
                        if CoinUtils.is_coin_shuffled(window.wallet, {'prevout_hash':txid, 'prevout_n':n, 'address':_addr, 'value':amount}, {txid: tx}):
                            # all checks pass -- we successfully recovered from bug #70! Hurray!
                            window.wallet.set_label(txid, _make_label(window, tot, amt, chg, fee, scale))
                            Plugin._increment_shuffle_counter(window)
                            window.print_error("CashShuffle: found coin {} in tentative shuffle cache, applied label".format(utxo))
                            window.update_wallet()
                        else:
                            # hmm. this branch is very very unlikely.
                            window.print_error("CashShuffle: found coin {} in shuffle cache, but its tx is not a shuffle tx; label not applied".format(utxo))
                        break
                else:
                    # This coin was spent in this tx, but it appears to not be the tx we anticipated.. Last player didn't broadcast and we spent it later (perhaps as a re-shuffle or other).
                    window.print_error("CashShuffle: removing spent coin {} from tentative shuffle cache, label not applied".format(utxo))
                t.pop(utxo)  # unconditionally remove this tentative coin from the dict since either way it's spent
                return

def _got_tx_check_if_spent_shuffled_coin_and_freeze_used_address_etc(window, tx):
    ''' Freeze address after spending from a shuffled coin address for privacy (issue #100).
        Also remove any shuffled coin spends from the _is_shuffled_cache. '''
    inputs = tx.inputs()
    addrs_to_freeze = set()
    coins_to_purge_from_shuffle_cache = list()
    coins_to_purge_from_reshuffles = set()
    wallet = window.wallet
    all_addresses = None
    def is_mine(a):
        ''' This is faster than calling wallet.is_mine on *each* input
        as that involves a lot of rebuilding of the addresses list for each call.
        Also we use a set here which is faster than O(n) list lookup.
        This matters on huge tx's with many inputs as a speedup.'''
        nonlocal all_addresses
        if all_addresses is None:
            all_addresses = set(wallet.get_addresses())
        return a in all_addresses

    for inp in inputs:
        addr = inp['address']
        if isinstance(addr, Address) and is_mine(addr):
            # This coin was ours, purge True/False results from the
            # _is_shuffled_cache for this coin.
            name = CoinUtils.get_name(inp)
            coins_to_purge_from_shuffle_cache.append(name)
            coins_to_purge_from_reshuffles.add(name)
            if addr not in addrs_to_freeze and wallet.is_coin_shuffled(inp):
                # We spent a shuffled coin belonging to us.
                # Freeze that address to protect privacy.
                addrs_to_freeze.add(addr)
    if addrs_to_freeze:
        change_addr_set = set(wallet.get_change_addresses())
        addrs_to_freeze2 = addrs_to_freeze & change_addr_set  # we *ONLY* freeze if change address. see #1291
        if addrs_to_freeze2:
            wallet.set_frozen_state(addrs_to_freeze2, True)
            for addr in addrs_to_freeze2:
                name = addr.to_storage_string()
                if not wallet.labels.get(name):  # only put a label in there if no label there already
                    wallet.set_label(name, _("Shuffled coin spent (frozen for privacy)"))
    # the below is to prevent the "is_shuffled_cache" from growing forever which
    # impacts performance and wastes memory.  Since we were checking a seen TX
    # anyway, might as well expire coins from the cache that were spent.
    # remove_from_shufflecache acquires locks as it operates on the cache.
    CoinUtils.remove_from_shufflecache(wallet, coins_to_purge_from_shuffle_cache)
    # "forget" that these addresses were designated as shuffled addresses.
    CoinUtils.remove_from_shuffled_address_cache(wallet, addrs_to_freeze)
    wallet._reshuffles.difference_update(coins_to_purge_from_reshuffles)


def _got_tx(window, tx):
    ''' Generic callback to monitor tx's received for a wallet. Note that
        if this is called the tx definitely is for this window/wallet. '''
    if not hasattr(window, '_shuffle_patched_'):
        # defensie programming in case this signal arrives late
        # just as the user was disabling cash shuffle
        # (signal arrives via QueuedConnection which is why this check is necessary)
        return
    _got_tx_check_tentative_shuffles(window, tx)  # check for workaround to bug#70
    _got_tx_check_if_spent_shuffled_coin_and_freeze_used_address_etc(window, tx) # Feature #100
    # Note at this point the is_shuffled cache has had entries for inputs in
    # the tx above removed. If you want to add checks to this function that
    # involve the _is_shuffled_cache, do it above before the
    # '_got_tx_check_if_spent_shuffled_coin_and_freeze_used_address_etc' call.


class MsgForwarder(QObject):
    ''' Forwards messages from BackgroundShufflingThread to the GUI thread using
        Qt signal magic. See function update_coin_status above. '''

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
    logger = MsgForwarder(window)

    window.background_process = BackgroundShufflingThread(window,
                                                          window.wallet,
                                                          network_settings,
                                                          logger = logger,
                                                          period = period,
                                                          password = password,
                                                          timeout = timeout)
    window.background_process.start()

def monkey_patches_apply(window):
    def patch_window(window):
        if getattr(window, '_shuffle_patched_', None):
            return
        window.background_process = None
        window.send_tab_shuffle_extra = SendTabExtra(window)
        window._shuffle_tentative = dict()
        class Sigs(QObject):
            tx = pyqtSignal(QObject, object)
        window._shuffle_sigs = sigs = Sigs(window)
        sigs.tx.connect(_got_tx)
        window._shuffle_network_callback = lambda event, *args: network_callback(window, event, *args)
        if window.network:
            window.network.register_callback(window._shuffle_network_callback, ['new_transaction'])
        window._shuffle_patched_ = True
        window.force_use_single_change_addr = _("CashShuffle is enabled: change address logic will be handled by CashShuffle (to preserve privacy).")
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
        wallet.is_coin_shuffled = lambda coin, txs=None: CoinUtils.is_coin_shuffled(wallet, coin, txs)
        wallet.get_shuffled_and_unshuffled_coins = lambda *args, **kwargs: CoinUtils.get_shuffled_and_unshuffled_coins(wallet, *args, **kwargs)
        wallet.cashshuffle_get_new_change_address = lambda for_shufflethread=False: CoinUtils.get_new_change_address_safe(wallet, for_shufflethread=for_shufflethread)
        wallet._is_shuffled_cache = dict()
        wallet._shuffled_address_cache = set()
        wallet._addresses_cashshuffle_reserved = set()
        wallet._reshuffles = set()
        wallet._last_change = None
        CoinUtils.load_shuffle_change_shared_with_others(wallet)  # sets wallet._shuffle_change_shared_with_others
        # Paranoia -- force wallet into this single change address mode in case
        # other code (plugins, etc) generate tx's. We don't want tx generation
        # code to clobber our shuffle tx output addresses.
        change_addr_policy_1 = (bool(wallet.storage.get('use_change')), bool(wallet.storage.get('multiple_change')))
        change_addr_policy_2 = (bool(wallet.use_change), bool(wallet.multiple_change))
        desired_policy = (True, False)
        if any(policy != desired_policy for policy in (change_addr_policy_1, change_addr_policy_2)):
            wallet.use_change, wallet.multiple_change = desired_policy
            wallet.storage.put('use_change', desired_policy[0])
            wallet.storage.put('multiple_change', desired_policy[1])
            wallet.print_error("CashShuffle forced change address policy to: use_change={}, multiple_change={}"
                               .format(desired_policy[0], desired_policy[1]))
        # More paranoia -- in case app crashed, unfreeze coins frozen by last
        # app run.
        CoinUtils.unfreeze_frozen_by_shuffling(wallet)
        wallet._shuffle_patched_ = True
        print_error("[shuffle] Patched wallet")

    patch_wallet(window.wallet)
    patch_utxo_list(window.utxo_list)
    patch_window(window)

def monkey_patches_remove(window):
    def restore_window(window):
        if not getattr(window, '_shuffle_patched_', None):
            return
        if window.network:
            window.network.unregister_callback(window._shuffle_network_callback)
        delattr(window, '_shuffle_network_callback')
        try: window._shuffle_sigs.tx.disconnect()
        except TypeError: pass
        window._shuffle_sigs.deleteLater()
        delattr(window, "_shuffle_sigs")
        delattr(window, '_shuffle_tentative')
        window.send_tab_shuffle_extra.setParent(None); window.send_tab_shuffle_extra.deleteLater();
        delattr(window, 'send_tab_shuffle_extra')
        delattr(window, 'background_process')
        delattr(window, '_shuffle_patched_')
        window.force_use_single_change_addr = None
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
        delattr(wallet, "_shuffled_address_cache")
        delattr(wallet, '_shuffle_patched_')
        delattr(wallet, "_last_change")
        delattr(wallet, "_reshuffles")
        CoinUtils.store_shuffle_change_shared_with_others(wallet) # save _shuffle_change_shared_with_others to storage -- note this doesn't call storage.write() for performance reasons.
        delattr(wallet, '_shuffle_change_shared_with_others')
        CoinUtils.unfreeze_frozen_by_shuffling(wallet)
        print_error("[shuffle] Unpatched wallet")

    restore_window(window)
    restore_utxo_list(window.utxo_list)
    restore_wallet(window.wallet)

def _elide(x, maxlen=30, startlen=8):
    ''' Useful for eliding GUI text with an ellipsis ... in the middle '''
    if len(x) > maxlen and startlen + 3 < maxlen:
        return x[:startlen] + "..." + x[-(maxlen-startlen-3):]
    return x

class Plugin(BasePlugin):

    instance = None       # The extant instance singleton, if any. Variable is cleared on plugin stop.
    gui = None            # The "gui object" singleton (ElectrumGui) -- a useful refrence to keep around.
    network_dialog = None # The NetworkDialog window singleton (managed by the ElectrumGui singleton).

    def fullname(self):
        return 'CashShuffle'

    def description(self):
        return _("CashShuffle Protocol")

    def is_available(self):
        return networks.net is not networks.TaxCoinNet

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.windows = []
        self.disabled_windows = [] # this is to manage the "cashshuffle disabled" xtra gui element in the send tab
        self._hide_history_txs = False
        self.initted = False

    def is_defunct(self):
        return Plugin.instance is not self

    @hook
    def init_qt(self, gui):
        if self.initted:
            return
        self.print_error("Initializing...")
        Plugin.instance = self
        Plugin.gui = gui
        self._delete_old_keys(gui.config)
        if Plugin.network_dialog != gui.nd:
            Plugin.network_dialog = gui.nd # each time we are stopped, our module gets re-imported and we lose globals... so try and recapture this singleton
        ct = 0
        for window in gui.windows:
            self.on_new_window(window)
            ct += 1
        self.on_network_dialog(Plugin.network_dialog) # If we have a network dialgog, add self to network dialog
        self.initted = True
        self._hide_history_txs = bool(gui.config.get(ConfKeys.Global.HIDE_TXS_FROM_HISTORY, False))
        self.print_error("Initialized (had {} extant windows).".format(ct))
        self._hide_history_txs_check()

    @hook
    def on_network_dialog(self, nd):
        Plugin.network_dialog = nd
        if not nd: return
        self.print_error("OnNetworkDialog", str(nd))
        if not hasattr(nd, "__shuffle_settings__") or not nd.__shuffle_settings__:
            nd.__shuffle_settings__ = st = SettingsTab(parent=nd.nlayout.tabs, config=nd.nlayout.config)
            nd.nlayout.tabs.addTab(st, QIcon(':icons/CashShuffleLogos/logo-vertical.svg'), _("CashShuffle"))
            st.applyChanges.connect(Plugin.try_to_apply_network_dialog_settings)
        elif nd.__shuffle_settings__:
            # they may have a fake view if they didn't apply the last settings, refresh the view
            st = nd.__shuffle_settings__
            st.refreshFromSettings()

    @hook
    def window_update_status(self, window):
        but = getattr(window, '__shuffle__status__button__', None)
        if but:
            but.update_cashshuffle_icon()

    def show_cashshuffle_tab_in_network_dialog(self, window):
        window.gui_object.show_network_dialog(window)
        nd = Plugin.network_dialog
        if nd and getattr(nd, '__shuffle_settings__', None):
            st = nd.__shuffle_settings__
            nd.nlayout.tabs.setCurrentWidget(st)
            nd.activateWindow()
            return True
        return False

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
                st.kill()
                st.setParent(None)
                st.deleteLater()  # need to call this otherwise it sticks around :/
                st = None
            Plugin.network_dialog.__shuffle_settings__ = None
            self.print_error("Removed CashShuffle network settings tab")

    def window_has_cashshuffle(self, window):
        return window in self.windows

    def window_wants_cashshuffle(self, window):
        return window.wallet.storage.get(ConfKeys.PerWallet.ENABLED, False)

    def window_set_wants_cashshuffle(self, window, b):
        window.wallet.storage.put(ConfKeys.PerWallet.ENABLED, bool(b))

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

    @classmethod
    def is_wallet_cashshuffle_compatible(cls, window):
        from electroncash.wallet import ImportedWalletBase, Multisig_Wallet
        if (window.wallet.is_watching_only()
            or window.wallet.is_hardware()
            or isinstance(window.wallet, (Multisig_Wallet, ImportedWalletBase))):
            # wallet is watching-only, multisig, or hardware so.. not compatible
            return False
        return True

    def add_button_to_window(self, window):
        if not hasattr(window, '__shuffle__status__button__'):
            from .qt_status_bar_mgr import ShuffleStatusBarButtonMgr
            window.__shuffle__status__button__ = ShuffleStatusBarButtonMgr(self, window)
            window.print_error("Added cashshuffle status button")

    @classmethod
    def remove_button_from_window(cls, window):
        if hasattr(window, '__shuffle__status__button__'):
            window.__shuffle__status__button__.remove()
            delattr(window, '__shuffle__status__button__')
            window.print_error("Removed cashshuffle status button")

    @hook
    def on_new_window(self, window):
        if not self.is_wallet_cashshuffle_compatible(window):
            # wallet is watching-only, multisig, or hardware so.. mark it permanently for no cashshuffle
            self.window_set_cashshuffle(window, False)
            window.update_status()  # this has the side-effect of refreshing the cash shuffle status bar button's context menu (which has actions even for disabled/incompatible windows)
            return
        self.add_button_to_window(window)  # unconditionally add the button if compatible -- they may want to enable it later
        if window.wallet and not self.window_has_cashshuffle(window):
            if self.window_wants_cashshuffle(window):
                self._enable_for_window(window) or self._window_add_to_disabled(window)
            else:
                self._window_add_to_disabled(window)

    def _enable_for_window(self, window):
        name = window.wallet.basename()
        self.print_error("Window '{}' registered, performing window-specific startup code".format(name))
        if window.gui_object.warn_if_no_secp(
                parent=window,
                message=_("CashShuffle requires libsecp; cannot enable shuffling for this wallet."),
                icon=QMessageBox.Critical):
            self.print_error("Refusing to enable CashShuffle for window '{}' because no libsecp :(".format(name))
            return
        if self.is_defunct(): return  # we need to do this because presentation of above dialog box may mean user had the opportunity to close the plugin in another window
        cached_password = window.gui_object.get_cached_password(window.wallet)
        password = None
        while window.wallet.has_password():
            msg = _("CashShuffle requires access to '{}'.").format(name) + "\n" +  _('Please enter your password')
            if cached_password:
                password = cached_password
                cached_password = None
            else:
                pwdlg = PasswordDialog(parent=window.top_level_window(), msg=msg)
                password = pwdlg.run()
            if self.is_defunct(): return  # we need to do this because presentation of above dialog box may mean user had the opportunity to close the plugin in another window
            if password is None:
                # User cancelled password input
                if not self.warn_if_shuffle_disable_not_ok(window, msg=_('CashShuffle will now be <i>disabled</i> for a wallet which has previously had it <b>enabled</b>. Are you sure?')):
                    # User was warned and opted to try again to enable
                    continue
                self.window_set_cashshuffle(window, False)
                window.show_error(_("CashShuffle password prompt canceled; disabling for this wallet."), parent=window)
                return
            try:
                window.wallet.check_password(password)
                break
            except Exception as e:
                window.show_error(str(e), parent=window)
                if self.is_defunct(): return  # we need to do this because presentation of above dialog box may mean user had the opportunity to close the plugin in another window
                continue
        network_settings = Plugin.get_network_settings(window.config)
        if not network_settings:
            network_settings = self.settings_dialog(window, msg=_("Please choose a CashShuffle server"), restart_ask = False)
        if self.is_defunct(): return  # we need to do this because presentation of above dialog box may mean user had the opportunity to close the plugin in another window
        if not network_settings:
            self.window_set_cashshuffle(window, False)
            window.show_error(_("Can't get network, disabling CashShuffle."), parent=window)
            return
        self._delete_old_keys(window.wallet)
        self._window_remove_from_disabled(window)
        network_settings = copy.deepcopy(network_settings)
        network_settings['host'] = network_settings.pop('server')
        monkey_patches_apply(window)
        self.windows.append(window)
        self._increment_session_counter(window)
        window.update_status()
        window.utxo_list.update()
        start_background_shuffling(window, network_settings, password=password)
        return True

    @hook
    def utxo_list_item_setup(self, utxo_list, item, x, name):
        my_custom_item_setup(utxo_list, item, x, name)

    @hook
    def utxo_list_context_menu_setup(self, utxo_list, menu, selected):
        window = utxo_list.parent
        if window in self.windows:
            my_custom_utxo_context_menu_setup(window, utxo_list, menu, selected)

    @hook
    def history_list_filter(self, history_list, h_item, label):
        # NB: 'h_item' might be None due to performance reasons
        if self._hide_history_txs:
            return bool(label.startswith("Shuffle ")  # this string is not translated for performance reasons. _make_label also does not translate this string.
                        and ( any( x for x in BackgroundShufflingThread.SCALE_ARROWS
                                   if x in label )
                              or BackgroundShufflingThread.SCALE_ARROW_UNKNOWN in label
                            )
                        )
        return None

    @hook
    def history_list_context_menu_setup(self, history_list, menu, item, tx_hash):
        # NB: We unconditionally create this menu if the plugin is loaded because
        # it's possible for any wallet, even a watching-only wallet to have
        # shuffle tx's with the correct labels (if the user uses labelsync or
        # has imported labels).
        menu.addSeparator()
        def action_callback():
            self._hide_history_txs = not self._hide_history_txs
            Plugin.gui.config.set_key(ConfKeys.Global.HIDE_TXS_FROM_HISTORY, self._hide_history_txs, save=True)
            action.setChecked(self._hide_history_txs)
            if self._hide_history_txs:
                tip = _("Shuffle transactions are now hidden")
            else:
                tip = _("Shuffle transactions are now shown")
            QToolTip.showText(QCursor.pos(), tip, history_list)
            history_list.update() # unconditionally update this history list as it may be embedded in the address_detail window and not a global history list..
            for w in Plugin.gui.windows:
                # Need to update all the other open windows.
                # Note: We still miss any other open windows' address-detail
                #       history lists with this.. but that's ok as most of the
                #       time it won't be noticed by people and actually
                #       finding all those windows would just make this code
                #       less maintainable.
                if history_list is not w.history_list:  # check if not already updated above
                    w.history_list.update()
        action = menu.addAction(_("Hide shuffle transactions"), action_callback)
        action.setCheckable(True)
        action.setChecked(self._hide_history_txs)

    def on_close(self):
        ''' This is called on plugin unload/disable '''
        self.del_network_dialog_tab()
        PoolsWinMgr.killInstance()
        for window in self.windows.copy():
            self.on_close_window(window)
        for window in self.disabled_windows.copy():
            self.on_close_window(window)
        if self.gui:
            for window in self.gui.windows:
                # lastly, we do this for ALL the extant wallet windows because all
                # of their CashShuffle context menus attached to the cashshuffle
                # status button need updating when the plugin is exited. Note
                # that there may be windows in this set (incompatible windows)
                # that aren't in either of the above 2 sets of windows.
                window.update_status()
        self.initted = False
        Plugin.instance = None
        self.print_error("Plugin closed")
        assert len(self.windows) == 0 and len(self.disabled_windows) == 0, (self.windows, self.disabled_windows)
        self._hide_history_txs_check()

    def _hide_history_txs_check(self):
        # Handle possibility that now that plugin is closed or opened, shuffle tx's are hidden or not hidden. hide/unhide them
        if self._hide_history_txs and Plugin.gui:
            def refresh_history_lists(gui):
                for w in gui.windows:
                    w.history_list.update()
            QTimer.singleShot(250, lambda: refresh_history_lists(Plugin.gui))

    @hook
    def on_close_window(self, window):
        def didRemove(window):
            self.print_error("Window '{}' removed".format(window.wallet.basename()))
        self.remove_button_from_window(window)
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
            window.update_status()  # ensure cashshuffle icon has the right menus, etc
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
    def on_spend_coins(self, window, coins):
        if (not coins or window not in self.windows
                # the coin may not be "mine" if doing private key -> sweep
                # in that case, just abort this as it doesn't matter what
                # mode the send tab is in
                or (window.tx_external_keypairs
                        and not window.wallet.is_mine(coins[0]['address']))):
            return

        extra = window.send_tab_shuffle_extra
        spend_mode = extra.spendingMode()
        is_shuffled = CoinUtils.is_coin_shuffled(window.wallet, coins[0])  # check coins[0]
        if spend_mode == extra.SpendingModeShuffled and not is_shuffled:
            # Coin is not shuffled, spend mode is Shuffled, force send tab to
            # coin's mode
            extra.setSpendingMode(extra.SpendingModeUnshuffled)
        elif spend_mode == extra.SpendingModeUnshuffled and is_shuffled:
            # Coin is shuffled, spend mode is UnShuffled, force send tab to
            # coin's mode
            extra.setSpendingMode(extra.SpendingModeShuffled)

    @hook
    def spendable_coin_filter(self, window, coins):
        if not coins or window not in self.windows:
            return

        extra = window.send_tab_shuffle_extra
        spend_mode = extra.spendingMode()
        external_coin_addresses = set()  # this is only ever used if they are doing a sweep. in which case we always allow the coins involved in the sweep
        for pubkey in window.tx_external_keypairs:
            a = Address.from_pubkey(pubkey)
            external_coin_addresses.add(a)

        if spend_mode == extra.SpendingModeShuffled:
            # in Cash-Shuffle mode + shuffled spending we can ONLY spend shuffled coins + unshuffled living on a shuffled coin address
            shuf_adrs_seen = set()
            shuf_coins_seen = set()
            for coin in coins.copy():
                if coin['address'] in external_coin_addresses:
                    # completely bypass this filter for external keypair dict
                    # which is only used for sweep dialog in send tab
                    continue
                is_shuf_adr = CoinUtils.is_shuffled_address(window.wallet, coin['address'])
                if is_shuf_adr:
                    shuf_adrs_seen.add(coin['address'])
                if (not CoinUtils.is_coin_shuffled(window.wallet, coin)
                        and not is_shuf_adr):  # we allow coins sitting on a shuffled address to be "spent as shuffled"
                    coins.remove(coin)
                else:
                    shuf_coins_seen.add(CoinUtils.get_name(coin))
            # NEW! Force co-spending of other coins sitting on a shuffled address (Fix #3)
            for adr in shuf_adrs_seen:
                adr_coins = window.wallet.get_addr_utxo(adr)
                for name, adr_coin in adr_coins.items():
                    if name not in shuf_coins_seen and not adr_coin['is_frozen_coin']:
                        coins.append(adr_coin)
                        shuf_coins_seen.add(name)

        elif spend_mode == extra.SpendingModeUnshuffled:
            # in Cash-Shuffle mode + unshuffled spending we can ONLY spend unshuffled coins (not sitting on a shuffled address)
            for coin in coins.copy():
                if ((CoinUtils.is_coin_shuffled(window.wallet, coin)
                        or is_coin_busy_shuffling(window, coin)
                        or CoinUtils.is_shuffled_address(window.wallet, coin['address']))
                        and coin['address'] not in external_coin_addresses):
                    coins.remove(coin)

    @hook
    def balance_label_extra(self, window):
        if window not in self.windows:
            return
        shuf, unshuf, uprog, usas = CoinUtils.get_shuffled_and_unshuffled_coin_totals(window.wallet)
        totShuf, nShuf = shuf
        # TODO: handle usas separately?
        totShuf += usas[0]
        nShuf += usas[1]
        window.send_tab_shuffle_extra.refresh(shuf, unshuf, uprog, usas)
        if nShuf:
            return (_('Shuffled: {} {} in {} Coin'),
                    _('Shuffled: {} {} in {} Coins'))[0 if nShuf == 1 else 1].format(window.format_amount(totShuf).strip(), window.base_unit(), nShuf)
        return None

    @hook
    def not_enough_funds_extra(self, window):
        if window not in self.windows:
            return

        shuf, unshuf, uprog, usas = CoinUtils.get_shuffled_and_unshuffled_coin_totals(window.wallet)
        totShuf, nShuf, totUnshuf, nUnshuf, totInProg, nInProg = *shuf, *unshuf, *uprog
        # TODO: handle usas separately?
        totShuf += usas[0]
        nShuf += usas[1]

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
                window.print_error("WARNING: Window lacks a background_process, FIXME!")

    def view_pools(self, window):
        assert isinstance(window, ElectrumWindow), "view_pools must be passed an ElectrumWindow object! FIXME!"
        settings = __class__.get_and_validate_network_settings(window.config)
        if settings:
            sdict = settings.copy()
            sdict['name'] = "{}:{}".format(sdict['server'], sdict['info'])
            PoolsWinMgr.show(sdict, settings, window.config, parent_window=window, modal=False)
        else:
            # this should not normally be reachable in the UI, hence why we don't i18n the error string.
            window.show_error("CashShuffle is not properly set up -- no server defined! Please select a server from the settings.")

    def restart_cashshuffle(self, window, msg = None, parent = None):
        if (parent or window).question("{}{}".format(msg + "\n\n" if msg else "", _("Restart the CashShuffle plugin now?")),
                                       app_modal=True):
            self.restart_all()
            window.notify(_("CashShuffle restarted"))

    def settings_dialog(self, window, msg=None, restart_ask = True):
        def window_parent(w):
            # this is needed because WindowModalDialog overrides window.parent
            if callable(w.parent): return w.parent()
            return w.parent
        while not isinstance(window, ElectrumWindow) and window and window_parent(window):
            # MacOS fixups -- we can get into a situation where we are created without the ElectrumWindow being an immediate parent or grandparent
            window = window_parent(window)
        assert window and isinstance(window, ElectrumWindow)

        d = SettingsDialog(title=_("CashShuffle Settings"), config=window.config, message=msg)
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
                    self.restart_cashshuffle(window, msg = _("CashShuffle must be restarted for the server change to take effect."))
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
            if window and instance:
                # window will raise itself.
                instance.restart_cashshuffle(window,
                                             msg = _("CashShuffle must be restarted for the server change to take effect."),
                                             parent = Plugin.network_dialog)

    @staticmethod
    def save_network_settings(config, network_settings):
        ns = copy.deepcopy(network_settings)
        print_error("Saving network settings: {}".format(ns))
        config.set_key(ConfKeys.Global.SERVER, ns)

    @staticmethod
    def get_network_settings(config):
        return copy.deepcopy(config.get(ConfKeys.Global.SERVER, None))

    @staticmethod
    def get_and_validate_network_settings(config):
        selected = dict()
        try:
            # try and pre-populate from config
            current = __class__.get_network_settings(config)
            dummy = (current["server"], current["info"], current["ssl"]); del dummy;
            selected = current
        except (KeyError, TypeError):
            pass
        return selected

    def settings_widget(self, window):
        weakMeth = Weak(self.settings_dialog)
        weakWindow = Weak(window)
        return EnterButton(_('Settings'), lambda: weakMeth(weakWindow))

    def requires_settings(self):
        return True

    def _delete_old_keys(self, config_or_wallet):
        getter, setter, defuncts, thing = None, None, tuple(), None
        if isinstance(config_or_wallet, SimpleConfig):
            config = config_or_wallet
            getter = lambda k: config.get(k)
            setter = lambda k: config.set_key(k, None, save=True)
            defuncts = ConfKeys.Global.DEFUNCT
            thing = "config"
        elif isinstance(config_or_wallet, Abstract_Wallet):
            storage = config_or_wallet.storage
            getter = lambda k: storage.get(k)
            setter = lambda k: storage.put(k, None)
            defuncts = ConfKeys.PerWallet.DEFUNCT
            thing = "wallet.storage for {}".format(config_or_wallet.basename())

        if thing:
            ct = 0
            for k in defuncts:
                if getter(k) is not None:
                    ct += 1
                    setter(k)
            if ct:
                self.print_error("Found and removed {} deprecated keys from {}".format(ct, thing))

    # counters: shuffle counter and session counter
    @classmethod
    def _increment_generic_counter(cls, window, key):
        window.wallet.storage.put(key, cls._get_generic_counter(window, key) + 1)
    @staticmethod
    def _get_generic_counter(window, key):
        try:
            ctr = int(window.wallet.storage.get(key, 0))
        except (ValueError, TypeError):  # paranoia
            # stored value must have not been an int. :(
            ctr = 0
        return ctr
    @classmethod
    def _increment_session_counter(cls, window):
        cls._increment_generic_counter(window, ConfKeys.PerWallet.SESSION_COUNTER)
    @classmethod
    def _get_session_counter(cls, window):
        return cls._get_generic_counter(window, ConfKeys.PerWallet.SESSION_COUNTER)
    @classmethod
    def _increment_shuffle_counter(cls, window):
        cls._increment_generic_counter(window, ConfKeys.PerWallet.SHUFFLE_COUNTER)
    @classmethod
    def _get_shuffle_counter(cls, window):
        return cls._get_generic_counter(window, ConfKeys.PerWallet.SHUFFLE_COUNTER)
    # /counters

    def warn_if_shuffle_disable_not_ok(self, window, *, msg=None):
        '''
        Determine if disabling (or not re-enabling in the case of a pw dialog
        cancel) of cash shuffle is ok for this wallet.

        This method may block the GUI with a local modal dialog asking the user
        if they are sure.

        In the future, we may also put code to say "shuffles pending, please
        wait..." in a cancellable progress-type dialog.

        Returns True if calling code should proceed with disable action.
        '''
        # Note -- window may not necessarily be shuffle patched as this
        # may be called from the password dialog
        noprompt = window.wallet.storage.get(ConfKeys.PerWallet.DISABLE_NAGGER_NOPROMPT, False)
        if not noprompt and type(self)._get_session_counter(window) > 0:
            if msg is None:
                msg = _('You are now <i>disabling</i> CashShuffle for this wallet. Are you sure?')
            ans, chk = window.question(
                    msg=msg,
                    informative_text=_('Spending and linking coins with CashShuffle disabled may compromise your privacy for both shuffled and unshuffled coins in this wallet.'),
                    title=_("Privacy Warning"), rich_text=True,
                    checkbox_text=_("Never ask for this wallet"), checkbox_ischecked=noprompt,
                )
            if chk:
                window.wallet.storage.put(ConfKeys.PerWallet.DISABLE_NAGGER_NOPROMPT, bool(chk))
            return bool(ans)
        return True


class SendTabExtraDisabled(QFrame, PrintError):
    ''' Implements a Widget that appears in the main_window 'send tab' to inform the user CashShuffle was disabled for this wallet '''

    def __init__(self, window):
        self.send_tab = window.send_tab
        self.send_grid = window.send_grid
        self.wallet = window.wallet
        self.window = window
        super().__init__(window.send_tab)
        self.send_grid.addWidget(self, 0, 0, 1, self.send_grid.columnCount()) # just our luck. row 0 is free!
        self.setup()

    def setup(self):
        self.setFrameStyle(QFrame.StyledPanel|QFrame.Sunken)
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


        icon = FixedAspectRatioSvgWidget(75, ":icons/CashShuffleLogos/logo-vertical_grayed.svg")
        icon.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        icon.setToolTip(_("CashShuffle Disabled"))
        l.addWidget(icon, 0, 0, l.rowCount(), 1)

        l.setSizeConstraint(QLayout.SetNoConstraint)



class SendTabExtra(QFrame, PrintError):
    ''' Implements a Widget that appears in the main_window 'send tab' to inform the user of shuffled coin status & totals '''

    needRefreshSignal = pyqtSignal() # protocol thread uses this signal to tell us that amounts have changed
    needWalletSaveSignal = pyqtSignal() # protocol thread uses this signal to tell us that the wallet should be saved to disk using storage.write
    pixmap_cached = None # singleton gets initialized first time an instance of this class is constructed. Contains the cashshuffle_icon5.png scaled to 125px width

    def __init__(self, window):
        self.send_tab = window.send_tab
        self.send_grid = window.send_grid
        self.wallet = window.wallet
        self.window = window
        super().__init__(window.send_tab)
        self.send_grid.addWidget(self, 0, 0, 1, self.send_grid.columnCount()) # just our luck. row 0 is free!
        self.setup()

    def setup(self):
        self.setFrameStyle(QFrame.StyledPanel|QFrame.Sunken)
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
        # Shuffled
        self.shufLabel = HelpLabel(_("Shuffled available:"), self.msg)
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
        # Unshuffled
        self.unshufLabel = HelpLabel(_("Unshuffled available:"), self.msg2)
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

        self.spendShuffled.setChecked(True)

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


        icon = FixedAspectRatioSvgWidget(125, ":icons/CashShuffleLogos/logo-vertical.svg")
        icon.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        l.addWidget(icon, 0, 0, l.rowCount(), 1)

        l.setSizeConstraint(QLayout.SetNoConstraint)


        self.spendButtons.buttonClicked.connect(self.onSpendRadio)
        self.window.history_updated_signal.connect(self.refresh)
        self.needRefreshSignal.connect(self.refresh)
        self.needRefreshSignal.connect(self.window.update_fee)
        self.needWalletSaveSignal.connect(self.wallet.storage.write)
        self.spendButtons.buttonClicked.connect(lambda x="ignored": self.refresh())
        self.pauseBut.clicked.connect(self.onClickedPause)

        self.onSpendRadio() # sets up the title label and possibly warns user if starting up in "spend unshuffled" mode

    def onSpendRadio(self, ignored = None):
        which = self.spendingMode()
        if which == self.SpendingModeShuffled:
            self.titleLabel.setText("<big><b>{}</b></big> &nbsp;&nbsp; ({})"
                                    .format(_("CashShuffle Enabled"), _("Only <b>shuffled</b> funds will be sent")))
            self.titleLabel.help_text = self.msg
            self.forceUnpause()
            #self.pauseBut.setDisabled(True)
        elif which == self.SpendingModeUnshuffled:
            self.titleLabel.setText("<big><b>{}</b></big> &nbsp;&nbsp; ({})"
                                    .format(_("CashShuffle Enabled"), _("Only <i>unshuffled</i> funds will be sent")))
            self.titleLabel.help_text = self.msg2
            #self.pauseBut.setEnabled(bool(self.window.background_process and not self.window.background_process.is_offline_mode()))
            noprompt = self.wallet.storage.get(ConfKeys.PerWallet.SPEND_UNSHUFFLED_NAGGER_NOPROMPT, False)
            if not noprompt:
                ans, chk = self.window.question(
                        msg=_('You are now spending <b><i>unshuffled</i></b> coins. Are you sure?'),
                        informative_text=_('Spending and linking these coins may compromise your privacy not only for new received coins, but also for your past spending of shuffled coins.'),
                        title=_("Privacy Warning"), rich_text=True,
                        checkbox_text=_("Never ask for this wallet"), checkbox_ischecked=noprompt,
                    )
                if chk:
                    self.wallet.storage.put(ConfKeys.PerWallet.SPEND_UNSHUFFLED_NAGGER_NOPROMPT, bool(chk))
                if not ans:
                    self.spendShuffled.animateClick()
                    return

        self.window.update_fee()

    def onClickedPause(self, b):
        if self.window.background_process:
            self.window.background_process.set_paused(b)
            # Note: GUI refresh() wil later also set this string but we set it immediately here so UI feel peppier
            self.pauseBut.setText(_("Pause Shuffling") if not b else _("Shuffling Paused"))
            self.window.utxo_list.update()

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

    _templates = tuple()

    @rate_limited(0.250)
    def refresh(self, shuf=None, unshuf=None, inprog=None, usas=None):
        if not hasattr(self.window.wallet, '_shuffle_patched_'):
            # this can happen if this timer fires after the wallet was "un-monkey-patched". It's the price we pay for @rate_limied. :)
            return
        if shuf is None or unshuf is None or inprog is None or usas is None:
            shuf, unshuf, inprog, usas = CoinUtils.get_shuffled_and_unshuffled_coin_totals(self.window.wallet)
        amount, n, amountUnshuf, nUnshuf, amountInProg, nInProg = *shuf, *unshuf, *inprog
        amount += usas[0]
        n += usas[1]
        # TODO: handle usas separately?
        if not __class__._templates:  # lazy init
            __class__._templates = (
                # bold [0]
                ( # [0] is singular [1] is plural
                    ( "<b>{}</b> {}", ("<b>{}</b> %s <small>(%s)</small>"%(_("Coin"),_("UTXO"))) ),
                    ( "<b>{}</b> {}", ("<b>{}</b> %s <small>(%s)</small>"%(_("Coins"),_("UTXOs"))) )
                ),
                # normal [1]
                ( #[0] singular, [1] plural
                    ( "{} {}", ("{} %s <small>(%s)</small>"%(_("Coin"),_("UTXO"))) ), # normal singular
                    ( "{} {}", ("{} %s <small>(%s)</small>"%(_("Coins"),_("UTXOs"))) ) # normal text plural template
                )
            )
        bt = self._templates[0] # bold text templates (sub-list [0]==singular [1]==plural)
        nt = self._templates[1] # normal text templates (sub-list [0]==singular [1]==plural)
        mode = self.spendingMode()
        tshuf = (bt if mode == self.SpendingModeShuffled else nt)[0 if n == 1 else 1] # select a template based on mode & plurality
        tunshuf = (bt if mode == self.SpendingModeUnshuffled else nt)[0 if nUnshuf == 1 else 1] # select a template based on mode
        self.amountLabel.setText(tshuf[0].format(self.window.format_amount(amount).strip(), self.window.base_unit()))
        self.numCoinsLabel.setText(tshuf[1].format(n))
        self.amountLabelUnshuf.setText(tunshuf[0].format(self.window.format_amount(amountUnshuf).strip(), self.window.base_unit()))
        self.numCoinsLabelUnshuf.setText(tunshuf[1].format(nUnshuf))
        tbusy = nt[0 if nInProg == 1 else 1]
        self.amountLabelBusy.setText(tbusy[0].format(self.window.format_amount(amountInProg).strip(), self.window.base_unit()))
        self.numCoinsLabelBusy.setText(tbusy[1].format(nInProg))

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

        self.pauseBut.setEnabled(bool(self.window.background_process #and mode == self.SpendingModeUnshuffled
                                      and not self.window.background_process.is_offline_mode()))


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

    def setSpendingMode(self, spendMode):
        but2Check = None
        if spendMode == self.SpendingModeUnshuffled and not self.spendUnshuffled.isChecked():
            but2Check = self.spendUnshuffled
        elif spendMode == self.SpendingModeShuffled and not self.spendShuffled.isChecked():
            but2Check = self.spendShuffled
        if but2Check:
            but2Check.setChecked(True)
            self.onSpendRadio()  # slot won't get called from setting radio buttons programmaticallys, so we force-call the slot


class NetworkCheckerDelegateMixin:
    '''Abstract base for classes receiving data from the NetworkChecker.
    SettingsDialog implements this, as does the PoolsWindow.'''
    settingsChanged = pyqtSignal(dict)
    statusChanged = pyqtSignal(dict)

class SettingsDialogMixin(NetworkCheckerDelegateMixin, PrintError):
    ''' Abstrat Base class -- do not instantiate this as it will raise errors
    because the pyqtSignal cannot be bound to a non-QObject.

    Instead, use SettingsDialog and/or SettingsTab which interit from this and
    are proper QObject subclasses.

    Also call __init__ on the QObject/QWidget first before calling this
    class's __init__ method.'''
    # from base: settingsChanged = pyqtSignal(dict)
    # from base: statusChanged = pyqtSignal(dict)
    formChanged = pyqtSignal()

    _DEFAULT_HOST_SUBSTR = "shuffle.servo.cash"  # on fresh install, prefer this server as default (substring match)

    def __init__(self, config, message=None):
        assert config
        assert isinstance(self, QWidget)
        self.config = config
        self.networkChecker = None
        self.serverOk = None
        self._vpLastStatus = dict()
        self.setup(message)

        #DEBUG
        destroyed_print_error(self)

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
        selIdx, defIdx = (-1,)*2
        self.cb.clear()
        for host, d0 in sorted(servers.items()):
            d = d0.copy()
            d['server'] = host
            item = _elide(host) + (' [ssl]' if d['ssl'] else '')
            self.cb.addItem(item, d)
            if selected and selected == d:
                selIdx = self.cb.count()-1
            elif defIdx < 0 and self._DEFAULT_HOST_SUBSTR in host:
                defIdx = self.cb.count()-1

        self.cb.addItem(_("(Custom)"))
        if selIdx > -1:
            self.cb.setCurrentIndex(selIdx)
        elif selected and len(selected) == 3:
            custIdx = self.cb.count()-1
            self.cb.setItemData(custIdx, selected.copy())
            self.cb.setCurrentIndex(custIdx)
        elif defIdx > -1:
            self.cb.setCurrentIndex(defIdx)

    def refreshFromSettings(self):
        selected = Plugin.get_and_validate_network_settings(self.config)
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
        vbox2 = QVBoxLayout(self.statusGB)
        self.statusLabel = QLabel("", self.statusGB)
        self.statusLabel.setMinimumHeight(50)
        self.statusLabel.setAlignment(Qt.AlignAbsolute|Qt.AlignTop)
        vbox2.addWidget(self.statusLabel)

        # add the "Coin selection settings..." link
        self.coinSelectionSettingsLabel = QLabel("<a href='dummy'>{}</a>".format(_("Coin selection settings...")))
        self.coinSelectionSettingsLabel.linkActivated.connect(self.onCoinSelectionSettingsClick)
        vbox.addWidget(self.coinSelectionSettingsLabel)

        self.vbox = vbox

        if not isinstance(self, SettingsTab):
            # add close button only if not SettingsTab
            vbox.addStretch()
            buttons = Buttons(CloseButton(self), OkButton(self))
            vbox.addLayout(buttons)

        # NEW! add the "View pools..." button to the bottom
        vbox = self.statusGB.layout()
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        self.poolsBut = QPushButton(_("View pools..."))
        f = self.poolsBut.font(); f.setPointSize(f.pointSize()-(2 if sys.platform=='darwin' else 1)); self.poolsBut.setFont(f)
        hbox.addWidget(self.poolsBut)
        hbox.addStretch(1)
        vbox.addLayout(hbox)
        self.statusChanged.connect(self._vpGotStatus)
        self.poolsBut.setEnabled(False)
        self.poolsBut.clicked.connect(self._vpOnPoolsBut, Qt.DirectConnection)

    def kill(self):
        self.stopNetworkChecker()

    def onCoinSelectionSettingsClick(self, ignored):
        win = CoinSelectionSettingsWindow()
        win.exec_()
        win.deleteLater()
        if self.window().isVisible():
            self.window().raise_()
            self.activateWindow()

    def _vpGotStatus(self, sdict):
        self._vpLastStatus = sdict.copy()
        if sdict.get('status') in (_("Ok"), _("Banned")):
            self.poolsBut.setEnabled(True)
        else:
            self.poolsBut.setEnabled(False)

    def _vpOnPoolsBut(self):
        w = PoolsWinMgr.show(self._vpLastStatus, self.get_form(), self.config, modal=True)

    def _on_statusChanged(self, d):
        red, blue, green = "red", "blue", "green"
        try: red, blue, green = ColorScheme.RED._get_color(0), ColorScheme.BLUE._get_color(0), ColorScheme.GREEN._get_color(0)
        except AttributeError: pass
        #self.print_error("status changed", d)
        if not d: # Empty dict means we are connecting
            self.serverOk = None
            self.statusLabel.setText("<font color=\"{}\"><i>{}</i></font>".format(blue, _("Checking server...")))
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
            self.statusLabel.setText("<b>" + _("Status") + ":</b> <font color=\"{}\">{}</font>".format(red, reason))
            self.serverOk = False
            return

        # any other case has all the below keys defined

        self.serverOk = d['status'] == _('Ok')

        self.statusLabel.setText(
            '''
            <b>{}:</b> <i>{}</i><br>
            <b>{}:</b> <font color="{}">{}</font> {} &nbsp;&nbsp;&nbsp;{}
            <small>{}: {} &nbsp;&nbsp;&nbsp; {}: {} &nbsp;&nbsp;&nbsp; {}: {}</small>
            '''
            .format(_('Server'), _elide(d['host'], maxlen=40, startlen=12),
                    _('Status'), green if not d['banned'] else "#dd4444", d['status'], "&nbsp;&nbsp;<b>{}</b> {}".format(_("Ban score:"),d['banScore']) if d['banScore'] else '', '<br>' if d['banScore'] else '',
                    _('Pool size'), d['poolSize'],
                    _('Connections'),
                    d['connections'],
                    _('Active pools'), d['pools'])
        )

    def _on_formChange(self):
        try:
            #self.print_error("onFormChange")
            d = self.get_form()
            self.settingsChanged.emit(d)
        except RuntimeError as e:
            # Paranoia guard against C++ object deleted exception
            # (we may get called from a QTimer.singleShot below)
            if 'C++' not in str(e).upper():
                raise

    def startNetworkChecker(self):
        if self.networkChecker: return

        self.networkChecker = NetworkChecker(self)
        self.statusChanged.connect(self._on_statusChanged, Qt.QueuedConnection)
        self.formChanged.connect(self._on_formChange, Qt.QueuedConnection)
        self.print_error("Starting network checker...")
        self.networkChecker.start()
        QTimer.singleShot(100, self._on_formChange)  # kicks off the network checker by sending it new settings

    def stopNetworkChecker(self):
        if self.networkChecker:
            try: self.statusChanged.disconnect(self._on_statusChanged)
            except TypeError: pass  # not connected
            try: self.statusChanged.disconnect(self._on_formChange)
            except TypeError: pass  # not connected
            self.networkChecker.stop()
            self.networkChecker = None
            self.print_error("Stopped network checker.")
    # /
# /SettingsDialogMixin
class SettingsDialog(SettingsDialogMixin, AppModalDialog):
    ''' Concrete class for the stand-alone Settings window you get when
    you right-click and get "CashShuffle Settings..." from the CashShuffle status
    button context menu '''
    def __init__(self, title, config, message=None, windowFlags=None):
        AppModalDialog.__init__(self, title=title, windowFlags=windowFlags, parent=None)
        self.setMinimumSize(400, 350)
        SettingsDialogMixin.__init__(self, config=config, message=message)
# /SettingsDialog
class SettingsTab(SettingsDialogMixin, QWidget):
    # Apparently if you inherit from a C++ object first it creates problems.
    # You are supposed to inherit from the mixins in Python first, then the
    # Qt C++ object last. Who knew. All of Electron Cash codebase apparently
    # is doing it wrong.
    # See this: http://python.6.x6.nabble.com/Issue-with-multiple-inheritance-td5207771.html
    # So we inherit from our mixin first. (Note I had problems with overriding
    # __init__ here and Qt's C++ calling the wrong init here.)
    applyChanges = pyqtSignal(object)

    def __init__(self, parent, config, message=None):
        QWidget.__init__(self, parent=parent)
        SettingsDialogMixin.__init__(self, config=config, message=message)
        # add the "Apply" button to the bottom
        self.apply = QPushButton(_("Apply"), self)
        hbox = QHBoxLayout()
        self.vbox.addLayout(hbox)
        self.vbox.addStretch()
        hbox.addStretch(1)
        hbox.addWidget(self.apply)
        self.apply.clicked.connect(self._re_emit_applyChanges)

    def _re_emit_applyChanges(self):
        self.applyChanges.emit(self)

    def _vpOnPoolsBut(self):
        w = PoolsWinMgr.show(self._vpLastStatus, self.get_form(), self.config, modal=False, parent_window=self)
# /SettingsTab

class NetworkChecker(PrintError):
    ''' Runs in a separate thread, checks the server automatically when the settings form changes
        and publishes results to GUI thread. '''
    pollTimeSecs = 15.0
    checkShufflePort = True
    verifySSL = True  # if true, verify the ssl socket of the shuffle port when checking the server

    def __init__(self, parent):
        assert isinstance(parent, NetworkCheckerDelegateMixin), "Parent to NetworkChecker must be a NetworkCheckerDelegateMixin"
        self.weakParent = Weak.ref(parent)
        self.q = queue.Queue()
        self.thread = threading.Thread(target=self.thread_func, daemon=True)
        self._please_stop = False
        self._sock = None
        self._update_ct = 0
        parent.settingsChanged.connect(self._on_settings_changed, Qt.QueuedConnection)
        self.print_error("created")
        finalization_print_error(self)

    def stop(self):
        if self.thread.is_alive():
            self._please_stop = True
            self.q.put(None)    # signal to thread to die
            try: self._sock.close() # force close thread
            except: pass
            self.thread.join(timeout=15.0)  # wait for thread to finish
            if self.thread.is_alive():
                # This should never happen
                self.print_error("*** WARNING: Waited for thread to exit for 15.0 seconds, but it is still running! FIXME!")

    def start(self):
        if not self.thread.is_alive():
            self.q.put(None)  # paranoia just in case
            self.q = queue.Queue()  # clear the queue
            self._please_stop = False
            self.thread.start()  # this raises RuntimeError if called more than once.

    def _on_settings_changed(self, d):
        self._update_ct = 0  # reset ctr for these settings.  ctr = 0 causes us to tell gui to draw the "Connecting, please wait..." text
        self.q.put(d.copy())  # notify thread which waits on this q

    def _wait_drain_q(self, last_settings):
        q = self.q
        try:
            res = None
            try:
                # Drain queue to get latest settings
                while True:
                    # keep reading from the queue until it's empty
                    res = q.get_nowait()
                    if res is None:
                        # we got a None, return early -- this indicates abort thread
                        return res
            except queue.Empty:
                ''' No settings were waiting in queue.. move to blocking
                operation '''
            if self._please_stop:
                return # indicate stop
            if res is not None:
                # we had a result, return
                return res
            # no result from Queue, block for pollTimeSecs
            return q.get(timeout=self.pollTimeSecs)
        except queue.Empty:
            # no result in pollTimeSecs, return last settings value
            return last_settings

    def thread_func(self):
        try:
            self.print_error("thread entered")
            settings = dict()
            while True:
                settings = self._wait_drain_q(settings)
                if settings is None:
                    return  # exit thread if we got a None
                if settings:
                    self._on_update_status(settings)
        finally:
            self.print_error("thread exiting")

    def _emit_status_changed(self, d):
        self.weakParent() and self.weakParent().statusChanged.emit(d)

    def _on_update_status(self, d):
        d = d.copy()
        #self.print_error("updateStatus", d) # XXX
        is_bad_server, is_bad_ssl, is_offline_mode = False, False, False
        try:
            if not Network.get_instance():
                is_offline_mode = True
                raise RuntimeError("No network")

            if self._update_ct == 0:
                self._emit_status_changed(dict())  # tells GUI we are "connecting..."
            self._update_ct += 1

            port, poolSize, connections, pools, banScore, banned = query_server_for_stats(d['server'], d['info'], d['ssl'])

            if self._please_stop:
                return

            if poolSize < 3:
                # hard-coded -- do not accept servers with poolSize < 3
                is_bad_server = True
                raise RuntimeError("PoolSize must be >=3, got: {}".format(poolSize))
            if d['ssl'] and self.verifySSL and not verify_ssl_socket(d['server'], int(port), timeout=7.5):
                is_bad_ssl = True
                raise RuntimeError("Could not verify SSL server certificate.")

            if self._please_stop:
                return

            if self.checkShufflePort:
                self._sock = socket.create_connection((d['server'], port), 5.0) # test connectivity to port
                self._sock.close()
                self._sock = None

            if self._please_stop:
                return

            self._emit_status_changed({
                'host'   : d['server'],
                'status' : _('Ok') if not banned else _('Banned'),
                'poolSize' : str(poolSize),
                'connections' : str(connections),
                'pools' : str(len(pools)),
                'poolsList' : pools,
                'banScore' : banScore,
                'banned' : banned,
                'name' : d['server'] + ":" + str(d['info']),
                'info' : d['info'],
                'ssl'  : d['ssl'],
            })
        except Exception as e:
            # DEBUG
            #import traceback
            #traceback.print_exc()
            # /DEBUG
            self.print_error("exception on connect:",str(e))
            if is_offline_mode:
                self._emit_status_changed({'failed' : 'offline_mode'})
            elif is_bad_ssl:
                self._emit_status_changed({'failed' : 'ssl'})
            elif is_bad_server:
                self._emit_status_changed({'failed' : 'bad'})
            else:
                self._emit_status_changed({'failed' : 'failed'})
# / NetworkChecker

class PoolsWinMgr(QObject, PrintError):
    simpleChangedSig = pyqtSignal()

    _instance = None
    def __init__(self):
        assert not PoolsWinMgr._instance, "More than 1 PoolsWinMgr instance detected -- PoolsWinMgr is a singleton!"
        super().__init__()
        PoolsWinMgr._instance = self
        self.poolWindows = {}
        self.print_error("created")
        #DEBUG
        destroyed_print_error(self)
    def __del__(self):
        stale = True
        if PoolsWinMgr._instance is self:
            PoolsWinMgr._instance = None
            stale = False
        print_error("[{}] finalized{}".format(__class__.__name__, " (stale instance)" if stale else ''))
        if hasattr(super(), '__del__'):
            super().__del__()
    #public methods
    @classmethod
    def instance(cls, create_if_missing=True):
        if not cls._instance and create_if_missing:
            cls._instance = cls()
        return cls._instance
    @classmethod
    def killInstance(cls):
        if cls._instance:
            cls._instance._killAll()
            cls._instance.deleteLater()
            cls._instance = None
    @classmethod
    def closeAll(cls):
        ''' This implicitly will also delete all the windows when event loop next runs. '''
        app = QApplication.instance()
        if app:
            poolWins = [w for w in app.topLevelWidgets() if isinstance(w, PoolsWindow)]
            for w in poolWins:
                w.close()
    @classmethod
    def show(cls, stats_dict, network_settings, config, *, parent_window=None, modal=False):
        mgr = cls.instance()
        return mgr._createOrShow(stats_dict, network_settings, config, parent_window=parent_window, modal=modal)
    #private methods
    def _createOrShow(self, stats_dict, network_settings, config, *, parent_window=None, modal=False):
        d = stats_dict
        if not isinstance(d, dict) or not d or not network_settings:
            self.print_error("createOrShow: got invalid args.. will not create/show a window")
            return
        name = d['name']
        w = self.poolWindows.get(name)
        if w and ((modal and w.windowModality() != Qt.ApplicationModal)
                  or (not modal and w.windowModality() != Qt.NonModal)):
            self.print_error("Found extant window {} but modal spec != extant modal, killing...".format(name))
            self._kill(name)
            w = None
        if not w:
            self.print_error("Creating", name)
            w = PoolsWindow(config, parent_window, d, network_settings, modal=modal)
            self.poolWindows[name] = w
            w.closed.connect(self._kill) # clean-up instance
        else:
            self.print_error("Updating", name)
            w.weakParent = Weak.ref(parent_window) if parent_window else None
            w.settings = network_settings
            w.settingsChanged.emit(w.settings)
        if w.isMinimized():
            w.showNormal()
        w.show(); w.raise_(); w.activateWindow()
        return w
    def _kill(self, name):
        window = self.poolWindows.pop(name) # will actually delete the QWidget instance.
        window.stopNetworkChecker()
        window.deleteLater() # force Qt delete. This call may be superfluous
        self.print_error("Killed", name)
    def _killAll(self):
        for n in self.poolWindows.copy():
            self._kill(n)
# /PoolsWinMgr

class PoolsWindow(QWidget, PrintError, NetworkCheckerDelegateMixin):
    closed = pyqtSignal(str)
    # from base: settingsChanged = pyqtSignal(dict)
    # from base: statusChanged = pyqtSignal(dict)

    def __init__(self, config, pseudo_parent, serverDict, settings, modal=False):
        super().__init__()  # top-level window
        self.setWindowModality(Qt.ApplicationModal if modal else Qt.NonModal)
        self.config = config
        self.weakParent = Weak.ref(pseudo_parent) if pseudo_parent else None
        self.sdict = serverDict.copy()
        self.settings = settings
        self.networkChecker = None
        self.needsColumnSizing = True
        name = self.sdict['name']
        self.setObjectName(name)
        self.setWindowTitle("CashShuffle - {} - Pools".format(_elide(name)))
        self.vbox = QVBoxLayout(self)
        # pools group box
        self.poolsGB = QGroupBox(_("{} Pools").format(_elide(name)) + " (0)")
        self.vbox.addWidget(self.poolsGB)
        self.vbox.setStretchFactor(self.poolsGB, 2)
        vbox2 = QVBoxLayout(self.poolsGB)
        # ban label
        self.banLabel = HelpLabel('', _("Bans usually occur when other shufflers detected invalid inputs coming from your client. Bans are temporary and usually last up to 30 minutes.\n\nThey may happen occasionally in rare circumstances. However, if this keeps happening please contact the developers and file a bug report."))
        self.banLabel.setHidden(True)
        vbox2.addWidget(self.banLabel)
        self.tree = QTreeWidget()
        self.tree.setSelectionMode(QAbstractItemView.NoSelection)
        self.tree.setMinimumHeight(50)
        self.tree.setHeaderItem(QTreeWidgetItem([_('Tier'), _('Players'), _('Type'), _('Version'), _('Full')]))
        vbox2.addWidget(self.tree)
        # The "simple view" checkbox
        hbox = QHBoxLayout()
        self.simpleChk = QCheckBox(_("Omit incompatible pools"))  # NB: checkbox state will be set in self.refresh()
        hbox.addWidget(self.simpleChk)
        vbox2.addLayout(hbox)
        # bottom buts
        self.vbox.addStretch()
        hbox = QHBoxLayout()
        self.closeBut = QPushButton(_("Close"))
        hbox.addStretch(1)
        hbox.addWidget(self.closeBut)
        self.vbox.addLayout(hbox)
        # signals
        self.closeBut.clicked.connect(self.close)
        self.closeBut.setDefault(True)
        self.statusChanged.connect(self.refresh)
        self.simpleChk.clicked.connect(self._setSimple)
        # NB: some signal/slot connections are also made in showEvent()
        # etc...
        self.resize(400,300)
        #DEBUG
        destroyed_print_error(self)
    def diagnostic_name(self):
        return "{}/{}".format(super().diagnostic_name(), self.objectName())
    def closeEvent(self, e):
        #self.print_error("Close")
        self.closed.emit(self.objectName())
        parent = self.weakParent and self.weakParent()
        if isinstance(parent, QWidget) and parent.isVisible() and parent.window().isVisible():
            try:
                # for some reason closing this dialog raises the wallet window and not the network dialog
                # activate the network dialog if it's up..
                parent.window().activateWindow()
            except RuntimeError as e:
                # Deal with wrapped C/C++ object deleted. For some reason
                # the weakRef is still alive even after C/C++ deletion
                # (and no other references referencing the object!).
                if 'C++' in str(e):
                    self.print_error("Underlying C/C++ object deleted. Working around PyQt5 bugs and ignoring...")
                else:
                    raise
        super().closeEvent(e)
        e.accept()
    def hideEvent(self, e):
        super().hideEvent(e)
        if e.isAccepted():
            #self.print_error("Hide")
            try: PoolsWinMgr.instance().simpleChangedSig.disconnect(self._simpleChangedSlot)
            except TypeError: pass  # Not connected.
            self.stopNetworkChecker()
    def showEvent(self, e):
        super().showEvent(e)
        if e.isAccepted():
            #self.print_error("Show")
            PoolsWinMgr.instance().simpleChangedSig.connect(self._simpleChangedSlot)
            self.refresh(self.sdict)
            self.startNetworkChecker()
            # do stuff related to refreshing, etc here...
    def _isSimple(self):
        return bool(self.config.get(ConfKeys.Global.VIEW_POOLS_SIMPLE, True))
    def _setSimple(self, b):
        b = bool(b)
        if b != self._isSimple():
            self.config.set_key(ConfKeys.Global.VIEW_POOLS_SIMPLE, b)
            self.needsColumnSizing = True
            PoolsWinMgr.instance().simpleChangedSig.emit()
    def _simpleChangedSlot(self):
        self.refresh(self.sdict)
    def refresh(self, sdict):
        # NB: sdict may be non-empty (has actual results) but still contain no
        # pools if server has no pools. It's only empty before we get a response
        # from stats port.
        if not sdict:
            return
        if self.sdict is not sdict:
            self.sdict = sdict.copy()
        simple = self._isSimple()
        self.simpleChk.setChecked(simple)
        mysettings = BackgroundShufflingThread.latest_shuffle_settings
        # handle if we detected a ban
        if self.sdict.get('banned'):
            banScore = self.sdict.get('banScore') or 0
            self.banLabel.setText('<font color="#dd4444"><b>{}</b></font> (ban score: {})'.format(_("Banned"), banScore))
            self.banLabel.setHidden(False)
        else:
            self.banLabel.setHidden(True)
        pools = self.sdict.get('poolsList', list()).copy()
        poolSize = str(self.sdict.get('poolSize', ''))
        self.tree.clear()
        try:
            pools.sort(reverse=True, key=lambda x:(0 if x['full'] else 1, x['amount'], x['members'], -x.get('version',0)))
        except (KeyError, ValueError, TypeError):
            # hmm. Pools dict is missing or has bad keys. Assume bad input. Clear list and proceed with a 'no pools' message
            pools = []
        for c in range(2,4):
            self.tree.setColumnHidden(c, simple)
        def grayify(twi):
            b = twi.foreground(0)
            b.setColor(Qt.gray)
            for i in range(twi.columnCount()):
                twi.setForeground(i, b)
        for p in pools:
            typ, version = p.get('type', mysettings.type_name), p.get('version', mysettings.version)
            is_my_settings = typ == mysettings.type_name and version == mysettings.version
            if not simple or is_my_settings:
                twi = QTreeWidgetItem([
                    format_satoshis_plain(p['amount']) + " BCH",
                    "{} / {}".format(str(p['members']), poolSize),
                    str(p.get('type','?')).lower(),
                    str(p.get('version','?')),
                    "√" if p['full'] else '-',
                ])
                if not is_my_settings:
                    grayify(twi)
                self.tree.addTopLevelItem(twi)

        tit = self.poolsGB.title().rsplit(' ', 1)[0]
        self.poolsGB.setTitle(tit + " ({})".format(self.tree.topLevelItemCount()))

        def sizeColumnsToFit():
            for i in range(self.tree.columnCount()):
                self.tree.resizeColumnToContents(i)

        if not self.tree.topLevelItemCount():
            twi = QTreeWidgetItem([_('No Pools'), '', '', '', ''])
            f = twi.font(0); f.setItalic(True); twi.setFont(0, f)
            self.tree.addTopLevelItem(twi)
            self.tree.setFirstItemColumnSpanned(twi, True)
            self.tree.setHeaderHidden(True)
            sizeColumnsToFit()  # in no pools mode we unconditionally size to fit
            self.needsColumnSizing = True  # once we enter this "No pools.." mode, we need to force resize columns next time we have real entries to avoid layout weirdness
        else:
            self.tree.setHeaderHidden(False)
            if self.needsColumnSizing:  # this flag suppresses resizing each refresh to allow users to manually size the columns after a display with real data appears.
                sizeColumnsToFit()
                self.needsColumnSizing = False
    def _kick_off_nc(self):
        try:
            self.settingsChanged.emit(self.settings) # kicks off the NetworkChecker by sending it some server settings to check
        except RuntimeError:
            pass  # paranoia: guard against wrapped C++ object exception.. shouldn't happen because timer was keyed off this object as receiver
    def startNetworkChecker(self):
        if self.networkChecker: return
        self.networkChecker = nc = NetworkChecker(self)
        nc.pollTimeSecs, nc.verifySSL, nc.checkShufflePort = 2.0, False, False
        self.print_error("Starting network checker...")
        self.networkChecker.start()
        QTimer.singleShot(500, self._kick_off_nc)  # despite appearances timer will not fire after object deletion due to PyQt5 singal/slot receiver rules
    def stopNetworkChecker(self):
        if self.networkChecker:
            self.networkChecker.stop() # waits for network checker to finish...
            self.networkChecker = None
            self.print_error("Stopped network checker.")
# /PoolsWindow

class CoinSelectionSettingsWindow(AppModalDialog, PrintError):
    ''' The pop-up window to manage minimum/maximum coin amount settings.
    Accessible from a link in the "CashShuffle Settings.." window or Network
    Dialog tab. '''
    def __init__(self, title=None):
        super().__init__(title=title or _("CashShuffle - Coin Selection Settings"), parent=None)
        vbox = QVBoxLayout(self)
        lbl = QLabel(_("Specify minimum and maximum coin amounts to select for shuffling:"))
        lbl.setWordWrap(True)
        vbox.addWidget(lbl)

        hbox = QHBoxLayout()
        hbox.addWidget(HelpLabel(_("Minimum coin:"),
                                 _("Coins (UTXOs) below this amount will not be selected for shuffling.")))
        self.minEdit = BTCAmountEdit(decimal_point=self._decimal_point,
                                     parent=self)
        hbox.addWidget(self.minEdit)
        vbox.addLayout(hbox)
        hbox = QHBoxLayout()
        hbox.addWidget(HelpLabel(_("Maximum coin:"),
                                 _("Coins (UTXOs) up to this amount will be selected for shuffling.")))
        self.maxEdit = BTCAmountEdit(decimal_point=self._decimal_point,
                                     parent=self)
        hbox.addWidget(self.maxEdit)
        vbox.addLayout(hbox)

        self.maxEdit.textEdited.connect(self.clearErr)
        self.minEdit.textEdited.connect(self.clearErr)

        vbox.addStretch()
        self.errLabel = QLabel("")
        self.errLabel.setAlignment(Qt.AlignCenter)
        vbox.addWidget(self.errLabel)

        vbox.addStretch()
        vbox.addLayout(Buttons(CancelButton(self),
                               EnterButton(_("Defaults"), self.default),
                               EnterButton(_("Apply"), self.apply),
                               ))
        self.resize(320,200)
        self.fromConfig()
        # DEBUG Qt destruction
        destroyed_print_error(self)

    def _decimal_point(self): return get_config().get('decimal_point', 8)

    def _fmt_amt(self, amt): return format_satoshis_plain(amt, self._decimal_point())

    def apply(self):
        lower, upper = self.minEdit.get_amount(), self.maxEdit.get_amount()
        if not lower or not upper or upper <= lower:
            self.setErr(_("Invalid amount"))
            return
        hard_upper = BackgroundShufflingThread.hard_upper_bound()
        if upper > hard_upper:
            self.setErr(_("Upper limit is {}").format(self._fmt_amt(hard_upper)))
            return
        hard_lower = BackgroundShufflingThread.hard_lower_bound()
        if lower < hard_lower:
            self.setErr(_("Lower limit is {}").format(self._fmt_amt(hard_lower)))
            return
        if (lower, upper) != tuple(BackgroundShufflingThread.update_lower_and_upper_bound_from_config()):
            pre = ''
            if (lower, upper) == self._get_defaults():
                BackgroundShufflingThread.reset_lower_and_upper_bound_to_defaults()
                pre = _("Default values restored.\n\n")
            else:
                actual_lower, actual_upper = BackgroundShufflingThread.set_lower_and_upper_bound(lower, upper)
                if (lower, upper) != (actual_lower, actual_upper):
                    pre = _("Actual amounts applied: {} and {}.\n\n").format(self._fmt_amt(actual_lower),
                                                                            self._fmt_amt(actual_upper))

            self.show_message(pre+_("Changes will take effect when the next shuffle round starts (usually within in a few minutes)."))
        self.accept()

    def fromConfig(self):
        lower, upper = BackgroundShufflingThread.update_lower_and_upper_bound_from_config()
        self.minEdit.setAmount(lower)
        self.maxEdit.setAmount(upper)
        self.clearErr()

    def _get_defaults(self): return BackgroundShufflingThread.DEFAULT_LOWER_BOUND, BackgroundShufflingThread.DEFAULT_UPPER_BOUND

    def default(self):
        lower, upper = self._get_defaults()
        self.minEdit.setAmount(lower)
        self.maxEdit.setAmount(upper)
        self.clearErr()

    def setErr(self, txt='', noerr=False):
        txt = txt or ""
        if noerr:
            try: color = ColorScheme.DEFAULT._get_color(0)
            except AttributeError: color = "#666666"
        else:
            try: color = ColorScheme.RED._get_color(0)
            except AttributeError: color = "red"
        self.errLabel.setText('<font color="{}">{}</font>'.format(color, txt))

    def clearErr(self): self.setErr('', noerr=True)
# /CoinSelectionSettingsWindow
