#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2019 The Electron Cash Developers
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

import sys, traceback, queue
from xmlrpc.client import ServerProxy, Transport
import http.client

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electroncash import bitcoin, util, keystore
from electroncash import transaction
from electroncash.plugins import BasePlugin, hook
from electroncash.i18n import _
from electroncash.wallet import Multisig_Wallet
from electroncash.util import bh2u, bfh, Weak, InvalidPassword, print_error

from electroncash_gui.qt.transaction_dialog import show_transaction, TxDialog

# Workarounds to the fact that xmlrpc.client doesn't take a timeout= arg.
class TimeoutTransport(Transport):
    def __init__(self, timeout=2.0, *l, **kw):
        super().__init__(*l, **kw)
        self.timeout = timeout
    def make_connection(self, host):
        return http.client.HTTPConnection(host, timeout=self.timeout)
class TimeoutServerProxy(ServerProxy):
    def __init__(self, uri, timeout=2.0, *l, **kw):
        kw['transport'] = TimeoutTransport(timeout=timeout, use_datetime=kw.get('use_datetime', False))
        super().__init__(uri, *l, **kw)
# /end timeout= Workarounds

PORT = 8081
HOST = 'sync.imaginary.cash'


class Listener(util.DaemonThread):

    def __init__(self, state):
        super().__init__()
        self.daemon = True
        self.state_ref = Weak.ref(state)
        self.received = set()
        self.keyhashes = []
        self.timeoutQ = queue.Queue() # this queue's sole purpose is to provide an interruptible sleep

    def diagnostic_name(self):
        wname = str(self.state_ref() and self.state_ref().window_ref() and self.state_ref().window_ref().diagnostic_name())
        return super().diagnostic_name() + "@" + wname

    def set_keyhashes(self, keyhashes):
        self.keyhashes = keyhashes

    def clear(self, keyhash):
        state = self.state_ref()
        if state: state.server.delete(keyhash)
        try: self.received.remove(keyhash)
        except (ValueError, KeyError): pass

    def run(self):
        self.print_error("started.")
        while self.running:
            try:
                if not self.keyhashes:
                    self.timeoutQ.get(timeout=2.0) # this shouldn't ever happen but.. poll until ready.
                    continue
                for keyhash in self.keyhashes:
                    if keyhash in self.received:
                        # already seen.. avoids popup window spam
                        continue
                    try:
                        message = self.state_ref() and self.state_ref().server.get(keyhash)
                    except Exception as e:
                        self.print_error("cannot contact cosigner pool", repr(e))
                        break
                    if message:
                        self.received.add(keyhash)
                        self.print_error("received message for", keyhash)
                        self.state_ref() and self.state_ref().cosigner_receive_signal.emit(keyhash, message)
                # poll every 10 seconds
                self.timeoutQ.get(timeout=10.0)
            except queue.Empty:
                # timed out, continue
                continue
        self.print_error("exiting.")

    def stop(self):
        # extends DaemonThread by also writing to the timeoutQ to wake up the sleeping thread, if any
        super().stop()
        self.timeoutQ.put(None) # wake up sleeper, if any

    def start(self):
        # overrides DaemonThread -- clears queue on (re)start
        if not self.is_running():
            self.timeoutQ = queue.Queue() # clear queue in case it had stale data.
            super().start()

    def stop_join(self):
        self.stop()
        try: self.join()
        except RuntimeError: pass # was never started


class State(QObject):
    ''' Window-specific state. Gets inserted into cosigner_pool_state attribute
    for window. '''
    cosigner_receive_signal = pyqtSignal(object, object)
    listener = None
    keys = []
    cosigner_list = []
    plugin_ref = None # Weak.ref to plugin object
    window_ref = None # Weak.ref to window object
    server = None

    def __init__(self, plugin, window):
        super().__init__() # top-level QObject, no parent()
        self.server = TimeoutServerProxy('http://%s:%d'%(HOST,PORT), allow_none=True, timeout = 2.0)
        self.listener = Listener(self)
        self.plugin_ref = Weak.ref(plugin)
        self.window_ref = Weak.ref(window)
        self.cosigner_receive_signal.connect(self.on_receive)

    def on_receive(self, k, m):
        plugin = self.plugin_ref()
        window = self.window_ref()
        if plugin and window:
            plugin.on_receive(window, k, m)


class _Dead:
    pass

class Plugin(BasePlugin):

    Instance_ref = Weak.ref(_Dead()) # Make sure Instance_ref is always defined, defaults to dead object

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.windows = []
        self.initted = False

    @hook
    def init_qt(self, gui):
        if self.initted: return # already initted
        self.print_error("Initializing...")
        for window in gui.windows:
            self.on_new_window(window)
        Plugin.Instance_ref = Weak.ref(self)
        self.initted = True

    @hook
    def on_new_window(self, window):
        try: wallet = window.wallet
        except AttributeError:
            # this can happen if wallet is not started up properly
            self.print_error("WARNING: Window {} lacks a wallet -- startup race condition likely. FIXME!".format(window.diagnostic_name()))
            return
        if isinstance(wallet, Multisig_Wallet):
            window.cosigner_pool_state = state = State(self, window)
            self.windows.append(window)
            self.update(window)
            # un-gray-out buttons for tx dialogs left around related to this window
            for b in Plugin.get_all_cosigner_buttons():
                if b.wallet_ref() == wallet:
                    b.setEnabled(True)

    @hook
    def on_close_window(self, window):
        if window in self.windows:
            state = getattr(window, 'cosigner_pool_state', None)
            if state:
                if state.listener:
                    self.print_error("shutting down listener for",window.diagnostic_name())
                    state.listener.stop_join()
                state.deleteLater()
                delattr(window, 'cosigner_pool_state')
            self.print_error("unregistered for window",window.diagnostic_name())
            self.windows.remove(window)
            # gray out buttons for tx dialogs left around related to this window
            for b in Plugin.get_all_cosigner_buttons():
                if b.wallet_ref() == window.wallet:
                    b.setEnabled(False)

    @staticmethod
    def get_all_cosigner_buttons():
        ret = []
        app = QApplication.instance()
        for w in app.topLevelWidgets():
            if isinstance(w, TxDialog):
                but = getattr(w, 'cosigner_send_button', None)
                if but: ret.append(but)
        return ret

    def is_available(self):
        return True

    def on_close(self):
        for w in self.windows.copy():
            self.on_close_window(w)
        self.windows = []
        self.initted = False
        super().on_close()

    def update(self, window):
        wallet = window.wallet
        state = window.cosigner_pool_state
        if not state:
            self.print_error("No cosigner pool state object for window", window.diagnostic_name())
            return
        listener = state.listener
        state.keys = []
        state.cosigner_list = []
        for key, keystore in wallet.keystores.items():
            xpub = keystore.get_master_public_key()
            K = bitcoin.deserialize_xpub(xpub)[-1]
            _hash = bh2u(bitcoin.Hash(K))
            if not keystore.is_watching_only():
                state.keys.append((key, _hash))
            else:
                state.cosigner_list.append((xpub, K, _hash))
        listener.set_keyhashes([t[1] for t in state.keys])
        if not listener.is_running():
            self.print_error("Starting listener for", window.diagnostic_name())
            listener.start()

    @hook
    def transaction_dialog(self, d):
        window, state = self._find_window_and_state_for_wallet(d.wallet)
        if window and state:
            d.cosigner_send_button = b = QPushButton(_("Send to cosigner"))
            b.wallet_ref = Weak.ref(window.wallet)
            b.clicked.connect(lambda: Plugin.do_send_static(d))
            d.buttons.insert(0, b)
            self.transaction_dialog_update(d)

    @hook
    def transaction_dialog_update(self, d):
        window, state = self._find_window_and_state_for_wallet(d.wallet)
        but = getattr(d, 'cosigner_send_button', None)
        if not but or not window or not state or d.tx.is_complete() or d.wallet.can_sign(d.tx):
            but and but.hide()
            return
        for xpub, K, _hash in state.cosigner_list:
            if self.cosigner_can_sign(d.tx, xpub):
                but and but.show()
                break
        else:
            but and but.hide()

    def _find_window_and_state_for_wallet(self, wallet):
        for window in self.windows:
            if window.wallet == wallet:
                return window, window.cosigner_pool_state
        return None, None

    def cosigner_can_sign(self, tx, cosigner_xpub):
        from electroncash.keystore import is_xpubkey, parse_xpubkey
        xpub_set = set([])
        for txin in tx.inputs():
            for x_pubkey in txin['x_pubkeys']:
                if is_xpubkey(x_pubkey):
                    xpub, s = parse_xpubkey(x_pubkey)
                    xpub_set.add(xpub)
        return cosigner_xpub in xpub_set

    @staticmethod
    def do_send_static(d):
        ''' Decouples button slot from running instance in case user stops/restarts the plugin while TxDialogs are up. '''
        plugin = Plugin.Instance_ref()
        if plugin:
            plugin.do_send(d)
        else:
            print_error("[cosigner_pool] No plugin.")

    def do_send(self, d):
        tx = d.tx
        window, state = self._find_window_and_state_for_wallet(d.wallet)
        if not tx or not window or not state:
            self.print_error("Missing tx or window or state")
            return
        for xpub, K, _hash in state.cosigner_list:
            if not self.cosigner_can_sign(tx, xpub):
                continue
            message = bitcoin.encrypt_message(bfh(tx.raw), bh2u(K)).decode('ascii')
            try:
                state.server.put(_hash, message)
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                window.show_error(_("Failed to send transaction to cosigning pool."))
                return
            d.show_message(_("Your transaction was sent to the cosigning pool.") + '\n' +
                           _("Open your cosigner wallet to retrieve it."))

    def on_receive(self, window, keyhash, message):
        self.print_error("signal arrived for", keyhash, "@", window.diagnostic_name())
        state = getattr(window, 'cosigner_pool_state', None)
        if not state:
            self.print_error("Error: state object not found")
            return
        keys = state.keys
        for key, _hash in keys:
            if _hash == keyhash:
                break
        else:
            self.print_error("keyhash not found")
            return

        wallet = window.wallet
        if isinstance(wallet.keystore, keystore.Hardware_KeyStore):
            window.show_warning(_('An encrypted transaction was retrieved from cosigning pool.') + '\n' +
                                _('However, hardware wallets do not support message decryption, '
                                  'which makes them not compatible with the current design of cosigner pool.'))
            return
        password = None
        if wallet.has_password():
            password = window.password_dialog(_('An encrypted transaction was retrieved from cosigning pool.') + '\n' +
                                              _('Please enter your password to decrypt it.'))
            if not password:
                return
        else:
            details = (_("If you choose 'Yes', it will be decrypted and a transaction window will be shown, giving you the opportunity to sign the transaction.")
                       + "\n\n" + _("If you choose 'No', you will be asked again later (the next time this wallet window is opened)."))
            ret = window.msg_box(icon = QMessageBox.Question, parent = None, title=_("Cosigner Pool"), buttons=QMessageBox.Yes|QMessageBox.No,
                                 text = _("An encrypted transaction was retrieved from cosigning pool.") + '\n' + _("Do you want to open it now?"),
                                 detail_text = details)
            if ret != QMessageBox.Yes:
                return

        err, badpass = "Unknown Error", False
        try:
            xprv = wallet.keystore.get_master_private_key(password)
        except InvalidPassword as e:
            err, badpass = str(e), True
            xprv = None
        if not xprv:
            window.show_error(err)
            if badpass:
                self.on_receive(window, keyhash, message) # try again
            return
        try:
            k = bh2u(bitcoin.deserialize_xprv(xprv)[-1])
            EC = bitcoin.EC_KEY(bfh(k))
            message = bh2u(EC.decrypt_message(message))
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            window.show_error(repr(e))
            return

        state.listener.clear(keyhash)
        tx = transaction.Transaction(message)
        show_transaction(tx, window, prompt_if_unsaved=True)
