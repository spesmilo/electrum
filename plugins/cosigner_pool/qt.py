#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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

import socket
import threading
import time
import xmlrpclib

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from electrum import bitcoin, util
from electrum import transaction
from electrum.plugins import BasePlugin, hook
from electrum.i18n import _

from electrum_gui.qt.transaction_dialog import show_transaction

import sys
import traceback


PORT = 12344
HOST = 'ecdsa.net'
server = xmlrpclib.ServerProxy('http://%s:%d'%(HOST,PORT), allow_none=True)


class Listener(util.DaemonThread):

    def __init__(self, parent):
        util.DaemonThread.__init__(self)
        self.daemon = True
        self.parent = parent
        self.received = set()
        self.keyhashes = []

    def set_keyhashes(self, keyhashes):
        self.keyhashes = keyhashes

    def clear(self, keyhash):
        server.delete(keyhash)
        self.received.remove(keyhash)

    def run(self):
        while self.running:
            if not self.keyhashes:
                time.sleep(2)
                continue
            for keyhash in self.keyhashes:
                if keyhash in self.received:
                    continue
                try:
                    message = server.get(keyhash)
                except Exception as e:
                    self.print_error("cannot contact cosigner pool")
                    time.sleep(30)
                    continue
                if message:
                    self.received.add(keyhash)
                    self.print_error("received message for", keyhash)
                    self.parent.obj.emit(SIGNAL("cosigner:receive"), keyhash,
                                         message)
            # poll every 30 seconds
            time.sleep(30)


class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.listener = None
        self.obj = QObject()
        self.obj.connect(self.obj, SIGNAL('cosigner:receive'), self.on_receive)
        self.keys = []
        self.cosigner_list = []

    @hook
    def init_qt(self, gui):
        for window in gui.windows:
            self.on_new_window(window)

    @hook
    def on_new_window(self, window):
        self.update(window)

    @hook
    def on_close_window(self, window):
        self.update(window)

    def is_available(self):
        return True

    def update(self, window):
        wallet = window.wallet
        if wallet.wallet_type not in ['2of2', '2of3']:
            return
        if self.listener is None:
            self.print_error("starting listener")
            self.listener = Listener(self)
            self.listener.start()
        elif self.listener:
            self.print_error("shutting down listener")
            self.listener.stop()
            self.listener = None
        self.keys = []
        self.cosigner_list = []
        for key, keystore in wallet.keystores.items():
            xpub = keystore.get_master_public_key()
            K = bitcoin.deserialize_xkey(xpub)[-1].encode('hex')
            _hash = bitcoin.Hash(K).encode('hex')
            if wallet.master_private_keys.get(key):
                self.keys.append((key, _hash, window))
            else:
                self.cosigner_list.append((window, xpub, K, _hash))
        if self.listener:
            self.listener.set_keyhashes([t[1] for t in self.keys])

    @hook
    def transaction_dialog(self, d):
        d.cosigner_send_button = b = QPushButton(_("Send to cosigner"))
        b.clicked.connect(lambda: self.do_send(d.tx))
        d.buttons.insert(0, b)
        self.transaction_dialog_update(d)

    @hook
    def transaction_dialog_update(self, d):
        if d.tx.is_complete() or d.wallet.can_sign(d.tx):
            d.cosigner_send_button.hide()
            return
        for window, xpub, K, _hash in self.cosigner_list:
            if window.wallet == d.wallet and self.cosigner_can_sign(d.tx, xpub):
                d.cosigner_send_button.show()
                break
        else:
            d.cosigner_send_button.hide()

    def cosigner_can_sign(self, tx, cosigner_xpub):
        from electrum.keystore import is_xpubkey, parse_xpubkey
        xpub_set = set([])
        for txin in tx.inputs():
            for x_pubkey in txin['x_pubkeys']:
                if is_xpubkey(x_pubkey):
                    xpub, s = parse_xpubkey(x_pubkey)
                    xpub_set.add(xpub)
        return cosigner_xpub in xpub_set

    def do_send(self, tx):
        for window, xpub, K, _hash in self.cosigner_list:
            if not self.cosigner_can_sign(tx, xpub):
                continue
            message = bitcoin.encrypt_message(tx.raw, K)
            try:
                server.put(_hash, message)
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                window.show_message("Failed to send transaction to cosigning pool.")
                return
            window.show_message("Your transaction was sent to the cosigning pool.\nOpen your cosigner wallet to retrieve it.")

    def on_receive(self, keyhash, message):
        self.print_error("signal arrived for", keyhash)
        for key, _hash, window in self.keys:
            if _hash == keyhash:
                break
        else:
            self.print_error("keyhash not found")
            return

        wallet = window.wallet
        if wallet.use_encryption:
            password = window.password_dialog('An encrypted transaction was retrieved from cosigning pool.\nPlease enter your password to decrypt it.')
            if not password:
                return
        else:
            password = None
            if not window.question(_("An encrypted transaction was retrieved from cosigning pool.\nDo you want to open it now?")):
                return

        xprv = wallet.get_master_private_key(key, password)
        if not xprv:
            return
        try:
            k = bitcoin.deserialize_xkey(xprv)[-1].encode('hex')
            EC = bitcoin.EC_KEY(k.decode('hex'))
            message = EC.decrypt_message(message)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            window.show_message(str(e))
            return

        self.listener.clear(keyhash)
        tx = transaction.Transaction(message)
        show_transaction(tx, window, prompt_if_unsaved=True)
