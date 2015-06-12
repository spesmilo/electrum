#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

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

from electrum_gui.qt import transaction_dialog

import sys
import traceback


PORT = 12344
HOST = 'ecdsa.net'
server = xmlrpclib.ServerProxy('http://%s:%d'%(HOST,PORT), allow_none=True)


class Listener(threading.Thread):

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.daemon = True
        self.parent = parent
        self.keyname = None
        self.keyhash = None
        self.is_running = False
        self.message = None

    def set_key(self, keyname, keyhash):
        self.keyname = keyname
        self.keyhash = keyhash

    def clear(self):
        server.delete(self.keyhash)
        self.message = None


    def run(self):
        self.is_running = True
        while self.is_running:
            if not self.keyhash:
                time.sleep(2)
                continue
            if not self.message:
                try:
                    self.message = server.get(self.keyhash)
                except Exception as e:
                    util.print_error("cannot contact cosigner pool")
                    time.sleep(30)
                    continue
                if self.message:
                    self.parent.win.emit(SIGNAL("cosigner:receive"))
            # poll every 30 seconds
            time.sleep(30)


class Plugin(BasePlugin):

    wallet = None
    listener = None

    @hook
    def init_qt(self, gui):
        self.win = gui.main_window
        self.win.connect(self.win, SIGNAL('cosigner:receive'), self.on_receive)

    def is_available(self):
        if self.wallet is None:
            return True
        return self.wallet.wallet_type in ['2of2', '2of3']

    @hook
    def load_wallet(self, wallet, window):
        self.wallet = wallet
        if not self.is_available():
            return
        if self.listener is None:
            self.listener = Listener(self)
            self.listener.start()
        self.cosigner_list = []
        for key, xpub in self.wallet.master_public_keys.items():
            K = bitcoin.deserialize_xkey(xpub)[-1].encode('hex')
            _hash = bitcoin.Hash(K).encode('hex')
            if self.wallet.master_private_keys.get(key):
                self.listener.set_key(key, _hash)
            else:
                self.cosigner_list.append((xpub, K, _hash))

    @hook
    def transaction_dialog(self, d):
        self.send_button = b = QPushButton(_("Send to cosigner"))
        b.clicked.connect(lambda: self.do_send(d.tx))
        d.buttons.insert(2, b)
        self.transaction_dialog_update(d)

    @hook
    def transaction_dialog_update(self, d):
        if d.tx.is_complete():
            self.send_button.hide()
            return
        for xpub, K, _hash in self.cosigner_list:
            if self.cosigner_can_sign(d.tx, xpub):
                self.send_button.show()
                break
        else:
            self.send_button.hide()

    def cosigner_can_sign(self, tx, cosigner_xpub):
        from electrum.transaction import x_to_xpub
        xpub_set = set([])
        for txin in tx.inputs:
            for x_pubkey in txin['x_pubkeys']:
                xpub = x_to_xpub(x_pubkey)
                if xpub:
                    xpub_set.add(xpub)

        return cosigner_xpub in xpub_set

    def do_send(self, tx):
        for xpub, K, _hash in self.cosigner_list:
            if not self.cosigner_can_sign(tx, xpub):
                continue
            message = bitcoin.encrypt_message(tx.raw, K)
            try:
                server.put(_hash, message)
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                self.win.show_message(str(e))
                return
        self.win.show_message("Your transaction was sent to the cosigning pool.\nOpen your cosigner wallet to retrieve it.")

    def on_receive(self):
        if self.wallet.use_encryption:
            password = self.win.password_dialog('An encrypted transaction was retrieved from cosigning pool.\nPlease enter your password to decrypt it.')
            if not password:
                return
        else:
            password = None
            if not self.win.question(_("An encrypted transaction was retrieved from cosigning pool.\nDo you want to open it now?")):
                return

        message = self.listener.message
        key = self.listener.keyname
        xprv = self.wallet.get_master_private_key(key, password)
        if not xprv:
            return
        try:
            k = bitcoin.deserialize_xkey(xprv)[-1].encode('hex')
            EC = bitcoin.EC_KEY(k.decode('hex'))
            message = EC.decrypt_message(message)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.win.show_message(str(e))
            return

        self.listener.clear()
        tx = transaction.Transaction(message)
        d = transaction_dialog.TxDialog(tx, self.win)
        d.saved = False
        d.show()
