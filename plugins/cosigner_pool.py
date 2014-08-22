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
from electrum.plugins import BasePlugin
from electrum.i18n import _

import sys
import traceback


PORT = 12344
HOST = 'ecdsa.net'
description = _("This plugin facilitates the use of multi-signatures wallets. It sends and receives partially signed transactions from/to your cosigner wallet. Transactions are encrypted and stored on a remote server.") 
server = xmlrpclib.ServerProxy('http://%s:%d'%(HOST,PORT), allow_none=True)


class Listener(threading.Thread):

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.daemon = True
        self.parent = parent
        self.key = None
        self.is_running = False
        self.message = None
        self.delete = False
 
    def set_key(self, key):
        self.key = key

    def clear(self):
        self.delete = True

    def run(self):
        self.is_running = True
        while self.is_running:

            if not self.key:
                time.sleep(2)
                continue

            if not self.message:
                try:
                    self.message = server.get(self.key)
                except Exception as e:
                    util.print_error("cannot contact cosigner pool")
                    time.sleep(30)
                    continue

                if self.message:
                    self.parent.win.emit(SIGNAL("cosigner:receive"))
            else:
                if self.delete:
                    # save it to disk
                    server.delete(self.key)
                    self.message = None
                    self.delete = False

            time.sleep(30)


class Plugin(BasePlugin):

    wallet = None
    listener = None

    def fullname(self):
        return 'Cosigner Pool'

    def description(self):
        return description

    def init(self):
        self.win = self.gui.main_window
        self.win.connect(self.win, SIGNAL('cosigner:receive'), self.on_receive)
        if self.listener is None:
            self.listener = Listener(self)
            self.listener.start()

    def enable(self):
        self.set_enabled(True)
        self.init()
        if self.win.wallet:
            self.load_wallet(self.win.wallet)
        return True

    def load_wallet(self, wallet):
        self.wallet = wallet
        mpk = self.wallet.get_master_public_keys()

        self.cold = mpk.get('x2')
        if self.cold:
            self.cold_K = bitcoin.deserialize_xkey(self.cold)[-1].encode('hex')
            self.cold_hash = bitcoin.Hash(self.cold_K).encode('hex')

        self.hot = mpk.get('x1')
        if self.hot:
            self.hot_K = bitcoin.deserialize_xkey(self.hot)[-1].encode('hex')
            self.hot_hash = bitcoin.Hash(self.hot_K).encode('hex')
            self.listener.set_key(self.hot_hash)


    def transaction_dialog(self, d):
        self.send_button = b = QPushButton(_("Send to cosigner"))
        b.clicked.connect(lambda: self.do_send(d.tx))
        d.buttons.insertWidget(2, b)
        self.transaction_dialog_update(d)


    def transaction_dialog_update(self, d):
        if d.tx.is_complete():
            self.send_button.hide()
            return
        if self.cosigner_can_sign(d.tx):
            self.send_button.show()
        else:
            self.send_button.hide()


    def cosigner_can_sign(self, tx):
        from electrum.transaction import x_to_xpub
        xpub_set = set([])
        for txin in tx.inputs:
            for x_pubkey in txin['x_pubkeys']:
                xpub = x_to_xpub(x_pubkey)
                if xpub:
                    xpub_set.add(xpub)

        return self.cold in xpub_set


    def do_send(self, tx):
        if not self.cosigner_can_sign(tx):
            return

        message = bitcoin.encrypt_message(tx.raw, self.cold_K)

        try:
            server.put(self.cold_hash, message)
            self.win.show_message("Your transaction was sent to the cosigning pool.\nOpen your cosigner wallet to retrieve it.")
        except Exception as e:
            self.win.show_message(str(e))


    def on_receive(self):

        if self.wallet.use_encryption:
            password = self.win.password_dialog('An encrypted transaction was retrieved from cosigning pool.\nPlease enter your password to decrypt it.')
            if not password:
                return
        else:
            password = None

        message = self.listener.message
        xpriv = self.wallet.get_master_private_key('x1/', password)
        if not xpriv:
            return
        try:
            k = bitcoin.deserialize_xkey(xpriv)[-1].encode('hex')
            EC = bitcoin.EC_KEY(k.decode('hex'))
            message = EC.decrypt_message(message)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.win.show_message(str(e))
            return

        self.listener.clear()

        tx = transaction.Transaction.deserialize(message)
        self.win.show_transaction(tx)



