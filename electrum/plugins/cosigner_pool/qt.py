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
import asyncio
import time
from xmlrpc.client import ServerProxy, Transport
from typing import TYPE_CHECKING, Union, List, Tuple, Dict
import ssl

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QPushButton
import certifi

from electrum import util, keystore, ecc, crypto
from electrum.transaction import Transaction, PartialTransaction, tx_from_any, SerializationError
from electrum.bip32 import BIP32Node
from electrum.plugin import BasePlugin, hook
from electrum.i18n import _
from electrum.wallet import Multisig_Wallet, Abstract_Wallet
from electrum.util import bfh, make_aiohttp_session
from electrum.logging import Logger
from electrum.network import Network

from electrum.gui.qt.transaction_dialog import show_transaction, TxDialog
from electrum.gui.qt.util import WaitingDialog

if TYPE_CHECKING:
    from electrum.gui.qt import ElectrumGui
    from electrum.gui.qt.main_window import ElectrumWindow


ca_path = certifi.where()
ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)


class XMLRPCProxyTransport(Transport):
    def request(self, host, handler, request_body, verbose=False):
        network = Network.get_instance()
        if network is None:
            return

        async def do_request(_host, _request_body):
            async with make_aiohttp_session(network.proxy) as session:
                async with session.post(f'https://{_host}', data=_request_body) as response:
                    response.raise_for_status()
                    p, u = self.getparser()
                    data = await response.read()
                    p.feed(data)
                    p.close()
                    return u.close()

        fut = asyncio.run_coroutine_threadsafe(do_request(host, request_body), network.asyncio_loop)
        return fut.result()


class Listener(util.DaemonThread):

    def __init__(self, cw: 'CosignerWallet'):
        util.DaemonThread.__init__(self)
        self.daemon = True
        self.cw = cw
        self.received = set()
        self.keyhashes = []

    def set_keyhashes(self, keyhashes):
        self.keyhashes = keyhashes

    def clear(self, keyhash):
        self.cw.cosigner_service.delete(keyhash)
        self.received.remove(keyhash)

    def run(self):
        while self.is_running():
            if not self.keyhashes:
                time.sleep(2)
                continue
            for keyhash in self.keyhashes:
                if keyhash in self.received:
                    continue
                try:
                    message = self.cw.cosigner_service.get(keyhash)
                except Exception as e:
                    self.logger.info(f"cannot contact cosigner pool. exc: {e!r}")
                    time.sleep(30)
                    continue
                if message:
                    self.received.add(keyhash)
                    self.logger.info(f"received message for {keyhash}")
                    self.cw.obj.cosigner_receive_signal.emit(keyhash, message)

            time.sleep(30)  # poll every 30 seconds


class QReceiveSignalObject(QObject):
    cosigner_receive_signal = pyqtSignal(object, object)


class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self._init_qt_received = False
        self.cosigner_wallets = {}  # type: Dict[Abstract_Wallet, CosignerWallet]

        transport = XMLRPCProxyTransport()
        self.cosigner_service = ServerProxy('https://cosigner.electrum.org/', transport, allow_none=True, context=ssl_context)

    @hook
    def init_qt(self, gui: 'ElectrumGui'):
        if self._init_qt_received:  # only need/want the first signal
            return
        self._init_qt_received = True
        for window in gui.windows:
            self.load_wallet(window.wallet, window)

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet', window: 'ElectrumWindow'):
        if type(wallet) != Multisig_Wallet:
            return
        self.cosigner_wallets[wallet] = CosignerWallet(wallet, self.cosigner_service, window)

    @hook
    def on_close_window(self, window):
        wallet = window.wallet
        if cw := self.cosigner_wallets.get(wallet):
            cw.close()
            self.cosigner_wallets.pop(wallet)

    def is_available(self):
        return True

    @hook
    def transaction_dialog(self, d: 'TxDialog'):
        if cw := self.cosigner_wallets.get(d.wallet):
            cw.hook_transaction_dialog(d)

    @hook
    def transaction_dialog_update(self, d: 'TxDialog'):
        if cw := self.cosigner_wallets.get(d.wallet):
            cw.hook_transaction_dialog_update(d)


class CosignerWallet(Logger):
    # one for each open window

    def __init__(self, wallet: 'Multisig_Wallet', cosigner_service: 'ServerProxy', window: 'ElectrumWindow'):
        assert isinstance(wallet, Multisig_Wallet)
        self.wallet = wallet
        self.window = window
        self.cosigner_service = cosigner_service
        Logger.__init__(self)
        self.obj = QReceiveSignalObject()
        self.obj.cosigner_receive_signal.connect(self.on_receive)

        self.keys = []  # type: List[Tuple[str, str]]
        self.cosigner_list = []  # type: List[Tuple[str, bytes, str]]
        for key, keystore in wallet.keystores.items():
            xpub = keystore.get_master_public_key()  # type: str
            pubkey = BIP32Node.from_xkey(xpub).eckey.get_public_key_bytes(compressed=True)
            _hash = crypto.sha256d(pubkey).hex()
            if not keystore.is_watching_only():
                self.keys.append((key, _hash))
            else:
                self.cosigner_list.append((xpub, pubkey, _hash))

        self.logger.info("starting listener")
        self.listener = Listener(self)
        self.listener.start()
        self.listener.set_keyhashes([t[1] for t in self.keys])

    def diagnostic_name(self):
        return self.wallet.diagnostic_name()

    def close(self):
        self.logger.info("shutting down listener")
        self.listener.stop()
        self.listener = None

    def hook_transaction_dialog(self, d: 'TxDialog'):
        d.cosigner_send_button = b = QPushButton(_("Send to cosigner"))
        b.clicked.connect(lambda: self.do_send(d.tx))
        d.buttons.insert(0, b)
        b.setVisible(False)

    def hook_transaction_dialog_update(self, d: 'TxDialog'):
        assert self.wallet == d.wallet
        if d.tx.is_complete() or d.wallet.can_sign(d.tx):
            d.cosigner_send_button.setVisible(False)
            return
        for xpub, K, _hash in self.cosigner_list:
            if self.cosigner_can_sign(d.tx, xpub):
                d.cosigner_send_button.setVisible(True)
                break
        else:
            d.cosigner_send_button.setVisible(False)

    def cosigner_can_sign(self, tx: Transaction, cosigner_xpub: str) -> bool:
        # TODO implement this properly:
        #      should return True iff cosigner (with given xpub) can sign and has not yet signed.
        #      note that tx could also be unrelated from wallet?... (not ismine inputs)
        return True

    def do_send(self, tx: Union[Transaction, PartialTransaction]):
        def on_success(result):
            self.window.show_message(_("Your transaction was sent to the cosigning pool.") + '\n' +
                                _("Open your cosigner wallet to retrieve it."))
        def on_failure(exc_info):
            e = exc_info[1]
            try: self.logger.error("on_failure", exc_info=exc_info)
            except OSError: pass
            self.window.show_error(_("Failed to send transaction to cosigning pool") + ':\n' + repr(e))

        buffer = []
        # construct messages
        for xpub, K, _hash in self.cosigner_list:
            if not self.cosigner_can_sign(tx, xpub):
                continue
            raw_tx_bytes = tx.serialize_as_bytes()
            public_key = ecc.ECPubkey(K)
            message = public_key.encrypt_message(raw_tx_bytes).decode('ascii')
            buffer.append((_hash, message))
        if not buffer:
            return

        # send messages
        # note: we send all messages sequentially on the same thread
        def send_messages_task():
            for _hash, message in buffer:
                self.cosigner_service.put(_hash, message)
        msg = _('Sending transaction to cosigning pool...')
        WaitingDialog(self.window, msg, send_messages_task, on_success, on_failure)

    def on_receive(self, keyhash, message):
        self.logger.info(f"signal arrived for {keyhash}")
        for key, _hash in self.keys:
            if _hash == keyhash:
                break
        else:
            self.logger.info("keyhash not found")
            return

        window = self.window
        wallet = self.wallet
        if isinstance(wallet.keystore, keystore.Hardware_KeyStore):
            window.show_warning(_('An encrypted transaction was retrieved from cosigning pool.') + '\n' +
                                _('However, hardware wallets do not support message decryption, '
                                  'which makes them not compatible with the current design of cosigner pool.'))
            return
        elif wallet.has_keystore_encryption():
            password = window.password_dialog(_('An encrypted transaction was retrieved from cosigning pool.') + '\n' +
                                              _('Please enter your password to decrypt it.'))
            if not password:
                return
        else:
            password = None
            if not window.question(_("An encrypted transaction was retrieved from cosigning pool.") + '\n' +
                                   _("Do you want to open it now?")):
                return

        xprv = wallet.keystore.get_master_private_key(password)
        if not xprv:
            return
        try:
            privkey = BIP32Node.from_xkey(xprv).eckey
            message = privkey.decrypt_message(message)
        except Exception as e:
            self.logger.exception('')
            window.show_error(_('Error decrypting message') + ':\n' + repr(e))
            return

        self.listener.clear(keyhash)
        try:
            tx = tx_from_any(message)
        except SerializationError as e:
            window.show_error(_("Electrum was unable to deserialize the transaction:") + "\n" + str(e))
            return
        show_transaction(tx, parent=window, prompt_if_unsaved=True)
