import socket
import requests
import threading
import hashlib
import json

try:
    import PyQt4
except Exception:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui
import aes
import base64

import electrum_ltc as electrum
from electrum_ltc.plugins import BasePlugin, hook
from electrum_ltc.i18n import _

from electrum_ltc_gui.qt import HelpButton, EnterButton
from electrum_ltc_gui.qt.util import ThreadedButton, Buttons, CancelButton, OkButton

class Plugin(BasePlugin):

    target_host = 'sync.bytesized-hosting.com:9090'
    encode_password = None

    def version(self):
        return "0.0.1"

    def encode(self, message):
        encrypted = electrum.bitcoin.aes_encrypt_with_iv(self.encode_password, self.iv, message.encode('utf8'))
        encoded_message = base64.b64encode(encrypted)
        return encoded_message

    def decode(self, message):
        decoded_message = electrum.bitcoin.aes_decrypt_with_iv(self.encode_password, self.iv, base64.b64decode(message)).decode('utf8')
        return decoded_message

    def set_nonce(self, nonce):
        self.print_error("Set nonce to", nonce)
        self.wallet.storage.put("wallet_nonce", nonce, True)
        self.wallet_nonce = nonce

    @hook
    def init_qt(self, gui):
        self.window = gui.main_window
        self.window.connect(self.window, SIGNAL('labels:pulled'), self.on_pulled)

    @hook
    def load_wallet(self, wallet):
        self.wallet = wallet

        self.wallet_nonce = self.wallet.storage.get("wallet_nonce")
        self.print_error("Wallet nonce is", self.wallet_nonce)
        if self.wallet_nonce is None:
            self.set_nonce(1)

        mpk = ''.join(sorted(self.wallet.get_master_public_keys().values()))
        self.encode_password = hashlib.sha1(mpk).digest().encode('hex')[:32]
        self.iv = hashlib.sha256(self.encode_password).digest()[:16]
        self.wallet_id = hashlib.sha256(mpk).digest().encode('hex')

        addresses = []
        for account in self.wallet.accounts.values():
            for address in account.get_addresses(0):
                addresses.append(address)

        self.addresses = addresses

        # If there is an auth token we can try to actually start syncing
        def do_pull_thread():
            try:
                self.pull_thread()
            except Exception as e:
                self.print_error("could not retrieve labels:", e)
        t = threading.Thread(target=do_pull_thread)
        t.setDaemon(True)
        t.start()


    def is_available(self):
        return True

    def requires_settings(self):
        return True

    @hook
    def set_label(self, item,label, changed):
        if self.encode_password is None:
            return
        if not changed:
            return
        bundle = {"walletId": self.wallet_id, "walletNonce": self.wallet.storage.get("wallet_nonce"), "externalId": self.encode(item), "encryptedLabel": self.encode(label)}
        t = threading.Thread(target=self.do_request, args=["POST", "/label", False, bundle])
        t.setDaemon(True)
        t.start()
        self.set_nonce(self.wallet.storage.get("wallet_nonce") + 1)

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        d = QDialog()
        vbox = QVBoxLayout(d)
        layout = QGridLayout()
        vbox.addLayout(layout)

        layout.addWidget(QLabel("Label sync options: "),2,0)

        self.upload = ThreadedButton("Force upload", self.push_thread, self.done_processing)
        layout.addWidget(self.upload, 2, 1)

        self.download = ThreadedButton("Force download", lambda: self.pull_thread(True), self.done_processing)
        layout.addWidget(self.download, 2, 2)

        self.accept = OkButton(d, _("Done"))
        vbox.addLayout(Buttons(CancelButton(d), self.accept))

        if d.exec_():
            return True
        else:
            return False

    def on_pulled(self):
        wallet = self.wallet
        wallet.storage.put('labels', wallet.labels, True)
        self.window.labelsChanged.emit()

    def done_processing(self):
        QMessageBox.information(None, _("Labels synchronised"), _("Your labels have been synchronised."))

    def do_request(self, method, url = "/labels", is_batch=False, data=None):
        url = 'https://' + self.target_host + url
        kwargs = {'headers': {}}
        if method == 'GET' and data:
            kwargs['params'] = data
        elif method == 'POST' and data:
            kwargs['data'] = json.dumps(data)
            kwargs['headers']['Content-Type'] = 'application/json'
        response = requests.request(method, url, **kwargs)
        if response.status_code != 200:
            raise BaseException(response.status_code, response.text)
        response = response.json()
        if "error" in response:
            raise BaseException(response["error"])
        return response

    def push_thread(self):
        bundle = {"labels": [], "walletId": self.wallet_id, "walletNonce": self.wallet_nonce}
        for key, value in self.wallet.labels.iteritems():
            try:
                encoded_key = self.encode(key)
                encoded_value = self.encode(value)
            except:
                self.print_error('cannot encode', repr(key), repr(value))
                continue
            bundle["labels"].append({'encryptedLabel': encoded_value, 'externalId':  encoded_key})
        self.do_request("POST", "/labels", True, bundle)

    def pull_thread(self, force = False):
        wallet_nonce = 1 if force else self.wallet_nonce - 1
        self.print_error("Asking for labels since nonce", wallet_nonce)
        response = self.do_request("GET", ("/labels/since/%d/for/%s" % (wallet_nonce, self.wallet_id) ))
        result = {}
        if not response["labels"] is None:
            for label in response["labels"]:
                try:
                    key = self.decode(label["externalId"])
                    value = self.decode(label["encryptedLabel"])
                except:
                    continue
                try:
                    json.dumps(key)
                    json.dumps(value)
                except:
                    self.print_error('error: no json', key)
                    continue
                result[key] = value

            wallet = self.wallet
            if not wallet:
                return
            for key, value in result.items():
                if force or not wallet.labels.get(key):
                    wallet.labels[key] = value

            self.window.emit(SIGNAL('labels:pulled'))
            self.set_nonce(response["nonce"] + 1)
            self.print_error("received %d labels"%len(response))
