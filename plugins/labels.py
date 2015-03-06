from electrum.util import print_error

import httplib, urllib
import socket
import threading
import hashlib
import json
from urlparse import urlparse, parse_qs
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

import electrum
from electrum.plugins import BasePlugin, hook
from electrum.i18n import _

from electrum_gui.qt import HelpButton, EnterButton

class Plugin(BasePlugin):

    target_host = 'labelectrum.herokuapp.com'
    encode_password = None

    def fullname(self):
        return _('Label Sync')

    def description(self):
        return '%s\n\n%s%s%s' % (_("This plugin can sync your labels across multiple Electrum installs by using a remote database to save your data. Labels, transactions ids and addresses are encrypted before they are sent to the remote server. This code might increase the load of your wallet with a few microseconds as it will sync labels on each startup."), _("To get started visit"), " http://labelectrum.herokuapp.com/ ", _(" to sign up for an account."))

    def version(self):
        return "0.2.1"

    def encode(self, message):
        encrypted = electrum.bitcoin.aes_encrypt_with_iv(self.encode_password, self.iv, message.encode('utf8'))
        encoded_message = base64.b64encode(encrypted)
        return encoded_message

    def decode(self, message):
        decoded_message = electrum.bitcoin.aes_decrypt_with_iv(self.encode_password, self.iv, base64.b64decode(message)).decode('utf8')
        return decoded_message


    @hook
    def init_qt(self, gui):
        self.window = gui.main_window
        if not self.auth_token(): # First run, throw plugin settings in your face
            self.load_wallet(self.window.wallet)
            if self.settings_dialog():
                self.set_enabled(True)
                return True
            else:
                self.set_enabled(False)
                return False

    @hook
    def load_wallet(self, wallet):
        self.wallet = wallet
        mpk = ''.join(sorted(self.wallet.get_master_public_keys().values()))
        self.encode_password = hashlib.sha1(mpk).digest().encode('hex')[:32]
        self.iv = hashlib.sha256(self.encode_password).digest()[:16]
        self.wallet_id = hashlib.sha256(mpk).digest().encode('hex')

        addresses = [] 
        for account in self.wallet.accounts.values():
            for address in account.get_addresses(0):
                addresses.append(address)

        self.addresses = addresses

        if self.auth_token():
            # If there is an auth token we can try to actually start syncing
            threading.Thread(target=self.do_full_pull).start()

    def auth_token(self):
        return self.config.get("plugin_label_api_key")

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
        try:
            bundle = {"label": {"external_id": self.encode(item), "text": self.encode(label)}}
            params = json.dumps(bundle)
            connection = httplib.HTTPConnection(self.target_host)
            connection.request("POST", ("/api/wallets/%s/labels.json?auth_token=%s" % (self.wallet_id, self.auth_token())), params, {'Content-Type': 'application/json'})

            response = connection.getresponse()
            if response.reason == httplib.responses[httplib.NOT_FOUND]:
                return
            response = json.loads(response.read())
        except socket.gaierror as e:
            print_error('Error connecting to service: %s ' %  e)
            return False

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)

    def settings_dialog(self):
        def check_for_api_key(api_key):
            if api_key and len(api_key) > 12:
              self.config.set_key("plugin_label_api_key", str(self.auth_token_edit.text()))
              self.upload.setEnabled(True)
              self.download.setEnabled(True)
              self.accept.setEnabled(True)
            else:
              self.upload.setEnabled(False)
              self.download.setEnabled(False)
              self.accept.setEnabled(False)

        d = QDialog()
        layout = QGridLayout(d)
        layout.addWidget(QLabel("API Key: "),0,0)

        self.auth_token_edit = QLineEdit(self.auth_token())
        self.auth_token_edit.textChanged.connect(check_for_api_key)

        layout.addWidget(QLabel("Label sync options: "),2,0)
        layout.addWidget(self.auth_token_edit, 0,1,1,2)

        decrypt_key_text =  QLineEdit(self.encode_password)
        decrypt_key_text.setReadOnly(True)
        layout.addWidget(decrypt_key_text, 1,1)
        layout.addWidget(QLabel("Decryption key: "),1,0)
        layout.addWidget(HelpButton("This key can be used on the LabElectrum website to decrypt your data in case you want to review it online."),1,2)

        self.upload = QPushButton("Force upload")
        self.upload.clicked.connect(self.full_push)
        layout.addWidget(self.upload, 2,1)

        self.download = QPushButton("Force download")
        self.download.clicked.connect(self.full_pull)
        layout.addWidget(self.download, 2,2)

        c = QPushButton(_("Cancel"))
        c.clicked.connect(d.reject)

        self.accept = QPushButton(_("Done"))
        self.accept.clicked.connect(d.accept)

        layout.addWidget(c,3,1)
        layout.addWidget(self.accept,3,2)

        check_for_api_key(self.auth_token())

        self.window.labelsChanged.connect(self.done_processing)

        if d.exec_():
          return True
        else:
          return False

    def done_processing(self):
        QMessageBox.information(None, _("Labels synchronised"), _("Your labels have been synchronised."))

    def full_push(self):
        threading.Thread(target=self.do_full_push).start()

    def full_pull(self):
        threading.Thread(target=self.do_full_pull, args=([True])).start()

    def do_full_push(self):
        try:
            bundle = {"labels": {}}
            for key, value in self.wallet.labels.iteritems():
                try:
                    encoded_key = self.encode(key)
                except:
                    print_error('cannot encode', repr(key))
                    continue
                try:
                    encoded_value = self.encode(value)
                except:
                    print_error('cannot encode', repr(value))
                    continue
                bundle["labels"][encoded_key] = encoded_value

            params = json.dumps(bundle)
            connection = httplib.HTTPConnection(self.target_host)
            connection.request("POST", ("/api/wallets/%s/labels/batch.json?auth_token=%s" % (self.wallet_id, self.auth_token())), params, {'Content-Type': 'application/json'})

            response = connection.getresponse()
            if response.reason == httplib.responses[httplib.NOT_FOUND]:
                print_error('404 error' %  e)
                return
            try:
                response = json.loads(response.read())
            except ValueError as e:
                print_error('Error loading labelsync response: %s' %  e)
                return False

            if "error" in response:
                print_error('Error loading labelsync response.')
                return False

        except socket.gaierror as e:
            print_error('Error connecting to service: %s ' %  e)
            return False

        self.window.labelsChanged.emit()

    def do_full_pull(self, force = False):
        connection = httplib.HTTPConnection(self.target_host)
        connection.request("GET", ("/api/wallets/%s/labels.json?auth_token=%s" % (self.wallet_id, self.auth_token())),"", {'Content-Type': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            print_error("Cannot retrieve labels:", response.status, response.reason)
            return
        response = json.loads(response.read())
        if "error" in response:
            raise BaseException(_("Could not sync labels: %s" % response["error"]))

        for label in response:
            try:
                key = self.decode(label["external_id"])
            except:
                continue
            try:
                value = self.decode(label["text"])
            except:
                continue
            try:
                json.dumps(key)
                json.dumps(value)
            except:
                print_error('error: no json', key)
                continue
            if force or not self.wallet.labels.get(key):
                self.wallet.labels[key] = value
        self.wallet.storage.put('labels', self.wallet.labels)
        print_error("received %d labels"%len(response))
        self.window.labelsChanged.emit()
