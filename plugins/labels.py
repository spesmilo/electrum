from electrum.util import print_error

import httplib, urllib
import socket
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
from electrum import bmp, pyqrnative
from electrum.plugins import BasePlugin
from electrum.i18n import _

from electrum_gui.qt import HelpButton, EnterButton

class Plugin(BasePlugin):

    def fullname(self):
        return _('Label Sync')

    def description(self):
        return '%s\n\n%s%s%s' % (_("This plugin can sync your labels across multiple Electrum installs by using a remote database to save your data. Labels, transactions and addresses are all sent and stored encrypted on the remote server. This code might increase the load of your wallet with a few microseconds as it will sync labels on each startup."), _("To get started visit"), " http://labelectrum.herokuapp.com/ ", _(" to sign up for an account."))

    def version(self):
        return "0.2.1"

    def encode(self, message):
        encrypted = aes.encryptData(self.encode_password, unicode(message))
        encoded_message = base64.b64encode(encrypted)

        return encoded_message

    def decode(self, message):
        decoded_message = aes.decryptData(self.encode_password, base64.b64decode(unicode(message)) )

        return decoded_message


    def init(self):
        self.target_host = 'labelectrum.herokuapp.com'
        self.window = self.gui.main_window

    def load_wallet(self, wallet):
        self.wallet = wallet
        if self.wallet.get_master_public_key():
            mpk = self.wallet.get_master_public_key()
        else:
            mpk = self.wallet.master_public_keys["m/0'/"][1]
        self.encode_password = hashlib.sha1(mpk).digest().encode('hex')[:32]
        self.wallet_id = hashlib.sha256(mpk).digest().encode('hex')

        addresses = [] 
        for account in self.wallet.accounts.values():
            for address in account.get_addresses(0):
                addresses.append(address)

        self.addresses = addresses

        if self.auth_token():
            # If there is an auth token we can try to actually start syncing
            self.full_pull()

    def auth_token(self):
        return self.config.get("plugin_label_api_key")

    def is_available(self):
        return True

    def requires_settings(self):
        return True

    def set_label(self, item,label, changed):
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
        self.download.clicked.connect(lambda: self.full_pull(True))
        layout.addWidget(self.download, 2,2)

        c = QPushButton(_("Cancel"))
        c.clicked.connect(d.reject)

        self.accept = QPushButton(_("Done"))
        self.accept.clicked.connect(d.accept)

        layout.addWidget(c,3,1)
        layout.addWidget(self.accept,3,2)

        check_for_api_key(self.auth_token())

        if d.exec_():
          return True
        else:
          return False

    def enable(self):
        if not self.auth_token(): # First run, throw plugin settings in your face
            self.init()
            self.load_wallet(self.gui.main_window.wallet)
            if self.settings_dialog():
                self.set_enabled(True)
                return True
            else:
                self.set_enabled(False)
                return False

        self.set_enabled(True)
        return True


    def full_push(self):
        if self.do_full_push():
            QMessageBox.information(None, _("Labels uploaded"), _("Your labels have been uploaded."))

    def full_pull(self, force = False):
        if self.do_full_pull(force) and force:
            QMessageBox.information(None, _("Labels synchronized"), _("Your labels have been synchronized."))
            self.window.update_history_tab()
            self.window.update_completions()
            self.window.update_receive_tab()
            self.window.update_contacts_tab()

    def do_full_push(self):
        try:
            bundle = {"labels": {}}
            for key, value in self.wallet.labels.iteritems():
                encoded = self.encode(key)
                bundle["labels"][encoded] = self.encode(value)

            params = json.dumps(bundle)
            connection = httplib.HTTPConnection(self.target_host)
            connection.request("POST", ("/api/wallets/%s/labels/batch.json?auth_token=%s" % (self.wallet_id, self.auth_token())), params, {'Content-Type': 'application/json'})

            response = connection.getresponse()
            if response.reason == httplib.responses[httplib.NOT_FOUND]:
                return
            try:
                response = json.loads(response.read())
            except ValueError as e:
                return False

            if "error" in response:
                QMessageBox.warning(None, _("Error"),_("Could not sync labels: %s" % response["error"]))
                return False

            return True
        except socket.gaierror as e:
            print_error('Error connecting to service: %s ' %  e)
            return False

    def do_full_pull(self, force = False):
        try:
            connection = httplib.HTTPConnection(self.target_host)
            connection.request("GET", ("/api/wallets/%s/labels.json?auth_token=%s" % (self.wallet_id, self.auth_token())),"", {'Content-Type': 'application/json'})
            response = connection.getresponse()
            if response.reason == httplib.responses[httplib.NOT_FOUND]:
                return
            try:
                response = json.loads(response.read())
            except ValueError as e:
                return False

            if "error" in response:
                QMessageBox.warning(None, _("Error"),_("Could not sync labels: %s" % response["error"]))
                return False

            for label in response:
                 decoded_key = self.decode(label["external_id"]) 
                 decoded_label = self.decode(label["text"]) 
                 if force or not self.wallet.labels.get(decoded_key):
                     self.wallet.labels[decoded_key] = decoded_label 
            return True
        except socket.gaierror as e:
            print_error('Error connecting to service: %s ' %  e)
            return False
