from electrum.util import print_error
from electrum_gui.i18n import _
import httplib, urllib
import socket
import hashlib
import json
from urlparse import urlparse, parse_qs
try:
    import PyQt4
except:
    sys.exit("Error: Could not import PyQt4 on Linux systems, you may try 'sudo apt-get install python-qt4'")

from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore
import PyQt4.QtGui as QtGui
import aes
import base64
from electrum_gui import bmp, pyqrnative, BasePlugin
from electrum_gui.i18n import _
from electrum_gui.gui_classic import HelpButton

class Plugin(BasePlugin):
    def version(self):
        return "0.2.1"

    def encode(self, message):
        encrypted = aes.encryptData(self.encode_password, unicode(message))
        encoded_message = base64.b64encode(encrypted)

        return encoded_message

    def decode(self, message):
        decoded_message = aes.decryptData(self.encode_password, base64.b64decode(unicode(message)) )

        return decoded_message

    def __init__(self, gui):
        self.target_host = 'labelectrum.herokuapp.com'
        BasePlugin.__init__(self, gui, 'labels', _('Label Sync'),_('This plugin can sync your labels accross multiple Electrum installs by using a remote database to save your data. Labels,  \
transactions and addresses are all sent and stored encrypted on the remote server. This code might increase the load of your wallet with a few microseconds as it will sync labels on each startup.\n\n\
To get started visit http://labelectrum.herokuapp.com/ to sign up for an account.'))

        self.wallet = gui.wallet
        self.gui = gui
        self.config = gui.config
        self.labels = self.wallet.labels
        self.transactions = self.wallet.transactions
        self.encode_password = hashlib.sha1(self.config.get("master_public_key")).digest().encode('hex')[:32]

        self.wallet_id = hashlib.sha256(str(self.config.get("master_public_key"))).digest().encode('hex')

        addresses = [] 
        for k, account in self.wallet.accounts.items():
            for address in account[0]:
                addresses.append(address)

        self.addresses = addresses

    def auth_token(self):
        return self.config.get("plugin_label_api_key")

    def init_gui(self):
        if self.is_enabled() and self.auth_token():
            # If there is an auth token we can try to actually start syncing
            self.full_pull()

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

        d = QDialog(self.gui)
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

    def toggle(self):
        enabled = not self.is_enabled()
        self.set_enabled(enabled)
        self.init_gui()

        if not self.auth_token() and enabled: # First run, throw plugin settings in your face
            if self.settings_dialog():
              self.set_enabled(True)
              return True
            else:
              self.set_enabled(False)
              return False
        return enabled

    def full_push(self):
        if self.do_full_push():
            QMessageBox.information(None, _("Labels uploaded"), _("Your labels have been uploaded."))

    def full_pull(self, force = False):
        if self.do_full_pull(force) and force:
            QMessageBox.information(None, _("Labels synchronized"), _("Your labels have been synchronized."))
            self.gui.update_history_tab()
            self.gui.update_completions()
            self.gui.update_receive_tab()
            self.gui.update_contacts_tab()

    def do_full_push(self):
        try:
            bundle = {"labels": {}}
            for key, value in self.labels.iteritems():
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
                 if force or not self.labels.get(decoded_key):
                     self.labels[decoded_key] = decoded_label 
            return True
        except socket.gaierror as e:
            print_error('Error connecting to service: %s ' %  e)
            return False
