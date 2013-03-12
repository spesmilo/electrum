from electrum.util import print_error
from electrum_gui.i18n import _
import httplib, urllib
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

target_host = 'labelectrum.herokuapp.com'
config = {}

def is_available():
    return True

def auth_token():
    global config
    return config.get("plugin_label_api_key")

def init(gui):
    """If you want to give this a spin create a account at the target_host url and put it in your user dir config
    file with the label_api_key."""

    global config
    config = gui.config

    if config.get('plugin_label_enabled'):
        gui.set_hook('create_settings_tab', add_settings_tab)
        gui.set_hook('close_settings_dialog', close_settings_dialog)

        if not auth_token():
          return 

        cloud_wallet = CloudWallet(gui.wallet)
        gui.set_hook('set_label', set_label)

        cloud_wallet.full_pull()

def wallet_id():
    global config
    return hashlib.sha256(str(config.get("master_public_key"))).digest().encode('hex')

def set_label(item,label, changed):
    if not changed:
        return 

    print "Label changed! Item: %s Label: %s label" % ( item, label)
    global target_host
    hashed = hashlib.sha256(item).digest().encode('hex')
    bundle = {"label": {"external_id": hashed, "text": label}}
    params = json.dumps(bundle)
    connection = httplib.HTTPConnection(target_host)
    connection.request("POST", ("/api/wallets/%s/labels.json?auth_token=%s" % (wallet_id(), auth_token())), params, {'Content-Type': 'application/json'})

    response = connection.getresponse()
    if response.reason == httplib.responses[httplib.NOT_FOUND]:
        return
    response = json.loads(response.read())

def close_settings_dialog(gui):
    global config

    # When you enable the plugin for the first time this won't exist.
    if is_enabled():
        if hasattr(gui, 'auth_token_edit'):
            config.set_key("plugin_label_api_key", str(gui.auth_token_edit.text()))
        else:
            QMessageBox.information(None, _("Cloud plugin loaded"), _("Please open the settings again to configure the label-cloud plugin."))

def add_settings_tab(gui, tabs):
    def check_for_api_key(api_key):
        global config
        if api_key and len(api_key) > 12:
          config.set_key("plugin_label_api_key", str(gui.auth_token_edit.text()))
          upload.setEnabled(True)
          download.setEnabled(True)
        else:
          upload.setEnabled(False)
          download.setEnabled(False)

    cloud_tab = QWidget()
    layout = QGridLayout(cloud_tab)
    layout.addWidget(QLabel("API Key: "),0,0)

    # TODO: I need to add it to the Electrum GUI here so I can retrieve it later when the settings dialog is closed, is there a better way to do this?
    gui.auth_token_edit = QLineEdit(auth_token())
    gui.auth_token_edit.textChanged.connect(check_for_api_key)

    layout.addWidget(gui.auth_token_edit, 0,1,1,2)
    layout.addWidget(QLabel("Label cloud options: "),1,0)

    upload = QPushButton("Force upload")
    upload.clicked.connect(lambda: full_push(gui.wallet))
    layout.addWidget(upload, 1,1)

    download = QPushButton("Force download")
    download.clicked.connect(lambda: full_pull(gui.wallet))
    layout.addWidget(download, 1,2)

    gui.cloud_tab = cloud_tab
    check_for_api_key(auth_token())

    tabs.addTab(cloud_tab, "Label cloud")

def full_push(wallet):
    cloud_wallet = CloudWallet(wallet)
    cloud_wallet.full_push()
    QMessageBox.information(None, _("Labels synced"), _("Your labels have been uploaded."))

def full_pull(wallet):
    cloud_wallet = CloudWallet(wallet)
    cloud_wallet.full_pull(True)
    QMessageBox.information(None, _("Labels synced"), _("Your labels have been synced, please restart Electrum for the changes to take effect."))

def show():
    print 'showing'

def get_info():
    return 'Label sync', "Syncs your labels with 'the cloud'. Labels are not encrypted, transactions and addresses are however. This code might increase the load of your wallet with a few micoseconds as it will sync labels on each startup."

def is_enabled():
    return config.get('plugin_label_enabled') is True

def toggle(gui):
    if not is_enabled():
        enabled = True
    else:
      enabled = False
      gui.unset_hook('create_settings_tab', add_settings_tab)
      gui.unset_hook('close_settings_dialog', close_settings_dialog)
         
    config.set_key('plugin_label_enabled', enabled, True)

    if enabled:
        init(gui)
    return enabled

# This can probably be refactored into plain top level methods instead of a class
class CloudWallet():
    def __init__(self, wallet):
        self.labels = wallet.labels
        self.transactions = wallet.transactions

        addresses = [] 
        for k, account in wallet.accounts.items():
            for address in account[0]:
                addresses.append(address)

        self.addresses = addresses

    def full_pull(self, force = False):
        global target_host
        connection = httplib.HTTPConnection(target_host)
        connection.request("GET", ("/api/wallets/%s/labels.json?auth_token=%s" % (wallet_id(), auth_token())),"", {'Content-Type': 'application/json'})
        response = connection.getresponse()
        if response.reason == httplib.responses[httplib.NOT_FOUND]:
            return
        try:
            response = json.loads(response.read())
        except ValueError as e:
            return

        if "error" in response:
            QMessageBox.warning(None, _("Error"),_("Could not sync labels: %s" % response["error"]))
            return 

        for label in response:
            for key in self.addresses:
                target_hashed = hashlib.sha256(key).digest().encode('hex')
                if label["external_id"] == target_hashed:
                   if force or not self.labels.get(key):
                       self.labels[key] = label["text"] 
            for key, value in self.transactions.iteritems():
                target_hashed = hashlib.sha256(key).digest().encode('hex')
                if label["external_id"] == target_hashed:
                   if force or not self.labels.get(key):
                       self.labels[key] = label["text"] 

    def full_push(self):
        global target_host

        bundle = {"labels": {}}
        for key, value in self.labels.iteritems():
            hashed = hashlib.sha256(key).digest().encode('hex')
            bundle["labels"][hashed] = value

        params = json.dumps(bundle)
        connection = httplib.HTTPConnection(target_host)
        connection.request("POST", ("/api/wallets/%s/labels/batch.json?auth_token=%s" % (wallet_id(), auth_token())), params, {'Content-Type': 'application/json'})

        response = connection.getresponse()
        if response.reason == httplib.responses[httplib.NOT_FOUND]:
            return
        try:
            response = json.loads(response.read())
        except ValueError as e:
            return

        if "error" in response:
            QMessageBox.warning(None, _("Error"),_("Could not sync labels: %s" % response["error"]))
            return 
