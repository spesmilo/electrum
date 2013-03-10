from electrum.util import print_error
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

def init(gui):
    """If you want to give this a spin create a account at the target_host url and put it in your user dir config
    file with the label_api_key."""

    global auth_token
    auth_token = gui.config.get("label_api_key")
    if not auth_token:
      return 

    cloud_wallet = CloudWallet(gui.wallet)
    gui.set_hook('create_settings_tab', add_settings_tab)
    gui.set_hook('label_changed', label_changed)
    cloud_wallet.full_pull()

def wallet_id(wallet):
    return hashlib.sha256(str(wallet.get_master_public_key())).digest().encode('hex')

def label_changed(gui,item,label):
    print "Label changed! Item: %s Label: %s label" % ( item, label)
    global auth_token, target_host
    hashed = hashlib.sha256(item).digest().encode('hex')
    bundle = {"label": {"external_id": hashed, "text": label}}
    params = json.dumps(bundle)
    connection = httplib.HTTPConnection(target_host)
    wallet = wallet_id(gui.wallet)
    connection.request("POST", ("/api/wallets/%s/labels.json?auth_token=%s" % (wallet, auth_token)), params, {'Content-Type': 'application/json'})

    response = connection.getresponse()
    if response.reason == httplib.responses[httplib.NOT_FOUND]:
        return
    response = json.loads(response.read())

def add_settings_tab(gui, tabs):
      cloud_tab = QWidget()
      layout = QGridLayout(cloud_tab)
      layout.addWidget(QLabel("API Key: "),0,0)
      layout.addWidget(QLineEdit(auth_token), 0,2)

      layout.addWidget(QLabel("Label sync options: "),1,0)

      upload = QPushButton("Force upload")
      upload.clicked.connect(lambda: full_push(gui.wallet))
      layout.addWidget(upload, 1,1)

      download = QPushButton("Force download")
      download.clicked.connect(lambda: full_pull(gui.wallet))
      layout.addWidget(download, 1,2)

      tabs.addTab(cloud_tab, "Label cloud")

def full_push(wallet):
    cloud_wallet = CloudWallet(wallet)
    cloud_wallet.full_push()
    print "Labels pushed"

def full_pull(wallet):
    cloud_wallet = CloudWallet(wallet)
    cloud_wallet.full_pull(True)
    print "Labels pulled, please restart your client"

def show():
    print 'showing'

def get_info():
    return 'Label sync', "Syncs your labels with LabElectrum. Labels are not encrypted, transactions and addresses are however."

def is_enabled():
    return True

def toggle(gui):
    return is_enabled()

# This can probably be refactored into plain top level methods instead of a class
class CloudWallet():
    def __init__(self, wallet):
        self.mpk = hashlib.sha256(str(wallet.get_master_public_key())).digest().encode('hex')
        self.labels = wallet.labels
        self.transactions = wallet.transactions

        addresses = [] 
        for k, account in wallet.accounts.items():
            for address in account[0]:
                addresses.append(address)

        self.addresses = addresses


    def full_pull(self, force = False):
        global target_host, auth_token
        connection = httplib.HTTPConnection(target_host)
        connection.request("GET", ("/api/wallets/%s/labels.json?auth_token=%s" % (self.mpk, auth_token)),"", {'Content-Type': 'application/json'})
        response = connection.getresponse()
        if response.reason == httplib.responses[httplib.NOT_FOUND]:
            return
        try:
            response = json.loads(response.read())
        except ValueError as e:
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
        global target_host, auth_token

        bundle = {"labels": {}}
        for key, value in self.labels.iteritems():
            hashed = hashlib.sha256(key).digest().encode('hex')
            bundle["labels"][hashed] = value

        params = json.dumps(bundle)
        connection = httplib.HTTPConnection(target_host)
        connection.request("POST", ("/api/wallets/%s/labels/batch.json?auth_token=%s" % (self.mpk, auth_token)), params, {'Content-Type': 'application/json'})

        response = connection.getresponse()
        if response.reason == httplib.responses[httplib.NOT_FOUND]:
            return
        response = json.loads(response.read())
        print response
