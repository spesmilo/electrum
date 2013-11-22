import PyQt4
import sys

import PyQt4.QtCore as QtCore
import urllib
import re
import time
import os
import httplib2
import json
import string

from urllib import urlencode

from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.QtWebKit import QWebView

from electrum import BasePlugin
from electrum.i18n import _, set_language
from electrum.util import user_dir
from electrum.util import appdata_dir
from electrum.util import format_satoshis
from electrum_gui.qt import ElectrumGui

from oauth2client.client import FlowExchangeError
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import OAuth2Credentials

SATOSHIS_PER_BTC = float(100000000)
COINBASE_ENDPOINT = 'https://coinbase.com'
CERTS_PATH = appdata_dir() + '/certs/ca-coinbase.crt'

class Plugin(BasePlugin):

    def fullname(self): return 'Coinbalance'

    def description(self): return 'After sending bitcoin, prompt to rebuy them via Coinbase.\n\nMarcell Ortutay, 1FNGQvm29tKM7y3niq63RKi7Qbg7oZ3jrB'

    def __init__(self, gui, name):
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()

    def _init(self):
        return True
    
    def is_available(self):
        return self._is_available

    def enable(self):
        return BasePlugin.enable(self)

    def receive_tx(self, tx, wallet):
        domain = wallet.get_account_addresses(None)
        is_relevant, is_send, v, fee = tx.get_value(domain, wallet.prevout_values)
        if isinstance(self.gui, ElectrumGui):
            try:
                web = propose_rebuy_qt(abs(v))
            except oauth2client.client.Error as e:
                rm_local_oauth_credentials()
        # TODO(ortutay): android flow



def propose_rebuy_qt(amount):
    web = QWebView()
    box = QMessageBox()
    box.setFixedSize(200, 200)

    # TODO(marcell): in the case of OAuth failure, remove local token
    credentials = read_local_oauth_credentials()
    questionText = _('Rebuy ') + format_satoshis(amount) + _(' BTC?')
    if credentials:
        credentials = refresh_credentials(credentials)
        store_local_oauth_credentials(credentials)
        totalPrice = get_coinbase_total_price(credentials, amount)
        questionText += _('\n(Price: ') + totalPrice + _(')')

    if not question(box, questionText):
        return

    if credentials:
        do_buy(credentials, amount)
    else:
        flow = OAuth2WebServerFlow(
            client_id='0a930a48b5a6ea10fb9f7a9fec3d093a6c9062ef8a7eeab20681274feabdab06',
            client_secret='f515989e8819f1822b3ac7a7ef7e57f755c9b12aee8f22de6b340a99fd0fd617',
            scope='buy',
            redirect_uri='urn:ietf:wg:oauth:2.0:oob',
            auth_uri='https://coinbase.com/oauth/authorize',
            token_uri='https://coinbase.com/oauth/token')
        do_oauth_flow(flow, web, amount)
    return web

def do_oauth_flow(flow, web, amount):
    # QT expects un-escaped URL
    auth_uri = urllib.unquote(flow.step1_get_authorize_url())
    web.load(QUrl(auth_uri))
    web.setFixedSize(500, 700)
    web.show()
    web.titleChanged.connect(lambda(title): complete_oauth_flow(flow, title, web, amount) if re.search('^[a-z0-9]+$', title) else False)
    
def complete_oauth_flow(flow, token, web, amount):
    web.close()
    http = httplib2.Http(ca_certs=CERTS_PATH)
    try:
        credentials = flow.step2_exchange(str(token), http=http)
    except FlowExchangeError as e:
        raise e
    store_local_oauth_credentials(credentials)
    do_buy(credentials, amount)
            
def read_local_oauth_credentials():
    if not os.access(token_path(), os.F_OK):
        return None
    f = open(token_path(), 'r')
    data = f.read()
    f.close()
    try:
        credentials = OAuth2Credentials.from_json(data)
        return credentials
    except Exception as e:
        return None

def store_local_oauth_credentials(credentials):
    f = open(token_path(), 'w')
    f.write(credentials.to_json())
    f.close()

def rm_local_oauth_credentials():
    os.remove(token_path())

def refresh_credentials(credentials):
    h = httplib2.Http(ca_certs=CERTS_PATH)
    credentials.refresh(h)
    return credentials

def do_buy(credentials, amount):
    h = httplib2.Http(ca_certs=CERTS_PATH)
    h = credentials.authorize(h)
    params = {'qty': float(amount)/SATOSHIS_PER_BTC, 'agree_btc_amount_varies': False}
    resp, content = h.request(COINBASE_ENDPOINT + '/api/v1/buys', 'POST', urlencode(params))
    if resp['status'] != '200':
        message(_('Error, could not buy bitcoin'))
        return
    content = json.loads(content)
    if content['success']:
        message(_('Success!\n') + content['transfer']['description'])
    else:
        if content['errors']:
            message(_('Error: ') + string.join(content['errors'], '\n'))
        else:
            message(_('Error, could not buy bitcoin'))

def token_path():
    dir = user_dir() + '/coinbalance'
    if not os.access(dir, os.F_OK):
        os.mkdir(dir)
    return dir + '/token'

def get_coinbase_total_price(credentials, amount):
    h = httplib2.Http(ca_certs=CERTS_PATH)
    params={'qty': amount/SATOSHIS_PER_BTC}
    resp, content = h.request(COINBASE_ENDPOINT + '/api/v1/prices/buy?' + urlencode(params),'GET')
    content = json.loads(content)
    if resp['status'] != '200':
        return 'unavailable'
    return '$' + content['total']['amount']

def message(msg):
    box = QMessageBox()
    box.setFixedSize(200, 200)
    return QMessageBox.information(box, _('Message'), msg)

def question(widget, msg):
    return (QMessageBox.question(
        widget, _('Message'), msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            == QMessageBox.Yes)
