import PyQt4
import sys

import PyQt4.QtCore as QtCore
import urllib
import re
import time
import os
import httplib2
import requests
import json
import string

from urllib import urlencode

from PyQt4.QtGui import *
from PyQt4.QtCore import *
from PyQt4.QtWebKit import *

from electrum import BasePlugin
from electrum.i18n import _, set_language
from electrum.util import user_dir

from oauth2client.client import FlowExchangeError
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import OAuth2Credentials
class Plugin(BasePlugin):

    def fullname(self): return 'Coinbalance'

    def description(self): return 'After sending bitcoin, prompt to rebuy them via Coinbase.'

    def __init__(self, gui, name):
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()

    def _init(self):
        return True
    
    def is_available(self):
        return self._is_available

    def enable(self):
        return BasePlugin.enable(self)

    def send_tx(self, tx, to_address, amount):
        web = proposeRebuy(amount)


SATOSHIS_PER_BTC = float(100000000)
COINBASE_ENDPOINT = 'https://coinbase.com'
CERTS_PATH = os.path.dirname(os.path.realpath(__file__)) + '/ca-coinbase.crt'

def proposeRebuy(amount):
    web = QWebView()
    box = QMessageBox()
    box.setFixedSize(200, 200)

    # TODO(marcell): in the case of OAuth failure, remove local token
    credentials = readLocalOauthCredentials()
    questionText = _('Rebuy ') + str(amount/SATOSHIS_PER_BTC) + _(' BTC?')
    if credentials:
        credentials = refreshCredentials(credentials)
        storeLocalOauthCredentials(credentials)
        totalPrice = getCoinbaseTotalPrice(credentials, amount)
        questionText += _('\n(Price: ') + totalPrice + _(')')

    if not question(box, questionText):
        return

    if credentials:
        doBuy(credentials, amount)
    else:
        flow = OAuth2WebServerFlow(
            client_id='0a930a48b5a6ea10fb9f7a9fec3d093a6c9062ef8a7eeab20681274feabdab06',
            client_secret='f515989e8819f1822b3ac7a7ef7e57f755c9b12aee8f22de6b340a99fd0fd617',
            scope='buy',
            redirect_uri='urn:ietf:wg:oauth:2.0:oob',
            auth_uri='https://coinbase.com/oauth/authorize',
            token_uri='https://coinbase.com/oauth/token')
        doOauthFlow(flow, web, amount)
    return web

def completeOauthFlow(flow, token, web, amount):
    http = httplib2.Http(ca_certs=CERTS_PATH)
    try:
        credentials = flow.step2_exchange(str(token), http=http)
    except FlowExchangeError as e:
        raise e
    storeLocalOauthCredentials(credentials)
    doBuy(credentials, amount)

def doBuy(credentials, amount):
    h = httplib2.Http(ca_certs=CERTS_PATH)
    h = credentials.authorize(h)
    params = {'qty': float(amount)/SATOSHIS_PER_BTC, 'agree_btc_amount_varies': False}
    resp, content = h.request(COINBASE_ENDPOINT + '/api/v1/buys', 'POST', urlencode(params))
    content = json.loads(content)
    if content['success']:
        message(_('Success!\n') + content['transfer']['description'])
    else:
        if content['errors']:
            message(_('Error: ') + string.join(content['errors'], '\n'))
        else:
            message(_('Error, could not buy bitcoin'))
            

def readLocalOauthCredentials():
    if not os.access(tokenPath(), os.F_OK):
        return None
    f = open(tokenPath(), 'r')
    data = f.read()
    f.close()
    try:
        credentials = OAuth2Credentials.from_json(data)
        return credentials
    except Exception as e:
        return None

def storeLocalOauthCredentials(credentials):
    f = open(tokenPath(), 'w')
    f.write(credentials.to_json())
    f.close()

def refreshCredentials(credentials):
    h = httplib2.Http(ca_certs=CERTS_PATH)
    credentials.refresh(h)
    return credentials

def tokenPath():
    dir = user_dir() + '/coinbalance'
    if not os.access(dir, os.F_OK):
        os.mkdir(dir)
    return dir + '/token'

def doOauthFlow(flow, web, amount):
    # QT expects un-escaped URL
    auth_uri = urllib.unquote(flow.step1_get_authorize_url())
    web.load(QUrl(auth_uri))
    web.setFixedSize(500, 700)
    web.show()
    web.titleChanged.connect(lambda(title): completeOauthFlow(flow, title, web, amount) if re.search('^[a-z0-9]+$', title) else False)
    
def getCoinbaseTotalPrice(credentials, amount):
    r = requests.get(COINBASE_ENDPOINT + '/api/v1/prices/buy',
                     params={'qty': amount/SATOSHIS_PER_BTC})
    resp = r.json()
    return '$' + resp['total']['amount']

def message(msg):
    box = QMessageBox()
    box.setFixedSize(200, 200)
    return QMessageBox.information(box, _('Message'), msg)
    pass

def question(widget, msg):
    return (QMessageBox.question(
        widget, _('Message'), msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            == QMessageBox.Yes)

#TODO(marcell): rm test code
# if __name__ == '__main__':
#     app = QApplication(sys.argv)
#     web = proposeRebuy(float(100000))
#     sys.exit(app.exec_())


