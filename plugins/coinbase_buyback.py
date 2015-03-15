import PyQt4
import sys

import PyQt4.QtCore as QtCore
import base64
import urllib
import re
import time
import os
import httplib
import datetime
import json
import string

from urllib import urlencode

from PyQt4.QtGui import *
from PyQt4.QtCore import *
try:
    from PyQt4.QtWebKit import QWebView
    loaded_qweb = True
except ImportError as e:
    loaded_qweb = False

from electrum_grs.plugins import BasePlugin, hook
from electrum_grs.i18n import _, set_language
from electrum_grs.util import user_dir
from electrum_grs.util import format_satoshis
from electrum_grs_gui.qt import ElectrumGui

SATOSHIS_PER_BTC = float(100000000)
COINBASE_ENDPOINT = 'https://coinbase.com'
SCOPE = 'buy'
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'
TOKEN_URI = 'https://coinbase.com/oauth/token'
CLIENT_ID = '0a930a48b5a6ea10fb9f7a9fec3d093a6c9062ef8a7eeab20681274feabdab06'
CLIENT_SECRET = 'f515989e8819f1822b3ac7a7ef7e57f755c9b12aee8f22de6b340a99fd0fd617'
# Expiry is stored in RFC3339 UTC format
EXPIRY_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

class Plugin(BasePlugin):

    def fullname(self): return 'Coinbase BuyBack'

    def description(self): return 'After sending bitcoin, prompt the user with the option to rebuy them via Coinbase.\n\nMarcell Ortutay, 1FNGQvm29tKM7y3niq63RKi7Qbg7oZ3jrB'

    def __init__(self, gui, name):
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()

    def _init(self):
        return loaded_qweb

    @hook
    def init_qt(self, gui):
        self.gui = gui

    def is_available(self):
        return False
        return self._is_available

    def enable(self):
        return BasePlugin.enable(self)

    @hook
    def receive_tx(self, tx, wallet):
        domain = wallet.get_account_addresses(None)
        is_relevant, is_send, v, fee = tx.get_value(domain, wallet.prevout_values)
        if isinstance(self.gui, ElectrumGui):
            try:
                web = propose_rebuy_qt(abs(v))
            except OAuth2Exception as e:
                rm_local_oauth_credentials()
        # TODO(ortutay): android flow


def propose_rebuy_qt(amount):
    web = QWebView()
    box = QMessageBox()
    box.setFixedSize(200, 200)

    credentials = read_local_oauth_credentials()
    questionText = _('Rebuy ') + format_satoshis(amount) + _(' BTC?')
    if credentials:
        credentials.refresh()
    if credentials and not credentials.invalid:
        credentials.store_locally()
        totalPrice = get_coinbase_total_price(credentials, amount)
        questionText += _('\n(Price: ') + totalPrice + _(')')

    if not question(box, questionText):
        return

    if credentials:
        do_buy(credentials, amount)
    else:
        do_oauth_flow(web, amount)
    return web

def do_buy(credentials, amount):
    conn = httplib.HTTPSConnection('coinbase.com')
    credentials.authorize(conn)
    params = {
        'qty': float(amount)/SATOSHIS_PER_BTC,
        'agree_btc_amount_varies': False
    }
    resp = conn.auth_request('POST', '/api/v1/buys', urlencode(params), None)

    if resp.status != 200:
        message(_('Error, could not buy bitcoin'))
        return
    content = json.loads(resp.read())
    if content['success']:
        message(_('Success!\n') + content['transfer']['description'])
    else:
        if content['errors']:
            message(_('Error: ') + string.join(content['errors'], '\n'))
        else:
            message(_('Error, could not buy bitcoin'))

def get_coinbase_total_price(credentials, amount):
    conn = httplib.HTTPSConnection('coinbase.com')
    params={'qty': amount/SATOSHIS_PER_BTC}
    conn.request('GET', '/api/v1/prices/buy?' + urlencode(params))
    resp = conn.getresponse()
    if resp.status != 200:
        return 'unavailable'
    content = json.loads(resp.read())
    return '$' + content['total']['amount']

def do_oauth_flow(web, amount):
    # QT expects un-escaped URL
    auth_uri = step1_get_authorize_url()
    web.load(QUrl(auth_uri))
    web.setFixedSize(500, 700)
    web.show()
    web.titleChanged.connect(lambda(title): complete_oauth_flow(title, web, amount) if re.search('^[a-z0-9]+$', title) else False)

def complete_oauth_flow(token, web, amount):
    web.close()
    credentials = step2_exchange(str(token))
    credentials.store_locally()
    do_buy(credentials, amount)

def token_path():
    dir = user_dir() + '/coinbase_buyback'
    if not os.access(dir, os.F_OK):
        os.mkdir(dir)
    return dir + '/token'

def read_local_oauth_credentials():
    if not os.access(token_path(), os.F_OK):
        return None
    f = open(token_path(), 'r')
    data = f.read()
    f.close()
    try:
        credentials = Credentials.from_json(data)
        return credentials
    except Exception as e:
        return None

def rm_local_oauth_credentials():
    os.remove(token_path())

def step1_get_authorize_url():
    return ('https://coinbase.com/oauth/authorize'
            + '?scope=' + SCOPE
            + '&redirect_uri=' + REDIRECT_URI
            + '&response_type=code'
            + '&client_id=' + CLIENT_ID
            + '&access_type=offline')

def step2_exchange(code):
    body = urllib.urlencode({
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        })
    headers = {
        'content-type': 'application/x-www-form-urlencoded',
    }

    conn = httplib.HTTPSConnection('coinbase.com')
    conn.request('POST', TOKEN_URI, body, headers)
    resp = conn.getresponse()
    if resp.status == 200:
        d = json.loads(resp.read())
        access_token = d['access_token']
        refresh_token = d.get('refresh_token', None)
        token_expiry = None
        if 'expires_in' in d:
            token_expiry = datetime.datetime.utcnow() + datetime.timedelta(
                seconds=int(d['expires_in']))
        return Credentials(access_token, refresh_token, token_expiry)
    else:
        raise OAuth2Exception(content)

class OAuth2Exception(Exception):
    """An error related to OAuth2"""

class Credentials(object):
    def __init__(self, access_token, refresh_token, token_expiry):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_expiry = token_expiry
        
        # Indicates a failed refresh
        self.invalid = False

    def to_json(self):
        token_expiry = self.token_expiry
        if (token_expiry and isinstance(token_expiry, datetime.datetime)):
            token_expiry = token_expiry.strftime(EXPIRY_FORMAT)
        
        d = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'token_expiry': token_expiry,
        }
        return json.dumps(d)

    def store_locally(self):
        f = open(token_path(), 'w')
        f.write(self.to_json())
        f.close()

    @classmethod
    def from_json(cls, s):
        data = json.loads(s)
        if ('token_expiry' in data
            and not isinstance(data['token_expiry'], datetime.datetime)):
            try:
                data['token_expiry'] = datetime.datetime.strptime(
                    data['token_expiry'], EXPIRY_FORMAT)
            except:
                data['token_expiry'] = None
        retval = Credentials(
            data['access_token'],
            data['refresh_token'],
            data['token_expiry'])
        return retval

    def apply(self, headers):
        headers['Authorization'] = 'Bearer ' + self.access_token

    def authorize(self, conn):
        request_orig = conn.request

        def new_request(method, uri, params, headers):
            if headers == None:
                headers = {}
                self.apply(headers)
            request_orig(method, uri, params, headers)
            resp = conn.getresponse()
            if resp.status == 401:
                # Refresh and try again
                self._refresh(request_orig)
                self.store_locally()
                self.apply(headers)
                request_orig(method, uri, params, headers)
                return conn.getresponse()
            else:
                return resp
        
        conn.auth_request = new_request
        return conn

    def refresh(self):
        try:
            self._refresh()
        except OAuth2Exception as e:
            rm_local_oauth_credentials()
            self.invalid = True
            raise e

    def _refresh(self):
        conn = httplib.HTTPSConnection('coinbase.com')
        body = urllib.urlencode({
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
        })
        headers = {
            'content-type': 'application/x-www-form-urlencoded',
        }
        conn.request('POST', TOKEN_URI, body, headers)
        resp = conn.getresponse()
        if resp.status == 200:
            d = json.loads(resp.read())
            self.token_response = d
            self.access_token = d['access_token']
            self.refresh_token = d.get('refresh_token', self.refresh_token)
            if 'expires_in' in d:
                self.token_expiry = datetime.timedelta(
                    seconds=int(d['expires_in'])) + datetime.datetime.utcnow()
        else:
            raise OAuth2Exception('Refresh failed, ' + content)

def message(msg):
    box = QMessageBox()
    box.setFixedSize(200, 200)
    return QMessageBox.information(box, _('Message'), msg)

def question(widget, msg):
    return (QMessageBox.question(
        widget, _('Message'), msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            == QMessageBox.Yes)

def main():
    app = QApplication(sys.argv)
    print sys.argv[1]
    propose_rebuy_qt(int(sys.argv[1]))
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
