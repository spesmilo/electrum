#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from threading import Thread
import socket
import os
import re
import requests
import json
from hashlib import sha256
from urlparse import urljoin
from urllib import quote
from functools import partial

import electrum
from electrum import bitcoin
from electrum.bitcoin import *
from electrum.mnemonic import Mnemonic
from electrum import version
from electrum.wallet import Multisig_Wallet, BIP32_Wallet
from electrum.i18n import _
from electrum.plugins import BasePlugin, run_hook, hook


from decimal import Decimal

# signing_xpub is hardcoded so that the wallet can be restored from seed, without TrustedCoin's server
signing_xpub = "xpub661MyMwAqRbcGnMkaTx2594P9EDuiEqMq25PM2aeG6UmwzaohgA6uDmNsvSUV8ubqwA3Wpste1hg69XHgjUuCD5HLcEp2QPzyV1HMrPppsL"
billing_xpub = "xpub6DTBdtBB8qUmH5c77v8qVGVoYk7WjJNpGvutqjLasNG1mbux6KsojaLrYf2sRhXAVU4NaFuHhbD9SvVPRt1MB1MaMooRuhHcAZH1yhQ1qDU"

SEED_PREFIX = version.SEED_PREFIX_2FA


class TrustedCoinException(Exception):
    def __init__(self, message, status_code=0):
        Exception.__init__(self, message)
        self.status_code = status_code

class TrustedCoinCosignerClient(object):
    def __init__(self, user_agent=None, base_url='https://api.trustedcoin.com/2/', debug=False):
        self.base_url = base_url
        self.debug = debug
        self.user_agent = user_agent

    def send_request(self, method, relative_url, data=None):
        kwargs = {'headers': {}}
        if self.user_agent:
            kwargs['headers']['user-agent'] = self.user_agent
        if method == 'get' and data:
            kwargs['params'] = data
        elif method == 'post' and data:
            kwargs['data'] = json.dumps(data)
            kwargs['headers']['content-type'] = 'application/json'
        url = urljoin(self.base_url, relative_url)
        if self.debug:
            print '%s %s %s' % (method, url, data)
        response = requests.request(method, url, **kwargs)
        if self.debug:
            print response.text
            print
        if response.status_code != 200:
            message = str(response.text)
            if response.headers.get('content-type') == 'application/json':
                r = response.json()
                if 'message' in r:
                    message = r['message']
            raise TrustedCoinException(message, response.status_code)
        if response.headers.get('content-type') == 'application/json':
            return response.json()
        else:
            return response.text

    def get_terms_of_service(self, billing_plan='electrum-per-tx-otp'):
        """
        Returns the TOS for the given billing plan as a plain/text unicode string.
        :param billing_plan: the plan to return the terms for
        """
        payload = {'billing_plan': billing_plan}
        return self.send_request('get', 'tos', payload)

    def create(self, xpubkey1, xpubkey2, email, billing_plan='electrum-per-tx-otp'):
        """
        Creates a new cosigner resource.
        :param xpubkey1: a bip32 extended public key (customarily the hot key)
        :param xpubkey2: a bip32 extended public key (customarily the cold key)
        :param email: a contact email
        :param billing_plan: the billing plan for the cosigner
        """
        payload = {
            'email': email,
            'xpubkey1': xpubkey1,
            'xpubkey2': xpubkey2,
            'billing_plan': billing_plan,
        }
        return self.send_request('post', 'cosigner', payload)

    def auth(self, id, otp):
        """
        Attempt to authenticate for a particular cosigner.
        :param id: the id of the cosigner
        :param otp: the one time password
        """
        payload = {'otp': otp}
        return self.send_request('post', 'cosigner/%s/auth' % quote(id), payload)

    def get(self, id):
        """
        Attempt to authenticate for a particular cosigner.
        :param id: the id of the cosigner
        :param otp: the one time password
        """
        return self.send_request('get', 'cosigner/%s' % quote(id))

    def sign(self, id, transaction, otp):
        """
        Attempt to authenticate for a particular cosigner.
        :param id: the id of the cosigner
        :param transaction: the hex encoded [partially signed] compact transaction to sign
        :param otp: the one time password
        """
        payload = {
            'otp': otp,
            'transaction': transaction
        }
        return self.send_request('post', 'cosigner/%s/sign' % quote(id), payload)

    def transfer_credit(self, id, recipient, otp, signature_callback):
        """
        Tranfer a cosigner's credits to another cosigner.
        :param id: the id of the sending cosigner
        :param recipient: the id of the recipient cosigner
        :param otp: the one time password (of the sender)
        :param signature_callback: a callback that signs a text message using xpubkey1/0/0 returning a compact sig
        """
        payload = {
            'otp': otp,
            'recipient': recipient,
            'timestamp': int(time.time()),

        }
        relative_url = 'cosigner/%s/transfer' % quote(id)
        full_url = urljoin(self.base_url, relative_url)
        headers = {
            'x-signature': signature_callback(full_url + '\n' + json.dumps(payload))
        }
        return self.send_request('post', relative_url, payload, headers)


server = TrustedCoinCosignerClient(user_agent="Electrum/" + version.ELECTRUM_VERSION)

class Wallet_2fa(Multisig_Wallet):

    def __init__(self, storage):
        BIP32_Wallet.__init__(self, storage)
        self.wallet_type = '2fa'
        self.m = 2
        self.n = 3
        self.is_billing = False
        self.billing_info = None

    def get_action(self):
        xpub1 = self.master_public_keys.get("x1/")
        xpub2 = self.master_public_keys.get("x2/")
        xpub3 = self.master_public_keys.get("x3/")
        if xpub2 is None and not self.storage.get('use_trustedcoin'):
            return 'show_disclaimer'
        if xpub2 is None:
            return 'create_extended_seed'
        if xpub3 is None:
            return 'create_remote_key'
        if not self.accounts:
            return 'create_accounts'

    def make_seed(self):
        return Mnemonic('english').make_seed(num_bits=256, prefix=SEED_PREFIX)

    def can_sign_without_server(self):
        return self.master_private_keys.get('x2/') is not None

    def extra_fee(self, tx):
        if self.can_sign_without_server():
            return 0
        if self.billing_info.get('tx_remaining'):
            return 0
        if self.is_billing:
            return 0
        # trustedcoin won't charge if the total inputs is lower than their fee
        price = int(self.price_per_tx.get(1))
        assert price <= 100000
        if tx.input_value() < price:
            self.print_error("not charging for this tx")
            return 0
        return price

    def estimated_fee(self, tx, fee_per_kb):
        fee = Multisig_Wallet.estimated_fee(self, tx, fee_per_kb)
        fee += self.extra_fee(tx)
        return fee

    def get_tx_fee(self, tx):
        fee = Multisig_Wallet.get_tx_fee(self, tx)
        fee += self.extra_fee(tx)
        return fee

    def make_unsigned_transaction(self, *args):
        tx = BIP32_Wallet.make_unsigned_transaction(self, *args)
        fee = self.extra_fee(tx)
        if fee:
            address = self.billing_info['billing_address']
            tx.outputs.append(('address', address, fee))
        return tx

    def sign_transaction(self, tx, password):
        BIP32_Wallet.sign_transaction(self, tx, password)
        if tx.is_complete():
            return
        if not self.auth_code:
            self.print_error("sign_transaction: no auth code")
            return
        long_user_id, short_id = self.get_user_id()
        tx_dict = tx.as_dict()
        raw_tx = tx_dict["hex"]
        r = server.sign(short_id, raw_tx, self.auth_code)
        if r:
            raw_tx = r.get('transaction')
            tx.update(raw_tx)
        self.print_error("twofactor: is complete", tx.is_complete())

    def get_user_id(self):
        def make_long_id(xpub_hot, xpub_cold):
            return bitcoin.sha256(''.join(sorted([xpub_hot, xpub_cold])))
        xpub_hot = self.master_public_keys["x1/"]
        xpub_cold = self.master_public_keys["x2/"]
        long_id = make_long_id(xpub_hot, xpub_cold)
        short_id = hashlib.sha256(long_id).hexdigest()
        return long_id, short_id

# Utility functions

def make_xpub(xpub, s):
    _, _, _, c, cK = deserialize_xkey(xpub)
    cK2, c2 = bitcoin._CKD_pub(cK, c, s)
    xpub2 = ("0488B21E" + "00" + "00000000" + "00000000").decode("hex") + c2 + cK2
    return EncodeBase58Check(xpub2)

def restore_third_key(wallet):
    long_user_id, short_id = wallet.get_user_id()
    xpub3 = make_xpub(signing_xpub, long_user_id)
    wallet.add_master_public_key('x3/', xpub3)

def make_billing_address(wallet, num):
    long_id, short_id = wallet.get_user_id()
    xpub = make_xpub(billing_xpub, long_id)
    _, _, _, c, cK = deserialize_xkey(xpub)
    cK, c = bitcoin.CKD_pub(cK, c, num)
    address = public_key_to_bc_address( cK )
    return address

def need_server(wallet, tx):
    from electrum.account import BIP32_Account
    # Detect if the server is needed
    long_id, short_id = wallet.get_user_id()
    xpub3 = wallet.master_public_keys['x3/']
    for x in tx.inputs_to_sign():
        if x[0:2] == 'ff':
            xpub, sequence = BIP32_Account.parse_xpubkey(x)
            if xpub == xpub3:
                return True
    return False


class TrustedCoinPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.seed_func = lambda x: bitcoin.is_new_seed(x, SEED_PREFIX)

    def constructor(self, s):
        return Wallet_2fa(s)

    def is_available(self):
        return True

    def set_enabled(self, wallet, enabled):
        wallet.storage.put('use_' + self.name, enabled)

    def is_enabled(self):
        return True

    @hook
    def on_new_window(self, window):
        wallet = window.wallet
        if wallet.storage.get('wallet_type') == '2fa':
            button = StatusBarButton(QIcon(":icons/trustedcoin.png"),
                                     _("TrustedCoin"),
                                     partial(self.settings_dialog, window))
            window.statusBar().addPermanentWidget(button)
            t = Thread(target=self.request_billing_info, args=(wallet,))
            t.setDaemon(True)
            t.start()

    def request_billing_info(self, wallet):
        billing_info = server.get(wallet.get_user_id()[1])
        billing_address = make_billing_address(wallet, billing_info['billing_index'])
        assert billing_address == billing_info['billing_address']
        wallet.billing_info = billing_info
        wallet.price_per_tx = dict(billing_info['price_per_tx'])
        return True

    def create_extended_seed(self, wallet, window):
        seed = wallet.make_seed()
        if not window.show_seed(seed, None):
            return

        if not window.verify_seed(seed, None, self.seed_func):
            return

        password = window.password_dialog()
        wallet.storage.put('seed_version', wallet.seed_version, True)
        wallet.storage.put('use_encryption', password is not None, True)

        words = seed.split()
        n = len(words)/2
        wallet.add_cosigner_seed(' '.join(words[0:n]), 'x1/', password)
        wallet.add_cosigner_xpub(' '.join(words[n:]), 'x2/')

        msg = [
            _('Your wallet file is:') + " %s"%os.path.abspath(wallet.storage.path),
            _('You need to be online in order to complete the creation of your wallet.'),
            _('If you generated your seed on an offline computer, click on "%s" to close this window, move your wallet file to an online computer and reopen it with Electrum.') % _('Close'),
            _('If you are online, click on "%s" to continue.') % _('Next')
        ]
        return window.question('\n\n'.join(msg), no_label=_('Close'), yes_label=_('Next'))


    def show_disclaimer(self, wallet, window):
        msg = [
            _("Two-factor authentication is a service provided by TrustedCoin.") + ' ',
            _("It uses a multi-signature wallet, where you own 2 of 3 keys.") + ' ',
            _("The third key is stored on a remote server that signs transactions on your behalf.") + ' ',
            _("To use this service, you will need a smartphone with Google Authenticator.") + '\n\n',

            _("A small fee will be charged on each transaction that uses the remote server.") + ' ',
            _("You may check and modify your billing preferences once the installation is complete.") + '\n\n',

            _("Note that your coins are not locked in this service.") + ' ',
            _("You may withdraw your funds at any time and at no cost, without the remote server, by using the 'restore wallet' option with your wallet seed.") + '\n\n',

            _('The next step will generate the seed of your wallet.') + ' ',
            _('This seed will NOT be saved in your computer, and it must be stored on paper.') + ' ',
            _('To be safe from malware, you may want to do this on an offline computer, and move your wallet later to an online computer.')
        ]
        icon = QPixmap(':icons/trustedcoin.png')
        if not window.question(''.join(msg), icon=icon):
            return False
        self.set_enabled(wallet, True)
        return True

    @hook
    def do_clear(self, window):
        window.wallet.is_billing = False

    @hook
    def get_wizard_action(self, window, wallet, action):
        if hasattr(self, action):
            return getattr(self, action)

    @hook
    def installwizard_restore(self, window, storage):
        if storage.get('wallet_type') != '2fa':
            return

        seed = window.enter_seed_dialog("Enter your seed", None, func=self.seed_func)
        if not seed:
            return
        wallet = Wallet_2fa(storage)
        password = window.password_dialog()

        wallet.add_seed(seed, password)
        words = seed.split()
        n = len(words)/2
        wallet.add_cosigner_seed(' '.join(words[0:n]), 'x1/', password)
        wallet.add_cosigner_seed(' '.join(words[n:]), 'x2/', password)

        restore_third_key(wallet)
        wallet.create_main_account(password)
        # disable plugin
        self.set_enabled(wallet, False)
        return wallet


    def create_remote_key(self, wallet, window):
        if wallet.storage.get('wallet_type') != '2fa':
            raise
            return

        email = self.accept_terms_of_use(window)
        if not email:
            return

        xpub_hot = wallet.master_public_keys["x1/"]
        xpub_cold = wallet.master_public_keys["x2/"]

        # Generate third key deterministically.
        long_user_id, short_id = wallet.get_user_id()
        xpub3 = make_xpub(signing_xpub, long_user_id)

        # secret must be sent by the server
        try:
            r = server.create(xpub_hot, xpub_cold, email)
        except socket.error:
            window.show_message('Server not reachable, aborting')
            return
        except TrustedCoinException as e:
            if e.status_code == 409:
                r = None
            else:
                raise e

        if r is None:
            otp_secret = None
        else:
            otp_secret = r.get('otp_secret')
            if not otp_secret:
                window.show_message(_('Error'))
                return
            _xpub3 = r['xpubkey_cosigner']
            _id = r['id']
            try:
                assert _id == short_id, ("user id error", _id, short_id)
                assert xpub3 == _xpub3, ("xpub3 error", xpub3, _xpub3)
            except Exception as e:
                window.show_message(str(e))
                return

        if not self.setup_google_auth(window, short_id, otp_secret):
            return

        wallet.add_master_public_key('x3/', xpub3)
        return True


