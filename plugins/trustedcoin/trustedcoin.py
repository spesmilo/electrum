#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import socket
import os
import re
import requests
import json
from hashlib import sha256
from urlparse import urljoin
from urllib import quote

import electrum
from electrum import bitcoin
from electrum.bitcoin import *
from electrum.mnemonic import Mnemonic
from electrum import version
from electrum.wallet import Multisig_Wallet, BIP32_Wallet
from electrum.i18n import _
from electrum.plugins import BasePlugin, run_hook, hook
from electrum.util import NotEnoughFunds

# signing_xpub is hardcoded so that the wallet can be restored from seed, without TrustedCoin's server
signing_xpub = "xpub661MyMwAqRbcGnMkaTx2594P9EDuiEqMq25PM2aeG6UmwzaohgA6uDmNsvSUV8ubqwA3Wpste1hg69XHgjUuCD5HLcEp2QPzyV1HMrPppsL"
billing_xpub = "xpub6DTBdtBB8qUmH5c77v8qVGVoYk7WjJNpGvutqjLasNG1mbux6KsojaLrYf2sRhXAVU4NaFuHhbD9SvVPRt1MB1MaMooRuhHcAZH1yhQ1qDU"

SEED_PREFIX = version.SEED_PREFIX_2FA

DISCLAIMER = [
    _("Two-factor authentication is a service provided by TrustedCoin.  "
      "It uses a multi-signature wallet, where you own 2 of 3 keys.  "
      "The third key is stored on a remote server that signs transactions on "
      "your behalf.  To use this service, you will need a smartphone with "
      "Google Authenticator installed."),
    _("A small fee will be charged on each transaction that uses the "
      "remote server.  You may check and modify your billing preferences "
      "once the installation is complete."),
    _("Note that your coins are not locked in this service.  You may withdraw "
      "your funds at any time and at no cost, without the remote server, by "
      "using the 'restore wallet' option with your wallet seed."),
    _("The next step will generate the seed of your wallet.  This seed will "
      "NOT be saved in your computer, and it must be stored on paper.  "
      "To be safe from malware, you may want to do this on an offline "
      "computer, and move your wallet later to an online computer."),
]
RESTORE_MSG = _("Enter the seed for your 2-factor wallet:")

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

    def make_seed(self):
        return Mnemonic('english').make_seed(num_bits=256, prefix=SEED_PREFIX)

    def can_sign_without_server(self):
        return self.master_private_keys.get('x2/') is not None

    def get_max_amount(self, config, inputs, recipient, fee):
        from electrum.transaction import Transaction
        sendable = sum(map(lambda x:x['value'], inputs))
        for i in inputs:
            self.add_input_info(i)
        xf = self.extra_fee()
        if xf and sendable >= xf:
            billing_address = self.billing_info['billing_address']
            sendable -= xf
            outputs = [(TYPE_ADDRESS, recipient, sendable),
                       (TYPE_ADDRESS, billing_address, xf)]
        else:
            outputs = [(TYPE_ADDRESS, recipient, sendable)]

        dummy_tx = Transaction.from_io(inputs, outputs)
        if fee is None:
            fee = self.estimate_fee(config, dummy_tx.estimated_size())
        amount = max(0, sendable - fee)
        return amount, fee

    def extra_fee(self):
        if self.can_sign_without_server():
            return 0
        if self.billing_info.get('tx_remaining'):
            return 0
        if self.is_billing:
            return 0
        price = int(self.price_per_tx.get(1))
        assert price <= 100000
        return price

    def make_unsigned_transaction(self, coins, outputs, config,
                                  fixed_fee=None, change_addr=None):
        mk_tx = lambda o: BIP32_Wallet.make_unsigned_transaction(
            self, coins, o, config, fixed_fee, change_addr)
        fee = self.extra_fee()
        if fee:
            address = self.billing_info['billing_address']
            fee_output = (TYPE_ADDRESS, address, fee)
            try:
                tx = mk_tx(outputs + [fee_output])
            except NotEnoughFunds:
                # trustedcoin won't charge if the total inputs is
                # lower than their fee
                tx = mk_tx(outputs)
                if tx.input_value() >= fee:
                    raise
                self.print_error("not charging for this tx")
        else:
            tx = mk_tx(outputs)
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


class TrustedCoinPlugin(BasePlugin):
    wallet_class = Wallet_2fa

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallet_class.plugin = self

    @staticmethod
    def is_valid_seed(seed):
        return bitcoin.is_new_seed(seed, SEED_PREFIX)

    def is_available(self):
        return True

    def set_enabled(self, wallet, enabled):
        wallet.storage.put('use_' + self.name, enabled)

    def is_enabled(self):
        return True

    @hook
    def get_additional_fee(self, wallet, tx):
        address = wallet.billing_info['billing_address']
        for _type, addr, amount in tx.outputs():
            if _type == TYPE_ADDRESS and addr == address:
                return amount

    def request_billing_info(self, wallet):
        billing_info = server.get(wallet.get_user_id()[1])
        billing_address = make_billing_address(wallet, billing_info['billing_index'])
        assert billing_address == billing_info['billing_address']
        wallet.billing_info = billing_info
        wallet.price_per_tx = dict(billing_info['price_per_tx'])
        return True

    def create_extended_seed(self, wallet, window):
        seed = wallet.make_seed()
        window.show_and_verify_seed(seed, is_valid=self.is_valid_seed)

        password = window.request_password()
        wallet.storage.put('seed_version', wallet.seed_version)
        wallet.storage.put('use_encryption', password is not None)

        words = seed.split()
        n = len(words)/2
        wallet.add_xprv_from_seed(' '.join(words[0:n]), 'x1/', password)
        wallet.add_xpub_from_seed(' '.join(words[n:]), 'x2/')

        wallet.storage.write()

        msg = [
            _("Your wallet file is: %s.")%os.path.abspath(wallet.storage.path),
            _("You need to be online in order to complete the creation of "
              "your wallet.  If you generated your seed on an offline "
              'computer, click on "%s" to close this window, move your '
              "wallet file to an online computer, and reopen it with "
              "Electrum.") % _('Cancel'),
            _('If you are online, click on "%s" to continue.') % _('Next')
        ]
        msg = '\n\n'.join(msg)
        self.confirm(window, msg)

    @hook
    def do_clear(self, window):
        window.wallet.is_billing = False

    def on_restore_wallet(self, wallet, wizard):
        assert isinstance(wallet, self.wallet_class)

        seed = wizard.request_seed(RESTORE_MSG, is_valid=self.is_valid_seed)
        password = wizard.request_password()

        wallet.add_seed(seed, password)
        words = seed.split()
        n = len(words)/2
        wallet.add_xprv_from_seed(' '.join(words[0:n]), 'x1/', password)
        wallet.add_xprv_from_seed(' '.join(words[n:]), 'x2/', password)

        restore_third_key(wallet)
        wallet.create_main_account()
        return wallet

    def create_remote_key(self, wallet, window):
        email = self.accept_terms_of_use(window)
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

        if self.setup_google_auth(window, short_id, otp_secret):
            wallet.add_master_public_key('x3/', xpub3)
            wallet.create_main_account()
