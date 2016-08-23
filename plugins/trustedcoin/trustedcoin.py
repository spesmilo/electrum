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
from electrum import keystore
from electrum.bitcoin import *
from electrum.mnemonic import Mnemonic
from electrum import version
from electrum.wallet import Multisig_Wallet, Deterministic_Wallet, Wallet
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
        self.m, self.n = 2, 3
        Deterministic_Wallet.__init__(self, storage)
        self.is_billing = False
        self.billing_info = None

    def can_sign_without_server(self):
        return not self.keystores.get('x2/').is_watching_only()

    def get_user_id(self):
        return get_user_id(self.storage)

    def get_max_amount(self, config, inputs, recipient, fee):
        from electrum.transaction import Transaction
        sendable = sum(map(lambda x:x['value'], inputs))
        for i in inputs:
            self.add_input_info(i)
        xf = self.extra_fee()
        _type, addr = recipient
        if xf and sendable >= xf:
            billing_address = self.billing_info['billing_address']
            sendable -= xf
            outputs = [(_type, addr, sendable),
                       (TYPE_ADDRESS, billing_address, xf)]
        else:
            outputs = [(_type, addr, sendable)]
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
        mk_tx = lambda o: Multisig_Wallet.make_unsigned_transaction(
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
        Multisig_Wallet.sign_transaction(self, tx, password)
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


# Utility functions

def get_user_id(storage):
    def make_long_id(xpub_hot, xpub_cold):
        return bitcoin.sha256(''.join(sorted([xpub_hot, xpub_cold])))
    xpub1 = storage.get('x1/')['xpub']
    xpub2 = storage.get('x2/')['xpub']
    long_id = make_long_id(xpub1, xpub2)
    short_id = hashlib.sha256(long_id).hexdigest()
    return long_id, short_id

def make_xpub(xpub, s):
    _, _, _, c, cK = deserialize_xkey(xpub)
    cK2, c2 = bitcoin._CKD_pub(cK, c, s)
    xpub2 = ("0488B21E" + "00" + "00000000" + "00000000").decode("hex") + c2 + cK2
    return EncodeBase58Check(xpub2)


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

    def make_seed(self):
        return Mnemonic('english').make_seed(num_bits=256, prefix=SEED_PREFIX)

    @hook
    def do_clear(self, window):
        window.wallet.is_billing = False

    def show_disclaimer(self, wizard):
        wizard.set_icon(':icons/trustedcoin.png')
        wizard.stack = []
        wizard.confirm_dialog(title='Disclaimer', message='\n\n'.join(DISCLAIMER), run_next = lambda x: wizard.run('choose_seed'))

    def choose_seed(self, wizard):
        title = _('Create or restore')
        message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
        choices = [
            ('create_seed', _('Create a new seed')),
            ('restore_wallet', _('I already have a seed')),
        ]
        wizard.choice_dialog(title=title, message=message, choices=choices, run_next=wizard.run)

    def create_seed(self, wizard):
        seed = self.make_seed()
        wizard.show_seed_dialog(run_next=wizard.confirm_seed, seed_text=seed)

    def create_keystore(self, wizard, seed, password):
        # this overloads the wizard's method
        words = seed.split()
        n = len(words)/2
        keystore1 = keystore.xprv_from_seed(' '.join(words[0:n]), password)
        keystore2 = keystore.xpub_from_seed(' '.join(words[n:]))
        wizard.storage.put('x1/', keystore1.dump())
        wizard.storage.put('x2/', keystore2.dump())
        wizard.storage.write()
        msg = [
            _("Your wallet file is: %s.")%os.path.abspath(wizard.storage.path),
            _("You need to be online in order to complete the creation of "
              "your wallet.  If you generated your seed on an offline "
              'computer, click on "%s" to close this window, move your '
              "wallet file to an online computer, and reopen it with "
              "Electrum.") % _('Cancel'),
            _('If you are online, click on "%s" to continue.') % _('Next')
        ]
        msg = '\n\n'.join(msg)
        wizard.stack = []
        wizard.confirm_dialog(title='', message=msg, run_next = lambda x: wizard.run('create_remote_key'))

    def restore_wallet(self, wizard):
        title = _("Restore two-factor Wallet")
        f = lambda x: wizard.run('on_restore_seed', x)
        wizard.restore_seed_dialog(run_next=f, is_valid=self.is_valid_seed)

    def on_restore_seed(self, wizard, seed):
        f = lambda pw: wizard.run('on_restore_pw', seed, pw)
        wizard.request_password(run_next=f)

    def on_restore_pw(self, wizard, seed, password):
        # FIXME
        # wallet.add_seed(seed, password)
        storage = wizard.storage
        words = seed.split()
        n = len(words)/2
        keystore1 = keystore.xprv_from_seed(' '.join(words[0:n]), password)
        keystore2 = keystore.xprv_from_seed(' '.join(words[n:]), password)
        storage.put('x1/', keystore1.dump())
        storage.put('x2/', keystore2.dump())
        long_user_id, short_id = get_user_id(storage)
        xpub3 = make_xpub(signing_xpub, long_user_id)
        keystore3 = keystore.from_xpub(xpub3)
        storage.put('x3/', keystore3.dump())
        wizard.wallet = Wallet(storage)
        wizard.create_addresses()

    def create_remote_key(self, wizard):
        email = self.accept_terms_of_use(wizard)
        xpub1 = wizard.storage.get('x1/')['xpub']
        xpub2 = wizard.storage.get('x2/')['xpub']
        # Generate third key deterministically.
        long_user_id, short_id = get_user_id(wizard.storage)
        xpub3 = make_xpub(signing_xpub, long_user_id)
        # secret must be sent by the server
        try:
            r = server.create(xpub1, xpub2, email)
        except socket.error:
            wizard.show_message('Server not reachable, aborting')
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
                wizard.show_message(_('Error'))
                return
            _xpub3 = r['xpubkey_cosigner']
            _id = r['id']
            try:
                assert _id == short_id, ("user id error", _id, short_id)
                assert xpub3 == _xpub3, ("xpub3 error", xpub3, _xpub3)
            except Exception as e:
                wizard.show_message(str(e))
                return
        if not self.setup_google_auth(wizard, short_id, otp_secret):
            wizard.show_message("otp error")
            return
        keystore3 = keystore.from_xpub(xpub3)
        wizard.storage.put('x3/', keystore3.dump())
        wizard.storage.put('use_trustedcoin', True)
        wizard.storage.write()
        wizard.wallet = Wallet(wizard.storage)
        wizard.run('create_addresses')

    @hook
    def get_action(self, storage):
        if not storage.get('x1/'):
            return self, 'show_disclaimer'
        if not storage.get('x2/'):
            return self, 'show_disclaimer'
        if not storage.get('x3/'):
            return self, 'create_remote_key'
