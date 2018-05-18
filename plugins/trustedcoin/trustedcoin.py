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
import requests
import json
from urllib.parse import urljoin
from urllib.parse import quote

import electrum
from electrum import bitcoin, ecc
from electrum import constants
from electrum import keystore
from electrum.bitcoin import *
from electrum.mnemonic import Mnemonic
from electrum import version
from electrum.wallet import Multisig_Wallet, Deterministic_Wallet
from electrum.i18n import _
from electrum.plugins import BasePlugin, hook
from electrum.util import NotEnoughFunds
from electrum.storage import STO_EV_USER_PW

# signing_xpub is hardcoded so that the wallet can be restored from seed, without TrustedCoin's server
def get_signing_xpub():
    if constants.net.TESTNET:
        return "tpubD6NzVbkrYhZ4XdmyJQcCPjQfg6RXVUzGFhPjZ7uvRC8JLcS7Hw1i7UTpyhp9grHpak4TyK2hzBJrujDVLXQ6qB5tNpVx9rC6ixijUXadnmY"
    else:
        return "xpub661MyMwAqRbcGnMkaTx2594P9EDuiEqMq25PM2aeG6UmwzaohgA6uDmNsvSUV8ubqwA3Wpste1hg69XHgjUuCD5HLcEp2QPzyV1HMrPppsL"

def get_billing_xpub():
    if constants.net.TESTNET:
        return "tpubD6NzVbkrYhZ4X11EJFTJujsYbUmVASAYY7gXsEt4sL97AMBdypiH1E9ZVTpdXXEy3Kj9Eqd1UkxdGtvDt5z23DKsh6211CfNJo8bLLyem5r"
    else:
        return "xpub6DTBdtBB8qUmH5c77v8qVGVoYk7WjJNpGvutqjLasNG1mbux6KsojaLrYf2sRhXAVU4NaFuHhbD9SvVPRt1MB1MaMooRuhHcAZH1yhQ1qDU"

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

KIVY_DISCLAIMER = [
    _("Two-factor authentication is a service provided by TrustedCoin. "
      "To use it, you must have a separate device with Google Authenticator."),
    _("This service uses a multi-signature wallet, where you own 2 of 3 keys.  "
      "The third key is stored on a remote server that signs transactions on "
      "your behalf.A small fee will be charged on each transaction that uses the "
      "remote server."),
    _("Note that your coins are not locked in this service.  You may withdraw "
      "your funds at any time and at no cost, without the remote server, by "
      "using the 'restore wallet' option with your wallet seed."),
]
RESTORE_MSG = _("Enter the seed for your 2-factor wallet:")

class TrustedCoinException(Exception):
    def __init__(self, message, status_code=0):
        Exception.__init__(self, message)
        self.status_code = status_code


class ErrorConnectingServer(Exception):
    pass


class TrustedCoinCosignerClient(object):
    def __init__(self, user_agent=None, base_url='https://api.trustedcoin.com/2/'):
        self.base_url = base_url
        self.debug = False
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
            print('%s %s %s' % (method, url, data))
        try:
            response = requests.request(method, url, **kwargs)
        except Exception as e:
            raise ErrorConnectingServer(e)
        if self.debug:
            print(response.text)
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
        """ Get billing info """
        return self.send_request('get', 'cosigner/%s' % quote(id))

    def get_challenge(self, id):
        """ Get challenge to reset Google Auth secret """
        return self.send_request('get', 'cosigner/%s/otp_secret' % quote(id))

    def reset_auth(self, id, challenge, signatures):
        """ Reset Google Auth secret """
        payload = {'challenge':challenge, 'signatures':signatures}
        return self.send_request('post', 'cosigner/%s/otp_secret' % quote(id), payload)

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
        Transfer a cosigner's credits to another cosigner.
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

    wallet_type = '2fa'

    def __init__(self, storage):
        self.m, self.n = 2, 3
        Deterministic_Wallet.__init__(self, storage)
        self.is_billing = False
        self.billing_info = None

    def can_sign_without_server(self):
        return not self.keystores['x2/'].is_watching_only()

    def get_user_id(self):
        return get_user_id(self.storage)

    def min_prepay(self):
        return min(self.price_per_tx.keys())

    def num_prepay(self, config):
        default = self.min_prepay()
        n = config.get('trustedcoin_prepay', default)
        if n not in self.price_per_tx:
            n = default
        return n

    def extra_fee(self, config):
        if self.can_sign_without_server():
            return 0
        if self.billing_info is None:
            self.plugin.start_request_thread(self)
            return 0
        if self.billing_info.get('tx_remaining'):
            return 0
        if self.is_billing:
            return 0
        n = self.num_prepay(config)
        price = int(self.price_per_tx[n])
        assert price <= 100000 * n
        return price

    def make_unsigned_transaction(self, coins, outputs, config, fixed_fee=None,
                                  change_addr=None, is_sweep=False):
        mk_tx = lambda o: Multisig_Wallet.make_unsigned_transaction(
            self, coins, o, config, fixed_fee, change_addr)
        fee = self.extra_fee(config) if not is_sweep else 0
        if fee:
            address = self.billing_info['billing_address']
            fee_output = (TYPE_ADDRESS, address, fee)
            try:
                tx = mk_tx(outputs + [fee_output])
            except NotEnoughFunds:
                # TrustedCoin won't charge if the total inputs is
                # lower than their fee
                tx = mk_tx(outputs)
                if tx.input_value() >= fee:
                    raise
                self.print_error("not charging for this tx")
        else:
            tx = mk_tx(outputs)
        return tx

    def on_otp(self, tx, otp):
        if not otp:
            self.print_error("sign_transaction: no auth code")
            return
        otp = int(otp)
        long_user_id, short_id = self.get_user_id()
        tx_dict = tx.as_dict()
        raw_tx = tx_dict["hex"]
        r = server.sign(short_id, raw_tx, otp)
        if r:
            raw_tx = r.get('transaction')
            tx.update(raw_tx)
        self.print_error("twofactor: is complete", tx.is_complete())
        # reset billing_info
        self.billing_info = None



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
    version, _, _, _, c, cK = deserialize_xpub(xpub)
    cK2, c2 = bitcoin._CKD_pub(cK, c, s)
    return bitcoin.serialize_xpub(version, c2, cK2)

def make_billing_address(wallet, num):
    long_id, short_id = wallet.get_user_id()
    xpub = make_xpub(get_billing_xpub(), long_id)
    version, _, _, _, c, cK = deserialize_xpub(xpub)
    cK, c = bitcoin.CKD_pub(cK, c, num)
    return bitcoin.public_key_to_p2pkh(cK)


class TrustedCoinPlugin(BasePlugin):
    wallet_class = Wallet_2fa
    disclaimer_msg = DISCLAIMER

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallet_class.plugin = self
        self.requesting = False

    @staticmethod
    def is_valid_seed(seed):
        return bitcoin.is_new_seed(seed, SEED_PREFIX)

    def is_available(self):
        return True

    def is_enabled(self):
        return True

    def can_user_disable(self):
        return False

    @hook
    def tc_sign_wrapper(self, wallet, tx, on_success, on_failure):
        if not isinstance(wallet, self.wallet_class):
            return
        if tx.is_complete():
            return
        if wallet.can_sign_without_server():
            return
        if not wallet.keystores['x3/'].get_tx_derivations(tx):
            self.print_error("twofactor: xpub3 not needed")
            return
        def wrapper(tx):
            self.prompt_user_for_otp(wallet, tx, on_success, on_failure)
        return wrapper

    @hook
    def get_tx_extra_fee(self, wallet, tx):
        if type(wallet) != Wallet_2fa:
            return
        if wallet.billing_info is None:
            assert wallet.can_sign_without_server()
            return None
        address = wallet.billing_info['billing_address']
        for _type, addr, amount in tx.outputs():
            if _type == TYPE_ADDRESS and addr == address:
                return address, amount

    def finish_requesting(func):
        def f(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            finally:
                self.requesting = False
        return f

    @finish_requesting
    def request_billing_info(self, wallet):
        if wallet.can_sign_without_server():
            return
        self.print_error("request billing info")
        try:
            billing_info = server.get(wallet.get_user_id()[1])
        except ErrorConnectingServer as e:
            self.print_error('cannot connect to TrustedCoin server: {}'.format(e))
            return
        billing_address = make_billing_address(wallet, billing_info['billing_index'])
        assert billing_address == billing_info['billing_address']
        wallet.billing_info = billing_info
        wallet.price_per_tx = dict(billing_info['price_per_tx'])
        wallet.price_per_tx.pop(1)
        return True

    def start_request_thread(self, wallet):
        from threading import Thread
        if self.requesting is False:
            self.requesting = True
            t = Thread(target=self.request_billing_info, args=(wallet,))
            t.setDaemon(True)
            t.start()
            return t

    def make_seed(self):
        return Mnemonic('english').make_seed(seed_type='2fa', num_bits=128)

    @hook
    def do_clear(self, window):
        window.wallet.is_billing = False

    def show_disclaimer(self, wizard):
        wizard.set_icon(':icons/trustedcoin-wizard.png')
        wizard.stack = []
        wizard.confirm_dialog(title='Disclaimer', message='\n\n'.join(self.disclaimer_msg), run_next = lambda x: wizard.run('choose_seed'))

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
        f = lambda x: wizard.request_passphrase(seed, x)
        wizard.show_seed_dialog(run_next=f, seed_text=seed)

    @classmethod
    def get_xkeys(self, seed, passphrase, derivation):
        from electrum.mnemonic import Mnemonic
        from electrum.keystore import bip32_root, bip32_private_derivation
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase)
        xprv, xpub = bip32_root(bip32_seed, 'standard')
        xprv, xpub = bip32_private_derivation(xprv, "m/", derivation)
        return xprv, xpub

    @classmethod
    def xkeys_from_seed(self, seed, passphrase):
        words = seed.split()
        n = len(words)
        # old version use long seed phrases
        if n >= 20:
            # note: pre-2.7 2fa seeds were typically 24-25 words, however they
            # could probabilistically be arbitrarily shorter due to a bug. (see #3611)
            # the probability of it being < 20 words is about 2^(-(256+12-19*11)) = 2^(-59)
            assert passphrase == ''
            xprv1, xpub1 = self.get_xkeys(' '.join(words[0:12]), '', "m/")
            xprv2, xpub2 = self.get_xkeys(' '.join(words[12:]), '', "m/")
        elif n==12:
            xprv1, xpub1 = self.get_xkeys(seed, passphrase, "m/0'/")
            xprv2, xpub2 = self.get_xkeys(seed, passphrase, "m/1'/")
        else:
            raise Exception('unrecognized seed length: {} words'.format(n))
        return xprv1, xpub1, xprv2, xpub2

    def create_keystore(self, wizard, seed, passphrase):
        # this overloads the wizard's method
        xprv1, xpub1, xprv2, xpub2 = self.xkeys_from_seed(seed, passphrase)
        k1 = keystore.from_xprv(xprv1)
        k2 = keystore.from_xpub(xpub2)
        wizard.request_password(run_next=lambda pw, encrypt: self.on_password(wizard, pw, encrypt, k1, k2))

    def on_password(self, wizard, password, encrypt_storage, k1, k2):
        k1.update_password(None, password)
        wizard.storage.set_keystore_encryption(bool(password))
        if encrypt_storage:
            wizard.storage.set_password(password, enc_version=STO_EV_USER_PW)
        wizard.storage.put('x1/', k1.dump())
        wizard.storage.put('x2/', k2.dump())
        wizard.storage.write()
        self.go_online_dialog(wizard)

    def restore_wallet(self, wizard):
        wizard.opt_bip39 = False
        wizard.opt_ext = True
        title = _("Restore two-factor Wallet")
        f = lambda seed, is_bip39, is_ext: wizard.run('on_restore_seed', seed, is_ext)
        wizard.restore_seed_dialog(run_next=f, test=self.is_valid_seed)

    def on_restore_seed(self, wizard, seed, is_ext):
        f = lambda x: self.restore_choice(wizard, seed, x)
        wizard.passphrase_dialog(run_next=f) if is_ext else f('')

    def restore_choice(self, wizard, seed, passphrase):
        wizard.set_icon(':icons/trustedcoin-wizard.png')
        wizard.stack = []
        title = _('Restore 2FA wallet')
        msg = ' '.join([
            'You are going to restore a wallet protected with two-factor authentication.',
            'Do you want to keep using two-factor authentication with this wallet,',
            'or do you want to disable it, and have two master private keys in your wallet?'
        ])
        choices = [('keep', 'Keep'), ('disable', 'Disable')]
        f = lambda x: self.on_choice(wizard, seed, passphrase, x)
        wizard.choice_dialog(choices=choices, message=msg, title=title, run_next=f)

    def on_choice(self, wizard, seed, passphrase, x):
        if x == 'disable':
            f = lambda pw, encrypt: wizard.run('on_restore_pw', seed, passphrase, pw, encrypt)
            wizard.request_password(run_next=f)
        else:
            self.create_keystore(wizard, seed, passphrase)

    def on_restore_pw(self, wizard, seed, passphrase, password, encrypt_storage):
        storage = wizard.storage
        xprv1, xpub1, xprv2, xpub2 = self.xkeys_from_seed(seed, passphrase)
        k1 = keystore.from_xprv(xprv1)
        k2 = keystore.from_xprv(xprv2)
        k1.add_seed(seed)
        k1.update_password(None, password)
        k2.update_password(None, password)
        storage.put('x1/', k1.dump())
        storage.put('x2/', k2.dump())
        long_user_id, short_id = get_user_id(storage)
        xpub3 = make_xpub(get_signing_xpub(), long_user_id)
        k3 = keystore.from_xpub(xpub3)
        storage.put('x3/', k3.dump())

        storage.set_keystore_encryption(bool(password))
        if encrypt_storage:
            storage.set_password(password, enc_version=STO_EV_USER_PW)

        wizard.wallet = Wallet_2fa(storage)
        wizard.create_addresses()


    def create_remote_key(self, email, wizard):
        xpub1 = wizard.storage.get('x1/')['xpub']
        xpub2 = wizard.storage.get('x2/')['xpub']
        # Generate third key deterministically.
        long_user_id, short_id = get_user_id(wizard.storage)
        xpub3 = make_xpub(get_signing_xpub(), long_user_id)
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
                wizard.show_message(str(e))
                return
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
        self.request_otp_dialog(wizard, short_id, otp_secret, xpub3)

    def check_otp(self, wizard, short_id, otp_secret, xpub3, otp, reset):
        if otp:
            self.do_auth(wizard, short_id, otp, xpub3)
        elif reset:
            wizard.opt_bip39 = False
            wizard.opt_ext = True
            f = lambda seed, is_bip39, is_ext: wizard.run('on_reset_seed', short_id, seed, is_ext, xpub3)
            wizard.restore_seed_dialog(run_next=f, test=self.is_valid_seed)

    def on_reset_seed(self, wizard, short_id, seed, is_ext, xpub3):
        f = lambda passphrase: wizard.run('on_reset_auth', short_id, seed, passphrase, xpub3)
        wizard.passphrase_dialog(run_next=f) if is_ext else f('')

    def do_auth(self, wizard, short_id, otp, xpub3):
        try:
            server.auth(short_id, otp)
        except Exception as e:
            wizard.show_message(str(e))
            return
        k3 = keystore.from_xpub(xpub3)
        wizard.storage.put('x3/', k3.dump())
        wizard.storage.put('use_trustedcoin', True)
        wizard.storage.write()
        wizard.wallet = Wallet_2fa(wizard.storage)
        wizard.run('create_addresses')

    def on_reset_auth(self, wizard, short_id, seed, passphrase, xpub3):
        xprv1, xpub1, xprv2, xpub2 = self.xkeys_from_seed(seed, passphrase)
        try:
            assert xpub1 == wizard.storage.get('x1/')['xpub']
            assert xpub2 == wizard.storage.get('x2/')['xpub']
        except:
            wizard.show_message(_('Incorrect seed'))
            return
        r = server.get_challenge(short_id)
        challenge = r.get('challenge')
        message = 'TRUSTEDCOIN CHALLENGE: ' + challenge
        def f(xprv):
            _, _, _, _, c, k = deserialize_xprv(xprv)
            pk = bip32_private_key([0, 0], k, c)
            key = ecc.ECPrivkey(pk)
            sig = key.sign_message(message, True)
            return base64.b64encode(sig).decode()

        signatures = [f(x) for x in [xprv1, xprv2]]
        r = server.reset_auth(short_id, challenge, signatures)
        new_secret = r.get('otp_secret')
        if not new_secret:
            wizard.show_message(_('Request rejected by server'))
            return
        self.request_otp_dialog(wizard, short_id, new_secret, xpub3)

    @hook
    def get_action(self, storage):
        if storage.get('wallet_type') != '2fa':
            return
        if not storage.get('x1/'):
            return self, 'show_disclaimer'
        if not storage.get('x2/'):
            return self, 'show_disclaimer'
        if not storage.get('x3/'):
            return self, 'accept_terms_of_use'
