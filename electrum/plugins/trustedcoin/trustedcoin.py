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

import json
import time
import hashlib
from typing import Dict, Union, Sequence, List, TYPE_CHECKING
from urllib.parse import urljoin
from urllib.parse import quote

from aiohttp import ClientResponse

from electrum import ecc, constants, keystore, version, bip32, bitcoin
from electrum.bip32 import BIP32Node, xpub_type
from electrum.crypto import sha256
from electrum.transaction import PartialTxOutput, PartialTxInput, PartialTransaction, Transaction
from electrum.mnemonic import Mnemonic, calc_seed_type, is_any_2fa_seed_type
from electrum.wallet import Multisig_Wallet, Deterministic_Wallet
from electrum.i18n import _
from electrum.plugin import BasePlugin, hook
from electrum.util import NotEnoughFunds, UserFacingException, error_text_str_to_safe_str
from electrum.network import Network
from electrum.logging import Logger

if TYPE_CHECKING:
    from electrum.wizard import NewWalletWizard


def get_signing_xpub(xtype):
    if not constants.net.TESTNET:
        xpub = "xpub661MyMwAqRbcGnMkaTx2594P9EDuiEqMq25PM2aeG6UmwzaohgA6uDmNsvSUV8ubqwA3Wpste1hg69XHgjUuCD5HLcEp2QPzyV1HMrPppsL"
    else:
        xpub = "tpubD6NzVbkrYhZ4XdmyJQcCPjQfg6RXVUzGFhPjZ7uvRC8JLcS7Hw1i7UTpyhp9grHpak4TyK2hzBJrujDVLXQ6qB5tNpVx9rC6ixijUXadnmY"
    if xtype not in ('standard', 'p2wsh'):
        raise NotImplementedError('xtype: {}'.format(xtype))
    if xtype == 'standard':
        return xpub
    node = BIP32Node.from_xkey(xpub)
    return node._replace(xtype=xtype).to_xpub()


def get_billing_xpub():
    if constants.net.TESTNET:
        return "tpubD6NzVbkrYhZ4X11EJFTJujsYbUmVASAYY7gXsEt4sL97AMBdypiH1E9ZVTpdXXEy3Kj9Eqd1UkxdGtvDt5z23DKsh6211CfNJo8bLLyem5r"
    else:
        return "xpub6DTBdtBB8qUmH5c77v8qVGVoYk7WjJNpGvutqjLasNG1mbux6KsojaLrYf2sRhXAVU4NaFuHhbD9SvVPRt1MB1MaMooRuhHcAZH1yhQ1qDU"


DESKTOP_DISCLAIMER = [
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
DISCLAIMER = DESKTOP_DISCLAIMER

MOBILE_DISCLAIMER = [
    _("Two-factor authentication is a service provided by TrustedCoin. "
      "To use it, you must have a separate device with Google Authenticator."),
    _("This service uses a multi-signature wallet, where you own 2 of 3 keys.  "
      "The third key is stored on a remote server that signs transactions on "
      "your behalf. A small fee will be charged on each transaction that uses the "
      "remote server."),
    _("Note that your coins are not locked in this service.  You may withdraw "
      "your funds at any time and at no cost, without the remote server, by "
      "using the 'restore wallet' option with your wallet seed."),
]

RESTORE_MSG = _("Enter the seed for your 2-factor wallet:")


class TrustedCoinException(Exception):
    def __init__(self, message, *, status_code=0):
        # note: 'message' is arbitrary text coming from the server
        safer_message = (
            f"Received error from 2FA server\n"
            f"[DO NOT TRUST THIS MESSAGE]:\n\n"
            f"status_code={status_code}\n\n"
            f"{error_text_str_to_safe_str(message)}")
        Exception.__init__(self, safer_message)
        self.status_code = status_code


class ErrorConnectingServer(Exception):
    def __init__(self, reason: Union[str, Exception] = None):
        self.reason = reason

    def __str__(self):
        header = _("Error connecting to {} server").format('TrustedCoin')
        reason = self.reason
        if isinstance(reason, BaseException):
            reason = repr(reason)
        return f"{header}:\n{reason}" if reason else header


class TrustedCoinCosignerClient(Logger):
    def __init__(self, user_agent=None, base_url='https://api.trustedcoin.com/2/'):
        self.base_url = base_url
        self.debug = False
        self.user_agent = user_agent
        Logger.__init__(self)

    async def handle_response(self, resp: ClientResponse):
        if resp.status != 200:
            try:
                r = await resp.json()
                message = r['message']
            except Exception:
                message = await resp.text()
            raise TrustedCoinException(message, status_code=resp.status)
        try:
            return await resp.json()
        except Exception:
            return await resp.text()

    def send_request(self, method, relative_url, data=None, *, timeout=None):
        network = Network.get_instance()
        if not network:
            raise ErrorConnectingServer('You are offline.')
        url = urljoin(self.base_url, relative_url)
        if self.debug:
            self.logger.debug(f'<-- {method} {url} {data}')
        headers = {}
        if self.user_agent:
            headers['user-agent'] = self.user_agent
        try:
            if method == 'get':
                response = Network.send_http_on_proxy(method, url,
                                                      params=data,
                                                      headers=headers,
                                                      on_finish=self.handle_response,
                                                      timeout=timeout)
            elif method == 'post':
                response = Network.send_http_on_proxy(method, url,
                                                      json=data,
                                                      headers=headers,
                                                      on_finish=self.handle_response,
                                                      timeout=timeout)
            else:
                raise Exception(f"unexpected {method=!r}")
        except TrustedCoinException:
            raise
        except Exception as e:
            raise ErrorConnectingServer(e)
        else:
            if self.debug:
                self.logger.debug(f'--> {response}')
            return response

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
        return self.send_request('post', 'cosigner/%s/sign' % quote(id), payload,
                                 timeout=60)


server = TrustedCoinCosignerClient(user_agent="Electrum/" + version.ELECTRUM_VERSION)


class Wallet_2fa(Multisig_Wallet):
    plugin: 'TrustedCoinPlugin'
    wallet_type = '2fa'

    def __init__(self, db, *, config):
        self.m, self.n = 2, 3
        Deterministic_Wallet.__init__(self, db, config=config)
        self.is_billing = False
        self.billing_info = None
        self._load_billing_addresses()

    def _load_billing_addresses(self):
        billing_addresses = {
            'legacy': self.db.get('trustedcoin_billing_addresses', {}),
            'segwit': self.db.get('trustedcoin_billing_addresses_segwit', {})
        }
        self._billing_addresses = {}  # type: Dict[str, Dict[int, str]]  # addr_type -> index -> addr
        self._billing_addresses_set = set()  # set of addrs
        for addr_type, d in list(billing_addresses.items()):
            self._billing_addresses[addr_type] = {}
            # convert keys from str to int
            for index, addr in d.items():
                self._billing_addresses[addr_type][int(index)] = addr
                self._billing_addresses_set.add(addr)

    def can_sign_without_server(self):
        return not self.keystores['x2'].is_watching_only()

    def get_user_id(self):
        return get_user_id(self.db)

    def min_prepay(self):
        return min(self.price_per_tx.keys())

    def num_prepay(self):
        default_fallback = self.min_prepay()
        num = self.config.PLUGIN_TRUSTEDCOIN_NUM_PREPAY
        if num not in self.price_per_tx:
            num = default_fallback
        return num

    def extra_fee(self):
        if self.can_sign_without_server():
            return 0
        if self.billing_info is None:
            self.plugin.start_request_thread(self)
            return 0
        if self.billing_info.get('tx_remaining'):
            return 0
        if self.is_billing:
            return 0
        n = self.num_prepay()
        price = int(self.price_per_tx[n])
        # sanity check: price capped at 0.5 mBTC per tx or 20 mBTC total
        #               (note that the server can influence our choice of n by sending unexpected values)
        if price > min(50_000 * n, 2_000_000):
            raise Exception(f"too high trustedcoin fee ({price} for {n} txns)")
        return price

    def make_unsigned_transaction(
            self, *,
            outputs: List[PartialTxOutput],
            is_sweep=False,
            **kwargs,
    ) -> PartialTransaction:

        mk_tx = lambda o: Multisig_Wallet.make_unsigned_transaction(
            self, outputs=o, **kwargs)
        extra_fee = self.extra_fee() if not is_sweep else 0
        if extra_fee:
            address = self.billing_info['billing_address_segwit']
            fee_output = PartialTxOutput.from_address_and_value(address, extra_fee)
            try:
                tx = mk_tx(outputs + [fee_output])
            except NotEnoughFunds:
                # TrustedCoin won't charge if the total inputs is
                # lower than their fee
                tx = mk_tx(outputs)
                if tx.input_value() >= extra_fee:
                    raise
                self.logger.info("not charging for this tx")
        else:
            tx = mk_tx(outputs)
        return tx

    def on_otp(self, tx: PartialTransaction, otp):
        if not otp:
            self.logger.info("sign_transaction: no auth code")
            return
        otp = int(otp)
        long_user_id, short_id = self.get_user_id()
        raw_tx = tx.serialize_as_bytes().hex()
        assert raw_tx[:10] == "70736274ff", f"bad magic. {raw_tx[:10]}"
        try:
            r = server.sign(short_id, raw_tx, otp)
        except TrustedCoinException as e:
            if e.status_code == 400:  # invalid OTP
                raise UserFacingException(_('Invalid one-time password.')) from e
            else:
                raise
        if r:
            received_raw_tx = r.get('transaction')
            received_tx = Transaction(received_raw_tx)
            tx.combine_with_other_psbt(received_tx)
        self.logger.info(f"twofactor: is complete {tx.is_complete()}")
        # reset billing_info
        self.billing_info = None
        self.plugin.start_request_thread(self)

    def add_new_billing_address(self, billing_index: int, address: str, addr_type: str):
        billing_addresses_of_this_type = self._billing_addresses[addr_type]
        saved_addr = billing_addresses_of_this_type.get(billing_index)
        if saved_addr is not None:
            if saved_addr == address:
                return  # already saved this address
            else:
                raise Exception('trustedcoin billing address inconsistency.. '
                                'for index {}, already saved {}, now got {}'
                                .format(billing_index, saved_addr, address))
        # do we have all prior indices? (are we synced?)
        largest_index_we_have = max(billing_addresses_of_this_type) if billing_addresses_of_this_type else -1
        if largest_index_we_have + 1 < billing_index:  # need to sync
            for i in range(largest_index_we_have + 1, billing_index):
                addr = make_billing_address(self, i, addr_type=addr_type)
                billing_addresses_of_this_type[i] = addr
                self._billing_addresses_set.add(addr)
        # save this address; and persist to disk
        billing_addresses_of_this_type[billing_index] = address
        self._billing_addresses_set.add(address)
        self._billing_addresses[addr_type] = billing_addresses_of_this_type
        self.db.put('trustedcoin_billing_addresses', self._billing_addresses['legacy'])
        self.db.put('trustedcoin_billing_addresses_segwit', self._billing_addresses['segwit'])

    def is_billing_address(self, addr: str) -> bool:
        return addr in self._billing_addresses_set


# Utility functions

def get_user_id(db):
    def make_long_id(xpub_hot, xpub_cold):
        return sha256(''.join(sorted([xpub_hot, xpub_cold])))
    xpub1 = db.get('x1')['xpub']
    xpub2 = db.get('x2')['xpub']
    long_id = make_long_id(xpub1, xpub2)
    short_id = hashlib.sha256(long_id).hexdigest()
    return long_id, short_id


def make_xpub(xpub, s) -> str:
    rootnode = BIP32Node.from_xkey(xpub)
    child_pubkey, child_chaincode = bip32._CKD_pub(parent_pubkey=rootnode.eckey.get_public_key_bytes(compressed=True),
                                                   parent_chaincode=rootnode.chaincode,
                                                   child_index=s)
    child_node = BIP32Node(xtype=rootnode.xtype,
                           eckey=ecc.ECPubkey(child_pubkey),
                           chaincode=child_chaincode)
    return child_node.to_xpub()


def make_billing_address(wallet, num, addr_type):
    long_id, short_id = wallet.get_user_id()
    xpub = make_xpub(get_billing_xpub(), long_id)
    usernode = BIP32Node.from_xkey(xpub)
    child_node = usernode.subkey_at_public_derivation([num])
    pubkey = child_node.eckey.get_public_key_bytes(compressed=True)
    if addr_type == 'legacy':
        return bitcoin.public_key_to_p2pkh(pubkey)
    elif addr_type == 'segwit':
        return bitcoin.public_key_to_p2wpkh(pubkey)
    else:
        raise ValueError(f'unexpected billing type: {addr_type}')


class TrustedCoinPlugin(BasePlugin):
    wallet_class = Wallet_2fa
    disclaimer_msg = DISCLAIMER

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallet_class.plugin = self
        self.requesting = False

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
        if not wallet.keystores['x3'].can_sign(tx, ignore_watching_only=True):
            self.logger.info("twofactor: xpub3 not needed")
            return
        def wrapper(tx):
            assert tx
            self.prompt_user_for_otp(wallet, tx, on_success, on_failure)
        return wrapper

    def prompt_user_for_otp(self, wallet, tx, on_success, on_failure) -> None:
        raise NotImplementedError()

    @hook
    def get_tx_extra_fee(self, wallet, tx: Transaction):
        if type(wallet) != Wallet_2fa:
            return
        for o in tx.outputs():
            if wallet.is_billing_address(o.address):
                return o.address, o.value

    def finish_requesting(func):
        def f(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            finally:
                self.requesting = False
        return f

    @finish_requesting
    def request_billing_info(self, wallet: 'Wallet_2fa', *, suppress_connection_error=True):
        if wallet.can_sign_without_server():
            return
        self.logger.info("request billing info")
        try:
            billing_info = server.get(wallet.get_user_id()[1])
        except ErrorConnectingServer as e:
            if suppress_connection_error:
                self.logger.info(repr(e))
                return
            raise
        billing_index = billing_info['billing_index']
        # add segwit billing address; this will be used for actual billing
        billing_address = make_billing_address(wallet, billing_index, addr_type='segwit')
        if billing_address != billing_info['billing_address_segwit']:
            raise Exception(f'unexpected trustedcoin billing address: '
                            f'calculated {billing_address}, received {billing_info["billing_address_segwit"]}')
        wallet.add_new_billing_address(billing_index, billing_address, addr_type='segwit')
        # also add legacy billing address; only used for detecting past payments in GUI
        billing_address = make_billing_address(wallet, billing_index, addr_type='legacy')
        wallet.add_new_billing_address(billing_index, billing_address, addr_type='legacy')

        wallet.billing_info = billing_info
        wallet.price_per_tx = dict(billing_info['price_per_tx'])
        wallet.price_per_tx.pop(1, None)
        self.billing_info_retrieved(wallet)
        return True

    def billing_info_retrieved(self, wallet):
        # override to handle billing info when it becomes available
        pass

    def start_request_thread(self, wallet):
        from threading import Thread
        if self.requesting is False:
            self.requesting = True
            t = Thread(target=self.request_billing_info, args=(wallet,))
            t.daemon = True
            t.start()
            return t

    def make_seed(self, seed_type):
        if not is_any_2fa_seed_type(seed_type):
            raise Exception(f'unexpected seed type: {seed_type!r}')
        return Mnemonic('english').make_seed(seed_type=seed_type)

    @hook
    def do_clear(self, window):
        window.wallet.is_billing = False

    @classmethod
    def get_xkeys(self, seed, t, passphrase, derivation):
        assert is_any_2fa_seed_type(t)
        xtype = 'standard' if t == '2fa' else 'p2wsh'
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase=passphrase)
        rootnode = BIP32Node.from_rootseed(bip32_seed, xtype=xtype)
        child_node = rootnode.subkey_at_private_derivation(derivation)
        return child_node.to_xprv(), child_node.to_xpub()

    @classmethod
    def xkeys_from_seed(self, seed, passphrase):
        t = calc_seed_type(seed)
        if not is_any_2fa_seed_type(t):
            raise Exception(f'unexpected seed type: {t!r}')
        words = seed.split()
        n = len(words)
        if t == '2fa':
            if n >= 20:  # old scheme
                # note: pre-2.7 2fa seeds were typically 24-25 words, however they
                # could probabilistically be arbitrarily shorter due to a bug. (see #3611)
                # the probability of it being < 20 words is about 2^(-(256+12-19*11)) = 2^(-59)
                if passphrase:
                    raise Exception("old '2fa'-type electrum seed cannot have passphrase")
                xprv1, xpub1 = self.get_xkeys(' '.join(words[0:12]), t, '', "m/")
                xprv2, xpub2 = self.get_xkeys(' '.join(words[12:]), t, '', "m/")
            elif n == 12:  # new scheme
                xprv1, xpub1 = self.get_xkeys(seed, t, passphrase, "m/0'/")
                xprv2, xpub2 = self.get_xkeys(seed, t, passphrase, "m/1'/")
            else:
                raise Exception(f'unrecognized seed length for "2fa" seed: {n}')
        elif t == '2fa_segwit':
            xprv1, xpub1 = self.get_xkeys(seed, t, passphrase, "m/0'/")
            xprv2, xpub2 = self.get_xkeys(seed, t, passphrase, "m/1'/")
        else:
            raise Exception(f'unexpected seed type: {t!r}')
        return xprv1, xpub1, xprv2, xpub2

    @hook
    def get_action(self, db):
        if db.get('wallet_type') != '2fa':
            return
        if not db.get('x1'):
            return self, 'show_disclaimer'
        if not db.get('x2'):
            return self, 'show_disclaimer'
        if not db.get('x3'):
            return self, 'accept_terms_of_use'

    # insert trustedcoin pages in new wallet wizard
    def extend_wizard(self, wizard: 'NewWalletWizard'):
        views = {
            'trustedcoin_start': {
                'next': 'trustedcoin_choose_seed',
            },
            'trustedcoin_choose_seed': {
                'next': lambda d: 'trustedcoin_create_seed' if d['keystore_type'] == 'createseed'
                        else 'trustedcoin_have_seed'
            },
            'trustedcoin_create_seed': {
                'next': 'trustedcoin_confirm_seed'
            },
            'trustedcoin_confirm_seed': {
                'next': 'trustedcoin_tos'
            },
            'trustedcoin_have_seed': {
                'next': 'trustedcoin_keep_disable'
            },
            'trustedcoin_keep_disable': {
                'next': lambda d: 'trustedcoin_tos' if d['trustedcoin_keepordisable'] != 'disable'
                        else 'wallet_password',
                'accept': self.recovery_disable,
                'last': lambda d: wizard.is_single_password() and d['trustedcoin_keepordisable'] == 'disable'
            },
            'trustedcoin_tos': {
                'next': 'trustedcoin_show_confirm_otp'
            },
            'trustedcoin_show_confirm_otp': {
                'accept': self.on_accept_otp_secret,
                'next': 'wallet_password',
                'last': lambda d: wizard.is_single_password() or 'xprv1' in d
            }
        }
        wizard.navmap_merge(views)

    # combined create_keystore and create_remote_key pre
    def create_keys(self, wizard_data):
        if 'seed' not in wizard_data:
            # online continuation
            xprv1, xpub1, xprv2, xpub2 = (wizard_data['xprv1'], wizard_data['xpub1'], None, wizard_data['xpub2'])
        else:
            xprv1, xpub1, xprv2, xpub2 = self.xkeys_from_seed(wizard_data['seed'], wizard_data['seed_extra_words'])

        data = {'x1': {'xpub': xpub1}, 'x2': {'xpub': xpub2}}

        # Generate third key deterministically.
        long_user_id, short_id = get_user_id(data)
        xtype = xpub_type(xpub1)
        xpub3 = make_xpub(get_signing_xpub(xtype), long_user_id)

        return xprv1, xpub1, xprv2, xpub2, xpub3, short_id

    def on_accept_otp_secret(self, wizard_data):
        self.logger.debug('OTP secret accepted, creating keystores')
        xprv1, xpub1, xprv2, xpub2, xpub3, short_id = self.create_keys(wizard_data)
        k1 = keystore.from_xprv(xprv1)
        k2 = keystore.from_xpub(xpub2)
        k3 = keystore.from_xpub(xpub3)

        wizard_data['x1'] = k1.dump()
        wizard_data['x2'] = k2.dump()
        wizard_data['x3'] = k3.dump()

    def recovery_disable(self, wizard_data):
        if wizard_data['trustedcoin_keepordisable'] != 'disable':
            return

        self.logger.debug('2fa disabled, creating keystores')
        xprv1, xpub1, xprv2, xpub2, xpub3, short_id = self.create_keys(wizard_data)
        k1 = keystore.from_xprv(xprv1)
        k2 = keystore.from_xprv(xprv2)
        k3 = keystore.from_xpub(xpub3)

        wizard_data['x1'] = k1.dump()
        wizard_data['x2'] = k2.dump()
        wizard_data['x3'] = k3.dump()

