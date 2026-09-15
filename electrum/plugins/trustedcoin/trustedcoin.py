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

import hashlib
from typing import Tuple, TYPE_CHECKING

import electrum_ecc as ecc

from electrum import constants, keystore, bip32
from electrum.bip32 import BIP32Node, xpub_type, is_xprv, is_xpub
from electrum.crypto import sha256
from electrum.mnemonic import Mnemonic, calc_seed_type, is_any_2fa_seed_type
from electrum.wallet import Multisig_Wallet, Deterministic_Wallet
from electrum.i18n import _
from electrum.plugin import BasePlugin
from electrum.keystore import KeyStore

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


DESKTOP_DISCLAIMER = [
    _("The two-factor authentication service of TrustedCoin has been discontinued. "
      "Your coins are not locked: they can be recovered with your 2FA seed."),
    _("A 2FA wallet is a multi-signature wallet, where two of the three keys are derived from your seed. "
      "You may keep using two-factor authentication, with the Electrum app on your phone as cosigner: "
      "this computer will hold the first key, and your phone will hold the second key."),
    _("Alternatively, you may disable two-factor authentication, and have both keys in this wallet."),
]
DISCLAIMER = DESKTOP_DISCLAIMER

MOBILE_DISCLAIMER = [
    _("The two-factor authentication service of TrustedCoin has been discontinued. "
      "Your coins are not locked: they can be recovered with your 2FA seed."),
    _("To use this device as the cosigner of a 2FA wallet on Electrum desktop, "
      "restore your 2FA seed on desktop, and scan the QR code it displays."),
    _("Alternatively, you may restore your 2FA seed on this device, with two-factor authentication disabled."),
]


# The desktop wizard displays the second master private key in a QR code,
# along with the two other master public keys, for the mobile app to scan.
COSIGNER_QR_PREFIX = '2fa_cosigner:'


def make_cosigner_qr_data(xprv2: str, xpub1: str, xpub3: str) -> str:
    return COSIGNER_QR_PREFIX + ':'.join([xprv2, xpub1, xpub3])


def parse_cosigner_qr_data(data: str) -> Tuple[str, str, str]:
    """Returns (xprv2, xpub1, xpub3). Raises ValueError."""
    if not data.startswith(COSIGNER_QR_PREFIX):
        raise ValueError('not a 2fa cosigner QR code')
    keys = data[len(COSIGNER_QR_PREFIX):].split(':')
    if len(keys) != 3:
        raise ValueError('unexpected number of keys in 2fa cosigner QR code')
    xprv2, xpub1, xpub3 = keys
    if not (is_xprv(xprv2) and is_xpub(xpub1) and is_xpub(xpub3)):
        raise ValueError('invalid keys in 2fa cosigner QR code')
    return xprv2, xpub1, xpub3


class Wallet_2fa(Multisig_Wallet):
    plugin: 'TrustedCoinPlugin'
    wallet_type = '2fa'

    def __init__(self, db, *, config):
        self.m, self.n = 2, 3
        if not db.get('x3'):
            # wallet created offline, and never completed online with the TrustedCoin server
            xpub3 = get_xpub3(db.get('x1')['xpub'], db.get('x2')['xpub'])
            db.put('x3', keystore.from_xpub(xpub3).dump())
        Deterministic_Wallet.__init__(self, db, config=config)

    def can_sign_without_cosigner(self) -> bool:
        return not self.keystores['x1'].is_watching_only() and not self.keystores['x2'].is_watching_only()

    def can_enable_disable_keystore(self, ks: KeyStore) -> bool:
        return False

    def enable_keystore(self, keystore, is_hardware_keystore, password):
        raise Exception("2fa wallet cannot enable keystore")

    def disable_keystore(self, keystore):
        raise Exception("2fa wallet cannot disable keystore")


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


def get_xpub3(xpub1: str, xpub2: str) -> str:
    """The third key is derived from the TrustedCoin signing key."""
    long_user_id, short_id = get_user_id({'x1': {'xpub': xpub1}, 'x2': {'xpub': xpub2}})
    return make_xpub(get_signing_xpub(xpub_type(xpub1)), long_user_id)


class TrustedCoinPlugin(BasePlugin):
    wallet_class = Wallet_2fa

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallet_class.plugin = self

    def is_available(self):
        return True

    def is_enabled(self):
        return True

    def can_user_disable(self):
        return False

    @classmethod
    def get_xkeys(cls, seed, t, passphrase, derivation):
        assert is_any_2fa_seed_type(t)
        xtype = 'standard' if t == '2fa' else 'p2wsh'
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase=passphrase)
        rootnode = BIP32Node.from_rootseed(bip32_seed, xtype=xtype)
        child_node = rootnode.subkey_at_private_derivation(derivation)
        return child_node.to_xprv(), child_node.to_xpub()

    @classmethod
    def xkeys_from_seed(cls, seed, passphrase):
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
                xprv1, xpub1 = cls.get_xkeys(' '.join(words[0:12]), t, '', "m/")
                xprv2, xpub2 = cls.get_xkeys(' '.join(words[12:]), t, '', "m/")
            elif n == 12:  # new scheme
                xprv1, xpub1 = cls.get_xkeys(seed, t, passphrase, "m/0'/")
                xprv2, xpub2 = cls.get_xkeys(seed, t, passphrase, "m/1'/")
            else:
                raise Exception(f'unrecognized seed length for "2fa" seed: {n}')
        elif t == '2fa_segwit':
            xprv1, xpub1 = cls.get_xkeys(seed, t, passphrase, "m/0'/")
            xprv2, xpub2 = cls.get_xkeys(seed, t, passphrase, "m/1'/")
        else:
            raise Exception(f'unexpected seed type: {t!r}')
        return xprv1, xpub1, xprv2, xpub2

    # insert trustedcoin pages in new wallet wizard
    def extend_wizard(self, wizard: 'NewWalletWizard'):
        views = {
            'trustedcoin_start': {
                'next': 'trustedcoin_choose_seed',
            },
            'trustedcoin_choose_seed': {
                'next': lambda d: 'trustedcoin_have_seed' if d['keystore_type'] == 'haveseed'
                        else 'trustedcoin_scan_cosigner_qr',
            },
            'trustedcoin_have_seed': {
                'next': lambda d: 'trustedcoin_have_ext' if wizard.wants_ext(d) else 'trustedcoin_keep_disable',
            },
            'trustedcoin_have_ext': {
                'next': 'trustedcoin_keep_disable',
            },
            'trustedcoin_keep_disable': {
                'next': lambda d: 'trustedcoin_show_cosigner_qr' if d['trustedcoin_keepordisable'] != 'disable'
                        else 'wallet_password',
                'accept': lambda d: self.recovery_disable(d) if d['trustedcoin_keepordisable'] == 'disable' else None,
                'last': lambda d: wizard.is_single_password() and d['trustedcoin_keepordisable'] == 'disable'
            },
            # desktop: show xprv2 to the mobile cosigner, keep xprv1
            'trustedcoin_show_cosigner_qr': {
                'accept': self.on_accept_cosigner_qr,
                'next': 'wallet_password',
                'last': lambda d: wizard.is_single_password()
            },
            # mobile: scan xprv2 from the desktop wizard
            'trustedcoin_scan_cosigner_qr': {
                'accept': self.on_scan_cosigner_qr,
                'next': 'wallet_password',
                'last': lambda d: wizard.is_single_password()
            },
        }
        wizard.navmap_merge(views)

    def create_keys(self, wizard_data) -> Tuple[str, str, str, str, str]:
        seed_extension = wizard_data['seed_extra_words'] if wizard_data['seed_extend'] else ''
        xprv1, xpub1, xprv2, xpub2 = self.xkeys_from_seed(wizard_data['seed'], seed_extension)
        return xprv1, xpub1, xprv2, xpub2, get_xpub3(xpub1, xpub2)

    def on_accept_cosigner_qr(self, wizard_data):
        self.logger.debug('mobile cosigner confirmed, creating keystores')
        xprv1, xpub1, xprv2, xpub2, xpub3 = self.create_keys(wizard_data)
        wizard_data.update({'x1': xprv1, 'x2': xpub2, 'x3': xpub3})

    def on_scan_cosigner_qr(self, wizard_data):
        self.logger.debug('cosigner QR code scanned, creating keystores')
        xprv2, xpub1, xpub3 = parse_cosigner_qr_data(wizard_data['trustedcoin_cosigner_qr'])
        wizard_data.update({'x1': xpub1, 'x2': xprv2, 'x3': xpub3})

    def recovery_disable(self, wizard_data):
        self.logger.debug('2fa disabled, creating keystores')
        xprv1, xpub1, xprv2, xpub2, xpub3 = self.create_keys(wizard_data)
        wizard_data.update({'x1': xprv1, 'x2': xprv2, 'x3': xpub3})
