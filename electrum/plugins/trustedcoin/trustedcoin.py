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
from typing import Optional, Sequence, Tuple, Union, TYPE_CHECKING

import electrum_ecc as ecc

from electrum import constants, cosigner, descriptor, keystore, bip32
from electrum.bip32 import BIP32Node, xpub_type, is_xprv, is_xpub
from electrum.crypto import sha256
from electrum.mnemonic import Mnemonic, calc_seed_type, is_any_2fa_seed_type
from electrum.transaction import (PartialTransaction, PartialTxInput, PartialTxOutput, Sighash,
                                  tx_from_any)
from electrum.wallet import Multisig_Wallet, Deterministic_Wallet
from electrum.i18n import _
from electrum.plugin import BasePlugin
from electrum.keystore import KeyStore

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
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


# The mobile app does not need a wallet in order to cosign: it stores the keys
# of the wallets it cosigns for in its config file. Transactions to be cosigned
# are prefixed, so that the mobile app knows to look them up there.
PSBT_QR_PREFIX = '2fa:'


def make_psbt_qr_data(tx: PartialTransaction) -> str:
    qr_data, __ = tx.to_qr_data()
    return PSBT_QR_PREFIX + qr_data


def parse_psbt_qr_data(data: str) -> PartialTransaction:
    """Returns the transaction to be cosigned. Raises ValueError."""
    if not data.startswith(PSBT_QR_PREFIX):
        raise ValueError('not a 2fa transaction QR code')
    try:
        tx = tx_from_any(data[len(PSBT_QR_PREFIX):])
    except Exception as e:
        raise ValueError(f'could not parse transaction: {e}') from e
    if not isinstance(tx, PartialTransaction):
        raise ValueError('not a partially signed transaction')
    return tx


def get_cosigner_id(xpub2: str) -> str:
    """A cosigner is indexed by the fingerprint its key uses in transactions."""
    return keystore.from_xpub(xpub2).get_root_fingerprint()


def add_cosigner(config: 'SimpleConfig', *, xprv2: str, xpub1: str, xpub3: str, password: str) -> None:
    """Stores the keys of a 2fa wallet."""
    xpub2 = keystore.from_xprv(xprv2).get_master_public_key()
    cosigner.add_cosigner(
        config, get_cosigner_id(xpub2),
        {'xpub1': xpub1, 'xpub2': xpub2, 'xpub3': xpub3, 'xprv2': xprv2},
        password)


def find_cosigner_for_tx(config: 'SimpleConfig', tx: PartialTransaction, password: str) -> Optional[dict]:
    """Returns the keys of the 2fa wallet that transaction needs, None if this device
    does not cosign for it. Raises InvalidPassword.
    """
    fingerprints = {fp.hex() for txin in tx.inputs() for fp, __ in txin.bip32_paths.values()}
    for cosigner_id in cosigner.get_cosigner_ids(config):
        if cosigner_id not in fingerprints:
            continue
        keys = cosigner.get_cosigner(config, cosigner_id, password)
        if get_cosigner_id(keys['xpub2']) != cosigner_id:
            raise ValueError(f'cosigner {cosigner_id} does not match its keys')
        return keys
    return None


def _get_script_descriptor(keys: dict, der_suffix: Sequence[int]) -> descriptor.Descriptor:
    keystores = [keystore.from_xpub(keys[name]) for name in ['xpub1', 'xpub2', 'xpub3']]
    pubkeys = [ks.get_pubkey_provider(der_suffix) for ks in keystores]
    multi = descriptor.MultisigDescriptor(pubkeys=pubkeys, thresh=2, is_sorted=True)
    if xpub_type(keys['xpub1']) == 'standard':
        return descriptor.SHDescriptor(subdescriptor=multi)
    return descriptor.WSHDescriptor(subdescriptor=multi)


def claims_wallet_key(keys: dict, txinout: Union[PartialTxInput, PartialTxOutput]) -> bool:
    """Whether the transaction says that input or output uses a key of the 2fa wallet."""
    ks = keystore.from_xpub(keys['xpub2'])
    return ks.find_my_pubkey_in_txinout(txinout)[0] is not None


def _get_wallet_script(
        keys: dict,
        txinout: Union[PartialTxInput, PartialTxOutput],
) -> Optional[descriptor.Descriptor]:
    """The script of the 2fa wallet for that input or output, None if it does not belong to it.
    The derivation found in the transaction is only a hint: whoever created the transaction can
    claim one of our keys for a script they own, so the script is recomputed from the xpubs.
    """
    ks = keystore.from_xpub(keys['xpub2'])
    __, der_suffix = ks.find_my_pubkey_in_txinout(txinout, only_der_suffix=True)
    if der_suffix is None:
        return None
    desc = _get_script_descriptor(keys, der_suffix)
    return desc if txinout.scriptpubkey == desc.expand().output_script else None


def is_wallet_output(keys: dict, txout: PartialTxOutput) -> bool:
    """Whether that output pays back to the 2fa wallet."""
    return _get_wallet_script(keys, txout) is not None


def add_wallet_info_to_tx(tx: PartialTransaction, keys: dict) -> None:
    """Adds the scripts of the 2fa wallet, which a signer would otherwise get from its
    wallet. Raises ValueError if the transaction cannot be verified.
    """
    for txin in tx.inputs():
        if not claims_wallet_key(keys, txin):
            continue
        desc = _get_wallet_script(keys, txin)
        if desc is None:
            raise ValueError('input does not spend from this 2fa wallet')
        txin.script_descriptor = desc
        if txin.witness or txin.script_sig:
            # those fields decide how the input is signed, so a transaction that carries
            # them could choose the sighash algorithm our key signs under
            raise ValueError('input is already finalized')
        if not desc.is_segwit() and txin.utxo is None:
            # the signature of a non-segwit input does not commit to its amount. Without
            # the previous transaction we cannot know it, and the fee could be anything.
            # note: we ask the script we recomputed, as txin.is_segwit() believes the
            # witness field of the transaction, which is not ours.
            raise ValueError('missing previous transaction of a non-segwit input')
        if txin.sighash is not None and txin.sighash != Sighash.ALL:
            # with SIGHASH_NONE or ANYONECANPAY, our signature would not commit to the
            # outputs of the transaction, which could then be changed after we signed
            raise ValueError(f'non-default sighash type: {txin.sighash}')
    if tx.get_fee() is None:
        # the amount of an input is unknown, so we cannot tell what the transaction pays
        raise ValueError('unknown fee')


def sign_tx(tx: PartialTransaction, keys: dict) -> None:
    """Signs the transaction with the key of the cosigner. Raises ValueError if the
    transaction cannot be verified."""
    add_wallet_info_to_tx(tx, keys)
    keystore.from_xprv(keys['xprv2']).sign_transaction(tx, None)


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
                'next': 'trustedcoin_have_seed',
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
            # show xprv2 to the mobile cosigner, keep xprv1
            'trustedcoin_show_cosigner_qr': {
                'accept': self.on_accept_cosigner_qr,
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

    def recovery_disable(self, wizard_data):
        self.logger.debug('2fa disabled, creating keystores')
        xprv1, xpub1, xprv2, xpub2, xpub3 = self.create_keys(wizard_data)
        wizard_data.update({'x1': xprv1, 'x2': xprv2, 'x3': xpub3})
