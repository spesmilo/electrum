# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

"""Keys of the wallets this device cosigns for, stored in the 'keystores' file.

This device can sign for a wallet it does not have: a key is scanned from a QR
code, together with the master public keys of the other cosigners, which are
needed in order to rebuild the scripts of that wallet. What we sign is checked
against those scripts, because the transaction we are given may lie about what
it does.

A cosigner is indexed by the fingerprint that its key uses in transactions (the
root fingerprint of its key origin), so that a transaction can be matched against
that file without decrypting anything. Everything else is encrypted with the
password of the device, so that whoever reads the file cannot derive the addresses
of those wallets, and thus cannot see their history.
"""

import json
import os
import stat
from typing import Dict, List, Optional, Sequence, Union, TYPE_CHECKING

from . import descriptor, keystore
from .bip32 import is_xprv, is_xpub, xpub_type
from .crypto import pw_encode_with_version_and_mac, pw_decode_with_version_and_mac
from .transaction import PartialTransaction, PartialTxInput, PartialTxOutput
from .util import os_chmod

if TYPE_CHECKING:
    from .simple_config import SimpleConfig


KEYSTORES_FILE_NAME = 'keystores'

# The device that holds the other keys of the wallet displays one of them in a
# QR code, for this device to scan.
COSIGNER_QR_PREFIX = 'cosigner:'


class Cosigner:
    """A key this device signs with, and the wallet that key belongs to.

    The wallet is described the way Electrum describes one: the master public keys
    of the other cosigners, and the number of signatures it requires. The type of
    its scripts follows from the header of the master keys ('xpub', 'Ypub', 'Zpub'...).
    """

    def __init__(self, *, xprv: str, xpubs: Sequence[str] = (), m: int = 1):
        self.xprv = xprv
        self.xpubs = list(xpubs)
        self.m = m
        self.keystore = keystore.from_xprv(xprv)
        # the order of the keys does not matter: Electrum sorts them in the script
        self.keystores = [self.keystore] + [keystore.from_xpub(xpub) for xpub in self.xpubs]
        if not 1 <= m <= len(self.keystores):
            raise ValueError(f'{m} signatures for {len(self.keystores)} keys')
        if len({ks.xpub for ks in self.keystores}) != len(self.keystores):
            raise ValueError('duplicate keys')
        if len({xpub_type(ks.xpub) for ks in self.keystores}) != 1:
            raise ValueError('the keys of a wallet must have the same type')

    @classmethod
    def from_qr_data(cls, data: str) -> 'Cosigner':
        """Reads the QR code that sets up this device as cosigner. Raises ValueError."""
        if not data.startswith(COSIGNER_QR_PREFIX):
            raise ValueError('not a cosigner QR code')
        m, __, keys = data[len(COSIGNER_QR_PREFIX):].partition(':')
        xprv, *xpubs = keys.split(':')
        if not (m.isdigit() and is_xprv(xprv) and all(is_xpub(xpub) for xpub in xpubs)):
            raise ValueError('invalid keys in cosigner QR code')
        return cls(xprv=xprv, xpubs=xpubs, m=int(m))

    def to_qr_data(self) -> str:
        """The QR code that sets up another device as cosigner of this wallet."""
        return COSIGNER_QR_PREFIX + ':'.join([str(self.m), self.xprv, *self.xpubs])

    @classmethod
    def from_dict(cls, d: Dict) -> 'Cosigner':
        return cls(xprv=d['xprv'], xpubs=d['xpubs'], m=d['m'])

    def to_dict(self) -> Dict:
        return {'m': self.m, 'xprv': self.xprv, 'xpubs': self.xpubs}

    @property
    def cosigner_id(self) -> str:
        """A cosigner is indexed by the fingerprint its key uses in transactions."""
        return self.keystore.get_root_fingerprint()

    @property
    def script_type(self) -> str:
        # as Standard_Wallet and Multisig_Wallet do, in load_keystore
        xtype = xpub_type(self.keystore.xpub)
        if len(self.keystores) == 1:
            return 'p2pkh' if xtype == 'standard' else xtype
        return 'p2sh' if xtype == 'standard' else xtype

    def get_script_descriptor(self, der_suffix: Sequence[int]) -> descriptor.Descriptor:
        pubkeys = [ks.get_pubkey_provider(der_suffix) for ks in self.keystores]
        return descriptor.from_legacy_electrum_script_type(self.script_type, pubkeys=pubkeys, m=self.m)

    def claims_our_key(self, txinout: Union[PartialTxInput, PartialTxOutput]) -> bool:
        """Whether the transaction says that input or output uses our key."""
        return self.keystore.find_my_pubkey_in_txinout(txinout)[0] is not None

    def get_wallet_script(
            self,
            txinout: Union[PartialTxInput, PartialTxOutput],
    ) -> Optional[descriptor.Descriptor]:
        """The script of the wallet for that input or output, None if it does not belong to it.
        The derivation found in the transaction is only a hint: whoever created the transaction
        can claim our key for a script they own, so the script is recomputed from the keys.
        """
        __, der_suffix = self.keystore.find_my_pubkey_in_txinout(txinout, only_der_suffix=True)
        if der_suffix is None:
            return None
        desc = self.get_script_descriptor(der_suffix)
        return desc if txinout.scriptpubkey == desc.expand().output_script else None

    def is_wallet_output(self, txout: PartialTxOutput) -> bool:
        """Whether that output pays back to the wallet."""
        return self.get_wallet_script(txout) is not None

    def sign_transaction(self, tx: PartialTransaction) -> None:
        """Signs the transaction with our key. Raises ValueError if it cannot be verified."""
        # add the scripts of the wallet, which a signer would otherwise get from its wallet
        for txin in tx.inputs():
            if not self.claims_our_key(txin):
                continue
            desc = self.get_wallet_script(txin)
            if desc is None:
                raise ValueError('input does not spend from this wallet')
            txin.script_descriptor = desc
        self.keystore.sign_transaction(tx, None)


def get_cosigner_ids(config: 'SimpleConfig') -> List[str]:
    """The fingerprints of the cosigners this device signs for."""
    return list(_read_keystores(config))


def get_cosigner(config: 'SimpleConfig', cosigner_id: str, password: str) -> Cosigner:
    """Raises InvalidPassword."""
    cosigner = Cosigner.from_dict(_decrypt(_read_keystores(config)[cosigner_id], password))
    if cosigner.cosigner_id != cosigner_id:
        raise ValueError(f'cosigner {cosigner_id} does not match its keys')
    return cosigner


def add_cosigner(config: 'SimpleConfig', cosigner: Cosigner, password: str) -> None:
    assert password, 'the keys of a cosigner must be encrypted'
    cosigners = _read_keystores(config)
    cosigners[cosigner.cosigner_id] = _encrypt(cosigner.to_dict(), password)
    _write_keystores(config, cosigners)


def find_cosigner_id_for_tx(config: 'SimpleConfig', tx: PartialTransaction) -> Optional[str]:
    """The cosigner that transaction needs, None if this device does not sign for it.
    Nothing is decrypted, so the password of the device is not needed here.
    """
    fingerprints = {fp.hex() for txin in tx.inputs() for fp, __ in txin.bip32_paths.values()}
    for cosigner_id in get_cosigner_ids(config):
        if cosigner_id in fingerprints:
            return cosigner_id
    return None


def find_cosigner_for_tx(config: 'SimpleConfig', tx: PartialTransaction, password: str) -> Optional[Cosigner]:
    """The keys that transaction needs, None if this device does not sign for it.
    Raises InvalidPassword.
    """
    cosigner_id = find_cosigner_id_for_tx(config, tx)
    return get_cosigner(config, cosigner_id, password) if cosigner_id is not None else None


def check_cosigners_password(config: 'SimpleConfig', password: str) -> None:
    """Whether the keys of the cosigners can be read with that password.
    Raises InvalidPassword.
    """
    for blob in _read_keystores(config).values():
        _decrypt(blob, password)


def update_cosigners_password(config: 'SimpleConfig', old_password: str, new_password: str) -> None:
    """Re-encrypts the keys, after the password of the device has changed.
    Raises InvalidPassword, without writing anything.
    """
    cosigners = _read_keystores(config)
    if not cosigners:
        # this device cosigns for nothing; do not create the file
        return
    _write_keystores(config, {
        cosigner_id: _encrypt(_decrypt(blob, old_password), new_password)
        for cosigner_id, blob in cosigners.items()
    })


def _encrypt(data: Dict, password: str) -> str:
    return pw_encode_with_version_and_mac(json.dumps(data).encode('utf8'), password)


def _decrypt(blob: str, password: str) -> Dict:
    return json.loads(pw_decode_with_version_and_mac(blob, password).decode('utf8'))


def _keystores_path(config: 'SimpleConfig') -> str:
    return os.path.join(config.path, KEYSTORES_FILE_NAME)


def _read_keystores(config: 'SimpleConfig') -> Dict[str, str]:
    path = _keystores_path(config)
    if not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        cosigners = json.loads(f.read())
    if not isinstance(cosigners, dict):
        raise ValueError(f'invalid keystores file at {path}')
    return cosigners


def _write_keystores(config: 'SimpleConfig', cosigners: Dict[str, str]) -> None:
    # written through a temporary file: a partial write would lose the keys of
    # the other wallets this device cosigns for
    path = _keystores_path(config)
    temp_path = f'{path}.tmp.{os.getpid()}'
    with open(temp_path, 'w', encoding='utf-8') as f:
        os_chmod(temp_path, stat.S_IREAD | stat.S_IWRITE)  # set restrictive perms *before* we write data
        f.write(json.dumps(cosigners, indent=4, sort_keys=True))
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp_path, path)
