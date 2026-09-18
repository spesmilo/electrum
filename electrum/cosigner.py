# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

"""Keys of the wallets this device cosigns for, stored in the config file.

A cosigner is indexed by the fingerprint that its key uses in transactions (the
root fingerprint of its key origin), so that a transaction can be matched against
the config file without decrypting anything. Everything else is encrypted with the
password of the device, so that whoever reads the config file cannot derive the
addresses of those wallets, and thus cannot see their history.

What a record contains depends on the multisig scheme; it is opaque here.
"""

import json
from typing import Dict, List, TYPE_CHECKING

from .crypto import pw_encode_with_version_and_mac, pw_decode_with_version_and_mac

if TYPE_CHECKING:
    from .simple_config import SimpleConfig


def get_cosigner_ids(config: 'SimpleConfig') -> List[str]:
    """The fingerprints of the cosigners this device signs for."""
    return list(config.COSIGNERS)


def get_cosigner(config: 'SimpleConfig', cosigner_id: str, password: str) -> Dict:
    """Raises InvalidPassword."""
    blob = config.COSIGNERS[cosigner_id]
    return json.loads(pw_decode_with_version_and_mac(blob, password).decode('utf8'))


def add_cosigner(config: 'SimpleConfig', cosigner_id: str, data: Dict, password: str) -> None:
    assert password, 'the keys of a cosigner must be encrypted'
    cosigners = dict(config.COSIGNERS)
    cosigners[cosigner_id] = _encrypt(data, password)
    config.COSIGNERS = cosigners


def check_cosigners_password(config: 'SimpleConfig', password: str) -> None:
    """Whether the keys of the cosigners can be read with that password.
    Raises InvalidPassword.
    """
    for cosigner_id in get_cosigner_ids(config):
        get_cosigner(config, cosigner_id, password)


def update_cosigners_password(config: 'SimpleConfig', old_password: str, new_password: str) -> None:
    """Re-encrypts the keys, after the password of the device has changed.
    Raises InvalidPassword, without writing anything.
    """
    if not config.COSIGNERS:
        # this device cosigns for nothing; do not write the config file
        return
    cosigners = {
        cosigner_id: _encrypt(get_cosigner(config, cosigner_id, old_password), new_password)
        for cosigner_id in get_cosigner_ids(config)
    }
    config.COSIGNERS = cosigners


def _encrypt(data: Dict, password: str) -> str:
    return pw_encode_with_version_and_mac(json.dumps(data).encode('utf8'), password)
