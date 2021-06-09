#!/usr/bin/env python3
#
# This script is just a demonstration how one could go about bruteforcing an
# Electrum wallet file password. As it is pure-python and runs in the CPU,
# it is horribly slow. It could be changed to utilise multiple threads
# but any serious attempt would need at least GPU acceleration.
#
# There are two main types of password encryption that need to be disambiguated
# for Electrum wallets:
# (1) keystore-encryption: The wallet file itself is mostly plaintext (json),
#                          only the Bitcoin private keys themselves are encrypted.
#                          (e.g. seed words, xprv are encrypted; addresses are not)
#                          Even in memory (at runtime), the private keys are typically
#                          stored encrypted, and only when needed the user is prompted
#                          for their password to decrypt the keys briefly.
# (2) storage-encryption: The file itself is encrypted. When opened in a text editor,
#                         it is base64 ascii text. Normally storage-encrypted wallets
#                         also have keystore-encryption (unless they don't have private keys).
# Storage-encryption was introduced in Electrum 2.8, keystore-encryption predates that.
# Newly created wallets in modern Electrum have storage-encryption enabled by default.
#
# Storage encryption uses a stronger KDF than keystore-encryption.
# As is, this script can test around ~1000 passwords per second for storage-encryption.

import sys
from string import digits, ascii_uppercase, ascii_lowercase
from itertools import product
from typing import Callable
from functools import partial

from electrum.wallet import Wallet, Abstract_Wallet
from electrum.storage import WalletStorage
from electrum.wallet_db import WalletDB
from electrum.simple_config import SimpleConfig
from electrum.util import InvalidPassword


ALLOWED_CHARS = digits + ascii_uppercase + ascii_lowercase
MAX_PASSWORD_LEN = 12


def test_password_for_storage_encryption(storage: WalletStorage, password: str) -> bool:
    try:
        storage.decrypt(password)
    except InvalidPassword:
        return False
    else:
        return True


def test_password_for_keystore_encryption(wallet: Abstract_Wallet, password: str) -> bool:
    try:
        wallet.check_password(password)
    except InvalidPassword:
        return False
    else:
        return True


def bruteforce_loop(test_password: Callable[[str], bool]) -> str:
    num_tested = 0
    for pw_len in range(1, MAX_PASSWORD_LEN + 1):
        for pw_tuple in product(ALLOWED_CHARS, repeat=pw_len):
            password = "".join(pw_tuple)
            if test_password(password):
                return password
            num_tested += 1
            if num_tested % 5000 == 0:
                print(f"> tested {num_tested} passwords so far... most recently tried: {password!r}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("ERROR. usage: bruteforce_pw.py <path_to_wallet_file>")
        sys.exit(1)
    path = sys.argv[1]

    config = SimpleConfig()
    storage = WalletStorage(path)
    if not storage.file_exists():
        print(f"ERROR. wallet file not found at path: {path}")
        sys.exit(1)
    if storage.is_encrypted():
        test_password = partial(test_password_for_storage_encryption, storage)
        print(f"wallet found: with storage encryption.")
    else:
        db = WalletDB(storage.read(), manual_upgrades=True)
        wallet = Wallet(db, storage, config=config)
        if not wallet.has_password():
            print("wallet found but it is not encrypted.")
            sys.exit(0)
        test_password = partial(test_password_for_keystore_encryption, wallet)
        print(f"wallet found: with keystore encryption.")
    password = bruteforce_loop(test_password)
    print(f"====================")
    print(f"password found: {password}")
