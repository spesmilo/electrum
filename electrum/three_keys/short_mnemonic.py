import os
from typing import List, Tuple

from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Protocol.KDF import PBKDF2

from electrum.ecc import ECPrivkey
from electrum.i18n import _
from electrum.mnemonic import load_wordlist

MNEMONIC_LENGTH = 12
ENTROPY_LEN = 16
PBKDF_ITERATIONS = 100_000

BIP39_WORDLIST = load_wordlist("english.txt")


def is_valid(seed: List[str]) -> bool:
    if len(seed) != MNEMONIC_LENGTH or any([word not in BIP39_WORDLIST for word in seed]):
        return False
    return True


def generate_entropy() -> bytes:
    return os.urandom(ENTROPY_LEN)


def entropy_to_privkey(entropy: bytes) -> bytes:
    priv_key = PBKDF2(entropy, entropy, dkLen=32, count=PBKDF_ITERATIONS,
                      prf=lambda p, s: HMAC.new(p, s, SHA256).digest())
    return priv_key


def seed_to_privkey(seed: List[str]) -> bytes:
    index_cache = [BIP39_WORDLIST.index(word) for word in seed]
    payload = 0
    for i, b in enumerate(reversed(index_cache)):
        payload = payload | (b << (i * 11))

    payload = payload.to_bytes(17, 'big')
    checksum = payload[:1]
    entropy = payload[1:]

    sha256sum = SHA256.new(entropy).digest()
    if sha256sum.hex()[0] != checksum.hex()[1]:
        raise ValueError(_('Invalid seed'))

    private_key = entropy_to_privkey(entropy)

    return private_key


def seed_to_keypair(seed: List[str]) -> Tuple[bytes, str]:
    privkey = seed_to_privkey(seed)
    pubkey = ECPrivkey(privkey).get_public_key_hex()
    return (privkey, pubkey)
