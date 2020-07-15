import os

from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256, HMAC

ENTROPY_LEN = 16
PBKDF_ITERATIONS = 100_000


def generate_entropy():
    return os.urandom(ENTROPY_LEN)


def entropy_to_privkey(entropy: bytes) -> bytes:
    priv_key = PBKDF2(entropy, entropy, dkLen=32, count=PBKDF_ITERATIONS,
                      prf=lambda p, s: HMAC.new(p, s, SHA256).digest())
    return priv_key
