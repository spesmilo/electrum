from typing import Tuple

from ecdsa.util import string_to_number

from . import ecc
from .bip32 import xpub_from_pubkey, get_pubkey_from_xpub
from .bitcoin import rev_hex, EncodeBase58Check, script_to_address, public_key_to_p2pkh
from .crypto import sha256d
from .util import bfh, bh2u, BitcoinException


def old_parse_xpubkey(x_pubkey):
    assert x_pubkey[0:2] == 'fe'
    pk = x_pubkey[2:]
    mpk = pk[0:128]
    dd = pk[128:]
    s = []
    while dd:
        n = int(rev_hex(dd[0:4]), 16)
        dd = dd[4:]
        s.append(n)
    assert len(s) == 2
    return mpk, s


def old_get_sequence(mpk, for_change, n):
    return string_to_number(sha256d(("%d:%d:" % (n, for_change)).encode('ascii') + bfh(mpk)))


def old_get_pubkey_from_mpk(mpk, for_change, n) -> str:
    z = old_get_sequence(mpk, for_change, n)
    master_public_key = ecc.ECPubkey(bfh('04' + mpk))
    public_key = master_public_key + z * ecc.generator()
    return public_key.get_public_key_hex(compressed=False)


def parse_xpubkey(x_pubkey: str):
    # type + xpub + derivation
    if x_pubkey[0:2] == 'fe':
        mpk, s = old_parse_xpubkey(x_pubkey)
        xkey = old_get_pubkey_from_mpk(mpk, *s)
        cK = bfh(ecc.ECPubkey(bfh(xkey)).get_public_key_hex(compressed=True))
        xkey = xpub_from_pubkey('standard', cK)
        return xkey, s
    elif x_pubkey[0:2] == 'ff':
        pk = bfh(x_pubkey)
        # xpub:
        pk = pk[1:]
        xkey = EncodeBase58Check(pk[0:78])
        # derivation:
        dd = pk[78:]
        s = []
        # FIXME: due to an oversight, levels in the derivation are only
        # allocated 2 bytes, instead of 4 (in bip32)
        while dd:
            n = int(rev_hex(bh2u(dd[0:2])), 16)
            dd = dd[2:]
            s.append(n)
        assert len(s) == 2
        return xkey, s
    else:
        return None, None


def xpubkey_to_address(x_pubkey) -> Tuple[str, str]:
    if x_pubkey[0:2] == 'fd':
        address = script_to_address(x_pubkey[2:])
        return x_pubkey, address
    if x_pubkey[0:2] in ['02', '03', '04']:
        pubkey = x_pubkey
    elif x_pubkey[0:2] == 'ff':
        xpub, s = parse_xpubkey(x_pubkey)
        pubkey = get_pubkey_from_xpub(xpub, s)
    elif x_pubkey[0:2] == 'fe':
        mpk, s = old_parse_xpubkey(x_pubkey)
        pubkey = old_get_pubkey_from_mpk(mpk, s[0], s[1])
    else:
        raise BitcoinException("Cannot parse pubkey. prefix: {}".format(x_pubkey[0:2]))
    if pubkey:
        address = public_key_to_p2pkh(bfh(pubkey))
    return pubkey, address


def xpubkey_to_pubkey(x_pubkey: str):
    pubkey, address = xpubkey_to_address(x_pubkey)
    return pubkey


def is_xpubkey(x_pubkey):
    return x_pubkey[0:2] == 'ff'
