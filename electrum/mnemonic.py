#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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
import os
import math
import hashlib
import unicodedata
import string
from typing import Sequence, Dict, Iterator, Optional
from types import MappingProxyType

from .util import resource_path, bfh, randrange
from .crypto import hmac_oneshot
from . import version
from .logging import Logger


# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F, 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals'),
]

def is_CJK(c: str) -> bool:
    n = ord(c)
    for imin, imax, name in CJK_INTERVALS:
        if imin <= n <= imax:
            return True
    return False


def normalize_text(seed: str) -> str:
    # normalize
    seed = unicodedata.normalize('NFKD', seed)
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed


def is_matching_seed(*, seed: str, seed_again: str) -> bool:
    """Compare two seeds for equality, as used in "confirm seed" screen in wizard.
    Not just for electrum seeds, but other types (e.g. bip39) as well.
    Note: we don't use normalize_text, as that is specific to electrum seeds.
    """
    seed = " ".join(seed.split())
    seed_again = " ".join(seed_again.split())
    return seed == seed_again


_WORDLIST_CACHE = {}  # type: Dict[str, Wordlist]


class Wordlist(tuple):

    def __init__(self, words: Sequence[str]):
        super().__init__()
        index_from_word = {w: i for i, w in enumerate(words)}
        self._index_from_word = MappingProxyType(index_from_word)  # no mutation

    def index(self, word: str, start=None, stop=None) -> int:
        try:
            return self._index_from_word[word]
        except KeyError as e:
            raise ValueError from e

    def __contains__(self, word: str) -> bool:
        try:
            self.index(word)
        except ValueError:
            return False
        else:
            return True

    @classmethod
    def from_file(cls, filename: str) -> 'Wordlist':
        path = resource_path('wordlist', filename)
        if path not in _WORDLIST_CACHE:
            with open(path, 'r', encoding='utf-8') as f:
                s = f.read().strip()
            s = unicodedata.normalize('NFKD', s)
            lines = s.split('\n')
            words = []
            for line in lines:
                line = line.split('#')[0]
                line = line.strip(' \r')
                assert ' ' not in line
                if line:
                    words.append(line)

            _WORDLIST_CACHE[path] = Wordlist(words)
        return _WORDLIST_CACHE[path]


filenames = {
    'en':'english.txt',
    'es':'spanish.txt',
    'ja':'japanese.txt',
    'pt':'portuguese.txt',
    'zh':'chinese_simplified.txt'
}


class Mnemonic(Logger):
    # Seed derivation does not follow BIP39
    # Mnemonic phrase uses a hash based checksum, instead of a wordlist-dependent checksum

    def __init__(self, lang: str = None):
        Logger.__init__(self)
        lang = lang or 'en'
        self.logger.info(f'language {lang}')
        filename = filenames.get(lang[0:2], 'english.txt')
        self.wordlist = Wordlist.from_file(filename)
        self.logger.info(f"wordlist has {len(self.wordlist)} words")

    @classmethod
    def mnemonic_to_seed(cls, mnemonic: str, *, passphrase: Optional[str]) -> bytes:
        PBKDF2_ROUNDS = 2048
        mnemonic = normalize_text(mnemonic)
        passphrase = passphrase or ''
        passphrase = normalize_text(passphrase)
        return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), b'electrum' + passphrase.encode('utf-8'), iterations = PBKDF2_ROUNDS)

    def mnemonic_encode(self, i: int) -> str:
        n = len(self.wordlist)
        words = []
        while i:
            x = i % n
            i = i//n
            words.append(self.wordlist[x])
        return ' '.join(words)

    def get_suggestions(self, prefix: str) -> Iterator[str]:
        for w in self.wordlist:
            if w.startswith(prefix):
                yield w

    def mnemonic_decode(self, seed: str) -> int:
        n = len(self.wordlist)
        words = seed.split()
        i = 0
        while words:
            w = words.pop()
            k = self.wordlist.index(w)
            i = i*n + k
        return i

    def make_seed(self, *, seed_type: str = None, num_bits: int = None) -> str:
        from .keystore import bip39_is_checksum_valid
        if seed_type is None:
            seed_type = 'segwit'
        if num_bits is None:
            num_bits = 132
        prefix = version.seed_prefix(seed_type)
        # increase num_bits in order to obtain a uniform distribution for the last word
        bpw = math.log(len(self.wordlist), 2)
        num_bits = int(math.ceil(num_bits/bpw) * bpw)
        self.logger.info(f"make_seed. prefix: '{prefix}', entropy: {num_bits} bits")
        # generate random
        entropy = 1
        while entropy < pow(2, num_bits - bpw):  # try again if seed would not contain enough words
            entropy = randrange(pow(2, num_bits))
        # brute-force seed that has correct "version number"
        nonce = 0
        while True:
            nonce += 1
            i = entropy + nonce
            seed = self.mnemonic_encode(i)
            if i != self.mnemonic_decode(seed):
                raise Exception('Cannot extract same entropy from mnemonic!')
            if is_old_seed(seed):
                continue
            # Make sure the mnemonic we generate is not also a valid bip39 seed
            # by accident. Note that this test has not always been done historically,
            # so it cannot be relied upon.
            if bip39_is_checksum_valid(seed, wordlist=self.wordlist) == (True, True):
                continue
            if is_new_seed(seed, prefix):
                break
        num_words = len(seed.split())
        self.logger.info(f'{num_words} words')
        if (final_seed_type := calc_seed_type(seed)) != seed_type:
            # note: I guess this can probabilistically happen for old "2fa" seeds that depend on the word count
            raise Exception(f"{final_seed_type=!r} does not match requested {seed_type=!r}. have {num_words=!r}")
        return seed


def is_new_seed(x: str, prefix=version.SEED_PREFIX) -> bool:
    x = normalize_text(x)
    s = hmac_oneshot(b"Seed version", x.encode('utf8'), hashlib.sha512).hex()
    return s.startswith(prefix)


def is_old_seed(seed: str) -> bool:
    from . import old_mnemonic
    seed = normalize_text(seed)
    words = seed.split()
    try:
        # checks here are deliberately left weak for legacy reasons, see #3149
        old_mnemonic.mn_decode(words)
        uses_electrum_words = True
    except Exception:
        uses_electrum_words = False
    try:
        seed = bfh(seed)
        is_hex = (len(seed) == 16 or len(seed) == 32)
    except Exception:
        is_hex = False
    return is_hex or (uses_electrum_words and (len(words) == 12 or len(words) == 24))


def calc_seed_type(x: str) -> str:
    num_words = len(x.split())
    if is_old_seed(x):
        return 'old'
    elif is_new_seed(x, version.SEED_PREFIX):
        return 'standard'
    elif is_new_seed(x, version.SEED_PREFIX_SW):
        return 'segwit'
    elif is_new_seed(x, version.SEED_PREFIX_2FA) and (num_words == 12 or num_words >= 20):
        # Note: in Electrum 2.7, there was a breaking change in key derivation
        #       for this seed type. Unfortunately the seed version/prefix was reused,
        #       and now we can only distinguish them based on number of words. :(
        return '2fa'
    elif is_new_seed(x, version.SEED_PREFIX_2FA_SW):
        return '2fa_segwit'
    return ''


def can_seed_have_passphrase(seed: str) -> bool:
    stype = calc_seed_type(seed)
    if not stype:
        raise Exception(f'unexpected seed type: {stype!r}')
    if stype == 'old':
        return False
    if stype == '2fa':
        # post-version-2.7 2fa seeds can have passphrase, but older ones cannot
        num_words = len(seed.split())
        if num_words == 12:
            return True
        else:
            return False
    # all other types can have a seed extension/passphrase
    return True


def is_seed(x: str) -> bool:
    return bool(calc_seed_type(x))


def is_any_2fa_seed_type(seed_type: str) -> bool:
    return seed_type in ['2fa', '2fa_segwit']
