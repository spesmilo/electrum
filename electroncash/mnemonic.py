#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2020 The Electron Cash Developers
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
import binascii
import ecdsa
import hashlib
import hmac
import math
import os
import pkgutil
import string
import unicodedata
import weakref

from enum import IntEnum, unique, auto
from typing import Dict, List, Optional, Set, Tuple, Union

from . import version
from .bitcoin import hmac_sha_512
from .util import PrintError

# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F , 'Kanbun'),
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

_cjk_min_max = None
def is_CJK(c) -> bool:
    global _cjk_min_max
    if not _cjk_min_max:
        # cache some values for fast path
        _cjk_min_max = (
            min(x[0] for x in CJK_INTERVALS),
            max(x[1] for x in CJK_INTERVALS),
        )
    n = ord(c)
    if n < _cjk_min_max[0] or n > _cjk_min_max[1]:
        # Fast path -- n is clearly out of range.
        return False
    # Slow path: n may be in range of one of the intervals so scan them all using a slow linear search
    for imin,imax,name in CJK_INTERVALS:
        if n>=imin and n<=imax: return True
    return False


def normalize_text(seed: str, is_passphrase=False) -> str:
    # normalize
    seed = unicodedata.normalize('NFKD', seed)
    # lower
    if not is_passphrase:
        seed = seed.lower()
        # normalize whitespaces
        seed = u' '.join(seed.split())
        # remove whitespaces between CJK
        seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed

def load_wordlist(filename: str) -> List[str]:
    data = pkgutil.get_data(__name__, os.path.join('wordlist', filename))
    s = data.decode('utf-8').strip()
    s = unicodedata.normalize('NFKD', s)
    lines = s.split('\n')
    wordlist = []
    for line in lines:
        line = line.split('#')[0]
        line = line.strip(' \r')
        assert ' ' not in line
        if line:
            wordlist.append(normalize_text(line))
    return wordlist


filenames = {
    'en':'english.txt',
    'es':'spanish.txt',
    'ja':'japanese.txt',
    'pt':'portuguese.txt',
    'zh':'chinese_simplified.txt'
}

@unique
class SeedType(IntEnum):
    BIP39    = auto()
    Electrum = auto()
    Old      = auto()

seed_type_names = {
    SeedType.BIP39    : "bip39",
    SeedType.Electrum : "electrum",
    SeedType.Old     : "old",
}
seed_type_names_inv = {
    "bip39"    : SeedType.BIP39,
    "electrum" : SeedType.Electrum,
    "standard" : SeedType.Electrum,  # this was the old name for this type
    "old"      : SeedType.Old,
}

def autodetect_seed_type(seed: str, lang: Optional[str] = None, *,
                         prefix: str = version.SEED_PREFIX) -> Set[SeedType]:
    ''' Given a mnemonic seed phrase, auto-detect the possible seed types it can
    be. Note that some lucky seed phrases match all three types. Electron Cash
    will never generate a seed that matches more than one type, but it is
    possible for imported seeds to be ambiguous. May return the empty set if the
    seed phrase is invalid and/or fails checksum checks for all three types. '''
    ret = set()
    if is_bip39_seed(seed, lang):
        ret.add( SeedType.BIP39 )
    if is_electrum_seed(seed, prefix):
        ret.add( SeedType.Electrum )
    if is_old_seed(seed):
        ret.add( SeedType.Old )
    return ret

def is_bip39_seed(seed: str, lang: Optional[str]=None) -> bool:
    """ Checks if `seed` is a valid BIP39 seed phrase (passes wordlist AND
    checksum tests). If lang=None, then the English wordlist is assumed. This
    function is added here as a convenience. """
    from . import mnemonic
    return mnemonic.Mnemonic(lang).is_seed(seed)

def is_electrum_seed(seed: str, prefix: str=version.SEED_PREFIX) -> bool:
    """ Checks if `seed` is a valid Electrum seed phrase.

    Returns True if the text in question matches the checksum for Electrum
    seeds. Does not depend on any particular word list, just checks unicode
    data.  Very fast. """
    from . import mnemonic
    return mnemonic.Mnemonic_Electrum.verify_checksum_only(seed, prefix)

def is_old_seed(seed: str) -> bool:
    """ Returns True if `seed` is a valid "old" seed phrase of 12 or 24 words
    *OR* if it's a hex string encoding 16 or 32 bytes. """
    from . import old_mnemonic
    return old_mnemonic.mn_is_seed(seed)


def seed_type(seed: str) -> Optional[SeedType]:
    if is_old_seed(seed):
        return SeedType.Old
    elif is_electrum_seed(seed):
        return SeedType.Electrum
    elif is_bip39_seed(seed):
        return SeedType.BIP39

def seed_type_name(seed: str) -> str:
    return seed_type_names.get(seed_type(seed), '')

def format_seed_type_name_for_ui(name : str) -> str:
    """ Given a seed type name e.g. bip39 or standard, transforms it to a
    canonical UI string "BIP39" or "Electrum" """
    name = name.strip().lower()  # paranoia
    name = seed_type_names.get(seed_type_names_inv.get(name)) or name  # transforms 'standard' -> 'electrum'
    if name == 'bip39':
        return name.upper()
    else:
        return name.title()  # Title Caps for "Old" and "Electrum"

is_seed = lambda x: seed_type(x) is not None



class MnemonicBase(PrintError):
    """ Base class for both Mnemonic (BIP39-based) and Mnemonic_Electrum.
    They both use the same word list, so the commonality between them is
    captured in this class. """

    class Data:
        """ Each instance of Mnemonic* shares common Data, per language. """
        words : Tuple[str] = None
        word_indices : Dict[str, int] = None

    shared_datas = weakref.WeakValueDictionary()  # key: 2-char lang -> weakvalue: Data

    def __init__(self, lang=None):
        if isinstance(lang, str):
            lang = lang[:2].lower()
        if lang not in filenames:
            lang = 'en'
        self.lang = lang
        self.data = self.shared_datas.get(lang)
        if not self.data:
            self.data = self.Data()
            self.print_error('loading wordlist for:', lang)
            filename = filenames[lang]
            self.data.words = tuple(load_wordlist(filename))
            self.data.word_indices = dict()
            for i, word in enumerate(self.data.words):
                self.data.word_indices[word] = i  # saves on O(N) lookups for words. The alternative is to call wordlist.index(w) for each word which is slow.
            self.print_error("wordlist has %d words"%len(self.data.words))
            assert len(self.data.words) == len(self.data.word_indices)  # Paranoia to ensure word list is composed of unique words.
            self.shared_datas[self.lang] = self.data

    @property
    def wordlist(self) -> Tuple[str]: return self.data.words

    @property
    def wordlist_indices(self) -> Dict[str, int]: return self.data.word_indices

    def get_suggestions(self, prefix):
        for w in self.wordlist:
            if w.startswith(prefix):
                yield w

    @classmethod
    def list_languages(cls) -> List[str]:
        return list(filenames.keys())

    @classmethod
    def normalize_text(cls, txt: Union[str, bytes], is_passphrase=False) -> str:
        if isinstance(txt, bytes):
            txt = txt.decode('utf8')
        elif not isinstance(txt, str):  # noqa: F821
            raise TypeError("String value expected")

        return normalize_text(txt, is_passphrase=is_passphrase)

    @classmethod
    def detect_language(cls, code: str) -> str:
        code = cls.normalize_text(code)
        first = code.split(' ')[0]
        languages = cls.list_languages()

        for lang in languages:
            mnemo = cls(lang)
            if first in mnemo.wordlist:
                return lang

        raise Exception("Language not detected")

    @classmethod
    def mnemonic_to_seed(cls, mnemonic: str, passphrase: Optional[str]) -> bytes:
        raise NotImplementedError(f'mnemonic_to_seed is not implemented in {cls.__name__}')

    def make_seed(self, seed_type=None, num_bits=128, custom_entropy=1) -> str:
        raise NotImplementedError(f'make_seed is not implemented in {type(self).__name__}')

    @classmethod
    def is_wordlist_valid(cls, mnemonic: str, lang: Optional[str] = None) -> Tuple[bool, str]:
        """ Returns (True, lang) if the passed-in `mnemonic` phrase has all its
        words found in the wordlist for `lang`. Pass in a None value for `lang`
        to auto-detect language. The fallback language is always "en".

        If the `mnemonic` contains any word not in the wordlist for `lang`,
        returns (False, lang) if lang was specified or (False, "en") if it was
        not. """
        if lang is None:
            try:
                lang = cls.detect_language(mnemonic)
            except:
                lang = 'en'
        elif lang not in cls.list_languages():
            lang = 'en'
        return cls(lang).verify_wordlist(mnemonic), lang

    def verify_wordlist(self, mnemonic: str) -> bool:
        """ Instance method which is a variation on is_wordlist_valid, which
        does no language detection and simply checks all of the words in
        mnemonic versus this instance's wordlist, returns True if they are all
        in the wordlist. """
        mnemonic = self.normalize_text(mnemonic)
        for w in mnemonic.split():
            if w not in self.wordlist_indices:
                return False
        return True

    def is_checksum_valid(self, mnemonic : str) -> Tuple[bool, bool]:
        raise NotImplementedError(f'is_checksum_valid is not implemented in {type(self).__name__}')

    def is_seed(self, mnemonic: str) -> bool:
        """ Convenient alias for is_checksum_valid()[0] """
        return self.is_checksum_valid(mnemonic)[0]


class Mnemonic(MnemonicBase):
    """ Implements seed derivation following BIP39, which is now the Electron
    Cash default. The previous 'Electrum' seedformat is provided by the
    Mnemonic_Electrum class later in this file.

    BIP39 uses a wordlist-dependent checksum. Because of this we should always
    accept seeds that fail checksum otherwise users will not always be able to
    restore their seeds."""

    @classmethod
    def mnemonic_to_seed(cls, mnemonic: str, passphrase: Optional[str]) -> bytes:
        PBKDF2_ROUNDS = 2048
        mnemonic = cls.normalize_text(mnemonic)
        passphrase = cls.normalize_text(passphrase or '', is_passphrase=True)
        return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), b'mnemonic' + passphrase.encode('utf-8'), iterations = PBKDF2_ROUNDS)

    def make_seed(self, seed_type=None, num_bits=128, custom_entropy=1) -> str:
        if self.lang not in ('en', 'es'):
            raise NotImplementedError(f"Cannot make a seed for language '{self.lang}'. "
                                      + "Only English and Spanish are supported as seed generation languages in this implementation")
        if num_bits not in (128, 160, 192, 224, 256):
            raise ValueError('Strength should be one of the following [128, 160, 192, 224, 256], not %d.' % num_bits)
        def inner(num_bits):
            data = os.urandom(num_bits // 8)
            h = hashlib.sha256(data).hexdigest()
            b = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8) + bin(int(h, 16))[2:].zfill(256)[:len(data) * 8 // 32]
            result = []
            for i in range(len(b) // 11):
                idx = int(b[i * 11:(i + 1) * 11], 2)
                result.append(self.wordlist[idx])
            if self.lang == 'ja':  # Japanese must be joined by ideographic space.
                result_phrase = u'\u3000'.join(result)
            else:
                result_phrase = ' '.join(result)
            return result_phrase
        iters = 0
        while True:
            iters += 1
            seed = inner(num_bits)
            # avoid ambiguity between old-style seeds and BIP39, as well as avoid clashes with Electrum seeds
            if autodetect_seed_type(seed, self.lang) == {SeedType.BIP39}:
                self.print_error("make_seed iterations:", iters)
                return seed

    def is_checksum_valid(self, mnemonic : str) -> Tuple[bool, bool]:
        """Test checksum of BIP39 mnemonic. Returns tuple (is_checksum_valid,
        is_wordlist_valid). Note that for an invalid worlist, is_checksum_valid
        will always be False (this is because BIP39 relies on the wordlist for
        the checksum)."""
        words = self.normalize_text(mnemonic).split()
        words_len = len(words)
        worddict = self.wordlist_indices
        n = len(worddict)
        i = 0
        for w in words:
            try:
                k = worddict[w]
            except KeyError:
                return False, False
            i = i*n + k
        if words_len not in (12, 15, 18, 21, 24):
            return False, True
        checksum_length = 11 * words_len // 33  # num bits
        entropy_length = 32 * checksum_length  # num bits
        entropy = i >> checksum_length
        checksum = i % 2**checksum_length
        entropy_bytes = int.to_bytes(entropy, length=entropy_length//8, byteorder="big")
        hashed = int.from_bytes(hashlib.sha256(entropy_bytes).digest(), byteorder="big")
        calculated_checksum = hashed >> (256 - checksum_length)
        return checksum == calculated_checksum, True


class Mnemonic_Electrum(MnemonicBase):
    """ This implements the "Electrum" mnemonic seed phrase format, which was
    used for many years, but starting in 2020, Electron Cash switched back to
    BIP39 since it has wider support.

    The Electrum seed phrase format uses a hash based checksum of the normalized
    text data, instead of a wordlist-dependent checksum. """

    @classmethod
    def mnemonic_to_seed(cls, mnemonic, passphrase):
        """ Electrum format """
        PBKDF2_ROUNDS = 2048
        mnemonic = cls.normalize_text(mnemonic)
        passphrase = cls.normalize_text(passphrase or '', is_passphrase=True)
        return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), b'electrum' + passphrase.encode('utf-8'), iterations = PBKDF2_ROUNDS)

    def mnemonic_encode(self, i):
        n = len(self.wordlist)
        words = []
        while i:
            x = i%n
            i = i//n
            words.append(self.wordlist[x])
        return ' '.join(words)

    def mnemonic_decode(self, seed):
        n = len(self.wordlist)
        i = 0
        for w in reversed(seed.split()):
            k = self.wordlist_indices[w]
            i = i*n + k
        return i

    def make_seed(self, seed_type=None, num_bits=132, custom_entropy=1):
        """ Electrum format """
        if self.lang not in ('en', 'es', 'pt'):
            raise NotImplementedError(f"Cannot make a seed for language '{self.lang}'. "
                                      + "Only English, Spanish, and Portuguese are supported as seed generation languages in this implementation")
        if seed_type is None:
            seed_type = 'electrum'
        prefix = version.seed_prefix(seed_type)
        # increase num_bits in order to obtain a uniform distibution for the last word
        bpw = math.log(len(self.wordlist), 2)
        num_bits = int(math.ceil(num_bits/bpw) * bpw)
        # handle custom entropy; make sure we add at least 16 bits
        n_custom = int(math.ceil(math.log(custom_entropy, 2)))
        n = max(16, num_bits - n_custom)
        self.print_error("make_seed", prefix, "adding %d bits"%n)
        my_entropy = 1
        while my_entropy < pow(2, n - bpw):
            # try again if seed would not contain enough words
            my_entropy = ecdsa.util.randrange(pow(2, n))
        nonce = 0
        while True:
            nonce += 1
            i = custom_entropy * (my_entropy + nonce)
            seed = self.mnemonic_encode(i)
            assert i == self.mnemonic_decode(seed)
            # avoid ambiguity between old-style seeds and new-style, as well as avoid clashes with BIP39 seeds
            if autodetect_seed_type(seed, self.lang, prefix=prefix) == {SeedType.Electrum}:
                break
        self.print_error('{nwords} words, {nonce} iterations'.format(nwords=len(seed.split()), nonce=nonce))
        return seed

    def check_seed(self, seed: str, custom_entropy: int) -> bool:
        assert self.verify_checksum_only(seed)
        i = self.mnemonic_decode(seed)
        return i % custom_entropy == 0

    def is_checksum_valid(self, mnemonic: str, *, prefix: str = version.SEED_PREFIX) -> Tuple[bool, bool]:
        return self.verify_checksum_only(mnemonic, prefix), self.verify_wordlist(mnemonic)

    @classmethod
    def verify_checksum_only(cls, mnemonic: str, prefix: str = version.SEED_PREFIX) -> bool:
        x = cls.normalize_text(mnemonic)
        s = hmac_sha_512(b"Seed version", x.encode('utf8')).hex()
        return s.startswith(prefix)

    def is_seed(self, mnemonic: str) -> bool:
        """ Overrides super, skips the wordlist check which is not needed to
        answer this question for Electrum seeds. """
        return self.verify_checksum_only(mnemonic)
