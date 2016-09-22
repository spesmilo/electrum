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
import hmac
import math
import hashlib
import unicodedata
import string

import ecdsa
import pbkdf2

from util import print_error
from bitcoin import is_old_seed, is_new_seed
import version
import i18n

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

def is_CJK(c):
    n = ord(c)
    for imin,imax,name in CJK_INTERVALS:
        if n>=imin and n<=imax: return True
    return False


def normalize_text(seed):
    # normalize
    seed = unicodedata.normalize('NFKD', unicode(seed))
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed


filenames = {
    'en':'english.txt',
    'es':'spanish.txt',
    'ja':'japanese.txt',
    'pt':'portuguese.txt',
    'zh':'chinese_simplified.txt'
}



class Mnemonic(object):
    # Seed derivation no longer follows BIP39
    # Mnemonic phrase uses a hash based checksum, instead of a wordlist-dependent checksum

    def __init__(self, lang=None):
        lang = lang or 'en'
        print_error('language', lang)
        filename = filenames.get(lang[0:2], 'english.txt')
        path = os.path.join(os.path.dirname(__file__), 'wordlist', filename)
        s = open(path,'r').read().strip()
        s = unicodedata.normalize('NFKD', s.decode('utf8'))
        lines = s.split('\n')
        self.wordlist = []
        for line in lines:
            line = line.split('#')[0]
            line = line.strip(' \r')
            assert ' ' not in line
            if line:
                self.wordlist.append(line)
        print_error("wordlist has %d words"%len(self.wordlist))

    @classmethod
    def mnemonic_to_seed(self, mnemonic, passphrase):
        PBKDF2_ROUNDS = 2048
        mnemonic = normalize_text(mnemonic)
        passphrase = normalize_text(passphrase)
        return pbkdf2.PBKDF2(mnemonic, 'electrum' + passphrase, iterations = PBKDF2_ROUNDS, macmodule = hmac, digestmodule = hashlib.sha512).read(64)

    def mnemonic_encode(self, i):
        n = len(self.wordlist)
        words = []
        while i:
            x = i%n
            i = i/n
            words.append(self.wordlist[x])
        return ' '.join(words)

    def get_suggestions(self, prefix):
        for w in self.wordlist:
            if w.startswith(prefix):
                yield w

    def mnemonic_decode(self, seed):
        n = len(self.wordlist)
        words = seed.split()
        i = 0
        while words:
            w = words.pop()
            k = self.wordlist.index(w)
            i = i*n + k
        return i

    def check_seed(self, seed, custom_entropy):
        assert is_new_seed(seed)
        i = self.mnemonic_decode(seed)
        return i % custom_entropy == 0

    def make_seed(self, num_bits=128, prefix=version.SEED_PREFIX, custom_entropy=1):
        # increase num_bits in order to obtain a uniform distibution for the last word
        bpw = math.log(len(self.wordlist), 2)
        num_bits = int(math.ceil(num_bits/bpw)) * bpw
        # handle custom entropy; make sure we add at least 16 bits
        n_custom = int(math.ceil(math.log(custom_entropy, 2)))
        n = max(16, num_bits - n_custom)
        print_error("make_seed", prefix, "adding %d bits"%n)
        my_entropy = ecdsa.util.randrange(pow(2, n))
        nonce = 0
        while True:
            nonce += 1
            i = custom_entropy * (my_entropy + nonce)
            seed = self.mnemonic_encode(i)
            assert i == self.mnemonic_decode(seed)
            if is_old_seed(seed):
                continue
            if is_new_seed(seed, prefix):
                break
        print_error('%d words'%len(seed.split()))
        return seed
