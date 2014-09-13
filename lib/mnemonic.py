#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import os
import hmac
import math
import hashlib
import unicodedata
import string

import ecdsa
import pbkdf2

import util
from util import print_error
from bitcoin import is_old_seed, is_new_seed
import version


filenames = {
    'en':'english.txt',
    'es':'spanish.txt',
    'ja':'japanese.txt',
    'pt':'portuguese.txt',
}



class Mnemonic(object):
    # Seed derivation no longer follows BIP39
    # Mnemonic phrase uses a hash based checksum, instead of a wordlist-dependent checksum

    def __init__(self, lang='en'):
        filename = filenames.get(lang[0:2], 'english.txt')
        path = os.path.join(util.appdata_dir(), 'wordlist', filename)
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
        mnemonic = self.prepare_seed(mnemonic)
        return pbkdf2.PBKDF2(mnemonic, 'mnemonic' + passphrase, iterations = PBKDF2_ROUNDS, macmodule = hmac, digestmodule = hashlib.sha512).read(64)

    @classmethod
    def prepare_seed(self, seed):
        # normalize
        seed = unicodedata.normalize('NFKD', unicode(seed))
        # lower
        seed = seed.lower()
        # remove accents and whitespaces
        seed = u''.join([c for c in seed if not unicodedata.combining(c) and not c in string.whitespace])
        return seed

    def mnemonic_encode(self, i):
        n = len(self.wordlist)
        words = []
        while i:
            x = i%n
            i = i/n
            words.append(self.wordlist[x])
        return ' '.join(words)

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

    def make_seed(self, num_bits=128, prefix=version.SEED_BIP44, custom_entropy=1):
        n = int(math.ceil(math.log(custom_entropy,2)))
        # bits of entropy used by the prefix
        k = len(prefix)*4
        # we add at least 16 bits
        n_added = max(16, k + num_bits - n)
        print_error("make_seed", prefix, "adding %d bits"%n_added)
        my_entropy = ecdsa.util.randrange( pow(2, n_added) )
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

