#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 thomasv@gitorious
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

import bitcoin
from bitcoin import *
from i18n import _
from transaction import Transaction, is_extended_pubkey
from util import print_msg, InvalidPassword


class Account(object):
    def __init__(self, v):
        self.receiving_pubkeys   = v.get('receiving', [])
        self.change_pubkeys      = v.get('change', [])
        # addresses will not be stored on disk
        self.receiving_addresses = map(self.pubkeys_to_address, self.receiving_pubkeys)
        self.change_addresses    = map(self.pubkeys_to_address, self.change_pubkeys)

    def dump(self):
        return {'receiving':self.receiving_pubkeys, 'change':self.change_pubkeys}

    def get_pubkey(self, for_change, n):
        pubkeys_list = self.change_pubkeys if for_change else self.receiving_pubkeys
        return pubkeys_list[n]

    def get_address(self, for_change, n):
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        return addr_list[n]

    def get_pubkeys(self, for_change, n):
        return [ self.get_pubkey(for_change, n)]

    def get_addresses(self, for_change):
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        return addr_list[:]

    def derive_pubkeys(self, for_change, n):
        pass

    def create_new_address(self, for_change):
        pubkeys_list = self.change_pubkeys if for_change else self.receiving_pubkeys
        addr_list = self.change_addresses if for_change else self.receiving_addresses
        n = len(pubkeys_list)
        pubkeys = self.derive_pubkeys(for_change, n)
        address = self.pubkeys_to_address(pubkeys)
        pubkeys_list.append(pubkeys)
        addr_list.append(address)
        print_msg(address)
        return address

    def pubkeys_to_address(self, pubkey):
        return public_key_to_bc_address(pubkey.decode('hex'))

    def has_change(self):
        return True

    def get_name(self, k):
        return _('Main account')

    def redeem_script(self, for_change, n):
        return None

    def is_used(self, wallet):
        addresses = self.get_addresses(False)
        return any(wallet.address_is_old(a, -1) for a in addresses)

    def synchronize_sequence(self, wallet, for_change):
        limit = wallet.gap_limit_for_change if for_change else wallet.gap_limit
        while True:
            addresses = self.get_addresses(for_change)
            if len(addresses) < limit:
                address = self.create_new_address(for_change)
                wallet.add_address(address)
                continue
            if map( lambda a: wallet.address_is_old(a), addresses[-limit:] ) == limit*[False]:
                break
            else:
                address = self.create_new_address(for_change)
                wallet.add_address(address)

    def synchronize(self, wallet):
        self.synchronize_sequence(wallet, False)
        self.synchronize_sequence(wallet, True)


class ImportedAccount(Account):
    def __init__(self, d):
        self.keypairs = d['imported']

    def synchronize(self, wallet):
        return

    def get_addresses(self, for_change):
        return [] if for_change else sorted(self.keypairs.keys())

    def get_pubkey(self, *sequence):
        for_change, i = sequence
        assert for_change == 0
        addr = self.get_addresses(0)[i]
        return self.keypairs[addr][0]

    def get_xpubkeys(self, for_change, n):
        return self.get_pubkeys(for_change, n)

    def get_private_key(self, sequence, wallet, password):
        from wallet import pw_decode
        for_change, i = sequence
        assert for_change == 0
        address = self.get_addresses(0)[i]
        pk = pw_decode(self.keypairs[address][1], password)
        # this checks the password
        if address != address_from_private_key(pk):
            raise InvalidPassword()
        return [pk]

    def has_change(self):
        return False

    def add(self, address, pubkey, privkey, password):
        from wallet import pw_encode
        self.keypairs[address] = [pubkey, pw_encode(privkey, password)]

    def remove(self, address):
        self.keypairs.pop(address)

    def dump(self):
        return {'imported':self.keypairs}

    def get_name(self, k):
        return _('Imported keys')

    def update_password(self, old_password, new_password):
        for k, v in self.keypairs.items():
            pubkey, a = v
            b = pw_decode(a, old_password)
            c = pw_encode(b, new_password)
            self.keypairs[k] = (pubkey, c)


class OldAccount(Account):
    """  Privatekey(type,n) = Master_private_key + H(n|S|type)  """

    def __init__(self, v):
        Account.__init__(self, v)
        self.mpk = v['mpk'].decode('hex')

    @classmethod
    def mpk_from_seed(klass, seed):
        secexp = klass.stretch_key(seed)
        master_private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve = SECP256k1 )
        master_public_key = master_private_key.get_verifying_key().to_string().encode('hex')
        return master_public_key

    @classmethod
    def stretch_key(self,seed):
        oldseed = seed
        for i in range(100000):
            seed = hashlib.sha256(seed + oldseed).digest()
        return string_to_number( seed )

    @classmethod
    def get_sequence(self, mpk, for_change, n):
        return string_to_number( Hash( "%d:%d:"%(n,for_change) + mpk ) )

    def get_address(self, for_change, n):
        pubkey = self.get_pubkey(for_change, n)
        address = public_key_to_bc_address( pubkey.decode('hex') )
        return address

    @classmethod
    def get_pubkey_from_mpk(self, mpk, for_change, n):
        z = self.get_sequence(mpk, for_change, n)
        master_public_key = ecdsa.VerifyingKey.from_string(mpk, curve = SECP256k1)
        pubkey_point = master_public_key.pubkey.point + z*SECP256k1.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point(pubkey_point, curve = SECP256k1)
        return '04' + public_key2.to_string().encode('hex')

    def derive_pubkeys(self, for_change, n):
        return self.get_pubkey_from_mpk(self.mpk, for_change, n)

    def get_private_key_from_stretched_exponent(self, for_change, n, secexp):
        order = generator_secp256k1.order()
        secexp = ( secexp + self.get_sequence(self.mpk, for_change, n) ) % order
        pk = number_to_string( secexp, generator_secp256k1.order() )
        compressed = False
        return SecretToASecret( pk, compressed )


    def get_private_key(self, sequence, wallet, password):
        seed = wallet.get_seed(password)
        self.check_seed(seed)
        for_change, n = sequence
        secexp = self.stretch_key(seed)
        pk = self.get_private_key_from_stretched_exponent(for_change, n, secexp)
        return [pk]


    def check_seed(self, seed):
        secexp = self.stretch_key(seed)
        master_private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve = SECP256k1 )
        master_public_key = master_private_key.get_verifying_key().to_string()
        if master_public_key != self.mpk:
            print_error('invalid password (mpk)', self.mpk.encode('hex'), master_public_key.encode('hex'))
            raise InvalidPassword()
        return True

    def get_master_pubkeys(self):
        return [self.mpk.encode('hex')]

    def get_type(self):
        return _('Old Electrum format')

    def get_xpubkeys(self, for_change, n):
        s = ''.join(map(lambda x: bitcoin.int_to_hex(x,2), (for_change, n)))
        mpk = self.mpk.encode('hex')
        x_pubkey = 'fe' + mpk + s
        return [ x_pubkey ]

    @classmethod
    def parse_xpubkey(self, x_pubkey):
        assert is_extended_pubkey(x_pubkey)
        pk = x_pubkey[2:]
        mpk = pk[0:128]
        dd = pk[128:]
        s = []
        while dd:
            n = int(bitcoin.rev_hex(dd[0:4]), 16)
            dd = dd[4:]
            s.append(n)
        assert len(s) == 2
        return mpk, s


class BIP32_Account(Account):

    def __init__(self, v):
        Account.__init__(self, v)
        self.xpub = v['xpub']
        self.xpub_receive = None
        self.xpub_change = None

    def dump(self):
        d = Account.dump(self)
        d['xpub'] = self.xpub
        return d

    def first_address(self):
        pubkeys = self.derive_pubkeys(0, 0)
        addr = self.pubkeys_to_address(pubkeys)
        return addr, pubkeys

    def get_master_pubkeys(self):
        return [self.xpub]

    @classmethod
    def derive_pubkey_from_xpub(self, xpub, for_change, n):
        _, _, _, c, cK = deserialize_xkey(xpub)
        for i in [for_change, n]:
            cK, c = CKD_pub(cK, c, i)
        return cK.encode('hex')

    def get_pubkey_from_xpub(self, xpub, for_change, n):
        xpubs = self.get_master_pubkeys()
        i = xpubs.index(xpub)
        pubkeys = self.get_pubkeys(for_change, n)
        return pubkeys[i]

    def derive_pubkeys(self, for_change, n):
        xpub = self.xpub_change if for_change else self.xpub_receive
        if xpub is None:
            xpub = bip32_public_derivation(self.xpub, "", "/%d"%for_change)
            if for_change:
                self.xpub_change = xpub
            else:
                self.xpub_receive = xpub
        _, _, _, c, cK = deserialize_xkey(xpub)
        cK, c = CKD_pub(cK, c, n)
        result = cK.encode('hex')
        return result


    def get_private_key(self, sequence, wallet, password):
        out = []
        xpubs = self.get_master_pubkeys()
        roots = [k for k, v in wallet.master_public_keys.iteritems() if v in xpubs]
        for root in roots:
            xpriv = wallet.get_master_private_key(root, password)
            if not xpriv:
                continue
            _, _, _, c, k = deserialize_xkey(xpriv)
            pk = bip32_private_key( sequence, k, c )
            out.append(pk)
        return out

    def get_type(self):
        return _('Standard 1 of 1')

    def get_xpubkeys(self, for_change, n):
        # unsorted
        s = ''.join(map(lambda x: bitcoin.int_to_hex(x,2), (for_change,n)))
        xpubs = self.get_master_pubkeys()
        return map(lambda xpub: 'ff' + bitcoin.DecodeBase58Check(xpub).encode('hex') + s, xpubs)

    @classmethod
    def parse_xpubkey(self, pubkey):
        assert is_extended_pubkey(pubkey)
        pk = pubkey.decode('hex')
        pk = pk[1:]
        xkey = bitcoin.EncodeBase58Check(pk[0:78])
        dd = pk[78:]
        s = []
        while dd:
            n = int( bitcoin.rev_hex(dd[0:2].encode('hex')), 16)
            dd = dd[2:]
            s.append(n)
        assert len(s) == 2
        return xkey, s

    def get_name(self, k):
        return "Main account" if k == '0' else "Account " + k




class Multisig_Account(BIP32_Account):

    def __init__(self, v):
        self.m = v.get('m', 2)
        Account.__init__(self, v)
        self.xpub_list = v['xpubs']

    def dump(self):
        d = Account.dump(self)
        d['xpubs'] = self.xpub_list
        d['m'] = self.m
        return d

    def get_pubkeys(self, for_change, n):
        return self.get_pubkey(for_change, n)

    def derive_pubkeys(self, for_change, n):
        return map(lambda x: self.derive_pubkey_from_xpub(x, for_change, n), self.get_master_pubkeys())

    def redeem_script(self, for_change, n):
        pubkeys = self.get_pubkeys(for_change, n)
        return Transaction.multisig_script(sorted(pubkeys), self.m)

    def pubkeys_to_address(self, pubkeys):
        redeem_script = Transaction.multisig_script(sorted(pubkeys), self.m)
        address = hash_160_to_bc_address(hash_160(redeem_script.decode('hex')), 5)
        return address

    def get_address(self, for_change, n):
        return self.pubkeys_to_address(self.get_pubkeys(for_change, n))

    def get_master_pubkeys(self):
        return self.xpub_list

    def get_type(self):
        return _('Multisig %d of %d'%(self.m, len(self.xpub_list)))
