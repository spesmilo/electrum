#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 thomasv@gitorious
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

from bitcoin import *
from i18n import _
from transaction import Transaction



class Account(object):
    def __init__(self, v):
        self.addresses = v.get('0', [])
        self.change = v.get('1', [])

    def dump(self):
        return {'0':self.addresses, '1':self.change}

    def get_addresses(self, for_change):
        return self.change[:] if for_change else self.addresses[:]

    def create_new_address(self, for_change):
        addresses = self.change if for_change else self.addresses
        n = len(addresses)
        address = self.get_address( for_change, n)
        addresses.append(address)
        print address
        return address

    def get_address(self, for_change, n):
        pass
        
    def get_pubkeys(self, sequence):
        return [ self.get_pubkey( *sequence )]

    def has_change(self):
        return True

    def get_name(self, k):
        return _('Main account')

    def get_keyID(self, *sequence):
        pass

    def redeem_script(self, *sequence):
        pass


class PendingAccount(Account):
    def __init__(self, v):
        self.addresses = [ v['pending'] ]
        self.change = []

    def has_change(self):
        return False

    def dump(self):
        return {'pending':self.addresses[0]}

    def get_name(self, k):
        return _('Pending account')


class ImportedAccount(Account):
    def __init__(self, d):
        self.keypairs = d['imported']

    def get_addresses(self, for_change):
        return [] if for_change else sorted(self.keypairs.keys())

    def get_pubkey(self, *sequence):
        for_change, i = sequence
        assert for_change == 0
        addr = self.get_addresses(0)[i]
        return self.keypairs[addr][i][0]

    def get_private_key(self, sequence, wallet, password):
        from wallet import pw_decode
        for_change, i = sequence
        assert for_change == 0
        address = self.get_addresses(0)[i]
        pk = pw_decode(self.keypairs[address][1], password)
        # this checks the password
        assert address == address_from_private_key(pk)
        return [pk]

    def has_change(self):
        return False

    def add(self, address, pubkey, privkey, password):
        from wallet import pw_encode
        self.keypairs[address] = (pubkey, pw_encode(privkey, password ))

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
        self.addresses = v.get(0, [])
        self.change = v.get(1, [])
        self.mpk = v['mpk'].decode('hex')

    def dump(self):
        return {0:self.addresses, 1:self.change}

    @classmethod
    def mpk_from_seed(klass, seed):
        curve = SECP256k1
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

    def get_sequence(self, for_change, n):
        return string_to_number( Hash( "%d:%d:"%(n,for_change) + self.mpk ) )

    def get_address(self, for_change, n):
        pubkey = self.get_pubkey(for_change, n)
        address = public_key_to_bc_address( pubkey.decode('hex') )
        return address

    def get_pubkey(self, for_change, n):
        curve = SECP256k1
        mpk = self.mpk
        z = self.get_sequence(for_change, n)
        master_public_key = ecdsa.VerifyingKey.from_string( mpk, curve = SECP256k1 )
        pubkey_point = master_public_key.pubkey.point + z*curve.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )
        return '04' + public_key2.to_string().encode('hex')

    def get_private_key_from_stretched_exponent(self, for_change, n, secexp):
        order = generator_secp256k1.order()
        secexp = ( secexp + self.get_sequence(for_change, n) ) % order
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
        curve = SECP256k1
        secexp = self.stretch_key(seed)
        master_private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve = SECP256k1 )
        master_public_key = master_private_key.get_verifying_key().to_string()
        if master_public_key != self.mpk:
            print_error('invalid password (mpk)', self.mpk.encode('hex'), master_public_key.encode('hex'))
            raise Exception('Invalid password')
        return True

    def redeem_script(self, sequence):
        return None

    def get_master_pubkeys(self):
        return [self.mpk.encode('hex')]

    def get_type(self):
        return _('Old Electrum format')

    def get_keyID(self, sequence):
        a, b = sequence
        return 'old(%s,%d,%d)'%(self.mpk.encode('hex'),a,b)



class BIP32_Account(Account):

    def __init__(self, v):
        Account.__init__(self, v)
        self.xpub = v['xpub']

    def dump(self):
        d = Account.dump(self)
        d['xpub'] = self.xpub
        return d

    def get_address(self, for_change, n):
        pubkey = self.get_pubkey(for_change, n)
        address = public_key_to_bc_address( pubkey.decode('hex') )
        return address

    def first_address(self):
        return self.get_address(0,0)

    def get_master_pubkeys(self):
        return [self.xpub]

    def get_pubkey_from_x(self, xpub, for_change, n):
        _, _, _, c, cK = deserialize_xkey(xpub)
        for i in [for_change, n]:
            cK, c = CKD_pub(cK, c, i)
        return cK.encode('hex')

    def get_pubkeys(self, sequence):
        return sorted(map(lambda x: self.get_pubkey_from_x(x, *sequence), self.get_master_pubkeys()))

    def get_pubkey(self, for_change, n):
        return self.get_pubkeys((for_change, n))[0]


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


    def redeem_script(self, sequence):
        return None

    def get_type(self):
        return _('Standard 1 of 1')

    def get_keyID(self, sequence):
        s = '/' + '/'.join( map(lambda x:str(x), sequence) )
        return '&'.join( map(lambda x: 'bip32(%s,%s)'%(x, s), self.get_master_pubkeys() ) )

    def get_name(self, k):
        name = "Unnamed account"
        m = re.match("m/(\d+)'", k)
        if m:
            num = m.group(1)
            if num == '0':
                name = "Main account"
            else:
                name = "Account %s"%num
                    
        return name



class BIP32_Account_2of2(BIP32_Account):

    def __init__(self, v):
        BIP32_Account.__init__(self, v)
        self.xpub2 = v['xpub2']

    def dump(self):
        d = BIP32_Account.dump(self)
        d['xpub2'] = self.xpub2
        return d

    def redeem_script(self, sequence):
        pubkeys = self.get_pubkeys(sequence)
        return Transaction.multisig_script(pubkeys, 2)

    def get_address(self, for_change, n):
        address = hash_160_to_bc_address(hash_160(self.redeem_script((for_change, n)).decode('hex')), 5)
        return address

    def get_master_pubkeys(self):
        return [self.xpub, self.xpub2]

    def get_type(self):
        return _('Multisig 2 of 2')


class BIP32_Account_2of3(BIP32_Account_2of2):

    def __init__(self, v):
        BIP32_Account_2of2.__init__(self, v)
        self.xpub3 = v['xpub3']

    def dump(self):
        d = BIP32_Account_2of2.dump(self)
        d['xpub3'] = self.xpub3
        return d

    def get_master_pubkeys(self):
        return [self.xpub, self.xpub2, self.xpub3]

    def get_type(self):
        return _('Multisig 2 of 3')




