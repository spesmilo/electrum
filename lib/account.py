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
        
    def get_private_key(self, seed, sequence):
        for_change, n = sequence
        secexp = self.stretch_key(seed)
        return self.get_private_key_from_stretched_exponent(for_change, n, secexp)

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


class BIP32_Account(Account):

    def __init__(self, v):
        Account.__init__(self, v)
        self.c = v['c'].decode('hex')
        self.K = v['K'].decode('hex')
        self.cK = v['cK'].decode('hex')

    def dump(self):
        d = Account.dump(self)
        d['c'] = self.c.encode('hex')
        d['K'] = self.K.encode('hex')
        d['cK'] = self.cK.encode('hex')
        return d

    def get_address(self, for_change, n):
        pubkey = self.get_pubkey(for_change, n)
        address = public_key_to_bc_address( pubkey.decode('hex') )
        return address

    def first_address(self):
        return self.get_address(0,0)

    def get_pubkey(self, for_change, n):
        K = self.K
        chain = self.c
        for i in [for_change, n]:
            K, K_compressed, chain = CKD_prime(K, chain, i)
        return K_compressed.encode('hex')

    def redeem_script(self, sequence):
        return None




class BIP32_Account_2of2(BIP32_Account):

    def __init__(self, v):
        BIP32_Account.__init__(self, v)
        self.c2 = v['c2'].decode('hex')
        self.K2 = v['K2'].decode('hex')
        self.cK2 = v['cK2'].decode('hex')

    def dump(self):
        d = BIP32_Account.dump(self)
        d['c2'] = self.c2.encode('hex')
        d['K2'] = self.K2.encode('hex')
        d['cK2'] = self.cK2.encode('hex')
        return d

    def get_pubkey2(self, for_change, n):
        K = self.K2
        chain = self.c2
        for i in [for_change, n]:
            K, K_compressed, chain = CKD_prime(K, chain, i)
        return K_compressed.encode('hex')

    def redeem_script(self, sequence):
        chain, i = sequence
        pubkey1 = self.get_pubkey(chain, i)
        pubkey2 = self.get_pubkey2(chain, i)
        return Transaction.multisig_script([pubkey1, pubkey2], 2)

    def get_address(self, for_change, n):
        address = hash_160_to_bc_address(hash_160(self.redeem_script((for_change, n)).decode('hex')), 5)
        return address

    def get_pubkeys(self, sequence):
        return [ self.get_pubkey( *sequence ), self.get_pubkey2( *sequence )]

class BIP32_Account_2of3(BIP32_Account_2of2):

    def __init__(self, v):
        BIP32_Account_2of2.__init__(self, v)
        self.c3 = v['c3'].decode('hex')
        self.K3 = v['K3'].decode('hex')
        self.cK3 = v['cK3'].decode('hex')

    def dump(self):
        d = BIP32_Account_2of2.dump(self)
        d['c3'] = self.c3.encode('hex')
        d['K3'] = self.K3.encode('hex')
        d['cK3'] = self.cK3.encode('hex')
        return d

    def get_pubkey3(self, for_change, n):
        K = self.K3
        chain = self.c3
        for i in [for_change, n]:
            K, K_compressed, chain = CKD_prime(K, chain, i)
        return K_compressed.encode('hex')

    def get_redeem_script(self, sequence):
        chain, i = sequence
        pubkey1 = self.get_pubkey(chain, i)
        pubkey2 = self.get_pubkey2(chain, i)
        pubkey3 = self.get_pubkey3(chain, i)
        return Transaction.multisig_script([pubkey1, pubkey2, pubkey3], 3)

    def get_pubkeys(self, sequence):
        return [ self.get_pubkey( *sequence ), self.get_pubkey2( *sequence ), self.get_pubkey3( *sequence )]



