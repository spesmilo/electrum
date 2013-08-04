"""
todolist:
 * passwords, private keys storage
 * multisig service
 * compatibility with old addresses for restore
 * gui
 
        an account may use one or several MPKs.
        due to the type 1 derivations, we need to pass the mpk to this function
        None : all accounts
        -1 : imported
        0,1... : seeded sequences

        each account has a public and private master key
"""

from bitcoin import *


class Account(object):
    def __init__(self, v):
        self.addresses = v.get('0', [])
        self.change = v.get('1', [])
        self.name = v.get('name', 'unnamed')

    def dump(self):
        return {'0':self.addresses, '1':self.change, 'name':self.name}

    def get_name(self):
        return self.name

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
        



class OldAccount(Account):
    """  Privatekey(type,n) = Master_private_key + H(n|S|type)  """

    def __init__(self, mpk, mpk2 = None, mpk3 = None):
        self.mpk = mpk
        self.mpk2 = mpk2
        self.mpk3 = mpk3

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

    def get_sequence(self, sequence, mpk):
        for_change, n = sequence
        return string_to_number( Hash( "%d:%d:"%(n,for_change) + mpk.decode('hex') ) )

    def get_address(self, sequence):
        if not self.mpk2:
            pubkey = self.get_pubkey(sequence)
            address = public_key_to_bc_address( pubkey.decode('hex') )
        elif not self.mpk3:
            pubkey1 = self.get_pubkey(sequence)
            pubkey2 = self.get_pubkey(sequence, mpk = self.mpk2)
            address = Transaction.multisig_script([pubkey1, pubkey2], 2)["address"]
        else:
            pubkey1 = self.get_pubkey(sequence)
            pubkey2 = self.get_pubkey(sequence, mpk = self.mpk2)
            pubkey3 = self.get_pubkey(sequence, mpk = self.mpk3)
            address = Transaction.multisig_script([pubkey1, pubkey2, pubkey3], 2)["address"]
        return address

    def get_pubkey(self, sequence, mpk=None):
        curve = SECP256k1
        if mpk is None: mpk = self.mpk
        z = self.get_sequence(sequence, mpk)
        master_public_key = ecdsa.VerifyingKey.from_string( mpk.decode('hex'), curve = SECP256k1 )
        pubkey_point = master_public_key.pubkey.point + z*curve.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )
        return '04' + public_key2.to_string().encode('hex')

    def get_private_key_from_stretched_exponent(self, sequence, secexp):
        order = generator_secp256k1.order()
        secexp = ( secexp + self.get_sequence(sequence, self.mpk) ) % order
        pk = number_to_string( secexp, generator_secp256k1.order() )
        compressed = False
        return SecretToASecret( pk, compressed )
        
    def get_private_key(self, sequence, seed):
        secexp = self.stretch_key(seed)
        return self.get_private_key_from_stretched_exponent(sequence, secexp)

    def get_private_keys(self, sequence_list, seed):
        secexp = self.stretch_key(seed)
        return [ self.get_private_key_from_stretched_exponent( sequence, secexp) for sequence in sequence_list]

    def check_seed(self, seed):
        curve = SECP256k1
        secexp = self.stretch_key(seed)
        master_private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve = SECP256k1 )
        master_public_key = master_private_key.get_verifying_key().to_string().encode('hex')
        if master_public_key != self.mpk:
            print_error('invalid password (mpk)')
            raise BaseException('Invalid password')
        return True

    def get_input_info(self, sequence):
        if not self.mpk2:
            pk_addr = self.get_address(sequence)
            redeemScript = None
        elif not self.mpk3:
            pubkey1 = self.get_pubkey(sequence)
            pubkey2 = self.get_pubkey(sequence,mpk=self.mpk2)
            pk_addr = public_key_to_bc_address( pubkey1.decode('hex') ) # we need to return that address to get the right private key
            redeemScript = Transaction.multisig_script([pubkey1, pubkey2], 2)['redeemScript']
        else:
            pubkey1 = self.get_pubkey(sequence)
            pubkey2 = self.get_pubkey(sequence, mpk=self.mpk2)
            pubkey3 = self.get_pubkey(sequence, mpk=self.mpk3)
            pk_addr = public_key_to_bc_address( pubkey1.decode('hex') ) # we need to return that address to get the right private key
            redeemScript = Transaction.multisig_script([pubkey1, pubkey2, pubkey3], 2)['redeemScript']
        return pk_addr, redeemScript



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
        address = public_key_to_bc_address( pubkey )
        return address

    def get_pubkey(self, for_change, n):
        K = self.K
        chain = self.c
        for i in [for_change, n]:
            K, K_compressed, chain = CKD_prime(K, chain, i)
        return K_compressed

    def get_private_key(self, sequence, master_k):
        chain = self.c
        k = master_k
        for i in sequence:
            k, chain = CKD(k, chain, i)
        return SecretToASecret(k, True)

    def get_private_keys(self, sequence_list, seed):
        return [ self.get_private_key( sequence, seed) for sequence in sequence_list]

    def check_seed(self, seed):
        master_secret, master_chain, master_public_key, master_public_key_compressed = bip32_init(seed)
        assert self.mpk == (master_public_key.encode('hex'), master_chain.encode('hex'))

    def get_input_info(self, sequence):
        chain, i = sequence
        pk_addr = self.get_address(chain, i)
        redeemScript = None
        return pk_addr, redeemScript



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
        return K_compressed

    def get_address(self, for_change, n):
        pubkey1 = self.get_pubkey(for_change, n)
        pubkey2 = self.get_pubkey2(for_change, n)
        address = Transaction.multisig_script([pubkey1.encode('hex'), pubkey2.encode('hex')], 2)["address"]
        return address

    def get_input_info(self, sequence):
        chain, i = sequence
        pubkey1 = self.get_pubkey(chain, i)
        pubkey2 = self.get_pubkey2(chain, i)
        # fixme
        pk_addr = None # public_key_to_bc_address( pubkey1 ) # we need to return that address to get the right private key
        redeemScript = Transaction.multisig_script([pubkey1.encode('hex'), pubkey2.encode('hex')], 2)['redeemScript']
        return pk_addr, redeemScript

