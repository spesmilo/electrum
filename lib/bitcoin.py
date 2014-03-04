# -*- coding: utf-8 -*-
#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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


import hashlib, base64, ecdsa, re
import hmac
from util import print_error

def rev_hex(s):
    return s.decode('hex')[::-1].encode('hex')

def int_to_hex(i, length=1):
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

def var_int(i):
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    if i<0xfd:
        return int_to_hex(i)
    elif i<=0xffff:
        return "fd"+int_to_hex(i,2)
    elif i<=0xffffffff:
        return "fe"+int_to_hex(i,4)
    else:
        return "ff"+int_to_hex(i,8)

def op_push(i):
    if i<0x4c:
        return int_to_hex(i)
    elif i<0xff:
        return '4c' + int_to_hex(i)
    elif i<0xffff:
        return '4d' + int_to_hex(i,2)
    else:
        return '4e' + int_to_hex(i,4)
    


def sha256(x):
    return hashlib.sha256(x).digest()

def Hash(x):
    if type(x) is unicode: x=x.encode('utf-8')
    return sha256(sha256(x))

hash_encode = lambda x: x[::-1].encode('hex')
hash_decode = lambda x: x.decode('hex')[::-1]
hmac_sha_512 = lambda x,y: hmac.new(x, y, hashlib.sha512).digest()

def mnemonic_to_seed(mnemonic, passphrase):
    from pbkdf2 import PBKDF2
    import hmac
    PBKDF2_ROUNDS = 2048
    return PBKDF2(mnemonic, 'mnemonic' + passphrase, iterations = PBKDF2_ROUNDS, macmodule = hmac, digestmodule = hashlib.sha512).read(64)

from version import SEED_PREFIX
is_seed = lambda x: hmac_sha_512("Seed version", x).encode('hex')[0:2].startswith(SEED_PREFIX)

# pywallet openssl private key implementation

def i2d_ECPrivateKey(pkey, compressed=False):
    if compressed:
        key = '3081d30201010420' + \
              '%064x' % pkey.secret + \
              'a081a53081a2020101302c06072a8648ce3d0101022100' + \
              '%064x' % _p + \
              '3006040100040107042102' + \
              '%064x' % _Gx + \
              '022100' + \
              '%064x' % _r + \
              '020101a124032200'
    else:
        key = '308201130201010420' + \
              '%064x' % pkey.secret + \
              'a081a53081a2020101302c06072a8648ce3d0101022100' + \
              '%064x' % _p + \
              '3006040100040107044104' + \
              '%064x' % _Gx + \
              '%064x' % _Gy + \
              '022100' + \
              '%064x' % _r + \
              '020101a144034200'
        
    return key.decode('hex') + i2o_ECPublicKey(pkey.pubkey, compressed)
    
def i2o_ECPublicKey(pubkey, compressed=False):
    # public keys are 65 bytes long (520 bits)
    # 0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
    # 0x00 = point at infinity, 0x02 and 0x03 = compressed, 0x04 = uncompressed
    # compressed keys: <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
    if compressed:
        if pubkey.point.y() & 1:
            key = '03' + '%064x' % pubkey.point.x()
        else:
            key = '02' + '%064x' % pubkey.point.x()
    else:
        key = '04' + \
              '%064x' % pubkey.point.x() + \
              '%064x' % pubkey.point.y()
            
    return key.decode('hex')
            
# end pywallet openssl private key implementation

                                                
            
############ functions from pywallet ##################### 

def hash_160(public_key):
    try:
        md = hashlib.new('ripemd160')
        md.update(sha256(public_key))
        return md.digest()
    except Exception:
        import ripemd
        md = ripemd.new(sha256(public_key))
        return md.digest()


def public_key_to_bc_address(public_key):
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160)

def hash_160_to_bc_address(h160, addrtype = 0):
    vh160 = chr(addrtype) + h160
    h = Hash(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)

def bc_address_to_hash_160(addr):
    bytes = b58decode(addr, 25)
    return ord(bytes[0]), bytes[1:21]


__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
    """ encode v, which is a string of bytes, to base58."""

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def b58decode(v, length):
    """ decode v into a string of len bytes."""
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base**i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]: nPad += 1
        else: break

    result = chr(0)*nPad + result
    if length is not None and len(result) != length:
        return None

    return result


def EncodeBase58Check(vchIn):
    hash = Hash(vchIn)
    return b58encode(vchIn + hash[0:4])

def DecodeBase58Check(psz):
    vchRet = b58decode(psz, None)
    key = vchRet[0:-4]
    csum = vchRet[-4:]
    hash = Hash(key)
    cs32 = hash[0:4]
    if cs32 != csum:
        return None
    else:
        return key

def PrivKeyToSecret(privkey):
    return privkey[9:9+32]

def SecretToASecret(secret, compressed=False, addrtype=0):
    vchIn = chr((addrtype+128)&255) + secret
    if compressed: vchIn += '\01'
    return EncodeBase58Check(vchIn)

def ASecretToSecret(key, addrtype=0):
    vch = DecodeBase58Check(key)
    if vch and vch[0] == chr((addrtype+128)&255):
        return vch[1:]
    else:
        return False

def regenerate_key(sec):
    b = ASecretToSecret(sec)
    if not b:
        return False
    b = b[0:32]
    return EC_KEY(b)

def GetPubKey(pubkey, compressed=False):
    return i2o_ECPublicKey(pubkey, compressed)

def GetPrivKey(pkey, compressed=False):
    return i2d_ECPrivateKey(pkey, compressed)

def GetSecret(pkey):
    return ('%064x' % pkey.secret).decode('hex')

def is_compressed(sec):
    b = ASecretToSecret(sec)
    return len(b) == 33


def public_key_from_private_key(sec):
    # rebuild public key from private key, compressed or uncompressed
    pkey = regenerate_key(sec)
    assert pkey
    compressed = is_compressed(sec)
    public_key = GetPubKey(pkey.pubkey, compressed)
    return public_key.encode('hex')


def address_from_private_key(sec):
    public_key = public_key_from_private_key(sec)
    address = public_key_to_bc_address(public_key.decode('hex'))
    return address


def is_valid(addr):
    ADDRESS_RE = re.compile('[1-9A-HJ-NP-Za-km-z]{26,}\\Z')
    if not ADDRESS_RE.match(addr): return False
    try:
        addrtype, h = bc_address_to_hash_160(addr)
    except Exception:
        return False
    return addr == hash_160_to_bc_address(h, addrtype)


########### end pywallet functions #######################

try:
    from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
except Exception:
    print "cannot import ecdsa.curve_secp256k1. You probably need to upgrade ecdsa.\nTry: sudo pip install --upgrade ecdsa"
    exit()

from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.util import string_to_number, number_to_string

def msg_magic(message):
    varint = var_int(len(message))
    encoded_varint = "".join([chr(int(varint[i:i+2], 16)) for i in xrange(0, len(varint), 2)])
    return "\x18Bitcoin Signed Message:\n" + encoded_varint + message


def verify_message(address, signature, message):
    try:
        EC_KEY.verify_message(address, signature, message)
        return True
    except Exception as e:
        print_error("Verification error: {0}".format(e))
        return False


def encrypt_message(message, pubkey):
    return EC_KEY.encrypt_message(message, pubkey.decode('hex'))


def chunks(l, n):
    return [l[i:i+n] for i in xrange(0, len(l), n)]


def ECC_YfromX(x,curved=curve_secp256k1, odd=True):
    _p = curved.p()
    _a = curved.a()
    _b = curved.b()
    for offset in range(128):
        Mx = x + offset
        My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
        My = pow(My2, (_p+1)/4, _p )

        if curved.contains_point(Mx,My):
            if odd == bool(My&1):
                return [My,offset]
            return [_p-My,offset]
    raise Exception('ECC_YfromX: No Y found')

def private_header(msg,v):
    assert v<1, "Can't write version %d private header"%v
    r = ''
    if v==0:
        r += ('%08x'%len(msg)).decode('hex')
        r += sha256(msg)[:2]
    return ('%02x'%v).decode('hex') + ('%04x'%len(r)).decode('hex') + r

def public_header(pubkey,v):
    assert v<1, "Can't write version %d public header"%v
    r = ''
    if v==0:
        r = sha256(pubkey)[:2]
    return '\x6a\x6a' + ('%02x'%v).decode('hex') + ('%04x'%len(r)).decode('hex') + r


def negative_point(P):
    return Point( P.curve(), P.x(), -P.y(), P.order() )


def point_to_ser(P, comp=True ):
    if comp:
        return ( ('%02x'%(2+(P.y()&1)))+('%064x'%P.x()) ).decode('hex')
    return ( '04'+('%064x'%P.x())+('%064x'%P.y()) ).decode('hex')


def ser_to_point(Aser):
    curve = curve_secp256k1
    generator = generator_secp256k1
    _r  = generator.order()
    assert Aser[0] in ['\x02','\x03','\x04']
    if Aser[0] == '\x04':
        return Point( curve, str_to_long(Aser[1:33]), str_to_long(Aser[33:]), _r )
    Mx = string_to_number(Aser[1:])
    return Point( curve, Mx, ECC_YfromX(Mx, curve, Aser[0]=='\x03')[0], _r )



class EC_KEY(object):
    def __init__( self, k ):
        secret = string_to_number(k)
        self.pubkey = ecdsa.ecdsa.Public_key( generator_secp256k1, generator_secp256k1 * secret )
        self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
        self.secret = secret

    def get_public_key(self, compressed=True):
        return point_to_ser(self.pubkey.point, compressed).encode('hex')

    def sign_message(self, message, compressed, address):
        private_key = ecdsa.SigningKey.from_secret_exponent( self.secret, curve = SECP256k1 )
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest_deterministic( Hash( msg_magic(message) ), hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_string )
        assert public_key.verify_digest( signature, Hash( msg_magic(message) ), sigdecode = ecdsa.util.sigdecode_string)
        for i in range(4):
            sig = base64.b64encode( chr(27 + i + (4 if compressed else 0)) + signature )
            try:
                self.verify_message( address, sig, message)
                return sig
            except Exception:
                continue
        else:
            raise Exception("error: cannot sign message")


    @classmethod
    def verify_message(self, address, signature, message):
        """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
        from ecdsa import numbertheory, util
        import msqr
        curve = curve_secp256k1
        G = generator_secp256k1
        order = G.order()
        # extract r,s from signature
        sig = base64.b64decode(signature)
        if len(sig) != 65: raise Exception("Wrong encoding")
        r,s = util.sigdecode_string(sig[1:], order)
        nV = ord(sig[0])
        if nV < 27 or nV >= 35:
            raise Exception("Bad encoding")
        if nV >= 31:
            compressed = True
            nV -= 4
        else:
            compressed = False

        recid = nV - 27
        # 1.1
        x = r + (recid/2) * order
        # 1.3
        alpha = ( x * x * x  + curve.a() * x + curve.b() ) % curve.p()
        beta = msqr.modular_sqrt(alpha, curve.p())
        y = beta if (beta - recid) % 2 == 0 else curve.p() - beta
        # 1.4 the constructor checks that nR is at infinity
        R = Point(curve, x, y, order)
        # 1.5 compute e from message:
        h = Hash( msg_magic(message) )
        e = string_to_number(h)
        minus_e = -e % order
        # 1.6 compute Q = r^-1 (sR - eG)
        inv_r = numbertheory.inverse_mod(r,order)
        Q = inv_r * ( s * R + minus_e * G )
        public_key = ecdsa.VerifyingKey.from_public_point( Q, curve = SECP256k1 )
        # check that Q is the public key
        public_key.verify_digest( sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)
        # check that we get the original signing address
        addr = public_key_to_bc_address( point_to_ser(public_key.pubkey.point, compressed) )
        if address != addr:
            raise Exception("Bad signature")


    # ecdsa encryption/decryption methods
    # credits: jackjack, https://github.com/jackjack-jj/jeeq

    @classmethod
    def encrypt_message(self, message, pubkey):
        generator = generator_secp256k1
        curved = curve_secp256k1
        r = ''
        msg = private_header(message,0) + message
        msg = msg + ('\x00'*( 32-(len(msg)%32) ))
        msgs = chunks(msg,32)

        _r  = generator.order()
        str_to_long = string_to_number

        P = generator
        if len(pubkey)==33: #compressed
            pk = Point( curve_secp256k1, str_to_long(pubkey[1:33]), ECC_YfromX(str_to_long(pubkey[1:33]), curve_secp256k1, pubkey[0]=='\x03')[0], _r )
        else:
            pk = Point( curve_secp256k1, str_to_long(pubkey[1:33]), str_to_long(pubkey[33:65]), _r )

        for i in range(len(msgs)):
            n = ecdsa.util.randrange( pow(2,256) )
            Mx = str_to_long(msgs[i])
            My, xoffset = ECC_YfromX(Mx, curved)
            M = Point( curved, Mx+xoffset, My, _r )
            T = P*n
            U = pk*n + M
            toadd = point_to_ser(T) + point_to_ser(U)
            toadd = chr(ord(toadd[0])-2 + 2*xoffset) + toadd[1:]
            r += toadd

        return base64.b64encode(public_header(pubkey,0) + r)


    def decrypt_message(self, enc):
        G = generator_secp256k1
        curved = curve_secp256k1
        pvk = self.secret
        pubkeys = [point_to_ser(G*pvk,True), point_to_ser(G*pvk,False)]
        enc = base64.b64decode(enc)
        str_to_long = string_to_number

        assert enc[:2]=='\x6a\x6a'

        phv = str_to_long(enc[2])
        assert phv==0, "Can't read version %d public header"%phv
        hs = str_to_long(enc[3:5])
        public_header=enc[5:5+hs]
        checksum_pubkey=public_header[:2]
        address=filter(lambda x:sha256(x)[:2]==checksum_pubkey, pubkeys)
        assert len(address)>0, 'Bad private key'
        address=address[0]
        enc=enc[5+hs:]
        r = ''
        for Tser,User in map(lambda x:[x[:33],x[33:]], chunks(enc,66)):
            ots = ord(Tser[0])
            xoffset = ots>>1
            Tser = chr(2+(ots&1))+Tser[1:]
            T = ser_to_point(Tser)
            U = ser_to_point(User)
            V = T*pvk
            Mcalc = U + negative_point(V)
            r += ('%064x'%(Mcalc.x()-xoffset)).decode('hex')

        pvhv = str_to_long(r[0])
        assert pvhv==0, "Can't read version %d private header"%pvhv
        phs = str_to_long(r[1:3])
        private_header = r[3:3+phs]
        size = str_to_long(private_header[:4])
        checksum = private_header[4:6]
        r = r[3+phs:]

        msg = r[:size]
        hashmsg = sha256(msg)[:2]
        checksumok = hashmsg==checksum

        return [msg, checksumok, address]





###################################### BIP32 ##############################

random_seed = lambda n: "%032x"%ecdsa.util.randrange( pow(2,n) )
BIP32_PRIME = 0x80000000

def bip32_init(seed):
    import hmac
    seed = seed.decode('hex')        
    I = hmac.new("Bitcoin seed", seed, hashlib.sha512).digest()

    master_secret = I[0:32]
    master_chain = I[32:]

    K, K_compressed = get_pubkeys_from_secret(master_secret)
    return master_secret, master_chain, K, K_compressed


def get_pubkeys_from_secret(secret):
    # public key
    private_key = ecdsa.SigningKey.from_string( secret, curve = SECP256k1 )
    public_key = private_key.get_verifying_key()
    K = public_key.to_string()
    K_compressed = GetPubKey(public_key.pubkey,True)
    return K, K_compressed



# Child private key derivation function (from master private key)
# k = master private key (32 bytes)
# c = master chain code (extra entropy for key derivation) (32 bytes)
# n = the index of the key we want to derive. (only 32 bits will be used)
# If n is negative (i.e. the 32nd bit is set), the resulting private key's
#  corresponding public key can NOT be determined without the master private key.
# However, if n is positive, the resulting private key's corresponding
#  public key can be determined without the master private key.
def CKD(k, c, n):
    import hmac
    from ecdsa.util import string_to_number, number_to_string
    order = generator_secp256k1.order()
    keypair = EC_KEY(k)
    K = GetPubKey(keypair.pubkey,True)

    if n & BIP32_PRIME: # We want to make a "secret" address that can't be determined from K
        data = chr(0) + k + rev_hex(int_to_hex(n,4)).decode('hex')
        I = hmac.new(c, data, hashlib.sha512).digest()
    else: # We want a "non-secret" address that can be determined from K
        I = hmac.new(c, K + rev_hex(int_to_hex(n,4)).decode('hex'), hashlib.sha512).digest()
        
    k_n = number_to_string( (string_to_number(I[0:32]) + string_to_number(k)) % order , order )
    c_n = I[32:]
    return k_n, c_n

# Child public key derivation function (from public key only)
# K = master public key 
# c = master chain code
# n = index of key we want to derive
# This function allows us to find the nth public key, as long as n is 
#  non-negative. If n is negative, we need the master private key to find it.
def CKD_prime(K, c, n):
    import hmac
    from ecdsa.util import string_to_number, number_to_string
    order = generator_secp256k1.order()

    if n & BIP32_PRIME: raise

    K_public_key = ecdsa.VerifyingKey.from_string( K, curve = SECP256k1 )
    K_compressed = GetPubKey(K_public_key.pubkey,True)

    I = hmac.new(c, K_compressed + rev_hex(int_to_hex(n,4)).decode('hex'), hashlib.sha512).digest()

    curve = SECP256k1
    pubkey_point = string_to_number(I[0:32])*curve.generator + K_public_key.pubkey.point
    public_key = ecdsa.VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )

    K_n = public_key.to_string()
    K_n_compressed = GetPubKey(public_key.pubkey,True)
    c_n = I[32:]

    return K_n, K_n_compressed, c_n



def bip32_private_derivation(k, c, branch, sequence):
    assert sequence.startswith(branch)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '': continue
        n = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        k, c = CKD(k, c, n)
    K, K_compressed = get_pubkeys_from_secret(k)
    return k.encode('hex'), c.encode('hex'), K.encode('hex'), K_compressed.encode('hex')


def bip32_public_derivation(c, K, branch, sequence):
    assert sequence.startswith(branch)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        n = int(n)
        K, cK, c = CKD_prime(K, c, n)

    return c.encode('hex'), K.encode('hex'), cK.encode('hex')


def bip32_private_key(sequence, k, chain):
    for i in sequence:
        k, chain = CKD(k, chain, i)
    return SecretToASecret(k, True)




################################## transactions

MIN_RELAY_TX_FEE = 10000



def test_bip32(seed, sequence):
    """
    run a test vector,
    see https://en.bitcoin.it/wiki/BIP_0032_TestVectors
    """

    master_secret, master_chain, master_public_key, master_public_key_compressed = bip32_init(seed)
        
    print "secret key", master_secret.encode('hex')
    print "chain code", master_chain.encode('hex')

    key_id = hash_160(master_public_key_compressed)
    print "keyid", key_id.encode('hex')
    print "base58"
    print "address", hash_160_to_bc_address(key_id)
    print "secret key", SecretToASecret(master_secret, True)

    k = master_secret
    c = master_chain

    s = ['m']
    for n in sequence.split('/'):
        s.append(n)
        print "Chain [%s]" % '/'.join(s)
        
        n = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        k0, c0 = CKD(k, c, n)
        K0, K0_compressed = get_pubkeys_from_secret(k0)

        print "* Identifier"
        print "  * (main addr)", hash_160_to_bc_address(hash_160(K0_compressed))

        print "* Secret Key"
        print "  * (hex)", k0.encode('hex')
        print "  * (wif)", SecretToASecret(k0, True)

        print "* Chain Code"
        print "   * (hex)", c0.encode('hex')

        k = k0
        c = c0
    print "----"

        

def test_crypto():

    G = generator_secp256k1
    _r  = G.order()
    pvk = ecdsa.util.randrange( pow(2,256) ) %_r

    Pub = pvk*G
    pubkey_c = point_to_ser(Pub,True)
    pubkey_u = point_to_ser(Pub,False)
    addr_c = public_key_to_bc_address(pubkey_c)
    addr_u = public_key_to_bc_address(pubkey_u)

    print "Private key            ", '%064x'%pvk
    print "Compressed public key  ", pubkey_c.encode('hex')
    print "Uncompressed public key", pubkey_u.encode('hex')

    message = "Chancellor on brink of second bailout for banks"
    enc = EC_KEY.encrypt_message(message,pubkey_c)
    eck = EC_KEY(number_to_string(pvk,_r))
    dec = eck.decrypt_message(enc)
    print "decrypted", dec

    signature = eck.sign_message(message, True, addr_c)
    print signature
    EC_KEY.verify_message(addr_c, signature, message)


if __name__ == '__main__':
    test_crypto()
    #test_bip32("000102030405060708090a0b0c0d0e0f", "0'/1/2'/2/1000000000")
    #test_bip32("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542","0/2147483647'/1/2147483646'/2")

