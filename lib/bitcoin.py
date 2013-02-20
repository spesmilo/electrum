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


Hash = lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()
hash_encode = lambda x: x[::-1].encode('hex')
hash_decode = lambda x: x.decode('hex')[::-1]


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
        md.update(hashlib.sha256(public_key).digest())
        return md.digest()
    except:
        import ripemd
        md = ripemd.new(hashlib.sha256(public_key).digest())
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

def encode_point(pubkey, compressed=False):
    order = generator_secp256k1.order()
    p = pubkey.pubkey.point
    x_str = ecdsa.util.number_to_string(p.x(), order)
    y_str = ecdsa.util.number_to_string(p.y(), order)
    if compressed:
        return chr(2 + (p.y() & 1)) + x_str
    else:
        return chr(4) + pubkey.to_string() #x_str + y_str

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
    secret = int('0x' + b.encode('hex'), 16)
    return EC_KEY(secret)

def GetPubKey(pubkey, compressed=False):
    return i2o_ECPublicKey(pubkey, compressed)

def GetPrivKey(pkey, compressed=False):
    return i2d_ECPrivateKey(pkey, compressed)

def GetSecret(pkey):
    return ('%064x' % pkey.secret).decode('hex')

def is_compressed(sec):
    b = ASecretToSecret(sec)
    return len(b) == 33

########### end pywallet functions #######################

# secp256k1, http://www.oid-info.com/get/1.3.132.0.10
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
curve_secp256k1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b )
generator_secp256k1 = ecdsa.ellipticcurve.Point( curve_secp256k1, _Gx, _Gy, _r )
oid_secp256k1 = (1,3,132,0,10)
SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, oid_secp256k1 ) 

class EC_KEY(object):
    def __init__( self, secret ):
        self.pubkey = ecdsa.ecdsa.Public_key( generator_secp256k1, generator_secp256k1 * secret )
        self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
        self.secret = secret


###################################### BIP32 ##############################

def bip32_init(seed):
    import hmac
        
    I = hmac.new("Bitcoin seed", seed, hashlib.sha512).digest()

    print "seed", seed.encode('hex')
    master_secret = I[0:32]
    master_chain = I[32:]

    # public key
    curve = SECP256k1
    master_private_key = ecdsa.SigningKey.from_string( master_secret, curve = SECP256k1 )
    master_public_key = master_private_key.get_verifying_key()
    K = master_public_key.to_string()
    K_compressed = GetPubKey(master_public_key.pubkey,True)
    return master_secret, master_chain, K, K_compressed

    
def CKD(k, c, n):
    import hmac
    from ecdsa.util import string_to_number, number_to_string
    order = generator_secp256k1.order()
    keypair = EC_KEY(string_to_number(k))
    K = GetPubKey(keypair.pubkey,True)
    I = hmac.new(c, K + rev_hex(int_to_hex(n,4)).decode('hex'), hashlib.sha512).digest()
    k_n = number_to_string( (string_to_number(I[0:32]) * string_to_number(k)) % order , order )
    c_n = I[32:]
    return k_n, c_n


def CKD_prime(K, c, n):
    import hmac
    from ecdsa.util import string_to_number, number_to_string
    order = generator_secp256k1.order()

    K_public_key = ecdsa.VerifyingKey.from_string( K, curve = SECP256k1 )
    K_compressed = GetPubKey(K_public_key.pubkey,True)

    I = hmac.new(c, K_compressed + rev_hex(int_to_hex(n,4)).decode('hex'), hashlib.sha512).digest()

    #pubkey = ecdsa.ecdsa.Public_key( generator_secp256k1, string_to_number(I[0:32]) * K_public_key.pubkey.point )
    public_key = ecdsa.VerifyingKey.from_public_point( string_to_number(I[0:32]) * K_public_key.pubkey.point, curve = SECP256k1 )
    K_n = public_key.to_string()
    K_n_compressed = GetPubKey(public_key.pubkey,True)
    c_n = I[32:]

    return K_n, K_n_compressed, c_n





################################## transactions


def tx_filter(s): 
    out = re.sub('( [^\n]*|)\n','',s)
    out = out.replace(' ','')
    out = out.replace('\n','')
    return out

def raw_tx( inputs, outputs, for_sig = None ):
    s  = int_to_hex(1,4)                                         # version
    s += var_int( len(inputs) )                                  # number of inputs
    for i in range(len(inputs)):
        _, _, p_hash, p_index, p_script, pubkeysig = inputs[i]
        s += p_hash.decode('hex')[::-1].encode('hex')            # prev hash
        s += int_to_hex(p_index,4)                               # prev index

        if for_sig is None:
            if len(pubkeysig) == 1:
                pubkey, sig = pubkeysig[0]
                sig = sig + chr(1)                               # hashtype
                script  = int_to_hex( len(sig))
                script += sig.encode('hex')
                script += int_to_hex( len(pubkey))
                script += pubkey.encode('hex')
            else:
                pubkey0, sig0 = pubkeysig[0]
                pubkey1, sig1 = pubkeysig[1]
                sig0 = sig0 + chr(1)
                sig1 = sig1 + chr(1)
                inner_script = multisig_script([pubkey0, pubkey1])
                script = '00'                                    # op_0
                script += int_to_hex(len(sig0))
                script += sig0.encode('hex')
                script += int_to_hex(len(sig1))
                script += sig1.encode('hex')
                script += var_int(len(inner_script)/2)
                script += inner_script

        elif for_sig==i:
            if len(pubkeysig) > 1:
                script = multisig_script(pubkeysig)              # p2sh uses the inner script
            else:
                script = p_script                                # scriptsig
        else:
            script=''
        s += var_int( len(tx_filter(script))/2 )                 # script length
        s += script
        s += "ffffffff"                                          # sequence

    s += var_int( len(outputs) )                                 # number of outputs
    for output in outputs:
        addr, amount = output
        s += int_to_hex( amount, 8)                              # amount
        addrtype, hash_160 = bc_address_to_hash_160(addr)
        if addrtype == 0:
            script = '76a9'                                      # op_dup, op_hash_160
            script += '14'                                       # push 0x14 bytes
            script += hash_160.encode('hex')
            script += '88ac'                                     # op_equalverify, op_checksig
        elif addrtype == 5:
            script = 'a9'                                        # op_hash_160
            script += '14'                                       # push 0x14 bytes
            script += hash_160.encode('hex')
            script += '87'                                       # op_equal
        else:
            raise
            
        s += var_int( len(tx_filter(script))/2 )                #  script length
        s += script                                             #  script
    s += int_to_hex(0,4)                                        #  lock time
    if for_sig is not None and for_sig != 1: s += int_to_hex(1, 4)               #  hash type
    return tx_filter(s)


def deserialize(raw_tx):
    import deserialize
    vds = deserialize.BCDataStream()
    vds.write(raw_tx.decode('hex'))
    return deserialize.parse_Transaction(vds)


def multisig_script(public_keys, num=None):
    # supports only "2 of 2", and "2 of 3" transactions
    n = len(public_keys)

    if num is None:
        num = n

    assert num <= n and n <= 3 and n >= 2
    
    if num==2:
        s = '52'
    elif num == 3:
        s = '53'
    else:
        raise
    
    for k in public_keys:
        s += var_int(len(k)/2)
        s += k
    if n==2:
        s += '52'
    elif n==3:
        s += '53'
    else:
        raise
    s += 'ae'
    return s



def test_bip32():
    seed = "ff000000000000000000000000000000".decode('hex')
    master_secret, master_chain, master_public_key, master_public_key_compressed = bip32_init(seed)
        
    print "secret key", master_secret.encode('hex')
    print "chain code", master_chain.encode('hex')

    key_id = hash_160(master_public_key_compressed)
    print "keyid", key_id.encode('hex')
    print "base58"
    print "address", hash_160_to_bc_address(key_id)
    print "secret key", SecretToASecret(master_secret, True)

    print "-- m/0 --"
    k0, c0 = CKD(master_secret, master_chain, 0)
    print "secret", k0.encode('hex')
    print "chain", c0.encode('hex')
    print "secret key", SecretToASecret(k0, True)
    
    K0, K0_compressed, c0 = CKD_prime(master_public_key, master_chain, 0)
    print "address", hash_160_to_bc_address(hash_160(K0_compressed))
    
    print "-- m/0/1 --"
    K01, K01_compressed, c01 = CKD_prime(K0, c0, 1)
    print "address", hash_160_to_bc_address(hash_160(K01_compressed))
    
    print "-- m/0/1/3 --"
    K013, K013_compressed, c013 = CKD_prime(K01, c01, 3)
    print "address", hash_160_to_bc_address(hash_160(K013_compressed))
    
    print "-- m/0/1/3/7 --"
    K0137, K0137_compressed, c0137 = CKD_prime(K013, c013, 7)
    print "address", hash_160_to_bc_address(hash_160(K0137_compressed))
        

def test_p2sh():

    print "2 of 2"
    pubkeys = ["04e89a79651522201d756f14b1874ae49139cc984e5782afeca30ffe84e5e6b2cfadcfe9875c490c8a1a05a4debd715dd57471af8886ab5dfbb3959d97f087f77a",
               "0455cf4a3ab68a011b18cb0a86aae2b8e9cad6c6355476de05247c57a9632d127084ac7630ad89893b43c486c5a9f7ec6158fb0feb708fa9255d5c4d44bc0858f8"]
    s = multisig_script(pubkeys)
    print "address", hash_160_to_bc_address(hash_160(s.decode('hex')), 5)


    print "Gavin's tutorial: redeem p2sh:  http://blockchain.info/tx-index/30888901"
    pubkey1 = "0491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f86"
    pubkey2 = "04865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec6874"
    pubkey3 = "048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d46213"
    pubkeys = [pubkey1, pubkey2, pubkey3]

    tx_for_sig = raw_tx( [(None, None, '3c9018e8d5615c306d72397f8f5eef44308c98fb576a88e030c25456b4f3a7ac', 0, 'a914f815b036d9bbbce5e9f2a00abd1bf3dc91e9551087', pubkeys)],
                         [('1GtpSrGhRGY5kkrNz4RykoqRQoJuG2L6DS',1000000)], for_sig = 0)

    print "tx for sig", tx_for_sig

    signature1 = "304502200187af928e9d155c4b1ac9c1c9118153239aba76774f775d7c1f9c3e106ff33c0221008822b0f658edec22274d0b6ae9de10ebf2da06b1bbdaaba4e50eb078f39e3d78"
    signature2 = "30440220795f0f4f5941a77ae032ecb9e33753788d7eb5cb0c78d805575d6b00a1d9bfed02203e1f4ad9332d1416ae01e27038e945bc9db59c732728a383a6f1ed2fb99da7a4"

    for pubkey in pubkeys:
        import traceback, sys

        public_key = ecdsa.VerifyingKey.from_string(pubkey[2:].decode('hex'), curve = SECP256k1)

        try:
            public_key.verify_digest( signature1.decode('hex'), Hash( tx_for_sig.decode('hex') ), sigdecode = ecdsa.util.sigdecode_der)
            print True
        except ecdsa.keys.BadSignatureError:
            #traceback.print_exc(file=sys.stdout)
            print False

        try:
            public_key.verify_digest( signature2.decode('hex'), Hash( tx_for_sig.decode('hex') ), sigdecode = ecdsa.util.sigdecode_der)
            print True
        except ecdsa.keys.BadSignatureError:
            #traceback.print_exc(file=sys.stdout)
            print False

if __name__ == '__main__':
    #test_bip32()
    test_p2sh()

