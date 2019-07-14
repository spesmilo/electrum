
import hashlib
from functools import reduce
from operator import mul
from electrum import bitcoin

try: 
    from hashlib import scrypt
    def scrypt_func(data):
        return scrypt(data.encode("ascii"),salt=b"",n=16384,r=8,p=8,dklen=32)

except:
    import pyscrypt as scrypt
    def scrypt_func(data):
        scrypt.hash(data.encode("ascii"),salt=b"",N=16384,r=8,p=8,dkLen=32)

bitcoin_b58chars = bitcoin.__b58chars
bitcoin_b58chars_values = dict((chr(c), val) for val, c in enumerate(bitcoin_b58chars))

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def compute_privatekey_sec256k1(secret1_b58, secret2_b58):
    hashed_secret1 = scrypt_func(secret1_b58)
    hashed_secret2 = scrypt_func(secret2_b58)

    n1 = int.from_bytes(hashed_secret1, 'big')
    n2 = int.from_bytes(hashed_secret2, 'big')
    n0 = (n1 + n2) % N

    privkey_b256 = int.to_bytes(n0, 32, 'big')

    return privkey_b256

def compute_privatekey_bitcoin(secret1_b58, secret2_b58):

    privkey_b256 = compute_privatekey_sec256k1(secret1_b58, secret2_b58)
    privkey_wif = bitcoin.serialize_privkey(privkey_b256, compressed=True, internal_use=True, txin_type="p2pkh")
    return privkey_wif
    
p14 = 4875194084160298409672797
p28 = 23767517358231570773047645414309870043308402671871

def reconstruct(secrets,l):

    if l == 14:
        p = p14
    if l == 28:
        p = p28
    V = make_zp_value_type(p)
    recovershares = [Share(i, V(base58decode(c))) for i, c in secrets]

    s = shamir_reconstruct(recovershares, p)
    return  base58encode(s, length=l)

def lagrange(points, modulus):
    """ Evaluation at x=0 without computing the polynomial 
        Params
            points: list of Share
        Returns
            y: int """
    V = make_zp_value_type(modulus)
    ls = []
    for i, pj in enumerate(points):
        factors = []
        for j, pm in enumerate(points):
            if i != j:
                factors.append((V(0) - V(pm.x)) / (V(pj.x) - V(pm.x)))
        l = reduce(mul, factors)
        ls.append(l)
    L = map(mul, ls, [p.y for p in points])
    y = int(sum(L, V(0)))
    return y

def shamir_reconstruct(shares, modulus):
    """ Reconstructs the secret using Lagrange polynomial interpolation.
        Params
            shares: list of Share (at least 2 Shares as k > 1 for SSSS)
        Returns
            secret: string """
    if len(shares) < 2:
        raise ReconstructionError('Shares are not correct, reconstruction did not work.')
    secret_int = lagrange(shares, modulus)
    return secret_int

def extended_gcd(n1, n2):
    """ Returns (bezout_a, bezout_b, gcd) using the extended euclidean algorithm.
        Params
            n1: int
            n2: int
        Returns
            bezout_a: int
            bezout_b: int
            gcd: int """
    x = 0
    x_old = 1
    y = 1
    y_old  = 0
    while n2 != 0:
        Q = n1 // n2 #quotient
        n1, n2 = n2, n1%n2
        x, x_old = x_old - Q*x, x
        y, y_old = y_old - Q*y, y
    bezout_a = x_old
    bezout_b = y_old
    gcd = n1
    return (bezout_a, bezout_b, gcd)

def make_zp_value_type(modulus):
    class ZpValue(object):
        def __init__(self, value):
            assert (0 <= value < modulus)
            self.value = value
        def __neg__(self):
            return ZpValue((-self.value) % modulus)
        def __add__(self, other):
            return ZpValue((self.value + other.value) % modulus)
        def __cmp__(self, other):
            return cmp(self.value, other.value)
        def __eq__(self, other):
            if type(other) is not type(self):
                return False
            return self.value == other.value
        def __hash__(self):
            return hash(self.value)
        def __sub__(self, other):
            return ZpValue((self.value - other.value) % modulus)
        def __mul__(self, other):
            return ZpValue((self.value * other.value) % modulus)
        def __pow__(self, other):
            return ZpValue(pow(self.value, other.value, modulus))
        def __str__(self):
            return str(self.value)
        def __repr__(self):
            return 'V('+repr(self.value)+')'
        def __invert__(self):
            if self.value == 0:
                raise ZeroDivisionError()
            bezout_a, _, _ = extended_gcd(self.value, modulus)
            return ZpValue(bezout_a % modulus)
        def __truediv__(self, other):
            return self * ~other
        def __int__(self):
            return self.value
    return ZpValue
    
class ZpField(object):
    """ZpZ field with the given modulus"""
    def __init__(self, modulus=186656847850553718541328329082447202544255493182466124110756684855815008420043):
        self.modulus = modulus #default modulus is prime following 2**256
        self.value_type = make_zp_value_type(self.modulus)
        

class Share(object):
    def __init__(self, x, y):
        """ 
        This data structure can be a Shamir or an IDA share, containing 
        its x, which is the index, and its y=P(x) which is the share.
        Params
            x: int
            y: field.ZpValue
        """
        self.x = x
        self.y = y
        
    def __eq__(self, other):
        if type(other) is not type(self):
            return False
        if self.x == other.x and self.y == other.y:
            return True
        return False

    def __repr__(self):
        rep = '['+type(self).__name__+'] '
        rep += 'Index x = '+str(self.x)+', Share y = P(x) = '+str(self.y)
        return rep

def base58encode(value, leading_zeros=None, length=None):
    result = ""
    while value != 0:
        div, mod = divmod(value, 58)
        result = chr(bitcoin_b58chars[mod]) + result
        value = div
    if leading_zeros:
        return chr(bitcoin_b58chars[0]) * leading_zeros + result
    if length is not None:
        result = chr(bitcoin_b58chars[0]) * (length-len(result)) + result
    return result

def base58decode(b58str):
    value = 0
    for c in b58str:
        if c not in bitcoin_b58chars_values:
            raise Base58DecodingError("Invalid character: %s" % (c))
        value = value * 58 + bitcoin_b58chars_values[c]
    return (value)

