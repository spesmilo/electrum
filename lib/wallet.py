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


import sys, base64, os, re, hashlib, copy, operator, ast, threading, random, getpass
import aes, ecdsa
from ecdsa.util import string_to_number, number_to_string
from util import print_error

############ functions from pywallet ##################### 

addrtype = 0

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

def hash_160_to_bc_address(h160):
    vh160 = chr(addrtype) + h160
    h = Hash(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)

def bc_address_to_hash_160(addr):
    bytes = b58decode(addr, 25)
    return bytes[1:21]

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
    """ encode v, which is a string of bytes, to base58.		
    """

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
    """ decode v into a string of len bytes
    """
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


def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

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

def SecretToASecret(secret):
    vchIn = chr(addrtype+128) + secret
    return EncodeBase58Check(vchIn)

def ASecretToSecret(key):
    vch = DecodeBase58Check(key)
    if vch and vch[0] == chr(addrtype+128):
        return vch[1:]
    else:
        return False

########### end pywallet functions #######################

# get password routine
def prompt_password(prompt, confirm=True):
    if sys.stdin.isatty():
        password = getpass.getpass(prompt)

        if password and confirm:
            password2 = getpass.getpass("Confirm: ")

            if password != password2:
                print_error("Error: Passwords do not match.")
                sys.exit(1)

    else:
        password = raw_input(prompt)

    if not password:
        password = None

    return password

# URL decode
_ud = re.compile('%([0-9a-hA-H]{2})', re.MULTILINE)
urldecode = lambda x: _ud.sub(lambda m: chr(int(m.group(1), 16)), x)


def int_to_hex(i, length=1):
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return s.decode('hex')[::-1].encode('hex')


# AES
EncodeAES = lambda secret, s: base64.b64encode(aes.encryptData(secret,s))
DecodeAES = lambda secret, e: aes.decryptData(secret, base64.b64decode(e))



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


def filter(s): 
    out = re.sub('( [^\n]*|)\n','',s)
    out = out.replace(' ','')
    out = out.replace('\n','')
    return out

def raw_tx( inputs, outputs, for_sig = None ):
    s  = int_to_hex(1,4)                                     +   '     version\n' 
    s += int_to_hex( len(inputs) )                           +   '     number of inputs\n'
    for i in range(len(inputs)):
        _, _, p_hash, p_index, p_script, pubkey, sig = inputs[i]
        s += p_hash.decode('hex')[::-1].encode('hex')        +  '     prev hash\n'
        s += int_to_hex(p_index,4)                           +  '     prev index\n'
        if for_sig is None:
            sig = sig + chr(1)                               # hashtype
            script  = int_to_hex( len(sig))                  +  '     push %d bytes\n'%len(sig)
            script += sig.encode('hex')                      +  '     sig\n'
            pubkey = chr(4) + pubkey
            script += int_to_hex( len(pubkey))               +  '     push %d bytes\n'%len(pubkey)
            script += pubkey.encode('hex')                   +  '     pubkey\n'
        elif for_sig==i:
            script = p_script                                +  '     scriptsig \n'
        else:
            script=''
        s += int_to_hex( len(filter(script))/2 )             +  '     script length \n'
        s += script
        s += "ffffffff"                                      +  '     sequence\n'
    s += int_to_hex( len(outputs) )                          +  '     number of outputs\n'
    for output in outputs:
        addr, amount = output
        s += int_to_hex( amount, 8)                          +  '     amount: %d\n'%amount 
        script = '76a9'                                      # op_dup, op_hash_160
        script += '14'                                       # push 0x14 bytes
        script += bc_address_to_hash_160(addr).encode('hex')
        script += '88ac'                                     # op_equalverify, op_checksig
        s += int_to_hex( len(filter(script))/2 )             +  '     script length \n'
        s += script                                          +  '     script \n'
    s += int_to_hex(0,4)                                     # lock time
    if for_sig is not None: s += int_to_hex(1, 4)            # hash type
    return s




def format_satoshis(x, is_diff=False, num_zeros = 0):
    from decimal import Decimal
    s = Decimal(x)
    sign, digits, exp = s.as_tuple()
    digits = map(str, digits)
    while len(digits) < 9:
        digits.insert(0,'0')
    digits.insert(-8,'.')
    s = ''.join(digits).rstrip('0')
    if sign: 
        s = '-' + s
    elif is_diff:
        s = "+" + s

    p = s.find('.')
    s += "0"*( 1 + num_zeros - ( len(s) - p ))
    s += " "*( 9 - ( len(s) - p ))
    s = " "*( 5 - ( p )) + s
    return s


from version import ELECTRUM_VERSION, SEED_VERSION
from interface import DEFAULT_SERVERS




class Wallet:
    def __init__(self):

        self.electrum_version = ELECTRUM_VERSION
        self.seed_version = SEED_VERSION
        self.update_callbacks = []

        self.gap_limit = 5           # configuration
        self.use_change = True
        self.fee = 100000
        self.num_zeros = 0
        self.master_public_key = ''
        self.conversion_currency = None

        # saved fields
        self.use_encryption = False
        self.addresses = []          # receiving addresses visible for user
        self.change_addresses = []   # addresses used as change
        self.seed = ''               # encrypted
        self.history = {}
        self.labels = {}             # labels for addresses and transactions
        self.aliases = {}            # aliases for addresses
        self.authorities = {}        # trusted addresses
        self.frozen_addresses = []
        self.prioritized_addresses = []
        self.expert_mode = False
        
        self.receipts = {}           # signed URIs
        self.receipt = None          # next receipt
        self.addressbook = []        # outgoing addresses, for payments
        self.debug_server = False    # write server communication debug info to stdout

        # not saved
        self.tx_history = {}

        self.imported_keys = {}
        self.remote_url = None

        self.was_updated = True
        self.blocks = -1
        self.banner = ''

        # there is a difference between self.up_to_date and self.is_up_to_date()
        # self.is_up_to_date() returns true when all requests have been answered and processed
        # self.up_to_date is true when the wallet is synchronized (stronger requirement)
        self.up_to_date_event = threading.Event()
        self.up_to_date_event.clear()
        self.up_to_date = False
        self.lock = threading.Lock()
        self.tx_event = threading.Event()

        self.pick_random_server()

    def register_callback(self, update_callback):
        with self.lock:
            self.update_callbacks.append(update_callback)

    def trigger_callbacks(self):
        with self.lock:
            callbacks = self.update_callbacks[:]
        [update() for update in callbacks]

    def pick_random_server(self):
        self.server = random.choice( DEFAULT_SERVERS )         # random choice when the wallet is created

    def is_up_to_date(self):
        return self.interface.responses.empty() and not self.interface.unanswered_requests

    def set_server(self, server):
        # raise an error if the format isnt correct
        a,b,c = server.split(':')
        b = int(b)
        assert c in ['t','h','n']
        # set the server
        if server != self.server:
            self.server = server
            self.save()
            self.interface.is_connected = False  # this exits the polling loop
            self.interface.poke()

    def set_path(self, wallet_path):

        if wallet_path is not None:
            self.path = wallet_path
        else:
            # backward compatibility: look for wallet file in the default data directory
            if "HOME" in os.environ:
                wallet_dir = os.path.join( os.environ["HOME"], '.electrum')
            elif "LOCALAPPDATA" in os.environ:
                wallet_dir = os.path.join( os.environ["LOCALAPPDATA"], 'Electrum' )
            elif "APPDATA" in os.environ:
                wallet_dir = os.path.join( os.environ["APPDATA"], 'Electrum' )
            else:
                raise BaseException("No home directory found in environment variables.")

            if not os.path.exists( wallet_dir ): os.mkdir( wallet_dir )
            self.path = os.path.join( wallet_dir, 'electrum.dat' )

    def import_key(self, keypair, password):
        address, key = keypair.split(':')
        if not self.is_valid(address):
            raise BaseException('Invalid Bitcoin address')
        if address in self.all_addresses():
            raise BaseException('Address already in wallet')
        b = ASecretToSecret( key )
        if not b: 
            raise BaseException('Unsupported key format')
        secexp = int( b.encode('hex'), 16)
        private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve=SECP256k1 )
        # sanity check
        public_key = private_key.get_verifying_key()
        if not address == public_key_to_bc_address( '04'.decode('hex') + public_key.to_string() ):
            raise BaseException('Address does not match private key')
        self.imported_keys[address] = self.pw_encode( key, password )

    def new_seed(self, password):
        seed = "%032x"%ecdsa.util.randrange( pow(2,128) )
        #self.init_mpk(seed)
        # encrypt
        self.seed = self.pw_encode( seed, password )


    def init_mpk(self,seed):
        # public key
        curve = SECP256k1
        secexp = self.stretch_key(seed)
        master_private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve = SECP256k1 )
        self.master_public_key = master_private_key.get_verifying_key().to_string()

    def all_addresses(self):
        return self.addresses + self.change_addresses + self.imported_keys.keys()

    def is_mine(self, address):
        return address in self.all_addresses()

    def is_change(self, address):
        return address in self.change_addresses

    def is_valid(self,addr):
        ADDRESS_RE = re.compile('[1-9A-HJ-NP-Za-km-z]{26,}\\Z')
        if not ADDRESS_RE.match(addr): return False
        try:
            h = bc_address_to_hash_160(addr)
        except:
            return False
        return addr == hash_160_to_bc_address(h)

    def stretch_key(self,seed):
        oldseed = seed
        for i in range(100000):
            seed = hashlib.sha256(seed + oldseed).digest()
        return string_to_number( seed )

    def get_sequence(self,n,for_change):
        return string_to_number( Hash( "%d:%d:"%(n,for_change) + self.master_public_key ) )

    def get_private_key_base58(self, address, password):
        pk = self.get_private_key(address, password)
        if pk is None: return None
        return SecretToASecret( pk )

    def get_private_key(self, address, password):
        """  Privatekey(type,n) = Master_private_key + H(n|S|type)  """
        order = generator_secp256k1.order()
        
        if address in self.imported_keys.keys():
            b = self.pw_decode( self.imported_keys[address], password )
            if not b: return None
            b = ASecretToSecret( b )
            secexp = int( b.encode('hex'), 16)
        else:
            if address in self.addresses:
                n = self.addresses.index(address)
                for_change = False
            elif address in self.change_addresses:
                n = self.change_addresses.index(address)
                for_change = True
            else:
                raise BaseException("unknown address")
            try:
                seed = self.pw_decode( self.seed, password)
            except:
                raise BaseException("Invalid password")
            if not seed: return None
            secexp = self.stretch_key(seed)
            secexp = ( secexp + self.get_sequence(n,for_change) ) % order

        pk = number_to_string(secexp,order)
        return pk

    def msg_magic(self, message):
        return "\x18Bitcoin Signed Message:\n" + chr( len(message) ) + message

    def sign_message(self, address, message, password):
        private_key = ecdsa.SigningKey.from_string( self.get_private_key(address, password), curve = SECP256k1 )
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest( Hash( self.msg_magic( message ) ), sigencode = ecdsa.util.sigencode_string )
        assert public_key.verify_digest( signature, Hash( self.msg_magic( message ) ), sigdecode = ecdsa.util.sigdecode_string)
        for i in range(4):
            sig = base64.b64encode( chr(27+i) + signature )
            try:
                self.verify_message( address, sig, message)
                return sig
            except:
                continue
        else:
            raise BaseException("error: cannot sign message")


    def verify_message(self, address, signature, message):
        """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
        from ecdsa import numbertheory, ellipticcurve, util
        import msqr
        curve = curve_secp256k1
        G = generator_secp256k1
        order = G.order()
        # extract r,s from signature
        sig = base64.b64decode(signature)
        if len(sig) != 65: raise BaseException("Wrong encoding")
        r,s = util.sigdecode_string(sig[1:], order)
        nV = ord(sig[0])
        if nV < 27 or nV >= 35:
            raise BaseException("Bad encoding")
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
        R = ellipticcurve.Point(curve, x, y, order)
        # 1.5 compute e from message:
        h = Hash( self.msg_magic( message ) )
        e = string_to_number(h)
        minus_e = -e % order
        # 1.6 compute Q = r^-1 (sR - eG)
        inv_r = numbertheory.inverse_mod(r,order)
        Q = inv_r * ( s * R + minus_e * G )
        public_key = ecdsa.VerifyingKey.from_public_point( Q, curve = SECP256k1 )
        # check that Q is the public key
        public_key.verify_digest( sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)
        # check that we get the original signing address
        addr = public_key_to_bc_address( encode_point(public_key, compressed) )
        if address != addr:
            raise BaseException("Bad signature")
    

    def create_new_address(self, for_change):
        """   Publickey(type,n) = Master_public_key + H(n|S|type)*point  """
        curve = SECP256k1
        n = len(self.change_addresses) if for_change else len(self.addresses)
        z = self.get_sequence(n,for_change)
        master_public_key = ecdsa.VerifyingKey.from_string( self.master_public_key, curve = SECP256k1 )
        pubkey_point = master_public_key.pubkey.point + z*curve.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )
        address = public_key_to_bc_address( '04'.decode('hex') + public_key2.to_string() )
        if for_change:
            self.change_addresses.append(address)
        else:
            self.addresses.append(address)

        self.history[address] = []
        print address
        return address


    def change_gap_limit(self, value):
        if value >= self.gap_limit:
            self.gap_limit = value
            self.save()
            self.interface.poke()
            return True

        elif value >= self.min_acceptable_gap():
            k = self.num_unused_trailing_addresses()
            n = len(self.addresses) - k + value
            self.addresses = self.addresses[0:n]
            self.gap_limit = value
            self.save()
            return True
        else:
            return False

    def num_unused_trailing_addresses(self):
        k = 0
        for a in self.addresses[::-1]:
            if self.history.get(a):break
            k = k + 1
        return k

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        k = self.num_unused_trailing_addresses()
        for a in self.addresses[0:-k]:
            if self.history.get(a):
                n = 0
            else:
                n += 1
                if n > nmax: nmax = n
        return nmax + 1


    def synchronize(self):
        if not self.master_public_key:
            return []

        new_addresses = []
        while True:
            if self.change_addresses == []:
                new_addresses.append( self.create_new_address(True) )
                continue
            a = self.change_addresses[-1]
            if self.history.get(a):
                new_addresses.append( self.create_new_address(True) )
            else:
                break

        n = self.gap_limit
        while True:
            if len(self.addresses) < n:
                new_addresses.append( self.create_new_address(False) )
                continue
            if map( lambda a: self.history.get(a), self.addresses[-n:] ) == n*[[]]:
                break
            else:
                new_addresses.append( self.create_new_address(False) )

        if self.remote_url:
            num = self.get_remote_number()
            while len(self.addresses)<num:
                new_addresses.append( self.create_new_address(False) )

        return new_addresses


    def get_remote_number(self):
        import jsonrpclib
        server = jsonrpclib.Server(self.remote_url)
        out = server.getnum()
        return out

    def get_remote_mpk(self):
        import jsonrpclib
        server = jsonrpclib.Server(self.remote_url)
        out = server.getkey()
        return out

    def is_found(self):
        return (len(self.change_addresses) > 1 ) or ( len(self.addresses) > self.gap_limit )

    def fill_addressbook(self):
        for tx in self.tx_history.values():
            if tx['value']<0:
                for i in tx['outputs']:
                    if not self.is_mine(i) and i not in self.addressbook:
                        self.addressbook.append(i)
        # redo labels
        self.update_tx_labels()


    def save(self):
        # TODO: Need special config storage class. Should not be mixed
        # up with the wallet.
        # Settings should maybe be stored in a flat ini file.
        s = {
            'seed_version': self.seed_version,
            'use_encryption': self.use_encryption,
            'use_change': self.use_change,
            'master_public_key': self.master_public_key.encode('hex'),
            'fee': self.fee,
            'server': self.server,
            'seed': self.seed,
            'addresses': self.addresses,
            'change_addresses': self.change_addresses,
            'history': self.history, 
            'labels': self.labels,
            'contacts': self.addressbook,
            'imported_keys': self.imported_keys,
            'aliases': self.aliases,
            'authorities': self.authorities,
            'receipts': self.receipts,
            'num_zeros': self.num_zeros,
            'frozen_addresses': self.frozen_addresses,
            'prioritized_addresses': self.prioritized_addresses,
            'expert_mode': self.expert_mode,
            'gap_limit': self.gap_limit,
            'debug_server': self.debug_server,
            'conversion_currency': self.conversion_currency
        }
        f = open(self.path,"w")
        f.write( repr(s) )
        f.close()
        import stat
        os.chmod(self.path,stat.S_IREAD | stat.S_IWRITE)

    def read(self):
        import interface

        upgrade_msg = """This wallet seed is deprecated. Please run upgrade.py for a diagnostic."""
        self.file_exists = False
        try:
            f = open(self.path,"r")
            data = f.read()
            f.close()
        except:
            return
        try:
            d = ast.literal_eval( data )
            interface.old_to_new(d)
            self.seed_version = d.get('seed_version')
            self.master_public_key = d.get('master_public_key').decode('hex')
            self.use_encryption = d.get('use_encryption')
            self.use_change = bool(d.get('use_change', True))
            self.fee = int(d.get('fee'))
            self.seed = d.get('seed')
            self.server = d.get('server')
            self.addresses = d.get('addresses')
            self.change_addresses = d.get('change_addresses')
            self.history = d.get('history')
            self.labels = d.get('labels')
            self.addressbook = d.get('contacts')
            self.imported_keys = d.get('imported_keys', {})
            self.aliases = d.get('aliases', {})
            self.authorities = d.get('authorities', {})
            self.receipts = d.get('receipts', {})
            self.num_zeros = d.get('num_zeros', 0)
            self.frozen_addresses = d.get('frozen_addresses', [])
            self.prioritized_addresses = d.get('prioritized_addresses', [])
            self.expert_mode = d.get('expert_mode', False)
            self.gap_limit = d.get('gap_limit', 5)
            self.debug_server = d.get('debug_server', False)
            self.conversion_currency = d.get('conversion_currency', 'USD')
        except:
            raise BaseException("cannot read wallet file")

        self.update_tx_history()

        if self.seed_version != SEED_VERSION:
            raise BaseException(upgrade_msg)

        if self.remote_url: assert self.master_public_key.encode('hex') == self.get_remote_mpk()

        self.file_exists = True


    def get_address_flags(self, addr):
        flags = "C" if self.is_change(addr) else "I" if addr in self.imported_keys.keys() else "-" 
        flags += "F" if addr in self.frozen_addresses else "P" if addr in self.prioritized_addresses else "-"
        return flags
        

    def get_addr_balance(self, addr):
        assert self.is_mine(addr)
        h = self.history.get(addr,[])
        c = u = 0
        for item in h:
            v = item['value']
            if item['height']:
                c += v
            else:
                u += v
        return c, u

    def get_balance(self):
        conf = unconf = 0
        for addr in self.all_addresses(): 
            c, u = self.get_addr_balance(addr)
            conf += c
            unconf += u
        return conf, unconf


    def choose_tx_inputs( self, amount, fixed_fee, from_addr = None ):
        """ todo: minimize tx size """
        total = 0
        fee = self.fee if fixed_fee is None else fixed_fee

        coins = []
        prioritized_coins = []
        domain = [from_addr] if from_addr else self.all_addresses()
        for i in self.frozen_addresses:
            if i in domain: domain.remove(i)

        for i in self.prioritized_addresses:
            if i in domain: domain.remove(i)

        for addr in domain:
            h = self.history.get(addr)
            if h is None: continue
            for item in h:
                if item.get('raw_output_script'):
                    coins.append( (addr,item))

        coins = sorted( coins, key = lambda x: x[1]['timestamp'] )

        for addr in self.prioritized_addresses:
            h = self.history.get(addr)
            if h is None: continue
            for item in h:
                if item.get('raw_output_script'):
                    prioritized_coins.append( (addr,item))

        prioritized_coins = sorted( prioritized_coins, key = lambda x: x[1]['timestamp'] )

        inputs = []
        coins = prioritized_coins + coins

        for c in coins: 
            addr, item = c
            v = item.get('value')
            total += v
            inputs.append((addr, v, item['tx_hash'], item['index'], item['raw_output_script'], None, None) )
            fee = self.fee*len(inputs) if fixed_fee is None else fixed_fee
            if total >= amount + fee: break
        else:
            #print "not enough funds: %s %s"%(format_satoshis(total), format_satoshis(fee))
            inputs = []
        return inputs, total, fee

    def choose_tx_outputs( self, to_addr, amount, fee, total, change_addr=None ):
        outputs = [ (to_addr, amount) ]
        change_amount = total - ( amount + fee )
        if change_amount != 0:
            # normally, the update thread should ensure that the last change address is unused
            if not change_addr:
                change_addr = self.change_addresses[-1]
            outputs.append( ( change_addr,  change_amount) )
        return outputs

    def sign_inputs( self, inputs, outputs, password ):
        s_inputs = []
        for i in range(len(inputs)):
            addr, v, p_hash, p_pos, p_scriptPubKey, _, _ = inputs[i]
            private_key = ecdsa.SigningKey.from_string( self.get_private_key(addr, password), curve = SECP256k1 )
            public_key = private_key.get_verifying_key()
            pubkey = public_key.to_string()
            tx = filter( raw_tx( inputs, outputs, for_sig = i ) )
            sig = private_key.sign_digest( Hash( tx.decode('hex') ), sigencode = ecdsa.util.sigencode_der )
            assert public_key.verify_digest( sig, Hash( tx.decode('hex') ), sigdecode = ecdsa.util.sigdecode_der)
            s_inputs.append( (addr, v, p_hash, p_pos, p_scriptPubKey, pubkey, sig) )
        return s_inputs

    def pw_encode(self, s, password):
        if password:
            secret = Hash(password)
            return EncodeAES(secret, s)
        else:
            return s

    def pw_decode(self, s, password):
        if password is not None:
            secret = Hash(password)
            d = DecodeAES(secret, s)
            if s == self.seed:
                try:
                    d.decode('hex')
                except:
                    raise BaseException("Invalid password")
            return d
        else:
            return s

    def get_status(self, address):
        h = self.history.get(address)
        if not h:
            status = None
        else:
            lastpoint = h[-1]
            status = lastpoint['block_hash']
            if status == 'mempool': 
                status = status + ':%d'% len(h)
        return status

    def receive_status_callback(self, addr, status):
        with self.lock:
            if self.get_status(addr) != status:
                #print "updating status for", addr, status
                self.interface.get_history(addr)

    def receive_history_callback(self, addr, data): 
        #print "updating history for", addr
        with self.lock:
            self.history[addr] = data
            self.update_tx_history()
            self.save()

    def get_tx_history(self):
        lines = self.tx_history.values()
        lines = sorted(lines, key=operator.itemgetter("timestamp"))
        return lines

    def update_tx_history(self):
        self.tx_history= {}
        for addr in self.all_addresses():
            h = self.history.get(addr)
            if h is None: continue
            for tx in h:
                tx_hash = tx['tx_hash']
                line = self.tx_history.get(tx_hash)
                if not line:
                    self.tx_history[tx_hash] = copy.copy(tx)
                    line = self.tx_history.get(tx_hash)
                else:
                    line['value'] += tx['value']
                if line['height'] == 0:
                    line['timestamp'] = 1e12
        self.update_tx_labels()

    def update_tx_labels(self):
        for tx in self.tx_history.values():
            default_label = ''
            if tx['value']<0:
                for o_addr in tx['outputs']:
                    if not self.is_mine(o_addr):
                        try:
                            default_label = self.labels[o_addr]
                        except KeyError:
                            default_label = o_addr
            else:
                for o_addr in tx['outputs']:
                    if self.is_mine(o_addr) and not self.is_change(o_addr):
                        break
                else:
                    for o_addr in tx['outputs']:
                        if self.is_mine(o_addr):
                            break
                    else:
                        o_addr = None

                if o_addr:
                    dest_label = self.labels.get(o_addr)
                    try:
                        default_label = self.labels[o_addr]
                    except KeyError:
                        default_label = o_addr

            tx['default_label'] = default_label

    def mktx(self, to_address, amount, label, password, fee=None, change_addr=None, from_addr= None):
        if not self.is_valid(to_address):
            raise BaseException("Invalid address")
        inputs, total, fee = self.choose_tx_inputs( amount, fee, from_addr )
        if not inputs:
            raise BaseException("Not enough funds")

        if not self.use_change and not change_addr:
            change_addr = inputs[0][0]
            print "Sending change to", change_addr

        outputs = self.choose_tx_outputs( to_address, amount, fee, total, change_addr )
        s_inputs = self.sign_inputs( inputs, outputs, password )

        tx = filter( raw_tx( s_inputs, outputs ) )
        if to_address not in self.addressbook:
            self.addressbook.append(to_address)
        if label: 
            tx_hash = Hash(tx.decode('hex') )[::-1].encode('hex')
            self.labels[tx_hash] = label

        return tx

    def sendtx(self, tx):
        tx_hash = Hash(tx.decode('hex') )[::-1].encode('hex')
        self.tx_event.clear()
        self.interface.send([('blockchain.transaction.broadcast', [tx])])
        self.tx_event.wait()
        out = self.tx_result 
        if out != tx_hash:
            return False, "error: " + out
        if self.receipt:
            self.receipts[tx_hash] = self.receipt
            self.receipt = None
        return True, out


    def read_alias(self, alias):
        # this might not be the right place for this function.
        import urllib

        m1 = re.match('([\w\-\.]+)@((\w[\w\-]+\.)+[\w\-]+)', alias)
        m2 = re.match('((\w[\w\-]+\.)+[\w\-]+)', alias)
        if m1:
            url = 'http://' + m1.group(2) + '/bitcoin.id/' + m1.group(1) 
        elif m2:
            url = 'http://' + alias + '/bitcoin.id'
        else:
            return ''
        try:
            lines = urllib.urlopen(url).readlines()
        except:
            return ''

        # line 0
        line = lines[0].strip().split(':')
        if len(line) == 1:
            auth_name = None
            target = signing_addr = line[0]
        else:
            target, auth_name, signing_addr, signature = line
            msg = "alias:%s:%s:%s"%(alias,target,auth_name)
            print msg, signature
            self.verify_message(signing_addr, signature, msg)
        
        # other lines are signed updates
        for line in lines[1:]:
            line = line.strip()
            if not line: continue
            line = line.split(':')
            previous = target
            print repr(line)
            target, signature = line
            self.verify_message(previous, signature, "alias:%s:%s"%(alias,target))

        if not self.is_valid(target):
            raise BaseException("Invalid bitcoin address")

        return target, signing_addr, auth_name

    def update_password(self, seed, old_password, new_password):
        if new_password == '': new_password = None
        self.use_encryption = (new_password != None)
        self.seed = self.pw_encode( seed, new_password)
        for k in self.imported_keys.keys():
            a = self.imported_keys[k]
            b = self.pw_decode(a, old_password)
            c = self.pw_encode(b, new_password)
            self.imported_keys[k] = c
        self.save()

    def get_alias(self, alias, interactive = False, show_message=None, question = None):
        try:
            target, signing_address, auth_name = self.read_alias(alias)
        except BaseException, e:
            # raise exception if verify fails (verify the chain)
            if interactive:
                show_message("Alias error: " + str(e))
            return

        print target, signing_address, auth_name

        if auth_name is None:
            a = self.aliases.get(alias)
            if not a:
                msg = "Warning: the alias '%s' is self-signed.\nThe signing address is %s.\n\nDo you want to add this alias to your list of contacts?"%(alias,signing_address)
                if interactive and question( msg ):
                    self.aliases[alias] = (signing_address, target)
                else:
                    target = None
            else:
                if signing_address != a[0]:
                    msg = "Warning: the key of alias '%s' has changed since your last visit! It is possible that someone is trying to do something nasty!!!\nDo you accept to change your trusted key?"%alias
                    if interactive and question( msg ):
                        self.aliases[alias] = (signing_address, target)
                    else:
                        target = None
        else:
            if signing_address not in self.authorities.keys():
                msg = "The alias: '%s' links to %s\n\nWarning: this alias was signed by an unknown key.\nSigning authority: %s\nSigning address: %s\n\nDo you want to add this key to your list of trusted keys?"%(alias,target,auth_name,signing_address)
                if interactive and question( msg ):
                    self.authorities[signing_address] = auth_name
                else:
                    target = None

        if target:
            self.aliases[alias] = (signing_address, target)
            
        return target


    def parse_url(self, url, show_message, question):
        o = url[8:].split('?')
        address = o[0]
        if len(o)>1:
            params = o[1].split('&')
        else:
            params = []

        amount = label = message = signature = identity = ''
        for p in params:
            k,v = p.split('=')
            uv = urldecode(v)
            if k == 'amount': amount = uv
            elif k == 'message': message = uv
            elif k == 'label': label = uv
            elif k == 'signature':
                identity, signature = uv.split(':')
                url = url.replace('&%s=%s'%(k,v),'')
            else: 
                print k,v

        if label and self.labels.get(address) != label:
            if question('Give label "%s" to address %s ?'%(label,address)):
                if address not in self.addressbook and address not in self.all_addresses(): 
                    self.addressbook.append(address)
                self.labels[address] = label

        if signature:
            if re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', identity):
                signing_address = self.get_alias(identity, True, show_message, question)
            elif self.is_valid(identity):
                signing_address = identity
            else:
                signing_address = None
            if not signing_address:
                return
            try:
                self.verify_message(signing_address, signature, url )
                self.receipt = (signing_address, signature, url)
            except:
                show_message('Warning: the URI contains a bad signature.\nThe identity of the recipient cannot be verified.')
                address = amount = label = identity = message = ''

        if re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', address):
            payto_address = self.get_alias(address, True, show_message, question)
            if payto_address:
                address = address + ' <' + payto_address + '>'

        return address, amount, label, message, signature, identity, url


    def update(self):
        self.interface.poke()
        self.up_to_date_event.wait(10000000000)


    def start_session(self, interface):
        self.interface = interface
        self.interface.send([('server.banner',[]), ('blockchain.numblocks.subscribe',[]), ('server.peers.subscribe',[])])
        self.interface.subscribe(self.all_addresses())


    def freeze(self,addr):
        if addr in self.all_addresses() and addr not in self.frozen_addresses:
            self.unprioritize(addr)
            self.frozen_addresses.append(addr)
            self.save()
            return True
        else:
            return False

    def unfreeze(self,addr):
        if addr in self.all_addresses() and addr in self.frozen_addresses:
            self.frozen_addresses.remove(addr)
            self.save()
            return True
        else:
            return False

    def prioritize(self,addr):
        if addr in self.all_addresses() and addr not in self.prioritized_addresses:
            self.unfreeze(addr)
            self.prioritized_addresses.append(addr)
            self.save()
            return True
        else:
            return False

    def unprioritize(self,addr):
        if addr in self.all_addresses() and addr in self.prioritized_addresses:
            self.prioritized_addresses.remove(addr)
            self.save()
            return True
        else:
            return False
