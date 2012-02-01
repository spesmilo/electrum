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


import sys, base64, os, re, hashlib, copy, operator, ast

try:
    import ecdsa  
    from ecdsa.util import string_to_number, number_to_string
except:
    print "python-ecdsa does not seem to be installed. Try 'sudo easy_install ecdsa'"
    sys.exit(1)

try:
    import aes
except:
    print "AES does not seem to be installed. Try 'sudo easy_install slowaes'"
    sys.exit(1)


############ functions from pywallet ##################### 

addrtype = 0

def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
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




from version import ELECTRUM_VERSION, SEED_VERSION





class Wallet:
    def __init__(self, interface):

        self.electrum_version = ELECTRUM_VERSION
        self.seed_version = SEED_VERSION

        self.gap_limit = 5           # configuration
        self.fee = 100000
        self.master_public_key = ''

        # saved fields
        self.use_encryption = False
        self.addresses = []          # receiving addresses visible for user
        self.change_addresses = []   # addresses used as change
        self.seed = ''               # encrypted
        self.status = {}             # current status of addresses
        self.history = {}
        self.labels = {}             # labels for addresses and transactions
        self.addressbook = []        # outgoing addresses, for payments

        # not saved
        self.tx_history = {}

        self.imported_keys = {}

        self.interface = interface


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
        if not self.is_valid(address): return False
        b = ASecretToSecret( key )
        if not b: return False
        secexp = int( b.encode('hex'), 16)
        private_key = ecdsa.SigningKey.from_secret_exponent( secexp, curve=SECP256k1 )
        # sanity check
        public_key = private_key.get_verifying_key()
        if not address == public_key_to_bc_address( '04'.decode('hex') + public_key.to_string() ): return False
        self.imported_keys[address] = self.pw_encode( key, password )
        return True

    def new_seed(self, password):
        seed = "%032x"%ecdsa.util.randrange( pow(2,128) )
        self.init_mpk(seed)
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

    def get_private_key2(self, address, password):
        """  Privatekey(type,n) = Master_private_key + H(n|S|type)  """
        order = generator_secp256k1.order()
        
        if address in self.imported_keys.keys():
            b = self.pw_decode( self.imported_keys[address], password )
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
            seed = self.pw_decode( self.seed, password)
            secexp = self.stretch_key(seed)
            secexp = ( secexp + self.get_sequence(n,for_change) ) % order

        pk = number_to_string(secexp,order)
        return pk

    def sign_message(self, address, message, password):
        private_key = ecdsa.SigningKey.from_string( self.get_private_key2(address, password), curve = SECP256k1 )
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest( Hash( message ), sigencode = ecdsa.util.sigencode_string )
        assert public_key.verify_digest( signature, Hash( message ), sigdecode = ecdsa.util.sigdecode_string)
        for i in range(4):
            sig = base64.b64encode( chr(27+i) + signature )
            if self.verify_message( address, sig, message):
                return sig
        else:
            raise BaseException("error: cannot sign message")
        
            
    def verify_message(self, address, signature, message):
        """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
        
        from ecdsa import numbertheory, ellipticcurve, util
        import msqr
        curve = curve_secp256k1
        G = generator_secp256k1
        order = G.order()

        sig = base64.b64decode(signature)
        if len(sig) != 65: raise BaseException("error")
        recid = ord(sig[0]) - 27
        # print "recid", recid

        # extract r,s from signature
        r,s = util.sigdecode_string(sig[1:], order)

        # 1.1
        x = r + (recid/2) * order

        # 1.3
        alpha = ( x * x * x  + curve.a() * x + curve.b() ) % curve.p()
        beta = msqr.modular_sqrt(alpha, curve.p())
        y = beta if (beta - recid) % 2 == 0 else curve.p() - beta

        # 1.4 the constructor checks that nR is at infinity
        try:
            R = ellipticcurve.Point(curve, x, y, order)
        except:
            print "not in curve"
            return False

        # 1.5 compute e from message:
        h = Hash(message)
        e = string_to_number(h)
        minus_e = -e % order

        # 1.6 compute Q = r^-1 (sR - eG)
        inv_r = numbertheory.inverse_mod(r,order)
        Q = inv_r * ( s * R + minus_e * G )
        public_key = ecdsa.VerifyingKey.from_public_point( Q, curve = SECP256k1 )

        # check that Q is the public key
        try:
            public_key.verify_digest( sig[1:], h, sigdecode = ecdsa.util.sigdecode_string)
        except:
            print "wrong key"
            return False

        # check that we get the original signing address
        addr = public_key_to_bc_address( '04'.decode('hex') + public_key.to_string() )
        # print addr
        return address == addr
    

    def create_new_address2(self, for_change):
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

        # updates
        print address
        self.history[address] = h = self.interface.retrieve_history(address)
        self.status[address] = h[-1]['blk_hash'] if h else None
        return address


    def synchronize(self):
        is_new = False
        while True:
            if self.change_addresses == []:
                self.create_new_address2(True)
                is_new = True
                continue
            a = self.change_addresses[-1]
            if self.history.get(a):
                self.create_new_address2(True)
                is_new = True
            else:
                break

        n = self.gap_limit
        while True:
            if len(self.addresses) < n:
                self.create_new_address2(False)
                is_new = True
                continue
            if map( lambda a: self.history.get(a), self.addresses[-n:] ) == n*[[]]:
                break
            else:
                self.create_new_address2(False)
                is_new = True


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
        s = {
            'seed_version':self.seed_version,
            'use_encryption':self.use_encryption,
            'master_public_key': self.master_public_key.encode('hex'),
            'fee':self.fee,
            'host':self.interface.host,
            'port':self.interface.port,
            'blocks':self.interface.blocks,
            'seed':self.seed,
            'addresses':self.addresses,
            'change_addresses':self.change_addresses,
            'status':self.status,
            'history':self.history, 
            'labels':self.labels,
            'contacts':self.addressbook,
            'imported_keys':self.imported_keys,
            }
        f = open(self.path,"w")
        f.write( repr(s) )
        f.close()

    def read(self):
        upgrade_msg = """This wallet seed is deprecated. Please run upgrade.py for a diagnostic."""
        try:
            f = open(self.path,"r")
            data = f.read()
            f.close()
        except:
            return False
        try:
            d = ast.literal_eval( data )
            self.seed_version = d.get('seed_version')
            self.master_public_key = d.get('master_public_key').decode('hex')
            self.use_encryption = d.get('use_encryption')
            self.fee = int( d.get('fee') )
            self.interface.host = d.get('host')
            self.interface.set_port( d.get('port') )
            self.interface.blocks = d.get('blocks')
            self.seed = d.get('seed')
            self.addresses = d.get('addresses')
            self.change_addresses = d.get('change_addresses')
            self.status = d.get('status')
            self.history = d.get('history')
            self.labels = d.get('labels')
            self.addressbook = d.get('contacts')
            self.imported_keys = d.get('imported_keys',{})
        except:
            raise BaseException(upgrade_msg)

        self.update_tx_history()

        if self.seed_version != SEED_VERSION:
            raise BaseException(upgrade_msg)

        return True
        
    def get_new_address(self):
        n = 0 
        for addr in self.addresses[-self.gap_limit:]:
            if not self.history.get(addr): 
                n = n + 1
        if n < self.gap_limit:
            new_address = self.create_new_address2(False)
            self.history[new_address] = [] #get from server
            return True, new_address
        else:
            return False, "The last %d addresses in your list have never been used. You should use them first, or increase the allowed gap size in your preferences. "%self.gap_limit

    def get_addr_balance(self, addr):
        if self.is_mine(addr):
            h = self.history.get(addr)
        else:
            h = self.interface.retrieve_history(addr)
        if not h: return 0,0
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

    def update(self):
        is_new = False
        changed_addresses = self.interface.poll()
        for addr, blk_hash in changed_addresses.items():
            if self.status.get(addr) != blk_hash:
                print "updating history for", addr
                self.history[addr] = self.interface.retrieve_history(addr)
                self.status[addr] = blk_hash
                is_new = True

        if is_new:
            self.synchronize()
            self.update_tx_history()
            self.save()
            return True
        else:
            return False

    def choose_tx_inputs( self, amount, fixed_fee ):
        """ todo: minimize tx size """
        total = 0
        fee = self.fee if fixed_fee is None else fixed_fee

        coins = []
        for addr in self.all_addresses():
            h = self.history.get(addr)
            if h is None: continue
            for item in h:
                if item.get('raw_scriptPubKey'):
                    coins.append( (addr,item))

        coins = sorted( coins, key = lambda x: x[1]['nTime'] )
        inputs = []
        for c in coins: 
            addr, item = c
            v = item.get('value')
            total += v
            inputs.append((addr, v, item['tx_hash'], item['pos'], item['raw_scriptPubKey'], None, None) )
            fee = self.fee*len(inputs) if fixed_fee is None else fixed_fee
            if total >= amount + fee: break
        else:
            #print "not enough funds: %d %d"%(total, fee)
            inputs = []
        return inputs, total, fee

    def choose_tx_outputs( self, to_addr, amount, fee, total ):
        outputs = [ (to_addr, amount) ]
        change_amount = total - ( amount + fee )
        if change_amount != 0:
            # normally, the update thread should ensure that the last change address is unused
            outputs.append( ( self.change_addresses[-1],  change_amount) )
        return outputs

    def sign_inputs( self, inputs, outputs, password ):
        s_inputs = []
        for i in range(len(inputs)):
            addr, v, p_hash, p_pos, p_scriptPubKey, _, _ = inputs[i]
            private_key = ecdsa.SigningKey.from_string( self.get_private_key2(addr, password), curve = SECP256k1 )
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

    def get_tx_history(self):
        lines = self.tx_history.values()
        lines = sorted(lines, key=operator.itemgetter("nTime"))
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
                    line['nTime'] = 1e12
        self.update_tx_labels()

    def update_tx_labels(self):
        for tx in self.tx_history.values():
            default_label = ''
            if tx['value']<0:
                for o_addr in tx['outputs']:
                    if not self.is_change(o_addr):
                        dest_label = self.labels.get(o_addr)
                        if dest_label:
                            default_label = 'to: ' + dest_label
                        else:
                            default_label = 'to: ' + o_addr
            else:
                for o_addr in tx['outputs']:
                    if self.is_mine(o_addr) and not self.is_change(o_addr):
                        dest_label = self.labels.get(o_addr)
                        if dest_label:
                            default_label = 'at: ' + dest_label
                        else:
                            default_label = 'at: ' + o_addr
            tx['default_label'] = default_label

    def mktx(self, to_address, amount, label, password, fee=None):
        if not self.is_valid(to_address):
            raise BaseException("Invalid address")
        inputs, total, fee = self.choose_tx_inputs( amount, fee )
        if not inputs:
            raise BaseException("Not enough funds")
        outputs = self.choose_tx_outputs( to_address, amount, fee, total )
        s_inputs = self.sign_inputs( inputs, outputs, password )

        tx = filter( raw_tx( s_inputs, outputs ) )
        if to_address not in self.addressbook:
            self.addressbook.append(to_address)
        if label: 
            tx_hash = Hash(tx.decode('hex') )[::-1].encode('hex')
            self.labels[tx_hash] = label
        self.save()
        return tx

    def sendtx(self, tx):
        tx_hash = Hash(tx.decode('hex') )[::-1].encode('hex')
        out = self.interface.send_tx(tx)
        if out != tx_hash:
            return False, "error: " + out
        return True, out

