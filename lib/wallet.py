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

import sys
import base64
import os
import re
import hashlib
import copy
import operator
import ast
import threading
import random
import aes
import ecdsa
import Queue
import time

from ecdsa.util import string_to_number, number_to_string
from util import print_error, user_dir, format_satoshis
from bitcoin import *

# URL decode
_ud = re.compile('%([0-9a-hA-H]{2})', re.MULTILINE)
urldecode = lambda x: _ud.sub(lambda m: chr(int(m.group(1), 16)), x)

# AES encryption
EncodeAES = lambda secret, s: base64.b64encode(aes.encryptData(secret,s))
DecodeAES = lambda secret, e: aes.decryptData(secret, base64.b64decode(e))


from version import ELECTRUM_VERSION, SEED_VERSION


class Wallet:
    def __init__(self, config={}):

        self.config = config
        self.electrum_version = ELECTRUM_VERSION

        # saved fields
        self.seed_version          = config.get('seed_version', SEED_VERSION)
        self.gap_limit             = config.get('gap_limit', 5)
        self.use_change            = config.get('use_change',True)
        self.fee                   = int(config.get('fee',100000))
        self.num_zeros             = int(config.get('num_zeros',0))
        self.master_public_key     = config.get('master_public_key','')
        self.use_encryption        = config.get('use_encryption', False)
        self.addresses             = config.get('addresses', [])          # receiving addresses visible for user
        self.change_addresses      = config.get('change_addresses', [])   # addresses used as change
        self.seed                  = config.get('seed', '')               # encrypted
        self.history               = config.get('history',{})
        self.labels                = config.get('labels',{})              # labels for addresses and transactions
        self.aliases               = config.get('aliases', {})            # aliases for addresses
        self.authorities           = config.get('authorities', {})        # trusted addresses
        self.frozen_addresses      = config.get('frozen_addresses',[])
        self.prioritized_addresses = config.get('prioritized_addresses',[])
        self.receipts              = config.get('receipts',{})            # signed URIs
        self.addressbook           = config.get('contacts', [])           # outgoing addresses, for payments
        self.imported_keys         = config.get('imported_keys',{})

        # not saved
        self.receipt = None          # next receipt
        self.tx_history = {}
        self.was_updated = True
        self.blocks = -1
        self.banner = ''

        # there is a difference between wallet.up_to_date and interface.is_up_to_date()
        # interface.is_up_to_date() returns true when all requests have been answered and processed
        # wallet.up_to_date is true when the wallet is synchronized (stronger requirement)
        self.up_to_date_event = threading.Event()
        self.up_to_date_event.clear()
        self.up_to_date = False
        self.lock = threading.Lock()
        self.tx_event = threading.Event()

        self.update_tx_history()
        if self.seed_version != SEED_VERSION:
            raise ValueError("This wallet seed is deprecated. Please run upgrade.py for a diagnostic.")

    def init_up_to_date(self):
        self.up_to_date_event.clear()
        self.up_to_date = False

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
        self.master_public_key = master_private_key.get_verifying_key().to_string().encode('hex')

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
        return string_to_number( Hash( "%d:%d:"%(n,for_change) + self.master_public_key.decode('hex') ) )

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
        n = len(self.change_addresses) if for_change else len(self.addresses)
        address = self.get_new_address(n, for_change)
        if for_change:
            self.change_addresses.append(address)
        else:
            self.addresses.append(address)
        self.history[address] = []
        return address
        
    def get_new_address(self, n, for_change):
        """   Publickey(type,n) = Master_public_key + H(n|S|type)*point  """
        curve = SECP256k1
        z = self.get_sequence(n, for_change)
        master_public_key = ecdsa.VerifyingKey.from_string( self.master_public_key.decode('hex'), curve = SECP256k1 )
        pubkey_point = master_public_key.pubkey.point + z*curve.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )
        address = public_key_to_bc_address( '04'.decode('hex') + public_key2.to_string() )
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

        return new_addresses


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
                    raise ValueError("Invalid password")
            return d
        else:
            return s

    def get_status(self, address):
        with self.lock:
            h = self.history.get(address)
        if not h:
            status = None
        else:
            lastpoint = h[-1]
            status = lastpoint['block_hash']
            if status == 'mempool': 
                status = status + ':%d'% len(h)
        return status


    def receive_history_callback(self, addr, data): 
        #print "updating history for", addr
        with self.lock:
            self.history[addr] = data
            self.update_tx_history()
            self.save()

    def get_tx_history(self):
        with self.lock:
            lines = self.tx_history.values()
        lines = sorted(lines, key=operator.itemgetter("timestamp"))
        return lines

    def get_tx_hashes(self):
        with self.lock:
            hashes = self.tx_history.keys()
        return hashes

    def get_transactions_at_height(self, height):
        with self.lock:
            values = self.tx_history.values()[:]

        out = []
        for tx in values:
            if tx['height'] == height:
                out.append(tx['tx_hash'])
        return out

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
            raise ValueError("Invalid address")
        inputs, total, fee = self.choose_tx_inputs( amount, fee, from_addr )
        if not inputs:
            raise ValueError("Not enough funds")

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
        # synchronous
        h = self.send_tx(tx)
        self.tx_event.wait()
        self.receive_tx(h)

    def send_tx(self, tx):
        # asynchronous
        self.tx_event.clear()
        tx_hash = Hash(tx.decode('hex') )[::-1].encode('hex')
        self.interface.send([('blockchain.transaction.broadcast', [tx])])
        return tx_hash

    def receive_tx(self,tx_hash):
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
            url = 'https://' + m1.group(2) + '/bitcoin.id/' + m1.group(1) 
        elif m2:
            url = 'https://' + alias + '/bitcoin.id'
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
            raise ValueError("Invalid bitcoin address")

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
        self.interface.poke('synchronizer')
        self.up_to_date_event.wait(10000000000)


    def freeze(self,addr):
        if addr in self.all_addresses() and addr not in self.frozen_addresses:
            self.unprioritize(addr)
            self.frozen_addresses.append(addr)
            self.config.set_key('frozen_addresses', self.frozen_addresses, True)
            return True
        else:
            return False

    def unfreeze(self,addr):
        if addr in self.all_addresses() and addr in self.frozen_addresses:
            self.frozen_addresses.remove(addr)
            self.config.set_key('frozen_addresses', self.frozen_addresses, True)
            return True
        else:
            return False

    def prioritize(self,addr):
        if addr in self.all_addresses() and addr not in self.prioritized_addresses:
            self.unfreeze(addr)
            self.prioritized_addresses.append(addr)
            self.config.set_key('prioritized_addresses', self.prioritized_addresses, True)
            return True
        else:
            return False

    def unprioritize(self,addr):
        if addr in self.all_addresses() and addr in self.prioritized_addresses:
            self.prioritized_addresses.remove(addr)
            self.config.set_key('prioritized_addresses', self.prioritized_addresses, True)
            return True
        else:
            return False

    def save(self):
        s = {
            'seed_version': self.seed_version,
            'use_encryption': self.use_encryption,
            'use_change': self.use_change,
            'master_public_key': self.master_public_key,
            'fee': self.fee,
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
            'gap_limit': self.gap_limit,
        }
        for k, v in s.items():
            self.config.set_key(k,v)
        self.config.save()






class WalletSynchronizer(threading.Thread):


    def __init__(self, wallet, config):
        threading.Thread.__init__(self)
        self.daemon = True
        self.wallet = wallet
        self.interface = self.wallet.interface
        self.interface.register_channel('synchronizer')
        self.wallet.interface.register_callback('connected', self.wallet.init_up_to_date)
        self.wallet.interface.register_callback('connected', lambda: self.interface.send([('server.banner',[])],'synchronizer') )

    def synchronize_wallet(self):
        new_addresses = self.wallet.synchronize()
        if new_addresses:
            self.subscribe_to_addresses(new_addresses)
            
        if self.interface.is_up_to_date('synchronizer'):
            if not self.wallet.up_to_date:
                self.wallet.up_to_date = True
                self.wallet.was_updated = True
                self.wallet.up_to_date_event.set()
        else:
            if self.wallet.up_to_date:
                self.wallet.up_to_date = False
                self.wallet.was_updated = True



    def subscribe_to_addresses(self, addresses):
        messages = []
        for addr in addresses:
            messages.append(('blockchain.address.subscribe', [addr]))
        self.interface.send( messages, 'synchronizer')


    def run(self):

        # wait until we are connected, in case the user is not connected
        while not self.interface.is_connected:
            time.sleep(1)
        
        # request banner, because 'connected' event happens before this thread is started
        self.interface.send([('server.banner',[])],'synchronizer')

        # subscriptions
        self.interface.send([('blockchain.numblocks.subscribe',[])], 'synchronizer')
        self.interface.send([('server.peers.subscribe',[])],'synchronizer')
        self.subscribe_to_addresses(self.wallet.all_addresses())

        while True:
            # 1. send new requests
            self.synchronize_wallet()

            if self.wallet.was_updated:
                self.interface.trigger_callback('updated')
                self.wallet.was_updated = False

            # 2. get a response
            r = self.interface.get_response('synchronizer')
            if not r: continue

            # 3. handle response
            method = r['method']
            params = r['params']
            result = r['result']

            if method == 'blockchain.address.subscribe':
                addr = params[0]
                if self.wallet.get_status(addr) != result:
                    self.interface.send([('blockchain.address.get_history', [address] )])
                            
            elif method == 'blockchain.address.get_history':
                addr = params[0]
                self.wallet.receive_history_callback(addr, result)
                self.wallet.was_updated = True

            elif method == 'blockchain.transaction.broadcast':
                self.wallet.tx_result = result
                self.wallet.tx_event.set()

            elif method == 'blockchain.numblocks.subscribe':
                self.wallet.blocks = result
                self.wallet.was_updated = True

            elif method == 'server.version':
                pass

            elif method == 'server.peers.subscribe':
                servers = []
                for item in result:
                    s = []
                    host = item[1]
                    ports = []
                    version = None
                    if len(item) > 2:
                        for v in item[2]:
                            if re.match("[stgh]\d+", v):
                                ports.append((v[0], v[1:]))
                            if re.match("v(.?)+", v):
                                version = v[1:]
                    if ports and version:
                        servers.append((host, ports))
                self.interface.servers = servers
                self.interface.trigger_callback('peers')

            elif method == 'server.banner':
                self.wallet.banner = result
                self.wallet.was_updated = True

            else:
                print_error("Error: Unknown message:" + method + ", " + repr(params) + ", " + repr(result) )

            if self.wallet.was_updated:
                self.interface.trigger_callback('updated')
                self.wallet.was_updated = False


encode = lambda x: x[::-1].encode('hex')
decode = lambda x: x.decode('hex')[::-1]
from bitcoin import Hash, rev_hex, int_to_hex

class WalletVerifier(threading.Thread):

    def __init__(self, wallet, config):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.wallet = wallet
        self.interface = self.wallet.interface
        self.interface.register_channel('verifier')
        self.validated       = config.get('verified_tx',[])
        self.merkle_roots    = config.get('merkle_roots',{})
        self.headers         = config.get('block_headers',{})
        self.lock = threading.Lock()
        self.saved = True

    def run(self):
        requested = []

        while True:
            txlist = self.wallet.get_tx_hashes()

            for tx in txlist:
                if tx not in self.validated:
                    if tx not in requested:
                        requested.append(tx)
                        self.request_merkle(tx)
                        self.saved = False
                        break

            try:
                r = self.interface.get_response('verifier',timeout=1)
            except Queue.Empty:
                if len(self.validated) == len(txlist) and not self.saved:
                    print "saving verified transactions"
                    self.config.set_key('verified_tx', self.validated, True)
                    self.saved = True
                continue

            # 3. handle response
            method = r['method']
            params = r['params']
            result = r['result']

            if method == 'blockchain.transaction.get_merkle':
                tx_hash = params[0]
                tx_height = result.get('block_height')
                self.merkle_roots[tx_hash] = self.hash_merkle_root(result['merkle'], tx_hash)
                # if we already have the header, check merkle root directly
                header = self.headers.get(tx_height)
                if header:
                    self.validated.append(tx_hash)
                    assert header.get('merkle_root') == self.merkle_roots[tx_hash]
                self.request_headers(tx_height) 

            elif method == 'blockchain.block.get_header':
                self.validate_header(result)


    def request_merkle(self, tx_hash):
        self.interface.send([ ('blockchain.transaction.get_merkle',[tx_hash]) ], 'verifier')
        

    def request_headers(self, tx_height, delta=10):
        headers_requests = []
        for height in range(tx_height-delta,tx_height+delta): # we might can request blocks that do not exist yet
            if height not in self.headers:
                headers_requests.append( ('blockchain.block.get_header',[height]) )
        self.interface.send(headers_requests,'verifier')


    def validate_header(self, header):
        """ if there is a previous or a next block in the list, check the hash"""
        height = header.get('block_height')
        with self.lock:
            self.headers[height] = header # detect conflicts
            prev_header = next_header = None
            if height-1 in self.headers:
                prev_header = self.headers[height-1]
            if height+1 in self.headers:
                next_header = self.headers[height+1]

        if prev_header:
            prev_hash = self.hash_header(prev_header)
            assert prev_hash == header.get('prev_block_hash')
        if next_header:
            _hash = self.hash_header(header)
            assert _hash == next_header.get('prev_block_hash')
            
        # check if there are transactions at that height
        for tx_hash in self.wallet.get_transactions_at_height(height):
            if tx_hash in self.validated: continue
            # check if we already have the merkle root
            merkle_root = self.merkle_roots.get(tx_hash)
            if merkle_root:
                self.validated.append(tx_hash)
                assert header.get('merkle_root') == merkle_root

    def hash_header(self, res):
        header = int_to_hex(res.get('version'),4) \
            + rev_hex(res.get('prev_block_hash')) \
            + rev_hex(res.get('merkle_root')) \
            + int_to_hex(int(res.get('timestamp')),4) \
            + int_to_hex(int(res.get('bits')),4) \
            + int_to_hex(int(res.get('nonce')),4)
        return rev_hex(Hash(header.decode('hex')).encode('hex'))

    def hash_merkle_root(self, merkle_s, target_hash):
        h = decode(target_hash)
        for item in merkle_s:
            is_left = item[0] == 'L'
            h = Hash( h + decode(item[1:]) ) if is_left else Hash( decode(item[1:]) + h )
        return encode(h)
