#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
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


import threading, time, Queue, os, sys, shutil
from util import user_dir, appdata_dir, print_error
from bitcoin import *




class WalletVerifier(threading.Thread):
    """ Simple Payment Verification """

    def __init__(self, interface, config):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.interface = interface
        self.transactions    = {}                                 # requested verifications (with height sent by the requestor)
        self.interface.register_channel('verifier')

        self.verified_tx     = config.get('verified_tx3',{})      # height, timestamp of verified transactions
        self.merkle_roots    = config.get('merkle_roots',{})      # hashed by me
        
        self.targets         = config.get('targets',{})           # compute targets
        self.lock = threading.Lock()
        self.pending_headers = [] # headers that have not been verified
        self.height = 0
        self.local_height = 0
        self.running = False
        self.headers_url = 'http://headers.electrum.org/blockchain_headers'

    def get_confirmations(self, tx):
        """ return the number of confirmations of a monitored transaction. """
        with self.lock:
            if tx in self.verified_tx:
                height, timestamp, pos = self.verified_tx[tx]
                conf = (self.local_height - height + 1)
                if conf <= 0: timestamp = None

            elif tx in self.transactions:
                conf = -1
                timestamp = None

            else:
                conf = 0
                timestamp = None

        return conf, timestamp


    def get_txpos(self, tx_hash):
        "return position, even if the tx is unverified"
        with self.lock:
            x = self.verified_tx.get(tx_hash)
            y = self.transactions.get(tx_hash)
        if x:
            height, timestamp, pos = x
            return height, pos
        elif y:
            return y, 0
        else:
            return 1e12, 0


    def get_height(self, tx_hash):
        with self.lock:
            v = self.verified_tx.get(tx_hash)
        height = v[0] if v else None
        return height


    def add(self, tx_hash, tx_height):
        """ add a transaction to the list of monitored transactions. """
        assert tx_height > 0
        with self.lock:
            if tx_hash not in self.transactions.keys():
                self.transactions[tx_hash] = tx_height

    def stop(self):
        with self.lock: self.running = False
        self.interface.poke('verifier')

    def is_running(self):
        with self.lock: return self.running

    def run(self):

        self.init_headers_file()
        self.set_local_height()

        with self.lock:
            self.running = True
        requested_merkle = []
        requested_chunks = []
        requested_headers = []
        all_chunks = False
        
        # subscribe to block headers
        self.interface.send([ ('blockchain.headers.subscribe',[])], 'verifier')

        while self.is_running():
            # request missing chunks
            if not all_chunks and self.height and not requested_chunks:

                if self.local_height + 50 < self.height:
                    min_index = (self.local_height + 1)/2016
                    max_index = (self.height + 1)/2016
                    for i in range(min_index, max_index + 1):
                        print_error( "requesting chunk", i )
                        self.interface.send([ ('blockchain.block.get_chunk',[i])], 'verifier')
                        requested_chunks.append(i)
                        break
                else:
                    all_chunks = True
                    print_error("downloaded all chunks")

            # request missing tx
            if all_chunks:
                for tx_hash, tx_height in self.transactions.items():
                    if tx_hash not in self.verified_tx:
                        if self.merkle_roots.get(tx_hash) is None and tx_hash not in requested_merkle:
                            print_error('requesting merkle', tx_hash)
                            self.interface.send([ ('blockchain.transaction.get_merkle',[tx_hash, tx_height]) ], 'verifier')
                            requested_merkle.append(tx_hash)

            # process pending headers
            if self.pending_headers and all_chunks:
                done = []
                for header in self.pending_headers:
                    if self.verify_header(header):
                        done.append(header)
                    else:
                        # request previous header
                        i = header.get('block_height') - 1
                        if i not in requested_headers:
                            print_error("requesting header %d"%i)
                            self.interface.send([ ('blockchain.block.get_header',[i])], 'verifier')
                            requested_headers.append(i)
                        # no point continuing
                        break
                if done:
                    self.interface.trigger_callback('updated')
                    for header in done: 
                        self.pending_headers.remove(header)

            try:
                r = self.interface.get_response('verifier',timeout=1)
            except Queue.Empty:
                continue
            if not r: continue

            if r.get('error'):
                print_error('Verifier received an error:', r)
                continue

            # 3. handle response
            method = r['method']
            params = r['params']
            result = r['result']

            if method == 'blockchain.transaction.get_merkle':
                tx_hash = params[0]
                self.verify_merkle(tx_hash, result)
                requested_merkle.remove(tx_hash)

            elif method == 'blockchain.block.get_chunk':
                index = params[0]
                self.verify_chunk(index, result)
                requested_chunks.remove(index)

            elif method in ['blockchain.headers.subscribe', 'blockchain.block.get_header']:

                self.pending_headers.append(result)
                if method == 'blockchain.block.get_header':
                    requested_headers.remove(result.get('block_height'))
                else:
                    self.height = result.get('block_height')
                    self.interface.poke('synchronizer')
                
                self.pending_headers.sort(key=lambda x: x.get('block_height'))
                # print "pending headers", map(lambda x: x.get('block_height'), self.pending_headers)



    def verify_merkle(self, tx_hash, result):
        tx_height = result.get('block_height')
        pos = result.get('pos')
        self.merkle_roots[tx_hash] = self.hash_merkle_root(result['merkle'], tx_hash, pos)
        header = self.read_header(tx_height)
        if not header: return
        assert header.get('merkle_root') == self.merkle_roots[tx_hash]
        # we passed all the tests
        header = self.read_header(tx_height)
        timestamp = header.get('timestamp')
        with self.lock:
            self.verified_tx[tx_hash] = (tx_height, timestamp, pos)
        print_error("verified %s"%tx_hash)
        self.config.set_key('verified_tx3', self.verified_tx, True)
        self.interface.trigger_callback('updated')


    def verify_chunk(self, index, hexdata):
        data = hexdata.decode('hex')
        height = index*2016
        num = len(data)/80
        print_error("validating headers %d"%height)

        if index == 0:  
            previous_hash = ("0"*64)
        else:
            prev_header = self.read_header(index*2016-1)
            if prev_header is None: raise
            previous_hash = self.hash_header(prev_header)

        bits, target = self.get_target(index)

        for i in range(num):
            height = index*2016 + i
            raw_header = data[i*80:(i+1)*80]
            header = self.header_from_string(raw_header)
            _hash = self.hash_header(header)
            assert previous_hash == header.get('prev_block_hash')
            assert bits == header.get('bits')
            assert eval('0x'+_hash) < target

            previous_header = header
            previous_hash = _hash 

        self.save_chunk(index, data)


    def verify_header(self, header):
        # add header to the blockchain file
        # if there is a reorg, push it in a stack

        height = header.get('block_height')

        prev_header = self.read_header(height -1)
        if not prev_header:
            # return False to request previous header
            return False

        prev_hash = self.hash_header(prev_header)
        bits, target = self.get_target(height/2016)
        _hash = self.hash_header(header)
        try:
            assert prev_hash == header.get('prev_block_hash')
            assert bits == header.get('bits')
            assert eval('0x'+_hash) < target
        except:
            # this can be caused by a reorg.
            print_error("verify header failed"+ repr(header))
            # undo verifications
            with self.lock:
                items = self.verified_tx.items()[:]
            for tx_hash, item in items:
                tx_height, timestamp, pos = item
                if tx_height >= height:
                    print_error("redoing", tx_hash)
                    with self.lock:
                        self.verified_tx.pop(tx_hash)
                        if tx_hash in self.merkle_roots:
                            self.merkle_roots.pop(tx_hash)
            # return False to request previous header.
            return False

        self.save_header(header)
        print_error("verify header:", _hash, height)
        return True
        

            

    def header_to_string(self, res):
        s = int_to_hex(res.get('version'),4) \
            + rev_hex(res.get('prev_block_hash')) \
            + rev_hex(res.get('merkle_root')) \
            + int_to_hex(int(res.get('timestamp')),4) \
            + int_to_hex(int(res.get('bits')),4) \
            + int_to_hex(int(res.get('nonce')),4)
        return s


    def header_from_string(self, s):
        hex_to_int = lambda s: eval('0x' + s[::-1].encode('hex'))
        h = {}
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['timestamp'] = hex_to_int(s[68:72])
        h['bits'] = hex_to_int(s[72:76])
        h['nonce'] = hex_to_int(s[76:80])
        return h

    def hash_header(self, header):
        return rev_hex(Hash(self.header_to_string(header).decode('hex')).encode('hex'))

    def hash_merkle_root(self, merkle_s, target_hash, pos):
        h = hash_decode(target_hash)
        for i in range(len(merkle_s)):
            item = merkle_s[i]
            h = Hash( hash_decode(item) + h ) if ((pos >> i) & 1) else Hash( h + hash_decode(item) )
        return hash_encode(h)

    def path(self):
        wdir = self.config.get('blockchain_headers_path', user_dir())
        if wdir and not os.path.exists( wdir ): os.mkdir(wdir)
        return os.path.join( wdir, 'blockchain_headers')

    def init_headers_file(self):
        filename = self.path()
        if os.path.exists(filename):
            return
        
        try:
            import urllib, socket
            socket.setdefaulttimeout(30)
            print_error("downloading ", self.headers_url )
            urllib.urlretrieve(self.headers_url, filename)
        except:
            print_error( "download failed. creating file", filename )
            open(filename,'wb+').close()

    def save_chunk(self, index, chunk):
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(index*2016*80)
        h = f.write(chunk)
        f.close()
        self.set_local_height()

    def save_header(self, header):
        data = self.header_to_string(header).decode('hex')
        assert len(data) == 80
        height = header.get('block_height')
        filename = self.path()
        f = open(filename,'rb+')
        f.seek(height*80)
        h = f.write(data)
        f.close()
        self.set_local_height()


    def set_local_height(self):
        name = self.path()
        if os.path.exists(name):
            h = os.path.getsize(name)/80 - 1
            if self.local_height != h:
                self.local_height = h


    def read_header(self, block_height):
        name = self.path()
        if os.path.exists(name):
            f = open(name,'rb')
            f.seek(block_height*80)
            h = f.read(80)
            f.close()
            if len(h) == 80:
                h = self.header_from_string(h)
                return h 


    def get_target(self, index):

        max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        if index == 0: return 0x1d00ffff, max_target

        first = self.read_header((index-1)*2016)
        last = self.read_header(index*2016-1)
        
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 14*24*60*60
        nActualTimespan = max(nActualTimespan, nTargetTimespan/4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan*4)

        bits = last.get('bits') 
        # convert to bignum
        MM = 256*256*256
        a = bits%MM
        if a < 0x8000:
            a *= 256
        target = (a) * pow(2, 8 * (bits/MM - 3))

        # new target
        new_target = min( max_target, (target * nActualTimespan)/nTargetTimespan )
        
        # convert it to bits
        c = ("%064X"%new_target)[2:]
        i = 31
        while c[0:2]=="00":
            c = c[2:]
            i -= 1

        c = eval('0x'+c[0:6])
        if c > 0x800000: 
            c /= 256
            i += 1

        new_bits = c + MM * i
        return new_bits, new_target

