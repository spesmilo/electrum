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


import threading, time, Queue, os, sys
from util import user_dir
from bitcoin import *




class WalletVerifier(threading.Thread):

    def __init__(self, wallet, config):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.wallet = wallet
        self.interface = self.wallet.interface
        self.interface.register_channel('verifier')
        self.verified_tx     = config.get('verified_tx',[])
        self.merkle_roots    = config.get('merkle_roots',{})      # hashed by me
        self.targets         = config.get('targets',{})           # compute targets
        self.lock = threading.Lock()

        #self.config.set_key('verified_tx', [], True)
        #for i in range(70): self.get_target(i)
        #sys.exit()

        

    def run(self):
        requested_merkle = []
        requested_chunks = []

        while True:
            # request missing chunks
            max_index = self.wallet.blocks/2016
            if not requested_chunks:
                for i in range(0, max_index + 1):
                    # test if we can read the first header of the chunk
                    if self.read_header(i*2016): continue
                    print "requesting chunk", i
                    self.interface.send([ ('blockchain.block.get_chunk',[i])], 'verifier')
                    requested_chunks.append(i)
                    break

            # todo: request missing blocks too

            # request missing tx merkle
            txlist = self.wallet.get_tx_hashes()
            for tx in txlist:
                if tx not in self.verified_tx:
                    if tx not in requested_merkle:
                        requested_merkle.append(tx)
                        self.request_merkle(tx)
                        break

            try:
                r = self.interface.get_response('verifier',timeout=1)
            except Queue.Empty:
                time.sleep(1)
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

            elif method == 'blockchain.block.get_header':
                self.verify_header(result)


    def request_merkle(self, tx_hash):
        self.interface.send([ ('blockchain.transaction.get_merkle',[tx_hash]) ], 'verifier')


    def verify_merkle(self, tx_hash, result):
        tx_height = result.get('block_height')
        self.merkle_roots[tx_hash] = self.hash_merkle_root(result['merkle'], tx_hash)
        header = self.read_header(tx_height)
        if header:
            assert header.get('merkle_root') == self.merkle_roots[tx_hash]
            self.verified_tx.append(tx_hash)
            print "verified", tx_hash
            self.config.set_key('verified_tx', self.verified_tx, True)


    def verify_chunk(self, index, hexdata):
        data = hexdata.decode('hex')
        height = index*2016
        numblocks = len(data)/80
        print "validate_chunk", index, numblocks

        if index == 0:  
            previous_hash = ("0"*64)
        else:
            prev_header = self.read_header(index*2016-1)
            if prev_header is None: raise
            previous_hash = self.hash_header(prev_header)

        bits, target = self.get_target(index)

        for i in range(numblocks):
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
            self.save_header(header)
        if next_header:
            _hash = self.hash_header(header)
            assert _hash == next_header.get('prev_block_hash')
            

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


    def hash_merkle_root(self, merkle_s, target_hash):
        h = hash_decode(target_hash)
        for item in merkle_s:
            is_left = item[0] == 'L'
            h = Hash( h + hash_decode(item[1:]) ) if is_left else Hash( hash_decode(item[1:]) + h )
        return hash_encode(h)


    def path(self):
        wdir = user_dir()
        if not os.path.exists( wdir ):
            wdir = os.path.dirname(self.config.path)
        return os.path.join( wdir, 'blockchain_headers')


    def save_chunk(self, index, chunk):
        filename = self.path()
        if os.path.exists(filename):
            f = open(filename,'rw+')
        else:
            print "creating file", filename
            f = open(filename,'w+')
        f.seek(index*2016*80)
        h = f.write(chunk)
        f.close()


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
        # print "%3d"%index, "%8x"%bits, "%64X"%new_target, hex(c)[2:].upper(), hex(new_bits)
        return new_bits, new_target

