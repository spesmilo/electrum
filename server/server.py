#!/usr/bin/env python
# Copyright(C) 2011 thomasv@gitorious

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/agpl.html>.

"""
Todo:
   * server should check and return bitcoind status..
   * improve txpoint sorting
"""

SERVER_MESSAGE = """
Welcome to ecdsa.org.

This service is free. Support this node: 
19mP9FKrXqL46Si58pHdhGKow88SUPy1V8

The server code is free software; you may 
download it and operate your own Electrum 
node. See http://ecdsa.org/electrum
"""



import time, socket, operator, thread, ast, sys

import psycopg2, binascii
import bitcoinrpc

from Abe.abe import hash_to_address, decode_check_address
from Abe.DataStore import DataStore as Datastore_class
from Abe import DataStore, readconf, BCDataStream,  deserialize, util, base58


sessions = {}
dblock = thread.allocate_lock()


class MyStore(Datastore_class):

    def safe_sql(self,sql):
        try:
            dblock.acquire()
            ret = self.selectall(sql)
            dblock.release()
            return ret
        except:
            print "sql error", sql
            return []

    def get_tx_outputs(self, tx_id):
        return self.safe_sql("""SELECT
                txout.txout_pos,
                txout.txout_scriptPubKey,
                txout.txout_value,
                nexttx.tx_hash,
                nexttx.tx_id,
                txin.txin_pos,
                pubkey.pubkey_hash
              FROM txout
              LEFT JOIN txin ON (txin.txout_id = txout.txout_id)
              LEFT JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
              LEFT JOIN tx nexttx ON (txin.tx_id = nexttx.tx_id)
             WHERE txout.tx_id = %d 
             ORDER BY txout.txout_pos
        """%(tx_id))

    def get_tx_inputs(self, tx_id):
        return self.safe_sql(""" SELECT
                txin.txin_pos,
                txin.txin_scriptSig,
                txout.txout_value,
                COALESCE(prevtx.tx_hash, u.txout_tx_hash),
                prevtx.tx_id,
                COALESCE(txout.txout_pos, u.txout_pos),
                pubkey.pubkey_hash
              FROM txin
              LEFT JOIN txout ON (txout.txout_id = txin.txout_id)
              LEFT JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
              LEFT JOIN tx prevtx ON (txout.tx_id = prevtx.tx_id)
              LEFT JOIN unlinked_txin u ON (u.txin_id = txin.txin_id)
             WHERE txin.tx_id = %d
             ORDER BY txin.txin_pos
             """%(tx_id,))

    def get_address_out_rows(self, dbhash):
        return self.safe_sql(""" SELECT
                b.block_nTime,
                cc.chain_id,
                b.block_height,
                1,
                b.block_hash,
                tx.tx_hash,
                tx.tx_id,
                txin.txin_pos,
                -prevout.txout_value
              FROM chain_candidate cc
              JOIN block b ON (b.block_id = cc.block_id)
              JOIN block_tx ON (block_tx.block_id = b.block_id)
              JOIN tx ON (tx.tx_id = block_tx.tx_id)
              JOIN txin ON (txin.tx_id = tx.tx_id)
              JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
              JOIN pubkey ON (pubkey.pubkey_id = prevout.pubkey_id)
             WHERE pubkey.pubkey_hash = '%s'
               AND cc.in_longest = 1"""%dbhash)

    def get_address_out_rows_memorypool(self, dbhash):
        return self.safe_sql(""" SELECT
                1,
                tx.tx_hash,
                tx.tx_id,
                txin.txin_pos,
                -prevout.txout_value
              FROM tx 
              JOIN txin ON (txin.tx_id = tx.tx_id)
              JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
              JOIN pubkey ON (pubkey.pubkey_id = prevout.pubkey_id)
             WHERE pubkey.pubkey_hash ='%s' """%(dbhash))

    def get_address_in_rows(self, dbhash):
        return self.safe_sql(""" SELECT
                b.block_nTime,
                cc.chain_id,
                b.block_height,
                0,
                b.block_hash,
                tx.tx_hash,
                tx.tx_id,
                txout.txout_pos,
                txout.txout_value
              FROM chain_candidate cc
              JOIN block b ON (b.block_id = cc.block_id)
              JOIN block_tx ON (block_tx.block_id = b.block_id)
              JOIN tx ON (tx.tx_id = block_tx.tx_id)
              JOIN txout ON (txout.tx_id = tx.tx_id)
              JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
             WHERE pubkey.pubkey_hash = '%s'
               AND cc.in_longest = 1"""%(dbhash))

    def get_address_in_rows_memorypool(self, dbhash):
        return self.safe_sql( """ SELECT
                0,
                tx.tx_hash,
                tx.tx_id,
                txout.txout_pos,
                txout.txout_value
              FROM tx
              JOIN txout ON (txout.tx_id = tx.tx_id)
              JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
             WHERE pubkey.pubkey_hash = '%s' """%(dbhash))

    def get_txpoints(self, addr):
        version, binaddr = decode_check_address(addr)
        if binaddr is None:
            return "err"
        dbhash = self.binin(binaddr)
        rows = []
        rows += self.get_address_out_rows( dbhash )
        rows += self.get_address_in_rows( dbhash )

        txpoints = []
        known_tx = []

        for row in rows:
            try:
                nTime, chain_id, height, is_in, blk_hash, tx_hash, tx_id, pos, value = row
            except:
                print "cannot unpack row", row
                break
            tx_hash = self.hashout_hex(tx_hash)
            txpoint = {
                    "nTime":    int(nTime),
                    #"chain_id": int(chain_id),
                    "height":   int(height),
                    "is_in":    int(is_in),
                    "blk_hash": self.hashout_hex(blk_hash),
                    "tx_hash":  tx_hash,
                    "tx_id":    int(tx_id),
                    "pos":      int(pos),
                    "value":    int(value),
                    }

            txpoints.append(txpoint)
            known_tx.append(self.hashout_hex(tx_hash))


        # todo: sort them really...
        txpoints = sorted(txpoints, key=operator.itemgetter("nTime"))

        # read memory pool
        rows = []
        rows += self.get_address_in_rows_memorypool( dbhash )
        rows += self.get_address_out_rows_memorypool( dbhash )
        for row in rows:
            is_in, tx_hash, tx_id, pos, value = row
            tx_hash = self.hashout_hex(tx_hash)
            if tx_hash in known_tx:
                continue
            #print "mempool", tx_hash
            txpoint = {
                    "nTime":    0,
                    "chain_id": 1,
                    "height":   0,
                    "is_in":    int(is_in),
                    "blk_hash": 'mempool',
                    "tx_hash":  tx_hash,
                    "tx_id":    int(tx_id),
                    "pos":      int(pos),
                    "value":    int(value),
                    }
            txpoints.append(txpoint)


        for txpoint in txpoints:
            tx_id = txpoint['tx_id']
            
            txinputs = []
            inrows = self.get_tx_inputs(tx_id)
            for row in inrows:
                _hash = self.binout(row[6])
                address = hash_to_address(chr(0), _hash)
                txinputs.append(address)
            txpoint['inputs'] = txinputs
            txoutputs = []
            outrows = self.get_tx_outputs(tx_id)
            for row in outrows:
                _hash = self.binout(row[6])
                address = hash_to_address(chr(0), _hash)
                txoutputs.append(address)
            txpoint['outputs'] = txoutputs

            # for all unspent inputs, I want their scriptpubkey. (actually I could deduce it from the address)
            if not txpoint['is_in']:
                # detect if already redeemed...
                for row in outrows:
                    if row[6] == dbhash: break
                else:
                    raise
                #row = self.get_tx_output(tx_id,dbhash)
                # pos, script, value, o_hash, o_id, o_pos, binaddr = row
                # if not redeemed, we add the script
                if row:
                    if not row[4]: txpoint['raw_scriptPubKey'] = row[1]


        return txpoints


    def get_status(self, addr):
        # last block for an address
        tx_points = self.get_txpoints(addr)
        if not tx_points:
            return None
        else:
            return tx_points[-1]['blk_hash']


def send_tx(tx):
    import bitcoinrpc
    conn = bitcoinrpc.connect_to_local()
    try:
        v = conn.importtransaction(tx)
    except:
        v = "error: transaction rejected by memorypool"
    return v


def listen_thread(store):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('ecdsa.org', 50000))
    s.listen(1)
    while True:
        conn, addr = s.accept()
        thread.start_new_thread(client_thread, (addr, conn,))


def client_thread(ipaddr,conn):
    print "client thread", ipaddr
    try:
        ipaddr = ipaddr[0]
        msg = ''
        while 1:
            d = conn.recv(1024)
            msg += d
            if d[-1]=='#':
                break

        print msg

        try:
            cmd, data = ast.literal_eval(msg[:-1])
        except:
            print "syntax error", repr(msg)
            conn.close()
            return

        if cmd=='b':
            out = "%d"%store.get_block_number(1)

        elif cmd=='session':
            import random, string
            session_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(10))
            print "new session", ipaddr, session_id

            addresses = ast.literal_eval(data)
            sessions[session_id] = {}
            for a in addresses:
                sessions[session_id][a] = ''
            out = repr( (session_id, SERVER_MESSAGE) )

        elif cmd=='poll': 
            session_id = data
            addresses = sessions.get(session_id)
            if not addresses:
                print "session not found", ipaddr
                out = repr( (-1, {}))
            else:
                ret = {}
                for addr in addresses:
                    status = store.get_status( addr )
                    last_status = sessions[session_id].get( addr )
                    if last_status != status:
                        sessions[session_id][addr] = status
                        ret[addr] = status
                out = repr( (store.get_block_number(1), ret ) )

        elif cmd == 'h': 
            # history
            addr = data
            h = store.get_txpoints( addr )
            out = repr(h)

        elif cmd =='tx':        
            # transaction
            out = send_tx(data)
        else:
            out = None

        if out:
            #print ipaddr, cmd, len(out)
            try:
                conn.send(out)
            except:
                print "error, could not send"

    finally:
        conn.close()
    

ds = BCDataStream.BCDataStream()


def memorypool_update(store):

    conn = bitcoinrpc.connect_to_local()
    try:
        v = conn.getmemorypool()
    except:
        print "cannot contact bitcoin daemmon"
        return
    v = v['transactions']
    for hextx in v:
        ds.clear()
        ds.write(hextx.decode('hex'))
        tx = deserialize.parse_Transaction(ds)
        tx['hash'] = util.double_sha256(tx['tx'])
            
        if store.tx_find_id_and_value(tx):
            pass
        else:
            store.import_tx(tx, False)
            print tx['hash'][::-1].encode('hex')
    store.commit()

import traceback


if __name__ == '__main__':

    conf = DataStore.CONFIG_DEFAULTS
    args, argv = readconf.parse_argv( [], conf)
    args.dbtype='psycopg2'
    args.connect_args = {"database":"abe"}
    store = MyStore(args)

    thread.start_new_thread(listen_thread, (store,))

    while True:
        try:
            dblock.acquire()
            store.catch_up()
            memorypool_update(store)
            dblock.release()
        except:
            traceback.print_exc(file=sys.stdout)
        time.sleep(10)

