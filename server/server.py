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
   * command to check cache

 mempool transactions do not need to be added to the database; it slows it down
"""


import time, json, socket, operator, thread, ast, sys,re
import psycopg2, binascii

from Abe.abe import hash_to_address, decode_check_address
from Abe.DataStore import DataStore as Datastore_class
from Abe import DataStore, readconf, BCDataStream,  deserialize, util, base58

import ConfigParser
from json import dumps, loads
import urllib

# we need to import electrum
sys.path.append('../client/')
from wallet import Wallet
from interface import Interface


config = ConfigParser.ConfigParser()
# set some defaults, which will be overwritten by the config file
config.add_section('server')
config.set('server','banner', 'Welcome to Electrum!')
config.set('server', 'host', 'localhost')
config.set('server', 'port', 50000)
config.set('server', 'password', '')
config.set('server', 'irc', 'yes')
config.set('server', 'cache', 'no') 
config.set('server', 'ircname', 'Electrum server')
config.add_section('database')
config.set('database', 'type', 'psycopg2')
config.set('database', 'database', 'abe')

try:
    f = open('/etc/electrum.conf','r')
    config.readfp(f)
    f.close()
except:
    print "Could not read electrum.conf. I will use the default values."

try:
    f = open('/etc/electrum.banner','r')
    config.set('server','banner', f.read())
    f.close()
except:
    pass

password = config.get('server','password')
bitcoind_url = 'http://%s:%s@%s:%s/' % ( config.get('bitcoind','user'), config.get('bitcoind','password'), config.get('bitcoind','host'), config.get('bitcoind','port'))

stopping = False
block_number = -1
old_block_number = -1
sessions = {}
sessions_sub_numblocks = [] # sessions that have subscribed to the service

dblock = thread.allocate_lock()
peer_list = {}

wallets = {} # for ultra-light clients such as bccapi

from Queue import Queue
input_queue = Queue()
output_queue = Queue()
address_queue = Queue()

class MyStore(Datastore_class):

    def import_tx(self, tx, is_coinbase):
        tx_id = super(MyStore, self).import_tx(tx, is_coinbase)
        if config.get('server', 'cache') == 'yes': self.update_tx_cache(tx_id)

    def update_tx_cache(self, txid):
        inrows = self.get_tx_inputs(txid, False)
        for row in inrows:
            _hash = store.binout(row[6])
            address = hash_to_address(chr(0), _hash)
            if self.tx_cache.has_key(address):
                print "cache: invalidating", address
                self.tx_cache.pop(address)
            address_queue.put(address)

        outrows = self.get_tx_outputs(txid, False)
        for row in outrows:
            _hash = store.binout(row[6])
            address = hash_to_address(chr(0), _hash)
            if self.tx_cache.has_key(address):
                print "cache: invalidating", address
                self.tx_cache.pop(address)
            address_queue.put(address)

    def safe_sql(self,sql, params=(), lock=True):
        try:
            if lock: dblock.acquire()
            ret = self.selectall(sql,params)
            if lock: dblock.release()
            return ret
        except:
            print "sql error", sql
            return []

    def get_tx_outputs(self, tx_id, lock=True):
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
        """%(tx_id), (), lock)

    def get_tx_inputs(self, tx_id, lock=True):
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
             """%(tx_id,), (), lock)

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
             WHERE pubkey.pubkey_hash = ?
               AND cc.in_longest = 1""", (dbhash,))

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
             WHERE pubkey.pubkey_hash = ? """, (dbhash,))

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
             WHERE pubkey.pubkey_hash = ?
               AND cc.in_longest = 1""", (dbhash,))

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
             WHERE pubkey.pubkey_hash = ? """, (dbhash,))

    def get_history(self, addr):
        
        if config.get('server','cache') == 'yes':
            cached_version = self.tx_cache.get( addr )
            if cached_version is not None:
                return cached_version

        version, binaddr = decode_check_address(addr)
        if binaddr is None:
            return None

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
        address_has_mempool = False

        for row in rows:
            is_in, tx_hash, tx_id, pos, value = row
            tx_hash = self.hashout_hex(tx_hash)
            if tx_hash in known_tx:
                continue

            # this means that pending transactions were added to the db, even if they are not returned by getmemorypool
            address_has_mempool = True

            # this means pending transactions are returned by getmemorypool
            if tx_hash not in self.mempool_keys:
                continue

            #print "mempool", tx_hash
            txpoint = {
                    "nTime":    0,
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

        # cache result
        if config.get('server','cache') == 'yes' and not address_has_mempool:
            self.tx_cache[addr] = txpoints
        
        return txpoints



class Direct_Interface(Interface):
    def __init__(self):
        pass

    def handler(self, method, params = ''):
        cmds = {'session.new':new_session,
                'session.poll':poll_session,
                'session.update':update_session,
                'blockchain.transaction.broadcast':send_tx,
                'blockchain.address.get_history':store.get_history
                }
        func = cmds[method]
        return func( params )



def send_tx(tx):
    postdata = dumps({"method": 'importtransaction', 'params': [tx], 'id':'jsonrpc'})
    respdata = urllib.urlopen(bitcoind_url, postdata).read()
    r = loads(respdata)
    if r['error'] != None:
        out = "error: transaction rejected by memorypool\n"+tx
    else:
        out = r['result']
    return out



def random_string(N):
    import random, string
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(N))

    

def cmd_stop(data):
    global stopping
    if password == data:
        stopping = True
        return 'ok'
    else:
        return 'wrong password'

def cmd_load(pw):
    if password == pw:
        return repr( len(sessions) )
    else:
        return 'wrong password'


def clear_cache(pw):
    if password == pw:
        store.tx_cache = {}
        return 'ok'
    else:
        return 'wrong password'

def get_cache(pw,addr):
    if password == pw:
        return store.tx_cache.get(addr)
    else:
        return 'wrong password'


def poll_session(session_id):
    session = sessions.get(session_id)
    if session is None:
        print time.asctime(), "session not found", session_id
        out = repr( (-1, {}))
    else:
        t1 = time.time()
        addresses = session['addresses']
        session['last_time'] = time.time()
        ret = {}
        k = 0
        for addr in addresses:
            if store.tx_cache.get( addr ) is not None: k += 1
            status = get_address_status( addr )
            last_status = addresses.get( addr )
            if last_status != status:
                addresses[addr] = status
                ret[addr] = status
        if ret:
            sessions[session_id]['addresses'] = addresses
        out = repr( (block_number, ret ) )
        t2 = time.time() - t1 
        if t2 > 10:
            print "high load:", session_id, "%d/%d"%(k,len(addresses)), t2

        return out


def do_update_address(addr):
    # an address was involved in a transaction; we check if it was subscribed to in a session
    # the address can be subscribed in several sessions; the cache should ensure that we don't do redundant requests
    for session_id in sessions.keys():
        session = sessions[session_id]
        if session.get('type') != 'subscribe': continue
        addresses = session['addresses'].keys()

        if addr in addresses:
            print "address ", addr, "found in session", session_id
            status = get_address_status( addr )
            print "new_status:", status
            last_status = session['addresses'][addr]
            print "last_status", last_status
            if last_status != status:
                print "status is new", addr
                send_status(session_id,addr,status)
                sessions[session_id]['addresses'][addr] = status


def get_address_status(addr):
    # get address status, i.e. the last block for that address.
    tx_points = store.get_history(addr)
    if not tx_points:
        status = None
    else:
        lastpoint = tx_points[-1]
        status = lastpoint['blk_hash']
        # this is a temporary hack; move it up once old clients have disappeared
        if status == 'mempool': # and session['version'] != "old":
            status = status + ':%d'% len(tx_points)
    return status


def send_numblocks(session_id):
    out = json.dumps( {'method':'numblocks.subscribe', 'result':block_number} )
    output_queue.put((session_id, out))

def send_status(session_id, address, status):
    out = json.dumps( { 'method':'address.subscribe', 'address':address, 'status':status } )
    output_queue.put((session_id, out))

def subscribe_to_numblocks(session_id):
    sessions_sub_numblocks.append(session_id)
    send_numblocks(session_id)

def subscribe_to_address(session_id, address):
    status = get_address_status(address)
    sessions[session_id]['type'] = 'subscribe'
    sessions[session_id]['addresses'][address] = status
    sessions[session_id]['last_time'] = time.time()
    send_status(session_id, address, status)

def new_session(version, addresses):
    session_id = random_string(10)
    sessions[session_id] = { 'addresses':{}, 'version':version }
    for a in addresses:
        sessions[session_id]['addresses'][a] = ''
    out = repr( (session_id, config.get('server','banner').replace('\\n','\n') ) )
    sessions[session_id]['last_time'] = time.time()
    return out

def update_session(session_id,addresses):
    sessions[session_id]['addresses'] = {}
    for a in addresses:
        sessions[session_id]['addresses'][a] = ''
    sessions[session_id]['last_time'] = time.time()
    return 'ok'

def native_server_thread():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((config.get('server','host'), config.getint('server','port')))
    s.listen(1)
    while not stopping:
        conn, addr = s.accept()
        try:
            thread.start_new_thread(native_client_thread, (addr, conn,))
        except:
            # can't start new thread if there is no memory..
            traceback.print_exc(file=sys.stdout)


def native_client_thread(ipaddr,conn):
    #print "client thread", ipaddr
    try:
        ipaddr = ipaddr[0]
        msg = ''
        while 1:
            d = conn.recv(1024)
            msg += d
            if not d: 
                break
            if '#' in msg:
                msg = msg.split('#', 1)[0]
                break
        try:
            cmd, data = ast.literal_eval(msg)
        except:
            print "syntax error", repr(msg), ipaddr
            conn.close()
            return

        out = do_command(cmd, data, ipaddr)
        if out:
            #print ipaddr, cmd, len(out)
            try:
                conn.send(out)
            except:
                print "error, could not send"

    finally:
        conn.close()



# used by the native handler
def do_command(cmd, data, ipaddr):

    timestr = time.strftime("[%d/%m/%Y-%H:%M:%S]")

    if cmd=='b':
        out = "%d"%block_number

    elif cmd in ['session','new_session']:
        try:
            if cmd == 'session':
                addresses = ast.literal_eval(data)
                version = "old"
            else:
                version, addresses = ast.literal_eval(data)
                if version[0]=="0": version = "v" + version
        except:
            print "error", data
            return None
        print timestr, "new session", ipaddr, addresses[0] if addresses else addresses, len(addresses), version
        out = new_session(version, addresses)

    elif cmd=='update_session':
        try:
            session_id, addresses = ast.literal_eval(data)
        except:
            print "error"
            return None
        print timestr, "update session", ipaddr, addresses[0] if addresses else addresses, len(addresses)
        out = update_session(session_id,addresses)

    elif cmd == 'bccapi_login':
        import electrum
        print "data",data
        v, k = ast.literal_eval(data)
        master_public_key = k.decode('hex') # todo: sanitize. no need to decode twice...
        print master_public_key
        wallet_id = random_string(10)
        w = Wallet( Direct_Interface() )
        w.master_public_key = master_public_key.decode('hex')
        w.synchronize()
        wallets[wallet_id] = w
        out = wallet_id
        print "wallets", wallets

    elif cmd == 'bccapi_getAccountInfo':
        from wallet import int_to_hex
        v, wallet_id = ast.literal_eval(data)
        w = wallets.get(wallet_id)
        if w is not None:
            num = len(w.addresses)
            c, u = w.get_balance()
            out = int_to_hex(num,4) + int_to_hex(c,8) + int_to_hex( c+u, 8 )
            out = out.decode('hex')
        else:
            print "error",data
            out = "error"

    elif cmd == 'bccapi_getAccountStatement':
        from wallet import int_to_hex
        v, wallet_id = ast.literal_eval(data)
        w = wallets.get(wallet_id)
        if w is not None:
            num = len(w.addresses)
            c, u = w.get_balance()
            total_records = num_records = 0
            out = int_to_hex(num,4) + int_to_hex(c,8) + int_to_hex( c+u, 8 ) + int_to_hex( total_records ) + int_to_hex( num_records )
            out = out.decode('hex')
        else:
            print "error",data
            out = "error"

    elif cmd == 'bccapi_getSendCoinForm':
        out = ''

    elif cmd == 'bccapi_submitTransaction':
        out = ''
            
    elif cmd=='poll': 
        out = poll_session(data)

    elif cmd == 'h': 
        # history
        address = data
        out = repr( store.get_history( address ) )

    elif cmd == 'load': 
        out = cmd_load(data)

    elif cmd =='tx':
        out = send_tx(data)
        print timestr, "sent tx:", ipaddr, out

    elif cmd == 'stop':
        out = cmd_stop(data)

    elif cmd == 'peers':
        out = repr(peer_list.values())

    else:
        out = None

    return out



####################################################################

def tcp_server_thread():
    thread.start_new_thread(process_input_queue, ())
    thread.start_new_thread(process_output_queue, ())

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((config.get('server','host'), 50001))
    s.listen(1)
    while not stopping:
        conn, addr = s.accept()
        try:
            thread.start_new_thread(tcp_client_thread, (addr, conn,))
        except:
            # can't start new thread if there is no memory..
            traceback.print_exc(file=sys.stdout)


# one thread per client. put requests in a queue.
def tcp_client_thread(ipaddr,conn):
    """ use a persistent connection. put commands in a queue."""
    print "persistent client thread", ipaddr
    global sessions

    session_id = random_string(10)
    sessions[session_id] = { 'conn':conn, 'addresses':{}, 'version':'unknown' }

    ipaddr = ipaddr[0]
    msg = ''

    while not stopping:
        d = conn.recv(1024)
        msg += d
        if not d:
            print "lost connection", session_id
            sessions.pop(session_id)
            sessions_sub_numblocks.remove(session_id)
            break

        while True:
            s = msg.find('\n')
            if s ==-1:
                break
            else:
                c = msg[0:s]
                msg = msg[s+1:]
                c = json.loads(c)
                try:
                    cmd = c['method']
                    data = c['params']
                except:
                    print "syntax error", repr(c), ipaddr
                    continue

                # add to queue
                input_queue.put((session_id, cmd, data))


# read commands from the input queue. perform requests, etc. this should be called from the main thread.
def process_input_queue():
    while not stopping:
        session_id, cmd, data = input_queue.get()
        out = None
        if cmd == 'address.subscribe':
            subscribe_to_address(session_id,data)
        elif cmd == 'numblocks.subscribe':
            subscribe_to_numblocks(session_id)
        elif cmd == 'client.version':
            sessions[session_id]['version'] = data
        elif cmd == 'server.banner':
            out = json.dumps( { 'method':'server.banner', 'result':config.get('server','banner').replace('\\n','\n') } )
        elif cmd == 'address.get_history':
            address = data
            out = json.dumps( { 'method':'address.get_history', 'address':address, 'result':store.get_history( address ) } )
        elif cmd == 'transaction.broadcast':
            txo = send_tx(data)
            print "sent tx:", txo
            out = json.dumps( { 'method':'transaction.broadcast', 'result':txo } )
        else:
            print "unknown command", cmd
        if out:
            output_queue.put((session_id, out))

# this is a separate thread
def process_output_queue():
    while not stopping:
        session_id, out = output_queue.get()
        session = sessions.get(session_id)
        if session: 
            conn = session.get('conn')
            conn.send(out+'\n')



####################################################################


def memorypool_update(store):
    ds = BCDataStream.BCDataStream()
    store.mempool_keys = []

    postdata = dumps({"method": 'getmemorypool', 'params': [], 'id':'jsonrpc'})
    respdata = urllib.urlopen(bitcoind_url, postdata).read()
    r = loads(respdata)
    if r['error'] != None:
        return

    v = r['result'].get('transactions')
    for hextx in v:
        ds.clear()
        ds.write(hextx.decode('hex'))
        tx = deserialize.parse_Transaction(ds)
        tx['hash'] = util.double_sha256(tx['tx'])
        tx_hash = tx['hash'][::-1].encode('hex')
        store.mempool_keys.append(tx_hash)
        if store.tx_find_id_and_value(tx):
            pass
        else:
            store.import_tx(tx, False)

    store.commit()



def clean_session_thread():
    while not stopping:
        time.sleep(30)
        t = time.time()
        for k,s in sessions.items():
            if s.get('type') == 'subscribe': continue
            t0 = s['last_time']
            if t - t0 > 5*60:
                sessions.pop(k)
                print "lost session", k
            

def irc_thread():
    global peer_list
    NICK = 'E_'+random_string(10)
    while not stopping:
        try:
            s = socket.socket()
            s.connect(('irc.freenode.net', 6667))
            s.send('USER electrum 0 * :'+config.get('server','host')+' '+config.get('server','ircname')+'\n')
            s.send('NICK '+NICK+'\n')
            s.send('JOIN #electrum\n')
            sf = s.makefile('r', 0)
            t = 0
            while not stopping:
                line = sf.readline()
                line = line.rstrip('\r\n')
                line = line.split()
                if line[0]=='PING': 
                    s.send('PONG '+line[1]+'\n')
                elif '353' in line: # answer to /names
                    k = line.index('353')
                    for item in line[k+1:]:
                        if item[0:2] == 'E_':
                            s.send('WHO %s\n'%item)
                elif '352' in line: # answer to /who
            	    # warning: this is a horrible hack which apparently works
            	    k = line.index('352')
                    ip = line[k+4]
                    ip = socket.gethostbyname(ip)
                    name = line[k+6]
                    host = line[k+9]
                    peer_list[name] = (ip,host)
                if time.time() - t > 5*60:
                    s.send('NAMES #electrum\n')
                    t = time.time()
                    peer_list = {}
        except:
            traceback.print_exc(file=sys.stdout)
        finally:
    	    sf.close()
            s.close()



def http_server_thread(store):
    # see http://code.google.com/p/jsonrpclib/
    from SocketServer import ThreadingMixIn
    from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
    class SimpleThreadedJSONRPCServer(ThreadingMixIn, SimpleJSONRPCServer): pass
    server = SimpleThreadedJSONRPCServer(( config.get('server','host'), 8081))
    server.register_function(lambda : peer_list.values(), 'peers')
    server.register_function(cmd_stop, 'stop')
    server.register_function(cmd_load, 'load')
    server.register_function(lambda : block_number, 'blocks')
    server.register_function(clear_cache, 'clear_cache')
    server.register_function(get_cache, 'get_cache')
    server.register_function(send_tx, 'blockchain.transaction.broadcast')
    server.register_function(store.get_history, 'blockchain.address.get_history')
    server.register_function(new_session, 'session.new')
    server.register_function(update_session, 'session.update')
    server.register_function(poll_session, 'session.poll')
    server.serve_forever()


import traceback


if __name__ == '__main__':

    if len(sys.argv)>1:
        import jsonrpclib
        server = jsonrpclib.Server('http://%s:8081'%config.get('server','host'))
        cmd = sys.argv[1]
        if cmd == 'load':
            out = server.load(password)
        elif cmd == 'peers':
            out = server.peers()
        elif cmd == 'stop':
            out = server.stop(password)
        elif cmd == 'clear_cache':
            out = server.clear_cache(password)
        elif cmd == 'get_cache':
            out = server.get_cache(password,sys.argv[2])
        elif cmd == 'h':
            out = server.blockchain.address.get_history(sys.argv[2])
        elif cmd == 'tx':
            out = server.blockchain.transaction.broadcast(sys.argv[2])
        elif cmd == 'b':
            out = server.blocks()
        else:
            out = "Unknown command: '%s'" % cmd
        print out
        sys.exit(0)


    print "starting Electrum server"
    print "cache:", config.get('server', 'cache')

    conf = DataStore.CONFIG_DEFAULTS
    args, argv = readconf.parse_argv( [], conf)
    args.dbtype= config.get('database','type')
    if args.dbtype == 'sqlite3':
	args.connect_args = { 'database' : config.get('database','database') }
    elif args.dbtype == 'MySQLdb':
	args.connect_args = { 'db' : config.get('database','database'), 'user' : config.get('database','username'), 'passwd' : config.get('database','password') }
    elif args.dbtype == 'psycopg2':
	args.connect_args = { 'database' : config.get('database','database') }
    store = MyStore(args)
    store.tx_cache = {}
    store.mempool_keys = {}

    # supported protocols
    thread.start_new_thread(native_server_thread, ())
    thread.start_new_thread(tcp_server_thread, ())
    thread.start_new_thread(http_server_thread, (store,))

    thread.start_new_thread(clean_session_thread, ())

    if (config.get('server','irc') == 'yes' ):
	thread.start_new_thread(irc_thread, ())

    while not stopping:
        try:
            dblock.acquire()
            store.catch_up()
            memorypool_update(store)
            block_number = store.get_block_number(1)

            if block_number != old_block_number:
                old_block_number = block_number
                for session_id in sessions_sub_numblocks:
                    send_numblocks(session_id)

        except IOError:
            print "IOError: cannot reach bitcoind"
            block_number = 0
        except:
            traceback.print_exc(file=sys.stdout)
            block_number = 0
        finally:
            dblock.release()

        # do addresses
        while True:
            try:
                addr = address_queue.get(False)
            except:
                break
            do_update_address(addr)

        time.sleep(10)

    print "server stopped"

