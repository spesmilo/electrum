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


import time, thread, sys, socket, os
import urllib2,json
import MySQLdb as mdb
import Queue
from electrum import Wallet, Interface, WalletVerifier, SimpleConfig, WalletSynchronizer

import ConfigParser
config = ConfigParser.ConfigParser()
config.read("merchant.conf")

db_instance = config.get('db','instance')
db_user = config.get('db','user')
db_password = config.get('db','password')
db_name = config.get('db','name')

electrum_server = config.get('electrum','server')

my_password = config.get('main','password')
my_host = config.get('main','host')
my_port = config.getint('main','port')

cb_received = config.get('callback','received')
cb_expired = config.get('callback','expired')
cb_password = config.get('callback','password')


wallet_config = SimpleConfig()
master_public_key = config.get('electrum','mpk')
wallet_config.set_key('master_public_key',master_public_key)
wallet = Wallet(wallet_config)
wallet.synchronize = lambda: None # prevent address creation by the wallet


omg_addresses = {}

def input_reader_thread(request_queue):
    while True:
        addr, amount, confirmations = request_queue.get(True,1000000000)
        if addr in omg_addresses: 
            continue
        else:
            print "subscribing to ", addr
            omg_addresses[addr] = {'requested':float(amount), 'confirmations':int(confirmations)}

        if addr not in wallet.addresses:
            with wallet.lock:
                print "adding %s to wallet"%addr
                wallet.addresses.append(addr)
                wallet.history[addr] = []
                synchronizer.subscribe_to_addresses([addr])
                wallet.up_to_date = False



def on_wallet_update():
    print "updated_callback"
    for addr in omg_addresses:
        h = wallet.history.get(addr)

        requested_amount = omg_addresses[addr].get('requested')
        requested_confs  = omg_addresses[addr].get('confirmations')

        value = 0
        for tx_hash, tx_height in h:

            tx = wallet.transactions.get(tx_hash)
            if not tx: continue
            if verifier.get_confirmations(tx_hash) < requested_confs: continue
            for o in tx.get('outputs'):
                if o.get('address') == addr:
                    value += o.get('value')

        s = (value)/1.e8
        print "balance for %s:"%addr, s, requested_amount
        if s>= requested_amount: 
            print "payment accepted", addr
            out_queue.put( ('payment', addr))


stopping = False

def do_stop():
    global stopping
    stopping = True

def do_create(conn):
    # creation
    cur = conn.cursor()
    cur.execute("CREATE TABLE electrum_payments (id INT PRIMARY KEY, address VARCHAR(40), amount FLOAT, confirmations INT(8), received_at TIMESTAMP, expires_at TIMESTAMP, paid INT(1), processed INT(1));")
    conn.commit()

def process_request(i, amount, confirmations, expires_in, password):
    print "process_request", i, amount, confirmations, expires_in
    if password!=my_password:
        print "wrong password ", password
        return 
    addr = wallet.get_new_address(0, i, 0)
    out_queue.put( ('request', (i, addr, amount, confirmations, expires_in) ))
    return addr

def get_mpk():
    return wallet.master_public_key


def server_thread(conn):
    from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
    server = SimpleJSONRPCServer(( my_host, my_port))
    server.register_function(process_request, 'request')
    server.register_function(get_mpk, 'mpk')
    server.register_function(do_stop, 'stop')
    server.serve_forever()
    

def handle_command(cmd):
    import jsonrpclib
    server = jsonrpclib.Server('http://%s:%d'%(my_host, my_port))
    try:
        if cmd == 'mpk':
            out = server.mpk()
        elif cmd == 'stop':
            out = server.stop()
        elif cmd == 'create':
            conn = mdb.connect(db_instance, db_user, db_password, db_name);
            do_create(conn)
            out = "ok"
        else:
            out = "unknown command"
    except socket.error:
        print "Server not running"
        return 1

    print out
    return 0


if __name__ == '__main__':

    if len(sys.argv) > 1:
        ret = handle_command(sys.argv[1])
        sys.exit(ret)

    print "using database", db_name
    conn = mdb.connect(db_instance, db_user, db_password, db_name);

    interface = Interface({'server':"%s:%d:t"%(electrum_server, 50001)})
    interface.start()
    interface.send([('blockchain.numblocks.subscribe',[])])

    wallet.interface = interface
    interface.register_callback('updated', on_wallet_update)

    verifier = WalletVerifier(interface, wallet_config)
    wallet.set_verifier(verifier)

    synchronizer = WalletSynchronizer(wallet, wallet_config)
    synchronizer.start()

    verifier.start()
    

    # this process detects when addresses have paid
    request_queue = Queue.Queue()
    out_queue = Queue.Queue()
    thread.start_new_thread(input_reader_thread, (request_queue,))
    thread.start_new_thread(server_thread, (conn,))

    while not stopping:
        cur = conn.cursor()

        # read pending requests from table
        cur.execute("SELECT address, amount, confirmations FROM electrum_payments WHERE paid IS NULL;")
        data = cur.fetchall()
        for item in data: 
            request_queue.put(item)

        try:
            cmd, params = out_queue.get(True, 10)
        except Queue.Empty:
            cmd = ''

        if cmd == 'payment':
            addr = params
            # set paid=1 for received payments
            print "received payment from", addr
            cur.execute("select id from electrum_payments where address='%s';"%addr)
            id = cur.fetchone()[0]
            cur.execute("update electrum_payments set paid=1 where id=%d;"%(id))

        elif cmd == 'request':
            # add a new request to the table.
            i, addr, amount, confs, hours = params
            sql = "INSERT INTO electrum_payments (id, address, amount, confirmations, received_at, expires_at, paid, processed)"\
                + " VALUES (%d, '%s', %f, %d, CURRENT_TIMESTAMP, ADDTIME(CURRENT_TIMESTAMP, '0 %d:0:0'), NULL, NULL);"%(i, addr, amount, confs, hours)
            cur.execute(sql)


        # set paid=0 for expired requests 
        cur.execute("""UPDATE electrum_payments set paid=0 WHERE expires_at < CURRENT_TIMESTAMP and paid is NULL;""")

        # do callback for addresses that received payment
        cur.execute("""SELECT id, address, paid from electrum_payments WHERE paid is not NULL and processed is NULL;""")
        data = cur.fetchall()
        for item in data:
            print "callback:", item
            id = int(item[0])
            address = item[1]
            paid = int(item[2])
            headers = {'content-type':'application/json'}
            data_json = { 'id':id, 'address':address, 'btc_auth':cb_password }
            data_json = json.dumps(data_json)
            url = cb_received if paid else cb_expired
            req = urllib2.Request(url, data_json, headers)
            try:
                response_stream = urllib2.urlopen(req)
                cur.execute("UPDATE electrum_payments SET processed=1 WHERE id=%d;"%(id))
            except urllib2.HTTPError:
                print "cannot do callback", data_json
        
        conn.commit()


    conn.close()
    print "terminated"



