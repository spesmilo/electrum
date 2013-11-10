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
import Queue
import sqlite3
from electrum import Wallet, WalletStorage, SimpleConfig, Network, set_verbosity
set_verbosity(False)

import ConfigParser
config = ConfigParser.ConfigParser()
config.read("merchant.conf")

my_password = config.get('main','password')
my_host = config.get('main','host')
my_port = config.getint('main','port')

database = config.get('sqlite3','database')

received_url = config.get('callback','received')
expired_url = config.get('callback','expired')
cb_password = config.get('callback','password')

wallet_path = config.get('electrum','wallet_path')
master_public_key = config.get('electrum','mpk')
master_chain = config.get('electrum','chain')


pending_requests = {}

num = 0

def check_create_table(conn):
    global num
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='electrum_payments';")
    data = c.fetchall()
    if not data: 
        c.execute("""CREATE TABLE electrum_payments (address VARCHAR(40), amount FLOAT, confirmations INT(8), received_at TIMESTAMP, expires_at TIMESTAMP, paid INT(1), processed INT(1));""")
        conn.commit()

    c.execute("SELECT Count(address) FROM 'electrum_payments'")
    num = c.fetchone()[0]
    print "num rows", num



# this process detects when addresses have received payments
def on_wallet_update():
    for addr, v in pending_requests.items():
        h = wallet.history.get(addr, [])
        requested_amount = v.get('requested')
        requested_confs  = v.get('confirmations')
        value = 0
        for tx_hash, tx_height in h:
            tx = wallet.transactions.get(tx_hash)
            if not tx: continue
            if wallet.verifier.get_confirmations(tx_hash) < requested_confs: continue
            for o in tx.outputs:
                o_address, o_value = o
                if o_address == addr:
                    value += o_value

        s = (value)/1.e8
        print "balance for %s:"%addr, s, requested_amount
        if s>= requested_amount: 
            print "payment accepted", addr
            out_queue.put( ('payment', addr))


stopping = False

def do_stop(password):
    global stopping
    if password != my_password:
        return "wrong password"
    stopping = True
    return "ok"

def process_request(amount, confirmations, expires_in, password):
    global num

    if password != my_password:
        return "wrong password"

    try:
        amount = float(amount)
        confirmations = int(confirmations)
        expires_in = float(expires_in)
    except Exception:
        return "incorrect parameters"

    account = wallet.accounts["m/0'/0"]
    addr = account.get_address(0, num)
    num += 1

    out_queue.put( ('request', (addr, amount, confirmations, expires_in) ))
    return addr



def server_thread(conn):
    from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
    server = SimpleJSONRPCServer(( my_host, my_port))
    server.register_function(process_request, 'request')
    server.register_function(do_stop, 'stop')
    server.serve_forever()
    




def send_command(cmd, params):
    import jsonrpclib
    server = jsonrpclib.Server('http://%s:%d'%(my_host, my_port))
    try:
        if cmd == 'request':
            out = server.request(*params)
        elif cmd == 'stop':
            out = server.stop(*params)
        else:
            out = "unknown command"
    except socket.error:
        print "Server not running"
        return 1

    print out
    return 0


if __name__ == '__main__':

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        params = sys.argv[2:] + [my_password]
        ret = send_command(cmd, params)
        sys.exit(ret)

    conn = sqlite3.connect(database);
    # create table if needed
    check_create_table(conn)

    # init network
    config = SimpleConfig({'wallet_path':wallet_path})
    network = Network(config)
    network.start(wait=True)

    # create watching_only wallet
    storage = WalletStorage(config)
    wallet = Wallet(storage)
    if not storage.file_exists:
        wallet.seed = ''
        wallet.create_watching_only_wallet(master_chain,master_public_key)

    wallet.synchronize = lambda: None # prevent address creation by the wallet
    wallet.start_threads(network)
    network.register_callback('updated', on_wallet_update)
    
    out_queue = Queue.Queue()
    thread.start_new_thread(server_thread, (conn,))

    while not stopping:
        cur = conn.cursor()

        # read pending requests from table
        cur.execute("SELECT address, amount, confirmations FROM electrum_payments WHERE paid IS NULL;")
        data = cur.fetchall()

        # add pending requests to the wallet
        for item in data: 
            addr, amount, confirmations = item
            if addr in pending_requests: 
                continue
            else:
                with wallet.lock:
                    print "subscribing to %s"%addr
                    pending_requests[addr] = {'requested':float(amount), 'confirmations':int(confirmations)}
                    wallet.synchronizer.subscribe_to_addresses([addr])
                    wallet.up_to_date = False

        try:
            cmd, params = out_queue.get(True, 10)
        except Queue.Empty:
            cmd = ''

        if cmd == 'payment':
            addr = params
            # set paid=1 for received payments
            print "received payment from", addr
            cur.execute("update electrum_payments set paid=1 where address='%s'"%addr)

        elif cmd == 'request':
            # add a new request to the table.
            addr, amount, confs, minutes = params
            sql = "INSERT INTO electrum_payments (address, amount, confirmations, received_at, expires_at, paid, processed)"\
                + " VALUES ('%s', %f, %d, datetime('now'), datetime('now', '+%d Minutes'), NULL, NULL);"%(addr, amount, confs, minutes)
            print sql
            cur.execute(sql)

        # set paid=0 for expired requests 
        cur.execute("""UPDATE electrum_payments set paid=0 WHERE expires_at < CURRENT_TIMESTAMP and paid is NULL;""")

        # do callback for addresses that received payment or expired
        cur.execute("""SELECT address, paid from electrum_payments WHERE paid is not NULL and processed is NULL;""")
        data = cur.fetchall()
        for item in data:
            address, paid = item
            paid = bool(paid)
            headers = {'content-type':'application/json'}
            data_json = { 'address':address, 'password':cb_password, 'paid':paid }
            data_json = json.dumps(data_json)
            url = received_url if paid else expired_url
            req = urllib2.Request(url, data_json, headers)
            try:
                response_stream = urllib2.urlopen(req)
                cur.execute("UPDATE electrum_payments SET processed=1 WHERE id=%d;"%(id))
            except urllib2.HTTPError:
                print "cannot do callback", data_json
            except ValueError, e:
                print e
                print "cannot do callback", data_json
        
        conn.commit()

    conn.close()
    print "Done"

