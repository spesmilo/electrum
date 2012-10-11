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
from electrum import Wallet, Interface

import ConfigParser
config = ConfigParser.ConfigParser()
config.read("merchant.conf")

db_instance = config.get('db','instance')
db_user = config.get('db','user')
db_password = config.get('db','password')
db_name = config.get('db','name')

electrum_server = config.get('electrum','server')
mpk = config.get('electrum','mpk')

my_password = config.get('main','password')
my_host = config.get('main','host')
my_port = config.getint('main','port')

cb_received = config.get('callback','received')
cb_expired = config.get('callback','expired')
cb_password = config.get('callback','password')

wallet = Wallet()
wallet.master_public_key = mpk.decode('hex')



omg_addresses = {}

def electrum_input_thread(in_queue, i):
    while True:
        addr, amount = in_queue.get(True,1000000000)
        if addr in omg_addresses: 
            continue
        else:
            print "subscribing to ", addr
            omg_addresses[addr] = amount
            i.send([('blockchain.address.subscribe',[addr])])


def electrum_output_thread(out_queue, i):
    while True:
        r = i.responses.get(True, 100000000000)
        method = r.get('method') 

        if method == 'blockchain.address.subscribe':
            addr = r.get('params')[0]
            i.send([('blockchain.address.get_history',[addr])])

        elif method == 'blockchain.address.get_history':
            addr = r.get('params')[0]
            #print "received history for", addr
            confirmed = unconfirmed = 0
            h = r.get('result')
            if h is None:
                continue
            for item in h:
                v = item['value']
                if v<0: continue
                if item['height']:
                    confirmed += v
                else:
                    unconfirmed += v
                
            s = (confirmed+unconfirmed)/1.e8
            print "balance for %s:"%addr, s
            amount = float(omg_addresses.get(addr))
            if s>=amount:
                out_queue.put( ('payment',addr) )


stopping = False

def do_stop():
    global stopping
    stopping = True

def do_create(conn):
    # creation
    cur = conn.cursor()
    cur.execute("CREATE TABLE electrum_payments (id INT PRIMARY KEY, address VARCHAR(40), amount FLOAT, received_at TIMESTAMP, expires_at TIMESTAMP, paid INT(1), processed INT(1));")
    conn.commit()

def process_request(i, amount, confirmations, expires_in, password):
    print "process_request", i, amount, confirmations, expires_in
    if password!=my_password:
        print "wrong password ", password
        return
    addr = wallet.get_new_address(i, 0)
    out_queue.put( ('request',(i,addr,amount,expires_in) ))
    return addr

def get_mpk():
    return wallet.master_public_key.encode('hex')


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

    i = Interface({'server':"%s:%d:t"%(electrum_server, 50001)})
    i.init_socket()
    i.start()
    

    # this process detects when addresses have paid
    in_queue = Queue.Queue()
    out_queue = Queue.Queue()
    thread.start_new_thread(electrum_input_thread, (in_queue,i))
    thread.start_new_thread(electrum_output_thread, (out_queue,i))

    thread.start_new_thread(server_thread, (conn,))


    while not stopping:
        cur = conn.cursor()

        # get a list of addresses to watch
        cur.execute("SELECT address, amount FROM electrum_payments WHERE paid IS NULL;")
        data = cur.fetchall()
        for item in data: 
            in_queue.put(item)

        try:
            cmd, params = out_queue.get(True, 10)
        except Queue.Empty:
            cmd = ''

        if cmd == 'payment':
            # set paid=1 for received payments
            print "received payment from", addr
            cur.execute("select id from electrum_payments where address='%s';"%addr)
            id = cur.fetchone()[0]
            cur.execute("update electrum_payments set paid=1 where id=%d;"%(id))
        elif cmd == 'request':
            i, addr, amount, hours = params
            sql = "INSERT INTO electrum_payments (id, address, amount, received_at, expires_at, paid, processed)"\
                + " VALUES (%d, '%s', %f, CURRENT_TIMESTAMP, ADDTIME(CURRENT_TIMESTAMP, '0 %d:0:0'), NULL, NULL);"%(i, addr, amount, hours)
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


