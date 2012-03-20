#!/usr/bin/env python
# Copyright(C) 2012 thomasv@gitorious

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
config.set('server', 'port', '50000')
config.set('server', 'password', '')
config.set('server', 'irc', 'yes')
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

stopping = False
block_number = -1
old_block_number = -1
sessions = {}
sessions_sub_numblocks = {} # sessions that have subscribed to the service

m_sessions = [{}] # served by http

peer_list = {}

wallets = {} # for ultra-light clients such as bccapi

from Queue import Queue
input_queue = Queue()
output_queue = Queue()
address_queue = Queue()





class Direct_Interface(Interface):
    def __init__(self):
        pass

    def handler(self, method, params = ''):
        cmds = {'session.new':new_session,
                'session.poll':poll_session,
                'session.update':update_session,
                'transaction.broadcast':send_tx,
                'address.get_history':store.get_history
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

    

def cmd_stop(_,__,pw):
    global stopping
    if password == pw:
        stopping = True
        return 'ok'
    else:
        return 'wrong password'

def cmd_load(_,__,pw):
    if password == pw:
        return repr( len(sessions) )
    else:
        return 'wrong password'





def modified_addresses(session):
    if 1:
        t1 = time.time()
        addresses = session['addresses']
        session['last_time'] = time.time()
        ret = {}
        k = 0
        for addr in addresses:
            status = get_address_status( addr )
            msg_id, last_status = addresses.get( addr )
            if last_status != status:
                addresses[addr] = msg_id, status
                ret[addr] = status

        t2 = time.time() - t1 
        #if t2 > 10: print "high load:", session_id, "%d/%d"%(k,len(addresses)), t2
        return ret, addresses


def poll_session(session_id): 
    # native
    session = sessions.get(session_id)
    if session is None:
        print time.asctime(), "session not found", session_id
        return -1, {}
    else:
        ret, addresses = modified_addresses(session)
        if ret: sessions[session_id]['addresses'] = addresses
        return repr( (block_number,ret))


def poll_session_json(session_id, message_id):
    session = m_sessions[0].get(session_id)
    if session is None:
        raise BaseException("session not found %s"%session_id)
    else:
        out = []
        ret, addresses = modified_addresses(session)
        if ret: 
            m_sessions[0][session_id]['addresses'] = addresses
            for addr in ret:
                msg_id, status = addresses[addr]
                out.append(  { 'id':msg_id, 'result':status } )

        msg_id, last_nb = session.get('numblocks')
        if last_nb:
            if last_nb != block_number:
                m_sessions[0][session_id]['numblocks'] = msg_id, block_number
                out.append( {'id':msg_id, 'result':block_number} )

        return out


def do_update_address(addr):
    # an address was involved in a transaction; we check if it was subscribed to in a session
    # the address can be subscribed in several sessions; the cache should ensure that we don't do redundant requests

    for session_id in sessions.keys():
        session = sessions[session_id]
        if session.get('type') != 'persistent': continue
        addresses = session['addresses'].keys()

        if addr in addresses:
            status = get_address_status( addr )
            message_id, last_status = session['addresses'][addr]
            if last_status != status:
                #print "sending new status for %s:"%addr, status
                send_status(session_id,message_id,addr,status)
                sessions[session_id]['addresses'][addr] = (message_id,status)

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
    message_id = sessions_sub_numblocks[session_id]
    out = json.dumps( {'id':message_id, 'result':block_number} )
    output_queue.put((session_id, out))

def send_status(session_id, message_id, address, status):
    out = json.dumps( { 'id':message_id, 'result':status } )
    output_queue.put((session_id, out))

def address_get_history_json(_,message_id,address):
    return store.get_history(address)

def subscribe_to_numblocks(session_id, message_id):
    sessions_sub_numblocks[session_id] = message_id
    send_numblocks(session_id)

def subscribe_to_numblocks_json(session_id, message_id):
    global m_sessions
    m_sessions[0][session_id]['numblocks'] = message_id,block_number
    return block_number

def subscribe_to_address(session_id, message_id, address):
    status = get_address_status(address)
    sessions[session_id]['addresses'][address] = (message_id, status)
    sessions[session_id]['last_time'] = time.time()
    send_status(session_id, message_id, address, status)

def add_address_to_session_json(session_id, message_id, address):
    global m_sessions
    sessions = m_sessions[0]
    status = get_address_status(address)
    sessions[session_id]['addresses'][address] = (message_id, status)
    sessions[session_id]['last_time'] = time.time()
    m_sessions[0] = sessions
    return status

def add_address_to_session(session_id, address):
    status = get_address_status(address)
    sessions[session_id]['addresses'][addr] = ("", status)
    sessions[session_id]['last_time'] = time.time()
    return status

def new_session(version, addresses):
    session_id = random_string(10)
    sessions[session_id] = { 'addresses':{}, 'version':version }
    for a in addresses:
        sessions[session_id]['addresses'][a] = ('','')
    out = repr( (session_id, config.get('server','banner').replace('\\n','\n') ) )
    sessions[session_id]['last_time'] = time.time()
    return out


def client_version_json(session_id, _, version):
    global m_sessions
    sessions = m_sessions[0]
    sessions[session_id]['version'] = version
    m_sessions[0] = sessions

def create_session_json(_, __):
    sessions = m_sessions[0]
    session_id = random_string(10)
    print "creating session", session_id
    sessions[session_id] = { 'addresses':{}, 'numblocks':('','') }
    sessions[session_id]['last_time'] = time.time()
    m_sessions[0] = sessions
    return session_id



def get_banner(_,__):
    return config.get('server','banner').replace('\\n','\n')

def update_session(session_id,addresses):
    """deprecated in 0.42"""
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


def timestr():
    return time.strftime("[%d/%m/%Y-%H:%M:%S]")

# used by the native handler
def do_command(cmd, data, ipaddr):

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
        print timestr(), "new session", ipaddr, addresses[0] if addresses else addresses, len(addresses), version
        out = new_session(version, addresses)

    elif cmd=='address.subscribe':
        try:
            session_id, addr = ast.literal_eval(data)
        except:
            print "error"
            return None
        out = add_address_to_session(session_id,addr)

    elif cmd=='update_session':
        try:
            session_id, addresses = ast.literal_eval(data)
        except:
            print "error"
            return None
        print timestr(), "update session", ipaddr, addresses[0] if addresses else addresses, len(addresses)
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
        print timestr(), "sent tx:", ipaddr, out

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


def close_session(session_id):
    #print "lost connection", session_id
    sessions.pop(session_id)
    if session_id in sessions_sub_numblocks:
        sessions_sub_numblocks.pop(session_id)


# one thread per client. put requests in a queue.
def tcp_client_thread(ipaddr,conn):
    """ use a persistent connection. put commands in a queue."""

    print timestr(), "TCP session", ipaddr
    global sessions

    session_id = random_string(10)
    sessions[session_id] = { 'conn':conn, 'addresses':{}, 'version':'unknown', 'type':'persistent' }

    ipaddr = ipaddr[0]
    msg = ''

    while not stopping:
        try:
            d = conn.recv(1024)
        except socket.error:
            d = ''
        if not d:
            close_session(session_id)
            break

        msg += d
        while True:
            s = msg.find('\n')
            if s ==-1:
                break
            else:
                c = msg[0:s].strip()
                msg = msg[s+1:]
                if c == 'quit': 
                    conn.close()
                    close_session(session_id)
                    return
                try:
                    c = json.loads(c)
                except:
                    print "json error", repr(c)
                    continue
                try:
                    message_id = c.get('id')
                    method = c.get('method')
                    params = c.get('params')
                except:
                    print "syntax error", repr(c), ipaddr
                    continue

                # add to queue
                input_queue.put((session_id, message_id, method, params))



# read commands from the input queue. perform requests, etc. this should be called from the main thread.
def process_input_queue():
    while not stopping:
        session_id, message_id, method, data = input_queue.get()
        if session_id not in sessions.keys():
            continue
        out = None
        if method == 'address.subscribe':
            address = data[0]
            subscribe_to_address(session_id,message_id,address)
        elif method == 'numblocks.subscribe':
            subscribe_to_numblocks(session_id,message_id)
        elif method == 'client.version':
            sessions[session_id]['version'] = data[0]
        elif method == 'server.banner':
            out = { 'result':config.get('server','banner').replace('\\n','\n') } 
        elif method == 'server.peers':
            out = { 'result':peer_list.values() } 
        elif method == 'address.get_history':
            address = data[0]
            out = { 'result':store.get_history( address ) } 
        elif method == 'transaction.broadcast':
            postdata = dumps({"method": 'importtransaction', 'params': [data], 'id':'jsonrpc'})
            txo = urllib.urlopen(bitcoind_url, postdata).read()
            print "sent tx:", txo
            out = json.loads(txo)
        else:
            print "unknown command", method
        if out:
            out['id'] = message_id
            out = json.dumps( out )
            output_queue.put((session_id, out))

# this is a separate thread
def process_output_queue():
    while not stopping:
        session_id, out = output_queue.get()
        session = sessions.get(session_id)
        if session: 
            try:
                conn = session.get('conn')
                conn.send(out+'\n')
            except:
                close_session(session_id)
                



####################################################################




def clean_session_thread():
    while not stopping:
        time.sleep(30)
        t = time.time()
        for k,s in sessions.items():
            if s.get('type') == 'persistent': continue
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


def get_peers_json(_,__):
    return peer_list.values()

def http_server_thread():
    # see http://code.google.com/p/jsonrpclib/
    from SocketServer import ThreadingMixIn
    from StratumJSONRPCServer import StratumJSONRPCServer
    class StratumThreadedJSONRPCServer(ThreadingMixIn, StratumJSONRPCServer): pass
    server = StratumThreadedJSONRPCServer(( config.get('server','host'), 8081))
    server.register_function(get_peers_json, 'server.peers')
    server.register_function(cmd_stop, 'stop')
    server.register_function(cmd_load, 'load')
    server.register_function(get_banner, 'server.banner')
    server.register_function(lambda a,b,c: send_tx(c), 'transaction.broadcast')
    server.register_function(address_get_history_json, 'address.get_history')
    server.register_function(add_address_to_session_json, 'address.subscribe')
    server.register_function(subscribe_to_numblocks_json, 'numblocks.subscribe')
    server.register_function(client_version_json, 'client.version')
    server.register_function(create_session_json, 'session.create')   # internal message (not part of protocol)
    server.register_function(poll_session_json, 'session.poll')       # internal message (not part of protocol)
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
            out = server.server.peers()
        elif cmd == 'stop':
            out = server.stop(password)
        elif cmd == 'clear_cache':
            out = server.clear_cache(password)
        elif cmd == 'get_cache':
            out = server.get_cache(password,sys.argv[2])
        elif cmd == 'h':
            out = server.address.get_history(sys.argv[2])
        elif cmd == 'tx':
            out = server.transaction.broadcast(sys.argv[2])
        elif cmd == 'b':
            out = server.numblocks.subscribe()
        else:
            out = "Unknown command: '%s'" % cmd
        print out
        sys.exit(0)


    # backend
    import db
    store = db.MyStore(config,address_queue)


    # supported protocols
    thread.start_new_thread(native_server_thread, ())
    thread.start_new_thread(tcp_server_thread, ())
    thread.start_new_thread(http_server_thread, ())
    thread.start_new_thread(clean_session_thread, ())

    if (config.get('server','irc') == 'yes' ):
	thread.start_new_thread(irc_thread, ())

    print "starting Electrum server"


    while not stopping:
        block_number = store.main_iteration()

        if block_number != old_block_number:
            old_block_number = block_number
            for session_id in sessions_sub_numblocks.keys():
                send_numblocks(session_id)
        # do addresses
        while True:
            try:
                addr = address_queue.get(False)
            except:
                break
            do_update_address(addr)

        time.sleep(10)
    print "server stopped"

