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


import random, socket, ast
import thread, threading, traceback, sys, time, json

DEFAULT_TIMEOUT = 5
DEFAULT_SERVERS = ['ecdsa.org','electrum.novit.ro']  # list of default servers


class Interface:
    def __init__(self, host, port, address_callback=None, history_callback=None, newblock_callback=None):
        self.host = host
        self.port = port
        self.address_callback = address_callback
        self.history_callback = history_callback
        self.newblock_callback = newblock_callback

        self.servers = DEFAULT_SERVERS                            # actual list from IRC
        self.rtime = 0
        self.blocks = 0 
        self.message = ''
        self.was_updated = True # fixme: use a semaphore
        self.is_up_to_date = False

        self.is_connected = False
        self.disconnected_event = threading.Event()
        self.disconnected_event.clear()

        #only asynchrnous
        self.addresses_waiting_for_status = []
        self.addresses_waiting_for_history = []
        self.tx_event = threading.Event()
        self.up_to_date_event = threading.Event()
        self.up_to_date_event.clear()

        #json
        self.message_id = 0
        self.messages = {}

    def send_tx(self, data):
        self.tx_event.clear()
        self.send([('transaction.broadcast', [data])])
        self.tx_event.wait()
        return self.tx_result

    def get_servers(self):
        pass

    def start_session(self, addresses, version):
        pass


    def handle_json_response(self, c):
        #print c
        msg_id = c.get('id')
        result = c.get('result')
        error = c.get('error')
        if msg_id is None:
            print "error: message without ID"
            return

        method, params = self.messages[msg_id]
        if error:
            print "received error:", c, method, params
        else:
            if method == 'session.poll': #embedded messages
                if result:
                    self.is_up_to_date = False
                    for msg in result:
                        self.handle_json_response(msg)
                else:
                    self.is_up_to_date = True
            else:
                self.handle_response(method, params, result)
                



    def handle_response(self, method, params, result):

        if method == 'server.banner':
            self.message = result
            self.was_updated = True

        elif method == 'session.poll':
            # native poll
            blocks, changed_addresses = result 
            if blocks == -1: raise BaseException("session not found")
            self.blocks = int(blocks)
            if changed_addresses:
                self.is_up_to_date = False
                self.was_updated = True
                for addr, status in changed_addresses.items():
                    apply(self.address_callback, (addr, status))
            else:
                self.is_up_to_date = True

        elif method == 'server.peers':
            self.servers = map( lambda x:x[1], result )

        elif method == 'address.subscribe':
            addr = params[-1]
            if addr in self.addresses_waiting_for_status:
                self.addresses_waiting_for_status.remove(addr)
            apply(self.address_callback,(addr, result))
                            
        elif method == 'address.get_history':
            addr = params[0]
            if addr in self.addresses_waiting_for_history:
                self.addresses_waiting_for_history.remove(addr)
            apply(self.history_callback, (addr, result))
            self.was_updated = True

        elif method == 'transaction.broadcast':
            self.tx_result = result
            self.tx_event.set()

        elif method == 'numblocks.subscribe':
            self.blocks = result
            if self.newblock_callback: apply(self.newblock_callback,(result,))

        else:
            print "received message:", method, params, result


    def subscribe(self, addresses):
        messages = []
        for addr in addresses:
            messages.append(('address.subscribe', [addr]))
            self.addresses_waiting_for_status.append(addr)
        self.send(messages)


class PollingInterface(Interface):
    """ non-persistent connection. synchronous calls"""

    def start_session(self, addresses, version):
        self.send([('session.new', [ version, addresses ])] )
        thread.start_new_thread(self.poll_thread, (5,))

    def get_history(self, address):
        self.send([('address.get_history', [address] )])

    def update_wallet(self):
        while True:
            self.send([('session.poll', [])])
            if self.is_up_to_date: break

        #if is_new or wallet.remote_url:
        #    self.was_updated = True
        #    is_new = wallet.synchronize()
        #    wallet.update_tx_history()
        #    wallet.save()
        #    return is_new
        #else:
        #    return False

    def poll_thread(self, poll_interval):
        while self.is_connected:
            try:
                self.update_wallet()
                time.sleep(poll_interval)
            except socket.gaierror:
                break
            except socket.error:
                break
            except:
                traceback.print_exc(file=sys.stdout)
                break
            
        self.is_connected = False
        self.disconnected_event.set()

                
    def get_servers(self):
        #thread.start_new_thread(self.update_servers_thread, ())
        pass

    def update_servers_thread(self):
        # if my server is not reachable, I should get the list from one of the default servers
        # requesting servers could be an independent process
        while True:
            for server in DEFAULT_SERVERS:
                try:
                    self.peers_server = server

                    self.send([('server.peers',[])])

                    # print "Received server list from %s" % self.peers_server, out
                    break
                except socket.timeout:
                    continue
                except socket.error:
                    continue
                except:
                    traceback.print_exc(file=sys.stdout)

            time.sleep(5*60)





class NativeInterface(PollingInterface):

    def send(self, messages):
        import time
        cmds = {'session.new':'new_session',
                'server.peers':'peers',
                'session.poll':'poll',
                'transaction.broadcast':'tx',
                'address.get_history':'h',
                'address.subscribe':'address.subscribe'
                }

        for m in messages:
            method, params = m
            cmd = cmds[method]

            if cmd == 'poll':
                params = self.session_id

            if cmd in ['h', 'tx']:
                str_params = params[0]
            elif type(params) != type(''): 
                str_params = repr( params )
            else:
                str_params = params
            t1 = time.time()
            request = repr ( (cmd, str_params) ) + "#"
            s = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(DEFAULT_TIMEOUT)
            s.connect(( self.host if cmd!='peers' else self.peers_server, self.port) )
            s.send( request )
            out = ''
            while 1:
                msg = s.recv(1024)
                if msg: out += msg
                else: break
            s.close()
            self.rtime = time.time() - t1
            self.is_connected = True

            if cmd in[ 'peers','h','poll']:
                out = ast.literal_eval( out )

            if out=='': out=None #fixme

            if cmd == 'new_session':
                self.session_id, self.message = ast.literal_eval( out )
                self.was_updated = True
            else:
                self.handle_response(method, params, out)





class HttpInterface(PollingInterface):

    def start_session(self, addresses, version):
        self.session_id = None
        self.send([('client.version', [version]), ('server.banner',[]), ('numblocks.subscribe',[])])
        self.subscribe(addresses)
        thread.start_new_thread(self.poll_thread, (15,))


    def send(self, messages):
        import urllib2, json, time, cookielib

        cj = cookielib.CookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        urllib2.install_opener(opener)

        data = []
        for m in messages:
            method, params = m
            if type(params) != type([]): params = [params]
            t1 = time.time()
            data.append( { 'method':method, 'id':self.message_id, 'params':params } )
            self.messages[self.message_id] = (method, params)
            self.message_id += 1

        data_json = json.dumps(data)
        #print data_json
        #host = 'http://%s:%d'%( self.host if method!='server.peers' else self.peers_server, self.port )
        host = 'http://%s:%d'%( self.host, self.port )

        headers = {'content-type': 'application/json'}
        if self.session_id:
            headers['cookie'] = 'SESSION=%s'%self.session_id

        req = urllib2.Request(host, data_json, headers)
        response_stream = urllib2.urlopen(req)

        for index, cookie in enumerate(cj):
            if cookie.name=='SESSION':
                self.session_id = cookie.value

        response = json.loads( response_stream.read() )

        self.rtime = time.time() - t1
        self.is_connected = True

        for item in response:
            self.handle_json_response(item)





class AsynchronousInterface(Interface):
    """json-rpc over persistent TCP connection, asynchronous"""

    def listen_thread(self):
        try:
            self.is_connected = True
            out = ''
            while self.is_connected:
                try: msg = self.s.recv(1024)
                except socket.timeout: continue
                out += msg
                if msg == '': 
                    self.is_connected = False
                    print "disconnected."

                while True:
                    s = out.find('\n')
                    if s==-1: break
                    c = out[0:s]
                    out = out[s+1:]
                    c = json.loads(c)
                    self.handle_json_response(c)
                    if self.addresses_waiting_for_status or self.addresses_waiting_for_history:
                        self.is_up_to_date = False
                    else:
                        self.is_up_to_date = True
                        self.up_to_date_event.set()

        except:
            traceback.print_exc(file=sys.stdout)

        self.is_connected = False
        self.disconnected_event.set()

    def update_wallet(self,cb):
        self.up_to_date_event.wait()

    def send(self, messages):
        out = ''
        for m in messages:
            method, params = m 
            request = json.dumps( { 'id':self.message_id, 'method':method, 'params':params } )
            self.messages[self.message_id] = (method, params)
            self.message_id += 1
            out += request + '\n'
        self.s.send( out )

    def get_servers(self):
        self.send([('server.peers',[])])

    def get_history(self, addr):
        self.send([('address.get_history', [addr])])
        self.addresses_waiting_for_history.append(addr)

    def start_session(self, addresses, version):
        self.s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.s.settimeout(1)
        self.s.connect(( self.host, self.port))
        thread.start_new_thread(self.listen_thread, ())
        self.send([('client.version', [version]), ('server.banner',[]), ('numblocks.subscribe',[])])
        self.subscribe(addresses)





def new_interface(wallet):
    if wallet.host:
        host = wallet.host
    else:
        host = random.choice( DEFAULT_SERVERS )         # random choice when the wallet is created
    port = wallet.port
    address_cb = wallet.receive_status_callback
    history_cb = wallet.receive_history_callback

    if port == 50000:
        InterfaceClass = NativeInterface
    elif port == 50001:
        InterfaceClass = AsynchronousInterface
    elif port in [80, 81, 8080, 8081]:
        InterfaceClass = HttpInterface
    else:
        print "unknown port number: %d. using native protocol."%port
        InterfaceClass = NativeInterface

    interface = InterfaceClass(host, port, address_cb, history_cb)
        
    return interface
       

def loop_interfaces_thread(wallet):
    while True:
        try:
            addresses = wallet.all_addresses()
            version = wallet.electrum_version
            wallet.interface.start_session(addresses, version)
            wallet.interface.get_servers()

            wallet.interface.disconnected_event.wait()
            print "Disconnected"
        except socket.error:
            print "socket error"
            time.sleep(5)
        except:
            traceback.print_exc(file=sys.stdout)
            time.sleep(5)
            continue

        print "Starting new session: %s:%d"%(wallet.host,wallet.port)
        wallet.interface = new_interface(wallet)

