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


import random, socket, ast, re
import threading, traceback, sys, time, json, Queue

DEFAULT_TIMEOUT = 5
DEFAULT_SERVERS = ['ecdsa.org:50001:t'] #  ['electrum.bitcoins.sk','ecdsa.org','electrum.novit.ro']  # list of default servers


def old_to_new(s):
    s = s.replace("'blk_hash'", "'block_hash'")
    s = s.replace("'pos'", "'index'")
    s = s.replace("'nTime'", "'timestamp'")
    s = s.replace("'is_in'", "'is_input'")
    s = s.replace("'raw_scriptPubKey'","'raw_output_script'")
    return s


class Interface(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.daemon = True
        self.host = host
        self.port = port

        self.servers = [] # actual list from IRC
        self.rtime = 0

        self.is_connected = True
        self.poll_interval = 1

        #json
        self.message_id = 0
        self.responses = Queue.Queue()

    def poke(self):
        # push a fake response so that the getting thread exits its loop
        self.responses.put(None)

    def queue_json_response(self, c):
        #print repr(c)
        msg_id = c.get('id')
        result = c.get('result')
        error = c.get('error')
        params = c.get('params',[])
        method = c.get('method',None)
        if not method:
            return
        
        if error:
            print "received error:", c, method, params
        else:
            self.responses.put({'method':method, 'params':params, 'result':result})


    def subscribe(self, addresses):
        messages = []
        for addr in addresses:
            messages.append(('blockchain.address.subscribe', [addr]))
        self.send(messages)


    def get_servers(self, wallet):
        # loop over default servers
        # requesting servers could be an independent process
        addresses = wallet.all_addresses()
        version = wallet.electrum_version

        for server in DEFAULT_SERVERS:
            print "connecting to", server
            try:
                self.host = server
                self.start_session(addresses, version)
                wallet.host = self.host
                break
            except socket.timeout:
                continue
            except socket.error:
                continue
            except:
                traceback.print_exc(file=sys.stdout)


    def start_session(self, addresses, version):
        #print "Starting new session: %s:%d"%(self.host,self.port)
        self.send([('server.version', [version]), ('server.banner',[]), ('blockchain.numblocks.subscribe',[]), ('server.peers.subscribe',[])])
        self.subscribe(addresses)


class PollingInterface(Interface):
    """ non-persistent connection. synchronous calls"""

    def __init__(self, host, port):
        Interface.__init__(self, host, port)
        self.session_id = None

    def get_history(self, address):
        self.send([('blockchain.address.get_history', [address] )])

    def poll(self):
        pass
        #if is_new or wallet.remote_url:
        #    self.was_updated = True
        #    is_new = wallet.synchronize()
        #    wallet.update_tx_history()
        #    wallet.save()
        #    return is_new
        #else:
        #    return False

    def run(self):
        self.is_connected = True
        while self.is_connected:
            try:
                if self.session_id:
                    self.poll()
                time.sleep(self.poll_interval)
            except socket.gaierror:
                break
            except socket.error:
                break
            except:
                traceback.print_exc(file=sys.stdout)
                break
            
        self.is_connected = False
        self.poke()

                




class NativeInterface(PollingInterface):

    def start_session(self, addresses, version):
        self.send([('session.new', [ version, addresses ])] )
        self.send([('server.peers.subscribe',[])])

    def poll(self):
        self.send([('session.poll', [])])

    def send(self, messages):
        import time
        cmds = {'session.new':'new_session',
                'server.peers.subscribe':'peers',
                'session.poll':'poll',
                'blockchain.transaction.broadcast':'tx',
                'blockchain.address.get_history':'h',
                'blockchain.address.subscribe':'address.subscribe'
                }

        for m in messages:
            method, params = m
            cmd = cmds[method]

            if cmd == 'poll':
                params = self.session_id

            if cmd == 'address.subscribe':
                params = [ self.session_id ] +  params

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
            s.connect(( self.host, self.port) )
            s.send( request )
            out = ''
            while 1:
                msg = s.recv(1024)
                if msg: out += msg
                else: break
            s.close()
            self.rtime = time.time() - t1
            self.is_connected = True

            if cmd == 'h':
                out = old_to_new(out)

            if cmd in ['peers','h','poll']:
                out = ast.literal_eval( out )

            if out == '': 
                out = None

            if cmd == 'new_session':
                self.session_id, msg = ast.literal_eval( out )
                self.responses.put({'method':'server.banner', 'params':[], 'result':msg})
            else:
                self.responses.put({'method':method, 'params':params, 'result':out})




class HttpInterface(PollingInterface):

    def poll(self):
        self.send([])

    def send(self, messages):
        import urllib2, json, time, cookielib

        cj = cookielib.CookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        urllib2.install_opener(opener)

        t1 = time.time()

        data = []
        for m in messages:
            method, params = m
            if type(params) != type([]): params = [params]
            data.append( { 'method':method, 'id':self.message_id, 'params':params } )
            self.message_id += 1

        if data:
            data_json = json.dumps(data)
        else:
            # poll with GET
            data_json = None 

        host = 'http://%s:%d'%( self.host, self.port )
        headers = {'content-type': 'application/json'}
        if self.session_id:
            headers['cookie'] = 'SESSION=%s'%self.session_id

        req = urllib2.Request(host, data_json, headers)
        response_stream = urllib2.urlopen(req)

        for index, cookie in enumerate(cj):
            if cookie.name=='SESSION':
                self.session_id = cookie.value

        response = response_stream.read()
        if response: 
            response = json.loads( response )
            if type(response) is not type([]):
                self.queue_json_response(response)
            else:
                for item in response:
                    self.queue_json_response(item)

        if response: 
            self.poll_interval = 1
        else:
            if self.poll_interval < 15: 
                self.poll_interval += 1
        #print self.poll_interval, response

        self.rtime = time.time() - t1
        self.is_connected = True




class AsynchronousInterface(Interface):
    """json-rpc over persistent TCP connection, asynchronous"""

    def __init__(self, host, port):
        Interface.__init__(self, host, port)
        self.s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.s.settimeout(5)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            self.s.connect(( self.host, self.port))
            self.is_connected = True
        except:
            self.is_connected = False
            print "not connected"

    def run(self):
        try:
            out = ''
            while self.is_connected:
                try: msg = self.s.recv(1024)
                except socket.timeout: 
                    continue
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
                    self.queue_json_response(c)

        except:
            traceback.print_exc(file=sys.stdout)

        self.is_connected = False
        self.poke()

    def send(self, messages):
        out = ''
        for m in messages:
            method, params = m 
            request = json.dumps( { 'id':self.message_id, 'method':method, 'params':params } )
            self.message_id += 1
            out += request + '\n'
        self.s.send( out )

    def get_history(self, addr):
        self.send([('blockchain.address.get_history', [addr])])





class WalletSynchronizer(threading.Thread):

    def __init__(self, wallet, loop=False):
        threading.Thread.__init__(self)
        self.daemon = True
        self.wallet = wallet
        self.loop = loop
        self.start_interface()


    def handle_response(self, r):
        if r is None:
            return

        method = r['method']
        params = r['params']
        result = r['result']

        if method == 'server.banner':
            self.wallet.banner = result
            self.wallet.was_updated = True

        elif method == 'session.poll':
            # native poll
            blocks, changed_addresses = result 
            if blocks == -1: raise BaseException("session not found")
            self.wallet.blocks = int(blocks)
            if changed_addresses:
                self.wallet.was_updated = True
                for addr, status in changed_addresses.items():
                    self.wallet.receive_status_callback(addr, status)

        elif method == 'server.peers.subscribe':
            servers = []
            for item in result:
                s = []
                host = item[1]
                if len(item)>2:
                    for v in item[2]:
                        if re.match("[thn]\d+",v):
                            s.append(host+":"+v[1:]+":"+v[0])
                    #if not s:
                    #    s.append(host+":50000:n")
                #else:
                #    s.append(host+":50000:n")
                servers = servers + s
            self.interface.servers = servers

        elif method == 'blockchain.address.subscribe':
            addr = params[-1]
            self.wallet.receive_status_callback(addr, result)
                            
        elif method == 'blockchain.address.get_history':
            addr = params[0]
            self.wallet.receive_history_callback(addr, result)
            self.wallet.was_updated = True

        elif method == 'blockchain.transaction.broadcast':
            self.wallet.tx_result = result
            self.wallet.tx_event.set()

        elif method == 'blockchain.numblocks.subscribe':
            self.wallet.blocks = result

        elif method == 'server.version':
            pass

        else:
            print "unknown message:", method, params, result


    def start_interface(self):
        try:
            host, port, protocol = self.wallet.server.split(':')
            port = int(port)
        except:
            self.wallet.pick_random_server()
            host, port, protocol = self.wallet.server.split(':')
            port = int(port)

        #print protocol, host, port
        if protocol == 'n':
            InterfaceClass = NativeInterface
        elif protocol == 't':
            InterfaceClass = AsynchronousInterface
        elif protocol == 'h':
            InterfaceClass = HttpInterface
        else:
            print "unknown protocol"
            InterfaceClass = NativeInterface

        self.interface = InterfaceClass(host, port)
        self.wallet.interface = self.interface

        with self.wallet.lock:
            self.wallet.addresses_waiting_for_status = []
            self.wallet.addresses_waiting_for_history = []
            addresses = self.wallet.all_addresses()
            version = self.wallet.electrum_version
            for addr in addresses:
                self.wallet.addresses_waiting_for_status.append(addr)

        try:
            self.interface.start()
            self.interface.start_session(addresses,version)
        except:
            self.interface.is_connected = False


    def run(self):
        import socket, time
        while True:
            try:
                while self.interface.is_connected:
                    new_addresses = self.wallet.synchronize()
                    if new_addresses:
                        self.interface.subscribe(new_addresses)
                        for addr in new_addresses:
                            with self.wallet.lock:
                                self.wallet.addresses_waiting_for_status.append(addr)

                    if self.wallet.is_up_to_date():
                        self.wallet.up_to_date = True
                        self.wallet.up_to_date_event.set()
                    else:
                        self.wallet.up_to_date = False

                    response = self.interface.responses.get(True,100000000000) # workaround so that it can be keyboard interrupted
                    self.handle_response(response)
            except socket.error:
                print "socket error"
                wallet.interface.is_connected = False

            if self.loop:
                time.sleep(5)
                self.start_interface()
                continue
            else:
                break



