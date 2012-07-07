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

from version import ELECTRUM_VERSION
from util import print_error

DEFAULT_TIMEOUT = 5
DEFAULT_SERVERS = [ 'ecdsa.org:50001:t', 
                    'electrum.novit.ro:50001:t', 
                    'uncle-enzo.info:50001:t', 
                    'electrum.bytesized-hosting.com:50000:t']  # list of default servers


def replace_keys(obj, old_key, new_key):
    if isinstance(obj, dict):
        if old_key in obj:
            obj[new_key] = obj[old_key]
            del obj[old_key]
        for elem in obj.itervalues():
            replace_keys(elem, old_key, new_key)
    elif isinstance(obj, list):
        for elem in obj:
            replace_keys(elem, old_key, new_key)

def old_to_new(d):
    replace_keys(d, 'blk_hash', 'block_hash')
    replace_keys(d, 'pos', 'index')
    replace_keys(d, 'nTime', 'timestamp')
    replace_keys(d, 'is_in', 'is_input')
    replace_keys(d, 'raw_scriptPubKey', 'raw_output_script')


class Interface(threading.Thread):
    def __init__(self, host, port, debug_server):
        threading.Thread.__init__(self)
        self.daemon = True
        self.host = host
        self.port = port

        self.servers = [] # actual list from IRC
        self.rtime = 0
        self.bytes_received = 0

        self.is_connected = True
        self.poll_interval = 1

        #json
        self.message_id = 0
        self.responses = Queue.Queue()
        self.unanswered_requests = {}

        self.debug_server = debug_server

    def init_socket(self):
        pass

    def poke(self):
        # push a fake response so that the getting thread exits its loop
        self.responses.put(None)

    def queue_json_response(self, c):

        if self.debug_server:
          print "<--",c

        msg_id = c.get('id')
        error = c.get('error')
        
        if error:
            print "received error:", c
            return

        if msg_id is not None:
            method, params = self.unanswered_requests.pop(msg_id)
            result = c.get('result')
        else:
            # notification
            method = c.get('method')
            params = c.get('params')

            if method == 'blockchain.numblocks.subscribe':
                result = params[0]
                params = []

            elif method == 'blockchain.address.subscribe':
                addr = params[0]
                result = params[1]
                params = [addr]

        self.responses.put({'method':method, 'params':params, 'result':result})



    def subscribe(self, addresses):
        messages = []
        for addr in addresses:
            messages.append(('blockchain.address.subscribe', [addr]))
        self.send(messages)




class PollingInterface(Interface):
    """ non-persistent connection. synchronous calls"""

    def __init__(self, host, port, debug_server):
        Interface.__init__(self, host, port, debug_server)
        self.session_id = None
        self.debug_server = debug_server

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

                







class HttpStratumInterface(PollingInterface):

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
            self.unanswered_requests[self.message_id] = method, params
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
        self.bytes_received += len(response)
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




class TcpStratumInterface(Interface):
    """json-rpc over persistent TCP connection, asynchronous"""

    def __init__(self, host, port, debug_server):
        Interface.__init__(self, host, port, debug_server)
        self.debug_server = debug_server

    def init_socket(self):
        self.s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.s.settimeout(60)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            self.s.connect(( self.host, self.port))
            self.is_connected = True
            self.send([('server.version', [ELECTRUM_VERSION])])
            print "Connected to %s:%d"%(self.host,self.port)
        except:
            self.is_connected = False
            print_error("Not connected")

    def run(self):
        try:
            out = ''
            while self.is_connected:
                try: msg = self.s.recv(1024)
                except socket.timeout:
                    # ping the server with server.version, as a real ping does not exist yet
                    self.send([('server.version', [ELECTRUM_VERSION])])
                    continue
                out += msg
                self.bytes_received += len(msg)
                if msg == '': 
                    self.is_connected = False
                    print "Disconnected."

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
        print "Poking"
        self.poke()

    def send(self, messages):
        out = ''
        for m in messages:
            method, params = m 
            request = json.dumps( { 'id':self.message_id, 'method':method, 'params':params } )
            self.unanswered_requests[self.message_id] = method, params

            if self.debug_server:
              print "-->",request

            self.message_id += 1
            out += request + '\n'

        while out:
            sent = self.s.send( out )
            out = out[sent:]

    def get_history(self, addr):
        self.send([('blockchain.address.get_history', [addr])])





class WalletSynchronizer(threading.Thread):

    def __init__(self, wallet, loop=False):
        threading.Thread.__init__(self)
        self.daemon = True
        self.wallet = wallet
        self.loop = loop
        self.init_interface()

    def init_interface(self):
        try:
            host, port, protocol = self.wallet.server.split(':')
            port = int(port)
        except:
            self.wallet.pick_random_server()
            host, port, protocol = self.wallet.server.split(':')
            port = int(port)

        #print protocol, host, port
        if protocol == 't':
            InterfaceClass = TcpStratumInterface
        elif protocol == 'h':
            InterfaceClass = HttpStratumInterface
        else:
            print_error("Error: Unknown protocol")
            InterfaceClass = TcpStratumInterface

        self.interface = InterfaceClass(host, port, self.wallet.debug_server)
        self.wallet.interface = self.interface


    def handle_response(self, r):
        if r is None:
            return

        method = r['method']
        params = r['params']
        result = r['result']

        if method == 'server.banner':
            self.wallet.banner = result
            self.wallet.was_updated = True

        elif method == 'server.peers.subscribe':
            servers = []
            for item in result:
                s = []
                host = item[1]
                ports = []
                version = None
                if len(item)>2:
                    for v in item[2]:
                        if re.match("[th]\d+",v):
                            ports.append((v[0],v[1:]))
                        if re.match("v(.?)+",v):
                            version = v[1:]
                if ports and version:
                    servers.append( (host, ports) )
            self.interface.servers = servers

        elif method == 'blockchain.address.subscribe':
            addr = params[0]
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
            self.wallet.was_updated = True

        elif method == 'server.version':
            pass

        else:
            print_error("Error: Unknown message:" + method + ", " + params + ", " + result)


    def start_interface(self):
        self.interface.init_socket()
        self.interface.start()
        if self.interface.is_connected:
            self.wallet.start_session(self.interface)



    def run(self):
        import socket, time
        self.start_interface()
        while True:
            while self.interface.is_connected:
                new_addresses = self.wallet.synchronize()
                if new_addresses:
                    self.interface.subscribe(new_addresses)

                if self.wallet.is_up_to_date():
                    if not self.wallet.up_to_date:
                        self.wallet.up_to_date = True
                        self.wallet.was_updated = True
                        self.wallet.up_to_date_event.set()
                else:
                    if self.wallet.up_to_date:
                        self.wallet.up_to_date = False
                        self.wallet.was_updated = True

                if self.wallet.was_updated:
                    self.wallet.trigger_callbacks()
                    self.wallet.was_updated = False

                response = self.interface.responses.get()
                self.handle_response(response)

            self.wallet.trigger_callbacks()
            if self.loop:
                time.sleep(5)
                self.init_interface()
                self.start_interface()
                continue
            else:
                break



