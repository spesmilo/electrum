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
import thread, threading, traceback, sys, time, json, Queue

DEFAULT_TIMEOUT = 5
DEFAULT_SERVERS = ['electrum.bitcoins.sk','ecdsa.org','electrum.novit.ro']  # list of default servers


class Interface:
    def __init__(self, host, port):
        self.host = host
        self.port = port

        self.servers = [] # actual list from IRC
        self.rtime = 0

        self.is_connected = True

        #only asynchrnous
        self.addresses_waiting_for_status = []
        self.addresses_waiting_for_history = []

        #json
        self.message_id = 0
        self.messages = {}
        self.responses = Queue.Queue()


    def is_up_to_date(self):
        return self.responses.empty() and not ( self.addresses_waiting_for_status or self.addresses_waiting_for_history )



    def queue_json_response(self, c):
        #print repr(c)
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
            self.update_waiting_lists(method, params)
            self.responses.put({'method':method, 'params':params, 'result':result})


    def update_waiting_lists(self, method, params):
        if method == 'address.subscribe':
            addr = params[-1]
            if addr in self.addresses_waiting_for_status:
                self.addresses_waiting_for_status.remove(addr)
        elif method == 'address.get_history':
            addr = params[0]
            if addr in self.addresses_waiting_for_history:
                self.addresses_waiting_for_history.remove(addr)


    def subscribe(self, addresses):
        messages = []
        for addr in addresses:
            messages.append(('address.subscribe', [addr]))
            self.addresses_waiting_for_status.append(addr)
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





class PollingInterface(Interface):
    """ non-persistent connection. synchronous calls"""

    def start_session(self, addresses, version):
        self.send([('session.new', [ version, addresses ])] )
        self.send([('server.peers',[])])
        thread.start_new_thread(self.poll_thread, (5,))

    def get_history(self, address):
        self.send([('address.get_history', [address] )])

    def poll(self):
        self.send([('session.poll', [])])

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
                self.poll()
                time.sleep(poll_interval)
            except socket.gaierror:
                break
            except socket.error:
                break
            except:
                traceback.print_exc(file=sys.stdout)
                break
            
        self.is_connected = False
        self.responses.put(None)

                




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

            if cmd == 'address.subscribe':
                params = [ self.session_id] +  params

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

            if cmd in[ 'peers','h','poll']:
                out = ast.literal_eval( out )

            if out=='': out=None #fixme

            if cmd == 'new_session':
                self.session_id, self.message = ast.literal_eval( out )
            else:
                self.update_waiting_lists(method, params)
                self.responses.put({'method':method, 'params':params, 'result':out})





class HttpInterface(PollingInterface):

    def start_session(self, addresses, version):
        self.session_id = None
        self.send([('client.version', [version]), ('server.banner',[]), ('numblocks.subscribe',[]), ('server.peers',[])])
        self.subscribe(addresses)
        thread.start_new_thread(self.poll_thread, (15,))

    def poll(self):
        self.send( [] )

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
            self.messages[self.message_id] = (method, params)
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

        self.rtime = time.time() - t1
        self.is_connected = True




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
                    self.queue_json_response(c)

        except:
            traceback.print_exc(file=sys.stdout)

        self.is_connected = False
        self.responses.put(None)

    def send(self, messages):
        out = ''
        for m in messages:
            method, params = m 
            request = json.dumps( { 'id':self.message_id, 'method':method, 'params':params } )
            self.messages[self.message_id] = (method, params)
            self.message_id += 1
            out += request + '\n'
        self.s.send( out )

    def get_history(self, addr):
        self.send([('address.get_history', [addr])])
        self.addresses_waiting_for_history.append(addr)

    def start_session(self, addresses, version):
        self.s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.s.settimeout(5)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        self.s.connect(( self.host, self.port))
        thread.start_new_thread(self.listen_thread, ())
        self.send([('client.version', [version]), ('server.banner',[]), ('numblocks.subscribe',[]), ('server.peers',[])])
        self.subscribe(addresses)





    

def loop_interfaces_thread(wallet):
    while True:
        try:
            wallet.start_interface()
            wallet.run()
        except socket.error:
            print "socket error"
            time.sleep(5)
        except:
            traceback.print_exc(file=sys.stdout)
            time.sleep(5)
            continue

