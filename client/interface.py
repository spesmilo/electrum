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

class Interface:
    def __init__(self):
        self.servers = ['ecdsa.org','electrum.novit.ro']  # list of default servers
        self.host = random.choice( self.servers )         # random choice when the wallet is created
        self.rtime = 0
        self.blocks = 0 
        self.message = ''
        self.set_port(50000)
        self.is_connected = False

    def set_port(self, port_number):
        self.port = port_number
        if self.use_http():
            self.handler = self.http_json_handler
        else:
            self.handler = self.native_handler

    def use_http(self): 
        return self.port in [80,81,8080,8081]

    def native_handler(self, method, params = ''):
        import time
        cmds = {'session.new':'new_session',
                'peers':'peers',
                'session.poll':'poll',
                'session.update':'update_session',
                'blockchain.transaction.broadcast':'tx',
                'blockchain.address.get_history':'h'
                }
        cmd = cmds[method]
        if type(params) != type(''): params = repr( params )
        t1 = time.time()
        request = repr ( (cmd, params) ) + "#"
        s = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
        s.connect(( self.host, self.port))
        s.send( request )
        out = ''
        while 1:
            msg = s.recv(1024)
            if msg: out += msg
            else: break
        s.close()
        self.rtime = time.time() - t1
        self.is_connected = True
        if cmd in[ 'peers','h']:
            out = ast.literal_eval( out )
        return out

    def http_json_handler(self, method, params = []):
        import urllib2, json, time
        if type(params) != type([]): params = [ params ]
        t1 = time.time()
        data = { 'method':method, 'id':'jsonrpc', 'params':params }
        data_json = json.dumps(data)
        host = 'http://%s:%d'%(self.host,self.port)
        req = urllib2.Request(host, data_json, {'content-type': 'application/json'})
        response_stream = urllib2.urlopen(req)
        response = json.loads( response_stream.read() )
        out = response.get('result')
        if not out:
            print response
        self.rtime = time.time() - t1
        self.is_connected = True
        return out

    def send_tx(self, data):
        out = self.handler('blockchain.transaction.broadcast', data )
        return out

    def retrieve_history(self, address):
        out = self.handler('blockchain.address.get_history', address )
        return out

    def poll(self):
        out = self.handler('session.poll', self.session_id )
        blocks, changed_addr = ast.literal_eval( out )
        if blocks == -1: raise BaseException("session not found")
        self.blocks = int(blocks)
        return changed_addr

    def new_session(self, addresses, version):
        out = self.handler('session.new', [ version, addresses ] )
        self.session_id, self.message = ast.literal_eval( out )

    def update_session(self, addresses):
        out = self.handler('session.update', [ self.session_id, addresses ] )
        return out
    
    def get_servers(self):
        out = self.handler('peers')
        self.servers = map( lambda x:x[1], out )
