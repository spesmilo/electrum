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

import time, thread, sys, socket

# see http://code.google.com/p/jsonrpclib/
import jsonrpclib
from wallet import Wallet

"""
Simple wallet daemon for webservers.
- generates new addresses on request
- private keys are not needed in order to generate new addresses. A neutralized wallet can be used (seed removed)
- no gap limit: use 'getnum' to know how many addresses have been created.

todo:
- return the max gap
- add expiration date

"""


host = 'ecdsa.org'
port = 8444
wallet_path = 'wallet_path'
username = 'foo'
password = 'bar'
wallet = Wallet()
stopping = False



from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCRequestHandler
import SimpleXMLRPCServer

class authHandler(SimpleJSONRPCRequestHandler):
    def parse_request(self):
        if SimpleXMLRPCServer.SimpleXMLRPCRequestHandler.parse_request(self):
            if self.authenticate(self.headers):
                return True
            else:
                self.send_error(401, 'Authentication failed')
            return False

    def authenticate(self, headers):
        from base64 import b64decode
        basic, _, encoded = headers.get('Authorization').partition(' ')
        assert basic == 'Basic', 'Only basic authentication supported'
        x_username, _, x_password = b64decode(encoded).partition(':')
        return username == x_username and password == x_password


def do_stop():
    global stopping
    stopping = True

def get_new_address():
    a = wallet.create_new_address(False)
    wallet.save()
    return a

def get_num():
    return len(wallet.addresses)

def get_mpk():
    return wallet.master_public_key.encode('hex')



if __name__ == '__main__':

    if len(sys.argv)>1:
        import jsonrpclib
        server = jsonrpclib.Server('http://%s:%s@%s:%d'%(username, password, host, port))
        cmd = sys.argv[1]

        try:
            if cmd == 'getnum':
                out = server.getnum()
            elif cmd == 'getkey':
                out = server.getkey()
            elif cmd == 'getnewaddress':
                out = server.getnewaddress()
            elif cmd == 'stop':
                out = server.stop()
        except socket.error:
            print "server not running"
            sys.exit(1)
        print out
        sys.exit(0)

    else:

        wallet.set_path(wallet_path)
        wallet.read()

        def server_thread():
            from SocketServer import ThreadingMixIn
            from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
            server = SimpleJSONRPCServer(( host, port), requestHandler=authHandler)
            server.register_function(get_new_address, 'getnewaddress')
            server.register_function(get_num, 'getnum')
            server.register_function(get_mpk, 'getkey')
            server.register_function(do_stop, 'stop')
            server.serve_forever()

        thread.start_new_thread(server_thread, ())
        while not stopping: time.sleep(0.1)




