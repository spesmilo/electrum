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
from interface import Interface

"""
Simple wallet daemon for webservers.
- generates new addresses on request
- private keys are not needed in order to generate new addresses. A neutralized wallet can be used (seed removed)
- no gap limit: use 'getnum' to know how many addresses have been created.
"""


host = 'localhost'
port = 8444
password = 'my_password'
path = 'wallet_path'

interface = Interface()
wallet = Wallet(interface)
stopping = False


def do_stop(pw):
    if pw != password: return False
    global stopping
    stopping = True

def get_new_address(pw):
    if pw != password: return False
    a = wallet.create_new_address(False)
    wallet.save()
    return a

def get_num(pw):
    if pw != password: return False
    return len(wallet.addresses)



if __name__ == '__main__':

    if len(sys.argv)>1:
        import jsonrpclib
        server = jsonrpclib.Server('http://%s:%d'%(host,port))
        cmd = sys.argv[1]

        try:
            if cmd == 'getnum':
                out = server.getnum(password)
            elif cmd == 'getnewaddress':
                out = server.getnewaddress(password)
            elif cmd == 'stop':
                out = server.stop(password)
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
            server = SimpleJSONRPCServer(( host, port))
            server.register_function(get_new_address, 'getnewaddress')
            server.register_function(get_num, 'getnum')
            server.register_function(do_stop, 'stop')
            server.serve_forever()

        thread.start_new_thread(server_thread, ())
        while not stopping: time.sleep(0.1)




