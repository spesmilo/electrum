#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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


"""
jsonrpc interface for webservers
"""

import socket, os
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer, SimpleJSONRPCRequestHandler

from electrum.wallet import WalletStorage, Wallet
from electrum.commands import known_commands, Commands


class RequestHandler(SimpleJSONRPCRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def end_headers(self):
        self.send_header("Access-Control-Allow-Headers", 
                         "Origin, X-Requested-With, Content-Type, Accept")
        self.send_header("Access-Control-Allow-Origin", "*")
        SimpleJSONRPCRequestHandler.end_headers(self)



class ElectrumGui:

    def __init__(self, config, network):
        self.network = network
        self.config = config
        host = config.get('rpchost', 'localhost')
        port = config.get('rpcport', 7777)
        self.server = SimpleJSONRPCServer((host, port), requestHandler=RequestHandler)
        self.server.socket.settimeout(1)
        self.server.register_function(self.do_getrequest, 'getrequest')

    def do_getrequest(self, key):
        # fixme: we load and sync the wallet on each request
        # the wallet should be synchronized in the daemon instead
        storage = WalletStorage(self.config.get_wallet_path())
        if not storage.file_exists:
            raise BaseException("Wallet not found")
        wallet = Wallet(storage)
        wallet.start_threads(self.network)
        cmd_runner = Commands(self.config, wallet, self.network)
        result = cmd_runner.getrequest(key)
        wallet.stop_threads()
        return result

    def main(self, url):
        while True:
            try:
                self.server.handle_request()
            except socket.timeout:
                continue
            except:
                break



"""
* replace merchant script:
    * client process that connects to the daemon, receives notifications and pushes callbacks
    * it requires a new gui type

     electrum -g jsonrpc &
or:  electrum daemon loadwallet


use the daemon:
  pros: single process instead of 2
  jsonrpc is not really a gui

  the wallet sould be synced in the daemon (so that we can add requests from the gui, list them, etc)

  short-term solution:
    * serve jsonrpc requests with the daemon
    * load wallet on each command
    * open some rpc commands to public

 * other solution:
    * use a database
    * 'addrequest' writes request to database

the daemon does not need to load and sync the wallet

 * daemon loadwallet
 * 


 Private methods: 
    wallet commands

 Public methods:
  - getrequest(key)
  - paymentack(): 
     is sent as the body of the POST
  


"""
