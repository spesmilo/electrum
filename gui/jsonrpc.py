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
jsonrpc interface for webservers.
may be called from your php script.
"""

import socket, os
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer, SimpleJSONRPCRequestHandler

from electrum_grs.wallet import WalletStorage, Wallet
from electrum_grs.commands import known_commands, Commands


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
        storage = WalletStorage(self.config.get_wallet_path())
        if not storage.file_exists:
            raise BaseException("Wallet not found")
        self.wallet = Wallet(storage)
        self.cmd_runner = Commands(self.config, self.wallet, self.network)
        host = config.get('rpchost', 'localhost')
        port = config.get('rpcport', 7777)
        self.server = SimpleJSONRPCServer((host, port), requestHandler=RequestHandler)
        self.server.socket.settimeout(1)
        for cmdname in known_commands:
            self.server.register_function(getattr(self.cmd_runner, cmdname), cmdname)

    def main(self, url):
        self.wallet.start_threads(self.network)
        while True:
            try:
                self.server.handle_request()
            except socket.timeout:
                continue
            except:
                break
        self.wallet.stop_threads()
