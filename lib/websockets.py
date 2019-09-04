#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import queue
import threading, os, json
from collections import defaultdict
try:
    from SimpleWebSocketServer import WebSocket, SimpleSSLWebSocketServer
except ImportError:
    import sys
    sys.exit("install SimpleWebSocketServer")

from . import util
from .address import Address

request_queue = queue.Queue()

class ElectrumWebSocket(WebSocket, util.PrintError):

    def handleMessage(self):
        assert self.data[:3] == 'id:'
        self.print_error("message received", self.data)
        request_id = self.data[3:]
        request_queue.put((self, request_id))

    def handleConnected(self):
        self.print_error("connected", self.address)

    def handleClose(self):
        self.print_error("closed", self.address)



class WsClientThread(util.DaemonThread):

    def __init__(self, config, network):
        super().__init__()
        self.network = network
        self.config = config
        self.response_queue = queue.Queue()
        self.subscriptions = defaultdict(list)
        self.sh2addr = dict()

    def make_request(self, request_id):
        # read json file
        rdir = self.config.get('requests_dir')
        n = os.path.join(rdir, 'req', request_id[0], request_id[1], request_id, request_id + '.json')
        with open(n, encoding='utf-8') as f:
            s = f.read()
        d = json.loads(s)
        addr = d.get('address')
        amount = d.get('amount')
        return addr, amount

    def reading_thread(self):
        while self.is_running():
            try:
                ws, request_id = request_queue.get()
            except queue.Empty:
                continue
            try:
                addr, amount = self.make_request(request_id)
            except:
                continue
            try:
                addr = Address.from_string(addr)
            except Exception as e:
                self.print_error("Error parsing address", addr, repr(e))
                continue
            l = self.subscriptions[addr]  # defaultdict will create empty list if not already there.
            l.append((ws, amount))
            h = addr.to_scripthash_hex()
            self.sh2addr[h] = addr  # remember this scripthash_hex -> addr mapping since run() below needs it.
            self.network.send([('blockchain.scripthash.subscribe', [h])], self.response_queue.put)


    def run(self):
        threading.Thread(target=self.reading_thread).start()
        while self.is_running():
            try:
                r = self.response_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.print_error('response', r)
            method = r.get('method')
            params = r.get('params')
            result = r.get('result')
            if result is None:
                continue
            if method == 'blockchain.scripthash.subscribe':
                self.network.send([('blockchain.scripthash.get_balance', params)], self.response_queue.put)
            elif method == 'blockchain.scripthash.get_balance':
                h = params[0]
                addr = self.sh2addr.get(h)
                if addr is None:
                    self.print_error("can't find address for scripthash:", h)
                    continue
                l = self.subscriptions.get(addr, [])
                for ws, amount in l:
                    if not ws.closed:
                        if sum(result.values()) >= amount:
                            ws.sendMessage('paid')



class WebSocketServer(threading.Thread):

    def __init__(self, config, ns):
        threading.Thread.__init__(self)
        self.config = config
        self.net_server = ns
        self.daemon = True

    def run(self):
        t = WsClientThread(self.config, self.net_server)
        t.start()

        host = self.config.get('websocket_server')
        port = self.config.get('websocket_port', 9999)
        certfile = self.config.get('ssl_chain')
        keyfile = self.config.get('ssl_privkey')
        self.server = SimpleSSLWebSocketServer(host, port, ElectrumWebSocket, certfile, keyfile)
        self.server.serveforever()
