#!/usr/bin/env python
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

import threading, Queue, os, json, time
from collections import defaultdict
try:
    from SimpleWebSocketServer import WebSocket, SimpleSSLWebSocketServer
except ImportError:
    import sys
    sys.exit("install SimpleWebSocketServer")

import util

request_queue = Queue.Queue()

class ElectrumWebSocket(WebSocket):

    def handleMessage(self):
        assert self.data[0:3] == 'id:'
        util.print_error("message received", self.data)
        request_id = self.data[3:]
        request_queue.put((self, request_id))

    def handleConnected(self):
        util.print_error("connected", self.address)

    def handleClose(self):
        util.print_error("closed", self.address)



class WsClientThread(util.DaemonThread):

    def __init__(self, config, network):
        util.DaemonThread.__init__(self)
        self.network = network
        self.config = config
        self.response_queue = Queue.Queue()
        self.subscriptions = defaultdict(list)

    def make_request(self, request_id):
        # read json file
        rdir = self.config.get('requests_dir')
        n = os.path.join(rdir, 'req', request_id[0], request_id[1], request_id, request_id + '.json')
        with open(n) as f:
            s = f.read()
        d = json.loads(s)
        addr = d.get('address')
        amount = d.get('amount')
        return addr, amount

    def reading_thread(self):
        while self.is_running():
            try:
                ws, request_id = request_queue.get()
            except Queue.Empty:
                continue
            try:
                addr, amount = self.make_request(request_id)
            except:
                continue
            l = self.subscriptions.get(addr, [])
            l.append((ws, amount))
            self.subscriptions[addr] = l
            self.network.send([('blockchain.address.subscribe', [addr])], self.response_queue.put)


    def run(self):
        threading.Thread(target=self.reading_thread).start()
        while self.is_running():
            try:
                r = self.response_queue.get(timeout=0.1)
            except Queue.Empty:
                continue
            util.print_error('response', r)
            method = r.get('method')
            params = r.get('params')
            result = r.get('result')
            if result is None:
                continue    
            if method == 'blockchain.address.subscribe':
                self.network.send([('blockchain.address.get_balance', params)], self.response_queue.put)
            elif method == 'blockchain.address.get_balance':
                addr = params[0]
                l = self.subscriptions.get(addr, [])
                for ws, amount in l:
                    if not ws.closed:
                        if sum(result.values()) >=amount:
                            ws.sendMessage(unicode('paid'))



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


