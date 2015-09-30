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

import threading, Queue, os, json, time
from collections import defaultdict
try:
    from SimpleWebSocketServer import WebSocket, SimpleSSLWebSocketServer
except ImportError:
    print "install SimpleWebSocketServer"
    sys.exit()

import util

request_queue = Queue.Queue()

class ElectrumWebSocket(WebSocket):

    def handleMessage(self):
        assert self.data[0:3] == 'id:'
        print "message received", self.data
        request_id = self.data[3:]
        request_queue.put((self, request_id))

    def handleConnected(self):
        util.print_error("connected", self.address)

    def handleClose(self):
        util.print_error("closed", self.address)



class WsClientThread(util.DaemonThread):

    def __init__(self, config, server):
        util.DaemonThread.__init__(self)
        self.server = server
        self.config = config
        self.response_queue = Queue.Queue()
        self.server.add_client(self)
        self.subscriptions = defaultdict(list)
        self.sub_ws = defaultdict(list)
        self.counter = 0

    def make_request(self, request_id):
        # read json file
        rdir = self.config.get('requests_dir')
        n = os.path.join(rdir, request_id + '.json')
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
            method = 'blockchain.address.subscribe'
            params = [addr]
            request = {'method':method, 'params':params, 'id':self.counter}
            self.subscriptions[method].append(params)
            self.sub_ws[self.counter] = ws, amount, request
            self.counter += 1
            self.server.send_request(self, request)

    def run(self):
        threading.Thread(target=self.reading_thread).start()
        while self.is_running():
            try:
                r = self.response_queue.get(timeout=0.1)
            except Queue.Empty:
                continue
            id = r.get('id')
            if id is None: 
                method = r.get('method')
                params = r.get('params')
            else:
                ws, amount, rr = self.sub_ws[id]
                method = rr.get('method')
                params = rr.get('params')

            result = r.get('result')

            if method == 'blockchain.address.subscribe':
                util.print_error('response', r)
                if result is not None:
                    request = {'method':'blockchain.address.get_balance', 'params':params, 'id':self.counter}
                    self.server.send_request(self, request)
                    self.sub_ws[self.counter] = ws, amount, request
                    self.counter += 1

            if r.get('method') == 'blockchain.address.get_balance':
                util.print_error('response', r)
                if not ws.closed:
                    if sum(result.values()) >=amount:
                        ws.sendMessage(unicode('paid'))

        self.server.remove_client(self)


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


