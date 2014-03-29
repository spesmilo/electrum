#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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

import socket
import time
import sys
import os
import threading
import traceback
import json
import Queue
from network import Network
from util import print_msg
from simple_config import SimpleConfig


class NetworkProxy(threading.Thread):
    # connects to daemon
    # sends requests, runs callbacks

    def __init__(self, config = {}):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = SimpleConfig(config) if type(config) == type({}) else config
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.daemon_port = config.get('daemon_port', 8000)
        self.message_id = 0
        self.unanswered_requests = {}
        self.subscriptions = {}
        self.debug = False
        self.lock = threading.Lock()


    def start(self, start_daemon=False):
        daemon_started = False
        while True:
            try:
                self.socket.connect(('', self.daemon_port))
                threading.Thread.start(self)
                return True

            except socket.error:
                if not start_daemon:
                    return False

                elif not daemon_started:
                    print "Starting daemon [%s]"%self.config.get('server')
                    daemon_started = True
                    pid = os.fork()
                    if (pid == 0): # The first child.
                        os.chdir("/")
                        os.setsid()
                        os.umask(0)
                        pid2 = os.fork()
                        if (pid2 == 0):  # Second child
                            server = NetworkServer(self.config)
                            try:
                                server.main_loop()
                            except KeyboardInterrupt:
                                print "Ctrl C - Stopping server"
                            sys.exit(1)
                        sys.exit(0)
                else:
                    time.sleep(0.1)



    def parse_json(self, message):
        s = message.find('\n')
        if s==-1: 
            return None, message
        j = json.loads( message[0:s] )
        return j, message[s+1:]


    def run(self):
        # read responses and trigger callbacks
        message = ''
        while True:
            try:
                data = self.socket.recv(1024)
            except:
                data = ''
            if not data:
                break

            message += data
            while True:
                response, message = self.parse_json(message)
                if response is not None: 
                    self.process(response)
                else:
                    break

        print "NetworkProxy: exiting"


    def process(self, response):
        # runs callbacks
        if self.debug: print "<--", response

        msg_id = response.get('id')
        with self.lock: 
            method, params, callback = self.unanswered_requests.pop(msg_id)

        result = response.get('result')
        callback(None, {'method':method, 'params':params, 'result':result, 'id':msg_id})


    def subscribe(self, messages, callback):
        # detect if it is a subscription
        with self.lock:
            if self.subscriptions.get(callback) is None: 
                self.subscriptions[callback] = []
            for message in messages:
                if message not in self.subscriptions[callback]:
                    self.subscriptions[callback].append(message)

        self.do_send( messages, callback )


    def do_send(self, messages, callback):
        """return the ids of the requests that we sent"""
        out = ''
        ids = []
        for m in messages:
            method, params = m 
            request = json.dumps( { 'id':self.message_id, 'method':method, 'params':params } )
            self.unanswered_requests[self.message_id] = method, params, callback
            ids.append(self.message_id)
            if self.debug: print "-->", request
            self.message_id += 1
            out += request + '\n'
        while out:
            sent = self.socket.send( out )
            out = out[sent:]
        return ids


    def synchronous_get(self, requests, timeout=100000000):
        queue = Queue.Queue()
        ids = self.do_send(requests, lambda i,x: queue.put(x))
        id2 = ids[:]
        res = {}
        while ids:
            r = queue.get(True, timeout)
            _id = r.get('id')
            if _id in ids:
                ids.remove(_id)
                res[_id] = r.get('result')
        out = []
        for _id in id2:
            out.append(res[_id])
        return out


    def get_servers(self):
        return self.synchronous_get([('network.get_servers',[])])[0]

    def get_header(self, height):
        return self.synchronous_get([('network.get_header',[height])])[0]

    def get_local_height(self):
        return self.synchronous_get([('network.get_local_height',[])])[0]

    def is_connected(self):
        return self.synchronous_get([('network.is_connected',[])])[0]

    def is_up_to_date(self):
        return self.synchronous_get([('network.is_up_to_date',[])])[0]

    def main_server(self):
        return self.synchronous_get([('network.main_server',[])])[0]

    def stop(self):
        return self.synchronous_get([('daemon.shutdown',[])])[0]


    def trigger_callback(self, cb):
        pass






class ClientThread(threading.Thread):
    # read messages from client (socket), and sends them to Network
    # responses are sent back on the same socket

    def __init__(self, server, network, socket):
        threading.Thread.__init__(self)
        self.server = server
        self.daemon = True
        self.s = socket
        self.s.settimeout(0.1)
        self.network = network
        self.queue = Queue.Queue()
        self.unanswered_requests = {}
        self.debug = False


    def run(self):
        message = ''
        while True:
            self.send_responses()
            try:
                data = self.s.recv(1024)
            except socket.timeout:
                continue

            if not data:
                break
            message += data

            while True:
                cmd, message = self.parse_json(message)
                if not cmd:
                    break
                self.process(cmd)

        #print "client thread terminating"


    def parse_json(self, message):
        n = message.find('\n')
        if n==-1: 
            return None, message
        j = json.loads( message[0:n] )
        return j, message[n+1:]


    def process(self, request):
        if self.debug: print "<--", request
        method = request['method']
        params = request['params']
        _id = request['id']

        if method.startswith('network.'):
            out = {'id':_id}
            try:
                f = getattr(self.network, method[8:])
            except AttributeError:
                out['error'] = "unknown method"
            try:
                out['result'] = f(*params)
            except BaseException as e:
                out['error'] =str(e)
            self.queue.put(out) 
            return

        if method == 'daemon.shutdown':
            self.server.running = False
            self.queue.put({'id':_id, 'result':True})
            return

        def cb(i,r):
            _id = r.get('id')
            if _id is not None:
                my_id = self.unanswered_requests.pop(_id)
                r['id'] = my_id
            self.queue.put(r)

        new_id = self.network.interface.send([(method, params)], cb) [0]
        self.unanswered_requests[new_id] = _id


    def send_responses(self):
        while True:
            try:
                r = self.queue.get_nowait()
            except Queue.Empty:
                break
            out = json.dumps(r) + '\n'
            while out:
                n = self.s.send(out)
                out = out[n:]
            if self.debug: print "-->", r
        



class NetworkServer:

    def __init__(self, config):
        network = Network(config)
        if not network.start(wait=True):
            print_msg("Not connected, aborting.")
            sys.exit(1)
        self.network = network
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.daemon_port = config.get('daemon_port', 8000)
        self.server.bind(('', self.daemon_port))
        self.server.listen(5)
        self.server.settimeout(1)
        self.running = False
        self.timeout = config.get('daemon_timeout', 60)


    def main_loop(self):
        self.running = True
        t = time.time()
        while self.running:
            try:
                connection, address = self.server.accept()
            except socket.timeout:
                if time.time() - t > self.timeout:
                    break
                continue
            t = time.time()
            client = ClientThread(self, self.network, connection)
            client.start()



if __name__ == '__main__':
    import simple_config
    config = simple_config.SimpleConfig({'verbose':True, 'server':'ecdsa.net:50002:s'})
    server = NetworkServer(config)
    try:
        server.main_loop()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server"
        sys.exit(1)
