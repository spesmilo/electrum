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
from util import print_error, print_stderr
from simple_config import SimpleConfig


"""
The Network object is not aware of clients/subscribers
It only does subscribe/unsubscribe to addresses
Which client has wich address is managed by the daemon
Network also reports status changes
"""

DAEMON_PORT=8001


def parse_json(message):
    n = message.find('\n')
    if n==-1: 
        return None, message
    try:
        j = json.loads( message[0:n] )
    except:
        j = None
    return j, message[n+1:]



class ClientThread(threading.Thread):
    # read messages from client (socket), and sends them to Network
    # responses are sent back on the same socket

    def __init__(self, server, network, s):
        threading.Thread.__init__(self)
        self.server = server
        self.daemon = True
        self.s = s
        self.s.settimeout(0.1)
        self.network = network
        self.queue = Queue.Queue()
        self.unanswered_requests = {}
        self.debug = False
        self.server.add_client(self)


    def run(self):

        message = ''
        while True:
            try:
                self.send_responses()
            except socket.error:
                break

            try:
                data = self.s.recv(1024)
            except socket.timeout:
                continue
            except:
                data = ''
            if not data:
                break
            message += data
            while True:
                cmd, message = parse_json(message)
                if not cmd:
                    break
                self.process(cmd)

        self.server.remove_client(self)




    def process(self, request):
        if self.debug: 
            print_error("<--", request)
        method = request['method']
        params = request['params']
        _id = request['id']

        if method == ('daemon.stop'):
            self.server.stop()
            return

        if method.startswith('network.'):
            out = {'id':_id}
            try:
                f = getattr(self.network, method[8:])
            except AttributeError:
                out['error'] = "unknown method"
            try:
                out['result'] = f(*params)
            except BaseException as e:
                out['error'] = str(e)
                print_error("network error", str(e))

            self.queue.put(out)
            return

        def cb(i,r):
            _id = r.get('id')
            if _id is not None:
                my_id = self.unanswered_requests.pop(_id)
                r['id'] = my_id
            self.queue.put(r)

        try:
            new_id = self.network.interface.send([(method, params)], cb) [0]
        except Exception as e:
            self.queue.put({'id':_id, 'error':str(e)}) 
            print_error("network interface error", str(e))
            return

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
            if self.debug: 
                print_error("-->", r)



class NetworkServer:

    def __init__(self, config):
        self.network = Network(config)
        self.network.trigger_callback = self.trigger_callback
        self.network.start()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.daemon_port = config.get('daemon_port', DAEMON_PORT)
        self.socket.bind(('', self.daemon_port))
        self.socket.listen(5)
        self.socket.settimeout(1)
        self.running = False
        # daemon terminates after period of inactivity
        self.timeout = config.get('daemon_timeout', 5*60)
        self.lock = threading.RLock()

        # each GUI is a client of the daemon
        self.clients = []
        # daemon needs to know which client subscribed to which address

    def stop(self):
        with self.lock:
            self.running = False

    def add_client(self, client):
        for key in ['status','banner','updated','servers','interfaces']:
            value = self.get_status_value(key)
            client.queue.put({'method':'network.status', 'params':[key, value]})
        with self.lock:
            self.clients.append(client)


    def remove_client(self, client):
        with self.lock:
            self.clients.remove(client)
        print_error("client quit:", len(self.clients))

    def get_status_value(self, key):
        if key == 'status':
            value = self.network.connection_status
        elif key == 'banner':
            value = self.network.banner
        elif key == 'updated':
            value = (self.network.get_local_height(), self.network.get_server_height())
        elif key == 'servers':
            value = self.network.get_servers()
        elif key == 'interfaces':
            value = self.network.get_interfaces()
        return value

    def trigger_callback(self, key):
        value = self.get_status_value(key)
        print_error("daemon trigger callback", key, len(self.clients))
        for client in self.clients:
            client.queue.put({'method':'network.status', 'params':[key, value]})

    def main_loop(self):
        self.running = True
        t = time.time()
        while self.running:
            try:
                connection, address = self.socket.accept()
            except socket.timeout:
                if not self.clients:
                    if time.time() - t > self.timeout:
                        print_error("Daemon timeout")
                        break
                else:
                    t = time.time()
                continue
            t = time.time()
            client = ClientThread(self, self.network, connection)
            client.start()
        print_error("Daemon exiting")




if __name__ == '__main__':
    import simple_config, util
    config = simple_config.SimpleConfig()
    util.set_verbosity(True)
    server = NetworkServer(config)
    try:
        server.main_loop()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server"
        sys.exit(1)
