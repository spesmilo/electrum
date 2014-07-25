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

from daemon import parse_json, NetworkServer, DAEMON_PORT





class NetworkProxy(threading.Thread):

    def __init__(self, socket, config=None):
        if config is None:
            config = {}  # Do not use mutables as default arguments!
        threading.Thread.__init__(self)
        self.config = SimpleConfig(config) if type(config) == type({}) else config
        self.socket = socket
        self.socket.settimeout(0.1)
        self.message_id = 0
        self.unanswered_requests = {}
        self.subscriptions = {}
        self.debug = False
        self.lock = threading.Lock()
        self.pending_transactions_for_notifications = []
        self.callbacks = {}
        self.running = True
        self.daemon = True

        # status variables
        self.status = 'connecting'
        self.servers = {}
        self.banner = ''
        self.blockchain_height = 0
        self.server_height = 0
        self.interfaces = []

    def is_running(self):
        return self.running

    def run(self):
        # read responses and trigger callbacks
        message = ''
        while self.is_running():
            try:
                data = self.socket.recv(1024)
            except socket.timeout:
                continue
            except:
                data = ''
            if not data:
                break
            message += data
            while True:
                response, message = parse_json(message)
                if response is not None: 
                    self.process(response)
                else:
                    break
        # fixme: server does not detect if we don't call shutdown
        self.socket.shutdown(2)
        self.socket.close()
        print_error("NetworkProxy thread terminating")

    def process(self, response):
        if self.debug: 
            print_error("<--", response)

        if response.get('method') == 'network.status':
            #print_error("<--", response)
            key, value = response.get('params')
            if key == 'status':
                self.status = value
            elif key == 'banner':
                self.banner = value
            elif key == 'updated':
                self.blockchain_height, self.server_height = value
            elif key == 'servers':
                self.servers = value
            elif key == 'interfaces':
                self.interfaces = value
            self.trigger_callback(key)
            return

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

        self.send( messages, callback )


    def send(self, messages, callback):
        """return the ids of the requests that we sent"""
        with self.lock:
            out = ''
            ids = []
            for m in messages:
                method, params = m 
                request = json.dumps( { 'id':self.message_id, 'method':method, 'params':params } )
                self.unanswered_requests[self.message_id] = method, params, callback
                ids.append(self.message_id)
                if self.debug: 
                    print_error("-->", request)
                self.message_id += 1
                out += request + '\n'
            while out:
                sent = self.socket.send( out )
                out = out[sent:]
            return ids


    def synchronous_get(self, requests, timeout=100000000):
        queue = Queue.Queue()
        ids = self.send(requests, lambda i,x: queue.put(x))
        id2 = ids[:]
        res = {}
        while ids:
            r = queue.get(True, timeout)
            _id = r.get('id')
            if _id in ids:
                ids.remove(_id)
                res[_id] = r.get('result')
            else:
                raise
        out = []
        for _id in id2:
            out.append(res[_id])
        return out


    def get_servers(self):
        return self.servers

    def get_interfaces(self):
        return self.interfaces

    def get_header(self, height):
        return self.synchronous_get([('network.get_header',[height])])[0]

    def get_local_height(self):
        return self.blockchain_height

    def get_server_height(self):
        return self.server_height

    def is_connected(self):
        return self.status == 'connected'

    def is_connecting(self):
        return self.status == 'connecting'

    def is_up_to_date(self):
        return self.synchronous_get([('network.is_up_to_date',[])])[0]

    def get_parameters(self):
        return self.synchronous_get([('network.get_parameters',[])])[0]

    def set_parameters(self, *args):
        return self.synchronous_get([('network.set_parameters',args)])[0]

    def stop(self):
        self.running = False

    def stop_daemon(self):
        return self.send([('daemon.stop',[])], None)

    def register_callback(self, event, callback):
        with self.lock:
            if not self.callbacks.get(event):
                self.callbacks[event] = []
            self.callbacks[event].append(callback)

    def trigger_callback(self, event):
        with self.lock:
            callbacks = self.callbacks.get(event,[])[:]
        if callbacks:
            [callback() for callback in callbacks]

        print_error("trigger_callback", event, len(callbacks))
