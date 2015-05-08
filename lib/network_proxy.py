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

import util
from network import Network
from util import print_error, print_stderr, parse_json
from simple_config import SimpleConfig
from daemon import NetworkServer
from network import serialize_proxy, serialize_server



class NetworkProxy(util.DaemonThread):

    def __init__(self, socket, config=None):

        if config is None:
            config = {}  # Do not use mutables as default arguments!
        util.DaemonThread.__init__(self)
        self.config = SimpleConfig(config) if type(config) == type({}) else config
        self.message_id = 0
        self.unanswered_requests = {}
        self.subscriptions = {}
        self.debug = False
        self.lock = threading.Lock()
        self.pending_transactions_for_notifications = []
        self.callbacks = {}

        if socket:
            self.pipe = util.SocketPipe(socket)
            self.network = None
        else:
            self.network = Network(config)
            self.pipe = util.QueuePipe(send_queue=self.network.requests_queue)
            self.network.start(self.pipe.get_queue)
            for key in ['status','banner','updated','servers','interfaces']:
                value = self.network.get_status_value(key)
                self.pipe.get_queue.put({'method':'network.status', 'params':[key, value]})

        # status variables
        self.status = 'connecting'
        self.servers = {}
        self.banner = ''
        self.blockchain_height = 0
        self.server_height = 0
        self.interfaces = []


    def run(self):
        while self.is_running():
            try:
                response = self.pipe.get()
            except util.timeout:
                continue
            if response is None:
                break
            self.process(response)
        self.trigger_callback('stop')
        if self.network:
            self.network.stop()
        self.print_error("stopped")

    def process(self, response):
        if self.debug:
            print_error("<--", response)

        if response.get('method') == 'network.status':
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
        result = response.get('result')
        error = response.get('error')
        if msg_id is not None:
            with self.lock:
                method, params, callback = self.unanswered_requests.pop(msg_id)
        else:
            method = response.get('method')
            params = response.get('params')
            with self.lock:
                for k,v in self.subscriptions.items():
                    if (method, params) in v:
                        callback = k
                        break
                else:
                    print_error( "received unexpected notification", method, params)
                    return


        r = {'method':method, 'params':params, 'result':result, 'id':msg_id, 'error':error}
        callback(r)


    def send(self, messages, callback):
        """return the ids of the requests that we sent"""

        # detect subscriptions
        sub = []
        for message in messages:
            m, v = message
            if m[-10:] == '.subscribe':
                sub.append(message)
        if sub:
            with self.lock:
                if self.subscriptions.get(callback) is None:
                    self.subscriptions[callback] = []
                for message in sub:
                    if message not in self.subscriptions[callback]:
                        self.subscriptions[callback].append(message)

        with self.lock:
            requests = []
            ids = []
            for m in messages:
                method, params = m
                request = { 'id':self.message_id, 'method':method, 'params':params }
                self.unanswered_requests[self.message_id] = method, params, callback
                ids.append(self.message_id)
                requests.append(request)
                if self.debug:
                    print_error("-->", request)
                self.message_id += 1

            self.pipe.send_all(requests)
            return ids


    def synchronous_get(self, requests, timeout=100000000):
        queue = Queue.Queue()
        ids = self.send(requests, queue.put)
        id2 = ids[:]
        res = {}
        while ids:
            r = queue.get(True, timeout)
            _id = r.get('id')
            ids.remove(_id)
            if r.get('error'):
                return BaseException(r.get('error'))
            result = r.get('result')
            res[_id] = r.get('result')
        out = []
        for _id in id2:
            out.append(res[_id])
        return out


    def get_servers(self):
        return self.servers

    def get_interfaces(self):
        return self.interfaces

    def get_header(self, height):
        return self.synchronous_get([('network.get_header', [height])])[0]

    def get_local_height(self):
        return self.blockchain_height

    def get_server_height(self):
        return self.server_height

    def is_connected(self):
        return self.status == 'connected'

    def is_connecting(self):
        return self.status == 'connecting'

    def is_up_to_date(self):
        return self.unanswered_requests == {}

    def get_parameters(self):
        return self.synchronous_get([('network.get_parameters', [])])[0]

    def set_parameters(self, host, port, protocol, proxy, auto_connect):
        proxy_str = serialize_proxy(proxy)
        server_str = serialize_server(host, port, protocol)
        self.config.set_key('auto_cycle', auto_connect, True)
        self.config.set_key("proxy", proxy_str, True)
        self.config.set_key("server", server_str, True)
        # abort if changes were not allowed by config
        if self.config.get('server') != server_str or self.config.get('proxy') != proxy_str:
            return

        return self.synchronous_get([('network.set_parameters', (host, port, protocol, proxy, auto_connect))])[0]

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
