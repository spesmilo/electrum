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

DAEMON_SOCKET = 'daemon.sock'


def do_start_daemon(config):
    import subprocess
    args = [sys.executable, __file__, config.path]
    logfile = open(os.path.join(config.path, 'daemon.log'),'w')
    p = subprocess.Popen(args, stderr=logfile, stdout=logfile, close_fds=(os.name=="posix"))
    print_stderr("starting daemon (PID %d)"%p.pid)



def get_daemon(config, start_daemon):
    import socket
    daemon_socket = os.path.join(config.path, DAEMON_SOCKET)
    daemon_started = False
    while True:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(daemon_socket)
            return s
        except socket.error:
            if not start_daemon:
                return False
            elif not daemon_started:
                do_start_daemon(config)
                daemon_started = True
            else:
                time.sleep(0.1)
        except:
            # do not use daemon if AF_UNIX is not available (windows)
            return False



class ClientThread(util.DaemonThread):

    def __init__(self, server, s):
        util.DaemonThread.__init__(self)
        self.server = server
        self.client_pipe = util.SocketPipe(s)
        self.response_queue = Queue.Queue()
        self.server.add_client(self)

    def reading_thread(self):
        while self.is_running():
            try:
                request = self.client_pipe.get()
            except util.timeout:
                continue
            if request is None:
                self.running = False
                break
            if request.get('method') == 'daemon.stop':
                self.server.stop()
                continue
            self.server.send_request(self, request)

    def run(self):
        threading.Thread(target=self.reading_thread).start()
        while self.is_running():
            try:
                response = self.response_queue.get(timeout=0.1)
            except Queue.Empty:
                continue
            try:
                self.client_pipe.send(response)
            except socket.error:
                self.running = False
                break
        self.server.remove_client(self)





class NetworkServer(util.DaemonThread):

    def __init__(self, config):
        util.DaemonThread.__init__(self)
        self.debug = False
        self.config = config
        self.network = Network(config)
        # network sends responses on that queue
        self.network_queue = Queue.Queue()

        self.running = False
        self.lock = threading.RLock()

        # each GUI is a client of the daemon
        self.clients = []
        self.request_id = 0
        self.requests = {}

    def add_client(self, client):
        for key in ['status','banner','updated','servers','interfaces']:
            value = self.network.get_status_value(key)
            client.response_queue.put({'method':'network.status', 'params':[key, value]})
        with self.lock:
            self.clients.append(client)
            print_error("new client:", len(self.clients))

    def remove_client(self, client):
        with self.lock:
            self.clients.remove(client)
            print_error("client quit:", len(self.clients))

    def send_request(self, client, request):
        with self.lock:
            self.request_id += 1
            self.requests[self.request_id] = (request['id'], client)
            request['id'] = self.request_id

        if self.debug:
            print_error("-->", request)
        self.network.requests_queue.put(request)


    def run(self):
        self.network.start(self.network_queue)
        while self.is_running():
            try:
                response = self.network_queue.get(timeout=0.1)
            except Queue.Empty:
                continue
            if self.debug:
                print_error("<--", response)
            response_id = response.get('id')
            if response_id:
                with self.lock:
                    client_id, client = self.requests.pop(response_id)
                response['id'] = client_id
                client.response_queue.put(response)
            else:
                # notification
                for client in self.clients:
                    client.response_queue.put(response)

        self.network.stop()
        print_error("server exiting")



def daemon_loop(server):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    daemon_socket = os.path.join(server.config.path, DAEMON_SOCKET)
    if os.path.exists(daemon_socket):
        os.remove(daemon_socket)
    daemon_timeout = server.config.get('daemon_timeout', None)
    s.bind(daemon_socket)
    s.listen(5)
    s.settimeout(1)
    t = time.time()
    while server.running:
        try:
            connection, address = s.accept()
        except socket.timeout:
            if daemon_timeout is None:
                continue
            if not server.clients:
                if time.time() - t > daemon_timeout:
                    print_error("Daemon timeout")
                    break
            else:
                t = time.time()
            continue
        t = time.time()
        client = ClientThread(server, connection)
        client.start()
    server.stop()
    # sleep so that other threads can terminate cleanly
    time.sleep(0.5)
    print_error("Daemon exiting")


if __name__ == '__main__':
    import simple_config, util
    _config = {}
    if len(sys.argv) > 1:
        _config['electrum_path'] = sys.argv[1]
    config = simple_config.SimpleConfig(_config)
    util.set_verbosity(True)
    server = NetworkServer(config)
    server.start()
    try:
        daemon_loop(server)
    except KeyboardInterrupt:
        print "Ctrl C - Stopping daemon"
        server.stop()
        sys.exit(1)
