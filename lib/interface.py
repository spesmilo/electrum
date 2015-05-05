#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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


import re, errno, os
import threading, traceback, sys, time, Queue
import socket
import ssl

import x509
import util
import requests
ca_path = requests.certs.where()

from version import ELECTRUM_VERSION, PROTOCOL_VERSION
from simple_config import SimpleConfig


def Interface(server, response_queue, config = None):
    """Interface factory function.  The returned interface class handles the connection
    to a single remote electrum server.  The object handles all necessary locking.  It's
    exposed API is:

    - Inherits everything from threading.Thread.
    - Member functions send_request(), stop(), is_connected()
    - Member variable server.
    
    "is_connected()" is currently racy.  "server" is constant for the object's lifetime and hence
    synchronization is unnecessary.
    """
    host, port, protocol = server.split(':')
    if protocol in 'st':
        return TcpInterface(server, response_queue, config)
    else:
        raise Exception('Unknown protocol: %s'%protocol)

class TcpInterface(threading.Thread):

    def __init__(self, server, response_queue, config = None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config if config is not None else SimpleConfig()
        self.connected = False
        self.debug = False # dump network messages. can be changed at runtime using the console
        self.message_id = 0
        self.response_queue = response_queue
        self.request_queue = Queue.Queue()
        self.unanswered_requests = {}
        # are we waiting for a pong?
        self.is_ping = False
        self.ping_time = 0
        # parse server
        self.server = server
        self.host, self.port, self.protocol = self.server.split(':')
        self.port = int(self.port)
        self.use_ssl = (self.protocol == 's')

    def print_error(self, *msg):
        util.print_error("[%s]"%self.host, *msg)

    def process_response(self, response):
        if self.debug:
            self.print_error("<--", response)

        msg_id = response.get('id')
        error = response.get('error')
        result = response.get('result')

        if msg_id is not None:
            method, params, _id, queue = self.unanswered_requests.pop(msg_id)
            if queue is None:
                queue = self.response_queue
        else:
            # notification
            method = response.get('method')
            params = response.get('params')
            _id = None
            queue = self.response_queue
            # restore parameters
            if method == 'blockchain.numblocks.subscribe':
                result = params[0]
                params = []
            elif method == 'blockchain.headers.subscribe':
                result = params[0]
                params = []
            elif method == 'blockchain.address.subscribe':
                addr = params[0]
                result = params[1]
                params = [addr]

        if method == 'server.version':
            self.server_version = result
            self.is_ping = False
            return

        if error:
            queue.put((self, {'method':method, 'params':params, 'error':error, 'id':_id}))
        else:
            queue.put((self, {'method':method, 'params':params, 'result':result, 'id':_id}))


    def check_host_name(self, peercert, name):
        """Simple certificate/host name checker.  Returns True if the
        certificate matches, False otherwise.  Does not support
        wildcards."""
        # Check that the peer has supplied a certificate.
        # None/{} is not acceptable.
        if not peercert:
            return False
        if peercert.has_key("subjectAltName"):
            for typ, val in peercert["subjectAltName"]:
                if typ == "DNS" and val == name:
                    return True
        else:
            # Only check the subject DN if there is no subject alternative
            # name.
            cn = None
            for attr, val in peercert["subject"]:
                # Use most-specific (last) commonName attribute.
                if attr == "commonName":
                    cn = val
            if cn is not None:
                return cn == name
        return False


    def get_simple_socket(self):
        try:
            l = socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            self.print_error("cannot resolve hostname")
            return
        for res in l:
            try:
                s = socket.socket(res[0], socket.SOCK_STREAM)
                s.connect(res[4])
                return s
            except BaseException as e:
                continue
        else:
            self.print_error("failed to connect", str(e))


    def get_socket(self):
        if self.use_ssl:
            cert_path = os.path.join( self.config.path, 'certs', self.host)
            if not os.path.exists(cert_path):
                is_new = True
                s = self.get_simple_socket()
                if s is None:
                    return
                # try with CA first
                try:
                    s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23, cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca_path, do_handshake_on_connect=True)
                except ssl.SSLError, e:
                    s = None
                if s and self.check_host_name(s.getpeercert(), self.host):
                    self.print_error("SSL certificate signed by CA")
                    return s

                # get server certificate.
                # Do not use ssl.get_server_certificate because it does not work with proxy
                s = self.get_simple_socket()
                try:
                    s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23, cert_reqs=ssl.CERT_NONE, ca_certs=None)
                except ssl.SSLError, e:
                    self.print_error("SSL error retrieving SSL certificate:", e)
                    return

                dercert = s.getpeercert(True)
                s.close()
                cert = ssl.DER_cert_to_PEM_cert(dercert)
                # workaround android bug
                cert = re.sub("([^\n])-----END CERTIFICATE-----","\\1\n-----END CERTIFICATE-----",cert)
                temporary_path = cert_path + '.temp'
                with open(temporary_path,"w") as f:
                    f.write(cert)
            else:
                is_new = False

        s = self.get_simple_socket()
        if s is None:
            return

        s.settimeout(2)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if self.use_ssl:
            try:
                s = ssl.wrap_socket(s,
                                    ssl_version=ssl.PROTOCOL_SSLv23,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs= (temporary_path if is_new else cert_path),
                                    do_handshake_on_connect=True)
            except ssl.SSLError, e:
                self.print_error("SSL error:", e)
                if e.errno != 1:
                    return
                if is_new:
                    rej = cert_path + '.rej'
                    if os.path.exists(rej):
                        os.unlink(rej)
                    os.rename(temporary_path, rej)
                else:
                    with open(cert_path) as f:
                        cert = f.read()
                    try:
                        x = x509.X509()
                        x.parse(cert)
                        x.slow_parse()
                    except:
                        traceback.print_exc(file=sys.stderr)
                        self.print_error("wrong certificate")
                        return
                    try:
                        x.check_date()
                    except:
                        self.print_error("certificate has expired:", cert_path)
                        os.unlink(cert_path)
                        return
                    self.print_error("wrong certificate")
                return
            except BaseException, e:
                self.print_error(e)
                if e.errno == 104:
                    return
                traceback.print_exc(file=sys.stderr)
                return

            if is_new:
                self.print_error("saving certificate")
                os.rename(temporary_path, cert_path)

        return s

    def send_request(self, request, response_queue = None):
        '''Queue a request.  Blocking only if called from other threads.'''
        self.request_queue.put((request, response_queue), threading.current_thread() != self)

    def send_requests(self):
        '''Sends all queued requests'''
        while self.is_connected() and not self.request_queue.empty():
            request, response_queue = self.request_queue.get()
            method = request.get('method')
            params = request.get('params')
            r = {'id': self.message_id, 'method': method, 'params': params}
            try:
                self.pipe.send(r)
            except socket.error, e:
                self.print_error("socket error:", e)
                self.connected = False
                return
            if self.debug:
                self.print_error("-->", r)
            self.unanswered_requests[self.message_id] = method, params, request.get('id'), response_queue
            self.message_id += 1

    def is_connected(self):
        return self.connected

    def stop(self):
        if self.connected and self.protocol in 'st' and self.s:
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
        self.connected = False
        self.print_error("stopped")

    def maybe_ping(self):
        # ping the server with server.version?
        if time.time() - self.ping_time > 60:
            if self.is_ping:
                self.print_error("ping timeout")
                self.stop()
            else:
                self.send_request({'method':'server.version', 'params':[ELECTRUM_VERSION, PROTOCOL_VERSION]})
                self.is_ping = True
                self.ping_time = time.time()

    def run(self):
        self.s = self.get_socket()
        if self.s:
            self.pipe = util.SocketPipe(self.s)
            self.s.settimeout(2)
            self.connected = True
            self.print_error("connected")

        self.change_status()
        if not self.connected:
            return

        # request timer
        request_time = False
        while self.connected:
            self.maybe_ping()
            self.send_requests()
            if not self.connected:
                break
            try:
                response = self.pipe.get()
            except util.timeout:
                if self.unanswered_requests:
                    if request_time is False:
                        request_time = time.time()
                        self.print_error("setting timer")
                    else:
                        if time.time() - request_time > 10:
                            self.print_error("request timeout", len(self.unanswered_requests))
                            self.connected = False
                            break
                continue
            if response is None:
                self.connected = False
                break
            if request_time is not False:
                self.print_error("stopping timer")
                request_time = False
            self.process_response(response)

        self.change_status()

    def change_status(self):
        self.response_queue.put((self, None))




def check_cert(host, cert):
    try:
        x = x509.X509()
        x.parse(cert)
        x.slow_parse()
    except:
        traceback.print_exc(file=sys.stdout)
        return

    try:
        x.check_date()
        expired = False
    except:
        expired = True

    m = "host: %s\n"%host
    m += "has_expired: %s\n"% expired
    util.print_msg(m)


def test_certificates():
    config = SimpleConfig()
    mydir = os.path.join(config.path, "certs")
    certs = os.listdir(mydir)
    for c in certs:
        print c
        p = os.path.join(mydir,c)
        with open(p) as f:
            cert = f.read()
        check_cert(c, cert)

if __name__ == "__main__":
    test_certificates()
