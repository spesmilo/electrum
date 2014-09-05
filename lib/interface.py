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


import random, ast, re, errno, os
import threading, traceback, sys, time, json, Queue
import socks
import socket
import ssl

from version import ELECTRUM_VERSION, PROTOCOL_VERSION
from util import print_error, print_msg
from simple_config import SimpleConfig

import x509

DEFAULT_TIMEOUT = 5
proxy_modes = ['socks4', 'socks5', 'http']


import util




def Interface(server, config = None):
    host, port, protocol = server.split(':')
    port = int(port)
    if protocol in 'st':
        return TcpInterface(server, config)
    elif protocol in 'hg':
        return HttpInterface(server, config)
    else:
        raise Exception('Unknown protocol: %s'%protocol)

class TcpInterface(threading.Thread):

    def __init__(self, server, config = None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config if config is not None else SimpleConfig()
        self.lock = threading.Lock()

        self.is_connected = False
        self.debug = False # dump network messages. can be changed at runtime using the console
        self.message_id = 0
        self.unanswered_requests = {}

        # are we waiting for a pong?
        self.is_ping = False

        # parse server
        self.server = server
        self.host, self.port, self.protocol = self.server.split(':')
        self.port = int(self.port)
        self.use_ssl = (self.protocol == 's')
        self.proxy = self.parse_proxy_options(self.config.get('proxy'))
        if self.proxy:
            self.proxy_mode = proxy_modes.index(self.proxy["mode"]) + 1


    def process_response(self, response):
        if self.debug:
            print_error("<--", response)

        msg_id = response.get('id')
        error = response.get('error')
        result = response.get('result')

        if msg_id is not None:
            with self.lock:
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


    def get_socket(self):

        if self.proxy is not None:
            socks.setdefaultproxy(self.proxy_mode, self.proxy["host"], int(self.proxy["port"]))
            socket.socket = socks.socksocket
            # prevent dns leaks, see http://stackoverflow.com/questions/13184205/dns-over-proxy
            def getaddrinfo(*args):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
            socket.getaddrinfo = getaddrinfo

        if self.use_ssl:
            cert_path = os.path.join( self.config.path, 'certs', self.host)
            if not os.path.exists(cert_path):
                is_new = True
                # get server certificate.
                # Do not use ssl.get_server_certificate because it does not work with proxy
                try:
                    l = socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                except socket.gaierror:
                    print_error("error: cannot resolve", self.host)
                    return

                for res in l:
                    try:
                        s = socket.socket( res[0], socket.SOCK_STREAM )
                        s.connect(res[4])
                    except:
                        s = None
                        continue

                    # first try with ca
                    try:
                        ca_certs = os.path.join(self.config.path, 'ca', 'ca-bundle.crt')
                        s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv3, cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca_certs, do_handshake_on_connect=True)
                        print_error("SSL with ca:", self.host)
                        return s
                    except ssl.SSLError, e:
                        pass

                    try:
                        s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv3, cert_reqs=ssl.CERT_NONE, ca_certs=None)
                    except ssl.SSLError, e:
                        print_error("SSL error retrieving SSL certificate:", self.host, e)
                        s = None

                    break

                if s is None:
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

        try:
            addrinfo = socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            print_error("error: cannot resolve", self.host)
            return

        for res in addrinfo:
            try:
                s = socket.socket( res[0], socket.SOCK_STREAM )
                s.settimeout(2)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                s.connect(res[4])
            except:
                s = None
                continue
            break

        if s is None:
            print_error("failed to connect", self.host, self.port)
            return

        if self.use_ssl:
            try:
                s = ssl.wrap_socket(s,
                                    ssl_version=ssl.PROTOCOL_SSLv3,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs= (temporary_path if is_new else cert_path),
                                    do_handshake_on_connect=True)
            except ssl.SSLError, e:
                print_error("SSL error:", self.host, e)
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
                        print_error("wrong certificate", self.host)
                        return
                    try:
                        x.check_date()
                    except:
                        print_error("certificate has expired:", cert_path)
                        os.unlink(cert_path)
                        return
                    print_error("wrong certificate", self.host)
                return
            except Exception:
                print_error("wrap_socket failed", self.host)
                traceback.print_exc(file=sys.stderr)
                return

            if is_new:
                print_error("saving certificate for", self.host)
                os.rename(temporary_path, cert_path)

        return s
        

    def send_request(self, request, queue=None):
        _id = request.get('id')
        method = request.get('method')
        params = request.get('params')
        with self.lock:
            try:
                r = {'id':self.message_id, 'method':method, 'params':params}
                self.pipe.send(r)
                if self.debug:
                    print_error("-->", r)
            except socket.error, e:
                print_error("socked error:", self.server, e)
                self.is_connected = False
                return
            self.unanswered_requests[self.message_id] = method, params, _id, queue
            self.message_id += 1

    def parse_proxy_options(self, s):
        if type(s) == type({}): return s  # fixme: type should be fixed
        if type(s) != type(""): return None  
        if s.lower() == 'none': return None
        proxy = { "mode":"socks5", "host":"localhost" }
        args = s.split(':')
        n = 0
        if proxy_modes.count(args[n]) == 1:
            proxy["mode"] = args[n]
            n += 1
        if len(args) > n:
            proxy["host"] = args[n]
            n += 1
        if len(args) > n:
            proxy["port"] = args[n]
        else:
            proxy["port"] = "8080" if proxy["mode"] == "http" else "1080"
        return proxy

    def stop(self):
        if self.is_connected and self.protocol in 'st' and self.s:
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
        self.is_connected = False

    def start(self, response_queue):
        self.response_queue = response_queue
        threading.Thread.start(self)

    def run(self):
        self.s = self.get_socket()
        if self.s:
            self.s.settimeout(60)
            self.is_connected = True
            print_error("connected to", self.host, self.port)
            self.pipe = util.SocketPipe(self.s)

        self.change_status()
        if not self.is_connected:
            return

        t = 0
        while self.is_connected:
            # ping the server with server.version
            if time.time() - t > 60:
                if self.is_ping:
                    print_error("ping timeout", self.server)
                    self.is_connected = False
                    break
                else:
                    self.send_request({'method':'server.version', 'params':[ELECTRUM_VERSION, PROTOCOL_VERSION]})
                    self.is_ping = True
                    t = time.time()
            try:
                response = self.pipe.get()
            except util.timeout:
                continue
            if response is None:
                self.is_connected = False
                break
            self.process_response(response)

        self.change_status()
        print_error("closing connection:", self.server)

    def change_status(self):
        # print_error( "change status", self.server, self.is_connected)
        self.response_queue.put((self, None))



class HttpInterface(TcpInterface):

    def run(self):
        self.start_http()
        if self.is_connected:
            self.send_request({'method':'server.version', 'params':[ELECTRUM_VERSION, PROTOCOL_VERSION]})
            self.change_status()
            self.run_http()
        self.change_status()

    def send_request(self, request, queue=None):
        import urllib2, json, time, cookielib
        print_error( "send_http", messages )
        
        if self.proxy:
            socks.setdefaultproxy(self.proxy_mode, self.proxy["host"], int(self.proxy["port"]) )
            socks.wrapmodule(urllib2)

        cj = cookielib.CookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        urllib2.install_opener(opener)

        t1 = time.time()

        data = []
        ids = []
        for m in messages:
            method, params = m
            if type(params) != type([]): params = [params]
            data.append( { 'method':method, 'id':self.message_id, 'params':params } )
            self.unanswered_requests[self.message_id] = method, params, callback
            ids.append(self.message_id)
            self.message_id += 1

        if data:
            data_json = json.dumps(data)
        else:
            # poll with GET
            data_json = None 

            
        headers = {'content-type': 'application/json'}
        if self.session_id:
            headers['cookie'] = 'SESSION=%s'%self.session_id

        try:
            req = urllib2.Request(self.connection_msg, data_json, headers)
            response_stream = urllib2.urlopen(req, timeout=DEFAULT_TIMEOUT)
        except Exception:
            return

        for index, cookie in enumerate(cj):
            if cookie.name=='SESSION':
                self.session_id = cookie.value

        response = response_stream.read()
        self.bytes_received += len(response)
        if response: 
            response = json.loads( response )
            if type(response) is not type([]):
                self.process_response(response)
            else:
                for item in response:
                    self.process_response(item)
        if response: 
            self.poll_interval = 1
        else:
            if self.poll_interval < 15: 
                self.poll_interval += 1
        #print self.poll_interval, response
        self.rtime = time.time() - t1
        self.is_connected = True
        return ids

    def poll(self):
        self.send([], None)

    def start_http(self):
        self.rtime = 0
        self.bytes_received = 0
        self.poll_interval = 1

        self.session_id = None
        self.is_connected = True
        self.connection_msg = ('https' if self.use_ssl else 'http') + '://%s:%d'%( self.host, self.port )
        try:
            self.poll()
        except Exception:
            print_error("http init session failed")
            self.is_connected = False
            return

        if self.session_id:
            print_error('http session:',self.session_id)
            self.is_connected = True
        else:
            self.is_connected = False

    def run_http(self):
        self.is_connected = True
        while self.is_connected:
            try:
                if self.session_id:
                    self.poll()
                time.sleep(self.poll_interval)
            except socket.gaierror:
                break
            except socket.error:
                break
            except Exception:
                traceback.print_exc(file=sys.stdout)
                break
            
        self.is_connected = False






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
    print_msg(m)


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
