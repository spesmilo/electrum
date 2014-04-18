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


DEFAULT_TIMEOUT = 5
proxy_modes = ['socks4', 'socks5', 'http']


def check_cert(host, cert):
    from OpenSSL import crypto as c
    _cert = c.load_certificate(c.FILETYPE_PEM, cert)

    m = "host: %s\n"%host
    m += "has_expired: %s\n"% _cert.has_expired()
    m += "pubkey: %s bits\n" % _cert.get_pubkey().bits()
    m += "serial number: %s\n"% _cert.get_serial_number() 
    #m += "issuer: %s\n"% _cert.get_issuer()
    #m += "algo: %s\n"% _cert.get_signature_algorithm() 
    m += "version: %s\n"% _cert.get_version()
    print_msg(m)


def cert_has_expired(cert_path):
    try:
        import OpenSSL
    except Exception:
        print_error("Warning: cannot import OpenSSL")
        return False
    from OpenSSL import crypto as c
    with open(cert_path) as f:
        cert = f.read()
    _cert = c.load_certificate(c.FILETYPE_PEM, cert)
    return _cert.has_expired()


def check_certificates():
    config = SimpleConfig()
    mydir = os.path.join(config.path, "certs")
    certs = os.listdir(mydir)
    for c in certs:
        print c
        p = os.path.join(mydir,c)
        with open(p) as f:
            cert = f.read()
        check_cert(c, cert)
    

def cert_verify_hostname(s):
    # hostname verification (disabled)
    from backports.ssl_match_hostname import match_hostname, CertificateError
    try:
        match_hostname(s.getpeercert(True), host)
        print_error("hostname matches", host)
    except CertificateError, ce:
        print_error("hostname did not match", host)



class Interface(threading.Thread):


    def __init__(self, server, config = None):

        threading.Thread.__init__(self)
        self.daemon = True
        self.config = config if config is not None else SimpleConfig()
        self.connect_event = threading.Event()

        self.subscriptions = {}
        self.lock = threading.Lock()

        self.rtime = 0
        self.bytes_received = 0
        self.is_connected = False
        self.poll_interval = 1

        self.debug = False # dump network messages. can be changed at runtime using the console

        #json
        self.message_id = 0
        self.unanswered_requests = {}

        # parse server
        self.server = server
        try:
            host, port, protocol = self.server.split(':')
            port = int(port)
        except Exception:
            self.server = None
            return

        if protocol not in 'ghst':
            raise Exception('Unknown protocol: %s'%protocol)

        self.host = host
        self.port = port
        self.protocol = protocol
        self.use_ssl = ( protocol in 'sg' )
        self.proxy = self.parse_proxy_options(self.config.get('proxy'))
        if self.proxy:
            self.proxy_mode = proxy_modes.index(self.proxy["mode"]) + 1





    def queue_json_response(self, c):

        # uncomment to debug
        if self.debug:
            print_error( "<--",c )

        msg_id = c.get('id')
        error = c.get('error')
        
        if error:
            print_error("received error:", c)
            if msg_id is not None:
                with self.lock: 
                    method, params, callback = self.unanswered_requests.pop(msg_id)
                callback(self,{'method':method, 'params':params, 'error':error, 'id':msg_id})

            return

        if msg_id is not None:
            with self.lock: 
                method, params, callback = self.unanswered_requests.pop(msg_id)
            result = c.get('result')

        else:
            # notification
            method = c.get('method')
            params = c.get('params')

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

            with self.lock:
                for k,v in self.subscriptions.items():
                    if (method, params) in v:
                        callback = k
                        break
                else:
                    print_error( "received unexpected notification", method, params)
                    print_error( self.subscriptions )
                    return


        callback(self, {'method':method, 'params':params, 'result':result, 'id':msg_id})


    def on_version(self, i, result):
        self.server_version = result


    def start_http(self):
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

                
    def poll(self):
        self.send([], None)


    def send_http(self, messages, callback):
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
                self.queue_json_response(response)
            else:
                for item in response:
                    self.queue_json_response(item)

        if response: 
            self.poll_interval = 1
        else:
            if self.poll_interval < 15: 
                self.poll_interval += 1
        #print self.poll_interval, response

        self.rtime = time.time() - t1
        self.is_connected = True
        return ids




    def start_tcp(self):

        self.connection_msg = self.host + ':%d' % self.port

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
                    if cert_has_expired(cert_path):
                        print_error("certificate has expired:", cert_path)
                        os.unlink(cert_path)
                    else:
                        print_error("wrong certificate", self.host)
                return
            except Exception:
                print_error("wrap_socket failed", self.host)
                traceback.print_exc(file=sys.stdout)
                return

            if is_new:
                print_error("saving certificate for", self.host)
                os.rename(temporary_path, cert_path)

        s.settimeout(60)
        self.s = s
        self.is_connected = True
        print_error("connected to", self.host, self.port)


    def run_tcp(self):
        try:
            #if self.use_ssl: self.s.do_handshake()
            out = ''
            while self.is_connected:
                try: 
                    timeout = False
                    msg = self.s.recv(1024)
                except socket.timeout:
                    timeout = True
                except ssl.SSLError:
                    timeout = True
                except socket.error, err:
                    if err.errno == 60:
                        timeout = True
                    elif err.errno in [11, 10035]:
                        print_error("socket errno", err.errno)
                        time.sleep(0.1)
                        continue
                    else:
                        traceback.print_exc(file=sys.stdout)
                        raise

                if timeout:
                    # ping the server with server.version, as a real ping does not exist yet
                    self.send([('server.version', [ELECTRUM_VERSION, PROTOCOL_VERSION])], self.on_version)
                    continue

                out += msg
                self.bytes_received += len(msg)
                if msg == '': 
                    self.is_connected = False

                while True:
                    s = out.find('\n')
                    if s==-1: break
                    c = out[0:s]
                    out = out[s+1:]
                    c = json.loads(c)
                    self.queue_json_response(c)

        except Exception:
            traceback.print_exc(file=sys.stdout)

        self.is_connected = False


    def send_tcp(self, messages, callback):
        """return the ids of the requests that we sent"""
        out = ''
        ids = []
        for m in messages:
            method, params = m 
            request = json.dumps( { 'id':self.message_id, 'method':method, 'params':params } )
            self.unanswered_requests[self.message_id] = method, params, callback
            ids.append(self.message_id)
            if self.debug:
                print "-->", request
            self.message_id += 1
            out += request + '\n'
        while out:
            try:
                sent = self.s.send( out )
                out = out[sent:]
            except socket.error,e:
                if e[0] in (errno.EWOULDBLOCK,errno.EAGAIN):
                    print_error( "EAGAIN: retrying")
                    time.sleep(0.1)
                    continue
                else:
                    traceback.print_exc(file=sys.stdout)
                    # this happens when we get disconnected
                    print_error( "Not connected, cannot send" )
                    return None
        return ids





    def start_interface(self):

        if self.protocol in 'st':
            self.start_tcp()
        elif self.protocol in 'gh':
            self.start_http()

        self.connect_event.set()



    def stop_subscriptions(self):
        for callback in self.subscriptions.keys():
            callback(self, None)
        self.subscriptions = {}


    def send(self, messages, callback):

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

        if not self.is_connected: 
            print_error("interface: trying to send while not connected")
            return

        if self.protocol in 'st':
            with self.lock:
                out = self.send_tcp(messages, callback)
        else:
            # do not use lock, http is synchronous
            out = self.send_http(messages, callback)

        return out


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


    def is_up_to_date(self):
        return self.unanswered_requests == {}



    def start(self, queue = None, wait = False):
        if not self.server:
            return
        self.queue = queue if queue else Queue.Queue()
        threading.Thread.start(self)
        if wait:
            self.connect_event.wait()


    def run(self):
        self.start_interface()
        if self.is_connected:
            self.send([('server.version', [ELECTRUM_VERSION, PROTOCOL_VERSION])], self.on_version)
            self.change_status()
            self.run_tcp() if self.protocol in 'st' else self.run_http()
        self.change_status()
        

    def change_status(self):
        #print "change status", self.server, self.is_connected
        self.queue.put(self)


    def synchronous_get(self, requests, timeout=100000000):
        queue = Queue.Queue()
        ids = self.send(requests, lambda i,r: queue.put(r))
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


if __name__ == "__main__":

    check_certificates()
