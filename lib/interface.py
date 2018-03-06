#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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
import aiosocks
import os
import stat
import re
import ssl
import sys
import threading
import time
import traceback
import asyncio
import json
import asyncio.streams
from asyncio.sslproto import SSLProtocol
import io

import requests

from aiosocks.errors import SocksError
from concurrent.futures import TimeoutError

ca_path = requests.certs.where()

from .util import print_error
from .ssl_in_socks import sslInSocksReaderWriter
from . import util
from . import x509
from . import pem

def get_ssl_context(cert_reqs, ca_certs):
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_certs)
    context.check_hostname = False
    context.verify_mode = cert_reqs
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    return context

class Interface(util.PrintError):
    """The Interface class handles a socket connected to a single remote
    electrum server.  It's exposed API is:

    - Member functions close(), fileno(), get_response(), has_timed_out(),
      ping_required(), queue_request(), send_request()
    - Member variable server.
    """

    def __init__(self, server, config_path, proxy_config, is_running):
        self.is_running = is_running
        self.addr = self.auth = None
        if proxy_config is not None:
            if proxy_config["mode"] == "socks5":
                self.addr = aiosocks.Socks5Addr(proxy_config["host"], proxy_config["port"])
                self.auth = aiosocks.Socks5Auth(proxy_config["user"], proxy_config["password"]) if proxy_config["user"] != "" else None
            elif proxy_config["mode"] == "socks4":
                self.addr = aiosocks.Socks4Addr(proxy_config["host"], proxy_config["port"])
                self.auth = aiosocks.Socks4Auth(proxy_config["password"]) if proxy_config["password"] != "" else None
            else:
                raise Exception("proxy mode not supported")

        self.server = server
        self.config_path = config_path
        host, port, protocol = self.server.split(':')
        self.host = host
        self.port = int(port)
        self.use_ssl = (protocol=='s')
        self.reader = self.writer = None
        self.lock = asyncio.Lock()
        # Dump network messages.  Set at runtime from the console.
        self.debug = False
        self.unsent_requests = asyncio.PriorityQueue()
        self.unanswered_requests = {}
        self.last_ping = 0
        self.closed_remotely = False
        self.buf = bytes()

    def conn_coro(self, context):
        return asyncio.open_connection(self.host, self.port, ssl=context)

    async def _save_certificate(self, cert_path, require_ca):
        dercert = None
        if require_ca:
            context = get_ssl_context(cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca_path)
        else:
            context = get_ssl_context(cert_reqs=ssl.CERT_NONE, ca_certs=None)
        try:
            if self.addr is not None:
                proto_factory = lambda: SSLProtocol(asyncio.get_event_loop(), asyncio.Protocol(), context, None)
                socks_create_coro = aiosocks.create_connection(proto_factory, \
                                    proxy=self.addr, \
                                    proxy_auth=self.auth, \
                                    dst=(self.host, self.port))
                transport, protocol = await asyncio.wait_for(socks_create_coro, 5)
                async def job(fut):
                    try:
                        if protocol._sslpipe is not None:
                            fut.set_result(protocol._sslpipe.ssl_object.getpeercert(True))
                    except BaseException as e:
                        fut.set_exception(e)
                while self.is_running():
                    fut = asyncio.Future()
                    asyncio.ensure_future(job(fut))
                    try:
                        await fut
                    except:
                        pass
                    try:
                        fut.exception()
                        dercert = fut.result()
                    except ValueError:
                        await asyncio.sleep(1)
                        continue
                    except:
                        if self.is_running():
                            traceback.print_exc()
                            print("Previous exception from _save_certificate")
                        continue
                    break
                if not self.is_running(): return
                transport.close()
            else:
                reader, writer = await asyncio.wait_for(self.conn_coro(context), 3)
                dercert = writer.get_extra_info('ssl_object').getpeercert(True)
                writer.close()
        except OSError as e: # not ConnectionError because we need socket.gaierror too
            if self.is_running():
                self.print_error(self.server, "Exception in _save_certificate", type(e))
            return
        except TimeoutError:
            return
        assert dercert
        if not require_ca:
            cert = ssl.DER_cert_to_PEM_cert(dercert)
        else:
            # Don't pin a CA signed certificate
            cert = ""
        temporary_path = cert_path + '.temp'
        with open(temporary_path, "w") as f:
            f.write(cert)
        return temporary_path

    async def _get_read_write(self):
        async with self.lock:
            if self.reader is not None and self.writer is not None:
                return self.reader, self.writer, True
            if self.use_ssl:
                cert_path = os.path.join(self.config_path, 'certs', self.host)
                if not os.path.exists(cert_path):
                    temporary_path = await self._save_certificate(cert_path, True)
                    if not temporary_path:
                        temporary_path = await self._save_certificate(cert_path, False)
                    if not temporary_path:
                        raise ConnectionError("Could not get certificate on second try")

                    is_new = True
                else:
                    is_new = False
                ca_certs = temporary_path if is_new else cert_path

                size = os.stat(ca_certs)[stat.ST_SIZE]
                self_signed = size != 0
                if not self_signed:
                    ca_certs = ca_path
            try:
                if self.addr is not None:
                    if not self.use_ssl:
                        open_coro = aiosocks.open_connection(proxy=self.addr, proxy_auth=self.auth, dst=(self.host, self.port))
                        self.reader, self.writer = await asyncio.wait_for(open_coro, 5)
                    else:
                        ssl_in_socks_coro = sslInSocksReaderWriter(self.addr, self.auth, self.host, self.port, ca_certs)
                        self.reader, self.writer = await asyncio.wait_for(ssl_in_socks_coro, 5)
                else:
                    context = get_ssl_context(cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca_certs) if self.use_ssl else None
                    self.reader, self.writer = await asyncio.wait_for(self.conn_coro(context), 5)
            except TimeoutError:
                self.print_error("TimeoutError after getting certificate successfully...")
                raise
            except BaseException as e:
                if self.is_running():
                    if not isinstance(e, OSError):
                        traceback.print_exc()
                        self.print_error("Previous exception will now be reraised")
                raise e
            if self.use_ssl and is_new:
                self.print_error("saving new certificate for", self.host)
                os.rename(temporary_path, cert_path)
            return self.reader, self.writer, False

    async def send_all(self, list_of_requests):
        _, w, usedExisting = await self._get_read_write()
        starttime = time.time()
        for i in list_of_requests:
            w.write(json.dumps(i).encode("ascii") + b"\n")
        await w.drain()
        if time.time() - starttime > 2.5:
            self.print_error("send_all: sending is taking too long. Used existing connection: ", usedExisting)
            raise ConnectionError("sending is taking too long")

    def close(self):
        if self.writer:
            self.writer.close()

    def _try_extract(self):
        try:
            pos = self.buf.index(b"\n")
        except ValueError:
            return
        obj = self.buf[:pos]
        try:
            obj = json.loads(obj.decode("ascii"))
        except ValueError:
            return
        else:
            self.buf = self.buf[pos+1:]
            self.last_action = time.time()
            return obj
    async def get(self):
        reader, _, _ = await self._get_read_write()

        while self.is_running():
            tried = self._try_extract()
            if tried: return tried
            temp = io.BytesIO()
            try:
                data = await asyncio.wait_for(reader.read(2**10), 1)
                temp.write(data)
            except asyncio.TimeoutError:
                continue
            self.buf += temp.getvalue()

    def idle_time(self):
        return time.time() - self.last_action

    def diagnostic_name(self):
        return self.host

    async def queue_request(self, *args):  # method, params, _id
        '''Queue a request, later to be send with send_requests when the
        socket is available for writing.
        '''
        self.request_time = time.time()
        await self.unsent_requests.put((self.request_time, args))

    def num_requests(self):
        '''Keep unanswered requests below 100'''
        n = 100 - len(self.unanswered_requests)
        return min(n, self.unsent_requests.qsize())

    async def send_request(self):
        '''Sends queued requests.  Returns False on failure.'''
        make_dict = lambda m, p, i: {'method': m, 'params': p, 'id': i}
        n = self.num_requests()
        try:
            prio, request = await asyncio.wait_for(self.unsent_requests.get(), 1.5)
        except TimeoutError:
            return False
        try:
            await self.send_all([make_dict(*request)])
        except (SocksError, OSError, TimeoutError) as e:
            if type(e) is SocksError:
                self.print_error(e)
            await self.unsent_requests.put((prio, request))
            return False
        if self.debug:
            self.print_error("-->", request)
        self.unanswered_requests[request[2]] = request
        self.last_action = time.time()
        return True

    def ping_required(self):
        '''Maintains time since last ping.  Returns True if a ping should
        be sent.
        '''
        now = time.time()
        if now - self.last_ping > 60:
            self.last_ping = now
            return True
        return False

    def has_timed_out(self):
        '''Returns True if the interface has timed out.'''
        if (self.unanswered_requests and time.time() - self.request_time > 10
            and self.idle_time() > 10):
            self.print_error("timeout", len(self.unanswered_requests))
            return True
        return False

    async def get_response(self):
        '''Call if there is data available on the socket.  Returns a list of
        (request, response) pairs.  Notifications are singleton
        unsolicited responses presumably as a result of prior
        subscriptions, so request is None and there is no 'id' member.
        Otherwise it is a response, which has an 'id' member and a
        corresponding request.  If the connection was closed remotely
        or the remote server is misbehaving, a (None, None) will appear.
        '''
        response = await self.get()
        if not type(response) is dict:
            if response is None:
                self.closed_remotely = True
                if self.is_running():
                    self.print_error("connection closed remotely")
            return None, None
        if self.debug:
            self.print_error("<--", response)
        wire_id = response.get('id', None)
        if wire_id is None:  # Notification
            return None, response
        else:
            request = self.unanswered_requests.pop(wire_id, None)
            if request:
                return request, response
            else:
                self.print_error("unknown wire ID", wire_id)
                return None, None # Signal

def check_cert(host, cert):
    try:
        b = pem.dePem(cert, 'CERTIFICATE')
        x = x509.X509(b)
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


# Used by tests
def _match_hostname(name, val):
    if val == name:
        return True

    return val.startswith('*.') and name.endswith(val[1:])


def test_certificates():
    from .simple_config import SimpleConfig
    config = SimpleConfig()
    mydir = os.path.join(config.path, "certs")
    certs = os.listdir(mydir)
    for c in certs:
        p = os.path.join(mydir,c)
        with open(p) as f:
            cert = f.read()
        check_cert(c, cert)

if __name__ == "__main__":
    test_certificates()
