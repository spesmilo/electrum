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
import os
import re
import socket
import ssl
import sys
import threading
import traceback
import aiorpcx
import asyncio
import concurrent.futures

import requests

from .util import PrintError, aiosafe, bfh

ca_path = requests.certs.where()

from . import util
from . import x509
from . import pem
from .version import ELECTRUM_VERSION, PROTOCOL_VERSION
from .util import NotificationSession
from . import blockchain

class Interface(PrintError):

    def __init__(self, network, server, config_path, proxy):
        self.exception = None
        self.ready = asyncio.Future()
        self.server = server
        self.host, self.port, self.protocol = self.server.split(':')
        self.port = int(self.port)
        self.config_path = config_path
        self.cert_path = os.path.join(self.config_path, 'certs', self.host)
        self.fut = asyncio.get_event_loop().create_task(self.run())
        self.tip_header = None
        self.tip = 0
        self.blockchain = None
        self.network = network
        if proxy:
            username, pw = proxy.get('user'), proxy.get('password')
            if not username or not pw:
                auth = None
            else:
                auth = aiorpcx.socks.SOCKSUserAuth(username, pw)
            if proxy['mode'] == "socks4":
                self.proxy = aiorpcx.socks.SOCKSProxy((proxy['host'], int(proxy['port'])), aiorpcx.socks.SOCKS4a, auth)
            elif proxy['mode'] == "socks5":
                self.proxy = aiorpcx.socks.SOCKSProxy((proxy['host'], int(proxy['port'])), aiorpcx.socks.SOCKS5, auth)
            else:
                raise NotImplementedError # http proxy not available with aiorpcx
        else:
            self.proxy = None

    def diagnostic_name(self):
        return self.host

    async def is_server_ca_signed(self, sslc):
        try:
            await self.open_session(sslc, exit_early=True)
        except ssl.SSLError as e:
            assert e.reason == 'CERTIFICATE_VERIFY_FAILED'
            return False
        return True

    @util.aiosafe
    async def run(self):
        if self.protocol != 's':
            await self.open_session(None, exit_early=False)
            assert False

        ca_sslc = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        exists = os.path.exists(self.cert_path)
        if exists:
            with open(self.cert_path, 'r') as f:
                contents = f.read()
            if contents != '': # if not CA signed
                try:
                    b = pem.dePem(contents, 'CERTIFICATE')
                except SyntaxError:
                    exists = False
                else:
                    x = x509.X509(b)
                    try:
                        x.check_date()
                    except x509.CertificateError as e:
                        self.print_error("certificate problem", e)
                        os.unlink(self.cert_path)
                        exists = False
        if not exists:
            ca_signed = await self.is_server_ca_signed(ca_sslc)
            if ca_signed:
                with open(self.cert_path, 'w') as f:
                    # empty file means this is CA signed, not self-signed
                    f.write('')
            else:
                await self.save_certificate()
        siz = os.stat(self.cert_path).st_size
        if siz == 0: # if CA signed
            sslc = ca_sslc
        else:
            sslc = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cert_path)
            sslc.check_hostname = 0
        await self.open_session(sslc, exit_early=False)
        assert False

    def mark_ready(self):
        assert self.tip_header
        chain = blockchain.check_header(self.tip_header)
        if not chain:
            self.blockchain = blockchain.blockchains[0]
        else:
            self.blockchain = chain

        self.print_error("set blockchain with height", self.blockchain.height())

        if not self.ready.done():
            self.ready.set_result(1)

    async def save_certificate(self):
        if not os.path.exists(self.cert_path):
            # we may need to retry this a few times, in case the handshake hasn't completed
            for _ in range(10):
                dercert = await self.get_certificate()
                if dercert:
                    self.print_error("succeeded in getting cert")
                    with open(self.cert_path, 'w') as f:
                        cert = ssl.DER_cert_to_PEM_cert(dercert)
                        # workaround android bug
                        cert = re.sub("([^\n])-----END CERTIFICATE-----","\\1\n-----END CERTIFICATE-----",cert)
                        f.write(cert)
                        # even though close flushes we can't fsync when closed.
                        # and we must flush before fsyncing, cause flush flushes to OS buffer
                        # fsync writes to OS buffer to disk
                        f.flush()
                        os.fsync(f.fileno())
                    break
                await asyncio.sleep(1)
            else:
                assert False, "could not get certificate"

    async def get_certificate(self):
        sslc = ssl.SSLContext()
        try:
            async with aiorpcx.ClientSession(self.host, self.port, ssl=sslc, proxy=self.proxy) as session:
                return session.transport._ssl_protocol._sslpipe._sslobj.getpeercert(True)
        except ValueError:
            return None

    async def open_session(self, sslc, exit_early):
        header_queue = asyncio.Queue()
        async with NotificationSession(None, header_queue, self.host, self.port, ssl=sslc, proxy=self.proxy) as session:
            ver = await session.send_request('server.version', [ELECTRUM_VERSION, PROTOCOL_VERSION])
            if exit_early:
                return
            self.print_error(ver, self.host)
            subscription_res = await session.send_request('blockchain.headers.subscribe')
            self.tip_header = blockchain.deserialize_header(bfh(subscription_res['hex']), subscription_res['height'])
            self.tip = subscription_res['height']
            self.mark_ready()
            self.session = session
            while True:
                try:
                    new_header = await asyncio.wait_for(header_queue.get(), 300)
                    self.tip_header = new_header
                    self.tip = new_header['block_height']
                except concurrent.futures.TimeoutError:
                    await asyncio.wait_for(session.send_request('server.ping'), 5)

    def queue_request(self, method, params, msg_id):
        pass

    def close(self):
        self.fut.cancel()

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
        with open(p, encoding='utf-8') as f:
            cert = f.read()
        check_cert(c, cert)

if __name__ == "__main__":
    test_certificates()
