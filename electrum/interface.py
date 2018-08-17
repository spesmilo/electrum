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

import requests

from .util import PrintError

ca_path = requests.certs.where()

from . import util
from . import x509
from . import pem
from .version import ELECTRUM_VERSION, PROTOCOL_VERSION

class Interface(PrintError):

    def __init__(self, server, config_path, connecting):
        self.connecting = connecting
        self.server = server
        self.host, self.port, self.protocol = self.server.split(':')
        self.config_path = config_path
        self.cert_path = os.path.join(self.config_path, 'certs', self.host)
        self.fut = asyncio.get_event_loop().create_task(self.run())

    def diagnostic_name(self):
        return self.host

    async def is_server_ca_signed(self, sslc):
        try:
            await self.open_session(sslc, do_sleep=False)
        except ssl.SSLError as e:
            assert e.reason == 'CERTIFICATE_VERIFY_FAILED'
            return False
        return True

    @util.aiosafe
    async def run(self):
        if self.protocol != 's':
            await self.open_session(None, execute_after_connect=lambda: self.connecting.remove(self.server))
            return

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
                        except x509.CertificateError:
                            self.print_error("certificate has expired:", self.cert_path)
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
        await self.open_session(sslc, execute_after_connect=lambda: self.connecting.remove(self.server))

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
            async with aiorpcx.ClientSession(self.host, self.port, ssl=sslc) as session:
                return session.transport._ssl_protocol._sslpipe._sslobj.getpeercert(True)
        except ValueError:
            return None

    async def open_session(self, sslc, do_sleep=True, execute_after_connect=lambda: None):
        async with aiorpcx.ClientSession(self.host, self.port, ssl=sslc) as session:
            ver = await session.send_request('server.version', [ELECTRUM_VERSION, PROTOCOL_VERSION])
            print(ver)
            connect_hook_executed = False
            while do_sleep:
                if not connect_hook_executed:
                    connect_hook_executed = True
                    execute_after_connect()
                await asyncio.wait_for(session.send_request('server.ping'), 5)
                await asyncio.sleep(300)

    def has_timed_out(self):
        return self.fut.done()

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
