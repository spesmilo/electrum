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

    @aiosafe
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
            copy_header_queue = asyncio.Queue()
            conniface = Conn(self.server, session, lambda idx, tip: self.network.request_chunk(idx, tip, session))
            block_retriever = asyncio.get_event_loop().create_task(self.run_fetch_blocks(subscription_res, copy_header_queue, conniface))
            while True:
                try:
                    new_header = await asyncio.wait_for(header_queue.get(), 300)
                    self.tip_header = new_header
                    self.tip = new_header['block_height']
                    await copy_header_queue.put(new_header)
                except concurrent.futures.TimeoutError:
                    await asyncio.wait_for(session.send_request('server.ping'), 5)

    def queue_request(self, method, params, msg_id):
        pass

    def close(self):
        self.fut.cancel()

    @aiosafe
    async def run_fetch_blocks(self, sub_reply, replies, conniface):
        async with self.network.bhi_lock:
            bhi = BlockHeaderInterface(conniface, self.blockchain.height()+1, self)
            await replies.put(blockchain.deserialize_header(bfh(sub_reply['hex']), sub_reply['height']))

        while True:
            self.network.notify('updated')
            item = await replies.get()
            async with self.network.bhi_lock:
                if self.blockchain.height()-1 < item['block_height']:
                    await bhi.sync_until()
                if self.blockchain.height() >= bhi.height and self.blockchain.check_header(item):
                    # another interface amended the blockchain
                    self.print_error("SKIPPING HEADER", bhi.height)
                    continue
                if self.tip < bhi.height:
                    bhi.height = self.tip
                await bhi.step(item)
                self.tip = max(bhi.height, self.tip)

class BlockHeaderInterface(PrintError):
    def __init__(self, conn, height, iface):
        self.height = height
        self.conn = conn
        self.iface = iface

    def diagnostic_name(self):
        return self.conn.server

    async def sync_until(self, next_height=None):
        if next_height is None:
            next_height = self.iface.tip
        last = None
        while last is None or self.height < next_height:
            if next_height > self.height + 10:
                could_connect, num_headers = await self.conn.request_chunk(self.height, next_height)
                self.iface.tip = max(self.height + num_headers, self.iface.tip)
                if not could_connect:
                    if self.height <= self.iface.network.max_checkpoint():
                        raise Exception('server chain conflicts with checkpoints or genesis')
                    last = await self.step()
                    self.iface.tip = max(self.height, self.iface.tip)
                    continue
                self.height = (self.height // 2016 * 2016) + num_headers
                if self.height > next_height:
                    assert False, (self.height, self.iface.tip)
                last = 'catchup'
            else:
                last = await self.step()
                self.iface.tip = max(self.height, self.iface.tip)
        return last

    async def step(self, header=None):
        assert self.height != 0
        if header is None:
            header = await self.conn.get_block_header(self.height, 'catchup')
        chain = self.iface.blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
        if chain: return 'catchup'
        can_connect = blockchain.can_connect(header) if 'mock' not in header else header['mock']['connect'](self)

        bad_header = None
        if not can_connect:
            self.print_error("can't connect", self.height)
            #backward
            bad = self.height
            bad_header = header
            self.height -= 1
            checkp = False
            if self.height <= self.iface.network.max_checkpoint():
                self.height = self.iface.network.max_checkpoint() + 1
                checkp = True

            header = await self.conn.get_block_header(self.height, 'backward')
            chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
            can_connect = blockchain.can_connect(header) if 'mock' not in header else header['mock']['connect'](self)
            if checkp:
                assert can_connect or chain, (can_connect, chain)
            while not chain and not can_connect:
                bad = self.height
                bad_header = header
                delta = self.iface.tip - self.height
                next_height = self.iface.tip - 2 * delta
                checkp = False
                if next_height <= self.iface.network.max_checkpoint():
                    next_height = self.iface.network.max_checkpoint() + 1
                    checkp = True
                self.height = next_height

                header = await self.conn.get_block_header(self.height, 'backward')
                chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
                can_connect = blockchain.can_connect(header) if 'mock' not in header else header['mock']['connect'](self)
                if checkp:
                    assert can_connect or chain, (can_connect, chain)
            self.print_error("exiting backward mode at", self.height)
        if can_connect:
            self.print_error("could connect", self.height)
            chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)

            if type(can_connect) is bool:
                # mock
                self.height += 1
                if self.height > self.iface.tip:
                    assert False
                return 'catchup'
            self.iface.blockchain = can_connect
            self.height += 1
            self.iface.blockchain.save_header(header)
            return 'catchup'

        if not chain:
            raise Exception("not chain") # line 931 in 8e69174374aee87d73cd2f8005fbbe87c93eee9c's network.py

        # binary
        if type(chain) in [int, bool]:
            pass # mock
        else:
            self.iface.blockchain = chain
        good = self.height
        self.height = (bad + good) // 2
        header = await self.conn.get_block_header(self.height, 'binary')
        while True:
            self.print_error("binary step")
            chain = blockchain.check_header(header) if 'mock' not in header else header['mock']['check'](header)
            if chain:
                assert bad != self.height, (bad, self.height)
                good = self.height
                self.iface.blockchain = self.iface.blockchain if type(chain) in [bool, int] else chain
            else:
                bad = self.height
                assert good != self.height
                bad_header = header
            if bad != good + 1:
                self.height = (bad + good) // 2
                header = await self.conn.get_block_header(self.height, 'binary')
                continue
            mock = bad_header and 'mock' in bad_header and bad_header['mock']['connect'](self)
            real = not mock and self.iface.blockchain.can_connect(bad_header, check_height=False)
            if not real and not mock:
                raise Exception('unexpected bad header during binary' + str(bad_header)) # line 948 in 8e69174374aee87d73cd2f8005fbbe87c93eee9c's network.py
            branch = blockchain.blockchains.get(bad)
            if branch is not None:
                ismocking = False
                if type(branch) is dict:
                    ismocking = True
                # FIXME: it does not seem sufficient to check that the branch
                # contains the bad_header. what if self.blockchain doesn't?
                # the chains shouldn't be joined then. observe the incorrect
                # joining on regtest with a server that has a fork of height
                # one. the problem is observed only if forking is not during
                # electrum runtime
                if ismocking and branch['check'](bad_header) or not ismocking and branch.check_header(bad_header):
                    self.print_error('joining chain', bad)
                    self.height += 1
                    return 'join'
                else:
                    if ismocking and branch['parent']['check'](header) or not ismocking and branch.parent().check_header(header):
                        self.print_error('reorg', bad, self.iface.tip)
                        self.iface.blockchain = branch.parent() if not ismocking else branch['parent']
                        self.height = bad
                        header = await self.conn.get_block_header(self.height, 'binary')
                    else:
                        if ismocking:
                            self.height = bad + 1
                            self.print_error("TODO replace blockchain")
                            return 'conflict'
                        self.print_error('forkpoint conflicts with existing fork', branch.path())
                        branch.write(b'', 0)
                        branch.save_header(bad_header)
                        self.iface.blockchain = branch
                        self.height = bad + 1
                        return 'conflict'
            else:
                bh = self.iface.blockchain.height()
                if bh > good:
                    forkfun = self.iface.blockchain.fork
                    if 'mock' in bad_header:
                        chain = bad_header['mock']['check'](bad_header)
                        forkfun = bad_header['mock']['fork'] if 'fork' in bad_header['mock'] else forkfun
                    else:
                        chain = self.iface.blockchain.check_header(bad_header)
                    if not chain:
                        b = forkfun(bad_header)
                        assert bad not in blockchain.blockchains, (bad, list(blockchain.blockchains.keys()))
                        blockchain.blockchains[bad] = b
                        self.iface.blockchain = b
                        self.height = b.forkpoint + 1
                        assert b.forkpoint == bad
                    return 'fork'
                else:
                    assert bh == good
                    if bh < self.iface.tip:
                        self.print_error("catching up from %d"% (bh + 1))
                        self.height = bh + 1
                    return 'no_fork'

class Conn:
    def __init__(self, server, session, get_chunk):
        self.server = server
        self.session = session # type: aiorpcx.ClientSession
        self.request_chunk = get_chunk
    async def get_block_header(self, height, assert_mode):
        res = await asyncio.wait_for(self.session.send_request('blockchain.block.header', [height]), 1)
        return blockchain.deserialize_header(bytes.fromhex(res), height)


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
