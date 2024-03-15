#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
# Copyright (C) 2022 The Electrum Developers
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
import asyncio
from collections import defaultdict
from typing import TYPE_CHECKING, Optional

from aiohttp import web

from electrum import util
from electrum.util import log_exceptions, ignore_exceptions
from electrum.plugin import BasePlugin, hook
from electrum.logging import Logger
from electrum.util import EventListener, event_listener
from electrum.invoices import PR_PAID, PR_EXPIRED

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.daemon import Daemon
    from electrum.wallet import Abstract_Wallet


class PayServerPlugin(BasePlugin):

    def __init__(self, parent, config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.config = config
        self.server = None

    def view_url(self, key) -> Optional[str]:
        if not self.server:
            return None
        return self.server.base_url + self.server.root + '/pay?id=' + key

    @hook
    def daemon_wallet_loaded(self, wallet: 'Abstract_Wallet', daemon: 'Daemon'):
        # we use the first wallet loaded
        if self.server is not None:
            return
        if self.config.NETWORK_OFFLINE:
            return
        self.server = PayServer(self.config, wallet)
        asyncio.run_coroutine_threadsafe(daemon.taskgroup.spawn(self.server.run()), daemon.asyncio_loop)

    @hook
    def wallet_export_request(self, d, key):
        if view_url := self.view_url(key):
            d['view_url'] = view_url

class PayServer(Logger, EventListener):

    WWW_DIR = os.path.join(os.path.dirname(__file__), 'www')

    def __init__(self, config: 'SimpleConfig', wallet: 'Abstract_Wallet'):
        Logger.__init__(self)
        assert self.has_www_dir(), self.WWW_DIR
        self.config = config
        self.wallet = wallet
        self.port = self.config.PAYSERVER_PORT
        self.pending = defaultdict(asyncio.Event)
        self.register_callbacks()

    @classmethod
    def has_www_dir(cls) -> bool:
        index_html = os.path.join(cls.WWW_DIR, "index.html")
        return os.path.exists(index_html)

    @property
    def base_url(self):
        return 'http://localhost:%d'%self.port

    @property
    def root(self):
        return self.config.PAYSERVER_ROOT

    @event_listener
    async def on_event_request_status(self, wallet, key, status):
        if status == PR_PAID:
            self.pending[key].set()

    @ignore_exceptions
    @log_exceptions
    async def run(self):
        app = web.Application()
        app.add_routes([web.get('/api/get_invoice', self.get_request)])
        app.add_routes([web.get('/api/get_status', self.get_status)])
        app.add_routes([web.get('/bip70/{key}.bip70', self.get_bip70_request)])
        # 'follow_symlinks=True' allows symlinks to traverse out the parent directory.
        # This was requested by distro packagers for vendored libs, and we restrict it to only those
        # to minimise attack surface. note: "add_routes" call order matters (inner path goes first)
        app.add_routes([web.static(f"{self.root}/vendor", os.path.join(self.WWW_DIR, 'vendor'), follow_symlinks=True)])
        app.add_routes([web.static(self.root, self.WWW_DIR)])
        if self.config.PAYSERVER_ALLOW_CREATE_INVOICE:
            app.add_routes([web.post('/api/create_invoice', self.create_request)])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host='localhost', port=self.port)
        await site.start()
        self.logger.info(f"running and listening on port {self.port}")

    async def create_request(self, request):
        params = await request.post()
        wallet = self.wallet
        if 'amount_sat' not in params or not params['amount_sat'].isdigit():
            raise web.HTTPUnsupportedMediaType()
        amount = int(params['amount_sat'])
        message = params['message'] or "donation"
        key = wallet.create_request(
            amount_sat=amount,
            message=message,
            exp_delay=3600,
            address=None)
        raise web.HTTPFound(self.root + '/pay?id=' + key)

    async def get_request(self, r):
        key = r.query_string
        request = self.wallet.get_formatted_request(key)
        return web.json_response(request)

    async def get_bip70_request(self, r):
        from electrum.paymentrequest import make_request
        key = r.match_info['key']
        request = self.wallet.get_request(key)
        if not request:
            return web.HTTPNotFound()
        pr = make_request(self.config, request)
        return web.Response(body=pr.SerializeToString(), content_type='application/bitcoin-paymentrequest')

    async def get_status(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        key = request.query_string
        info = self.wallet.get_formatted_request(key)
        if not info:
            await ws.send_str('unknown invoice')
            await ws.close()
            return ws
        if info.get('status') == PR_PAID:
            await ws.send_str(f'paid')
            await ws.close()
            return ws
        if info.get('status') == PR_EXPIRED:
            await ws.send_str(f'expired')
            await ws.close()
            return ws
        while True:
            try:
                await util.wait_for2(self.pending[key].wait(), 1)
                break
            except asyncio.TimeoutError:
                # send data on the websocket, to keep it alive
                await ws.send_str('waiting')
        await ws.send_str('paid')
        await ws.close()
        return ws

