#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum Developers
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
from typing import TYPE_CHECKING

from aiohttp import web

from electrum.util import log_exceptions, ignore_exceptions
from electrum.logging import Logger
from electrum.util import EventListener

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet


class HttpSwapServer(Logger, EventListener):
    """
    public API:
    - getpairs
    - createswap
    """

    WWW_DIR = os.path.join(os.path.dirname(__file__), 'www')

    def __init__(self, config: 'SimpleConfig', wallet: 'Abstract_Wallet'):
        Logger.__init__(self)
        self.config = config
        self.wallet = wallet
        self.sm = self.wallet.lnworker.swap_manager
        self.port = self.config.SWAPSERVER_PORT
        self.register_callbacks() # eventlistener

        self.pending = defaultdict(asyncio.Event)
        self.pending_msg = {}

    @ignore_exceptions
    @log_exceptions
    async def run(self):

        while self.wallet.has_password() and self.wallet.get_unlocked_password() is None:
            self.logger.info("This wallet is password-protected. Please unlock it to start the swapserver plugin")
            await asyncio.sleep(10)

        app = web.Application()
        app.add_routes([web.get('/getpairs', self.get_pairs)])
        app.add_routes([web.post('/createswap', self.create_swap)])
        app.add_routes([web.post('/createnormalswap', self.create_normal_swap)])
        app.add_routes([web.post('/addswapinvoice', self.add_swap_invoice)])

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host='localhost', port=self.port)
        await site.start()
        self.logger.info(f"running and listening on port {self.port}")

    async def get_pairs(self, r):
        sm = self.sm
        sm.server_update_pairs()
        pairs = {
            "info": [],
            "warnings": [],
            "htlcFirst": True,
            "pairs": {
                "BTC/BTC": {
                    "rate": 1,
                    "limits": {
                        "maximal": min(sm._max_forward, sm._max_reverse),  # legacy
                        "max_forward_amount": sm._max_forward,  # new version, uses 2 separate limits
                        "max_reverse_amount": sm._max_reverse,
                        "minimal": sm._min_amount,
                    },
                    "fees": {
                        "percentage": sm.percentage,
                        "minerFees": {
                            "baseAsset": {
                                "normal": sm.mining_fee,
                                "reverse": {
                                    "claim": sm.mining_fee,
                                    "lockup": sm.mining_fee
                                },
                                "mining_fee": sm.mining_fee
                            },
                            "quoteAsset": {
                                "normal": sm.mining_fee,
                                "reverse": {
                                    "claim": sm.mining_fee,
                                    "lockup": sm.mining_fee
                                },
                                "mining_fee": sm.mining_fee
                            }
                        }
                    }
                }
            }
        }
        return web.json_response(pairs)

    async def add_swap_invoice(self, r):
        request = await r.json()
        self.sm.server_add_swap_invoice(request)
        return web.json_response({})

    async def create_normal_swap(self, r):
        request = await r.json()
        response = self.sm.server_create_normal_swap(request)
        return web.json_response(response)

    async def create_swap(self, r):
        request = await r.json()
        response = self.sm.server_create_swap(request)
        return web.json_response(response)
