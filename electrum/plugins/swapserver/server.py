import os
import asyncio
from collections import defaultdict
from typing import TYPE_CHECKING

from aiohttp import web

from electrum.util import log_exceptions, ignore_exceptions
from electrum.logging import Logger
from electrum.util import EventListener
from electrum.lnaddr import lndecode

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet


class SwapServer(Logger, EventListener):
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
        sm.init_pairs()
        pairs = {
            "info": [],
            "warnings": [],
            "htlcFirst": True,
            "pairs": {
                "BTC/BTC": {
                    "rate": 1,
                    "limits": {
                        "maximal": sm._max_amount,
                        "minimal": sm._min_amount,
                        "maximalZeroConf": {
                            "baseAsset": 0,
                            "quoteAsset": 0
                        }
                    },
                    "fees": {
                        "percentage": 0.5,
                        "minerFees": {
                            "baseAsset": {
                                "normal": sm.normal_fee,
                                "reverse": {
                                    "claim": sm.claim_fee,
                                    "lockup": sm.lockup_fee
                                }
                            },
                            "quoteAsset": {
                                "normal": sm.normal_fee,
                                "reverse": {
                                    "claim": sm.claim_fee,
                                    "lockup": sm.lockup_fee
                                }
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
