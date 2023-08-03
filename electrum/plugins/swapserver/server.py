import os
import asyncio
from collections import defaultdict

from aiohttp import web
from aiorpcx import NetAddress


from electrum.util import log_exceptions, ignore_exceptions
from electrum.logging import Logger
from electrum.util import EventListener


class SwapServer(Logger, EventListener):
    """
    public API:
    - getpairs
    - createswap
    """

    WWW_DIR = os.path.join(os.path.dirname(__file__), 'www')

    def __init__(self, config, wallet):
        Logger.__init__(self)
        self.config = config
        self.wallet = wallet
        self.addr = NetAddress.from_string(self.config.SWAPSERVER_ADDRESS)
        self.register_callbacks() # eventlistener

        self.pending = defaultdict(asyncio.Event)
        self.pending_msg = {}

    @ignore_exceptions
    @log_exceptions
    async def run(self):
        app = web.Application()
        app.add_routes([web.get('/api/getpairs', self.get_pairs)])
        app.add_routes([web.post('/api/createswap', self.create_swap)])

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host=str(self.addr.host), port=self.addr.port, ssl_context=self.config.get_ssl_context())
        await site.start()
        self.logger.info(f"now running and listening. addr={self.addr}")

    async def get_pairs(self, r):
        sm = self.wallet.lnworker.swap_manager
        sm.init_pairs()
        pairs = {
            "info": [],
            "warnings": [],
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

    async def create_swap(self, r):
        sm = self.wallet.lnworker.swap_manager
        sm.init_pairs()
        request = await r.json()
        req_type = request['type']
        assert request['pairId'] == 'BTC/BTC'
        if req_type == 'reversesubmarine':
            lightning_amount_sat=request['invoiceAmount']
            payment_hash=bytes.fromhex(request['preimageHash'])
            their_pubkey=bytes.fromhex(request['claimPublicKey'])
            assert len(payment_hash) == 32
            assert len(their_pubkey) == 33
            swap, payment_hash, invoice, prepay_invoice = sm.add_server_swap(
                lightning_amount_sat=lightning_amount_sat,
                payment_hash=payment_hash,
                their_pubkey=their_pubkey
            )
            response = {
                'id': payment_hash.hex(),
                'invoice': invoice,
                'minerFeeInvoice': prepay_invoice,
                'lockupAddress': swap.lockup_address,
                'redeemScript': swap.redeem_script.hex(),
                'timeoutBlockHeight': swap.locktime,
                "onchainAmount": swap.onchain_amount,
            }
        elif req_type == 'submarine':
            their_invoice=request['invoice']
            their_pubkey=bytes.fromhex(request['refundPublicKey'])
            assert len(their_pubkey) == 33
            swap, payment_hash, invoice, prepay_invoice = sm.add_server_swap(
                invoice=their_invoice,
                their_pubkey=their_pubkey
            )
            response = {
                "id": payment_hash.hex(),
                "acceptZeroConf": False,
                "expectedAmount": swap.onchain_amount,
                "timeoutBlockHeight": swap.locktime,
                "address": swap.lockup_address,
                "redeemScript": swap.redeem_script.hex()
            }
        else:
            raise Exception('unsupported request type:' + req_type)
        return web.json_response(response)
