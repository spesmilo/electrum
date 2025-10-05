import os
import asyncio
import attr
import random
from collections import defaultdict

from aiohttp import ClientResponse
from aiohttp import web, client_exceptions
from aiorpcx import timeout_after, TaskTimeout, ignore_after


from electrum.util import log_exceptions, ignore_exceptions
from electrum.logging import Logger
from electrum.util import EventListener, event_listener
from electrum.invoices import PR_PAID, PR_EXPIRED


class NotaryServer(Logger, EventListener):
    """
    public API:
    - notarize: reply with an invoice
    - status: reply with proof
    - websocket for status updates
    """

    def __init__(self, config, wallet, notary):
        Logger.__init__(self)
        self.config = config
        self.wallet = wallet
        self.notary = notary
        self.port = self.config.NOTARY_SERVER_PORT
        self.register_callbacks() # eventlistener

        self.pending = defaultdict(asyncio.Event)
        self.pending_msg = {}


    @ignore_exceptions
    @log_exceptions
    async def run(self):
        self.root = '/root'
        app = web.Application()
        #app.add_routes([web.get('/api/status', self.get_status)])
        app.add_routes([web.post('/api/proof', self.get_proof)])
        app.add_routes([web.post('/api/notarize', self.notarize)])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host='0.0.0.0', port=self.port)#, ssl_context=self.config.get_ssl_context())
        await site.start()
        self.logger.info(f"nostary server is listening on port {self.port}")


    async def get_proof(self, request):
        """
        returns an invoice. the rhash will be used to get proof
        """
        params = await request.post()
        try:
            rhash = params['rhash']
        except:
            print(request, params)
            raise web.HTTPUnsupportedMediaType()
        proof = self.notary.get_proof(rhash)
        return web.json_response(proof)

    async def notarize(self, request):
        """ 
        returns an invoice 
        the rhash will be used to get proof
        """
        params = await request.post()
        print("request", request, params)
        try:
            event_id = params['event_id']
            event_pubkey = params['event_pubkey']
            log_fee_str = params['log_fee']
            log_fee = int(log_fee_str)
        except:
            raise web.HTTPUnsupportedMediaType()
        invoice = self.notary.add_request(event_id, event_pubkey, log_fee)
        return web.json_response(invoice)

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
                await asyncio.wait_for(self.pending[key].wait(), 1)
                break
            except asyncio.TimeoutError:
                # send data on the websocket, to keep it alive
                await ws.send_str('waiting')
        await ws.send_str('paid')
        await ws.close()
        return ws
