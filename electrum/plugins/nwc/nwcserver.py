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
import asyncio
import json
import time
import ssl
import logging
import urllib.parse
from typing import TYPE_CHECKING, Optional, List, Tuple, Awaitable

import electrum_aionostr as aionostr
from electrum_aionostr.event import Event as nEvent
from electrum_aionostr.key import PrivateKey

from electrum.lnworker import PaymentDirection
from electrum.plugin import BasePlugin, hook
from electrum.logging import Logger
from electrum.util import log_exceptions, ca_path, OldTaskGroup, get_asyncio_loop, InvoiceError, \
    LightningHistoryItem, event_listener, EventListener, make_aiohttp_proxy_connector, \
    get_running_loop
from electrum.invoices import Invoice, Request, PR_UNKNOWN, PR_PAID, BaseInvoice, PR_INFLIGHT
from electrum import constants

if TYPE_CHECKING:
    from aiohttp_socks import ProxyConnector

    from electrum.simple_config import SimpleConfig
    from electrum.wallet import Abstract_Wallet


class NWCServerPlugin(BasePlugin):
    URI_SCHEME = 'nostr+walletconnect://'

    def __init__(self, parent, config: 'SimpleConfig', name):
        BasePlugin.__init__(self, parent, config, name)
        self.config = config
        self.connections = None  # type: Optional[dict[str, dict]]  # pubkey_hex -> connection data
        self.nwc_server = None   # type: Optional[NWCServer]
        self.taskgroup = OldTaskGroup()
        self.initialized = False
        if not self.config.NWC_RELAY:  # type: ignore  # defined in __init__
            self.config.NWC_RELAY = self.config.NOSTR_RELAYS.split(',')[0]
        self.logger.debug(f"NWCServerPlugin created, waiting for wallet to load...")

    def start_plugin(self, wallet: 'Abstract_Wallet'):
        if not wallet.has_lightning():
            return
        if self.initialized:
            # this might be called for several wallets. only use one.
            return
        storage = self.get_storage(wallet)
        self.connections = storage.setdefault('connections', {})
        self.delete_expired_connections()
        self.nwc_server = NWCServer(self.config, wallet, self.taskgroup, self.connections)
        asyncio.run_coroutine_threadsafe(self.taskgroup.spawn(self.nwc_server.run()), get_asyncio_loop())
        self.initialized = True

    @hook
    def close_wallet(self, *args, **kwargs):
        async def close():
            if self.nwc_server and self.nwc_server.manager:
                self.nwc_server.do_stop = True
                await self.nwc_server.manager.close()
            await self.taskgroup.cancel_remaining()
        asyncio.run_coroutine_threadsafe(
            close(),
            get_asyncio_loop()
        )
        self.logger.debug(f"NWCServerPlugin closed, stopping taskgroup")

    def delete_expired_connections(self):
        if self.connections is None:
            return
        now = int(time.time())
        connections = list(self.connections.items())
        for pubkey, conn in connections:
            if 'valid_until' in conn and conn['valid_until'] <= now:
                del self.connections[pubkey]
                self.logger.info(f"Deleting expired NWC connection: {pubkey}")
        if len(self.connections) != len(connections) and self.nwc_server:
            self.nwc_server.restart_event_handler()

    def create_connection(self, name: str, daily_limit_sat: Optional[int], valid_for_sec: Optional[int]) -> str:
        assert self.connections is not None, f"Wallet not loaded yet"
        assert len(name) > 0, f"Invalid or missing connection name: {name}"

        for conn in self.connections.values():
            if conn['name'] == name:
                raise ValueError(f"Connection name already exists: {name}")

        our_connection_secret = PrivateKey()
        our_connection_pubkey: str = our_connection_secret.public_key.hex()

        client_secret = PrivateKey()
        client_pubkey: str = client_secret.public_key.hex()

        connection = {
            "name": name,
            "our_secret": our_connection_secret.hex(),
            "budget_spends": []
        }
        if daily_limit_sat is not None:
            connection['daily_limit_sat'] = daily_limit_sat
        if valid_for_sec:
            connection['valid_until'] = int(time.time()) + valid_for_sec
        connection_string = self.serialize_connection_uri(client_secret.hex(), our_connection_pubkey)
        self.connections[client_pubkey] = connection
        self.logger.debug(f"Added nwc connection: {name=}, {valid_for_sec=}, {daily_limit_sat=}")

        if self.nwc_server:
            self.nwc_server.restart_event_handler()

        return connection_string

    def remove_connection(self, name: str) -> None:
        assert self.connections is not None, f"Wallet not loaded yet"
        for pubkey, conn in self.connections.items():
            if conn['name'] == name:
                del self.connections[pubkey]
                return
        raise ValueError(f"Connection name not found: {name}")

    def list_connections(self) -> dict:
        assert self.connections is not None, f"Wallet not loaded yet"
        self.delete_expired_connections()
        connections_without_secrets = {}
        for client_pub, conn in self.connections.items():
            data = {
                'valid_until': conn.get('valid_until', "unset"),
                'daily_limit_sat': conn.get('daily_limit_sat', "unset"),
                'client_pub': client_pub,
            }
            connections_without_secrets[conn['name']] = data
        return connections_without_secrets

    def serialize_connection_uri(self, client_secret_hex: str, our_pubkey_hex: str) -> str:
        base_uri = f"{self.URI_SCHEME}{our_pubkey_hex}"

        # the NWC_RELAY is added first as this is the first relay parsed by clients
        query_params = [f"relay={urllib.parse.quote(self.config.NWC_RELAY)}"]  # type: ignore
        for relay in self.config.NOSTR_RELAYS.split(",")[:5]:
            if relay != self.config.NWC_RELAY:  # type: ignore
                query_params.append(f"relay={urllib.parse.quote(relay)}")

        query_params.append(f"secret={client_secret_hex}")

        # Construct the final URI
        query_string = "&".join(query_params)
        uri = f"{base_uri}?{query_string}"

        return uri


class NWCServer(Logger, EventListener):
    INFO_EVENT_KIND: int        = 13194
    REQUEST_EVENT_KIND: int     = 23194
    RESPONSE_EVENT_KIND: int    = 23195
    NOTIFICATION_EVENT_KIND: int = 23196
    SUPPORTED_SPENDING_METHODS: set[str] = {'pay_invoice', 'multi_pay_invoice'}
    SUPPORTED_METHODS: set[str] = {'make_invoice', 'lookup_invoice', 'get_balance', 'get_info',
                                   'list_transactions', 'notifications'}.union(SUPPORTED_SPENDING_METHODS)
    SUPPORTED_NOTIFICATIONS: list[str] = ["payment_sent", "payment_received"]

    def __init__(
        self,
        config: 'SimpleConfig',
        wallet: 'Abstract_Wallet',
        taskgroup: 'OldTaskGroup',
        connection_storage: dict,
    ):
        Logger.__init__(self)
        self.config = config  # type: 'SimpleConfig'
        self.wallet = wallet  # type: 'Abstract_Wallet'
        self.connections = connection_storage  # type: dict[str, dict]  # client hex pubkey -> connection data
        self.relays = config.NOSTR_RELAYS.split(",") or []  # type: List[str]
        self.do_stop = False
        self.taskgroup = taskgroup  # type: 'OldTaskGroup'
        self.ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_path)
        self.manager = None  # type: Optional[aionostr.Manager]
        # the task is stored so it can be cancelled when the connections change
        self.event_handler_task = None  # type: Optional[asyncio.Task]
        self.register_callbacks()

    def get_relay_manager(self) -> aionostr.Manager:
        assert get_asyncio_loop() == get_running_loop(), "NWCServer must run in the aio event loop"
        nostr_logger = self.logger.getChild('aionostr')
        nostr_logger.setLevel(logging.INFO)
        network = self.wallet.lnworker.network
        if network.proxy and network.proxy.enabled:
            proxy = make_aiohttp_proxy_connector(network.proxy, self.ssl_context)
        else:
            proxy: Optional['ProxyConnector'] = None
        return aionostr.Manager(
            # ensure that we also connect to NWC_RELAY, even if it's not in the NOSTR_RELAYS
            relays=set(self.config.NOSTR_RELAYS.split(",")) | {self.config.NWC_RELAY},  # type: ignore
            private_key=PrivateKey().hex(),  # use random private key
            log=nostr_logger,
            ssl_context=self.ssl_context,
            proxy=proxy
        )

    @log_exceptions
    async def run(self) -> None:
        while True:
            # wait until connections have been set up and network is available
            while (not self.connections
                        or not self.relays
                        or not self.wallet.network
                        or not self.wallet.network.is_connected()
                        or not self.wallet.lnworker):
                await asyncio.sleep(5)

            if not await self.refresh_manager():
                await asyncio.sleep(30)
                continue

            try:
                await self.publish_info_event()
                self.event_handler_task = await self.taskgroup.spawn(self.handle_requests())
                await self.event_handler_task
            except asyncio.CancelledError:
                if self.do_stop:
                    return
                self.logger.debug("Restarting nwc event handler")
            except Exception as e:
                self.logger.exception(f"Restarting nwc event handler after exception: {e}")
                if self.manager:  # close the manager so refresh_manager() will recreate it
                    await self.manager.close()
                    self.manager = None
                await asyncio.sleep(60)

    async def refresh_manager(self) -> bool:
        """Checks if manager is still connected to relays, if not recreates it and reconnects"""
        if self.manager is None:
            # on startup and proxy change
            self.manager = self.get_relay_manager()

        if len(self.manager.relays) <= 0 < len(self.relays):
            # manager lost all connections (relays)
            # setup new manager so relays are populated again
            await self.manager.close()
            self.manager = self.get_relay_manager()

        if not self.manager.connected:
            # not set in new manager instances
            await self.manager.connect()

        if len(self.manager.relays) <= 0:
            # manager should still have relays after connecting
            self.logger.warning(f"Could not connect to any relays!")
            return False

        return True

    def restart_event_handler(self) -> None:
        """To be called when the connections change so we restart with a new filter"""
        if self.event_handler_task:
            self.event_handler_task.cancel()

    @event_listener
    def on_event_proxy_set(self, *args):
        async def restart_manager():
            if self.manager:
                await self.manager.close()
                self.manager = None
            await asyncio.sleep(5)
            self.restart_event_handler()
            self.logger.info("proxy changed, restarting nwc plugin nostr transport")
        asyncio.run_coroutine_threadsafe(restart_manager(), get_asyncio_loop())

    async def handle_requests(self) -> None:
        query = {
            "authors": list(self.connections.keys()),  # the pubkeys of the client connections
            "kinds": [self.REQUEST_EVENT_KIND],
            "limit": 0,  # requests only new events after creating this subscription
            "since": int(time.time())
        }
        async for event in self.manager.get_events(query, single_event=False, only_stored=False):
            if event.pubkey not in self.connections.keys():
                continue

            # check if the connection is expired, if so we delete it and send an error
            valid_until: Optional[int] = self.connections[event.pubkey].get('valid_until')
            if valid_until and valid_until <= int(time.time()):
                await self.send_error(event, "UNAUTHORIZED", "Connection expired")
                del self.connections[event.pubkey]
                self.logger.info(f"Deleting expired NWC connection: {event.pubkey}")
                self.restart_event_handler()
                continue

            if event.kind != self.REQUEST_EVENT_KIND:
                self.logger.debug(f"Unknown nwc request event kind: {event.kind}")
                await self.send_error(event, "NOT_IMPLEMENTED")
                continue

            # if the request has an explicitly set expiration tag, ignore it if it is expired
            # otherwise ignore requests older than 30 sec to not handle requests the user may
            # already expect to have timed out
            if event.expires_at() is not None:
                if event.is_expired():
                    self.logger.debug(f"expired nwc request event: {event.content}")
                    continue
            elif event.created_at < int(time.time()) - 30:
                self.logger.debug(f"old nwc request event: {event.content}")
                await self.send_error(event, "OTHER", f"not handling too old request")
                continue

            # decrypt the requests content
            our_secret: str = self.connections[event.pubkey]['our_secret']
            our_connection_secret = PrivateKey(raw_secret=bytes.fromhex(our_secret))
            try:
                content = our_connection_secret.decrypt_message(event.content, event.pubkey)
                content = json.loads(content)
                event.content = content
                params: dict = content['params']
            except Exception:
                self.logger.debug(f"Invalid request event content: {event.content}", exc_info=True)
                continue

            # run the according method
            method: str = content.get('method')
            self.logger.debug(f"got request: {method=}, {params=}")
            task: Optional[Awaitable] = None
            if method == "pay_invoice" and not self.is_receive_only(event.pubkey):
                task = self.handle_pay_invoice(event, params)
            elif method == "multi_pay_invoice" and not self.is_receive_only(event.pubkey):
                task = self.handle_multi_pay_invoice(event, params)
            elif method == "make_invoice":
                task = self.handle_make_invoice(event, params)
            elif method == "lookup_invoice":
                task = self.handle_lookup_invoice(event, params)
            elif method == "get_balance":
                task = self.handle_get_balance(event)
            elif method == "get_info":
                task = self.handle_get_info(event)
            elif method == "list_transactions":
                task = self.handle_list_transactions(event, params)
            else:
                self.logger.debug(f"Unsupported nwc method requested: {content.get('method')}")
                await self.send_error(event, "NOT_IMPLEMENTED", f"{method} not supported")
                continue

            if task:
                await self.taskgroup.spawn(self.run_request_task(task, event))

    async def run_request_task(self, task: Awaitable, request_event: nEvent) -> None:
        """Catches request handling exceptions and send an error response"""
        try:
            await task
        except Exception as e:
            self.logger.exception("Error handling nwc request")
            await self.send_error(request_event, "INTERNAL", f"Error handling request: {str(e)[:100]}")

    async def send_error(self, causing_event: nEvent, error_type: str, error_msg: str = "") -> None:
        """Sends an error as response to the passed nEvent, containing the error type and message"""
        to_pubkey_hex = causing_event.pubkey
        response_to_id = causing_event.id
        res_type = None
        if isinstance(causing_event.content, dict):  # we have replaced the content with the decrypted content
            if 'method' in causing_event.content:
                res_type = causing_event.content['method']
        content = self.get_error_response(error_type, error_msg, res_type)
        await self.send_encrypted_response(to_pubkey_hex, json.dumps(content), response_to_id)

    @staticmethod
    def get_error_response(error_type: str, error_msg: str = "", method: Optional[str] = None) -> dict:
        content = {
            "error": {
                "code": error_type,
                "message": error_msg
            }
        }
        if method:
            content['result_type'] = method
        return content

    async def send_encrypted_response(
            self,
            to_pubkey_hex: str,
            content: str,
            response_event_id: str,
            *,
            add_tags: Optional[List] = None
    ) -> None:
        """Encrypts content for the given pubkey and sends it as response to the given event id"""
        our_secret: str = self.connections[to_pubkey_hex]['our_secret']
        tags = [['p', to_pubkey_hex], ['e', response_event_id]]
        if add_tags:
            tags.extend(add_tags)

        await self.taskgroup.spawn(aionostr._add_event(
            self.manager,
            kind=self.RESPONSE_EVENT_KIND,
            tags=tags,
            content=self.encrypt_to_pubkey(content, to_pubkey_hex),
            # use the private key we generated for this specific client
            private_key=our_secret
            )
        )

    @log_exceptions
    async def handle_pay_invoice(self, request_event: nEvent, params: dict) -> None:
        """
        Handler for pay_invoice method
        https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#pay_invoice
        """
        invoice: str = params.get('invoice', "")
        amount_msat: Optional[int] = params.get('amount')
        response = await self.pay_invoice(invoice, amount_msat, request_event.pubkey)
        response['result_type'] = 'pay_invoice'
        await self.send_encrypted_response(request_event.pubkey, json.dumps(response), request_event.id)

    @log_exceptions
    async def handle_multi_pay_invoice(self, request_event: nEvent, params: dict) -> None:
        """
        Handler for multi_pay_invoice method.
        https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#multi_pay_invoice
        """
        invoices: List[dict] = params.get('invoices', [])
        for invoice_req in invoices:
            invoice: str = invoice_req.get('invoice', "")
            amount_msat: Optional[int] = invoice_req.get('amount')
            inv_id: Optional[str] = invoice_req.get('id')
            response = await self.pay_invoice(invoice, amount_msat, request_event.pubkey)
            if not inv_id:
                # if we have no id we need the payment hash
                try:
                    inv_id = Invoice.from_bech32(invoice).rhash
                except InvoiceError:
                    inv_id = "none"
            response['result_type'] = 'multi_pay_invoice'
            id_tag = [['d', inv_id]]
            await self.send_encrypted_response(
                request_event.pubkey,
                json.dumps(response),
                request_event.id,
                add_tags=id_tag
            )

    @log_exceptions
    async def handle_make_invoice(self, request_event: nEvent, params: dict):
        """
        Handler for make_invoice method.
        https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#make_invoice
        """
        amount_msat = params.get('amount', 0)  # type: Optional[int]
        description = params.get('description', params.get('description_hash', ""))  # type: str
        expiry = params.get('expiry', 3600)  # type: int
        # create payment request
        key: str = self.wallet.create_request(
            amount_sat=amount_msat // 1000,
            message=description,
            exp_delay=expiry,
            address=None
        )
        req: Request = self.wallet.get_request(key)
        try:
            lnaddr, b11 = self.wallet.lnworker.get_bolt11_invoice(
                payment_hash=req.payment_hash,
                amount_msat=amount_msat,
                message=description,
                expiry=expiry,
                fallback_address=None
            )
        except Exception:
            self.logger.exception(f"failed to create invoice")
            response = self.get_error_response("INTERNAL", "Failed to create invoice", "make_invoice")
            return await self.send_encrypted_response(request_event.pubkey, json.dumps(response), request_event.id)
        response = {
            "result_type": "make_invoice",
            "result": {
                "type": "incoming",
                "invoice": b11,
                "description": description,
                "payment_hash": lnaddr.paymenthash.hex(),
                "amount": amount_msat,
                "created_at": lnaddr.date,
                "expires_at": req.get_expiration_date(),
                "metadata": {},
                "fees_paid": 0  # the spec wants this??
            }
        }
        self.logger.debug(f"make_invoice response: {response}")
        await self.send_encrypted_response(request_event.pubkey, json.dumps(response), request_event.id)

    @log_exceptions
    async def handle_lookup_invoice(self, request_event: nEvent, params: dict):
        """
        https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#lookup_invoice
        """
        invoice = params.get('invoice')
        payment_hash = params.get('payment_hash')
        if invoice:
            invoice = Invoice.from_bech32(invoice)
        elif payment_hash:
            invoice = self.wallet.get_invoice(payment_hash) or self.wallet.get_request(payment_hash)
        else:
            response = self.get_error_response("NOT_FOUND", "Missing invoice or payment_hash")
            return await self.send_encrypted_response(request_event.pubkey, json.dumps(response), request_event.id)

        status = None
        if invoice and invoice.is_lightning():
            status = self.wallet.get_invoice_status(invoice)
        if not invoice or status is None or status == PR_UNKNOWN:
            response = self.get_error_response("NOT_FOUND", "Invoice not found")
            return await self.send_encrypted_response(request_event.pubkey, json.dumps(response), request_event.id)

        direction = None
        b11 = None
        if self.wallet.get_invoice(invoice.rhash):
            direction = "outgoing"
            b11 = invoice.lightning_invoice
        elif self.wallet.get_request(invoice.rhash):
            direction = "incoming"
            _, b11 = self.wallet.lnworker.get_bolt11_invoice(
                payment_hash=bytes.fromhex(invoice.rhash),
                amount_msat=invoice.amount_msat,
                message=invoice.message,
                expiry=invoice.exp,
                fallback_address=None
            )

        response = {
            "result_type": "lookup_invoice",
            "result": {
                "description": invoice.message,
                "payment_hash": invoice.rhash,
                "amount": invoice.get_amount_msat(),
                "created_at": invoice.time,
                "expires_at": invoice.get_expiration_date(),
                "fees_paid": 0,
                "metadata": {}
            }
        }
        if payment_hash:  # if client requested by payment hash we add the invoice
            response['result']['invoice'] = b11

        info = self.get_payment_info(invoice.rhash)
        if info:
            _, _, fee_msat, settled_at = info
            if fee_msat:
                response['result']['fees_paid'] = fee_msat
            response['result']['settled_at'] = settled_at

        if direction:
            response['result']['type'] = direction
        if status == PR_PAID:
            response['result']['preimage'] = self.wallet.lnworker.get_preimage_hex(invoice.rhash) or "not found"
        self.logger.debug(f"lookup_invoice response: {response}")
        await self.send_encrypted_response(request_event.pubkey, json.dumps(response), request_event.id)

    @log_exceptions
    async def handle_get_balance(self, request_event: nEvent):
        """
        https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#get_balance
        """
        balance = int(self.wallet.lnworker.get_balance())
        response = {
            "result_type": "get_balance",
            "result": {
                "balance": balance * 1000,
            }
        }
        await self.send_encrypted_response(request_event.pubkey, json.dumps(response), request_event.id)

    @log_exceptions
    async def handle_get_info(self, request_event: nEvent):
        """
        https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#get_info
        """
        height = self.wallet.lnworker.network.blockchain().height()
        blockhash = self.wallet.lnworker.network.blockchain().get_hash(height)
        supported_methods = self.SUPPORTED_METHODS.copy()
        if self.is_receive_only(request_event.pubkey):
            supported_methods -= self.SUPPORTED_SPENDING_METHODS
        response = {
            "result_type": "get_info",
            "result": {
                "alias": self.config.LIGHTNING_NODE_ALIAS,
                "color": self.config.LIGHTNING_NODE_COLOR_RGB,
                "pubkey": self.wallet.lnworker.node_keypair.pubkey.hex(),
                "network": constants.net.NET_NAME,
                "block_height": height,
                "block_hash": blockhash,
                "methods": list(supported_methods),
            }
        }
        if self.SUPPORTED_NOTIFICATIONS:
            response['result']['notifications'] = self.SUPPORTED_NOTIFICATIONS
        await self.send_encrypted_response(request_event.pubkey, json.dumps(response), request_event.id)

    @log_exceptions
    async def handle_list_transactions(self, request_event: nEvent, params: dict):
        """
        https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#list_transactions
        Lists invoices and payments. If type is not specified, both invoices and payments are returned.
        The from and until parameters are timestamps in seconds since epoch.
        If from is not specified, it defaults to 0. If until is not specified, it defaults to the current time.
        Transactions are returned in descending order of creation time.
        """
        t0 = time.time()
        from_ts = int(params.get('from', 0))
        until_ts = int(params.get('until', time.time()))
        limit: Optional[int] = params.get('limit')
        offset: Optional[int] = params.get('offset')
        include_unpaid_reqs = bool(params.get('unpaid', False))
        # this is not in spec but alby go requests it
        include_unpaid_outgoing = bool(params.get('unpaid_outgoing', False))
        req_type = params.get('type', "undefined")

        lightning_history = self.wallet.lnworker.get_lightning_history()
        lightning_history = lightning_history.values()

        if req_type == "incoming":
            lightning_history = [tx for tx in lightning_history if tx.direction == PaymentDirection.RECEIVED]
        elif req_type == "outgoing":
            lightning_history = [tx for tx in lightning_history if tx.direction == PaymentDirection.SENT]
        else:
            directions = [PaymentDirection.SENT, PaymentDirection.RECEIVED]
            lightning_history = [tx for tx in lightning_history if tx.direction in directions]

        if include_unpaid_reqs:
            requests = self.wallet.get_unpaid_requests()
            for req in requests:
                if not req.is_lightning() or not (from_ts <= req.time <= until_ts):
                    continue
                lightning_history.append(
                    # append the payment request as LightingHistoryItem so they can be filtered
                    # together with the real lightning history items
                    LightningHistoryItem(
                        type='unpaid',
                        payment_hash=req.rhash,
                        preimage=None,
                        amount_msat=req.get_amount_msat() or 0,
                        fee_msat=None,
                        timestamp=req.time,
                        direction=PaymentDirection.RECEIVED,
                        group_id=None,
                        label=None
                    )
                )

        if include_unpaid_outgoing:
            """Alby Go requests unpaid_outgoing (out of nip47 spec) but then shows them as sent in the tx history.
            So we only return PR_INFLIGHT here so its not totally misleading in the history."""
            invoices = self.wallet.get_invoices()
            for inv in invoices:
                if (not inv.is_lightning()
                        or not (from_ts <= inv.time <= until_ts)
                        or not self.wallet.get_invoice_status(inv) == PR_INFLIGHT):
                    continue
                lightning_history.append(
                    LightningHistoryItem(
                        type='pending',
                        payment_hash=inv.rhash,
                        preimage=None,
                        amount_msat=inv.get_amount_msat() or 0,
                        fee_msat=None,
                        timestamp=inv.time,
                        direction=PaymentDirection.SENT,
                        group_id=None,
                        label=None
                    )
                )

        if from_ts > 0 or until_ts < time.time() - 50:
            # filter out transactions that are not in the time range
            lightning_history = [tx for tx in lightning_history if from_ts <= tx.timestamp <= until_ts]

        lightning_history = sorted(lightning_history, key=lambda tx: tx.timestamp, reverse=True)
        if offset and offset > 0:
            lightning_history = lightning_history[offset:]
        if limit and limit > 0:
            lightning_history = lightning_history[:limit]
        transactions = []
        for history_tx in lightning_history:
            tx = {
                "payment_hash": history_tx.payment_hash,
                "amount": abs(history_tx.amount_msat),
                "metadata": {},
                "fees_paid": 0
            }
            payment: Optional[BaseInvoice] = None
            if history_tx.direction == PaymentDirection.RECEIVED:
                tx['type'] = "incoming"
                payment = self.wallet.get_request(history_tx.payment_hash)
            elif history_tx.direction == PaymentDirection.SENT:
                tx['type'] = "outgoing"
                payment = self.wallet.get_invoice(history_tx.payment_hash)
            else:
                tx['type'] = req_type
            if payment:
                if include_unpaid_outgoing and history_tx.type == 'pending':
                    tx['description'] = f"pending! {payment.message}"
                else:
                    tx['description'] = payment.message
                tx['expires_at'] = payment.get_expiration_date()
                tx['created_at'] = payment.time
            else:
                # don't include txs with semi complete information as this will cause some clients
                # to fail displaying any transaction at all
                continue
            if (not include_unpaid_reqs and not include_unpaid_outgoing) or history_tx.type == 'payment':
                tx['settled_at'] = history_tx.timestamp
                tx['preimage'] = history_tx.preimage
            if history_tx.fee_msat:
                tx['fees_paid'] = history_tx.fee_msat
            transactions.append(tx)

        response = {
            "result_type": "list_transactions",
            "result": {
                "transactions": transactions,
            }
        }
        self.logger.debug(f"list_transactions: returning {len(transactions)} txs in {time.time() - t0:.2f}s")
        await self.send_encrypted_response(request_event.pubkey, json.dumps(response), request_event.id)

    @event_listener
    def on_event_request_status(self, wallet, key, status):
        if wallet != self.wallet:
            return
        request: Optional[Request] = self.wallet.get_request(key)
        if not request or not request.is_lightning() or not status == PR_PAID:
            return
        _, b11 = self.wallet.lnworker.get_bolt11_invoice(
            payment_hash=request.payment_hash,
            amount_msat=request.get_amount_msat(),
            message=request.message,
            expiry=request.exp,
            fallback_address=None
        )

        payment_info = self.get_payment_info(request.rhash)
        if payment_info:
            _, _, _, settled_at = payment_info
        else:
            settled_at = None

        notification = {
            "type": "incoming",
            "invoice": b11,
            "description": request.message,
            "payment_hash": request.rhash,
            "amount": request.get_amount_msat(),
            "created_at": request.time,
            "expires_at": request.get_expiration_date(),
            "preimage": self.wallet.lnworker.get_preimage_hex(request.rhash) or "not found",
            "metadata": {},
            "fees_paid": 0
        }
        if settled_at:
            notification['settled_at'] = settled_at

        self.publish_notification_event({
            "notification_type": "payment_received",
            "notification": notification,
        })

    @event_listener
    def on_event_payment_succeeded(self, wallet, key):
        if wallet != self.wallet:
            return
        invoice: Optional[Invoice] = self.wallet.get_invoice(key)
        if not invoice or not invoice.is_lightning():
            return

        payment_info = self.get_payment_info(key)
        if not payment_info:
            return
        _, fee_msat, _, settled_at = payment_info

        assert key == invoice.rhash, f"{key=!r} != {invoice.rhash=!r}"
        notification = {
            "type": "outgoing",
            "invoice": invoice.lightning_invoice or "",
            "description": invoice.message,
            "preimage": self.wallet.lnworker.get_preimage_hex(invoice.rhash) or "not found",
            "payment_hash": invoice.rhash,
            "amount": invoice.get_amount_msat(),
            "created_at": invoice.time,
            "expires_at": invoice.get_expiration_date(),
            "metadata": {}
        }
        if fee_msat:
            notification['fees_paid'] = fee_msat
        if settled_at:
            notification['settled_at'] = settled_at
        content = {
            "notification_type": "payment_sent",
            "notification": notification,
        }
        self.publish_notification_event(content)

    async def pay_invoice(self, b11: str, amount_msat: Optional[int], request_pub: str) -> dict:
        try:
            invoice: Invoice = Invoice.from_bech32(b11)
        except InvoiceError:
            return self.get_error_response("INTERNAL", "Invalid invoice")

        if invoice.get_amount_msat() is None and not amount_msat:
            return self.get_error_response("INTERNAL", "Missing amount")
        elif invoice.get_amount_msat() is None:
            invoice.set_amount_msat(amount_msat)

        if not self.budget_allows_spend(request_pub, invoice.get_amount_sat()):
            return self.get_error_response("QUOTA_EXCEEDED", "Payment exceeds daily limit")

        self.wallet.save_invoice(invoice)
        try:
            success, log = await self.wallet.lnworker.pay_invoice(
                invoice=invoice,
                amount_msat=amount_msat
            )
        except Exception as e:
            self.logger.exception(f"failed to pay nwc invoice")
            return self.get_error_response("PAYMENT_FAILED", str(e))
        preimage: bytes = self.wallet.lnworker.get_preimage(bytes.fromhex(invoice.rhash))
        response = {}
        if not success or not preimage:
            return self.get_error_response("PAYMENT_FAILED", str(log))
        else:
            self.add_to_budget(request_pub, invoice.get_amount_sat())
            response['result'] = {
                'preimage': preimage.hex(),
            }
        if success:
            self.logger.info(f"paid invoice request from NWC for {invoice.get_amount_sat()} sat")
        else:
            self.logger.info(f"failed to pay invoice request from NWC: {log}")
        return response

    def add_to_budget(self, client_pub: str, amount_sat: int) -> None:
        """
        If client_pub has a budget, check if the amount is within the budget and add it to the budget.
        Return True if the payment is allowed (within the budget)
        """
        if 'budget_spends' not in self.connections[client_pub]:
            self.connections[client_pub]['budget_spends'] = []
        # tuples don't work because jsondb converts them to lists on reload
        self.connections[client_pub]['budget_spends'].append([amount_sat, int(time.time())])

    def get_used_budget(self, client_pub: str) -> int:
        """
        Returns the used budget for the given client_pubkey.
        """
        if 'budget_spends' not in self.connections[client_pub]:
            return 0
        used_budget: int = 0
        budget_spends = self.connections[client_pub]['budget_spends']
        for amount, timestamp in list(budget_spends):
            if timestamp > int(time.time()) - 24 * 3600:
                used_budget += amount
            elif timestamp < int(time.time()) - 24 * 3600:
                # remove old expense
                try:
                    budget_spends.remove([amount, timestamp])
                except ValueError:
                    self.logger.debug("", exc_info=True)
                    continue  # could happen if there is a race
        return used_budget

    def budget_allows_spend(self, client_pub: str, sats_to_spend: int) -> bool:
        client_budget_sat: Optional[int] = self.connections[client_pub].get('daily_limit_sat')
        if client_budget_sat is None:
            return True  # unlimited budget
        used_budget: int = self.get_used_budget(client_pub)
        if used_budget + sats_to_spend > client_budget_sat:
            return False
        return True

    async def publish_info_event(self):
        """
        Publishes the info event according to spec, announcing the supported methods.
        We publish one info event for each client connection.
        https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#example-nip-47-info-event
        """
        if self.SUPPORTED_NOTIFICATIONS:
            tags = [['notifications', ' '.join(self.SUPPORTED_NOTIFICATIONS)]]
        else:
            tags = None
        for client_pubkey, connection in list(self.connections.items()):
            supported_methods = self.SUPPORTED_METHODS.copy()
            if self.is_receive_only(client_pubkey):
                supported_methods -= self.SUPPORTED_SPENDING_METHODS
            content = ' '.join(supported_methods)
            event_id = await aionostr._add_event(
                self.manager,
                kind=self.INFO_EVENT_KIND,
                tags=tags,  # only needed if we support notification events
                content=content,
                private_key=connection['our_secret']
            )
            self.logger.debug(f"Published info event {event_id} to {client_pubkey}")

    def publish_notification_event(self, content: dict):
        """
        https://github.com/nostr-protocol/nips/blob/75f246ed987c23c99d77bfa6aeeb1afb669e23f7/47.md#notification-events
        """
        self.logger.debug(f"Publishing notification event: {content}")
        for client_pubkey, connection in list(self.connections.items()):
            coro = self.taskgroup.spawn(aionostr._add_event(
                self.manager,
                kind=self.NOTIFICATION_EVENT_KIND,
                tags=[['p', client_pubkey]],
                content=self.encrypt_to_pubkey(json.dumps(content), client_pubkey),
                private_key=connection['our_secret']
                )
            )
            asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())

    def encrypt_to_pubkey(self, msg: str, pubkey: str) -> str:
        """
        Encrypts the given message to the given pubkey using the connection secret.
        """
        our_secret: str = self.connections[pubkey]['our_secret']
        our_secret_key = PrivateKey(raw_secret=bytes.fromhex(our_secret))
        encrypted_content: str = our_secret_key.encrypt_message(msg, pubkey)
        return encrypted_content

    def get_payment_info(self, payment_hash: str) \
        -> Optional[Tuple[PaymentDirection, int, Optional[int], int]]:
        payment_hash: bytes = bytes.fromhex(payment_hash)
        payments = self.wallet.lnworker.get_payments(status='settled')
        plist = payments.get(payment_hash)
        if plist:
            info = self.wallet.lnworker.get_payment_info(payment_hash)
            if info:
                dir, amount, fee, ts = self.wallet.lnworker.get_payment_value(info, plist)
                fee = abs(fee) if fee else None
                return dir, abs(amount), fee, ts
        return None

    def is_receive_only(self, pubkey: str) -> bool:
        return self.connections[pubkey].get('daily_limit_sat') == 0
