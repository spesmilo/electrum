#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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
import ast
import os
import time
import traceback
import sys
import threading
from typing import Dict, Optional, Tuple, Iterable
from base64 import b64decode
from collections import defaultdict

import aiohttp
from aiohttp import web, client_exceptions
import jsonrpcclient
import jsonrpcserver
from jsonrpcserver import response
from jsonrpcclient.clients.aiohttp_client import AiohttpClient
from aiorpcx import TaskGroup

from .network import Network
from .util import (json_decode, to_bytes, to_string, profiler, standardize_path, constant_time_compare)
from .util import PR_PAID, PR_EXPIRED, get_request_status
from .util import log_exceptions, ignore_exceptions
from .wallet import Wallet, Abstract_Wallet
from .storage import WalletStorage
from .commands import known_commands, Commands
from .simple_config import SimpleConfig
from .exchange_rate import FxThread
from .logging import get_logger, Logger


_logger = get_logger(__name__)


class DaemonNotRunning(Exception):
    pass

def get_lockfile(config: SimpleConfig):
    return os.path.join(config.path, 'daemon')


def remove_lockfile(lockfile):
    os.unlink(lockfile)


def get_file_descriptor(config: SimpleConfig):
    '''Tries to create the lockfile, using O_EXCL to
    prevent races.  If it succeeds it returns the FD.
    Otherwise try and connect to the server specified in the lockfile.
    If this succeeds, the server is returned.  Otherwise remove the
    lockfile and try again.'''
    lockfile = get_lockfile(config)
    while True:
        try:
            return os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except OSError:
            pass
        try:
            request(config, 'ping')
            return None
        except DaemonNotRunning:
            # Couldn't connect; remove lockfile and try again.
            remove_lockfile(lockfile)



def request(config: SimpleConfig, endpoint, args=(), timeout=60):
    lockfile = get_lockfile(config)
    while True:
        create_time = None
        try:
            with open(lockfile) as f:
                (host, port), create_time = ast.literal_eval(f.read())
        except Exception:
            raise DaemonNotRunning()
        rpc_user, rpc_password = get_rpc_credentials(config)
        server_url = 'http://%s:%d' % (host, port)
        auth = aiohttp.BasicAuth(login=rpc_user, password=rpc_password)
        loop = asyncio.get_event_loop()
        async def request_coroutine():
            async with aiohttp.ClientSession(auth=auth) as session:
                server = AiohttpClient(session, server_url)
                f = getattr(server, endpoint)
                response = await f(*args)
                return response.data.result
        try:
            fut = asyncio.run_coroutine_threadsafe(request_coroutine(), loop)
            return fut.result(timeout=timeout)
        except aiohttp.client_exceptions.ClientConnectorError as e:
            _logger.info(f"failed to connect to JSON-RPC server {e}")
            if not create_time or create_time < time.time() - 1.0:
                raise DaemonNotRunning()
        # Sleep a bit and try again; it might have just been started
        time.sleep(1.0)


def get_rpc_credentials(config: SimpleConfig) -> Tuple[str, str]:
    rpc_user = config.get('rpcuser', None)
    rpc_password = config.get('rpcpassword', None)
    if rpc_user is None or rpc_password is None:
        rpc_user = 'user'
        import ecdsa, base64
        bits = 128
        nbytes = bits // 8 + (bits % 8 > 0)
        pw_int = ecdsa.util.randrange(pow(2, bits))
        pw_b64 = base64.b64encode(
            pw_int.to_bytes(nbytes, 'big'), b'-_')
        rpc_password = to_string(pw_b64, 'ascii')
        config.set_key('rpcuser', rpc_user)
        config.set_key('rpcpassword', rpc_password, save=True)
    elif rpc_password == '':
        _logger.warning('RPC authentication is disabled.')
    return rpc_user, rpc_password


class WatchTowerServer(Logger):

    def __init__(self, network):
        Logger.__init__(self)
        self.config = network.config
        self.network = network
        self.lnwatcher = network.local_watchtower
        self.app = web.Application()
        self.app.router.add_post("/", self.handle)
        self.methods = jsonrpcserver.methods.Methods()
        self.methods.add(self.get_ctn)
        self.methods.add(self.add_sweep_tx)

    async def handle(self, request):
        request = await request.text()
        self.logger.info(f'{request}')
        response = await jsonrpcserver.async_dispatch(request, methods=self.methods)
        if response.wanted:
            return web.json_response(response.deserialized(), status=response.http_status)
        else:
            return web.Response()

    async def run(self):
        host = self.config.get('watchtower_host')
        port = self.config.get('watchtower_port', 12345)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, host, port, ssl_context=self.config.get_ssl_context())
        await site.start()

    async def get_ctn(self, *args):
        return await self.lnwatcher.sweepstore.get_ctn(*args)

    async def add_sweep_tx(self, *args):
        return await self.lnwatcher.sweepstore.add_sweep_tx(*args)


class PayServer(Logger):

    def __init__(self, daemon: 'Daemon'):
        Logger.__init__(self)
        self.daemon = daemon
        self.config = daemon.config
        self.pending = defaultdict(asyncio.Event)
        self.daemon.network.register_callback(self.on_payment, ['payment_received'])

    async def on_payment(self, evt, wallet, key, status):
        if status == PR_PAID:
            await self.pending[key].set()

    @ignore_exceptions
    @log_exceptions
    async def run(self):
        host = self.config.get('payserver_host', 'localhost')
        port = self.config.get('payserver_port')
        root = self.config.get('payserver_root', '/r')
        app = web.Application()
        app.add_routes([web.post('/api/create_invoice', self.create_request)])
        app.add_routes([web.get('/api/get_invoice', self.get_request)])
        app.add_routes([web.get('/api/get_status', self.get_status)])
        app.add_routes([web.get('/bip70/{key}.bip70', self.get_bip70_request)])
        app.add_routes([web.static(root, 'electrum/www')])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, port=port, host=host, ssl_context=self.config.get_ssl_context())
        await site.start()

    async def create_request(self, request):
        params = await request.post()
        wallet = self.daemon.wallet
        if 'amount_sat' not in params or not params['amount_sat'].isdigit():
            raise web.HTTPUnsupportedMediaType()
        amount = int(params['amount_sat'])
        message = params['message'] or "donation"
        payment_hash = await wallet.lnworker._add_invoice_coro(amount, message, 3600)
        key = payment_hash.hex()
        raise web.HTTPFound(self.root + '/pay?id=' + key)

    async def get_request(self, r):
        key = r.query_string
        request = self.daemon.wallet.get_request(key)
        return web.json_response(request)

    async def get_bip70_request(self, r):
        from .paymentrequest import make_request
        key = r.match_info['key']
        request = self.daemon.wallet.get_request(key)
        if not request:
            return web.HTTPNotFound()
        pr = make_request(self.config, request)
        return web.Response(body=pr.SerializeToString(), content_type='application/bitcoin-paymentrequest')

    async def get_status(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        key = request.query_string
        info = self.daemon.wallet.get_request(key)
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


class AuthenticationError(Exception):
    pass

class AuthenticationInvalidOrMissing(AuthenticationError):
    pass

class AuthenticationCredentialsInvalid(AuthenticationError):
    pass

class Daemon(Logger):

    @profiler
    def __init__(self, config: SimpleConfig, fd=None, *, listen_jsonrpc=True):
        Logger.__init__(self)
        self.auth_lock = asyncio.Lock()
        self.running = False
        self.running_lock = threading.Lock()
        self.config = config
        if fd is None and listen_jsonrpc:
            fd = get_file_descriptor(config)
            if fd is None:
                raise Exception('failed to lock daemon; already running?')
        self.asyncio_loop = asyncio.get_event_loop()
        self.network = None
        if not config.get('offline'):
            self.network = Network(config, daemon=self)
        self.fx = FxThread(config, self.network)
        self.gui_object = None
        # path -> wallet;   make sure path is standardized.
        self._wallets = {}  # type: Dict[str, Abstract_Wallet]
        daemon_jobs = []
        # Setup JSONRPC server
        if listen_jsonrpc:
            daemon_jobs.append(self.start_jsonrpc(config, fd))
        # request server
        self.pay_server = None
        if not config.get('offline') and self.config.get('run_payserver'):
            self.pay_server = PayServer(self)
            daemon_jobs.append(self.pay_server.run())
        # server-side watchtower
        self.watchtower = None
        if not config.get('offline') and self.config.get('run_watchtower'):
            self.watchtower = WatchTowerServer(self.network)
            daemon_jobs.append(self.watchtower.run)
        if self.network:
            self.network.start(jobs=[self.fx.run])

        self.taskgroup = TaskGroup()
        asyncio.run_coroutine_threadsafe(self._run(jobs=daemon_jobs), self.asyncio_loop)

    @log_exceptions
    async def _run(self, jobs: Iterable = None):
        if jobs is None:
            jobs = []
        try:
            async with self.taskgroup as group:
                [await group.spawn(job) for job in jobs]
                await group.spawn(asyncio.Event().wait)  # run forever (until cancel)
        except BaseException as e:
            self.logger.exception('daemon.taskgroup died.')
        finally:
            self.logger.info("stopping daemon.taskgroup")

    async def authenticate(self, headers):
        if self.rpc_password == '':
            # RPC authentication is disabled
            return
        auth_string = headers.get('Authorization', None)
        if auth_string is None:
            raise AuthenticationInvalidOrMissing('CredentialsMissing')
        basic, _, encoded = auth_string.partition(' ')
        if basic != 'Basic':
            raise AuthenticationInvalidOrMissing('UnsupportedType')
        encoded = to_bytes(encoded, 'utf8')
        credentials = to_string(b64decode(encoded), 'utf8')
        username, _, password = credentials.partition(':')
        if not (constant_time_compare(username, self.rpc_user)
                and constant_time_compare(password, self.rpc_password)):
            await asyncio.sleep(0.050)
            raise AuthenticationCredentialsInvalid('Invalid Credentials')

    async def handle(self, request):
        async with self.auth_lock:
            try:
                await self.authenticate(request.headers)
            except AuthenticationInvalidOrMissing:
                return web.Response(headers={"WWW-Authenticate": "Basic realm=Electrum"},
                                    text='Unauthorized', status=401)
            except AuthenticationCredentialsInvalid:
                return web.Response(text='Forbidden', status=403)
        request = await request.text()
        response = await jsonrpcserver.async_dispatch(request, methods=self.methods)
        if isinstance(response, jsonrpcserver.response.ExceptionResponse):
            self.logger.error(f"error handling request: {request}", exc_info=response.exc)
            # this exposes the error message to the client
            response.message = str(response.exc)
        if response.wanted:
            return web.json_response(response.deserialized(), status=response.http_status)
        else:
            return web.Response()

    async def start_jsonrpc(self, config: SimpleConfig, fd):
        self.app = web.Application()
        self.app.router.add_post("/", self.handle)
        self.rpc_user, self.rpc_password = get_rpc_credentials(config)
        self.methods = jsonrpcserver.methods.Methods()
        self.methods.add(self.ping)
        self.methods.add(self.gui)
        self.cmd_runner = Commands(config=self.config, network=self.network, daemon=self)
        for cmdname in known_commands:
            self.methods.add(getattr(self.cmd_runner, cmdname))
        self.methods.add(self.run_cmdline)
        self.host = config.get('rpchost', '127.0.0.1')
        self.port = config.get('rpcport', 0)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()
        socket = site._server.sockets[0]
        os.write(fd, bytes(repr((socket.getsockname(), time.time())), 'utf8'))
        os.close(fd)

    async def ping(self):
        return True

    async def gui(self, config_options):
        if self.gui_object:
            if hasattr(self.gui_object, 'new_window'):
                path = self.config.get_wallet_path(use_gui_last_wallet=True)
                self.gui_object.new_window(path, config_options.get('url'))
                response = "ok"
            else:
                response = "error: current GUI does not support multiple windows"
        else:
            response = "Error: Electrum is running in daemon mode. Please stop the daemon first."
        return response

    def load_wallet(self, path, password, *, manual_upgrades=True) -> Optional[Abstract_Wallet]:
        path = standardize_path(path)
        # wizard will be launched if we return
        if path in self._wallets:
            wallet = self._wallets[path]
            return wallet
        storage = WalletStorage(path, manual_upgrades=manual_upgrades)
        if not storage.file_exists():
            return
        if storage.is_encrypted():
            if not password:
                return
            storage.decrypt(password)
        if storage.requires_split():
            return
        if storage.requires_upgrade():
            return
        if storage.get_action():
            return
        wallet = Wallet(storage, config=self.config)
        wallet.start_network(self.network)
        self._wallets[path] = wallet
        self.wallet = wallet
        return wallet

    def add_wallet(self, wallet: Abstract_Wallet) -> None:
        path = wallet.storage.path
        path = standardize_path(path)
        self._wallets[path] = wallet

    def get_wallet(self, path: str) -> Abstract_Wallet:
        path = standardize_path(path)
        return self._wallets.get(path)

    def get_wallets(self) -> Dict[str, Abstract_Wallet]:
        return dict(self._wallets)  # copy

    def delete_wallet(self, path: str) -> bool:
        self.stop_wallet(path)
        if os.path.exists(path):
            os.unlink(path)
            return True
        return False

    def stop_wallet(self, path: str) -> bool:
        """Returns True iff a wallet was found."""
        path = standardize_path(path)
        wallet = self._wallets.pop(path, None)
        if not wallet:
            return False
        wallet.stop_threads()
        return True

    async def run_cmdline(self, config_options):
        cmdname = config_options['cmd']
        cmd = known_commands[cmdname]
        # arguments passed to function
        args = [config_options.get(x) for x in cmd.params]
        # decode json arguments
        args = [json_decode(i) for i in args]
        # options
        kwargs = {}
        for x in cmd.options:
            kwargs[x] = config_options.get(x)
        if cmd.requires_wallet:
            kwargs['wallet_path'] = config_options.get('wallet_path')
        func = getattr(self.cmd_runner, cmd.name)
        # fixme: not sure how to retrieve message in jsonrpcclient
        try:
            result = await func(*args, **kwargs)
        except Exception as e:
            result = {'error':str(e)}
        return result

    def run_daemon(self):
        self.running = True
        try:
            while self.is_running():
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.running = False
        self.on_stop()

    def is_running(self):
        with self.running_lock:
            return self.running and not self.taskgroup.closed()

    def stop(self):
        with self.running_lock:
            self.running = False

    def on_stop(self):
        if self.gui_object:
            self.gui_object.stop()
        # stop network/wallets
        for k, wallet in self._wallets.items():
            wallet.stop_threads()
        if self.network:
            self.logger.info("shutting down network")
            self.network.stop()
        self.logger.info("stopping taskgroup")
        fut = asyncio.run_coroutine_threadsafe(self.taskgroup.cancel_remaining(), self.asyncio_loop)
        try:
            fut.result(timeout=2)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
        self.logger.info("removing lockfile")
        remove_lockfile(get_lockfile(self.config))
        self.logger.info("stopped")

    def run_gui(self, config, plugins):
        threading.current_thread().setName('GUI')
        gui_name = config.get('gui', 'qt')
        if gui_name in ['lite', 'classic']:
            gui_name = 'qt'
        self.logger.info(f'launching GUI: {gui_name}')
        gui = __import__('electrum.gui.' + gui_name, fromlist=['electrum'])
        self.gui_object = gui.ElectrumGui(config, self, plugins)
        try:
            self.gui_object.main()
        except BaseException as e:
            self.logger.exception('')
            # app will exit now
        self.on_stop()
