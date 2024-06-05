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
import errno
import os
import time
import traceback
import sys
import threading
from typing import Dict, Optional, Tuple, Iterable, Callable, Union, Sequence, Mapping, TYPE_CHECKING
from base64 import b64decode, b64encode
from collections import defaultdict
import json
import socket
from enum import IntEnum

import aiohttp
from aiohttp import web, client_exceptions
from aiorpcx import timeout_after, TaskTimeout, ignore_after

from . import util
from .network import Network
from .util import (json_decode, to_bytes, to_string, profiler, standardize_path, constant_time_compare, InvalidPassword)
from .invoices import PR_PAID, PR_EXPIRED
from .util import log_exceptions, ignore_exceptions, randrange, OldTaskGroup, UserFacingException, JsonRPCError
from .util import EventListener, event_listener, traceback_format_exception
from .wallet import Wallet, Abstract_Wallet
from .storage import WalletStorage
from .wallet_db import WalletDB, WalletRequiresSplit, WalletRequiresUpgrade, WalletUnfinished
from .commands import known_commands, Commands
from .simple_config import SimpleConfig
from .exchange_rate import FxThread
from .logging import get_logger, Logger
from . import GuiImportError
from .plugin import run_hook, Plugins

if TYPE_CHECKING:
    from electrum import gui


_logger = get_logger(__name__)


class DaemonNotRunning(Exception):
    pass

def get_rpcsock_defaultpath(config: SimpleConfig):
    return os.path.join(config.path, 'daemon_rpc_socket')

def get_rpcsock_default_type(config: SimpleConfig):
    if config.RPC_PORT:
        return 'tcp'
    # Use unix domain sockets when available,
    # with the extra paranoia that in case windows "implements" them,
    # we want to test it before making it the default there.
    if hasattr(socket, 'AF_UNIX') and sys.platform != 'win32':
        return 'unix'
    return 'tcp'

def get_lockfile(config: SimpleConfig):
    return os.path.join(config.path, 'daemon')

def remove_lockfile(lockfile):
    os.unlink(lockfile)


def get_file_descriptor(config: SimpleConfig):
    '''Tries to create the lockfile, using O_EXCL to
    prevent races.  If it succeeds, it returns the FD.
    Otherwise, try and connect to the server specified in the lockfile.
    If this succeeds, the server is returned.  Otherwise, remove the
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



def request(config: SimpleConfig, endpoint, args=(), timeout: Union[float, int] = 60):
    lockfile = get_lockfile(config)
    while True:
        create_time = None
        path = None
        try:
            with open(lockfile) as f:
                socktype, address, create_time = ast.literal_eval(f.read())
                if socktype == 'unix':
                    path = address
                    (host, port) = "127.0.0.1", 0
                    # We still need a host and port for e.g. HTTP Host header
                elif socktype == 'tcp':
                    (host, port) = address
                else:
                    raise Exception(f"corrupt lockfile; socktype={socktype!r}")
        except Exception:
            raise DaemonNotRunning()
        rpc_user, rpc_password = get_rpc_credentials(config)
        server_url = 'http://%s:%d' % (host, port)
        auth = aiohttp.BasicAuth(login=rpc_user, password=rpc_password)
        loop = util.get_asyncio_loop()
        async def request_coroutine(
            *, socktype=socktype, path=path, auth=auth, server_url=server_url, endpoint=endpoint,
        ):
            if socktype == 'unix':
                connector = aiohttp.UnixConnector(path=path)
            elif socktype == 'tcp':
                connector = None # This will transform into TCP.
            else:
                raise Exception(f"impossible socktype ({socktype!r})")
            async with aiohttp.ClientSession(auth=auth, connector=connector) as session:
                c = util.JsonRPCClient(session, server_url)
                return await c.request(endpoint, *args)
        try:
            fut = asyncio.run_coroutine_threadsafe(request_coroutine(), loop)
            return fut.result(timeout=timeout)
        except aiohttp.client_exceptions.ClientConnectorError as e:
            _logger.info(f"failed to connect to JSON-RPC server {e}")
            if not create_time or create_time < time.time() - 1.0:
                raise DaemonNotRunning()
        # Sleep a bit and try again; it might have just been started
        time.sleep(1.0)


def wait_until_daemon_becomes_ready(*, config: SimpleConfig, timeout=5) -> bool:
    t0 = time.monotonic()
    while True:
        if time.monotonic() > t0 + timeout:
            return False  # timeout
        try:
            request(config, 'ping')
            return True  # success
        except DaemonNotRunning:
            time.sleep(0.05)
            continue


def get_rpc_credentials(config: SimpleConfig) -> Tuple[str, str]:
    rpc_user = config.RPC_USERNAME or None
    rpc_password = config.RPC_PASSWORD or None
    if rpc_user is None or rpc_password is None:
        rpc_user = 'user'
        bits = 128
        nbytes = bits // 8 + (bits % 8 > 0)
        pw_int = randrange(pow(2, bits))
        pw_b64 = b64encode(
            pw_int.to_bytes(nbytes, 'big'), b'-_')
        rpc_password = to_string(pw_b64, 'ascii')
        config.RPC_USERNAME = rpc_user
        config.RPC_PASSWORD = rpc_password
    return rpc_user, rpc_password


class AuthenticationError(Exception):
    pass

class AuthenticationInvalidOrMissing(AuthenticationError):
    pass

class AuthenticationCredentialsInvalid(AuthenticationError):
    pass

class AuthenticatedServer(Logger):

    def __init__(self, rpc_user, rpc_password):
        Logger.__init__(self)
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        self.auth_lock = asyncio.Lock()
        self._methods = {}  # type: Dict[str, Callable]

    def register_method(self, f):
        assert f.__name__ not in self._methods, f"name collision for {f.__name__}"
        self._methods[f.__name__] = f

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
        try:
            request = await request.text()
            request = json.loads(request)
            method = request['method']
            _id = request['id']
            params = request.get('params', [])  # type: Union[Sequence, Mapping]
            if method not in self._methods:
                raise Exception(f"attempting to use unregistered method: {method}")
            f = self._methods[method]
        except Exception as e:
            self.logger.exception("invalid request")
            return web.Response(text='Invalid Request', status=500)
        response = {
            'id': _id,
            'jsonrpc': '2.0',
        }
        try:
            if isinstance(params, dict):
                response['result'] = await f(**params)
            else:
                response['result'] = await f(*params)
        except UserFacingException as e:
            response['error'] = {
                'code': JsonRPCError.Codes.USERFACING,
                'message': str(e),
            }
        except BaseException as e:
            self.logger.exception("internal error while executing RPC")
            response['error'] = {
                'code': JsonRPCError.Codes.INTERNAL,
                'message': "internal error while executing RPC",
                'data': {
                    "exception": repr(e),
                    "traceback": "".join(traceback_format_exception(e)),
                },
            }
        return web.json_response(response)


class CommandsServer(AuthenticatedServer):

    def __init__(self, daemon: 'Daemon', fd):
        rpc_user, rpc_password = get_rpc_credentials(daemon.config)
        AuthenticatedServer.__init__(self, rpc_user, rpc_password)
        self.daemon = daemon
        self.fd = fd
        self.config = daemon.config
        sockettype = self.config.RPC_SOCKET_TYPE
        self.socktype = sockettype if sockettype != 'auto' else get_rpcsock_default_type(self.config)
        self.sockpath = self.config.RPC_SOCKET_FILEPATH or get_rpcsock_defaultpath(self.config)
        self.host = self.config.RPC_HOST
        self.port = self.config.RPC_PORT
        self.app = web.Application()
        self.app.router.add_post("/", self.handle)
        self.register_method(self.ping)
        self.register_method(self.gui)
        self.cmd_runner = Commands(config=self.config, network=self.daemon.network, daemon=self.daemon)
        for cmdname in known_commands:
            self.register_method(getattr(self.cmd_runner, cmdname))
        self.register_method(self.run_cmdline)

    def _socket_config_str(self) -> str:
        if self.socktype == 'unix':
            return f"<socket type={self.socktype}, path={self.sockpath}>"
        elif self.socktype == 'tcp':
            return f"<socket type={self.socktype}, host={self.host}, port={self.port}>"
        else:
            raise Exception(f"unknown socktype '{self.socktype!r}'")

    async def run(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        if self.socktype == 'unix':
            site = web.UnixSite(self.runner, self.sockpath)
        elif self.socktype == 'tcp':
            site = web.TCPSite(self.runner, self.host, self.port)
        else:
            raise Exception(f"unknown socktype '{self.socktype!r}'")
        try:
            await site.start()
        except Exception as e:
            raise Exception(f"failed to start CommandsServer at {self._socket_config_str()}. got exc: {e!r}") from None
        socket = site._server.sockets[0]
        if self.socktype == 'unix':
            addr = self.sockpath
        elif self.socktype == 'tcp':
            addr = socket.getsockname()
        else:
            raise Exception(f"impossible socktype ({self.socktype!r})")
        os.write(self.fd, bytes(repr((self.socktype, addr, time.time())), 'utf8'))
        os.close(self.fd)
        self.logger.info(f"now running and listening. socktype={self.socktype}, addr={addr}")

    async def ping(self):
        return True

    async def gui(self, config_options):
        # note: "config_options" is coming from the short-lived CLI-invocation,
        #        while self.config is the config of the long-lived daemon process.
        #       "config_options" should have priority.
        if self.daemon.gui_object:
            if hasattr(self.daemon.gui_object, 'new_window'):
                path = config_options.get('wallet_path') or self.config.get_wallet_path(use_gui_last_wallet=True)
                self.daemon.gui_object.new_window(path, config_options.get('url'))
                return True
            else:
                raise UserFacingException("error: current GUI does not support multiple windows")
        else:
            raise UserFacingException("error: Electrum is running in daemon mode. Please stop the daemon first.")

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
        if 'wallet_path' in cmd.options:
            kwargs['wallet_path'] = config_options.get('wallet_path')
        elif 'wallet' in cmd.options:
            kwargs['wallet'] = config_options.get('wallet_path')
        func = getattr(self.cmd_runner, cmd.name)
        # execute requested command now.  note: cmd can raise, the caller (self.handle) will wrap it.
        result = await func(*args, **kwargs)
        return result


class WatchTowerServer(AuthenticatedServer):

    def __init__(self, network: 'Network', port:int):
        self.port = port
        self.config = network.config
        self.network = network
        watchtower_user = self.config.WATCHTOWER_SERVER_USER or ""
        watchtower_password = self.config.WATCHTOWER_SERVER_PASSWORD or ""
        AuthenticatedServer.__init__(self, watchtower_user, watchtower_password)
        self.lnwatcher = network.local_watchtower
        self.app = web.Application()
        self.app.router.add_post("/", self.handle)
        self.register_method(self.get_ctn)
        self.register_method(self.add_sweep_tx)

    async def run(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, host='localhost', port=self.port)
        await site.start()
        self.logger.info(f"running and listening on port {self.port}")

    async def get_ctn(self, *args):
        return await self.lnwatcher.get_ctn(*args)

    async def add_sweep_tx(self, *args):
        return await self.lnwatcher.sweepstore.add_sweep_tx(*args)




class Daemon(Logger):

    network: Optional[Network] = None
    gui_object: Optional['gui.BaseElectrumGui'] = None
    watchtower: Optional['WatchTowerServer'] = None

    @profiler
    def __init__(
        self,
        config: SimpleConfig,
        fd=None,
        *,
        listen_jsonrpc: bool = True,
        start_network: bool = True,  # setting to False allows customising network settings before starting it
    ):
        Logger.__init__(self)
        self.config = config
        self.listen_jsonrpc = listen_jsonrpc
        if fd is None and listen_jsonrpc:
            fd = get_file_descriptor(config)
            if fd is None:
                raise Exception('failed to lock daemon; already running?')
        if 'wallet_path' in config.cmdline_options:
            self.logger.warning("Ignoring parameter 'wallet_path' for daemon. "
                                "Use the load_wallet command instead.")
        self._plugins = None  # type: Optional[Plugins]
        self.asyncio_loop = util.get_asyncio_loop()
        if not self.config.NETWORK_OFFLINE:
            self.network = Network(config, daemon=self)
        self.fx = FxThread(config=config)
        # wallet_key -> wallet
        self._wallets = {}  # type: Dict[str, Abstract_Wallet]
        self._wallet_lock = threading.RLock()

        self._stop_entered = False
        self._stopping_soon_or_errored = threading.Event()
        self._stopped_event = threading.Event()

        self.taskgroup = OldTaskGroup()
        asyncio.run_coroutine_threadsafe(self._run(), self.asyncio_loop)
        if start_network and self.network:
            self.start_network()
        # Setup commands server
        self.commands_server = None
        if listen_jsonrpc:
            self.commands_server = CommandsServer(self, fd)
            asyncio.run_coroutine_threadsafe(self.taskgroup.spawn(self.commands_server.run()), self.asyncio_loop)

    @log_exceptions
    async def _run(self):
        self.logger.info("starting taskgroup.")
        try:
            async with self.taskgroup as group:
                await group.spawn(asyncio.Event().wait)  # run forever (until cancel)
        except Exception as e:
            self.logger.exception("taskgroup died.")
            util.send_exception_to_crash_reporter(e)
        finally:
            self.logger.info("taskgroup stopped.")
            # note: we could just "await self.stop()", but in that case GUI users would
            #       not see the exception (especially if the GUI did not start yet).
            self._stopping_soon_or_errored.set()

    def start_network(self):
        self.logger.info(f"starting network.")
        assert not self.config.NETWORK_OFFLINE
        assert self.network
        # server-side watchtower
        if watchtower_port := self.config.WATCHTOWER_SERVER_PORT:
            self.watchtower = WatchTowerServer(self.network, watchtower_port)
            asyncio.run_coroutine_threadsafe(self.taskgroup.spawn(self.watchtower.run), self.asyncio_loop)

        self.network.start(jobs=[self.fx.run])
        # prepare lightning functionality, also load channel db early
        if self.config.LIGHTNING_USE_GOSSIP:
            self.network.start_gossip()

    @staticmethod
    def _wallet_key_from_path(path) -> str:
        """This does stricter path standardization than 'standardize_path'.
        It is used for keying the _wallets dict, but not for the actual filesystem operations. (see #8495)
        """
        path = standardize_path(path)
        # also resolve symlinks and windows network mounts/etc:
        path = os.path.realpath(path)
        path = os.path.normcase(path)
        return str(path)

    def with_wallet_lock(func):
        def func_wrapper(self: 'Daemon', *args, **kwargs):
            with self._wallet_lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    @with_wallet_lock
    def load_wallet(self, path, password, *, upgrade=False) -> Optional[Abstract_Wallet]:
        path = standardize_path(path)
        wallet_key = self._wallet_key_from_path(path)
        # wizard will be launched if we return
        if wallet := self._wallets.get(wallet_key):
            return wallet
        wallet = self._load_wallet(path, password, upgrade=upgrade, config=self.config)
        wallet.start_network(self.network)
        self.add_wallet(wallet)
        return wallet

    @staticmethod
    @profiler
    def _load_wallet(
            path,
            password,
            *,
            upgrade: bool = False,
            config: SimpleConfig,
    ) -> Optional[Abstract_Wallet]:
        path = standardize_path(path)
        storage = WalletStorage(path)
        if not storage.file_exists():
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        if storage.is_encrypted():
            if not password:
                raise InvalidPassword('No password given')
            storage.decrypt(password)
        # read data, pass it to db
        db = WalletDB(storage.read(), storage=storage, upgrade=upgrade)
        if db.get_action():
            raise WalletUnfinished(db)
        wallet = Wallet(db, config=config)
        return wallet

    @with_wallet_lock
    def add_wallet(self, wallet: Abstract_Wallet) -> None:
        path = wallet.storage.path
        wallet_key = self._wallet_key_from_path(path)
        self._wallets[wallet_key] = wallet
        run_hook('daemon_wallet_loaded', self, wallet)

    def get_wallet(self, path: str) -> Optional[Abstract_Wallet]:
        wallet_key = self._wallet_key_from_path(path)
        return self._wallets.get(wallet_key)

    @with_wallet_lock
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
        # note: this must not be called from the event loop. # TODO raise if so
        fut = asyncio.run_coroutine_threadsafe(self._stop_wallet(path), self.asyncio_loop)
        return fut.result()

    @with_wallet_lock
    async def _stop_wallet(self, path: str) -> bool:
        """Returns True iff a wallet was found."""
        wallet_key = self._wallet_key_from_path(path)
        wallet = self._wallets.pop(wallet_key, None)
        if not wallet:
            return False
        await wallet.stop()
        return True

    def run_daemon(self):
        # init plugins
        self._plugins = Plugins(self.config, 'cmdline')
        # block until we are stopping
        try:
            self._stopping_soon_or_errored.wait()
        except KeyboardInterrupt:
            self.logger.info("got KeyboardInterrupt")
        # we either initiate shutdown now,
        # or it has already been initiated (in which case this is a no-op):
        self.logger.info("run_daemon is calling stop()")
        asyncio.run_coroutine_threadsafe(self.stop(), self.asyncio_loop).result()
        # wait until "stop" finishes:
        self._stopped_event.wait()

    async def stop(self):
        if self._stop_entered:
            return
        self._stop_entered = True
        self._stopping_soon_or_errored.set()
        self.logger.info("stop() entered. initiating shutdown")
        try:
            if self.gui_object:
                self.gui_object.stop()
            self.logger.info("stopping all wallets")
            async with OldTaskGroup() as group:
                for k, wallet in self._wallets.items():
                    await group.spawn(wallet.stop())
            self.logger.info("stopping network and taskgroup")
            async with ignore_after(2):
                async with OldTaskGroup() as group:
                    if self.network:
                        await group.spawn(self.network.stop(full_shutdown=True))
                    await group.spawn(self.taskgroup.cancel_remaining())
            if self._plugins:
                self.logger.info("stopping plugins")
                self._plugins.stop()
                async with ignore_after(1):
                    await self._plugins.stopped_event_async.wait()
        finally:
            if self.listen_jsonrpc:
                self.logger.info("removing lockfile")
                remove_lockfile(get_lockfile(self.config))
            self.logger.info("stopped")
            self._stopped_event.set()

    def run_gui(self) -> None:
        assert self.config
        threading.current_thread().name = 'GUI'
        gui_name = self.config.GUI_NAME
        if gui_name in ['lite', 'classic']:
            gui_name = 'qt'
        self._plugins = Plugins(self.config, gui_name)  # init plugins
        self.logger.info(f'launching GUI: {gui_name}')
        try:
            try:
                gui = __import__('electrum.gui.' + gui_name, fromlist=['electrum'])
            except GuiImportError as e:
                sys.exit(str(e))
            self.gui_object = gui.ElectrumGui(config=self.config, daemon=self, plugins=self._plugins)
            if not self._stop_entered:
                self.gui_object.main()
            else:
                # If daemon.stop() was called before gui_object got created, stop gui now.
                self.gui_object.stop()
        except BaseException as e:
            self.logger.error(f'GUI raised exception: {repr(e)}. shutting down.')
            raise
        finally:
            # app will exit now
            asyncio.run_coroutine_threadsafe(self.stop(), self.asyncio_loop).result()

    @with_wallet_lock
    def _check_password_for_directory(self, *, old_password, new_password=None, wallet_dir: str) -> Tuple[bool, bool]:
        """Checks password against all wallets (in dir), returns whether they can be unified and whether they are already.
        If new_password is not None, update all wallet passwords to new_password.
        """
        assert os.path.exists(wallet_dir), f"path {wallet_dir!r} does not exist"
        failed = []
        is_unified = True
        for filename in os.listdir(wallet_dir):
            path = os.path.join(wallet_dir, filename)
            path = standardize_path(path)
            if not os.path.isfile(path):
                continue
            wallet = self.get_wallet(path)
            # note: we only create a new wallet object if one was not loaded into the wallet already.
            #       This is to avoid having two wallet objects contending for the same file.
            #       Take care: this only works if the daemon knows about all wallet objects.
            #                  if other code already has created a Wallet() for a file but did not tell the daemon,
            #                  hard-to-understand bugs will follow...
            if wallet is None:
                try:
                    wallet = self._load_wallet(path, old_password, upgrade=True, config=self.config)
                except util.InvalidPassword:
                    pass
                except Exception:
                    self.logger.exception(f'failed to load wallet at {path!r}:')
            if wallet is None:
                failed.append(path)
                continue
            if not wallet.storage.is_encrypted():
                is_unified = False
            try:
                try:
                    wallet.check_password(old_password)
                    old_password_real = old_password
                except util.InvalidPassword:
                    wallet.check_password(None)
                    old_password_real = None
            except Exception:
                failed.append(path)
                continue
            if new_password:
                self.logger.info(f'updating password for wallet: {path!r}')
                wallet.update_password(old_password_real, new_password, encrypt_storage=True)
        can_be_unified = failed == []
        is_unified = can_be_unified and is_unified
        return can_be_unified, is_unified

    @with_wallet_lock
    def update_password_for_directory(
            self,
            *,
            old_password,
            new_password,
            wallet_dir: Optional[str] = None,
    ) -> bool:
        """returns whether password is unified"""
        if new_password is None:
            # we opened a non-encrypted wallet
            return False
        if wallet_dir is None:
            wallet_dir = os.path.dirname(self.config.get_wallet_path())
        can_be_unified, is_unified = self._check_password_for_directory(
            old_password=old_password, new_password=None, wallet_dir=wallet_dir)
        if not can_be_unified:
            return False
        if is_unified and old_password == new_password:
            return True
        self._check_password_for_directory(
            old_password=old_password, new_password=new_password, wallet_dir=wallet_dir)
        return True
