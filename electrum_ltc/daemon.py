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
import ast
import os
import time
import traceback
import sys

# from jsonrpc import JSONRPCResponseManager
import jsonrpclib
from .jsonrpc import VerifyingJSONRPCServer

from .version import ELECTRUM_VERSION
from .network import Network
from .util import json_decode, DaemonThread
from .util import print_error, to_string
from .wallet import Wallet
from .storage import WalletStorage
from .commands import known_commands, Commands
from .simple_config import SimpleConfig
from .exchange_rate import FxThread
from .plugin import run_hook


def get_lockfile(config):
    return os.path.join(config.path, 'daemon')


def remove_lockfile(lockfile):
    os.unlink(lockfile)


def get_fd_or_server(config):
    '''Tries to create the lockfile, using O_EXCL to
    prevent races.  If it succeeds it returns the FD.
    Otherwise try and connect to the server specified in the lockfile.
    If this succeeds, the server is returned.  Otherwise remove the
    lockfile and try again.'''
    lockfile = get_lockfile(config)
    while True:
        try:
            return os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644), None
        except OSError:
            pass
        server = get_server(config)
        if server is not None:
            return None, server
        # Couldn't connect; remove lockfile and try again.
        remove_lockfile(lockfile)


def get_server(config):
    lockfile = get_lockfile(config)
    while True:
        create_time = None
        try:
            with open(lockfile) as f:
                (host, port), create_time = ast.literal_eval(f.read())
                rpc_user, rpc_password = get_rpc_credentials(config)
                if rpc_password == '':
                    # authentication disabled
                    server_url = 'http://%s:%d' % (host, port)
                else:
                    server_url = 'http://%s:%s@%s:%d' % (
                        rpc_user, rpc_password, host, port)
                server = jsonrpclib.Server(server_url)
            # Test daemon is running
            server.ping()
            return server
        except Exception as e:
            print_error("[get_server]", e)
        if not create_time or create_time < time.time() - 1.0:
            return None
        # Sleep a bit and try again; it might have just been started
        time.sleep(1.0)


def get_rpc_credentials(config):
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
        from .util import print_stderr
        print_stderr('WARNING: RPC authentication is disabled.')
    return rpc_user, rpc_password


class Daemon(DaemonThread):

    def __init__(self, config, fd, is_gui):
        DaemonThread.__init__(self)
        self.config = config
        if config.get('offline'):
            self.network = None
        else:
            self.network = Network(config)
            self.network.start()
        self.fx = FxThread(config, self.network)
        if self.network:
            self.network.add_jobs([self.fx])
        self.gui = None
        self.wallets = {}
        # Setup JSONRPC server
        self.init_server(config, fd, is_gui)

    def init_server(self, config, fd, is_gui):
        host = config.get('rpchost', '127.0.0.1')
        port = config.get('rpcport', 0)

        rpc_user, rpc_password = get_rpc_credentials(config)
        try:
            server = VerifyingJSONRPCServer((host, port), logRequests=False,
                                            rpc_user=rpc_user, rpc_password=rpc_password)
        except Exception as e:
            self.print_error('Warning: cannot initialize RPC server on host', host, e)
            self.server = None
            os.close(fd)
            return
        os.write(fd, bytes(repr((server.socket.getsockname(), time.time())), 'utf8'))
        os.close(fd)
        self.server = server
        server.timeout = 0.1
        server.register_function(self.ping, 'ping')
        if is_gui:
            server.register_function(self.run_gui, 'gui')
        else:
            server.register_function(self.run_daemon, 'daemon')
            self.cmd_runner = Commands(self.config, None, self.network)
            for cmdname in known_commands:
                server.register_function(getattr(self.cmd_runner, cmdname), cmdname)
            server.register_function(self.run_cmdline, 'run_cmdline')

    def ping(self):
        return True

    def run_daemon(self, config_options):
        config = SimpleConfig(config_options)
        sub = config.get('subcommand')
        assert sub in [None, 'start', 'stop', 'status', 'load_wallet', 'close_wallet']
        if sub in [None, 'start']:
            response = "Daemon already running"
        elif sub == 'load_wallet':
            path = config.get_wallet_path()
            wallet = self.load_wallet(path, config.get('password'))
            if wallet is not None:
                self.cmd_runner.wallet = wallet
                run_hook('load_wallet', wallet, None)
            response = wallet is not None
        elif sub == 'close_wallet':
            path = config.get_wallet_path()
            if path in self.wallets:
                self.stop_wallet(path)
                response = True
            else:
                response = False
        elif sub == 'status':
            if self.network:
                p = self.network.get_parameters()
                current_wallet = self.cmd_runner.wallet
                current_wallet_path = current_wallet.storage.path \
                                      if current_wallet else None
                response = {
                    'path': self.network.config.path,
                    'server': p[0],
                    'blockchain_height': self.network.get_local_height(),
                    'server_height': self.network.get_server_height(),
                    'spv_nodes': len(self.network.get_interfaces()),
                    'connected': self.network.is_connected(),
                    'auto_connect': p[4],
                    'version': ELECTRUM_VERSION,
                    'wallets': {k: w.is_up_to_date()
                                for k, w in self.wallets.items()},
                    'current_wallet': current_wallet_path,
                    'fee_per_kb': self.config.fee_per_kb(),
                }
            else:
                response = "Daemon offline"
        elif sub == 'stop':
            self.stop()
            response = "Daemon stopped"
        return response

    def run_gui(self, config_options):
        config = SimpleConfig(config_options)
        if self.gui:
            #if hasattr(self.gui, 'new_window'):
            #    path = config.get_wallet_path()
            #    self.gui.new_window(path, config.get('url'))
            #    response = "ok"
            #else:
            #    response = "error: current GUI does not support multiple windows"
            response = "error: Electrum GUI already running"
        else:
            response = "Error: Electrum is running in daemon mode. Please stop the daemon first."
        return response

    def load_wallet(self, path, password):
        # wizard will be launched if we return
        if path in self.wallets:
            wallet = self.wallets[path]
            return wallet
        storage = WalletStorage(path, manual_upgrades=True)
        if not storage.file_exists():
            return
        if storage.is_encrypted():
            if not password:
                return
            storage.decrypt(password)
        if storage.requires_split():
            return
        if storage.get_action():
            return
        wallet = Wallet(storage)
        wallet.start_threads(self.network)
        self.wallets[path] = wallet
        return wallet

    def add_wallet(self, wallet):
        path = wallet.storage.path
        self.wallets[path] = wallet

    def get_wallet(self, path):
        return self.wallets.get(path)

    def stop_wallet(self, path):
        wallet = self.wallets.pop(path)
        wallet.stop_threads()

    def run_cmdline(self, config_options):
        password = config_options.get('password')
        new_password = config_options.get('new_password')
        config = SimpleConfig(config_options)
        # FIXME this is ugly...
        config.fee_estimates = self.network.config.fee_estimates.copy()
        config.mempool_fees  = self.network.config.mempool_fees.copy()
        cmdname = config.get('cmd')
        cmd = known_commands[cmdname]
        if cmd.requires_wallet:
            path = config.get_wallet_path()
            wallet = self.wallets.get(path)
            if wallet is None:
                return {'error': 'Wallet "%s" is not loaded. Use "electrum-ltc daemon load_wallet"'%os.path.basename(path) }
        else:
            wallet = None
        # arguments passed to function
        args = map(lambda x: config.get(x), cmd.params)
        # decode json arguments
        args = [json_decode(i) for i in args]
        # options
        kwargs = {}
        for x in cmd.options:
            kwargs[x] = (config_options.get(x) if x in ['password', 'new_password'] else config.get(x))
        cmd_runner = Commands(config, wallet, self.network)
        func = getattr(cmd_runner, cmd.name)
        result = func(*args, **kwargs)
        return result

    def run(self):
        while self.is_running():
            self.server.handle_request() if self.server else time.sleep(0.1)
        for k, wallet in self.wallets.items():
            wallet.stop_threads()
        if self.network:
            self.print_error("shutting down network")
            self.network.stop()
            self.network.join()
        self.on_stop()

    def stop(self):
        self.print_error("stopping, removing lockfile")
        remove_lockfile(get_lockfile(self.config))
        DaemonThread.stop(self)

    def init_gui(self, config, plugins):
        gui_name = config.get('gui', 'qt')
        if gui_name in ['lite', 'classic']:
            gui_name = 'qt'
        gui = __import__('electrum_ltc.gui.' + gui_name, fromlist=['electrum_ltc'])
        self.gui = gui.ElectrumGui(config, self, plugins)
        try:
            self.gui.main()
        except BaseException as e:
            traceback.print_exc(file=sys.stdout)
            # app will exit now
