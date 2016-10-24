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
import sys
import time

import jsonrpclib
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer, SimpleJSONRPCRequestHandler

from version import ELECTRUM_VERSION
from network import Network
from util import json_decode, DaemonThread
from util import print_msg, print_error, print_stderr
from wallet import WalletStorage, Wallet
from commands import known_commands, Commands
from simple_config import SimpleConfig
from plugins import run_hook

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
            return os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY), None
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
                server = jsonrpclib.Server('http://%s:%d' % (host, port))
            # Test daemon is running
            server.ping()
            return server
        except:
            pass
        if not create_time or create_time < time.time() - 1.0:
            return None
        # Sleep a bit and try again; it might have just been started
        time.sleep(1.0)



class RequestHandler(SimpleJSONRPCRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def end_headers(self):
        self.send_header("Access-Control-Allow-Headers",
                         "Origin, X-Requested-With, Content-Type, Accept")
        self.send_header("Access-Control-Allow-Origin", "*")
        SimpleJSONRPCRequestHandler.end_headers(self)


class Daemon(DaemonThread):

    def __init__(self, config, fd):

        DaemonThread.__init__(self)
        self.config = config
        if config.get('offline'):
            self.network = None
        else:
            self.network = Network(config)
            self.network.start()
        self.gui = None
        self.wallets = {}
        # Setup JSONRPC server
        path = config.get_wallet_path()
        default_wallet = self.load_wallet(path)
        self.cmd_runner = Commands(self.config, default_wallet, self.network)
        self.init_server(config, fd)

    def init_server(self, config, fd):
        host = config.get('rpchost', '127.0.0.1')
        port = config.get('rpcport', 0)
        try:
            server = SimpleJSONRPCServer((host, port), logRequests=False,
                                         requestHandler=RequestHandler)
        except:
            self.print_error('Warning: cannot initialize RPC server on host', host)
            self.server = None
            os.close(fd)
            return
        os.write(fd, repr((server.socket.getsockname(), time.time())))
        os.close(fd)
        server.timeout = 0.1
        for cmdname in known_commands:
            server.register_function(getattr(self.cmd_runner, cmdname), cmdname)
        server.register_function(self.run_cmdline, 'run_cmdline')
        server.register_function(self.ping, 'ping')
        server.register_function(self.run_daemon, 'daemon')
        server.register_function(self.run_gui, 'gui')
        self.server = server

    def ping(self):
        return True

    def run_daemon(self, config):
        sub = config.get('subcommand')
        assert sub in ['start', 'stop', 'status']
        if sub == 'start':
            response = "Daemon already running"
        elif sub == 'status':
            if self.network:
                p = self.network.get_parameters()
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
            if hasattr(self.gui, 'new_window'):
                path = config.get_wallet_path()
                self.gui.new_window(path, config.get('url'))
                response = "ok"
            else:
                response = "error: current GUI does not support multiple windows"
        else:
            response = "Error: Electrum is running in daemon mode. Please stop the daemon first."
        return response

    def load_wallet(self, path):
        # wizard will be launched if we return
        if path in self.wallets:
            wallet = self.wallets[path]
            return wallet
        storage = WalletStorage(path)
        if not storage.file_exists:
            return
        if storage.requires_split():
            return
        if storage.requires_upgrade():
            self.print_error('upgrading wallet format')
            storage.upgrade()
        if storage.get_action():
            return
        wallet = Wallet(storage)
        wallet.start_threads(self.network)
        self.wallets[path] = wallet
        return wallet

    def add_wallet(self, wallet):
        path = wallet.storage.path
        self.wallets[path] = wallet

    def stop_wallet(self, path):
        wallet = self.wallets.pop(path)
        wallet.stop_threads()

    def run_cmdline(self, config_options):
        config = SimpleConfig(config_options)
        cmdname = config.get('cmd')
        cmd = known_commands[cmdname]
        path = config.get_wallet_path()
        wallet = self.load_wallet(path) if cmd.requires_wallet else None
        # arguments passed to function
        args = map(lambda x: config.get(x), cmd.params)
        # decode json arguments
        args = map(json_decode, args)
        # options
        args += map(lambda x: config.get(x), cmd.options)
        cmd_runner = Commands(config, wallet, self.network,
                              password=config_options.get('password'),
                              new_password=config_options.get('new_password'))
        func = getattr(cmd_runner, cmd.name)
        result = func(*args)
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
        gui = __import__('electrum_gui.' + gui_name, fromlist=['electrum_gui'])
        self.gui = gui.ElectrumGui(config, self, plugins)
        self.gui.main()
