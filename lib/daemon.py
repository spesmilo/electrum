#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import ast
import os
import sys
import time

import jsonrpclib
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer, SimpleJSONRPCRequestHandler

from network import Network
from util import json_decode, DaemonThread
from util import print_msg, print_error, print_stderr
from wallet import WalletStorage, Wallet
from wizard import WizardBase
from commands import known_commands, Commands
from simple_config import SimpleConfig


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

    def __init__(self, config, server):
        DaemonThread.__init__(self)
        self.config = config
        if config.get('offline'):
            self.network = None
        else:
            self.network = Network(config)
            self.network.start()
        self.gui = None
        self.wallets = {}
        self.server = server
        # Setup server
        cmd_runner = Commands(self.config, None, self.network)
        server.timeout = 0.1
        for cmdname in known_commands:
            server.register_function(getattr(cmd_runner, cmdname), cmdname)
        server.register_function(self.run_cmdline, 'run_cmdline')
        server.register_function(self.ping, 'ping')
        server.register_function(self.run_daemon, 'daemon')
        server.register_function(self.run_gui, 'gui')

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
                    'nodes': self.network.get_interfaces(),
                    'connected': self.network.is_connected(),
                    'auto_connect': p[4],
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

    def load_wallet(self, path, get_wizard=None):
        if path in self.wallets:
            wallet = self.wallets[path]
        else:
            storage = WalletStorage(path)
            if get_wizard:
                if storage.file_exists:
                    wallet = Wallet(storage)
                    action = wallet.get_action()
                else:
                    action = 'new'
                if action:
                    wizard = get_wizard()
                    wallet = wizard.run(self.network, storage)
                else:
                    wallet.start_threads(self.network)
            else:
                wallet = Wallet(storage)
                wallet.start_threads(self.network)
            if wallet:
                self.wallets[path] = wallet
        return wallet

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
            self.server.handle_request()
        for k, wallet in self.wallets.items():
            wallet.stop_threads()
        if self.network:
            self.print_error("shutting down network")
            self.network.stop()
            self.network.join()

    def stop(self):
        self.print_error("stopping, removing lockfile")
        Daemon.remove_lockfile(Daemon.lockfile(self.config))
        DaemonThread.stop(self)

    def init_gui(self, config, plugins):
        gui_name = config.get('gui', 'qt')
        if gui_name in ['lite', 'classic']:
            gui_name = 'qt'
        gui = __import__('electrum_gui.' + gui_name, fromlist=['electrum_gui'])
        self.gui = gui.ElectrumGui(config, self, plugins)
        self.gui.main()

    @staticmethod
    def lockfile(config):
        return os.path.join(config.path, 'daemon')

    @staticmethod
    def remove_lockfile(lockfile):
        os.unlink(lockfile)

    @staticmethod
    def get_fd_or_server(lockfile):
        '''If create is True, tries to create the lockfile, using O_EXCL to
        prevent races.  If it succeeds it returns the FD.

        Otherwise try and connect to the server specified in the lockfile.
        If this succeeds, the server is returned.  Otherwise remove the
        lockfile and try again.'''
        while True:
            try:
                return os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except OSError:
                pass
            server = Daemon.get_server(lockfile)
            if server is not None:
                return server
            # Couldn't connect; remove lockfile and try again.
            Daemon.remove_lockfile(lockfile)

    @staticmethod
    def get_server(lockfile):
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

    @staticmethod
    def create_daemon(config, fd):
        '''Create a daemon and server when they don't exist.'''
        host = config.get('rpchost', 'localhost')
        port = config.get('rpcport', 0)
        server = SimpleJSONRPCServer((host, port), logRequests=False,
                                     requestHandler=RequestHandler)
        os.write(fd, repr((server.socket.getsockname(), time.time())))
        os.close(fd)

        daemon = Daemon(config, server)
        daemon.start()
        return daemon
