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

import jsonrpclib
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer, SimpleJSONRPCRequestHandler

from network import Network
from util import check_www_dir, json_decode, DaemonThread
from util import print_msg, print_error, print_stderr
from wallet import WalletStorage, Wallet
from wizard import WizardBase
from commands import known_commands, Commands
from simple_config import SimpleConfig


def lockfile(config):
    return os.path.join(config.path, 'daemon')

def get_daemon(config):
    try:
        with open(lockfile(config)) as f:
            host, port = ast.literal_eval(f.read())
    except:
        return
    server = jsonrpclib.Server('http://%s:%d' % (host, port))
    # check if daemon is running
    try:
        server.ping()
        return server
    except:
        pass


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

    def __init__(self, config):
        DaemonThread.__init__(self)
        self.config = config
        if config.get('offline'):
            self.network = None
        else:
            self.network = Network(config)
            self.network.start()
        self.gui = None
        self.wallets = {}
        self.wallet = None
        self.cmd_runner = Commands(self.config, self.wallet, self.network)
        host = config.get('rpchost', 'localhost')
        port = config.get('rpcport', 0)
        self.server = SimpleJSONRPCServer((host, port), requestHandler=RequestHandler, logRequests=False)
        with open(lockfile(config), 'w') as f:
            f.write(repr(self.server.socket.getsockname()))
        self.server.timeout = 0.1
        for cmdname in known_commands:
            self.server.register_function(getattr(self.cmd_runner, cmdname), cmdname)
        self.server.register_function(self.run_cmdline, 'run_cmdline')
        self.server.register_function(self.ping, 'ping')
        self.server.register_function(self.run_daemon, 'daemon')
        self.server.register_function(self.run_gui, 'gui')

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
        os.unlink(lockfile(self.config))

    def stop(self):
        for k, wallet in self.wallets.items():
            wallet.stop_threads()
        DaemonThread.stop(self)

    def init_gui(self, config, plugins):
        gui_name = config.get('gui', 'qt')
        if gui_name in ['lite', 'classic']:
            gui_name = 'qt'
        gui = __import__('electrum_gui.' + gui_name, fromlist=['electrum_gui'])
        self.gui = gui.ElectrumGui(config, self, plugins)
        self.gui.main()

    @staticmethod
    def gui_command(config, config_options, plugins):
        server = get_daemon(config)
        if server is not None:
            return server.gui(config_options)

        daemon = Daemon(config)
        daemon.start()
        daemon.init_gui(config, plugins)
        sys.exit(0)

    @staticmethod
    def cmdline_command(config, config_options):
        server = get_daemon(config)
        if server is not None:
            return False, server.run_cmdline(config_options)

        return True, None

    @staticmethod
    def daemon_command(config, config_options):
        server = get_daemon(config)
        if server is not None:
            return server.daemon(config_options)

        subcommand = config.get('subcommand')
        if subcommand in ['status', 'stop']:
            print_msg("Daemon not running")
            sys.exit(1)
        elif subcommand == 'start':
            pid = os.fork()
            if pid == 0:
                daemon = Daemon(config)
                if config.get('websocket_server'):
                    from electrum import websockets
                    websockets.WebSocketServer(config, daemon.network).start()
                if config.get('requests_dir'):
                    check_www_dir(config.get('requests_dir'))
                daemon.start()
                daemon.join()
                sys.exit(0)
            else:
                print_stderr("starting daemon (PID %d)" % pid)
                sys.exit(0)
        else:
            print_msg("syntax: electrum daemon <start|status|stop>")
            sys.exit(1)
