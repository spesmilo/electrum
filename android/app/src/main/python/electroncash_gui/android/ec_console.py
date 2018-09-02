from __future__ import absolute_import, division, print_function

from code import InteractiveConsole
import os
from os.path import join

from electroncash import commands, daemon, util, version
from electroncash import main  # electron-cash script, renamed by build.gradle.
from electroncash.simple_config import SimpleConfig
from electroncash.storage import WalletStorage
from electroncash.wallet import Wallet


# Too noisy: "servers", "interfaces"
# Unused: "on_quotes", "on_history"
CALLBACKS = ["updated", "new_transaction", "status", "banner", "verified", "fee"]


class ECConsole(InteractiveConsole):
    """`interact` must be run on a background thread, because it blocks waiting for input.
    """
    def __init__(self, context, cmds):
        namespace = dict(c=cmds, context=context.getApplicationContext())
        namespace.update({name: CommandWrapper(cmds, name) for name in all_commands})
        namespace.update(help=Help())
        InteractiveConsole.__init__(self, locals=namespace)

    def interact(self):
        try:
            InteractiveConsole.interact(
                self, banner=(f"Electron Cash {version.PACKAGE_VERSION}\n"
                              f"Type 'help' for available commands and variables."))
        except SystemExit:
            pass


class CommandWrapper:
    def __init__(self, cmds, name):
        self.cmds = cmds
        self.name = name

    def __call__(self, *args, **kwargs):
        return getattr(self.cmds, self.name)(*args, **kwargs)


class Help:
    def __repr__(self):
        return self.help()

    def __call__(self, *args):
        print(self.help(*args))

    def help(self, name_or_wrapper=None):
        if name_or_wrapper is None:
            return("Commands:\n" +
                   "\n".join(f"  {cmd}" for name, cmd in sorted(all_commands.items())) +
                   "\nType help(<command>) for more details.\n"
                   "The following variables are also available: "
                   "c.config, c.daemon, c.network, c.wallet, context")
        else:
            if isinstance(name_or_wrapper, CommandWrapper):
                cmd = all_commands[name_or_wrapper.name]
            else:
                cmd = all_commands[name_or_wrapper]
            return f"{cmd}\n{cmd.description}"


# Adds additional commands which aren't available over JSON RPC.
class AllCommands(commands.Commands):
    def __init__(self):
        super().__init__(SimpleConfig({"verbose": True}), wallet=None, network=None)
        fd, server = daemon.get_fd_or_server(self.config)
        if not fd:
            raise Exception("Daemon already running")  # Same wording as in daemon.py.

        # Initialize here rather than in start() so the DaemonModel has a chance to register
        # its callback before the daemon threads start.
        self.daemon = daemon.Daemon(self.config, fd, False)
        self.network = self.daemon.network
        self.network.register_callback(self._on_callback, CALLBACKS)
        self.daemon_running = False

    # BEGIN commands from the argparse interface.

    def start(self):
        """Start the daemon"""
        self.daemon.start()
        self.daemon_running = True

    def status(self):
        """Get daemon status"""
        self._assert_daemon_running()
        return self.daemon.run_daemon({"subcommand": "status"})

    def stop(self):
        """Stop the daemon"""
        self._assert_daemon_running()
        self.daemon.stop()
        self.daemon.join()
        self.daemon_running = False

    def load_wallet(self, name, password=None):
        """Load a wallet"""
        self._assert_daemon_running()
        path = self._wallet_path(name)
        wallet = self.daemon.get_wallet(path)
        if not wallet:
            storage = WalletStorage(path)
            if not storage.file_exists():
                raise FileNotFoundError(path)
            if storage.is_encrypted():
                if not password:
                    raise util.InvalidPassword()
                storage.decrypt(password)

            wallet = Wallet(storage)
            wallet.start_threads(self.network)
            self.daemon.add_wallet(wallet)

        self.wallet = wallet
        self.network.notify("updated")
        return wallet

    def close_wallet(self, name=None):
        """Close a wallet"""
        self._assert_daemon_running()
        if not name:
            if not self.wallet:
                print("Wallet not loaded")  # Same wording as in commands.py.
                return
            path = self.wallet.storage.path
        else:
            path = self._wallet_path(name)
        self.daemon.stop_wallet(path)
        if self.wallet and (path == self.wallet.storage.path):
            self.wallet = None
            self.network.notify("updated")

    def create(self, name):
        """Create a new wallet interactively"""
        self._run_non_RPC({"cmd": "create", "wallet_path": self._wallet_path(name)})

    # TODO results in a file where storage.is_encrypted() is False, but
    # storage.get("use_encryption") is True, and password is not required.
    def restore(self, name, text):
        """Restore a wallet from text. Text can be a seed phrase, a master
        public key, a master private key, a list of bitcoin cash addresses
        or bitcoin cash private keys."""
        self._run_non_RPC({"cmd": "restore", "wallet_path": self._wallet_path(name),
                           "text": text, "offline": True})

    def _run_non_RPC(self, config_options):
        try:
            # 'cwd' is required by SimpleConfig.get_wallet_path.
            main.run_non_RPC(SimpleConfig(dict(config_options, cwd=os.getcwd())))
        except SystemExit as e:
            if e.code:
                raise Exception(f"{config_options['cmd']} failed: {e.code}")

    # END commands from the argparse interface.

    # BEGIN commands which only exist here.

    def list_wallets(self):
        """List available wallets"""
        return sorted(os.listdir(self._wallet_path()))

    def delete_wallet(self, name):
        """Delete a wallet"""
        raise NotImplementedError("TODO")

    # END commands which only exist here.

    def _assert_daemon_running(self):
        if not self.daemon_running:
            raise Exception("Daemon not running")  # Same wording as in electron-cash script.

    def _on_callback(self, *args):
        util.print_stderr("[Callback] " + ", ".join(repr(x) for x in args))

    def _wallet_path(self, name=""):
        wallets_dir = join(util.user_dir(), "wallets")
        util.make_dir(wallets_dir)
        return join(wallets_dir, name)


all_commands = commands.known_commands.copy()
for name, func in vars(AllCommands).items():
    if not name.startswith("_"):
        all_commands[name] = commands.Command(func, "")
