from __future__ import absolute_import, division, print_function

from code import InteractiveConsole
import os
from os.path import dirname, exists, join, split
import pkgutil
from shutil import copyfile
from time import time

from electroncash import commands, daemon, interface, keystore, storage, util
from electroncash.i18n import _
from electroncash.storage import WalletStorage
from electroncash.wallet import (ImportedAddressWallet, ImportedPrivkeyWallet, Standard_Wallet,
                                 Wallet)


CALLBACKS = ["banner", "blockchain_updated", "fee", "interfaces", "new_transaction",
             "on_history", "on_quotes", "servers", "status", "verified2", "wallet_updated"]


class AndroidConsole(InteractiveConsole):
    """`interact` must be run on a background thread, because it blocks waiting for input.
    """
    def __init__(self, app, cmds):
        namespace = dict(c=cmds, context=app)
        namespace.update({name: CommandWrapper(cmds, name) for name in all_commands})
        namespace.update(help=Help())
        InteractiveConsole.__init__(self, locals=namespace)

    def interact(self):
        try:
            InteractiveConsole.interact(
                self, banner=(
                    _("WARNING!") + "\n" +
                    _("Do not enter code here that you don't understand. Executing the wrong "
                      "code could lead to your coins being irreversibly lost.") + "\n" +
                    "Type 'help' for available commands and variables."))
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
class AndroidCommands(commands.Commands):
    def __init__(self, config):
        super().__init__(config, wallet=None, network=None)
        fd, server = daemon.get_fd_or_server(self.config)
        if not fd:
            raise Exception("Daemon already running")  # Same wording as in daemon.py.

        # Create daemon here rather than in start() so the DaemonModel has a chance to register
        # its callback before the daemon threads start.
        self.daemon = daemon.Daemon(self.config, fd, is_gui=False, plugins=None)
        self.daemon_running = False

        self.gui_callback = None
        self.network = self.daemon.network
        self.network.register_callback(self._on_callback, CALLBACKS)
        self.network.add_jobs([AutoSaver(self.daemon)])

        # Reduce network timeouts (#971).
        self.network.NODES_RETRY_INTERVAL = self.network.SERVER_RETRY_INTERVAL = 5
        interface.PING_INTERVAL = 60

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

    def close_wallet(self, name=None):
        """Close a wallet"""
        self._assert_daemon_running()
        self.daemon.stop_wallet(self._wallet_path(name))

    def create(self, name, password, seed=None, passphrase="", bip39_derivation=None,
               master=None, addresses=None, privkeys=None):
        """Create or restore a new wallet"""
        path = self._wallet_path(name)
        if exists(path):
            raise FileExistsError(path)
        storage = WalletStorage(path)

        if addresses is not None:
            wallet = ImportedAddressWallet.from_text(storage, addresses)
        elif privkeys is not None:
            wallet = ImportedPrivkeyWallet.from_text(storage, privkeys)
        else:
            if bip39_derivation is not None:
                ks = keystore.from_seed(seed, passphrase, seed_type='bip39',
                                        derivation=bip39_derivation)
            elif master is not None:
                ks = keystore.from_master_key(master)
            else:
                if seed is None:
                    seed = self.make_seed()
                    print("Your wallet generation seed is:\n\"%s\"" % seed)
                ks = keystore.from_seed(seed, passphrase)

            storage.put('keystore', ks.dump())
            wallet = Standard_Wallet(storage)

        wallet.update_password(None, password, encrypt=True)

    # END commands from the argparse interface.

    # BEGIN commands which only exist here.

    def select_wallet(self, name):
        if name is None:
            self.wallet = None
        else:
            self.wallet = self.daemon.wallets[self._wallet_path(name)]
        self.network.trigger_callback("wallet_updated", self.wallet)

    def list_wallets(self):
        """List available wallets"""
        return sorted([name for name in os.listdir(self._wallet_path())
                       if not name.endswith(storage.TMP_SUFFIX)])

    def delete_wallet(self, name=None):
        """Delete a wallet"""
        os.remove(self._wallet_path(name))

    def rename_wallet(self, name, new_name):
        if name == new_name:
            return
        original_path = self._wallet_path(name)
        if not exists(original_path):
            raise FileNotFoundError(original_path)
        new_path = join(split(original_path)[0], new_name)
        if exists(new_path):
            raise FileExistsError(new_path)
        if self.wallet is not None and self.wallet.storage.path == original_path:
            # We are renaming the currently loaded wallet. Close it before renaming it.
            self.close_wallet(name)
            self.select_wallet(None)
        os.rename(original_path, new_path)

    def copy_wallet(self, name, destination_path, overwrite=True, create_dir=True):
        original_path = self._wallet_path(name)
        if not exists(original_path):
            raise FileNotFoundError(original_path)
        destination_dir = dirname(destination_path)
        if not exists(destination_dir):
            if create_dir:
                os.makedirs(destination_dir)
            else:
                raise FileNotFoundError(destination_dir)
        if not overwrite:
            if exists(destination_path):
                raise FileExistsError(destination_path)
        copyfile(original_path, destination_path)

    def unit_test(self):
        """Run all unit tests. Expect failures with functionality not present on Android,
        such as Trezor.
        """

        # Speed up startup by not importing test code at module level.
        from electroncash import tests
        import unittest

        suite = unittest.defaultTestLoader.loadTestsFromNames(
            tests.__name__ + "." + info.name
            for info in pkgutil.iter_modules(tests.__path__)
            if info.name.startswith("test_"))
        unittest.TextTestRunner(verbosity=2).run(suite)

    # END commands which only exist here.

    def _assert_daemon_running(self):
        if not self.daemon_running:
            raise Exception("Daemon not running")  # Same wording as in electron-cash script.

    def _on_callback(self, event, *args):
        if self.gui_callback:
            self.gui_callback(event)

    def _wallet_path(self, name=""):
        if name is None:
            if not self.wallet:
                raise ValueError("No wallet selected")
            return self.wallet.storage.path
        else:
            wallets_dir = join(util.user_dir(), "wallets")
            util.make_dir(wallets_dir)
            return util.standardize_path(join(wallets_dir, name))


all_commands = commands.known_commands.copy()
for name, func in vars(AndroidCommands).items():
    if not name.startswith("_"):
        all_commands[name] = commands.Command(func, "")


AUTO_SAVE_INTERVAL = 300

class AutoSaver(util.ThreadJob):
    """Save wallets periodically if they've been syncing for a long time. This avoids losing
    too much progress if the process is killed or the phone is turned off.
    """
    def __init__(self, daemon):
        self.daemon = daemon
        self.syncing = {}

    def run(self):
        for name, wallet in self.daemon.wallets.items():
            if wallet.is_fully_settled_down():
                self.syncing.pop(name, None)
            else:
                last_save = self.syncing.setdefault(name, time())
                if time() - last_save > AUTO_SAVE_INTERVAL:
                    wallet.save_network_state()
                    self.syncing[name] = time()

        for name in [name for name in self.syncing if name not in self.daemon.wallets]:
            del self.syncing[name]
