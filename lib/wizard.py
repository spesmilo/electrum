#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 thomasv@gitorious, kyuupichan@gmail
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

from electrum import WalletStorage
from electrum.plugins import run_hook
from util import PrintError
from wallet import Wallet, Multisig_Wallet
from i18n import _

MSG_GENERATING_WAIT = _("Electrum is generating your addresses, please wait...")
MSG_ENTER_ANYTHING = _("Please enter a seed phrase, a master key, a list of "
                       "Bitcoin addresses, or a list of private keys")
MSG_ENTER_SEED_OR_MPK = _("Please enter a seed phrase or a master key (xpub or xprv):")
MSG_VERIFY_SEED = _("Your seed is important!\nTo make sure that you have properly saved your seed, please retype it here.")
MSG_COSIGNER = _("Please enter the master public key of cosigner #%d:")
MSG_SHOW_MPK = _("Here is your master public key:")
MSG_ENTER_PASSWORD = _("Choose a password to encrypt your wallet keys.  "
                       "Enter nothing if you want to disable encryption.")
MSG_RESTORE_PASSPHRASE = \
    _("Please enter the passphrase you used when creating your %s wallet.  "
      "Note this is NOT a password.  Enter nothing if you did not use "
      "one or are unsure.")

class UserCancelled(Exception):
    pass

class WizardBase(PrintError):
    '''Base class for gui-specific install wizards.'''
    user_actions = ('create', 'restore')
    wallet_kinds = [
        ('standard',  _("Standard wallet")),
        ('twofactor', _("Wallet with two-factor authentication")),
        ('multisig',  _("Multi-signature wallet")),
        ('hardware',  _("Hardware wallet")),
    ]


    # Derived classes must set:
    #   self.language_for_seed
    #   self.plugins

    def show_error(self, msg):
        raise NotImplementedError

    def show_warning(self, msg):
        raise NotImplementedError

    def remove_from_recently_open(self, filename):
        """Remove filename from the recently used list."""
        raise NotImplementedError

    def query_create_or_restore(self, wallet_kinds):
        """Ask the user what they want to do, and to what wallet kind.
        wallet_kinds is an array of tuples (kind, description).
        Return a tuple (action, kind).  Action is 'create' or 'restore',
        and kind is one of the wallet kinds passed."""
        raise NotImplementedError

    def query_multisig(self, action):
        """Asks the user what kind of multisig wallet they want.  Returns a
        string like "2of3".  Action is 'create' or 'restore'."""
        raise NotImplementedError

    def query_choice(self, msg, choices):
        """Asks the user which of several choices they would like.
        Return the index of the choice."""
        raise NotImplementedError

    def show_and_verify_seed(self, seed):
        """Show the user their seed.  Ask them to re-enter it.  Return
        True on success."""
        raise NotImplementedError

    def request_passphrase(self, device_text, restore=True):
        """Request a passphrase for a wallet from the given device and
        confirm it.  restore is True if restoring a wallet.  Should return
        a unicode string."""
        raise NotImplementedError

    def request_password(self, msg=None):
        """Request the user enter a new password and confirm it.  Return
        the password or None for no password."""
        raise NotImplementedError

    def request_seed(self, msg, is_valid=None):
        """Request the user enter a seed.  Returns the seed the user entered.
        is_valid is a function that returns True if a seed is valid, for
        dynamic feedback.  If not provided, Wallet.is_any is used."""
        raise NotImplementedError

    def request_trezor_reset_settings(self, device):
        """Ask the user how they want to initialize a trezor compatible
        device.  device is the device kind, e.g. "Keepkey", to be used
        in dialog messages.  Returns a 4-tuple: (strength, label,
        pinprotection, passphraseprotection).  Strength is 0, 1 or 2
        for a 12, 18 or 24 word seed, respectively.  Label is a name
        to give the device.  PIN protection and passphrase protection
        are booleans and should default to True and False respectively."""
        raise NotImplementedError

    def request_many(self, n, xpub_hot=None):
        """If xpub_hot is provided, a new wallet is being created.  Request N
        master public keys for cosigners; xpub_hot is the master xpub
        key for the wallet.

        If xpub_hot is None, request N cosigning master xpub keys,
        xprv keys, or seeds in order to perform wallet restore."""
        raise NotImplementedError

    def choose_server(self, network):
        """Choose a server if one is not set in the config anyway."""
        raise NotImplementedError

    def show_restore(self, wallet, network, action):
        """Show restore result"""
        pass

    def open_wallet(self, network, filename):
        '''The main entry point of the wizard.  Open a wallet from the given
        filename.  If the file doesn't exist launch the GUI-specific
        install wizard proper.'''
        storage = WalletStorage(filename)
        if storage.file_exists:
            wallet = Wallet(storage)
            self.update_wallet_format(wallet)
            task = None
        else:
            cr, wallet = self.create_or_restore(storage)
            if not wallet:
                return
            task = lambda: self.show_restore(wallet, network, cr)

        action = wallet.get_action()
        requires_action = action is not None
        while action:
            self.run_wallet_action(wallet, action)
            action = wallet.get_action()

        # Save the wallet after successful completion of actions.
        # It will be saved again once synchronized.
        if requires_action:
            wallet.storage.write()

        if network:
            self.choose_server(network)
        else:
            self.show_warning(_('You are offline'))

        # start wallet threads
        if network:
            wallet.start_threads(network)
        else:
            wallet.synchronize()

        if task:
            task()

        return wallet


    def run_wallet_action(self, wallet, action):
        self.print_error("action %s on %s" % (action, wallet.basename()))
        # Run the action on the wallet plugin, if any, then the
        # wallet and finally ourselves
        calls = [(wallet, (wallet, )),
                 (self, (wallet, ))]
        if hasattr(wallet, 'plugin'):
            calls.insert(0, (wallet.plugin, (wallet, self)))
        calls = [(getattr(actor, action), args) for (actor, args) in calls
                 if hasattr(actor, action)]
        if not calls:
            raise RuntimeError("No handler found for %s action" % action)
        for method, args in calls:
            method(*args)

    def create_or_restore(self, storage):
        '''After querying the user what they wish to do, create or restore
        a wallet and return it.'''
        self.remove_from_recently_open(storage.path)

        action, kind = self.query_create_or_restore(WizardBase.wallet_kinds)

        assert action in WizardBase.user_actions
        assert kind in [k for k, desc in WizardBase.wallet_kinds]

        if kind == 'multisig':
            wallet_type = self.query_multisig(action)
        elif kind == 'hardware':
            wallet_types, choices = self.plugins.hardware_wallets(action)
            if action == 'create':
                msg = _('Select the hardware wallet to create')
            else:
                msg = _('Select the hardware wallet to restore')
            choice = self.query_choice(msg, choices)
            wallet_type = wallet_types[choice]
        elif kind == 'twofactor':
            wallet_type = '2fa'
        else:
            wallet_type = 'standard'

        if action == 'create':
            wallet = self.create_wallet(storage, wallet_type, kind)
        else:
            wallet = self.restore_wallet(storage, wallet_type, kind)

        return action, wallet

    def construct_wallet(self, storage, wallet_type):
        storage.put('wallet_type', wallet_type)
        return Wallet(storage)

    def create_wallet(self, storage, wallet_type, kind):
        wallet = self.construct_wallet(storage, wallet_type)
        if kind == 'hardware':
            wallet.plugin.on_create_wallet(wallet, self)
        return wallet

    def restore_wallet(self, storage, wallet_type, kind):
        if wallet_type == 'standard':
            return self.restore_standard_wallet(storage)

        if kind == 'multisig':
            return self.restore_multisig_wallet(storage, wallet_type)

        # Plugin (two-factor or hardware)
        wallet = self.construct_wallet(storage, wallet_type)
        return wallet.plugin.on_restore_wallet(wallet, self)

    def restore_standard_wallet(self, storage):
        text = self.request_seed(MSG_ENTER_ANYTHING)
        need_password = Wallet.should_encrypt(text)
        password = self.request_password() if need_password else None
        return Wallet.from_text(text, password, storage)

    def restore_multisig_wallet(self, storage, wallet_type):
        # FIXME: better handling of duplicate keys
        m, n = Wallet.multisig_type(wallet_type)
        key_list = self.request_many(n - 1)
        need_password = any(Wallet.should_encrypt(text) for text in key_list)
        password = self.request_password() if need_password else None
        return Wallet.from_multisig(key_list, password, storage, wallet_type)

    def create_seed(self, wallet):
        '''The create_seed action creates a seed and then generates
        wallet account(s) whilst we still have the password.'''
        seed = wallet.make_seed(self.language_for_seed)
        self.show_and_verify_seed(seed)
        password = self.request_password()
        wallet.add_seed(seed, password)
        wallet.create_master_keys(password)
        if isinstance(wallet, Multisig_Wallet):
            self.add_cosigners(wallet)
        wallet.create_main_account(password)

    def add_cosigners(self, wallet):
        # FIXME: better handling of duplicate keys
        m, n = Wallet.multisig_type(wallet.wallet_type)
        xpub1 = wallet.master_public_keys.get("x1/")
        xpubs = self.request_many(n - 1, xpub1)
        for i, xpub in enumerate(xpubs):
            wallet.add_master_public_key("x%d/" % (i + 2), xpub)

    def update_wallet_format(self, wallet):
        # Backwards compatibility: convert old-format imported keys
        if wallet.imported_keys:
            msg = _("Please enter your password in order to update "
                    "imported keys")
            if wallet.use_encryption:
                password = self.request_password(msg)
            else:
                password = None

            try:
                wallet.convert_imported_keys(password)
            except Exception as e:
                self.show_error(str(e))

        # Call synchronize to regenerate addresses in case we're offline
        if wallet.get_master_public_keys() and not wallet.addresses():
            wallet.synchronize()
