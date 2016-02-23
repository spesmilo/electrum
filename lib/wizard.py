#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 thomasv@gitorious, kyuupichan@gmail
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

from electrum import WalletStorage
from electrum.plugins import run_hook
from util import PrintError
from wallet import Wallet
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
        """Ask the user what they want to do, and which wallet kind.
        wallet_kinds is an array of translated wallet descriptions.
        Return a a tuple (action, kind_index).  Action is 'create' or
        'restore', and kind the index of the wallet kind chosen."""
        raise NotImplementedError

    def query_multisig(self, action):
        """Asks the user what kind of multisig wallet they want.  Returns a
        string like "2of3".  Action is 'create' or 'restore'."""
        raise NotImplementedError

    def query_choice(self, msg, choices):
        """Asks the user which of several choices they would like.
        Return the index of the choice."""
        raise NotImplementedError

    def query_hw_wallet_choice(self, msg, action, choices):
        """Asks the user which hardware wallet kind they are using.  Action is
        'create' or 'restore' from the initial screen.  As this is
        confusing for hardware wallets ask a new question with the
        three possibilities Initialize ('create'), Use ('create') or
        Restore a software-only wallet ('restore').  Return a pair
        (action, choice)."""
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

    def show_restore(self, wallet, network):
        """Show restore result"""
        pass

    def finished(self):
        """Called when the wizard is done."""
        pass

    def run(self, network, storage):
        '''The main entry point of the wizard.  Open a wallet from the given
        filename.  If the file doesn't exist launch the GUI-specific
        install wizard proper, created by calling create_wizard().'''
        need_sync = False
        is_restore = False

        if storage.file_exists:
            wallet = Wallet(storage)
            if wallet.imported_keys:
                self.update_wallet_format(wallet)
        else:
            cr, wallet = self.create_or_restore(storage)
            if not wallet:
                return
            need_sync = True
            is_restore = (cr == 'restore')

        while True:
            action = wallet.get_action()
            if not action:
                break
            need_sync = True
            self.run_wallet_action(wallet, action)
            # Save the wallet after each action
            wallet.storage.write()

        if network:
            # Show network dialog if config does not exist
            if self.config.get('auto_connect') is None:
                self.choose_server(network)
        else:
            self.show_warning(_('You are offline'))

        if need_sync:
            self.create_addresses(wallet)

        # start wallet threads
        if network:
            wallet.start_threads(network)

        if is_restore:
            self.show_restore(wallet, network)

        self.finished()

        return wallet

    def run_wallet_action(self, wallet, action):
        self.print_error("action %s on %s" % (action, wallet.basename()))
        # Run the action on the wallet plugin, if any, then the
        # wallet and finally ourselves
        calls = []
        if hasattr(wallet, 'plugin'):
            calls.append((wallet.plugin, (wallet, self)))
        calls.extend([(wallet, ()), (self, (wallet, ))])
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

        # Filter out any unregistered wallet kinds
        registered_kinds = Wallet.categories()
        kinds, descriptions = zip(*[pair for pair in WizardBase.wallet_kinds
                                    if pair[0] in registered_kinds])
        action, kind_index = self.query_create_or_restore(descriptions)

        assert action in WizardBase.user_actions

        kind = kinds[kind_index]
        if kind == 'multisig':
            wallet_type = self.query_multisig(action)
        elif kind == 'hardware':
            # The create/restore distinction is not obvious for hardware
            # wallets; so we ask for the action again and default based
            # on the prior choice :)
            hw_wallet_types, choices = self.plugins.hardware_wallets(action)
            msg = _('Select the type of hardware wallet: ')
            action, choice = self.query_hw_wallet_choice(msg, action, choices)
            wallet_type = hw_wallet_types[choice]
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
        '''The create_seed action creates a seed and generates
        master keys.'''
        seed = wallet.make_seed(self.language_for_seed)
        self.show_and_verify_seed(seed)
        password = self.request_password()
        wallet.add_seed(seed, password)
        wallet.create_master_keys(password)

    def create_main_account(self, wallet):
        # FIXME: BIP44 restore requires password
        wallet.create_main_account()

    def create_addresses(self, wallet):
        wallet.synchronize()

    def add_cosigners(self, wallet):
        # FIXME: better handling of duplicate keys
        m, n = Wallet.multisig_type(wallet.wallet_type)
        xpub1 = wallet.master_public_keys.get("x1/")
        xpubs = self.request_many(n - 1, xpub1)
        for i, xpub in enumerate(xpubs):
            wallet.add_master_public_key("x%d/" % (i + 2), xpub)

    def update_wallet_format(self, wallet):
        # Backwards compatibility: convert old-format imported keys
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
