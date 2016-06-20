#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016 Thomas Voegtlin
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

import os
from electrum.wallet import Wallet, Multisig_Wallet, WalletStorage
from i18n import _


class BaseWizard(object):

    def __init__(self, config, network, path):
        super(BaseWizard, self).__init__()
        self.config  = config
        self.network = network
        self.storage = WalletStorage(path)
        self.wallet = None
        self.stack = []

    def run(self, action, *args):
        self.stack.append((action, args))
        if not action:
            return
        if hasattr(self.wallet, 'plugin'):
            if hasattr(self.wallet.plugin, action):
                f = getattr(self.wallet.plugin, action)
                apply(f, (self.wallet, self) + args)
        elif hasattr(self, action):
            f = getattr(self, action)
            apply(f, *args)
        else:
            raise BaseException("unknown action", action)

    def get_action(self):
        if self.storage.file_exists:
            self.wallet = Wallet(self.storage)
            action = self.wallet.get_action()
        else:
            action = 'new'
        return action

    def get_wallet(self):
        if self.wallet and self.wallet.get_action() is None:
            return self.wallet

    def can_go_back(self):
        return len(self.stack)>1

    def go_back(self):
        if not self.can_go_back():
            return
        self.stack.pop()
        action, args = self.stack.pop()
        self.run(action, *args)

    def run_wallet(self):
        self.stack = []
        action = self.wallet.get_action()
        if action:
            self.action_dialog(action=action, run_next=lambda x: self.run_wallet())

    def new(self):
        name = os.path.basename(self.storage.path)
        title = _("Welcome to the Electrum installation wizard.")
        message = '\n'.join([
            _("The wallet '%s' does not exist.") % name,
            _("What kind of wallet do you want to create?")
        ])
        wallet_kinds = [
            ('standard',  _("Standard wallet")),
            ('twofactor', _("Wallet with two-factor authentication")),
            ('multisig',  _("Multi-signature wallet")),
            ('hardware',  _("Hardware wallet")),
        ]
        registered_kinds = Wallet.categories()
        choices = [pair for pair in wallet_kinds if pair[0] in registered_kinds]
        self.choice_dialog(title = title, message=message, choices=choices, run_next=self.on_wallet_type)

    def on_wallet_type(self, choice):
        self.wallet_type = choice
        if choice == 'standard':
            action = 'choose_seed'
        elif choice == 'multisig':
            action = 'choose_multisig'
        elif choice == 'hardware':
            action = 'choose_hw'
        elif choice == 'twofactor':
            action = 'choose_seed'
        self.run(action)

    def choose_multisig(self):
        def on_multisig(m, n):
            self.multisig_type = "%dof%d"%(m, n)
            self.run('choose_seed')
        self.multisig_dialog(run_next=on_multisig)

    def choose_seed(self):
        title = _('Private Keys')
        message = _("Do you want to create a new seed, or to restore a wallet using an existing seed?")
        if self.wallet_type == 'standard':
            choices = [
                ('create_seed', _('Create a new seed')),
                ('restore_seed', _('I already have a seed')),
                ('restore_xpub', _('Watching-only wallet')),
            ]
        elif self.wallet_type == 'twofactor':
            choices = [
                ('create_2fa', _('Create a new seed')),
                ('restore_2fa', _('I already have a seed')),
            ]
        elif self.wallet_type == 'multisig':
            choices = [
                ('create_seed', _('Create a new seed')),
                ('restore_seed', _('I already have a seed')),
                ('restore_xpub', _('Watching-only wallet')),
                ('choose_hw', _('Cosign with hardware wallet')),
            ]
        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def create_2fa(self):
        print 'create 2fa'
        self.storage.put('wallet_type', '2fa')
        self.wallet = Wallet(self.storage)
        self.run_wallet()

    def restore_seed(self):
        msg = _('Please type your seed phrase using the virtual keyboard.')
        title = _('Enter Seed')
        self.enter_seed_dialog(run_next=self.add_password, title=title, message=msg, is_valid=Wallet.is_seed)

    def restore_xpub(self):
        title = "MASTER PUBLIC KEY"
        message = _('To create a watching-only wallet, paste your master public key, or scan it using the camera button.')
        self.add_xpub_dialog(run_next=lambda xpub: self.create_wallet(xpub, None), title=title, message=message, is_valid=Wallet.is_mpk)

    def restore_2fa(self):
        self.storage.put('wallet_type', '2fa')
        self.wallet = Wallet(self.storage)
        self.wallet.plugin.on_restore_wallet(self.wallet, self)

    def choose_hw(self):
        hw_wallet_types, choices = self.plugins.hardware_wallets('create')
        choices = zip(hw_wallet_types, choices)
        title = _('Hardware wallet')
        if choices:
            msg = _('Select the type of hardware wallet: ')
        else:
            msg = ' '.join([
                _('No hardware wallet support found on your system.'),
                _('Please install the relevant libraries (eg python-trezor for Trezor).'),
            ])
        self.choice_dialog(title=title, message=msg, choices=choices, run_next=self.on_hardware)

    def on_hardware(self, hw_type):
        self.hw_type = hw_type
        if self.wallet_type == 'multisig':
            self.create_hardware_multisig()
        else:
            title = _('Hardware wallet') + ' [%s]' % hw_type
            message = _('Do you have a device, or do you want to restore a wallet using an existing seed?')
            choices = [
                ('create_hardware_wallet', _('I have a device')),
                ('restore_hardware_wallet', _('Use hardware wallet seed')),
            ]
            self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def create_hardware_multisig(self):
        self.storage.put('wallet_type', self.multisig_type)
        self.wallet = Multisig_Wallet(self.storage)
        # todo: get the xpub from the plugin
        self.run('create_wallet', xpub, None)

    def create_hardware_wallet(self):
        self.storage.put('wallet_type', self.hw_type)
        self.wallet = Wallet(self.storage)
        self.wallet.plugin.on_create_wallet(self.wallet, self)
        self.terminate()

    def restore_hardware_wallet(self):
        self.storage.put('wallet_type', self.wallet_type)
        self.wallet = Wallet(self.storage)
        self.wallet.plugin.on_restore_wallet(self.wallet, self)
        self.terminate()

    def create_wallet(self, text, password):
        if self.wallet_type == 'standard':
            self.wallet = Wallet.from_text(text, password, self.storage)
            self.run('create_addresses')
        elif self.wallet_type == 'multisig':
            self.storage.put('wallet_type', self.multisig_type)
            self.wallet = Multisig_Wallet(self.storage)
            self.wallet.add_seed(text, password)
            self.wallet.create_master_keys(password)
            self.run_wallet()

    def add_cosigners(self):
        xpub = self.wallet.master_public_keys.get('x1/')
        self.show_xpub_dialog(run_next=lambda x: self.add_cosigner(), xpub=xpub)

    def add_cosigner(self):
        def on_xpub(xpub):
            self.wallet.add_cosigner(xpub)
            i = self.wallet.get_missing_cosigner()
            action = 'add_cosigner' if i else 'create_addresses'
            self.run(action)
        i = self.wallet.get_missing_cosigner()
        title = _("Add Cosigner") + " %d"%(i-1)
        message = _('Please paste your cosigners master public key, or scan it using the camera button.')
        self.add_xpub_dialog(run_next=on_xpub, title=title, message=message, is_valid=Wallet.is_any)

    def create_addresses(self):
        def task():
            self.wallet.create_main_account()
            self.wallet.synchronize()
            self.terminate()
        msg= _("Electrum is generating your addresses, please wait.")
        self.waiting_dialog(task, msg)

    def create_seed(self):
        from electrum.wallet import BIP32_Wallet
        seed = BIP32_Wallet.make_seed()
        msg = _("If you forget your PIN or lose your device, your seed phrase will be the "
                "only way to recover your funds.")
        self.show_seed_dialog(run_next=self.confirm_seed, message=msg, seed_text=seed)

    def confirm_seed(self, seed):
        assert Wallet.is_seed(seed)
        title = _('Confirm Seed')
        msg = _('Please retype your seed phrase, to confirm that you properly saved it')
        self.enter_seed_dialog(run_next=self.add_password, title=title, message=msg, is_valid=lambda x: x==seed)

    def add_password(self, seed):
        f = lambda x: self.create_wallet(seed, x)
        self.request_password(run_next=f)
