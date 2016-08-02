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
from electrum_ltc.wallet import Wallet, Multisig_Wallet, WalletStorage
from i18n import _


is_any_key = lambda x: Wallet.is_old_mpk(x) or Wallet.is_xprv(x) or Wallet.is_xpub(x) or Wallet.is_address(x) or Wallet.is_private_key(x)
is_private_key = lambda x: Wallet.is_xprv(x) or Wallet.is_private_key(x)
is_bip32_key = lambda x: Wallet.is_xprv(x) or Wallet.is_xpub(x)


class BaseWizard(object):

    def __init__(self, config, network, path):
        super(BaseWizard, self).__init__()
        self.config  = config
        self.network = network
        self.storage = WalletStorage(path)
        self.wallet = None
        self.stack = []

    def run(self, *args):
        action = args[0]
        args = args[1:]
        self.stack.append((action, args))
        if not action:
            return
        if hasattr(self.wallet, 'plugin') and hasattr(self.wallet.plugin, action):
            f = getattr(self.wallet.plugin, action)
            apply(f, (self.wallet, self) + args)
        elif hasattr(self, action):
            f = getattr(self, action)
            apply(f, args)
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
        title = _('Choose Seed')
        message = _("Do you want to create a new seed, or to restore a wallet using an existing seed?")
        if self.wallet_type == 'standard':
            choices = [
                ('create_seed', _('Create a new seed')),
                ('restore_seed', _('I already have a seed')),
                ('restore_from_key', _('Import keys')),
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
                ('restore_from_key', _('I have a master key')),
                #('choose_hw', _('Cosign with hardware wallet')),
            ]
        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def create_2fa(self):
        self.storage.put('wallet_type', '2fa')
        self.wallet = Wallet(self.storage)
        self.run('show_disclaimer')

    def restore_seed(self):
        # TODO: return derivation password too
        self.restore_seed_dialog(run_next=self.add_password, is_valid=Wallet.is_seed)

    def on_restore(self, text):
        if is_private_key(text):
            self.add_password(text)
        else:
            self.create_wallet(text, None)

    def restore_from_key(self):
        if self.wallet_type == 'standard':
            v = is_any_key
            title = _("Import keys")
            message = ' '.join([
                _("To create a watching-only wallet, please enter your master public key (xpub), or a list of Litecoin addresses."),
                _("To create a spending wallet, please enter a master private key (xprv), or a list of Litecoin private keys.")
            ])
        else:
            v = is_bip32_key
            title = _("Master public or private key")
            message = ' '.join([
                _("To create a watching-only wallet, please enter your master public key (xpub)."),
                _("To create a spending wallet, please enter a master private key (xprv).")
            ])
        self.restore_keys_dialog(title=title, message=message, run_next=self.on_restore, is_valid=v)

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
            self.wallet.add_cosigner('x1/', text, password)
            self.stack = []
            self.run('show_xpub_and_add_cosigners', (password,))

    def show_xpub_and_add_cosigners(self, password):
        xpub = self.wallet.master_public_keys.get('x1/')
        self.show_xpub_dialog(xpub=xpub, run_next=lambda x: self.run('add_cosigners', password))

    def add_cosigners(self, password):
        i = self.wallet.get_missing_cosigner()
        self.add_cosigner_dialog(run_next=lambda x: self.on_cosigner(x, password), index=(i-1), is_valid=Wallet.is_xpub)

    def on_cosigner(self, text, password):
        i = self.wallet.get_missing_cosigner()
        try:
            self.wallet.add_cosigner('x%d/'%i, text, password)
        except BaseException as e:
            print "error:" + str(e)
        i = self.wallet.get_missing_cosigner()
        if i:
            self.run('add_cosigners', password)
        else:
            self.create_addresses()

    def create_addresses(self):
        def task():
            self.wallet.create_main_account()
            self.wallet.synchronize()
            self.wallet.storage.write()
            self.terminate()
        msg = _("Electrum is generating your addresses, please wait.")
        self.waiting_dialog(task, msg)

    def create_seed(self):
        from electrum_ltc.wallet import BIP32_Wallet
        seed = BIP32_Wallet.make_seed()
        self.show_seed_dialog(run_next=self.confirm_seed, seed_text=seed)

    def confirm_seed(self, seed):
        self.confirm_seed_dialog(run_next=self.add_password, is_valid=lambda x: x==seed)

    def add_password(self, text):
        f = lambda pw: self.run('create_wallet', text, pw)
        self.request_password(run_next=f)
