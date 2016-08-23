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
import keystore
from wallet import Wallet, Imported_Wallet, Standard_Wallet, Multisig_Wallet, WalletStorage, wallet_types
from i18n import _
from plugins import run_hook

class BaseWizard(object):

    def __init__(self, config, network, path):
        super(BaseWizard, self).__init__()
        self.config = config
        self.network = network
        self.storage = WalletStorage(path)
        self.wallet = None
        self.stack = []
        self.plugin = None

    def run(self, *args):
        action = args[0]
        args = args[1:]
        self.stack.append((action, args))
        if not action:
            return
        if type(action) is tuple:
            self.plugin, action = action
        if self.plugin and hasattr(self.plugin, action):
            f = getattr(self.plugin, action)
            apply(f, (self,) + args)
        elif hasattr(self, action):
            f = getattr(self, action)
            apply(f, args)
        else:
            raise BaseException("unknown action", action)

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
            ('2fa', _("Wallet with two-factor authentication")),
            ('multisig',  _("Multi-signature wallet")),
            ('imported',  _("Watch Bitcoin addresses")),
        ]
        choices = [pair for pair in wallet_kinds if pair[0] in wallet_types]
        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.on_wallet_type)

    def on_wallet_type(self, choice):
        self.wallet_type = choice
        if choice == 'standard':
            action = 'choose_keystore'
        elif choice == 'multisig':
            action = 'choose_multisig'
        elif choice == '2fa':
            self.storage.put('wallet_type', '2fa')
            self.storage.put('use_trustedcoin', True)
            self.plugin = self.plugins.load_plugin('trustedcoin')
            action = self.storage.get_action()
        elif choice == 'imported':
            action = 'import_addresses'
        self.run(action)

    def choose_multisig(self):
        def on_multisig(m, n):
            self.multisig_type = "%dof%d"%(m, n)
            self.storage.put('wallet_type', self.multisig_type)
            self.n = n
            self.keystores = []
            self.run('choose_keystore')
        self.multisig_dialog(run_next=on_multisig)

    def choose_keystore(self):
        assert self.wallet_type in ['standard', 'multisig']
        c = self.wallet_type == 'multisig' and len(self.keystores)>0
        title = _('Add cosigner') + ' %d'%len(self.keystores) if c else _('Keystore')
        message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
        if not c:
            choices = [
                ('create_seed', _('Create a new seed')),
                ('restore_seed', _('I already have a seed')),
                ('restore_from_key', _('Import keys')),
                ('choose_hw',  _('Use hardware device')),
            ]
        else:
            choices = [
                ('restore_from_key', _('Import cosigner key')),
                ('choose_hw',  _('Cosign with hardware device')),
            ]

        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def restore_seed(self):
        # TODO: return derivation password too
        self.restore_seed_dialog(run_next=self.add_password, is_valid=keystore.is_seed)

    def on_restore(self, text):
        if keystore.is_address_list(text):
            self.wallet = Imported_Wallet(self.storage)
            for x in text.split():
                self.wallet.import_address(x)
            self.terminate()
        elif keystore.is_private(text):
            self.add_password(text)
        else:
            self.create_keystore(text, None)

    def import_addresses(self):
        v = keystore.is_address_list
        title = _("Import Bitcoin Addresses")
        message = _("Enter a list of Bitcoin addresses. This will create a watching-only wallet.")
        self.restore_keys_dialog(title=title, message=message, run_next=self.on_restore, is_valid=v)

    def restore_from_key(self):
        if self.wallet_type == 'standard':
            v = keystore.is_any_key
            title = _("Import keys")
            message = ' '.join([
                _("To create a watching-only wallet, please enter your master public key (xpub)."),
                _("To create a spending wallet, please enter a master private key (xprv), or a list of Bitcoin private keys.")
            ])
        else:
            v = keystore.is_bip32_key
            title = _("Master public or private key")
            message = ' '.join([
                _("To create a watching-only wallet, please enter your master public key (xpub)."),
                _("To create a spending wallet, please enter a master private key (xprv).")
            ])
        self.restore_keys_dialog(title=title, message=message, run_next=self.on_restore, is_valid=v)

    def choose_hw(self):
        hw_wallet_types, choices = self.plugins.hardware_wallets('create')
        choices = zip(hw_wallet_types, choices)
        title = _('Hardware Keystore')
        if choices:
            msg = _('Select the type of device') + ':'
        else:
            msg = ' '.join([
                _('No hardware wallet support found on your system.'),
                _('Please install the relevant libraries (eg python-trezor for Trezor).'),
            ])
        self.choice_dialog(title=title, message=msg, choices=choices, run_next=self.on_hardware)

    def on_hardware(self, hw_type):
        self.hw_type = hw_type
        title = _('Hardware wallet') + ' [%s]' % hw_type
        message = _('Do you have a device, or do you want to restore a wallet using an existing seed?')
        choices = [
            ('on_hardware_device', _('I have a %s device')%hw_type),
            ('on_hardware_seed', _('I have a %s seed')%hw_type),
        ]
        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def on_hardware_device(self):
        f = lambda x: self.run('on_hardware_account_id', x)
        self.account_id_dialog(run_next=f)

    def on_hardware_account_id(self, account_id):
        from keystore import hardware_keystore, bip44_derivation
        derivation = bip44_derivation(int(account_id))
        plugin = self.plugins.get_plugin(self.hw_type)
        xpub = plugin.setup_device(derivation, self)
        # create keystore
        d = {
            'type': 'hardware',
            'hw_type': self.hw_type,
            'derivation': derivation,
            'xpub': xpub,
        }
        k = hardware_keystore(self.hw_type, d)
        self.on_keystore(k, None)

    def on_hardware_seed(self):
        self.storage.put('key_type', 'hw_seed')
        is_valid = lambda x: True #fixme: bip39
        f = lambda seed: self.run('on_bip39_seed', seed)
        self.restore_seed_dialog(run_next=f, is_valid=is_valid)

    def on_bip39_seed(self, seed):
        f = lambda passphrase: self.run('on_bip39_passphrase', seed, passphrase)
        self.request_passphrase(self.storage.get('hw_type'), run_next=f)

    def on_bip39_passphrase(self, seed, passphrase):
        f = lambda account_id: self.run('on_bip44_account_id', seed, passphrase, account_id)
        self.account_id_dialog(run_next=f)

    def on_bip44_account_id(self, seed, passphrase, account_id):
        f = lambda pw: self.run('on_bip44', seed, passphrase, account_id, pw)
        self.request_password(run_next=f)

    def on_bip44(self, seed, passphrase, account_id, password):
        import keystore
        k = keystore.BIP32_KeyStore()
        k.add_seed(seed, password)
        bip32_seed = keystore.bip39_to_seed(seed, passphrase)
        derivation = "m/44'/0'/%d'"%account_id
        self.storage.put('account_id', account_id)
        k.add_xprv_from_seed(bip32_seed, derivation, password)
        self.on_keystore(k, password)

    def on_keystore(self, k, password):
        if self.wallet_type == 'standard':
            self.storage.put('keystore', k.dump())
            self.wallet = Standard_Wallet(self.storage)
            self.run('create_addresses')
        elif self.wallet_type == 'multisig':

            if k.xpub in map(lambda x: x.xpub, self.keystores):
                raise BaseException('duplicate key')
            self.keystores.append(k)

            if len(self.keystores) == 1:
                xpub = k.get_master_public_key()
                self.stack = []
                self.run('show_xpub_and_add_cosigners', xpub)
            elif len(self.keystores) < self.n:
                self.run('choose_keystore')
            else:
                for i, k in enumerate(self.keystores):
                    self.storage.put('x%d/'%(i+1), k.dump())
                self.storage.write()
                self.wallet = Multisig_Wallet(self.storage)
                self.run('create_addresses')

    def show_xpub_and_add_cosigners(self, xpub):
        self.show_xpub_dialog(xpub=xpub, run_next=lambda x: self.run('choose_keystore'))

    def add_cosigners(self, password, i):
        self.add_cosigner_dialog(run_next=lambda x: self.on_cosigner(x, password, i), index=i, is_valid=keystore.is_xpub)

    def on_cosigner(self, text, password, i):
        k = keystore.from_text(text, password)
        self.on_keystore(k)

    def create_seed(self):
        from electrum.mnemonic import Mnemonic
        seed = Mnemonic('en').make_seed()
        self.show_seed_dialog(run_next=self.confirm_seed, seed_text=seed)

    def confirm_seed(self, seed):
        self.confirm_seed_dialog(run_next=self.add_password, is_valid=lambda x: x==seed)

    def add_password(self, text):
        f = lambda pw: self.run('create_keystore', text, pw)
        self.request_password(run_next=f)

    def create_keystore(self, text, password):
        k = keystore.from_text(text, password)
        self.on_keystore(k, password)

    def create_addresses(self):
        def task():
            self.wallet.synchronize()
            self.wallet.storage.write()
            self.terminate()
        msg = _("Electrum is generating your addresses, please wait.")
        self.waiting_dialog(task, msg)
