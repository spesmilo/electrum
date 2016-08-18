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
from wallet import Wallet, Imported_Wallet, Standard_Wallet, Multisig_Wallet, WalletStorage
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
            ('twofactor', _("Wallet with two-factor authentication")),
            ('multisig',  _("Multi-signature wallet")),
        ]
        registered_kinds = Wallet.categories()
        choices = wallet_kinds#[pair for pair in wallet_kinds if pair[0] in registered_kinds]
        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.on_wallet_type)

    def on_wallet_type(self, choice):
        self.wallet_type = choice
        if choice == 'standard':
            action = 'choose_seed'
        elif choice == 'multisig':
            action = 'choose_multisig'
        elif choice == 'twofactor':
            self.storage.put('wallet_type', '2fa')
            self.storage.put('use_trustedcoin', True)
            self.plugin = self.plugins.load_plugin('trustedcoin')
            action = self.storage.get_action()

        self.run(action)

    def choose_multisig(self):
        def on_multisig(m, n):
            self.multisig_type = "%dof%d"%(m, n)
            self.n = n
            self.run('choose_seed')
        self.multisig_dialog(run_next=on_multisig)

    def choose_seed(self):
        title = _('Seed and Private Keys')
        message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
        if self.wallet_type in ['standard', 'multisig']:
            choices = [
                ('create_seed', _('Create a new seed')),
                ('restore_seed', _('I already have a seed')),
                ('restore_from_key', _('Import keys or addresses')),
                ('choose_hw',  _('Use hardware wallet')),
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

    def restore_from_key(self):
        if self.wallet_type == 'standard':
            v = keystore.is_any_key
            title = _("Import keys")
            message = ' '.join([
                _("To create a watching-only wallet, please enter your master public key (xpub), or a list of Litecoin addresses."),
                _("To create a spending wallet, please enter a master private key (xprv), or a list of Litecoin private keys.")
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
        self.storage.put('key_type', 'hardware')
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
        self.storage.put('hardware_type', hw_type)
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
        from keystore import load_keystore
        self.storage.put('account_id', int(account_id))
        keystore = load_keystore(self.storage, None)
        keystore.plugin.on_create_wallet(keystore, self)

    def on_hardware_seed(self):
        self.storage.put('key_type', 'hw_seed')
        is_valid = lambda x: True #fixme: bip39
        f = lambda seed: self.run('on_bip39_seed', seed)
        self.restore_seed_dialog(run_next=f, is_valid=is_valid)

    def on_bip_39_seed(self, seed):
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
        derivation = "m/44'/2'/%d'"%account_id
        self.storage.put('account_id', account_id)
        k.add_xprv_from_seed(bip32_seed, derivation, password)
        k.save(self.storage, 'x/')
        self.wallet = Standard_Wallet(self.storage)
        self.run('create_addresses')

    def create_wallet(self, k, password):
        if self.wallet_type == 'standard':
            k.save(self.storage, 'x/')
            self.wallet = Standard_Wallet(self.storage)
            self.run('create_addresses')
        elif self.wallet_type == 'multisig':
            self.storage.put('wallet_type', self.multisig_type)
            self.add_cosigner(k, 0)
            xpub = k.get_master_public_key()
            self.stack = []
            self.run('show_xpub_and_add_cosigners', password, xpub)

    def show_xpub_and_add_cosigners(self, password, xpub):
        self.show_xpub_dialog(xpub=xpub, run_next=lambda x: self.run('add_cosigners', password, 1))

    def add_cosigner(self, keystore, i):
        d = self.storage.get('master_public_keys', {})
        if keystore.xpub in d.values():
            raise BaseException('duplicate key')
        keystore.save(self.storage, 'x%d/'%(i+1))

    def add_cosigners(self, password, i):
        self.add_cosigner_dialog(run_next=lambda x: self.on_cosigner(x, password, i), index=i, is_valid=keystore.is_xpub)

    def on_cosigner(self, text, password, i):
        k = keystore.from_text(text, password)
        try:
            self.add_cosigner(k, i)
        except BaseException as e:
            self.show_message("error:" + str(e))
            return
        if i < self.n - 1:
            self.run('add_cosigners', password, i+1)
        else:
            self.wallet = Multisig_Wallet(self.storage)
            self.create_addresses()

    def create_seed(self):
        from electrum_ltc.mnemonic import Mnemonic
        seed = Mnemonic('en').make_seed()
        self.show_seed_dialog(run_next=self.confirm_seed, seed_text=seed)

    def confirm_seed(self, seed):
        self.confirm_seed_dialog(run_next=self.add_password, is_valid=lambda x: x==seed)

    def add_password(self, text):
        f = lambda pw: self.run('create_keystore', text, pw)
        self.request_password(run_next=f)

    def create_keystore(self, text, password):
        k = keystore.from_text(text, password)
        self.create_wallet(k, password)

    def create_addresses(self):
        def task():
            self.wallet.synchronize()
            self.wallet.storage.write()
            self.terminate()
        msg = _("Electrum is generating your addresses, please wait.")
        self.waiting_dialog(task, msg)
