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
import bitcoin
import keystore
from wallet import Wallet, Imported_Wallet, Standard_Wallet, Multisig_Wallet, WalletStorage, wallet_types
from i18n import _
from plugins import run_hook

class BaseWizard(object):

    def __init__(self, config, path):
        super(BaseWizard, self).__init__()
        self.config = config
        self.storage = WalletStorage(path)
        self.wallet = None
        self.stack = []
        self.plugin = None
        self.keystores = []
        self.is_kivy = config.get('gui') == 'kivy'

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

    def load_2fa(self):
        self.storage.put('wallet_type', '2fa')
        self.storage.put('use_trustedcoin', True)
        self.plugin = self.plugins.load_plugin('trustedcoin')

    def on_wallet_type(self, choice):
        self.wallet_type = choice
        if choice == 'standard':
            action = 'choose_keystore'
        elif choice == 'multisig':
            action = 'choose_multisig'
        elif choice == '2fa':
            self.load_2fa()
            action = self.storage.get_action()
        elif choice == 'imported':
            action = 'import_addresses'
        self.run(action)

    def choose_multisig(self):
        def on_multisig(m, n):
            self.multisig_type = "%dof%d"%(m, n)
            self.storage.put('wallet_type', self.multisig_type)
            self.n = n
            self.run('choose_keystore')
        self.multisig_dialog(run_next=on_multisig)

    def choose_keystore(self):
        assert self.wallet_type in ['standard', 'multisig']
        i = len(self.keystores)
        title = _('Add cosigner') + ' (%d of %d)'%(i+1, self.n) if self.wallet_type=='multisig' else _('Keystore')
        if self.wallet_type =='standard' or i==0:
            message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
            choices = [
                ('create_seed', _('Create a new seed')),
                ('restore_from_seed', _('I already have a seed')),
                ('restore_from_key', _('Use public or private keys')),
            ]
            if not self.is_kivy:
                choices.append(('choose_hw_device',  _('Use a hardware device')))
        else:
            message = _('Add a cosigner to your multi-sig wallet')
            choices = [
                ('restore_from_key', _('Enter cosigner key')),
                ('restore_from_seed', _('Enter cosigner seed')),
            ]
            if not self.is_kivy:
                choices.append(('choose_hw_device',  _('Cosign with hardware device')))

        self.choice_dialog(title=title, message=message, choices=choices, run_next=self.run)

    def import_addresses(self):
        v = keystore.is_address_list
        title = _("Import Bitcoin Addresses")
        message = _("Enter a list of Bitcoin addresses. This will create a watching-only wallet.")
        self.add_xpub_dialog(title=title, message=message, run_next=self.on_import_addresses, is_valid=v)

    def on_import_addresses(self, text):
        assert keystore.is_address_list(text)
        self.wallet = Imported_Wallet(self.storage)
        for x in text.split():
            self.wallet.import_address(x)
        self.terminate()

    def restore_from_key(self):
        if self.wallet_type == 'standard':
            v = keystore.is_any_key
            title = _("Create keystore from keys")
            message = ' '.join([
                _("To create a watching-only wallet, please enter your master public key (xpub)."),
                _("To create a spending wallet, please enter a master private key (xprv), or a list of Bitcoin private keys.")
            ])
            self.add_xpub_dialog(title=title, message=message, run_next=self.on_restore_from_key, is_valid=v)
        else:
            v = keystore.is_bip32_key
            i = len(self.keystores) + 1
            self.add_cosigner_dialog(index=i, run_next=self.on_restore_from_key, is_valid=v)

    def on_restore_from_key(self, text):
        k = keystore.from_keys(text)
        self.on_keystore(k)

    def choose_hw_device(self):
        title = _('Hardware Keystore')
        # check available plugins
        support = self.plugins.get_hardware_support()
        if not support:
            msg = '\n'.join([
                _('No hardware wallet support found on your system.'),
                _('Please install the relevant libraries (eg python-trezor for Trezor).'),
            ])
            self.confirm_dialog(title=title, message=msg, run_next= lambda x: self.choose_hw_device())
            return
        # scan devices
        devices = []
        devmgr = self.plugins.device_manager
        for name, description, plugin in support:
            try:
                # FIXME: side-effect: unpaired_device_info sets client.handler
                u = devmgr.unpaired_device_infos(None, plugin)
            except:
                devmgr.print_error("error", name)
                continue
            devices += map(lambda x: (name, x), u)
        if not devices:
            msg = '\n'.join([
                _('No hardware device detected.'),
                _('To trigger a rescan, press \'next\'.'),
            ])
            self.confirm_dialog(title=title, message=msg, run_next= lambda x: self.choose_hw_device())
            return
        # select device
        self.devices = devices
        choices = []
        for name, info in devices:
            state = _("initialized") if info.initialized else _("wiped")
            label = info.label or _("An unnamed %s")%name
            descr = "%s [%s, %s]" % (label, name, state)
            choices.append(((name, info), descr))
        msg = _('Select a device') + ':'
        self.choice_dialog(title=title, message=msg, choices=choices, run_next=self.on_device)

    def on_device(self, name, device_info):
        self.plugin = self.plugins.get_plugin(name)
        try:
            self.plugin.setup_device(device_info, self)
        except BaseException as e:
            self.show_error(str(e))
            self.choose_hw_device()
            return
        if self.wallet_type=='multisig':
            # There is no general standard for HD multisig.
            # This is partially compatible with BIP45; assumes index=0
            self.on_hw_derivation(name, device_info, "m/45'/0")
        else:
            from keystore import bip44_derivation
            f = lambda x: self.run('on_hw_derivation', name, device_info, bip44_derivation(int(x)))
            self.account_id_dialog(f)

    def account_id_dialog(self, f):
        message = '\n'.join([
            _('Enter your BIP44 account number here.'),
            _('If you are not sure what this is, leave this field to zero.')
        ])
        def is_int(x):
            try:
                int(x)
                return True
            except:
                return False
        self.line_dialog(run_next=f, title=_('Account Number'), message=message, default='0', test=is_int)

    def on_hw_derivation(self, name, device_info, derivation):
        from keystore import hardware_keystore
        xpub = self.plugin.get_xpub(device_info.device.id_, derivation, self)
        if xpub is None:
            self.show_error('Cannot read xpub from device')
            return
        d = {
            'type': 'hardware',
            'hw_type': name,
            'derivation': derivation,
            'xpub': xpub,
            'label': device_info.label,
        }
        k = hardware_keystore(d)
        self.on_keystore(k)

    def passphrase_dialog(self, run_next):
        title = _('Seed extension')
        message = '\n'.join([
            _('You may extend your seed with custom words.'),
            _('Your seed extension must be saved together with your seed.'),
        ])
        warning = '\n'.join([
            _('Note that this is NOT your encryption password.'),
            _('If you do not know what this is, leave this field empty.'),
        ])
        self.line_dialog(title=title, message=message, warning=warning, default='', test=lambda x:True, run_next=run_next)

    def restore_from_seed(self):
        self.opt_bip39 = True
        self.opt_ext = True
        test = bitcoin.is_seed if self.wallet_type == 'standard' else bitcoin.is_new_seed
        self.restore_seed_dialog(run_next=self.on_restore_seed, test=test)

    def on_restore_seed(self, seed, is_bip39, is_ext):
        if is_bip39:
            f = lambda passphrase: self.on_restore_bip39(seed, passphrase)
            self.passphrase_dialog(run_next=f) if is_ext else f('')
        else:
            seed_type = bitcoin.seed_type(seed)
            if seed_type == 'standard':
                f = lambda passphrase: self.run('create_keystore', seed, passphrase)
                self.passphrase_dialog(run_next=f) if is_ext else f('')
            elif seed_type == 'old':
                self.run('create_keystore', seed, '')
            elif seed_type == '2fa':
                if self.is_kivy:
                    self.show_error('2FA seeds are not supported in this version')
                    self.run('restore_from_seed')
                else:
                    self.load_2fa()
                    self.run('on_restore_seed', seed, is_ext)
            else:
                raise BaseException('Unknown seed type', seed_type)

    def on_restore_bip39(self, seed, passphrase):
        f = lambda x: self.run('on_bip44', seed, passphrase, int(x))
        self.account_id_dialog(f)

    def create_keystore(self, seed, passphrase):
        k = keystore.from_seed(seed, passphrase)
        self.on_keystore(k)

    def on_bip44(self, seed, passphrase, account_id):
        k = keystore.BIP32_KeyStore({})
        bip32_seed = keystore.bip39_to_seed(seed, passphrase)
        derivation = "m/44'/0'/%d'"%account_id
        k.add_xprv_from_seed(bip32_seed, derivation)
        self.on_keystore(k)

    def on_keystore(self, k):
        if self.wallet_type == 'standard':
            self.keystores.append(k)
            self.run('create_wallet')
        elif self.wallet_type == 'multisig':
            if k.xpub in map(lambda x: x.xpub, self.keystores):
                self.show_error(_('Error: duplicate master public key'))
                self.run('choose_keystore')
                return
            self.keystores.append(k)
            if len(self.keystores) == 1:
                xpub = k.get_master_public_key()
                self.stack = []
                self.run('show_xpub_and_add_cosigners', xpub)
            elif len(self.keystores) < self.n:
                self.run('choose_keystore')
            else:
                self.run('create_wallet')

    def create_wallet(self):
        if any(k.may_have_password() for k in self.keystores):
            self.request_password(run_next=self.on_password)
        else:
            self.on_password(None)

    def on_password(self, password):
        self.storage.put('use_encryption', bool(password))
        for k in self.keystores:
            if k.may_have_password():
                k.update_password(None, password)
        if self.wallet_type == 'standard':
            self.storage.put('keystore', k.dump())
            self.wallet = Standard_Wallet(self.storage)
            self.run('create_addresses')
        elif self.wallet_type == 'multisig':
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
        k = keystore.from_keys(text, password)
        self.on_keystore(k)

    def create_seed(self):
        from electrum.mnemonic import Mnemonic
        seed = Mnemonic('en').make_seed()
        self.opt_bip39 = False
        f = lambda x: self.request_passphrase(seed, x)
        self.show_seed_dialog(run_next=f, seed_text=seed)

    def request_passphrase(self, seed, opt_passphrase):
        if opt_passphrase:
            f = lambda x: self.confirm_seed(seed, x)
            self.passphrase_dialog(run_next=f)
        else:
            self.run('confirm_seed', seed, '')

    def confirm_seed(self, seed, passphrase):
        f = lambda x: self.confirm_passphrase(seed, passphrase)
        self.confirm_seed_dialog(run_next=f, test=lambda x: x==seed)

    def confirm_passphrase(self, seed, passphrase):
        f = lambda x: self.run('create_keystore', seed, x)
        if passphrase:
            title = _('Confirm Seed Extension')
            message = '\n'.join([
                _('Your seed extension must be saved together with your seed.'),
                _('Please type it here.'),
            ])
            self.line_dialog(run_next=f, title=title, message=message, default='', test=lambda x: x==passphrase)
        else:
            f('')

    def create_addresses(self):
        def task():
            self.wallet.synchronize()
            self.wallet.storage.write()
            self.terminate()
        msg = _("Electrum is generating your addresses, please wait.")
        self.waiting_dialog(task, msg)
